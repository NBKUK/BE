# main.py
import os, uuid
from typing import List
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import pyotp
from sqlalchemy.orm import Session

from db import init_db, get_db
from storage import (
    create_user, get_user_by_username, verify_password,
    get_totp_reset, create_totp_reset, delete_totp_reset,
    TransactionORM, list_transactions, now_iso
)
from app_models import (
    CardEntry, TransactionOut, StepOut, ReceiptOut, TxHistoryOut, TxHistoryItem,
    LoginIn, TokenPair, TotpRequestIn, TotpVerifyIn
)
from iso8583_tcp import ISO8583, iso_send_tcp, b64, MAC_HEX_KEY

# ---- Auth config ----
SECRET_KEY = os.getenv("JWT_SECRET", "change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_TTL_MIN", "30"))

bearer_scheme = HTTPBearer()

def create_access_token(sub: str, expires_delta: timedelta | None = None):
    to_encode = {"sub": sub}
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(401, "Token missing subject")
        return sub
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")

# ---- Protocols mapping and auth code length validation ----
PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6,
}

app = FastAPI(title="POS Backend (ISO8583 MTI 0200→0210→0500→0510)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Startup: initialize DB and bootstrap admin ----
@app.on_event("startup")
def bootstrap():
    init_db()
    # Bootstrap one admin if none exists (env configurable)
    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASS", "change-me")
    with next(get_db()) as db:
        if not get_user_by_username(db, admin_user):
            # optional: set a TOTP secret for admin (can be replaced via /auth/totp/request)
            totp_secret = pyotp.random_base32()
            create_user(db, admin_user, admin_pass, totp_secret=totp_secret)

# ---- Utilities ----
def mask_pan(pan: str) -> str:
    d = "".join(ch for ch in pan if ch.isdigit())
    return ("*" * max(0, len(d) - 4)) + d[-4:] if len(d) >= 4 else d

def cents(amount_major: float) -> int:
    return int(round(amount_major * 100))

# ---- Health ----
@app.get("/health")
def health():
    return {"ok": True}

# ---- Auth endpoints ----
@app.post("/auth/login", response_model=TokenPair)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = get_user_by_username(db, payload.username)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token(payload.username)
    return TokenPair(token=token)

@app.post("/auth/totp/request")
def totp_request(body: TotpRequestIn, db: Session = Depends(get_db)):
    user = get_user_by_username(db, body.username)
    if not user:
        raise HTTPException(404, "User not found")
    code = pyotp.random_base32()[:6]
    expires_at = int(time.time()) + 10 * 60  # 10 minutes
    create_totp_reset(db, body.username, code, expires_at)
    # In real deployment, send this code via your channel (email/SMS). We return it here for admin-only flow.
    return {"status": "ok", "code": code, "expires_in_sec": 600}

@app.post("/auth/totp/verify")
def totp_verify(body: TotpVerifyIn, db: Session = Depends(get_db)):
    rec = get_totp_reset(db, body.username)
    if not rec or rec.code != body.code or rec.expires_at < int(time.time()):
        raise HTTPException(400, "Invalid or expired code")
    user = get_user_by_username(db, body.username)
    if not user:
        raise HTTPException(404, "User not found")
    # reset password
    from storage import pwd_context
    user.password_hash = pwd_context.hash(body.new_password)
    db.add(user)
    db.commit()
    delete_totp_reset(db, body.username)
    return {"status": "password_updated"}

# ---- Transaction processing (0200 → 0210 → 0500 → 0510) ----
@app.post("/tx/process", response_model=TransactionOut)
def process_transaction(entry: CardEntry, _user: str = Depends(verify_token), db: Session = Depends(get_db)):
    # Validate protocol & auth length
    if entry.protocol not in PROTOCOLS:
        raise HTTPException(400, "Unsupported protocol")
    req_len = PROTOCOLS[entry.protocol]
    if not entry.auth_code.isdigit() or len(entry.auth_code) != req_len:
        raise HTTPException(400, f"Auth/approval code must be {req_len} digits")

    if entry.amount <= 0:
        raise HTTPException(400, "Invalid amount")

    iso = ISO8583(MAC_HEX_KEY)
    now = datetime.utcnow()

    # Common fields
    def currency_to_999(curr: str) -> str:
        up = curr.upper()
        if up in ("USD", "840"): return "840"
        if up in ("GBP", "826"): return "826"
        return "978"  # default EUR
    def stan() -> str:
        return f"{now.microsecond % 999999:06d}"

    de_common = {
        3: "000000",
        4: f"{cents(entry.amount):012d}",
        7: now.strftime("%m%d%H%M%S"),
        11: stan(),
        12: now.strftime("%H%M%S"),
        13: now.strftime("%m%d"),
        18: "5999",
        22: "012",  # keyed
        25: "00",
        41: str(entry.tid).ljust(8, "0")[:8],
        42: str(entry.mid).ljust(15, "0")[:15],
        49: currency_to_999(entry.currency),
    }

    # PAN + expiry
    pan_digits = "".join(ch for ch in entry.card_number if ch.isdigit())
    exp = entry.expiry.replace(" ", "")
    if "/" not in exp or len(exp) != 5:
        raise HTTPException(400, "Expiry must be MM/YY")
    mm, yy = exp.split("/")
    exp_de14 = yy + mm

    # ---- 0200 Auth ----
    m0200 = iso.pack("0200", {
        **de_common,
        2: pan_digits,
        14: exp_de14,
        32: "000001",
        60: entry.protocol,
        61: entry.auth_code,  # Provided by cardholder (issuer-provided)
    })
    try:
        r0210 = iso_send_tcp(m0200)
    except Exception as e:
        raise HTTPException(502, f"0200 failed: {e}")
    step0210 = StepOut(mti="0210", desc="Auth Response (ACK) → Terminal", ok=True, raw_b64=b64(r0210))

    # ---- 0500 Settlement (straight-through capture) ----
    m0500 = iso.pack("0500", {**de_common, 61: "SETTLE"})
    try:
        r0510 = iso_send_tcp(m0500)
    except Exception as e:
        raise HTTPException(502, f"0500 failed: {e}")
    step0510 = StepOut(mti="0510", desc="Settlement Response (ACK) → Terminal", ok=True, raw_b64=b64(r0510))

    # ---- store + receipt ----
    tx_id = str(uuid.uuid4())
    created = now_iso()
    masked = mask_pan(pan_digits)

    rec = ReceiptOut(
        transaction_id=tx_id,
        amount=entry.amount,
        currency=entry.currency,
        protocol=entry.protocol,
        card_last4=pan_digits[-4:] if len(pan_digits) >= 4 else pan_digits,
        auth_code=entry.auth_code,
        status="APPROVED",
        created_at=created,
    )

    row = TransactionORM(
        created_at=created,
        amount=entry.amount,
        currency=entry.currency,
        protocol=entry.protocol,
        auth_code=entry.auth_code,
        masked_pan=masked,
        status="APPROVED",
        step_0210=step0210.raw_b64 or "",
        step_0510=step0510.raw_b64 or "",
        receipt_id=tx_id,
    )
    db.add(row)
    db.commit()

    return TransactionOut(
        id=tx_id,
        status="APPROVED",
        steps=[step0210, step0510],
        receipt=rec,
    )

# ---- History ----
@app.get("/tx/history", response_model=TxHistoryOut)
def history(_user: str = Depends(verify_token), db: Session = Depends(get_db)):
    rows = list_transactions(db)
    items: List[TxHistoryItem] = []
    for r in rows:
        items.append(TxHistoryItem(
            id=r.id,
            created_at=r.created_at,
            amount=r.amount,
            currency=r.currency,
            protocol=r.protocol,
            auth_code=r.auth_code,
            masked_pan=r.masked_pan,
            status=r.status,
        ))
    return TxHistoryOut(items=items)
