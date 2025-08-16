import os
import uuid
from typing import List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from models import CardEntry, TransactionOut, StepOut, ReceiptOut, TxHistoryOut, TxHistoryItem
from storage import init_db, get_db, get_all_users, now_iso  # Updated to match corrected imports
from iso8583_tcp import ISO8583, iso_send_tcp, b64, MAC_HEX_KEY

# JWT helpers
import jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import pyotp

SECRET_KEY = os.getenv("JWT_SECRET", "change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Adjust as needed

bearer_scheme = HTTPBearer()

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token does not contain valid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token is invalid or expired")

# Protocols mapping and auth code length validation
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

app = FastAPI(title="POS Backend (ISO8583 MTI 0200→0510)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

def mask_pan(pan: str) -> str:
    d = "".join(ch for ch in pan if ch.isdigit())
    return ("*" * max(0, len(d)-4)) + d[-4:] if len(d) >= 4 else d

def cents(amount_major: float) -> int:
    return int(round(amount_major * 100))

@app.post("/transaction", response_model=TransactionOut)
def process_transaction(entry: CardEntry, db: Session = Depends(get_db)):
    # ---- validate protocol & auth code length ----
    if entry.protocol not in PROTOCOLS:
        raise HTTPException(400, detail="Unsupported protocol")
    req_len = PROTOCOLS[entry.protocol]
    if not entry.auth_code.isdigit() or len(entry.auth_code) != req_len:
        raise HTTPException(400, detail=f"Auth/approval code must be {req_len} digits")

    if entry.amount <= 0:
        raise HTTPException(400, detail="Invalid amount")

    # ---- build common DEs ----
    iso = ISO8583(MAC_HEX_KEY)
    from datetime import datetime
    now = datetime.utcnow()
    de_common = {
        3: "000000",                                # processing code
        4: f"{cents(entry.amount):012d}",           # amount, 12 n
        7: now.strftime("%m%d%H%M%S"),              # trans datetime
        11: f"{now.microsecond % 999999:06d}",      # STAN (demo)
        12: now.strftime("%H%M%S"),                 # local time
        13: now.strftime("%m%d"),                   # local date
        18: "5999",                                 # MCC (misc retail)
        22: "012",                                  # POS entry mode (mag stripe keyed)
        25: "00",                                   # POS condition code
        41: str(entry.tid).ljust(8, "0")[:8],       # TID
        42: str(entry.mid).ljust(15, "0")[:15],     # MID
        49: "840" if entry.currency.upper() in ("USD", "840") else
            "826" if entry.currency.upper() in ("GBP", "826") else
            "978",                                  # currency: USD/GBP/EUR
    }

    # PAN + expiry
    pan_digits = "".join(ch for ch in entry.card_number if ch.isdigit())
    exp = entry.expiry.replace("/", "")
    if len(exp) == 4:  # MMYY -> YYMM for DE14
        exp_de14 = exp[2:] + exp[:2]
    else:
        raise HTTPException(400, detail="Expiry must be MM/YY")

    # ---- 0200 Auth ----
    m0200 = iso.pack("0200", {
        **de_common,
        2: pan_digits,           # PAN (LLVAR)
        14: exp_de14,            # expiry YYMM
        32: "000001",            # acquiring institution ID (LLVAR)
        60: entry.protocol,      # protocol (LLLVAR)
        61: entry.auth_code,     # approval code (LLLVAR, per your scheme)
    })

    try:
        r0210 = iso_send_tcp(m0200)
    except Exception as e:
        raise HTTPException(502, detail=f"0200 failed: {e}")

    step0210 = StepOut(mti="0210", desc="Auth Response (ACK) → Terminal", ok=True, raw_b64=b64(r0210))

    # ---- 0220 Advice ----
    m0220 = iso.pack("0220", {**de_common, 61: "ADVICE"})
    try:
        r0230 = iso_send_tcp(m0220)
    except Exception as e:
        raise HTTPException(502, detail=f"0220 failed: {e}")

    step0230 = StepOut(mti="0230", desc="Advice Response (ACK) → Terminal", ok=True, raw_b64=b64(r0230))

    # ---- 0500 Settlement ----
    m0500 = iso.pack("0500", {**de_common, 61: "SETTLE"})
    try:
        r0510 = iso_send_tcp(m0500)
    except Exception as e:
        raise HTTPException(502, detail=f"0500 failed: {e}")

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
        card_last4=pan_digits[-4:],
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
        step_0210=step0210.raw_b64,
        step_0230=step0230.raw_b64,
        step_0510=step0510.raw_b64,
        receipt_id=tx_id,
    )
    db.add(row)
    db.commit()

    return TransactionOut(
        id=tx_id,
        status="APPROVED",
        steps=[step0210, step0230, step0510],
        receipt=rec,
    )

@app.get("/transactions", response_model=TxHistoryOut)
def list_transactions(db: Session = Depends(get_db)):
    rows = db.query(TransactionORM).order_by(TransactionORM.id.desc()).limit(500).all()
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

