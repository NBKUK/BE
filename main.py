# main.py
import os, uuid
from typing import List
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app_models import (
    CardEntry, TransactionOut, StepOut, ReceiptOut, TxHistoryOut, TxHistoryItem
)
from storage import init_db, get_db, TransactionORM, now_iso
from iso8583_tcp import ISO8583, iso_send_tcp, b64, MAC_HEX_KEY

from notify import manager, emit
from payout import bank_payout, crypto_payout, notify_webhook

# JWT bits (kept as-is if you already use them)
import jwt
from datetime import datetime, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import pyotp

SECRET_KEY = os.getenv("JWT_SECRET", "change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
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

# ------- Protocols & auth-code rules (unchanged) -------
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

app = FastAPI(title="POS Backend (ISO8583 MTI 0200→0510 + Payout)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(","),
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

# --------------------- WebSocket ---------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep the socket open; you can listen to pings if needed.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)

# --------------------- Transaction -------------------
@app.post("/transaction", response_model=TransactionOut)
async def process_transaction(entry: CardEntry, db: Session = Depends(get_db)):
    # Validate protocol & auth code length
    if entry.protocol not in PROTOCOLS:
        raise HTTPException(400, detail="Unsupported protocol")
    req_len = PROTOCOLS[entry.protocol]
    if not entry.auth_code.isdigit() or len(entry.auth_code) != req_len:
        raise HTTPException(400, detail=f"Auth/approval code must be {req_len} digits")
    if entry.amount <= 0:
        raise HTTPException(400, detail="Invalid amount")

    # Build DEs
    iso = ISO8583(MAC_HEX_KEY)
    now = datetime.utcnow()
    de_common = {
        3: "000000",
        4: f"{cents(entry.amount):012d}",
        7: now.strftime("%m%d%H%M%S"),
        11: f"{now.microsecond % 999999:06d}",
        12: now.strftime("%H%M%S"),
        13: now.strftime("%m%d"),
        18: "5999",
        22: "012",
        25: "00",
        41: str(entry.tid).ljust(8, "0")[:8],
        42: str(entry.mid).ljust(15, "0")[:15],
        49: "840" if entry.currency.upper() in ("USD", "840") else
            "826" if entry.currency.upper() in ("GBP", "826") else
            "978",
    }

    # PAN + expiry
    pan_digits = "".join(ch for ch in entry.card_number if ch.isdigit())
    exp = entry.expiry.replace("/", "")
    if len(exp) == 4:  # MMYY -> YYMM
        exp_de14 = exp[2:] + exp[:2]
    else:
        raise HTTPException(400, detail="Expiry must be MM/YY")

    tx_id = str(uuid.uuid4())
    created = now_iso()

    # Emit: transaction started
    await emit("TX_STARTED", tx_id, {"amount": entry.amount, "currency": entry.currency, "protocol": entry.protocol})
    await notify_webhook({"stage": "TX_STARTED", "tx_id": tx_id})

    # ---- 0200 Auth ----
    await emit("0200_SENT", tx_id)
    try:
        m0200 = iso.pack("0200", {
            **de_common,
            2: pan_digits,
            14: exp_de14,
            32: "000001",
            60: entry.protocol,
            61: entry.auth_code,
        })
        r0210 = iso_send_tcp(m0200)
        step0210 = StepOut(mti="0210", desc="Auth Response (ACK) → Terminal", ok=True, raw_b64=b64(r0210))
        await emit("0210_ACK", tx_id)
        await notify_webhook({"stage": "0210_ACK", "tx_id": tx_id})
    except Exception as e:
        await emit("0210_FAIL", tx_id, {"error": str(e)})
        await notify_webhook({"stage": "0210_FAIL", "tx_id": tx_id, "error": str(e)})
        raise HTTPException(502, detail=f"0200/0210 failed: {e}")

    # ---- 0220 Advice ----
    await emit("0220_SENT", tx_id)
    try:
        m0220 = iso.pack("0220", {**de_common, 61: "ADVICE"})
        r0230 = iso_send_tcp(m0220)
        step0230 = StepOut(mti="0230", desc="Advice Response (ACK) → Terminal", ok=True, raw_b64=b64(r0230))
        await emit("0230_ACK", tx_id)
        await notify_webhook({"stage": "0230_ACK", "tx_id": tx_id})
    except Exception as e:
        await emit("0230_FAIL", tx_id, {"error": str(e)})
        await notify_webhook({"stage": "0230_FAIL", "tx_id": tx_id, "error": str(e)})
        raise HTTPException(502, detail=f"0220/0230 failed: {e}")

    # ---- 0500 Settlement ----
    await emit("0500_SENT", tx_id)
    try:
        m0500 = iso.pack("0500", {**de_common, 61: "SETTLE"})
        r0510 = iso_send_tcp(m0500)
        step0510 = StepOut(mti="0510", desc="Settlement Response (ACK) → Terminal", ok=True, raw_b64=b64(r0510))
        await emit("0510_ACK", tx_id)
        await notify_webhook({"stage": "0510_ACK", "tx_id": tx_id})
    except Exception as e:
        await emit("0510_FAIL", tx_id, {"error": str(e)})
        await notify_webhook({"stage": "0510_FAIL", "tx_id": tx_id, "error": str(e)})
        raise HTTPException(502, detail=f"0500/0510 failed: {e}")

    # ---- Payout (immediately after 0510) ----
    payout_result = None
    payout_status = "SKIPPED"
    try:
        if entry.payout_method.upper() == "BANK":
            # Expect entry.payout_target like "IBAN|NAME" (simple parse)
            if not entry.payout_target or "|" not in entry.payout_target:
                raise ValueError("payout_target required as 'IBAN|Beneficiary Name' for BANK")
            iban, name = entry.payout_target.split("|", 1)
            await emit("PAYOUT_BANK_START", tx_id, {"iban": iban.strip(), "name": name.strip()})
            payout_result = await bank_payout(
                tx_id=tx_id,
                amount=entry.amount,
                currency=entry.currency,
                creditor_name=name.strip(),
                creditor_iban=iban.strip(),
            )
            payout_status = f"BANK_{payout_result.get('status','unknown').upper()}"
            await emit("PAYOUT_BANK_DONE", tx_id, {"result": payout_result})
            await notify_webhook({"stage": "PAYOUT_BANK_DONE", "tx_id": tx_id, "result": payout_result})

        elif entry.payout_method.upper() == "CRYPTO":
            if not entry.payout_target:
                raise ValueError("payout_target (wallet address) required for CRYPTO")
            await emit("PAYOUT_CRYPTO_START", tx_id, {"address": entry.payout_target})
            payout_result = await crypto_payout(
                tx_id=tx_id,
                amount=entry.amount,
                currency=entry.currency,
                address=entry.payout_target,
            )
            payout_status = f"CRYPTO_{payout_result.get('status','unknown').upper()}"
            await emit("PAYOUT_CRYPTO_DONE", tx_id, {"result": payout_result})
            await notify_webhook({"stage": "PAYOUT_CRYPTO_DONE", "tx_id": tx_id, "result": payout_result})
        else:
            payout_status = "UNSPECIFIED"
            await emit("PAYOUT_SKIPPED", tx_id, {"reason": "payout_method not BANK/CRYPTO"})
            await notify_webhook({"stage": "PAYOUT_SKIPPED", "tx_id": tx_id})
    except Exception as e:
        payout_status = f"FAILED: {e}"
        await emit("PAYOUT_FAIL", tx_id, {"error": str(e)})
        await notify_webhook({"stage": "PAYOUT_FAIL", "tx_id": tx_id, "error": str(e)})

    # ---- store + receipt ----
    masked = mask_pan(pan_digits)
    rec = ReceiptOut(
        transaction_id=tx_id,
        amount=entry.amount,
        currency=entry.currency,
        protocol=entry.protocol,
        card_last4=pan_digits[-4:],
        auth_code=entry.auth_code,
        status="APPROVED" if payout_status and not payout_status.startswith("FAILED") else "PENDING/FAILED",
        created_at=created,
    )

    row = TransactionORM(
        created_at=created,
        amount=entry.amount,
        currency=entry.currency,
        protocol=entry.protocol,
        auth_code=entry.auth_code,
        masked_pan=masked,
        status=rec.status,
        step_0210=step0210.raw_b64,
        step_0230=step0230.raw_b64,
        step_0510=step0510.raw_b64,
        receipt_id=tx_id,
        payout_status=payout_status,
    )
    db.add(row)
    db.commit()

    await emit("TX_COMPLETED", tx_id, {"final_status": rec.status, "payout_status": payout_status})
    await notify_webhook({"stage": "TX_COMPLETED", "tx_id": tx_id, "final_status": rec.status, "payout_status": payout_status})

    return TransactionOut(
        id=tx_id,
        status=rec.status,
        steps=[step0210, step0230, step0510],
        receipt=rec,
    )

# --------------- History -----------------
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
