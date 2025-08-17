# payout.py
import os
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import httpx

BANK_API_URL = os.getenv("BANK_API_URL")          # e.g. https://bank.example.com/pacs008
BANK_API_KEY = os.getenv("BANK_API_KEY")          # if needed
CRYPTO_API_URL = os.getenv("CRYPTO_API_URL")      # e.g. https://crypto.example.com/payout
CRYPTO_API_KEY = os.getenv("CRYPTO_API_KEY")
WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL")     # optional fallback notifications

def _amt_cents(amt: float) -> int:
    q = Decimal(str(amt)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int(q * 100)

def _pacs008_xml(
    msg_id: str,
    end_to_end_id: str,
    amount: float,
    currency: str,
    debtor_name: str,
    debtor_iban: str,
    creditor_name: str,
    creditor_iban: str,
) -> str:
    # Minimal pacs.008 for credit transfer (no schema validation here).
    # Adjust to your bank’s profile as needed.
    iso_now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    amt_str = f"{Decimal(str(amount)).quantize(Decimal('0.01'))}"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.02">
  <FIToFICstmrCdtTrf>
    <GrpHdr>
      <MsgId>{msg_id}</MsgId>
      <CreDtTm>{iso_now}</CreDtTm>
      <NbOfTxs>1</NbOfTxs>
      <SttlmInf>
        <SttlmMtd>CLRG</SttlmMtd>
      </SttlmInf>
    </GrpHdr>
    <CdtTrfTxInf>
      <PmtId>
        <EndToEndId>{end_to_end_id}</EndToEndId>
      </PmtId>
      <IntrBkSttlmAmt Ccy="{currency}">{amt_str}</IntrBkSttlmAmt>
      <Dbtr>
        <Nm>{debtor_name}</Nm>
      </Dbtr>
      <DbtrAcct>
        <Id><IBAN>{debtor_iban}</IBAN></Id>
      </DbtrAcct>
      <Cdtr>
        <Nm>{creditor_name}</Nm>
      </Cdtr>
      <CdtrAcct>
        <Id><IBAN>{creditor_iban}</IBAN></Id>
      </CdtrAcct>
    </CdtTrfTxInf>
  </FIToFICstmrCdtTrf>
</Document>
""".strip()

async def bank_payout(
    *,
    tx_id: str,
    amount: float,
    currency: str,
    creditor_name: str,
    creditor_iban: str,
    debtor_name: str = "Your Company Ltd",
    debtor_iban: str = "DE44500105175407324931",
) -> dict:
    xml = _pacs008_xml(
        msg_id=f"MSG-{tx_id}",
        end_to_end_id=f"E2E-{tx_id}",
        amount=amount,
        currency=currency,
        debtor_name=debtor_name,
        debtor_iban=debtor_iban,
        creditor_name=creditor_name,
        creditor_iban=creditor_iban,
    )

    if not BANK_API_URL:
        # No live endpoint configured; return “prepared” without POSTing.
        return {"status": "prepared", "format": "pacs.008", "tx_id": tx_id, "xml": xml}

    headers = {"Content-Type": "application/xml"}
    if BANK_API_KEY:
        headers["Authorization"] = f"Bearer {BANK_API_KEY}"

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(BANK_API_URL, content=xml.encode("utf-8"), headers=headers)
        r.raise_for_status()
        return {"status": "submitted", "format": "pacs.008", "tx_id": tx_id, "bank_response": r.text}

async def crypto_payout(
    *,
    tx_id: str,
    amount: float,
    currency: str,
    address: str,
    chain: str = "USDC-ETH"
) -> dict:
    if not CRYPTO_API_URL:
        return {"status": "prepared", "format": "crypto", "tx_id": tx_id, "address": address, "chain": chain, "amount": amount, "currency": currency}

    headers = {"Content-Type": "application/json"}
    if CRYPTO_API_KEY:
        headers["Authorization"] = f"Bearer {CRYPTO_API_KEY}"

    payload = {
        "tx_id": tx_id,
        "amount": amount,
        "currency": currency,
        "destination": {"address": address, "chain": chain},
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(CRYPTO_API_URL, json=payload, headers=headers)
        r.raise_for_status()
        return {"status": "submitted", "format": "crypto", "tx_id": tx_id, "crypto_response": r.json()}

async def notify_webhook(event: dict) -> None:
    if not WEBHOOK_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(WEBHOOK_URL, json=event)
    except Exception:
        # Non-fatal: don’t break the main flow on webhook errors
        pass
