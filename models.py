from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
import re

# ---- Input from POS (manual keyed entry) ----
class CardEntry(BaseModel):
    protocol: str
    amount: float = Field(..., description="Amount in major units, e.g., 12.34")
    currency: str = Field(..., description="ISO 4217 currency code, e.g., USD/GBP/EUR")
    card_number: str
    expiry: str  # "MM/YY"
    cvv: str
    auth_code: str
    online: bool = True
    pinless: bool = False
    mid: str = "MID00001"
    tid: str = "TID00001"
    payout_method: str = Field("BANK", description="Payment method, can be BANK or CRYPTO")
    payout_target: Optional[str] = None

    @validator('card_number')
    def validate_card_number(cls, v):
        if not re.match(r'^\d{16}$', v):
            raise ValueError("Card number must be 16 digits.")
        return v

    @validator('expiry')
    def validate_expiry(cls, v):
        if not re.match(r'^\d{2}/\d{2}$', v):
            raise ValueError("Expiry date must be in MM/YY format.")
        return v

    @validator('cvv')
    def validate_cvv(cls, v):
        if not re.match(r'^\d{3}$', v):
            raise ValueError("CVV must be 3 digits.")
        return v

# ---- Output structures ----
class StepOut(BaseModel):
    mti: str
    desc: str
    ok: bool = True
    raw_b64: Optional[str] = None
    note: Optional[str] = None

class ReceiptOut(BaseModel):
    transaction_id: str
    amount: float
    currency: str
    protocol: str
    card_last4: str
    auth_code: str
    status: str
    created_at: str

class TransactionOut(BaseModel):
    id: str
    status: str
    steps: List[StepOut]
    receipt: ReceiptOut

class TxHistoryItem(BaseModel):
    id: int
    created_at: str
    amount: float
    currency: str
    protocol: str
    auth_code: str
    masked_pan: str
    status: str

class TxHistoryOut(BaseModel):
    items: List[TxHistoryItem]

class LoginIn(BaseModel):
    username: str
    password: str

class TokenPair(BaseModel):
    token: str

class TotpRequestIn(BaseModel):
    username: str

class TotpVerifyIn(BaseModel):
    username: str
    code: str
    new_password: str

