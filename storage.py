# storage.py
from sqlalchemy import String, Integer, BigInteger, Float
from sqlalchemy.orm import Mapped, mapped_column, Session
from passlib.context import CryptContext
import time
from datetime import datetime, timezone

from db import Base

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---- ORM tables ----
class UserORM(Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String, nullable=True)

class TotpResetORM(Base):
    __tablename__ = "totp_resets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String, index=True)
    code: Mapped[str] = mapped_column(String)
    expires_at: Mapped[int] = mapped_column(BigInteger)

class TransactionORM(Base):
    __tablename__ = "transactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(String, index=True)
    amount: Mapped[float] = mapped_column(Float)
    currency: Mapped[str] = mapped_column(String(3))
    protocol: Mapped[str] = mapped_column(String)
    auth_code: Mapped[str] = mapped_column(String)
    masked_pan: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    step_0210: Mapped[str | None] = mapped_column(String, nullable=True)
    step_0510: Mapped[str | None] = mapped_column(String, nullable=True)
    receipt_id: Mapped[str] = mapped_column(String, index=True)

# ---- helpers ----
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def create_user(db: Session, username: str, password: str, totp_secret: str | None = None):
    hashed_password = pwd_context.hash(password)
    db_user = UserORM(username=username, password_hash=hashed_password, totp_secret=totp_secret)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_username(db: Session, username: str) -> UserORM | None:
    return db.query(UserORM).filter(UserORM.username == username).first()

def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_totp_reset(db: Session, username: str) -> TotpResetORM | None:
    return db.query(TotpResetORM).filter(TotpResetORM.username == username).first()

def create_totp_reset(db: Session, username: str, code: str, expires_at: int) -> TotpResetORM:
    # upsert simple: delete existing and insert fresh
    db.query(TotpResetORM).filter(TotpResetORM.username == username).delete()
    db_reset = TotpResetORM(username=username, code=code, expires_at=expires_at)
    db.add(db_reset)
    db.commit()
    db.refresh(db_reset)
    return db_reset

def delete_totp_reset(db: Session, username: str):
    db.query(TotpResetORM).filter(TotpResetORM.username == username).delete()
    db.commit()

def list_transactions(db: Session, limit: int = 500):
    return db.query(TransactionORM).order_by(TransactionORM.id.desc()).limit(limit).all()
