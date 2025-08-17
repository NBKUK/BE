# storage.py
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy import create_engine
import os
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

def now_iso() -> str:
    return datetime.utcnow().isoformat()

# ------------------ User ORM ------------------
class UserORM(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # ✅ added role field

# ------------------ TOTP Reset ORM ------------------
class TotpResetORM(Base):
    __tablename__ = "totp_resets"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reset_token = Column(String(128), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("UserORM")

# ------------------ Transaction ORM ------------------
class TransactionORM(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    created_at = Column(String(40), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(8), nullable=False)
    protocol = Column(String(64), nullable=False)
    auth_code = Column(String(12), nullable=False)
    masked_pan = Column(String(32), nullable=False)
    status = Column(String(24), nullable=False)
    step_0210 = Column(Text)
    step_0230 = Column(Text)
    step_0510 = Column(Text)
    receipt_id = Column(String(64), nullable=False, unique=True)
    payout_status = Column(String(128), nullable=True)  # ✅ already correct

# ------------------ DB Helpers ------------------
def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
