# storage.py (only the ORM shown; keep the rest of your file as before)
from sqlalchemy import Column, Integer, String, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine
import os
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

def now_iso() -> str:
    return datetime.utcnow().isoformat()

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
    payout_status = Column(String(128), nullable=True)  # <—— NEW

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
