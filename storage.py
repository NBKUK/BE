import os
import datetime as _dt
from typing import Generator

from sqlalchemy import create_engine, Integer, Float, String, Text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

# --- SQLAlchemy Base ---
class Base(DeclarativeBase):
    pass

# --- ORM for transactions history ---
class TransactionORM(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)

    amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(8), nullable=False)

    protocol: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_code: Mapped[str] = mapped_column(String(16), nullable=False)

    masked_pan: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)

    # raw response snapshots (base64)
    step_0210: Mapped[str] = mapped_column(Text, nullable=True)
    step_0230: Mapped[str] = mapped_column(Text, nullable=True)
    step_0510: Mapped[str] = mapped_column(Text, nullable=True)

    # external receipt id (UUID string)
    receipt_id: Mapped[str] = mapped_column(String(64), nullable=False)

# --- Engine & session ---
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

def init_db() -> None:
    Base.metadata.create_all(bind=engine)

def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def now_iso() -> str:
    # Always UTC in ISO8601, no microseconds
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
