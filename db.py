# db.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

import os

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./pos.db")
# Render/Postgres example: set DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/db

# sqlite needs check_same_thread for single-process usage
connect_args = {}
if DB_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DB_URL, echo=False, future=True, connect_args=connect_args)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    # Import ORM classes before create_all so metadata knows them
    from storage import UserORM, TotpResetORM, TransactionORM  # noqa
    Base.metadata.create_all(bind=engine)
