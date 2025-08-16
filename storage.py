from sqlalchemy import Column, String, Integer, Float, DateTime, BINARY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base  # Assuming you have a `Base` class that maps to your database

# User model (for login and password storage)
class UserORM(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    password_hash = Column(String)

# TOTP requests table
class TotpResetORM(Base):
    __tablename__ = "totp_resets"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    code = Column(String)
    expires_at = Column(BigInteger)

# Transaction model
class TransactionORM(Base):
    __tablename__ = 'transactions'
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=func.now())
    amount = Column(Float)
    currency = Column(String)
    protocol = Column(String)
    auth_code = Column(String)
    masked_pan = Column(String)
    status = Column(String)
    step_0210 = Column(BINARY)  # Store step 0210 as a binary field
    step_0230 = Column(BINARY)  # Store step 0230 as a binary field
    step_0510 = Column(BINARY)  # Store step 0510 as a binary field
    receipt_id = Column(String)

# Initialize database with Base
def init_db():
    from sqlalchemy import create_engine
    from .database import SessionLocal
    engine = create_engine("DATABASE_URL")  # Replace with your actual DB URL
    Base.metadata.create_all(bind=engine)

# Helper functions for password hashing and TOTP resets
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_user(db: Session, username: str, password: str):
    hashed_password = pwd_context.hash(password)
    db_user = UserORM(username=username, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_username(db: Session, username: str):
    return db.query(UserORM).filter(UserORM.username == username).first()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_totp_reset(db: Session, username: str):
    return db.query(TotpResetORM).filter(TotpResetORM.username == username).first()

def create_totp_reset(db: Session, username: str, code: str, expires_at: int):
    db_reset = TotpResetORM(username=username, code=code, expires_at=expires_at)
    db.add(db_reset)
    db.commit()
    db.refresh(db_reset)
    return db_reset

def delete_totp_reset(db: Session, username: str):
    db.query(TotpResetORM).filter(TotpResetORM.username == username).delete()
    db.commit()
