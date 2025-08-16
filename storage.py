from sqlalchemy import Column, String, Integer, Float, DateTime, BINARY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base  # Change relative import to absolute import

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
    expires_at = Column(Integer)

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
    from database import SessionLocal
    engine = create_engine("DATABASE_URL")  # Replace with your actual DB URL
    Base.metadata.create_all(bind=engine)

# Helper functions for password hashing and TOTP resets
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_user(db: Session, username: str, password: str):
    hashed_password = pwd_context.hash(password)
    db_user = UserORM(username=username, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_username(db: Session, username: str):
    return db.query(UserORM).

