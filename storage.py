from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from models import UserORM  # Assuming UserORM is defined in your models

DATABASE_URL = "sqlite:///./test.db"  # Adjust the database URL as per your setup

# Create engine
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base
Base = declarative_base()

# Dependency for getting database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Function to get all users (updated)
def get_all_users(db):
    return db.query(UserORM).all()

# Function to get user by username (updated)
def get_user_by_username(db, username: str):
    return db.query(UserORM).filter(UserORM.username == username).first()

# Other database functions as required


