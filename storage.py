from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Set up database connection string (adjust as per your setup)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")  # Example using SQLite

# Create engine and session
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for ORM models
Base = declarative_base()

# Initialize the database by creating tables
def init_db():
    # Create all tables in the database
    Base.metadata.create_all(bind=engine)

# Database session function for FastAPI usage
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

