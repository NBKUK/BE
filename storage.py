from sqlalchemy import Column, String, Integer, Float, DateTime, BINARY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base  # Assuming you have a `Base` class that maps to your database

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

    # You can also define a relationship to other tables if needed, for example:
    # receipt = relationship("ReceiptORM", back_populates="transaction")

# Initialize database with Base
def init_db():
    # Assuming `Base` is from SQLAlchemy, you would create the tables like this:
    from sqlalchemy import create_engine
    from .database import SessionLocal
    engine = create_engine("DATABASE_URL")  # Replace with your actual DB URL
    Base.metadata.create_all(bind=engine)
