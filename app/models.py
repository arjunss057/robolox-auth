from sqlalchemy import Column, Integer, String, Boolean

from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    totp_secret = Column(String, nullable=False)
    totp_enabled = Column(Boolean, default=True, nullable=False)
