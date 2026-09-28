import os
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException
from jose import JWTError, jwt
from dotenv import load_dotenv

PASSWORD_HASHER = PasswordHasher()

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES"))
PRE_AUTH_EXPIRE_MINUTES = int(os.getenv("PRE_AUTH_EXPIRE_MINUTES"))

def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False

def create_pre_auth_token(user_id: int) -> dict:
    expire = datetime.now(timezone.utc) + timedelta(minutes=PRE_AUTH_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "type": "pre_auth",
        "exp": expire
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_access_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "type": "access",
        "exp": expire
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_pre_auth_token(token: str) -> int:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "pre_auth":
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication stage"
            )
        return int(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired login token"
        )

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=401,
                detail="Invalid token type"
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
