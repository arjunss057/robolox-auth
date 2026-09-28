import pyotp
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import os
from dotenv import load_dotenv

from .database import Base, engine, get_db
from .models import User
from .schemas import RegisterRequest, LoginRequest, TotpVerifyRequest, TokenResponse
from .auth import hash_password, verify_password, create_access_token, create_pre_auth_token, verify_pre_auth_token

load_dotenv()
FRONT_END_ORIGIN = os.getenv("FRONT_END_ORIGIN")

app = FastAPI(
    title="Robolox server",
    description="Demo service with password + TOTP authentication"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONT_END_ORIGIN, ],
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"]
)

Base.metadata.create_all(bind=engine)

security = HTTPBearer()

@app.get("/")
def root():
    return {
        "service": "Robolox server",
        "status": "running"
    }

@app.get("/get-data")
def get_data(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.delete("/delete/{user_id}")
def do_delete(user_id: int, db: Session = Depends(get_db)):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )
    db.delete(user)
    db.commit()

    return {
        "message": "Account deleted successfully"
    }

@app.post("/register")
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.username == request.username).first()
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    password_hash = hash_password(request.password)
    totp_secret = pyotp.random_base32()

    user = User(
        username = request.username,
        password_hash = password_hash,
        totp_secret = totp_secret,
        totp_enabled = True
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    login_token = create_pre_auth_token(user.id)

    return {
        "message": "User created",
        "user_id": user.id,
        "totp_secret": totp_secret,
        "login_token": login_token
    }

@app.post("/login")
def login(
    request: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == request.username).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    login_token = create_pre_auth_token(user.id)

    return {
        "login_token": login_token,
        "requires_totp": True,
        "user_id": user.id
    }

@app.post("/verify-totp", response_model=TokenResponse)
def verify_totp(
    request: TotpVerifyRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    pre_auth_token = credentials.credentials
    user_id = verify_pre_auth_token(pre_auth_token)
    print(pre_auth_token, user_id)
    user = db.query(User).filter(User.id == user_id).first()
    print(user)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    print("passed 1st if")

    if not user.totp_enabled:
        raise HTTPException(
            status_code=400,
            detail="TOTP is not enabled"
        )
    print("passed 2nd if")

    totp = pyotp.TOTP(user.totp_secret)

    if not totp.verify(request.code, valid_window=1):
        raise HTTPException(
            status_code=401,
            detail="Invalid TOTP"
        )
    print("passed third if")

    access_token = create_access_token(user.id)
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
