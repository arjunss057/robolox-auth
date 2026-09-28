from pydantic import BaseModel

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TotpVerifyRequest(BaseModel):
    username: str
    code: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
