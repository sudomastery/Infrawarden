from pydantic import BaseModel, EmailStr


class PreloginRequest(BaseModel):
    email: EmailStr


class PreloginResponse(BaseModel):
    kdf_salt: str  # base64
    kdf_ops_limit: int
    kdf_mem_limit: int


class LoginRequest(BaseModel):
    email: EmailStr
    auth_hash: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
