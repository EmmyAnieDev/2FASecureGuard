from pydantic import BaseModel, EmailStr
from typing import Optional


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserLogin(UserBase):
    password: str
    otp_code: Optional[str] = None



class TokenData(BaseModel):
    email: Optional[str] = None


class TOTPVerifyRequest(BaseModel):
    token: str


class TOTPDisableRequest(BaseModel):
    password: str
    token: str