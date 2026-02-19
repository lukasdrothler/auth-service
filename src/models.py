from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class User(BaseModel):
    id: str
    username: str
    email: str
    email_verified: bool = False
    is_admin: bool = False
    premium_level: int = 0
    stripe_customer_id: Optional[str] = None
    disabled: bool = False


class UserInDBNoPassword(User):
    created_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class UserInDB(UserInDBNoPassword):
    hashed_password: str


class CreateUser(BaseModel):
    username: str
    email: str
    password: str


class LoginCredentials(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class CreateVerificationCodeResponse(BaseModel):
    username: str
    email: str
    value: str

class VerificationCode(BaseModel):
    user_id: str
    value: str
    created_at: datetime
    verified_at: Optional[datetime] = None


class VerifyEmailRequest(BaseModel):
    code: str
    email: str


class SendVerificationRequest(BaseModel):
    email: str


class UpdateUser(BaseModel):
    username: Optional[str] = None


class UpdatePassword(BaseModel):
    current_password: str
    new_password: str


class UpdateForgottenPassword(BaseModel):
    email: str
    new_password: str
    verification_code: str


class UpdateUserPremiumLevel(BaseModel):
    new_premium_level: int
    stripe_customer_id: Optional[str] = None


class MailRequest(BaseModel):
    template_name: str
    username: str
    recipient: str
    verification_code: Optional[str] = None
    subject: Optional[str] = None