"""Authentication schemas"""

from typing import Optional

from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    """Login request schema"""

    email: EmailStr
    password: str = ""


class TokenResponse(BaseModel):
    """Token response schema"""

    access_token: str = ""
    refresh_token: str = ""
    token_type: str = "bearer"
    expires_in: int = 0


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema"""

    refresh_token: str = ""


class PasswordChangeRequest(BaseModel):
    """Password change request schema"""

    current_password: str = ""
    new_password: str = ""


class PasswordResetRequest(BaseModel):
    """Password reset request schema"""

    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema"""

    token: str = ""
    new_password: str = ""


class TokenPayload(BaseModel):
    """Token payload schema"""

    sub: str = ""
    exp: int = 0
    type: str = ""
    role: Optional[str] = None


class MFARequiredResponse(BaseModel):
    """MFA required response schema"""

    mfa_required: bool = True
    mfa_token: str = ""
    expires_in: int = 0
