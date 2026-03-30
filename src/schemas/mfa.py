"""MFA (Multi-Factor Authentication) schemas"""

from typing import Optional

from pydantic import BaseModel


class MFASetupResponse(BaseModel):
    """MFA setup response with secret and provisioning URI"""

    secret: str
    provisioning_uri: str
    backup_codes: list[str]


class MFAVerifySetupRequest(BaseModel):
    """MFA setup verification request"""

    code: str
    secret: str


class MFAVerifyLoginRequest(BaseModel):
    """MFA login verification request"""

    code: str
    mfa_token: str


class MFAVerifyResponse(BaseModel):
    """MFA verification response with tokens"""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    backup_codes: Optional[list[str]] = None


class MFARequiredResponse(BaseModel):
    """MFA required response for login"""

    mfa_required: bool = True
    mfa_token: str
    expires_in: int


class MFADisableRequest(BaseModel):
    """MFA disable request"""

    code: str


class MFABackupCodesRequest(BaseModel):
    """MFA backup codes regeneration request"""

    code: str
