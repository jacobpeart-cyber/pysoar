"""Authentication endpoints with enhanced security"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, RedisClient
from src.models.user import User
from src.core.account_lockout import AccountLockoutManager
from src.core.config import settings
from src.core.password_policy import PasswordValidator
from src.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token_full,
    get_password_hash,
    verify_token,
)
from src.core.token_blacklist import TokenBlacklist
from src.schemas.auth import (
    LoginRequest,
    MFARequiredResponse,
    PasswordChangeRequest,
    RefreshTokenRequest,
    TokenResponse,
)
from src.schemas.user import UserResponse
from src.services.user_service import UserService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login")
async def login(
    request: LoginRequest,
    db: DatabaseSession = None,
    redis: RedisClient = None,
):
    """Authenticate user and return tokens or MFA challenge"""
    # Initialize account lockout manager
    lockout_manager = AccountLockoutManager(redis)

    # Check if account is locked
    is_locked, seconds_remaining = await lockout_manager.check_lockout(request.email)
    if is_locked:
        logger.warning(f"Login attempt on locked account: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked. Please try again later.",
        )

    # Authenticate user
    user_service = UserService(db)
    user = await user_service.authenticate(request.email, request.password)

    if not user:
        # Record failed attempt
        attempts_remaining, is_now_locked = await lockout_manager.record_failed_attempt(
            request.email
        )
        logger.warning(
            f"Failed login attempt for {request.email}. "
            f"Attempts remaining: {attempts_remaining}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Reset failed attempts on successful authentication
    await lockout_manager.reset_attempts(request.email)

    # Check if user must change password
    if getattr(user, "force_password_change", False):
        logger.info(f"User {user.id} required to change password")
        limited_token = create_access_token(
            subject=user.id,
            expires_delta=timedelta(minutes=5),
            extra_claims={"type": "limited", "scope": "password_change"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required",
            headers={"X-Password-Change-Required": "true", "X-Limited-Token": limited_token},
        )

    # Check if MFA is enabled
    if getattr(user, "mfa_enabled", False):
        logger.info(f"MFA required for user {user.id}")
        mfa_token = create_access_token(
            subject=user.id,
            expires_delta=timedelta(minutes=5),
            extra_claims={"type": "mfa"},
        )
        return MFARequiredResponse(
            mfa_required=True,
            mfa_token=mfa_token,
            expires_in=300,
        )

    # Update last login
    await user_service.update_last_login(user.id)

    # Create tokens
    access_token = create_access_token(
        subject=user.id,
        extra_claims={"role": user.role},
    )
    refresh_token = create_refresh_token(subject=user.id)

    logger.info(f"Successful login for user {user.id}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token_endpoint(
    request: RefreshTokenRequest,
    db: DatabaseSession = None,
):
    """Refresh access token using refresh token"""
    user_id = verify_token(request.refresh_token, token_type="refresh")

    if not user_id:
        logger.warning("Refresh attempt with invalid or expired refresh token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_service = UserService(db)
    user = await user_service.get_by_id(user_id)

    if not user or not user.is_active:
        logger.warning(f"Refresh attempt for inactive/missing user: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Create new tokens
    access_token = create_access_token(
        subject=user.id,
        extra_claims={"role": user.role},
    )
    refresh_token = create_refresh_token(subject=user.id)

    logger.info(f"Token refreshed for user {user.id}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: CurrentUser = None,
):
    """Get current authenticated user info"""
    return current_user


@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    redis: RedisClient = None,
):
    """Change current user's password"""
    user_service = UserService(db)

    # Validate new password
    is_valid, errors = PasswordValidator.validate(
        request.new_password,
        settings={"email": current_user.email},
    )

    if not is_valid:
        logger.warning(f"Password validation failed for user {current_user.id}: {errors}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password does not meet requirements",
        )

    try:
        await user_service.change_password(
            user_id=current_user.id,
            current_password=request.current_password,
            new_password=request.new_password,
        )

        # Revoke all user tokens after password change (A2 fix)
        blacklist = TokenBlacklist(redis)
        blacklist.revoke_all_user_tokens(current_user.id)

        # Clear force_password_change flag if it exists
        if hasattr(current_user, "force_password_change"):
            await user_service.update(
                current_user.id,
                force_password_change=False,
            )

        logger.info(f"Password changed for user {current_user.id}")

    except Exception as e:
        logger.error(f"Password change failed for user {current_user.id}: {e}")
        # B4 fix: Generic error message
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to change password",
        )

    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(
    current_user: CurrentUser = None,
    redis: RedisClient = None,
):
    """Logout current user by revoking all tokens"""
    blacklist = TokenBlacklist(redis)
    blacklist.revoke_all_user_tokens(current_user.id)
    logger.info(f"User {current_user.id} logged out")
    return {"message": "Logged out successfully"}


@router.post("/revoke-all")
async def revoke_all_tokens(
    current_user: CurrentUser = None,
    redis: RedisClient = None,
):
    """Revoke all tokens for current user (security incident endpoint)"""
    blacklist = TokenBlacklist(redis)
    blacklist.revoke_all_user_tokens(current_user.id)
    logger.warning(f"All tokens revoked for user {current_user.id}")
    return {"message": "All tokens have been revoked"}


# ---------------------------------------------------------------------------
# MFA alias routes
#
# The frontend SettingsPage calls POST /auth/mfa/enable and POST /auth/mfa/verify,
# while the real MFA implementation is mounted at /mfa/setup and /mfa/verify-setup.
# These aliases forward to the existing MFAManager to avoid duplicating logic.
# ---------------------------------------------------------------------------


@router.post("/mfa/enable")
async def mfa_enable_alias(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Generate a TOTP secret + provisioning URI for the caller.

    Mirrors /mfa/setup. Returns ``secret``, ``provisioning_uri`` (otpauth URL
    the frontend renders as a QR code), and a set of plaintext ``backup_codes``
    shown exactly once. The secret is NOT persisted until the user confirms
    via POST /auth/mfa/verify with a valid 6-digit code.
    """
    from src.core.mfa import MFAManager

    secret = MFAManager.generate_secret()
    provisioning_uri = MFAManager.get_provisioning_uri(
        secret=secret,
        email=current_user.email,
        issuer="PySOAR",
    )
    if not provisioning_uri:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate MFA setup",
        )
    backup_codes = MFAManager.generate_backup_codes()
    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "backup_codes": backup_codes,
    }


@router.post("/mfa/verify")
async def mfa_verify_alias(
    payload: dict,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Validate a 6-digit TOTP code against a provisioned secret and enable MFA.

    Accepts ``{"secret": "<base32>", "code": "123456"}``.
    """
    from src.core.mfa import MFAManager

    secret = payload.get("secret")
    code = payload.get("code")
    if not secret or not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Both 'secret' and 'code' are required",
        )

    if not MFAManager.verify_totp(secret, code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    backup_codes = MFAManager.generate_backup_codes()
    hashed_backup_codes = MFAManager.hash_backup_codes(backup_codes)

    user_service = UserService(db)
    await user_service.update(
        current_user.id,
        mfa_secret=secret,
        mfa_backup_codes=hashed_backup_codes,
        mfa_enabled=True,
    )
    return {
        "message": "MFA successfully enabled",
        "backup_codes": backup_codes,
    }


class PasswordResetTokenRequest(BaseModel):
    token: str = Field(min_length=48, max_length=256)


class PasswordResetValidateResponse(BaseModel):
    valid: bool
    expires_at: datetime


@router.post(
    "/password-reset/validate",
    response_model=PasswordResetValidateResponse,
    summary="Validate a password-reset token without consuming it",
)
async def password_reset_validate(
    payload: PasswordResetTokenRequest,
    db: DatabaseSession = None,
) -> PasswordResetValidateResponse:
    """Look up the token. Return 200 with the expiry if valid and unexpired,
    410 if expired, 404 if unknown. Generic error wording avoids confirming
    whether a guessed token exists in the system (enumeration defense)."""
    stmt = select(User).where(User.password_reset_token == payload.token)
    user = (await db.execute(stmt)).scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="Invalid or expired token")
    now_utc = datetime.now(timezone.utc)
    expires_at = user.password_reset_token_expires_at
    # SQLite returns naive datetimes from tz-aware columns; Postgres returns
    # aware. Normalize the stored value to tz-aware UTC so the comparison
    # works on both backends without crashing.
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at is None or expires_at < now_utc:
        raise HTTPException(status_code=410, detail="Invalid or expired token")
    return PasswordResetValidateResponse(
        valid=True,
        expires_at=user.password_reset_token_expires_at,
    )


class PasswordResetConsumeRequest(BaseModel):
    token: str = Field(min_length=48, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post(
    "/password-reset/consume",
    summary="Consume a password-reset token and set a new password",
)
async def password_reset_consume(
    payload: PasswordResetConsumeRequest,
    db: DatabaseSession = None,
) -> dict:
    """Burn the token, set the new password hash.

    Returns 200 with a generic body — never echoes the email or user_id so a
    successful response doesn't leak account identity to whoever submits the
    token. The downstream login flow is where the user proves identity.

    Timing-equalization: bcrypt the supplied password BEFORE the validity
    branch so the response latency for invalid/expired tokens matches the
    successful path. Without this, an attacker probing token space sees
    a measurable latency spike on the rare 'token found but expired' case
    that would help them differentiate valid tokens.
    """
    # Compute the new hash up-front so failure paths spend the same cycles
    # as the success path. The dummy result is discarded on failure.
    new_hash = get_password_hash(payload.new_password)

    stmt = select(User).where(User.password_reset_token == payload.token)
    user = (await db.execute(stmt)).scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="Invalid or expired token")

    # SQLite returns naive datetime from tz-aware columns; Postgres returns
    # aware. Normalize so the comparison works on both backends without
    # crashing with TypeError("can't compare offset-naive and offset-aware").
    now_utc = datetime.now(timezone.utc)
    expires_at = user.password_reset_token_expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at is None or expires_at < now_utc:
        raise HTTPException(status_code=410, detail="Invalid or expired token")

    user.hashed_password = new_hash
    user.password_reset_token = None
    user.password_reset_token_expires_at = None
    # NOTE: do NOT touch force_password_change here. Other policy code
    # (90-day rotation, post-incident force-change, etc.) owns that flag;
    # the reset flow has no business overriding their decisions.
    await db.commit()

    return {"status": "password_updated"}
