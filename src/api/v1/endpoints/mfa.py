"""MFA (Multi-Factor Authentication) endpoints"""

import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from src.api.deps import CurrentUser, DatabaseSession, RedisClient
from src.core.config import settings
from src.core.mfa import MFAManager
from src.core.security import create_access_token, create_refresh_token, decode_token_full, verify_token
from src.core.token_blacklist import TokenBlacklist
from src.models.user import User
from src.schemas.mfa import (
    MFABackupCodesRequest,
    MFADisableRequest,
    MFASetupResponse,
    MFAVerifyLoginRequest,
    MFAVerifyResponse,
    MFAVerifySetupRequest,
)
from src.services.user_service import UserService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mfa", tags=["MFA"])


@router.post("/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Generate MFA secret and provisioning URI for setup"""
    logger.info(f"MFA setup initiated for user {current_user.id}")

    # Generate secret and provisioning URI
    secret = MFAManager.generate_secret()
    provisioning_uri = MFAManager.get_provisioning_uri(
        secret=secret,
        email=current_user.email,
        issuer="PySOAR",
    )

    # Generate backup codes (not persisted yet)
    backup_codes = MFAManager.generate_backup_codes()

    if not provisioning_uri:
        logger.error(f"Failed to generate provisioning URI for user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate MFA setup",
        )

    return MFASetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        backup_codes=backup_codes,
    )


@router.post("/verify-setup")
async def verify_mfa_setup(
    request: MFAVerifySetupRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Verify TOTP code and persist MFA configuration"""
    logger.info(f"MFA setup verification initiated for user {current_user.id}")

    # Verify TOTP code against provided secret
    is_valid = MFAManager.verify_totp(request.secret, request.code)

    if not is_valid:
        logger.warning(f"MFA setup verification failed for user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    try:
        # Generate and hash backup codes
        backup_codes = MFAManager.generate_backup_codes()
        hashed_backup_codes = MFAManager.hash_backup_codes(backup_codes)

        # Persist encrypted secret and hashed backup codes
        user_service = UserService(db)
        await user_service.update(
            current_user.id,
            mfa_secret=request.secret,
            mfa_backup_codes=hashed_backup_codes,
            mfa_enabled=True,
        )

        logger.info(f"MFA successfully enabled for user {current_user.id}")

        return {
            "message": "MFA successfully enabled",
            "backup_codes": backup_codes,
        }

    except Exception as e:
        logger.error(f"Failed to persist MFA configuration for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable MFA",
        )


@router.post("/verify", response_model=MFAVerifyResponse)
async def verify_mfa_login(
    request: MFAVerifyLoginRequest,
    db: DatabaseSession = None,
    redis: RedisClient = None,
):
    """Verify MFA code during login and issue tokens"""
    logger.info("MFA login verification initiated")

    # Decode MFA token
    token_payload = decode_token_full(request.mfa_token)

    if not token_payload:
        logger.warning("Invalid MFA token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        )

    # Verify token type is "mfa"
    if token_payload.get("type") != "mfa":
        logger.warning("Token is not an MFA token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    user_id = token_payload.get("sub")

    # Load user
    user_service = UserService(db)
    user = await user_service.get_by_id(user_id)

    if not user or not user.is_active:
        logger.warning(f"MFA verification for invalid/inactive user: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    if not user.mfa_enabled:
        logger.warning(f"MFA verification for user without MFA enabled: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA not enabled for this user",
        )

    # Try TOTP verification first
    is_valid_totp = MFAManager.verify_totp(user.mfa_secret, request.code)

    if is_valid_totp:
        logger.info(f"MFA TOTP verification successful for user {user_id}")
    else:
        # Try backup code verification with locking (B1 fix)
        try:
            # Use SELECT FOR UPDATE to prevent race conditions
            db_user = await db.execute(
                select(User).where(User.id == user_id).with_for_update()
            )
            locked_user = db_user.scalar_one_or_none()

            if not locked_user or not locked_user.mfa_backup_codes:
                logger.warning(f"No backup codes available for user {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid verification code",
                )

            # Verify backup code
            is_valid_backup, code_hash_key = MFAManager.verify_backup_code(
                request.code,
                locked_user.mfa_backup_codes,
            )

            if not is_valid_backup:
                logger.warning(f"MFA backup code verification failed for user {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid verification code",
                )

            # Mark backup code as used
            locked_user.mfa_backup_codes[code_hash_key]["used"] = True
            await db.flush()

            logger.info(f"MFA backup code verification successful for user {user_id}")

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error during backup code verification for user {user_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid verification code",
            )

    # Blacklist MFA token after successful verification (B3 fix)
    blacklist = TokenBlacklist(redis)
    mfa_jti = token_payload.get("jti")
    if mfa_jti:
        blacklist.revoke_token(mfa_jti, expires_in=300)

    # Update last login
    await user_service.update_last_login(user_id)

    # Issue access and refresh tokens
    access_token = create_access_token(
        subject=user.id,
        extra_claims={"role": user.role},
    )
    refresh_token = create_refresh_token(subject=user.id)

    logger.info(f"Tokens issued after MFA verification for user {user_id}")

    return MFAVerifyResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/backup-codes")
async def regenerate_backup_codes(
    request: MFABackupCodesRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Regenerate backup codes after TOTP verification"""
    logger.info(f"Backup code regeneration initiated for user {current_user.id}")

    if not current_user.mfa_enabled:
        logger.warning(f"Backup code regeneration attempted by user without MFA: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not enabled",
        )

    # Verify TOTP code
    is_valid = MFAManager.verify_totp(current_user.mfa_secret, request.code)

    if not is_valid:
        logger.warning(f"TOTP verification failed for backup code regeneration: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code",
        )

    try:
        # Generate new backup codes and hash them
        backup_codes = MFAManager.generate_backup_codes()
        hashed_backup_codes = MFAManager.hash_backup_codes(backup_codes)

        # Update user with new backup codes
        user_service = UserService(db)
        await user_service.update(
            current_user.id,
            mfa_backup_codes=hashed_backup_codes,
        )

        logger.info(f"Backup codes regenerated for user {current_user.id}")

        return {
            "message": "Backup codes regenerated successfully",
            "backup_codes": backup_codes,
        }

    except Exception as e:
        logger.error(f"Failed to regenerate backup codes for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes",
        )


@router.post("/disable")
async def disable_mfa(
    request: MFADisableRequest,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Disable MFA after TOTP verification"""
    logger.info(f"MFA disable initiated for user {current_user.id}")

    if not current_user.mfa_enabled:
        logger.warning(f"Disable MFA attempted for user without MFA: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not enabled",
        )

    # Verify TOTP code
    is_valid = MFAManager.verify_totp(current_user.mfa_secret, request.code)

    if not is_valid:
        logger.warning(f"TOTP verification failed for MFA disable: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code",
        )

    try:
        # Disable MFA
        user_service = UserService(db)
        await user_service.update(
            current_user.id,
            mfa_enabled=False,
            mfa_secret=None,
            mfa_backup_codes=None,
        )

        logger.info(f"MFA successfully disabled for user {current_user.id}")

        return {
            "message": "MFA successfully disabled",
        }

    except Exception as e:
        logger.error(f"Failed to disable MFA for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable MFA",
        )
