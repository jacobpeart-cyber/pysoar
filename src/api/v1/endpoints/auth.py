"""Authentication endpoints"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.config import settings
from src.core.security import create_access_token, create_refresh_token, verify_token
from src.schemas.auth import (
    LoginRequest,
    PasswordChangeRequest,
    RefreshTokenRequest,
    TokenResponse,
)
from src.schemas.user import UserResponse
from src.services.user_service import UserService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    db: DatabaseSession,
):
    """Authenticate user and return tokens"""
    user_service = UserService(db)
    user = await user_service.authenticate(request.email, request.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Update last login
    await user_service.update_last_login(user.id)

    # Create tokens
    access_token = create_access_token(
        subject=user.id,
        extra_claims={"role": user.role},
    )
    refresh_token = create_refresh_token(subject=user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db: DatabaseSession,
):
    """Refresh access token using refresh token"""
    user_id = verify_token(request.refresh_token, token_type="refresh")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_service = UserService(db)
    user = await user_service.get_by_id(user_id)

    if not user or not user.is_active:
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

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: CurrentUser,
):
    """Get current authenticated user info"""
    return current_user


@router.post("/change-password")
async def change_password(
    request: PasswordChangeRequest,
    current_user: CurrentUser,
    db: DatabaseSession,
):
    """Change current user's password"""
    user_service = UserService(db)

    try:
        await user_service.change_password(
            user_id=current_user.id,
            current_password=request.current_password,
            new_password=request.new_password,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(current_user: CurrentUser):
    """Logout current user (client should discard tokens)"""
    # In a stateless JWT setup, logout is handled client-side
    # For stateful sessions, we would invalidate the token here
    return {"message": "Logged out successfully"}
