"""Security utilities for authentication and authorization"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4
import time

import bcrypt
from jose import JWTError, jwt

from src.core.config import settings

# Hardcoded algorithm allowlist - only symmetric HMAC algorithms permitted
_JWT_ALLOWED_ALGORITHMS = ["HS256", "HS384", "HS512"]

# Module-load validation: ensure configured algorithm is in allowlist
if settings.jwt_algorithm not in _JWT_ALLOWED_ALGORITHMS:
    raise ValueError(
        f"Invalid JWT algorithm '{settings.jwt_algorithm}'. "
        f"Allowed algorithms: {_JWT_ALLOWED_ALGORITHMS}"
    )

# Cache the validated algorithm at module load time
_JWT_ALGORITHM = settings.jwt_algorithm


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def create_access_token(
    subject: str | Any,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[dict] = None,
) -> str:
    """Create a JWT access token with revocation support"""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )

    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "type": "access",
        "jti": str(uuid4()),
        "iat": int(time.time()),
    }

    if extra_claims:
        to_encode.update(extra_claims)

    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=_JWT_ALGORITHM,
    )
    return encoded_jwt


def create_refresh_token(
    subject: str | Any,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT refresh token with revocation support"""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.refresh_token_expire_days
        )

    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid4()),
        "iat": int(time.time()),
    }

    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=_JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT token with type checking"""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=_JWT_ALLOWED_ALGORITHMS,
        )
        return payload
    except JWTError:
        return None


def decode_token_full(token: str) -> Optional[dict]:
    """Decode token without type checking, returning full payload"""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=_JWT_ALLOWED_ALGORITHMS,
        )
        return payload
    except JWTError:
        return None


def verify_token(token: str, token_type: str = "access") -> Optional[str]:
    """Verify a token and return the subject if valid"""
    payload = decode_token(token)
    if payload is None:
        return None

    if payload.get("type") != token_type:
        return None

    return payload.get("sub")
