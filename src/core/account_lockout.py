"""
Redis-backed account lockout manager.
Implements rate limiting and account lockout protection against brute-force attacks.
"""

import logging
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class AccountLockoutManager:
    """Manages failed login attempts and account lockout state."""

    LOCKOUT_KEY_PREFIX = "lockout:"
    DEFAULT_MAX_ATTEMPTS = 5
    DEFAULT_LOCKOUT_DURATION = 900  # 15 minutes in seconds

    def __init__(
        self,
        redis_client,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        lockout_duration_seconds: int = DEFAULT_LOCKOUT_DURATION,
    ):
        """
        Initialize AccountLockoutManager with Redis client and lockout parameters.

        Args:
            redis_client: Redis client instance for persistent storage
            max_attempts: Maximum failed login attempts before lockout
            lockout_duration_seconds: Duration of account lockout in seconds
        """
        self.redis = redis_client
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration_seconds

    def record_failed_attempt(self, identifier: str) -> Tuple[int, bool]:
        """
        Record a failed login attempt for an identifier (username/email).

        Uses absolute EXPIRE time (EXPIREAT) to prevent permanent lockout from
        continuous failed attempts resetting the TTL.

        Args:
            identifier: Username, email, or IP address to track

        Returns:
            tuple: (attempts_remaining, is_now_locked)
                - attempts_remaining: Number of attempts left before lockout (0 if locked)
                - is_now_locked: True if account is now locked after this attempt
        """
        if not identifier:
            logger.warning("Invalid identifier for failed attempt recording")
            return (0, True)

        key = f"{self.LOCKOUT_KEY_PREFIX}{identifier}"

        try:
            # Get current attempt count
            current_attempts = self.redis.get(key)
            current_attempts = int(current_attempts) if current_attempts else 0

            # Increment attempt counter
            new_attempts = current_attempts + 1

            # Calculate lockout expiration time (absolute UNIX timestamp)
            lockout_expiry = int(time.time()) + self.lockout_duration

            # Use pipeline for atomic operations
            pipe = self.redis.pipeline()
            pipe.set(key, new_attempts)
            pipe.expireat(key, lockout_expiry)  # B2 fix: Use absolute expiry time
            pipe.execute()

            attempts_remaining = max(0, self.max_attempts - new_attempts)
            is_locked = new_attempts >= self.max_attempts

            if is_locked:
                logger.warning(f"Account locked after {new_attempts} failed attempts: {identifier}")
            else:
                logger.info(f"Failed attempt recorded for {identifier}: {new_attempts}/{self.max_attempts}")

            return (attempts_remaining, is_locked)

        except Exception as e:
            logger.error(f"Redis error recording failed attempt for {identifier}: {e}")
            # B2 fix: FAIL CLOSED - return locked state on error
            return (0, True)

    def check_lockout(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Check if an account is currently locked.

        Args:
            identifier: Username, email, or IP address to check

        Returns:
            tuple: (is_locked, seconds_remaining)
                - is_locked: True if account is locked
                - seconds_remaining: TTL in seconds (None if not locked, lockout_duration if error)
        """
        if not identifier:
            logger.warning("Invalid identifier for lockout check")
            return (True, self.lockout_duration)

        key = f"{self.LOCKOUT_KEY_PREFIX}{identifier}"

        try:
            # Check if key exists and get TTL
            attempts = self.redis.get(key)

            if attempts is None:
                # Not locked
                return (False, None)

            attempts = int(attempts)

            # If attempts >= max, account is locked
            if attempts >= self.max_attempts:
                ttl = self.redis.ttl(key)
                # ttl is -1 if key exists but has no expiry (shouldn't happen)
                # ttl is -2 if key doesn't exist (shouldn't happen, we checked above)
                seconds_remaining = ttl if ttl > 0 else self.lockout_duration
                return (True, seconds_remaining)

            return (False, None)

        except Exception as e:
            logger.error(f"Redis error checking lockout for {identifier}: {e}")
            # B2 fix: FAIL CLOSED - return locked state on error
            return (True, self.lockout_duration)

    def reset_attempts(self, identifier: str) -> bool:
        """
        Reset failed attempts for an identifier after successful login.

        Args:
            identifier: Username, email, or IP address to reset

        Returns:
            bool: True if successfully reset, False on error
        """
        if not identifier:
            logger.warning("Invalid identifier for reset")
            return False

        key = f"{self.LOCKOUT_KEY_PREFIX}{identifier}"

        try:
            self.redis.delete(key)
            logger.info(f"Attempts reset for {identifier}")
            return True
        except Exception as e:
            logger.error(f"Redis error resetting attempts for {identifier}: {e}")
            return False
