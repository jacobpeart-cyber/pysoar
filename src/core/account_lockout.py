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
        self.redis = redis_client
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration_seconds

    async def record_failed_attempt(self, identifier: str) -> Tuple[int, bool]:
        if not identifier:
            logger.warning("Invalid identifier for failed attempt recording")
            return (0, True)

        key = f"{self.LOCKOUT_KEY_PREFIX}{identifier}"

        try:
            current_attempts = await self.redis.get(key)
            current_attempts = int(current_attempts) if current_attempts else 0

            new_attempts = current_attempts + 1
            lockout_expiry = int(time.time()) + self.lockout_duration

            pipe = self.redis.pipeline()
            pipe.set(key, new_attempts)
            pipe.expireat(key, lockout_expiry)
            await pipe.execute()

            attempts_remaining = max(0, self.max_attempts - new_attempts)
            is_locked = new_attempts >= self.max_attempts

            if is_locked:
                logger.warning(f"Account locked after {new_attempts} failed attempts: {identifier}")
            else:
                logger.info(f"Failed attempt recorded for {identifier}: {new_attempts}/{self.max_attempts}")

            return (attempts_remaining, is_locked)

        except Exception as e:
            logger.error(f"Redis error recording failed attempt for {identifier}: {e}")
            return (0, True)

    async def check_lockout(self, identifier: str) -> Tuple[bool, Optional[int]]:
        if not identifier:
            logger.warning("Invalid identifier for lockout check")
            return (True, self.lockout_duration)

        key = f"{self.LOCKOUT_KEY_PREFIX}{identifier}"

        try:
            attempts = await self.redis.get(key)

            if attempts is None:
                return (False, None)

            attempts = int(attempts)

            if attempts >= self.max_attempts:
                ttl = await self.redis.ttl(key)
                seconds_remaining = ttl if ttl > 0 else self.lockout_duration
                return (True, seconds_remaining)

            return (False, None)

        except Exception as e:
            logger.error(f"Redis error checking lockout for {identifier}: {e}")
            return (True, self.lockout_duration)

    async def reset_attempts(self, identifier: str) -> bool:
        if not identifier:
            logger.warning("Invalid identifier for reset")
            return False

        key = f"{self.LOCKOUT_KEY_PREFIX}{identifier}"

        try:
            await self.redis.delete(key)
            logger.info(f"Attempts reset for {identifier}")
            return True
        except Exception as e:
            logger.error(f"Redis error resetting attempts for {identifier}: {e}")
            return False
