"""
Redis-backed token blacklist for JWT revocation.

The client is the application's async Redis client, so every method is a
coroutine. The keys are the ones ``src.api.deps.get_current_user`` checks on
every request (``blacklist:<jti>`` and ``revoke:<user_id>``); before wave 5 the
class wrote different keys and never awaited the client, so logout, revoke-all
and the post-password-change revocation silently did nothing.
"""

import logging

logger = logging.getLogger(__name__)


class TokenBlacklist:
    """Manages JWT token revocation and user revocation timestamps."""

    REVOKED_TOKEN_PREFIX = "blacklist:"
    USER_REVOKED_PREFIX = "revoke:"
    #: Per-user token generation. Every token carries the generation it was
    #: issued under (``gen`` claim); revoking all tokens increments it, and the
    #: auth dependency refuses any token whose generation is older. No clock
    #: comparison, so a token issued in the same second as a revocation is
    #: judged by its generation, never by timing.
    USER_GENERATION_PREFIX = "revoke_gen:"
    CLOCK_SKEW_BUFFER = 5  # seconds

    def __init__(self, redis_client):
        """
        Initialize TokenBlacklist with Redis client.

        Args:
            redis_client: Redis client instance for persistent storage
        """
        self.redis = redis_client

    async def revoke_token(self, jti: str, expires_in: int) -> bool:
        """
        Revoke a specific token by its JTI (JWT ID).

        Args:
            jti: JWT ID to revoke
            expires_in: Token expiration time in seconds (used as TTL)

        Returns:
            bool: True if successfully revoked, False on error
        """
        if not jti or expires_in < 0:
            logger.warning(f"Invalid revocation request: jti={jti}, expires_in={expires_in}")
            return False

        key = f"{self.REVOKED_TOKEN_PREFIX}{jti}"
        try:
            # Store with TTL matching original token expiration
            await self.redis.setex(key, expires_in, "revoked")
            logger.info(f"Token revoked: {jti}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token {jti}: {e}")
            return False

    async def revoke_all_user_tokens(self, user_id: str) -> bool:
        """
        Revoke all tokens for a user by storing revocation timestamp.

        Args:
            user_id: User identifier to revoke all tokens for

        Returns:
            bool: True if successfully revoked, False on error
        """
        if not user_id:
            logger.warning("Invalid user_id for revocation")
            return False

        key = f"{self.USER_REVOKED_PREFIX}{user_id}"
        try:
            # Store current timestamp (in seconds since epoch)
            import time
            revocation_time = int(time.time())
            await self.redis.set(key, revocation_time)
            await self.redis.incr(f"{self.USER_GENERATION_PREFIX}{user_id}")
            logger.info(f"All tokens revoked for user: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke all tokens for user {user_id}: {e}")
            return False

    async def is_revoked(self, jti: str) -> bool:
        """
        Check if a specific token (by JTI) has been revoked.

        Args:
            jti: JWT ID to check

        Returns:
            bool: True if token is revoked, False otherwise
        """
        if not jti:
            logger.warning("Invalid jti for revocation check")
            return False

        key = f"{self.REVOKED_TOKEN_PREFIX}{jti}"
        try:
            result = await self.redis.exists(key)
            return bool(result)
        except Exception as e:
            logger.error(f"Error checking token revocation for {jti}: {e}")
            # Fail closed: treat as revoked on error
            return True

    async def is_user_revoked(self, user_id: str, token_iat: int) -> bool:
        """
        Check if a user was revoked after the token was issued.

        Args:
            user_id: User identifier
            token_iat: Token issued-at timestamp (Unix time in seconds)

        Returns:
            bool: True if user was revoked after token issuance, False otherwise
        """
        if not user_id or token_iat < 0:
            logger.warning(f"Invalid parameters for user revocation check: user_id={user_id}, token_iat={token_iat}")
            return False

        key = f"{self.USER_REVOKED_PREFIX}{user_id}"
        try:
            revocation_time_str = await self.redis.get(key)
            if revocation_time_str is None:
                return False

            revocation_time = int(revocation_time_str)
            # Apply clock skew buffer: token is considered revoked if user was revoked
            # after token issuance (with 5-second tolerance for clock drift)
            return revocation_time > (token_iat - self.CLOCK_SKEW_BUFFER)
        except (ValueError, TypeError) as e:
            logger.error(f"Error parsing revocation time for user {user_id}: {e}")
            # Fail closed: treat as revoked on error
            return True
        except Exception as e:
            logger.error(f"Error checking user revocation for {user_id}: {e}")
            # Fail closed: treat as revoked on error
            return True

    async def current_generation(self, user_id: str) -> int:
        """The generation new tokens for ``user_id`` must carry (0 until the
        first revocation). Raises on a Redis error so callers fail closed."""
        raw = await self.redis.get(f"{self.USER_GENERATION_PREFIX}{user_id}")
        return int(raw) if raw is not None else 0
