"""Caching layer using Redis with decorator support"""

import json
from functools import wraps
from typing import Any, Callable, Dict, Optional

from redis.asyncio import Redis

from src.core.logging import get_logger

logger = get_logger(__name__)


class CacheService:
    """Redis-backed caching service with helper methods"""

    def __init__(self, redis_client: Redis):
        """
        Initialize cache service

        Args:
            redis_client: Redis async client
        """
        self.redis = redis_client

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found or expired
        """
        try:
            value = await self.redis.get(key)
            if value is None:
                return None

            # Try to deserialize as JSON
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                # Return as string if not JSON
                return value.decode() if isinstance(value, bytes) else value

        except Exception as e:
            logger.warning(f"Cache get error for key {key}: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set value in cache

        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time to live in seconds (None = no expiration)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Serialize to JSON
            if isinstance(value, (dict, list)):
                serialized = json.dumps(value)
            else:
                serialized = str(value)

            if ttl:
                await self.redis.setex(key, ttl, serialized)
            else:
                await self.redis.set(key, serialized)

            return True

        except Exception as e:
            logger.warning(f"Cache set error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache

        Args:
            key: Cache key

        Returns:
            True if key existed, False otherwise
        """
        try:
            result = await self.redis.delete(key)
            return result > 0

        except Exception as e:
            logger.warning(f"Cache delete error for key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache

        Args:
            key: Cache key

        Returns:
            True if key exists, False otherwise
        """
        try:
            result = await self.redis.exists(key)
            return result > 0

        except Exception as e:
            logger.warning(f"Cache exists error for key {key}: {e}")
            return False

    async def get_or_set(
        self,
        key: str,
        factory_fn: Callable,
        ttl: Optional[int] = 300,
    ) -> Any:
        """
        Get value from cache or compute and set it (cache-aside pattern)

        Args:
            key: Cache key
            factory_fn: Async function to generate value if not cached
            ttl: Time to live in seconds (default 5 minutes)

        Returns:
            Cached or newly computed value
        """
        # Try to get from cache
        cached = await self.get(key)
        if cached is not None:
            logger.debug(f"Cache hit for key {key}")
            return cached

        logger.debug(f"Cache miss for key {key}, computing value")

        try:
            # Compute value
            value = await factory_fn()

            # Store in cache
            await self.set(key, value, ttl)

            return value

        except Exception as e:
            logger.error(f"Error in cache factory for key {key}: {e}")
            raise

    async def invalidate_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching pattern using SCAN

        Args:
            pattern: Redis key pattern (supports wildcards)

        Returns:
            Number of keys deleted
        """
        try:
            keys_deleted = 0
            cursor = 0

            while True:
                cursor, keys = await self.redis.scan(cursor, match=pattern)
                if keys:
                    await self.redis.delete(*keys)
                    keys_deleted += len(keys)

                if cursor == 0:
                    break

            logger.debug(f"Invalidated {keys_deleted} cache keys matching {pattern}")
            return keys_deleted

        except Exception as e:
            logger.warning(f"Cache invalidate_pattern error for {pattern}: {e}")
            return 0

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache stats
        """
        try:
            info = await self.redis.info("stats")
            memory_info = await self.redis.info("memory")

            return {
                "total_connections_received": info.get("total_connections_received", 0),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "used_memory_bytes": memory_info.get("used_memory", 0),
                "used_memory_human": memory_info.get("used_memory_human", ""),
                "evicted_keys": info.get("evicted_keys", 0),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
            }

        except Exception as e:
            logger.warning(f"Cache stats error: {e}")
            return {}


def cache_decorator(ttl: int = 300, key_prefix: str = ""):
    """
    Decorator for caching async function results

    Args:
        ttl: Time to live in seconds
        key_prefix: Prefix for cache keys

    Usage:
        @cache_decorator(ttl=600, key_prefix="user_data")
        async def get_user(user_id: int) -> User:
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(cache_service: CacheService, *args, **kwargs):
            # Build cache key
            key_parts = [key_prefix or func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}={v}" for k, v in kwargs.items())
            cache_key = ":".join(key_parts)

            # Try to get from cache
            cached = await cache_service.get(cache_key)
            if cached is not None:
                return cached

            # Compute and cache
            result = await func(*args, **kwargs)
            await cache_service.set(cache_key, result, ttl)

            return result

        return wrapper

    return decorator


class CacheInvalidator:
    """Helper for invalidating cache after data changes"""

    def __init__(self, cache_service: CacheService):
        """
        Initialize invalidator

        Args:
            cache_service: CacheService instance
        """
        self.cache = cache_service

    async def invalidate_user_cache(self, user_id: int):
        """Invalidate all cache entries for a user"""
        await self.cache.invalidate_pattern(f"user:{user_id}:*")
        logger.debug(f"Invalidated cache for user {user_id}")

    async def invalidate_alert_cache(self, alert_id: int):
        """Invalidate all cache entries for an alert"""
        await self.cache.invalidate_pattern(f"alert:{alert_id}:*")
        logger.debug(f"Invalidated cache for alert {alert_id}")

    async def invalidate_incident_cache(self, incident_id: int):
        """Invalidate all cache entries for an incident"""
        await self.cache.invalidate_pattern(f"incident:{incident_id}:*")
        logger.debug(f"Invalidated cache for incident {incident_id}")
