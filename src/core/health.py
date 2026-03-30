"""Health check service for production monitoring"""

import psutil
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from src.core.config import settings
from src.core.database import async_session_factory
from src.core.logging import get_logger

logger = get_logger(__name__)


class HealthChecker:
    """Comprehensive health checking for all system components"""

    def __init__(self, redis_client: Optional[Redis] = None):
        """Initialize health checker with optional Redis client"""
        self.redis_client = redis_client
        self.start_time = datetime.utcnow()

    async def check_database(self) -> Dict[str, Any]:
        """
        Check PostgreSQL database connectivity and query latency

        Returns:
            dict with status, latency_ms, message
        """
        try:
            async with async_session_factory() as session:
                start = datetime.utcnow()
                await session.execute(text("SELECT 1"))
                latency_ms = (datetime.utcnow() - start).total_seconds() * 1000

                return {
                    "status": "healthy",
                    "latency_ms": round(latency_ms, 2),
                    "message": "Database connection successful",
                }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "latency_ms": None,
                "message": f"Database connection failed: {str(e)}",
                "error": str(e),
            }

    async def check_redis(self) -> Dict[str, Any]:
        """
        Check Redis connectivity and memory usage

        Returns:
            dict with status, memory_mb, connected_clients, message
        """
        if not self.redis_client:
            return {
                "status": "degraded",
                "message": "Redis client not configured",
            }

        try:
            # Test ping
            pong = await self.redis_client.ping()
            if not pong:
                return {
                    "status": "unhealthy",
                    "message": "Redis ping failed",
                }

            # Get memory info
            info = await self.redis_client.info("memory")
            memory_mb = info.get("used_memory", 0) / (1024 * 1024)

            # Get connected clients
            server_info = await self.redis_client.info("clients")
            connected_clients = server_info.get("connected_clients", 0)

            return {
                "status": "healthy",
                "memory_mb": round(memory_mb, 2),
                "connected_clients": connected_clients,
                "message": "Redis connection successful",
            }
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Redis connection failed: {str(e)}",
                "error": str(e),
            }

    async def check_celery(self) -> Dict[str, Any]:
        """
        Check Celery worker availability and queue lengths

        Returns:
            dict with status, workers_active, queue_lengths, message
        """
        if not self.redis_client:
            return {
                "status": "degraded",
                "message": "Redis client not configured for Celery check",
            }

        try:
            # Check for active workers (they maintain a heartbeat in Redis)
            worker_keys = await self.redis_client.keys("celery.worker.*")
            active_workers = len(worker_keys) if worker_keys else 0

            # Get queue lengths
            queue_lengths = {}
            for queue_name in ["default", "priority", "background"]:
                queue_key = f"celery:{queue_name}"
                queue_len = await self.redis_client.llen(queue_key)
                queue_lengths[queue_name] = queue_len

            status = "healthy" if active_workers > 0 else "degraded"
            message = f"{active_workers} worker(s) active" if active_workers > 0 else "No active workers"

            return {
                "status": status,
                "workers_active": active_workers,
                "queue_lengths": queue_lengths,
                "message": message,
            }
        except Exception as e:
            logger.error(f"Celery health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Celery check failed: {str(e)}",
                "error": str(e),
            }

    async def check_disk(self) -> Dict[str, Any]:
        """
        Check disk space availability

        Returns:
            dict with status, total_gb, used_gb, free_gb, percent_used
        """
        try:
            disk = psutil.disk_usage("/")
            total_gb = disk.total / (1024 ** 3)
            used_gb = disk.used / (1024 ** 3)
            free_gb = disk.free / (1024 ** 3)
            percent_used = disk.percent

            status = "healthy"
            if percent_used > 90:
                status = "unhealthy"
                logger.warning(f"Disk usage critical: {percent_used}%")
            elif percent_used > 75:
                status = "degraded"
                logger.warning(f"Disk usage high: {percent_used}%")

            return {
                "status": status,
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(free_gb, 2),
                "percent_used": round(percent_used, 2),
                "message": f"Disk {percent_used}% used",
            }
        except Exception as e:
            logger.error(f"Disk health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Disk check failed: {str(e)}",
                "error": str(e),
            }

    async def check_memory(self) -> Dict[str, Any]:
        """
        Check system RAM usage

        Returns:
            dict with status, total_gb, used_gb, available_gb, percent_used
        """
        try:
            memory = psutil.virtual_memory()
            total_gb = memory.total / (1024 ** 3)
            used_gb = memory.used / (1024 ** 3)
            available_gb = memory.available / (1024 ** 3)
            percent_used = memory.percent

            status = "healthy"
            if percent_used > 90:
                status = "unhealthy"
                logger.warning(f"Memory usage critical: {percent_used}%")
            elif percent_used > 75:
                status = "degraded"
                logger.warning(f"Memory usage high: {percent_used}%")

            return {
                "status": status,
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "available_gb": round(available_gb, 2),
                "percent_used": round(percent_used, 2),
                "message": f"Memory {percent_used}% used",
            }
        except Exception as e:
            logger.error(f"Memory health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Memory check failed: {str(e)}",
                "error": str(e),
            }

    async def get_full_health(self) -> Dict[str, Any]:
        """
        Get comprehensive health status of all components

        Returns:
            dict with overall status and individual component statuses
        """
        # Run all checks in parallel
        db_health = await self.check_database()
        redis_health = await self.check_redis()
        celery_health = await self.check_celery()
        disk_health = await self.check_disk()
        memory_health = await self.check_memory()

        # Determine overall status
        statuses = [
            db_health.get("status", "unknown"),
            redis_health.get("status", "unknown"),
            celery_health.get("status", "unknown"),
            disk_health.get("status", "unknown"),
            memory_health.get("status", "unknown"),
        ]

        if "unhealthy" in statuses:
            overall_status = "unhealthy"
        elif "degraded" in statuses:
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        return {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "components": {
                "database": db_health,
                "redis": redis_health,
                "celery": celery_health,
                "disk": disk_health,
                "memory": memory_health,
            },
        }

    async def get_readiness(self) -> Dict[str, Any]:
        """
        Get readiness probe status for Kubernetes
        Ready to accept traffic if database and Redis are healthy

        Returns:
            dict with ready status
        """
        db_health = await self.check_database()
        redis_health = await self.check_redis()

        db_ready = db_health.get("status") == "healthy"
        redis_ready = redis_health.get("status") == "healthy"

        ready = db_ready and redis_ready

        return {
            "ready": ready,
            "database_healthy": db_ready,
            "redis_healthy": redis_ready,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def get_liveness(self) -> Dict[str, Any]:
        """
        Get liveness probe status for Kubernetes
        Still alive if the process is running

        Returns:
            dict with alive status
        """
        try:
            # Simple check that app is still responding
            async with async_session_factory() as session:
                await session.execute(text("SELECT 1"))

            return {
                "alive": True,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(f"Liveness check failed: {e}")
            return {
                "alive": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
