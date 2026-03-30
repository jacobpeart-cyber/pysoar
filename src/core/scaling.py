"""Horizontal scaling and performance configuration"""

import os
from dataclasses import dataclass
from multiprocessing import cpu_count
from typing import Any, Dict, Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class UvicornConfig:
    """Uvicorn server configuration for horizontal scaling"""

    workers: int = None  # Will be set to cpu_count * 2 + 1
    keep_alive: int = 120
    backlog: int = 2048
    timeout_keep_alive: int = 120
    timeout_notify: int = 30
    max_concurrent_connections: Optional[int] = None

    def __post_init__(self):
        """Calculate optimal worker count if not provided"""
        if self.workers is None:
            self.workers = cpu_count() * 2 + 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Uvicorn config"""
        return {
            "workers": self.workers,
            "keep_alive": self.keep_alive,
            "backlog": self.backlog,
            "timeout_keep_alive": self.timeout_keep_alive,
            "timeout_notify": self.timeout_notify,
            "max_concurrent_connections": self.max_concurrent_connections,
        }


@dataclass
class CeleryScaling:
    """Celery worker scaling configuration"""

    worker_concurrency: int = None  # Will be set to cpu_count * 2
    prefetch_multiplier: int = 4
    task_time_limit: int = 3600  # 1 hour hard limit
    task_soft_time_limit: int = 3300  # 55 minutes soft limit
    worker_max_tasks_per_child: int = 1000

    def __post_init__(self):
        """Calculate optimal concurrency if not provided"""
        if self.worker_concurrency is None:
            self.worker_concurrency = cpu_count() * 2

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Celery config"""
        return {
            "worker_concurrency": self.worker_concurrency,
            "worker_prefetch_multiplier": self.prefetch_multiplier,
            "task_time_limit": self.task_time_limit,
            "task_soft_time_limit": self.task_soft_time_limit,
            "worker_max_tasks_per_child": self.worker_max_tasks_per_child,
        }


@dataclass
class RedisPoolConfig:
    """Redis connection pool configuration"""

    max_connections: int = 50
    socket_timeout: int = 5
    socket_connect_timeout: int = 5
    socket_keepalive: bool = True
    socket_keepalive_options: Optional[Dict[str, Any]] = None
    retry_on_timeout: bool = True
    health_check_interval: int = 30

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Redis ConnectionPool config"""
        return {
            "max_connections": self.max_connections,
            "socket_timeout": self.socket_timeout,
            "socket_connect_timeout": self.socket_connect_timeout,
            "socket_keepalive": self.socket_keepalive,
            "retry_on_timeout": self.retry_on_timeout,
            "health_check_interval": self.health_check_interval,
        }


class HealthAggregator:
    """Aggregate health checks for distributed system monitoring"""

    def __init__(self):
        """Initialize health aggregator"""
        self.logger = structlog.get_logger(__name__)

    async def check_api_health(self) -> Dict[str, Any]:
        """Check API health status"""
        return {
            "status": "healthy",
            "timestamp": None,  # Will be set by caller
        }

    async def check_database_pool(self) -> Dict[str, Any]:
        """Check database connection pool utilization"""
        try:
            from src.core.database import get_pool_status, health_check

            is_healthy = await health_check()
            pool_status = await get_pool_status()

            return {
                "healthy": is_healthy,
                "pool": pool_status,
            }
        except Exception as e:
            self.logger.error("database_pool_check_failed", error=str(e))
            return {
                "healthy": False,
                "error": str(e),
            }

    async def check_redis_connectivity(self) -> Dict[str, Any]:
        """Check Redis connectivity and pool status"""
        try:
            from src.core.cache import redis_client

            if redis_client is None:
                return {"healthy": False, "error": "Redis client not initialized"}

            await redis_client.ping()
            info = await redis_client.info()

            return {
                "healthy": True,
                "info": {
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory": info.get("used_memory_human", "N/A"),
                    "uptime_seconds": info.get("uptime_in_seconds", 0),
                },
            }
        except Exception as e:
            self.logger.error("redis_check_failed", error=str(e))
            return {
                "healthy": False,
                "error": str(e),
            }

    async def check_celery_workers(self) -> Dict[str, Any]:
        """Check Celery worker availability"""
        try:
            from celery import current_app

            inspect = current_app.control.inspect()
            active_workers = inspect.active()

            if active_workers:
                worker_count = len(active_workers)
                return {
                    "healthy": True,
                    "worker_count": worker_count,
                    "workers": list(active_workers.keys()),
                }
            else:
                return {
                    "healthy": False,
                    "worker_count": 0,
                    "error": "No active workers found",
                }
        except Exception as e:
            self.logger.error("celery_check_failed", error=str(e))
            return {
                "healthy": False,
                "error": str(e),
            }

    async def aggregate_health(self) -> Dict[str, Any]:
        """Aggregate all health checks"""
        import asyncio
        from datetime import datetime

        db_health = await self.check_database_pool()
        redis_health = await self.check_redis_connectivity()
        celery_health = await self.check_celery_workers()
        api_health = await self.check_api_health()

        overall_healthy = (
            db_health.get("healthy", False)
            and redis_health.get("healthy", False)
            and celery_health.get("healthy", False)
        )

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_healthy": overall_healthy,
            "components": {
                "api": api_health,
                "database": db_health,
                "redis": redis_health,
                "celery": celery_health,
            },
        }


class MetricsExporter:
    """Export metrics in Prometheus format"""

    @staticmethod
    def format_counter(name: str, value: int, labels: Optional[Dict[str, str]] = None) -> str:
        """Format counter metric"""
        label_str = ""
        if labels:
            label_str = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}"
        return f"{name}{label_str} {value}"

    @staticmethod
    def format_gauge(name: str, value: float, labels: Optional[Dict[str, str]] = None) -> str:
        """Format gauge metric"""
        label_str = ""
        if labels:
            label_str = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}"
        return f"{name}{label_str} {value}"

    @staticmethod
    def format_histogram(
        name: str,
        buckets: Dict[str, int],
        sum_value: float,
        count: int,
        labels: Optional[Dict[str, str]] = None,
    ) -> list:
        """Format histogram metric"""
        lines = []
        label_str = ""
        if labels:
            label_str = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}"

        for bucket, count_val in buckets.items():
            lines.append(f"{name}_bucket{label_str},le=\"{bucket}\" {count_val}")

        lines.append(f"{name}_sum{label_str} {sum_value}")
        lines.append(f"{name}_count{label_str} {count}")
        return lines

    @staticmethod
    async def export_health_metrics(health_data: Dict[str, Any]) -> str:
        """Export health check data as Prometheus metrics"""
        lines = [
            "# HELP pysoar_health_check Application health check status",
            "# TYPE pysoar_health_check gauge",
            f'pysoar_health_check{{component="overall"}} {int(health_data.get("overall_healthy", False))}',
        ]

        components = health_data.get("components", {})
        for component, data in components.items():
            healthy = int(data.get("healthy", False))
            lines.append(f'pysoar_health_check{{component="{component}"}} {healthy}')

        # Database pool metrics
        if "database" in components and "pool" in components["database"]:
            pool_data = components["database"]["pool"]
            lines.append("# HELP pysoar_db_pool_size Current database pool size")
            lines.append("# TYPE pysoar_db_pool_size gauge")
            lines.append(f'pysoar_db_pool_size{{type="checked_in"}} {pool_data.get("checked_in", 0)}')
            lines.append(f'pysoar_db_pool_size{{type="checked_out"}} {pool_data.get("checked_out", 0)}')

        # Celery worker metrics
        if "celery" in components:
            celery_data = components["celery"]
            lines.append("# HELP pysoar_celery_workers Number of active Celery workers")
            lines.append("# TYPE pysoar_celery_workers gauge")
            lines.append(f'pysoar_celery_workers {celery_data.get("worker_count", 0)}')

        return "\n".join(lines) + "\n"


# Convenience instances for configuration
uvicorn_config = UvicornConfig()
celery_scaling = CeleryScaling()
redis_pool_config = RedisPoolConfig()
health_aggregator = HealthAggregator()
metrics_exporter = MetricsExporter()
