"""Database configuration and connection pooling"""

from typing import AsyncGenerator

from sqlalchemy import event, pool, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool

from src.core.config import settings


def _create_engine():
    """Create async engine with optimized pool configuration"""
    # Use NullPool for SQLite, QueuePool for production databases
    if "sqlite" in settings.database_url:
        poolclass = NullPool
        connect_args = {}
        engine_kwargs = {}
    else:
        # Production database configuration
        poolclass = AsyncAdaptedQueuePool
        connect_args = {
            "server_settings": {
                "application_name": "pysoar",
                "jit": "off",
            },
            "timeout": 30,
        }
        engine_kwargs = {
            "pool_size": 20,
            "max_overflow": 40,
            "pool_timeout": 30,
            "pool_recycle": 3600,  # Recycle connections after 1 hour
            "pool_pre_ping": True,  # Verify connection before use
        }

    engine = create_async_engine(
        settings.database_url,
        echo=settings.debug and not settings.is_production,
        future=True,
        poolclass=poolclass,
        connect_args=connect_args,
        **engine_kwargs,
    )

    # Add event listener for connection pool events in production
    if poolclass is AsyncAdaptedQueuePool:
        @event.listens_for(engine.sync_engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            """Configure connection on creation"""
            if hasattr(dbapi_conn, "isolation_level"):
                dbapi_conn.isolation_level = None

    return engine


# Create async engine with optimized pooling
engine = _create_engine()

# Create async session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting async database sessions.

    Properly yields and closes sessions with transaction management.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize the database (create tables)"""
    from src.models.base import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections and dispose of pool"""
    await engine.dispose()


async def health_check() -> bool:
    """
    Test database connection health.

    Returns:
        bool: True if connection is healthy, False otherwise
    """
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
            return True
    except Exception:
        return False


async def get_pool_status() -> dict:
    """
    Get connection pool status information.

    Returns:
        dict: Pool status metrics
    """
    if engine.pool.__class__.__name__ == "NullPool":
        return {"pool_type": "NullPool", "size": 0, "checked_in": 0, "checked_out": 0}

    pool_obj = engine.pool
    return {
        "pool_type": pool_obj.__class__.__name__,
        "size": pool_obj.size(),
        "checked_in": pool_obj.checkedin(),
        "checked_out": pool_obj.checkedout(),
        "pool_size": getattr(pool_obj, "pool_size", "N/A"),
        "max_overflow": getattr(pool_obj, "max_overflow", "N/A"),
    }
