"""Database configuration and connection pooling"""

from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from src.core.config import settings


def _create_engine():
    """Create async engine with pool configuration"""
    if "sqlite" in settings.database_url:
        return create_async_engine(
            settings.database_url,
            echo=settings.debug and not settings.is_production,
            future=True,
            poolclass=NullPool,
        )
    else:
        # asyncpg manages its own internal pool — do not pass a poolclass
        return create_async_engine(
            settings.database_url,
            echo=settings.debug and not settings.is_production,
            future=True,
            pool_size=20,
            max_overflow=40,
            pool_timeout=30,
            pool_recycle=3600,
            pool_pre_ping=True,
            connect_args={
                "server_settings": {
                    "application_name": "pysoar",
                    "jit": "off",
                },
                "timeout": 30,
            },
        )


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
    """Dependency for getting async database sessions."""
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
    """Test database connection health."""
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
            return True
    except Exception:
        return False


async def get_pool_status() -> dict:
    """Get connection pool status information."""
    pool_obj = engine.pool
    if pool_obj.__class__.__name__ == "NullPool":
        return {"pool_type": "NullPool", "size": 0, "checked_in": 0, "checked_out": 0}
    return {
        "pool_type": pool_obj.__class__.__name__,
        "size": getattr(pool_obj, "size", lambda: "N/A")(),
        "checked_in": getattr(pool_obj, "checkedin", lambda: "N/A")(),
        "checked_out": getattr(pool_obj, "checkedout", lambda: "N/A")(),
    }
