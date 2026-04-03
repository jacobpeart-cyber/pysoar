"""Pytest configuration and fixtures"""

import asyncio
from datetime import datetime
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from redis.asyncio import Redis

from src.core.config import settings
from src.core.database import get_db
from src.core.security import get_password_hash
from src.main import app
from src.models.base import Base
from src.models.user import User

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Create test engine
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
)

# Create test session factory
TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for the test session"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for each test"""
    # Drop first to clear stale indexes from prior failed tests
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with database session override"""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user"""
    user = User(
        email="test@example.com",
        hashed_password=get_password_hash("testpassword123"),
        full_name="Test User",
        role="analyst",
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """Create an admin test user"""
    user = User(
        email="admin@example.com",
        hashed_password=get_password_hash("adminpassword123"),
        full_name="Admin User",
        role="admin",
        is_active=True,
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def auth_headers(test_user: User) -> dict:
    """Get authentication headers for test user"""
    from src.core.security import create_access_token

    token = create_access_token(subject=test_user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def admin_auth_headers(admin_user: User) -> dict:
    """Get authentication headers for admin user"""
    from src.core.security import create_access_token

    token = create_access_token(subject=admin_user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def redis_mock() -> AsyncMock:
    """Create a mock Redis client for testing"""
    mock_redis = AsyncMock(spec=Redis)

    # Setup common Redis methods
    mock_redis.ping = AsyncMock(return_value=True)
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=1)
    mock_redis.exists = AsyncMock(return_value=0)
    mock_redis.incr = AsyncMock(return_value=1)
    mock_redis.zadd = AsyncMock(return_value=1)
    mock_redis.zcard = AsyncMock(return_value=0)
    mock_redis.zrange = AsyncMock(return_value=[])
    mock_redis.zremrangebyscore = AsyncMock(return_value=0)
    mock_redis.expire = AsyncMock(return_value=1)
    mock_redis.llen = AsyncMock(return_value=0)
    mock_redis.keys = AsyncMock(return_value=[])
    mock_redis.scan = AsyncMock(return_value=(0, []))
    mock_redis.info = AsyncMock(return_value={})
    mock_redis.hset = AsyncMock(return_value=1)
    mock_redis.hget = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock(return_value=True)

    return mock_redis


@pytest_asyncio.fixture
async def celery_mock() -> MagicMock:
    """Create a mock Celery app for testing"""
    mock_celery = MagicMock()
    mock_celery.send_task = AsyncMock(return_value=MagicMock(id="task-id"))
    mock_celery.AsyncResult = MagicMock(return_value=MagicMock(status="SUCCESS"))
    return mock_celery


@pytest_asyncio.fixture
async def sample_alert(db_session: AsyncSession):
    """Create a sample alert for testing"""
    from src.models.alert import Alert

    alert = Alert(
        title="Test Alert",
        description="Test alert description",
        severity="high",
        source="test_source",
        raw_event={
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "test",
            "source_ip": "192.168.1.1",
        },
        status="new",
    )
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)
    return alert


@pytest_asyncio.fixture
async def sample_incident(db_session: AsyncSession, test_user: User):
    """Create a sample incident for testing"""
    from src.models.incident import Incident

    incident = Incident(
        title="Test Incident",
        description="Test incident description",
        severity="critical",
        status="open",
        assigned_to_id=test_user.id,
    )
    db_session.add(incident)
    await db_session.commit()
    await db_session.refresh(incident)
    return incident


@pytest_asyncio.fixture
async def sample_ioc(db_session: AsyncSession):
    """Create a sample IOC (Indicator of Compromise) for testing"""
    from src.models.ioc import IOC

    ioc = IOC(
        value="192.168.1.1",
        type="ip",
        source="test",
        severity="high",
        confidence=90,
        description="Test IOC",
        tags=["malware", "c2"],
    )
    db_session.add(ioc)
    await db_session.commit()
    await db_session.refresh(ioc)
    return ioc


@pytest_asyncio.fixture
async def cleanup(db_session: AsyncSession):
    """Cleanup fixture that runs after each test"""
    yield

    # Clear all tables after test
    async with db_session.begin():
        for table in reversed(Base.metadata.sorted_tables):
            await db_session.execute(table.delete())
        await db_session.commit()
