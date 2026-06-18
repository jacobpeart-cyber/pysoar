"""Pytest configuration and fixtures"""

import os

# CRITICAL — must run BEFORE any `from src.core.config import settings` import
# anywhere in the test process. Force the production engine's database_url to
# point at the same SQLite file the test fixtures write to. Without this, the
# Zero Trust session-gate middleware (and any other code that uses
# async_session_factory directly instead of Depends(get_db)) hits ./pysoar.db
# while the test fixtures write to ./test.db — same-machine but DIFFERENT
# files, so the middleware sees stale or missing schema and returns 503.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")

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
from src.models.base import Base
from src.models.user import User

# Force-import every model module so Base.metadata.create_all stamps all
# their tables into the test DB. Without these, code that runs outside the
# Depends(get_db) override (e.g. the Zero Trust session-gate middleware
# calling async_session_factory directly) gets "no such table: ..." errors
# on the test SQLite file. Each import is side-effect-only; the Base
# metaclass registers tables on import. F401 suppresses the unused warning.
import src.agentic.models  # noqa: F401
import src.agents.models  # noqa: F401
import src.attack.models  # noqa: F401
import src.ai.models  # noqa: F401
import src.api_security.models  # noqa: F401
import src.audit_evidence.models  # noqa: F401
import src.collaboration.models  # noqa: F401
import src.compliance.models  # noqa: F401
import src.container_security.models  # noqa: F401
import src.darkweb.models  # noqa: F401
import src.data_lake.models  # noqa: F401
import src.deception.models  # noqa: F401
import src.dfir.models  # noqa: F401
import src.dlp.models  # noqa: F401
import src.exposure.models  # noqa: F401
import src.hunting.models  # noqa: F401
import src.integrations.models  # noqa: F401
import src.intel.models  # noqa: F401
import src.itdr.models  # noqa: F401
import src.ot_security.models  # noqa: F401
import src.phishing_sim.models  # noqa: F401
import src.playbook_builder.models  # noqa: F401
import src.privacy.models  # noqa: F401
import src.remediation.models  # noqa: F401
import src.risk_quant.models  # noqa: F401
import src.siem.models  # noqa: F401
import src.simulation.models  # noqa: F401
import src.stig.models  # noqa: F401
import src.supplychain.models  # noqa: F401
import src.threat_modeling.models  # noqa: F401
import src.tickethub.models  # noqa: F401
import src.zerotrust.models  # noqa: F401

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


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _ensure_schema_on_disk() -> AsyncGenerator[None, None]:
    """Ensure all tables exist on the shared SQLite file BEFORE every test —
    including tests that don't request the `db_session` fixture (e.g. the
    synchronous DLP discovery scanner tests that go through the production
    async_session_factory directly).

    `db_session` does its own drop_all + create_all for transactional
    isolation. This fixture runs second (autouse) and re-creates any tables
    that may have been dropped, so non-db_session tests still find the
    schema. `create_all(checkfirst=True)` is idempotent — no harm on the
    common path."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


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
async def client(
    db_session: AsyncSession, redis_mock: AsyncMock
) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with database session + Redis client overrides.

    The Redis override is critical: get_current_user (src/api/deps.py:84)
    does Redis-based JWT blacklist + revocation checks and FAILS CLOSED
    with 503 on Redis errors. Without overriding get_redis_client, every
    authenticated request 503s after a 5-second Redis-connect timeout.
    """

    async def override_get_db():
        yield db_session

    async def override_get_redis_client():
        yield redis_mock

    # Import `app` and the Redis dep lazily to avoid heavy collection imports.
    from src.main import app
    from src.api.deps import get_redis_client

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis_client] = override_get_redis_client

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
