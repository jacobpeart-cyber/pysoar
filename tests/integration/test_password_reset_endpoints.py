"""End-to-end tests for the password-reset URL consumption flow.

Tests both /validate and /consume endpoints (consume comes in Task 7).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.organization import Organization
from src.models.user import User
from src.remediation.engine import AccountActionExecutor


def _ctx(user_id: str, org_id: str) -> dict:
    return {
        "execution_id": f"reset-test-{org_id[:8]}",
        "organization_id": org_id,
        "initiated_by": user_id,
        "trigger_data": {},
    }


@pytest.fixture
async def issued_reset_token(
    db_session: AsyncSession, default_org: Organization, default_user: User
) -> tuple[User, str]:
    """Run the executor to create a real token on default_user. Returns the user
    and the plaintext token so the endpoint tests can submit it."""
    executor = AccountActionExecutor(db_session)
    await executor.execute(
        target=default_user.email,
        parameters={"action": "password_reset"},
        context=_ctx(default_user.id, default_org.id),
    )
    await db_session.commit()
    await db_session.refresh(default_user)
    return default_user, default_user.password_reset_token


class TestPasswordResetValidate:
    async def test_valid_token_returns_200(self, client: AsyncClient, issued_reset_token):
        user, token = issued_reset_token
        r = await client.post(
            "/api/v1/auth/password-reset/validate",
            json={"token": token},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is True
        assert "expires_at" in body
        # Email must NOT come back from this endpoint — disclosing which
        # email a token belongs to is an enumeration leak. Only valid/expiry.
        assert "email" not in body
        assert "user_id" not in body

    async def test_unknown_token_returns_404(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/auth/password-reset/validate",
            json={"token": "no-such-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx12"},
        )
        assert r.status_code == 404
        body = r.json()
        # Generic error — must NOT confirm "no such token" vs "expired"
        # because that differential helps an attacker probe token space.
        assert "detail" in body
        assert "invalid" in body["detail"].lower() or "expired" in body["detail"].lower()

    async def test_expired_token_returns_410(
        self, client: AsyncClient, db_session: AsyncSession, issued_reset_token
    ):
        user, token = issued_reset_token
        # Backdate the expiry. SQLite stores naive datetimes, so strip tzinfo.
        user.password_reset_token_expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).replace(tzinfo=None)
        await db_session.commit()

        r = await client.post(
            "/api/v1/auth/password-reset/validate",
            json={"token": token},
        )
        assert r.status_code == 410
        body = r.json()
        assert "expired" in body["detail"].lower()

    async def test_validate_does_NOT_invalidate(
        self, client: AsyncClient, db_session: AsyncSession, issued_reset_token
    ):
        """Validation is read-only. Repeated calls return 200 each time. The
        token only burns on /consume, not on /validate."""
        user, token = issued_reset_token
        for _ in range(3):
            r = await client.post(
                "/api/v1/auth/password-reset/validate",
                json={"token": token},
            )
            assert r.status_code == 200

        await db_session.refresh(user)
        assert user.password_reset_token == token  # still on the row
