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


class TestPasswordResetConsume:
    async def test_valid_token_changes_password(
        self,
        db_session: AsyncSession,
        issued_reset_token,
        client: AsyncClient,
    ):
        user, token = issued_reset_token
        old_hash = user.hashed_password

        r = await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "NewStr0ng!Pass2026"},
        )
        assert r.status_code == 200

        await db_session.refresh(user)
        assert user.hashed_password != old_hash
        # Token is burned
        assert user.password_reset_token is None
        assert user.password_reset_token_expires_at is None

    async def test_does_not_touch_force_password_change(
        self,
        db_session: AsyncSession,
        issued_reset_token,
        client: AsyncClient,
    ):
        """The reset flow has no business deciding whether the new password
        also needs to change on next login. Other policy code owns
        force_password_change. The reset endpoint must leave it untouched."""
        user, token = issued_reset_token
        # Force-set both possible starting states and confirm the endpoint
        # respects each one. Note: the executor always sets force_password_change=True
        # when issuing a token, so we set the desired starting value AFTER the
        # executor call, right before consuming the token.
        for starting_value in (True, False):
            # Issue a fresh token
            executor = AccountActionExecutor(db_session)
            await executor.execute(
                target=user.email,
                parameters={"action": "password_reset"},
                context=_ctx(user.id, user.organization_id),
            )
            await db_session.commit()
            await db_session.refresh(user)
            fresh_token = user.password_reset_token

            # NOW set the starting state (after executor has set it to True)
            user.force_password_change = starting_value
            await db_session.commit()

            r = await client.post(
                "/api/v1/auth/password-reset/consume",
                json={"token": fresh_token, "new_password": "NewStr0ng!Pass2026"},
            )
            assert r.status_code == 200
            await db_session.refresh(user)
            assert user.force_password_change is starting_value, (
                f"reset flow changed force_password_change from "
                f"{starting_value} to {user.force_password_change}"
            )

    async def test_token_only_works_once(
        self,
        db_session: AsyncSession,
        issued_reset_token,
        client: AsyncClient,
    ):
        user, token = issued_reset_token
        r1 = await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "NewStr0ng!Pass2026"},
        )
        assert r1.status_code == 200

        # Second attempt must fail because the token was burned
        r2 = await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "AnotherStr0ng!Pass"},
        )
        assert r2.status_code in (404, 410)

    async def test_expired_token_returns_410(
        self,
        db_session: AsyncSession,
        issued_reset_token,
        client: AsyncClient,
    ):
        user, token = issued_reset_token
        # Push expiry into the past — use the normalize pattern: AWARE
        # value so SQLite stores it correctly AND Postgres handles it
        user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await db_session.commit()

        r = await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "NewStr0ng!Pass2026"},
        )
        assert r.status_code == 410

    async def test_weak_password_rejected(
        self,
        db_session: AsyncSession,
        issued_reset_token,
        client: AsyncClient,
    ):
        """Pydantic min_length on new_password enforces the floor."""
        user, token = issued_reset_token
        r = await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "x"},  # too short
        )
        assert r.status_code == 422  # Pydantic validation failure

        await db_session.refresh(user)
        # Token must NOT be burned on validation failure
        assert user.password_reset_token == token

    async def test_failure_paths_take_similar_time_as_success(
        self,
        db_session: AsyncSession,
        issued_reset_token,
        client: AsyncClient,
    ):
        """Timing-defense smoke test: bcrypt runs on ALL paths (valid token,
        invalid token, expired token) so the response latency for invalid
        guesses doesn't differ measurably from the legitimate-token path.

        Not a hard real-time assertion (CI noise makes that fragile) — we
        only assert the failure path isn't ORDERS OF MAGNITUDE faster than
        success, which would indicate the bcrypt was skipped."""
        import time
        user, token = issued_reset_token

        t0 = time.perf_counter()
        await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": "no-such-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "new_password": "ValidPass12345!"},
        )
        invalid_dt = time.perf_counter() - t0

        t0 = time.perf_counter()
        await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "ValidPass12345!"},
        )
        valid_dt = time.perf_counter() - t0

        # bcrypt at default cost takes ~50-200ms. If the failure path skipped
        # bcrypt, it would be <5ms — a >10x gap. Assert the ratio is bounded.
        assert invalid_dt > valid_dt * 0.25, (
            f"invalid-token path was suspiciously faster than valid-token "
            f"path: invalid={invalid_dt*1000:.1f}ms valid={valid_dt*1000:.1f}ms — "
            f"check that bcrypt runs on failure paths"
        )
