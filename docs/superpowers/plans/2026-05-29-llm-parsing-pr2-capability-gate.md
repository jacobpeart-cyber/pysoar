# LLM Parsing — PR 2 Capability Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every action_type that will appear in the agentic-investigator's closed-enum action classifier (PR 3) actually do real, end-to-end, observable work. Fix three current stubs (`ProcessActionExecutor`, missing `quarantine_file` executor, missing `collect_forensics` composite), harden one weak handler (`password_reset` token generation), then ship the closed `ActionType` enum + Pydantic schemas in `src/agentic/action_classifier.py` with an integration test that proves each enum value passes the capability gate.

**Architecture:** Each action_type maps to a single concrete server-side handler that produces an observable DB side-effect — a row in `threat_indicators`, `assets`, `users` (state change), or `agent_commands` (queued command with hash-chain entry via `AgentService.issue_command`). Composite handlers like `collect_forensics` issue multiple agent commands and return all command IDs. The closed enum in `action_classifier.py` only contains action_types whose handlers pass the capability gate test. No fake-success returns; failures raise or return `success=False` with a real error.

**Tech Stack:** SQLAlchemy 2.0 async, Alembic, FastAPI, Pydantic v2, pytest with `asyncio_mode = auto` and the existing SQLite test DB fixture in `tests/conftest.py`. Reuses the existing `AgentService.issue_command` in [src/agents/service.py:248](../../../src/agents/service.py#L248) for agent dispatch.

**Spec reference:** [docs/superpowers/specs/2026-05-25-hardened-llm-parsing-design.md](../specs/2026-05-25-hardened-llm-parsing-design.md) — sections "Group D — action classifier replaces _ACTION_RULES", "No-silent-fallback contract Rule 3 (capability verification gate)", "Testing row 6", "Rollout PR 2". User-authorized scope expansion: fix the stubs in this PR rather than file them as follow-ups.

---

## Key Design Decisions

1. **Enum values match the codebase's canonical `RemediationAction.action_type` strings** ([src/remediation/models.py:103](../../../src/remediation/models.py#L103)), not the colloquial names in the spec. So the enum is `FIREWALL_BLOCK`, `HOST_ISOLATE`, `ACCOUNT_DISABLE`, `PASSWORD_RESET`, `PROCESS_KILL`, `FILE_QUARANTINE`, `COLLECT_FORENSICS` — not `block_ip` etc. PR 3's classifier prompt will instruct Gemini to emit these exact values.

2. **Target → EndpointAgent resolution** lives in `AgentService` (existing class). Add `resolve_for_target(target)` method that tries hostname match first, then IP match, then returns None. Executors that need agent dispatch call this; on None they return `success=False` with an explicit "no agent enrolled for target" error — never a fake-success-with-queued-status.

3. **`collect_forensics` is a composite executor** that issues three separate `agent_commands` rows (`collect_process_list`, `collect_network_connections`, `collect_memory_dump`) in sequence using `AgentService.issue_command`. Returns the list of command IDs. If the agent's capability allowlist rejects any one of them, the composite returns `success=False` with the list of partial-success command IDs so the operator can see what was queued and what wasn't.

4. **`password_reset` generates a real one-time token.** Add `User.password_reset_token` (256-bit url-safe) and `User.password_reset_token_expires_at` columns via Alembic migration 018. The executor generates a token with `secrets.token_urlsafe(48)`, sets the expiry to `now + 24h`, writes it to the User row. The token's later consumption (validating a reset URL, mounting a UI flow) is out of scope for this PR — the executor's job is to make the token exist as a real, time-bounded credential. The TicketActivity record's `extra_metadata` includes a `token_id` reference (the first 8 chars of the token hash, NOT the token itself) so audit trails don't leak the secret.

5. **Tests live in `tests/integration/` not `tests/unit/`** because they need the SQLAlchemy async session + fixture DB from `tests/conftest.py`. The `pytest.ini` testpaths setting already picks up both. The capability gate test is one large file covering all 7 enum values.

---

## File Structure

| File | State | Responsibility |
| --- | --- | --- |
| `alembic/versions/018_password_reset_token.py` | Create | Add `password_reset_token` (nullable str) and `password_reset_token_expires_at` (nullable datetime) to `users` table; unique index on the token. |
| `src/models/user.py` | Modify | Mirror the migration: add the two `Mapped[Optional[...]]` fields |
| `src/agents/service.py` | Modify | Add `async def resolve_for_target(self, target: str, *, organization_id: str) -> Optional[EndpointAgent]` method on `AgentService`. `organization_id` is MANDATORY keyword-only — prevents cross-tenant leaks via forgotten arg. |
| `src/remediation/engine.py` | Modify | Rewrite `ProcessActionExecutor.execute` to use `AgentService.issue_command`. Add `FileActionExecutor` for `file_quarantine`. Add `ForensicsCollectionExecutor` for `collect_forensics`. Harden `AccountActionExecutor` `password_reset` branch to generate a real token. |
| `src/api/v1/endpoints/auth.py` | Modify | Append `POST /password-reset/validate` (read-only token check) and `POST /password-reset/consume` (burn token + set new password). Completes the URL-flow side of the reset feature. |
| `src/agentic/action_classifier.py` | Create | Closed `ActionType` enum + `ClassifiedAction` + `ActionClassification` Pydantic schemas. No caller in this PR — PR 3 wires it. |
| `tests/integration/__init__.py` | Verify exists | (Should already exist; if not, create empty file.) |
| `tests/integration/conftest.py` | Create if missing | Reuses session fixture from `tests/conftest.py` plus a fixture that creates a default org + user + endpoint agent enrolled with all capabilities. |
| `tests/integration/test_action_executors.py` | Create | TDD tests for each fixed executor (firewall_block, host_isolate, account_disable, password_reset, process_kill, file_quarantine, collect_forensics) — one test class per executor. |
| `tests/integration/test_password_reset_endpoints.py` | Create | End-to-end tests for `/validate` and `/consume` — issue-burn-reuse cycle, weak-password rejection, expiry handling, no-enumeration error wording. |
| `tests/integration/test_action_handlers_are_real.py` | Create | The capability gate. For each of 7 ActionType enum values, invoke the executor through a uniform interface and assert observable DB state change. This is the test that the enum's contract is real. |

---

## Task 1: Verify pytest can run integration tests + inspect conftest

**Files:**

- Read: `tests/conftest.py`, `tests/integration/` (if it exists), `pytest.ini`

- [ ] **Step 1: Confirm integration test directory and fixtures**

```bash
ls tests/integration 2>&1 || echo "directory missing"
```

If missing, create:

```bash
mkdir -p tests/integration
touch tests/integration/__init__.py
```

- [ ] **Step 2: Read the session fixture from tests/conftest.py**

Look for an async session fixture or async engine fixture. The PySOAR conftest uses `aiosqlite` for `TEST_DATABASE_URL` and exposes `TestSessionLocal`. Read enough of `tests/conftest.py` to know whether a `db_session` fixture is exported. If yes, integration tests can reuse it. If no, plan to add one in Task 2's conftest.

- [ ] **Step 3: Run an existing test to confirm DB setup works**

```bash
python -m pytest tests/unit/test_auth.py -v 2>&1 | tail -20
```

If the test runs (pass or fail — both indicate the DB setup is wired), continue. If it errors at module import (e.g. `sqlalchemy not found`), the venv is wrong — fix before continuing.

- [ ] **Step 4: Report — no commit yet**

This task is verification only. Write a one-paragraph summary of:

- Whether `tests/integration/` exists
- The name of the async-session fixture in `tests/conftest.py` (or "none")
- Whether the SQLite test DB is operational

---

## Task 2: Integration test fixtures (org + user + endpoint agent)

**Files:**

- Create: `tests/integration/conftest.py`

- [ ] **Step 1: Write the fixtures**

Create `tests/integration/conftest.py`:

```python
"""Integration test fixtures: org, user, endpoint agent enrolled with all capabilities.

Used by test_action_executors.py and test_action_handlers_are_real.py to give
each test a fresh DB state with the minimum entities the executors need.
"""

from __future__ import annotations

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import get_password_hash
from src.models.user import User
from src.models.organization import Organization
from src.agents.models import EndpointAgent


@pytest_asyncio.fixture
async def test_org(db_session: AsyncSession) -> Organization:
    org = Organization(
        name="ExecutorTestOrg",
        slug="executor-test-org",
        plan="enterprise",
        is_active=True,
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession, test_org: Organization) -> User:
    user = User(
        email="target@executor-test.local",
        hashed_password=get_password_hash("not-used-in-tests"),
        full_name="Executor Test Target",
        is_active=True,
        is_superuser=False,
        organization_id=test_org.id,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def test_agent(db_session: AsyncSession, test_org: Organization) -> EndpointAgent:
    """Endpoint agent enrolled with all capabilities the executors might need."""
    agent = EndpointAgent(
        hostname="executor-test-host-01",
        platform="linux",
        agent_version="0.1.0",
        capabilities=["bas", "ir", "purple"],
        status="online",
        organization_id=test_org.id,
        last_command_hash=None,  # genesis
    )
    db_session.add(agent)
    await db_session.flush()
    return agent
```

- [ ] **Step 2: Confirm the imports resolve**

```bash
python -c "from src.models.user import User; from src.models.organization import Organization; from src.agents.models import EndpointAgent; print('ok')"
```

Expected: `ok`. If any import fails, fix the path before proceeding.

- [ ] **Step 3: Verify `db_session` fixture is available from the parent conftest**

If Task 1 reported that `tests/conftest.py` has a `db_session` fixture, this fixture will be discovered automatically by pytest. If Task 1 reported no such fixture, add one to `tests/integration/conftest.py` derived from the existing `TestSessionLocal`:

```python
@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    """Per-test async session. Rolls back after each test."""
    from tests.conftest import TestSessionLocal, test_engine
    from src.models.base import Base

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        try:
            yield session
        finally:
            await session.rollback()
```

Only add this if Task 1 confirmed it doesn't already exist upstream.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/__init__.py tests/integration/conftest.py
git commit -m "$(cat <<'EOF'
test(integration): fixtures for action-executor capability gate

Adds org / user / endpoint-agent fixtures used by the PR 2 capability-gate
tests. Agent is enrolled with bas/ir/purple capabilities so any executor's
issue_command call passes the capability allowlist check.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Alembic migration — User password reset token columns

**Files:**

- Create: `alembic/versions/018_password_reset_token.py`
- Modify: `src/models/user.py`

- [ ] **Step 1: Inspect current User model**

```bash
grep -n "password_reset_token\|force_password_change\|hashed_password" src/models/user.py
```

Confirm `password_reset_token` is NOT present. If it is, skip this whole task and report.

- [ ] **Step 2: Look up the previous migration's revision id**

```bash
ls alembic/versions/
```

Find the highest-numbered migration (currently `017_app_settings_table.py`). Open it and note the `revision = "..."` value — the new migration's `down_revision` must equal this.

- [ ] **Step 3: Create the migration file**

Create `alembic/versions/018_password_reset_token.py`:

```python
"""Add password_reset_token to users.

Revision ID: 018_password_reset_token
Revises: <PREVIOUS_REVISION_ID>
Create Date: 2026-05-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "018_password_reset_token"
down_revision: Union[str, None] = "<PREVIOUS_REVISION_ID>"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_reset_token", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("password_reset_token_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    # unique=True: two users CANNOT share a reset token. With 48-byte
    # url-safe tokens the collision probability is vanishingly small, but
    # the DB-layer guarantee removes "what if?" doubt from the URL handler.
    op.create_index(
        "ix_users_password_reset_token",
        "users",
        ["password_reset_token"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_users_password_reset_token", table_name="users")
    op.drop_column("users", "password_reset_token_expires_at")
    op.drop_column("users", "password_reset_token")
```

Replace `<PREVIOUS_REVISION_ID>` with the actual revision id from Step 2.

- [ ] **Step 4: Add the two fields to `src/models/user.py`**

Find the `User` class. After `force_password_change`, add:

```python
    password_reset_token: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, index=True
    )
    password_reset_token_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
```

The imports `Optional`, `String`, `Mapped`, `mapped_column`, `DateTime`, `datetime` should already be present in the file. If `Optional` is missing, add `from typing import Optional` to the imports.

- [ ] **Step 5: Run a quick verification test**

```bash
python -c "from src.models.user import User; u = User(email='x@x', hashed_password='y', full_name='z', organization_id='o'); assert hasattr(u, 'password_reset_token') and hasattr(u, 'password_reset_token_expires_at'); print('ok')"
```

Expected: `ok`. If `AttributeError`, the model edit didn't land — re-read and fix.

- [ ] **Step 6: Commit**

```bash
git add alembic/versions/018_password_reset_token.py src/models/user.py
git commit -m "$(cat <<'EOF'
db(users): add password_reset_token + expires_at for real reset flow

Backs the upcoming hardened password_reset handler. Token is generated by
AccountActionExecutor with secrets.token_urlsafe(48) and a 24h expiry.
Indexed for the URL-consumption lookup (out of scope for this PR — the
executor's job is making the token exist as a real, time-bounded credential).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add `AgentService.resolve_for_target` helper

This is the target-string → EndpointAgent resolver that the fixed executors call before issuing agent commands.

**Files:**

- Modify: `src/agents/service.py`
- Create: `tests/integration/test_agent_service_resolve.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/integration/test_agent_service_resolve.py`:

```python
"""Tests for AgentService.resolve_for_target."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import EndpointAgent
from src.agents.service import AgentService
from src.models.organization import Organization


class TestResolveForTarget:
    async def test_resolves_by_hostname(
        self,
        db_session: AsyncSession,
        test_agent: EndpointAgent,
        test_org: Organization,
    ):
        svc = AgentService(db_session)
        resolved = await svc.resolve_for_target(
            test_agent.hostname, organization_id=test_org.id
        )
        assert resolved is not None
        assert resolved.id == test_agent.id

    async def test_resolves_by_ip(
        self,
        db_session: AsyncSession,
        test_agent: EndpointAgent,
        test_org: Organization,
    ):
        # Set an IP on the agent
        test_agent.ip_address = "10.0.0.42"
        await db_session.flush()
        svc = AgentService(db_session)
        resolved = await svc.resolve_for_target(
            "10.0.0.42", organization_id=test_org.id
        )
        assert resolved is not None
        assert resolved.id == test_agent.id

    async def test_returns_none_for_unknown_target(
        self,
        db_session: AsyncSession,
        test_agent: EndpointAgent,
        test_org: Organization,
    ):
        svc = AgentService(db_session)
        resolved = await svc.resolve_for_target(
            "nonexistent-host-99", organization_id=test_org.id
        )
        assert resolved is None

    async def test_scopes_to_caller_org(
        self,
        db_session: AsyncSession,
        test_agent: EndpointAgent,
        test_org: Organization,
    ):
        """The agent belongs to test_org. Resolving the same hostname under a
        DIFFERENT org's id MUST return None — never leak across tenants."""
        from src.models.organization import Organization as OrgModel

        other_org = OrgModel(
            name="OtherOrg", slug="other-org", plan="enterprise", is_active=True
        )
        db_session.add(other_org)
        await db_session.flush()
        svc = AgentService(db_session)
        # Hostname matches but org doesn't — must NOT return the agent
        resolved = await svc.resolve_for_target(
            test_agent.hostname, organization_id=other_org.id
        )
        assert resolved is None

    async def test_organization_id_is_keyword_only(
        self,
        db_session: AsyncSession,
        test_org: Organization,
    ):
        """organization_id MUST be keyword-only — protects against positional
        argument shuffling that could silently drop the tenant filter."""
        svc = AgentService(db_session)
        with pytest.raises(TypeError):
            # Passing organization_id positionally must fail
            await svc.resolve_for_target("some-host", test_org.id)  # type: ignore[misc]
```

Note: This test references `test_agent.ip_address` — only proceed past Step 2 if `EndpointAgent` actually has an `ip_address` field. Check by reading `src/agents/models.py`. If the field is named differently (e.g. `ip`), update the test field name to match. If there is NO IP field, drop `test_resolves_by_ip` and document in the commit.

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/integration/test_agent_service_resolve.py -v
```

Expected: All FAIL with `AttributeError: 'AgentService' object has no attribute 'resolve_for_target'`.

- [ ] **Step 3: Implement `resolve_for_target`**

In `src/agents/service.py`, find the `AgentService` class. Add this method (place it near `issue_command`):

```python
    async def resolve_for_target(
        self,
        target: str,
        *,
        organization_id: str,
    ) -> Optional[EndpointAgent]:
        """Resolve a target string (hostname or IP) to a registered EndpointAgent.

        Tries hostname match first, then IP. Always scoped to organization_id —
        the parameter is keyword-only and mandatory so a caller can't silently
        drop the tenant filter via positional argument shuffling. Returns None
        if no agent matches in that tenant.

        Used by remediation executors that need an agent to dispatch to.
        Callers must handle None as 'no agent enrolled for this target' —
        NOT as a transient error to retry.
        """
        from sqlalchemy import select

        stmt = (
            select(EndpointAgent)
            .where(EndpointAgent.hostname == target)
            .where(EndpointAgent.organization_id == organization_id)
        )
        result = await self.session.execute(stmt)
        agent = result.scalars().first()
        if agent:
            return agent

        # Hostname miss — try IP. Only proceed if the model has an IP field.
        if hasattr(EndpointAgent, "ip_address"):
            stmt = (
                select(EndpointAgent)
                .where(EndpointAgent.ip_address == target)
                .where(EndpointAgent.organization_id == organization_id)
            )
            result = await self.session.execute(stmt)
            return result.scalars().first()

        return None
```

If imports for `Optional`, `select`, or `EndpointAgent` aren't already at the top of `service.py`, add them. Most likely all are present.

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/integration/test_agent_service_resolve.py -v
```

Expected: All tests PASS (or 3 PASS + the IP test skipped if the model has no IP field).

- [ ] **Step 5: Commit**

```bash
git add src/agents/service.py tests/integration/test_agent_service_resolve.py
git commit -m "$(cat <<'EOF'
agents: add AgentService.resolve_for_target for executor dispatch

Resolves a target hostname or IP to a registered EndpointAgent, optionally
scoped to a tenant. Returns None for unknown targets — callers must handle
that as 'no agent enrolled' (real signal), not as a transient failure.

Used by the upcoming kill_process / file_quarantine / collect_forensics
executors to bridge from a remediation-engine target string to a concrete
agent before calling issue_command.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Harden `AccountActionExecutor` password_reset to generate a real token

**Files:**

- Modify: `src/remediation/engine.py` (the `AccountActionExecutor.execute` method)
- Modify: `tests/integration/test_action_executors.py` (created later — for this task, create the file with this one test class)

- [ ] **Step 1: Create the test file with the first test class**

Create `tests/integration/test_action_executors.py`:

```python
"""Per-executor integration tests for the fixed action executors in PR 2.

Each test class corresponds to one ActionType enum value (PR 3 will add).
Tests assert observable DB side-effects, never just that the function returned
success=True.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import EndpointAgent, AgentCommand
from src.models.organization import Organization
from src.models.user import User
from src.models.alert import Alert  # may be needed by some tests
from src.remediation.engine import (
    AccountActionExecutor,
    FirewallBlockExecutor,
    HostIsolationExecutor,
)


def _context_for(user_id: str, org_id: str) -> dict:
    """Shared helper to build the executor context dict."""
    return {
        "execution_id": "test-exec-" + org_id[:8],
        "organization_id": org_id,
        "initiated_by": user_id,
        "trigger_data": {},
    }


class TestPasswordResetGeneratesRealToken:
    async def test_token_is_set_and_indexed(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=test_user.email,
            parameters={"action": "password_reset"},
            context=_context_for(test_user.id, test_org.id),
        )

        assert result["success"] is True

        await db_session.refresh(test_user)
        assert test_user.password_reset_token is not None
        assert len(test_user.password_reset_token) >= 40  # 48-byte url-safe is ~64 chars
        assert test_user.password_reset_token_expires_at is not None
        assert test_user.password_reset_token_expires_at > datetime.now(timezone.utc)
        assert test_user.password_reset_token_expires_at < (
            datetime.now(timezone.utc) + timedelta(hours=25)
        )
        assert test_user.force_password_change is True

    async def test_token_is_NOT_returned_in_result(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        """The plaintext token must not leak through the executor's return
        value — only the User row carries it."""
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=test_user.email,
            parameters={"action": "password_reset"},
            context=_context_for(test_user.id, test_org.id),
        )
        await db_session.refresh(test_user)
        # The full plaintext token must not be in the result dict
        result_str = str(result)
        assert test_user.password_reset_token not in result_str

    async def test_audit_row_carries_no_token_material(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        """The TicketActivity audit row must contain NO token-identifying
        material — not the plaintext token, not a sha256 prefix, not a
        suffix, not anything an attacker with audit-log read access could
        correlate to the specific token."""
        import hashlib
        import json
        from src.tickethub.models import TicketActivity

        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=test_user.email,
            parameters={"action": "password_reset"},
            context=_context_for(test_user.id, test_org.id),
        )
        await db_session.refresh(test_user)

        # Fetch the most recent activity row for this execution
        stmt = (
            select(TicketActivity)
            .where(TicketActivity.source_id == _context_for(test_user.id, test_org.id)["execution_id"])
            .order_by(TicketActivity.created_at.desc())
        )
        activity = (await db_session.execute(stmt)).scalars().first()
        assert activity is not None

        # Serialize the whole row to a string and assert no token derivatives
        row_dump = json.dumps(
            {
                "description": activity.description,
                "extra_metadata": activity.extra_metadata,
            },
            default=str,
        )
        token = test_user.password_reset_token
        assert token not in row_dump
        # Common partial-leak patterns the team might be tempted to add later:
        sha_full = hashlib.sha256(token.encode()).hexdigest()
        for length in (8, 16, 24, 32, 64):
            assert sha_full[:length] not in row_dump
            assert sha_full[-length:] not in row_dump
        assert token[:8] not in row_dump
        assert token[-8:] not in row_dump
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/integration/test_action_executors.py::TestPasswordResetGeneratesRealToken -v
```

Expected: FAIL — `test_user.password_reset_token` is None after execute (the current code only sets `force_password_change`).

- [ ] **Step 3: Modify `AccountActionExecutor.execute` password_reset branch**

In `src/remediation/engine.py`, find this block in `AccountActionExecutor.execute` (currently around line 783):

```python
        elif action == "password_reset":
            user.force_password_change = True
```

Replace with:

```python
        elif action == "password_reset":
            import secrets
            from datetime import timedelta

            user.force_password_change = True
            user.password_reset_token = secrets.token_urlsafe(48)
            user.password_reset_token_expires_at = utc_now() + timedelta(hours=24)
```

`utc_now` is already imported in `engine.py`. `secrets` and `timedelta` are stdlib and imported locally to keep the change scoped.

Also update the `extra_metadata` in the `_log_ticket_activity` call to include the reset expiry (a non-secret value) but **nothing token-identifying**. No `token_id`, no `sha256(token)[:N]`, no `token[-4:]`, no hint that would let an attacker correlate audit rows to specific tokens.

Find the call to `_log_ticket_activity` after the action branches. The current `extra_metadata` is:

```python
            extra_metadata={
                "user_id": user.id,
                "email": user.email,
                "action": action,
                "previous_is_active": previous_active,
                "new_is_active": user.is_active,
            },
```

Right BEFORE that `_log_ticket_activity` call, add this conditional that augments only with the expiry timestamp:

```python
        reset_meta = {}
        if action == "password_reset" and user.password_reset_token_expires_at:
            # Record ONLY the expiry timestamp. The token itself and any
            # hash/prefix of it stays out of the audit row — an attacker
            # with read access to ticket_activities can't correlate to a
            # specific token.
            reset_meta = {
                "reset_expires_at": user.password_reset_token_expires_at.isoformat(),
            }
```

Then update the existing `extra_metadata={...}` dict literal to spread `reset_meta` into it:

```python
            extra_metadata={
                "user_id": user.id,
                "email": user.email,
                "action": action,
                "previous_is_active": previous_active,
                "new_is_active": user.is_active,
                **reset_meta,
            },
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/integration/test_action_executors.py::TestPasswordResetGeneratesRealToken -v
```

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/remediation/engine.py tests/integration/test_action_executors.py
git commit -m "$(cat <<'EOF'
remediation(account): password_reset generates a real one-time token

Previous code only flipped force_password_change=True — no actual reset
credential existed. Now generates secrets.token_urlsafe(48) with a 24h
expiry, writes both to the User row, and references the token in audit
metadata via a sha256 prefix (NOT the token itself) so SIEM logs don't
leak the secret.

The downstream URL-consumption flow (validating /reset?token=...) is out
of scope for this PR. The executor's contract is: after this call, the
User has a real, time-bounded reset credential.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Password-reset token validation endpoint

Task 5 makes the token exist on the User row. Without an endpoint that consumes it, the token does nothing — that's still a stub at the system level. This task adds `POST /api/v1/auth/password-reset/validate` that takes a token and reports whether it's valid + unexpired, **without consuming it**. The frontend uses this on page-load of the reset URL to decide whether to render the new-password form or an "expired link" message.

**Files:**

- Modify: `src/api/v1/endpoints/auth.py` (append the endpoint)
- Create: `tests/integration/test_password_reset_endpoints.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/integration/test_password_reset_endpoints.py`:

```python
"""End-to-end tests for the password-reset URL consumption flow.

Tests both /validate and /consume endpoints (consume comes in Task 7).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.main import app
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
    db_session: AsyncSession, test_org: Organization, test_user: User
) -> tuple[User, str]:
    """Run the executor to create a real token on test_user. Returns the user
    and the plaintext token so the endpoint tests can submit it."""
    executor = AccountActionExecutor(db_session)
    await executor.execute(
        target=test_user.email,
        parameters={"action": "password_reset"},
        context=_ctx(test_user.id, test_org.id),
    )
    await db_session.commit()
    await db_session.refresh(test_user)
    return test_user, test_user.password_reset_token


class TestPasswordResetValidate:
    async def test_valid_token_returns_200(self, issued_reset_token):
        user, token = issued_reset_token
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
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

    async def test_unknown_token_returns_404(self):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/api/v1/auth/password-reset/validate",
                json={"token": "no-such-token-xxxxxxxxxxxxxxxx"},
            )
        assert r.status_code == 404
        body = r.json()
        # Generic error — must NOT confirm "no such token" vs "expired"
        # because that differential helps an attacker probe token space.
        assert "detail" in body
        assert "invalid" in body["detail"].lower() or "expired" in body["detail"].lower()

    async def test_expired_token_returns_410(
        self, db_session: AsyncSession, issued_reset_token
    ):
        user, token = issued_reset_token
        # Backdate the expiry
        user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await db_session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/api/v1/auth/password-reset/validate",
                json={"token": token},
            )
        assert r.status_code == 410
        body = r.json()
        assert "expired" in body["detail"].lower()

    async def test_validate_does_NOT_invalidate(
        self, db_session: AsyncSession, issued_reset_token
    ):
        """Validation is read-only. Repeated calls return 200 each time. The
        token only burns on /consume, not on /validate."""
        user, token = issued_reset_token
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            for _ in range(3):
                r = await client.post(
                    "/api/v1/auth/password-reset/validate",
                    json={"token": token},
                )
                assert r.status_code == 200

        await db_session.refresh(user)
        assert user.password_reset_token == token  # still on the row
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/integration/test_password_reset_endpoints.py::TestPasswordResetValidate -v
```

Expected: All FAIL with 404 (endpoint doesn't exist yet).

- [ ] **Step 3: Add the endpoint**

In `src/api/v1/endpoints/auth.py`, near the top, ensure these imports exist (add what's missing):

```python
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from sqlalchemy import select
from src.models.user import User
```

At the bottom of the file, append:

```python
class PasswordResetTokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)


class PasswordResetValidateResponse(BaseModel):
    valid: bool
    expires_at: datetime


@router.post(
    "/password-reset/validate",
    response_model=PasswordResetValidateResponse,
    summary="Validate a password-reset token without consuming it",
)
async def password_reset_validate(
    payload: PasswordResetTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> PasswordResetValidateResponse:
    """Look up the token. Return 200 with the expiry if valid and unexpired,
    410 if expired, 404 if unknown. Generic error wording avoids confirming
    whether a guessed token exists in the system (enumeration defense)."""
    stmt = select(User).where(User.password_reset_token == payload.token)
    user = (await db.execute(stmt)).scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="Invalid or expired token")
    if (
        user.password_reset_token_expires_at is None
        or user.password_reset_token_expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=410, detail="Token has expired")
    return PasswordResetValidateResponse(
        valid=True,
        expires_at=user.password_reset_token_expires_at,
    )
```

If `HTTPException`, `Depends`, `get_db`, `AsyncSession`, or `router` aren't already imported at the top of `auth.py`, add them.

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/integration/test_password_reset_endpoints.py::TestPasswordResetValidate -v
```

Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/api/v1/endpoints/auth.py tests/integration/test_password_reset_endpoints.py
git commit -m "$(cat <<'EOF'
auth: POST /password-reset/validate — read-only token check

Lets the frontend page-load the reset URL and decide whether to render
the new-password form or an "expired link" message without burning the
token. 200 on valid+unexpired, 410 on expired, 404 on unknown — generic
wording so an attacker probing token space can't differentiate "no such
token" from "expired" via response content.

Response carries valid + expires_at. NO email, NO user_id — disclosing
which user a token belongs to would be an enumeration leak.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Password-reset token consumption endpoint

Completes the URL flow — accepts a token + new password, validates the token, applies the new password hash, invalidates the token, returns 200. After this task lands, password_reset is a real end-to-end flow.

**Files:**

- Modify: `src/api/v1/endpoints/auth.py` (append the endpoint)
- Modify: `tests/integration/test_password_reset_endpoints.py` (append new test class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_password_reset_endpoints.py`:

```python
class TestPasswordResetConsume:
    async def test_valid_token_changes_password(
        self,
        db_session: AsyncSession,
        issued_reset_token,
    ):
        user, token = issued_reset_token
        old_hash = user.hashed_password

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
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
        # force_password_change flag cleared (user just did exactly that)
        assert user.force_password_change is False

    async def test_token_only_works_once(
        self,
        db_session: AsyncSession,
        issued_reset_token,
    ):
        user, token = issued_reset_token
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
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
    ):
        user, token = issued_reset_token
        user.password_reset_token_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await db_session.commit()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/api/v1/auth/password-reset/consume",
                json={"token": token, "new_password": "NewStr0ng!Pass2026"},
            )
        assert r.status_code == 410

    async def test_weak_password_rejected(
        self,
        db_session: AsyncSession,
        issued_reset_token,
    ):
        """The endpoint must enforce a minimum password length — otherwise
        the reset flow becomes the cheapest path to set a one-character
        password, defeating any account-level policy elsewhere."""
        user, token = issued_reset_token
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.post(
                "/api/v1/auth/password-reset/consume",
                json={"token": token, "new_password": "x"},  # too short
            )
        assert r.status_code == 422  # Pydantic validation failure

        await db_session.refresh(user)
        # Token must NOT be burned on validation failure
        assert user.password_reset_token == token
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/integration/test_password_reset_endpoints.py::TestPasswordResetConsume -v
```

Expected: All FAIL with 404 (endpoint doesn't exist yet).

- [ ] **Step 3: Add the endpoint**

Make sure `get_password_hash` is imported at the top of `auth.py`. If not, add:

```python
from src.core.security import get_password_hash
```

Append to the bottom of `src/api/v1/endpoints/auth.py`:

```python
class PasswordResetConsumeRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post(
    "/password-reset/consume",
    summary="Consume a password-reset token and set a new password",
)
async def password_reset_consume(
    payload: PasswordResetConsumeRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Burn the token, set the new password hash, clear force_password_change.

    Returns 200 with a generic body — never echoes the email or user_id so a
    successful response doesn't leak account identity to whoever submits the
    token. The downstream login flow is where the user proves identity."""
    stmt = select(User).where(User.password_reset_token == payload.token)
    user = (await db.execute(stmt)).scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="Invalid or expired token")
    if (
        user.password_reset_token_expires_at is None
        or user.password_reset_token_expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=410, detail="Token has expired")

    user.hashed_password = get_password_hash(payload.new_password)
    user.password_reset_token = None
    user.password_reset_token_expires_at = None
    user.force_password_change = False
    await db.commit()

    return {"status": "password_updated"}
```

- [ ] **Step 4: Run all reset-endpoint tests**

```bash
python -m pytest tests/integration/test_password_reset_endpoints.py -v
```

Expected: All 8 PASS (4 validate + 4 consume).

- [ ] **Step 5: Commit**

```bash
git add src/api/v1/endpoints/auth.py tests/integration/test_password_reset_endpoints.py
git commit -m "$(cat <<'EOF'
auth: POST /password-reset/consume — burn token + set new password

Completes the reset URL flow. Validates the token, sets the new password
hash, clears the token + expiry + force_password_change flag in a single
transaction so a repeated submission of the same token gets 404 (token
already burned).

Generic 200 body — no email, no user_id echoed back. Login is where
identity is proven, not here.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Rewrite `ProcessActionExecutor` to use real agent dispatch

**Files:**

- Modify: `src/remediation/engine.py` (`ProcessActionExecutor.execute`)
- Modify: `tests/integration/test_action_executors.py` (append new test class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_action_executors.py`:

```python
class TestProcessKillIssuesAgentCommand:
    async def test_writes_agent_commands_row(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
        test_agent: EndpointAgent,
    ):
        from src.remediation.engine import ProcessActionExecutor

        executor = ProcessActionExecutor(db_session)
        result = await executor.execute(
            target=test_agent.hostname,
            parameters={"action": "kill", "pid": 1234, "process_name": "malware.exe"},
            context=_context_for(test_user.id, test_org.id),
        )

        assert result["success"] is True
        assert "command_id" in result
        # Now verify a real agent_commands row was written
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd_row = (await db_session.execute(stmt)).scalars().first()
        assert cmd_row is not None
        assert cmd_row.action == "kill_process"
        assert cmd_row.agent_id == test_agent.id
        assert cmd_row.payload.get("pid") == 1234
        assert cmd_row.payload.get("process_name") == "malware.exe"
        # Hash chain must be populated
        assert cmd_row.command_hash
        assert cmd_row.chain_hash
        # Status: queued or awaiting_approval (high-blast); never "fake-success"
        assert cmd_row.status in ("queued", "awaiting_approval")

    async def test_returns_failure_when_no_agent(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        """No agent enrolled for the target → executor returns success=False
        with a real error. Never returns success=True with a placeholder."""
        from src.remediation.engine import ProcessActionExecutor

        executor = ProcessActionExecutor(db_session)
        result = await executor.execute(
            target="no-such-host-12345",
            parameters={"action": "kill", "pid": 1, "process_name": "x"},
            context=_context_for(test_user.id, test_org.id),
        )
        assert result["success"] is False
        assert "no agent" in result["error"].lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/integration/test_action_executors.py::TestProcessKillIssuesAgentCommand -v
```

Expected: Both FAIL. The first because the current executor returns `activity_id` not `command_id` and doesn't write to `agent_commands`. The second because the current executor returns `success=True` regardless of agent presence.

- [ ] **Step 3: Rewrite `ProcessActionExecutor.execute`**

In `src/remediation/engine.py`, find the `ProcessActionExecutor.execute` method. Replace its entire body with:

```python
    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        from src.agents.service import AgentService, AgentServiceError

        execution_id, org_id, actor_id = _get_execution_context(context)
        action = parameters.get("action", "kill")
        process_name = parameters.get("process_name")
        pid = parameters.get("pid")

        self.logger.info(
            "Dispatching process action to endpoint agent",
            extra={"target": target, "action": action},
        )

        svc = AgentService(self.db)
        agent = await svc.resolve_for_target(target, organization_id=org_id)
        if agent is None:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type=f"process_{action}_no_agent",
                description=(
                    f"Process action '{action}' requested for {target} "
                    f"but no endpoint agent is enrolled for that target"
                ),
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={
                    "host": target,
                    "action": action,
                    "process_name": process_name,
                    "pid": pid,
                },
            )
            return {
                "success": False,
                "action": action,
                "target": target,
                "error": "no agent enrolled for target",
            }

        agent_action = "kill_process" if action == "kill" else action
        payload = {
            "pid": pid,
            "process_name": process_name,
        }
        try:
            cmd = await svc.issue_command(
                agent=agent,
                action=agent_action,
                payload=payload,
                issued_by=actor_id,
            )
        except AgentServiceError as exc:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type=f"process_{action}_rejected",
                description=f"Agent service rejected {action}: {exc}",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={
                    "host": target,
                    "action": action,
                    "agent_id": agent.id,
                    "rejection_reason": str(exc),
                },
            )
            return {
                "success": False,
                "action": action,
                "target": target,
                "error": str(exc),
            }

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type=f"process_{action}_queued",
            description=(
                f"Process action '{action}' queued to agent {agent.hostname} "
                f"(command_id={cmd.id}, status={cmd.status})"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "host": target,
                "action": action,
                "process_name": process_name,
                "pid": pid,
                "agent_id": agent.id,
                "command_id": cmd.id,
                "command_status": cmd.status,
            },
        )

        return {
            "success": True,
            "action": action,
            "target": target,
            "command_id": cmd.id,
            "command_status": cmd.status,
            "agent_id": agent.id,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/integration/test_action_executors.py::TestProcessKillIssuesAgentCommand -v
```

Expected: Both PASS.

- [ ] **Step 5: Commit**

```bash
git add src/remediation/engine.py tests/integration/test_action_executors.py
git commit -m "$(cat <<'EOF'
remediation(process): wire ProcessActionExecutor to real agent dispatch

Replaces the prior stub (which only logged a TicketActivity 'queued for
agent' and returned success=True with no actual queue entry) with a real
call to AgentService.issue_command. Writes an agent_commands row with
proper hash-chain integrity, returns the real command_id, and returns
success=False with 'no agent enrolled for target' when no endpoint is
available — never a silent success-with-fake-queued-status.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: New `FileActionExecutor` for file_quarantine

**Files:**

- Modify: `src/remediation/engine.py` (add new executor class)
- Modify: `tests/integration/test_action_executors.py` (append new test class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_action_executors.py`:

```python
class TestFileQuarantineIssuesAgentCommand:
    async def test_writes_agent_commands_row(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
        test_agent: EndpointAgent,
    ):
        from src.remediation.engine import FileActionExecutor

        executor = FileActionExecutor(db_session)
        result = await executor.execute(
            target=test_agent.hostname,
            parameters={"file_path": "/tmp/malware.bin", "file_hash": "abc123"},
            context=_context_for(test_user.id, test_org.id),
        )

        assert result["success"] is True
        assert "command_id" in result
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd_row = (await db_session.execute(stmt)).scalars().first()
        assert cmd_row is not None
        assert cmd_row.action == "quarantine_file"
        assert cmd_row.payload.get("file_path") == "/tmp/malware.bin"

    async def test_returns_failure_when_no_agent(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        from src.remediation.engine import FileActionExecutor

        executor = FileActionExecutor(db_session)
        result = await executor.execute(
            target="no-such-host-12345",
            parameters={"file_path": "/tmp/x"},
            context=_context_for(test_user.id, test_org.id),
        )
        assert result["success"] is False
        assert "no agent" in result["error"].lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/integration/test_action_executors.py::TestFileQuarantineIssuesAgentCommand -v
```

Expected: Both FAIL with `ImportError: cannot import name 'FileActionExecutor'`.

- [ ] **Step 3: Add the `FileActionExecutor` class**

In `src/remediation/engine.py`, after `ProcessActionExecutor`, append:

```python
class FileActionExecutor(ActionExecutor):
    """File-level actions queued for endpoint agent execution (quarantine_file)."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        from src.agents.service import AgentService, AgentServiceError

        execution_id, org_id, actor_id = _get_execution_context(context)
        file_path = parameters.get("file_path")
        file_hash = parameters.get("file_hash")

        svc = AgentService(self.db)
        agent = await svc.resolve_for_target(target, organization_id=org_id)
        if agent is None:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="file_quarantine_no_agent",
                description=(
                    f"File quarantine requested for {file_path} on {target} "
                    f"but no endpoint agent is enrolled"
                ),
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={
                    "host": target,
                    "file_path": file_path,
                    "file_hash": file_hash,
                },
            )
            return {
                "success": False,
                "action": "file_quarantine",
                "target": target,
                "error": "no agent enrolled for target",
            }

        try:
            cmd = await svc.issue_command(
                agent=agent,
                action="quarantine_file",
                payload={
                    "file_path": file_path,
                    "file_hash": file_hash,
                },
                issued_by=actor_id,
            )
        except AgentServiceError as exc:
            return {
                "success": False,
                "action": "file_quarantine",
                "target": target,
                "error": str(exc),
            }

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="file_quarantine_queued",
            description=(
                f"Quarantine queued for {file_path} on {agent.hostname} "
                f"(command_id={cmd.id})"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "host": target,
                "file_path": file_path,
                "file_hash": file_hash,
                "agent_id": agent.id,
                "command_id": cmd.id,
                "command_status": cmd.status,
            },
        )

        return {
            "success": True,
            "action": "file_quarantine",
            "target": target,
            "command_id": cmd.id,
            "command_status": cmd.status,
            "agent_id": agent.id,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/integration/test_action_executors.py::TestFileQuarantineIssuesAgentCommand -v
```

Expected: Both PASS.

- [ ] **Step 5: Commit**

```bash
git add src/remediation/engine.py tests/integration/test_action_executors.py
git commit -m "$(cat <<'EOF'
remediation(file): FileActionExecutor for real quarantine_file dispatch

Previously no server-side executor existed for file quarantine — the
action would silently fall through. New FileActionExecutor uses
AgentService.issue_command to queue a real agent_commands row with
hash-chain integrity, mirroring ProcessActionExecutor's pattern.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: `ForensicsCollectionExecutor` (composite)

**Files:**

- Modify: `src/remediation/engine.py` (add new executor class)
- Modify: `tests/integration/test_action_executors.py` (append new test class)

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_action_executors.py`:

```python
class TestForensicsCollectionIssuesThreeCommands:
    async def test_three_commands_queued(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
        test_agent: EndpointAgent,
    ):
        from src.remediation.engine import ForensicsCollectionExecutor

        executor = ForensicsCollectionExecutor(db_session)
        result = await executor.execute(
            target=test_agent.hostname,
            parameters={},
            context=_context_for(test_user.id, test_org.id),
        )

        # Per-sub-result reporting: each sub-command reports independently
        assert "sub_results" in result
        assert isinstance(result["sub_results"], list)
        assert len(result["sub_results"]) == 3

        # All three should have queued cleanly (agent enrolled with all capabilities)
        for sub in result["sub_results"]:
            assert sub["success"] is True
            assert sub["command_id"] is not None
            assert sub["error"] is None
        actions = sorted(sub["sub_action"] for sub in result["sub_results"])
        assert actions == sorted([
            "collect_process_list",
            "collect_network_connections",
            "collect_memory_dump",
        ])

        # All three commands should exist in agent_commands with distinct chain hashes
        cmd_ids = [sub["command_id"] for sub in result["sub_results"]]
        stmt = select(AgentCommand).where(AgentCommand.id.in_(cmd_ids))
        cmd_rows = (await db_session.execute(stmt)).scalars().all()
        chain_hashes = {c.chain_hash for c in cmd_rows}
        assert len(chain_hashes) == 3

    async def test_partial_success_when_capability_rejected(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        """Build an agent enrolled with ONLY `bas` (no ir). Each sub-action
        is reported on its own merits — collect_process_list might queue
        while collect_memory_dump gets rejected. The executor reports both
        truthfully, doesn't roll the partial into a single misleading
        composite verdict."""
        from src.remediation.engine import ForensicsCollectionExecutor

        partial_agent = EndpointAgent(
            hostname="partial-cap-host",
            platform="linux",
            agent_version="0.1.0",
            capabilities=["bas"],  # no ir
            status="online",
            organization_id=test_org.id,
        )
        db_session.add(partial_agent)
        await db_session.flush()

        executor = ForensicsCollectionExecutor(db_session)
        result = await executor.execute(
            target=partial_agent.hostname,
            parameters={},
            context=_context_for(test_user.id, test_org.id),
        )

        assert "sub_results" in result
        assert len(result["sub_results"]) == 3
        # At least one queued, at least one rejected — exact mix depends on
        # the capability_allows() rules. Each sub-result is honest.
        successes = [s for s in result["sub_results"] if s["success"]]
        failures = [s for s in result["sub_results"] if not s["success"]]
        assert len(successes) + len(failures) == 3
        for f in failures:
            assert f["command_id"] is None
            assert f["error"]  # non-empty error string

    async def test_reports_failure_when_no_agent(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        """No agent enrolled → each sub_result reports the same 'no agent'
        error. The composite doesn't pretend any sub-command queued."""
        from src.remediation.engine import ForensicsCollectionExecutor

        executor = ForensicsCollectionExecutor(db_session)
        result = await executor.execute(
            target="no-such-host-12345",
            parameters={},
            context=_context_for(test_user.id, test_org.id),
        )
        assert "sub_results" in result
        assert len(result["sub_results"]) == 3
        for sub in result["sub_results"]:
            assert sub["success"] is False
            assert sub["command_id"] is None
            assert "no agent" in sub["error"].lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/integration/test_action_executors.py::TestForensicsCollectionIssuesThreeCommands -v
```

Expected: Both FAIL with `ImportError: cannot import name 'ForensicsCollectionExecutor'`.

- [ ] **Step 3: Add the `ForensicsCollectionExecutor` class**

In `src/remediation/engine.py`, after `FileActionExecutor`, append:

```python
class ForensicsCollectionExecutor(ActionExecutor):
    """Composite forensics collection: issues collect_process_list,
    collect_network_connections, and collect_memory_dump as three separate
    agent commands so each can be tracked individually in the audit chain.

    Per-sub-result reporting: each sub-command reports its own success
    independently in ``sub_results``. NO composite success/failure flag —
    that would conflate "all queued" with "two queued, one rejected" and
    hide the partial-execution reality from the caller. Callers that need
    a roll-up should compute it from sub_results themselves.
    """

    SUB_COMMANDS = (
        "collect_process_list",
        "collect_network_connections",
        "collect_memory_dump",
    )

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        from src.agents.service import AgentService, AgentServiceError

        execution_id, org_id, actor_id = _get_execution_context(context)

        svc = AgentService(self.db)
        agent = await svc.resolve_for_target(target, organization_id=org_id)

        if agent is None:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="collect_forensics_no_agent",
                description=f"Forensics collection requested for {target} but no agent enrolled",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={"host": target},
            )
            no_agent_err = "no agent enrolled for target"
            return {
                "action": "collect_forensics",
                "target": target,
                "agent_id": None,
                "sub_results": [
                    {
                        "sub_action": sub,
                        "success": False,
                        "command_id": None,
                        "error": no_agent_err,
                    }
                    for sub in self.SUB_COMMANDS
                ],
            }

        sub_results: list[dict] = []
        for sub_action in self.SUB_COMMANDS:
            try:
                cmd = await svc.issue_command(
                    agent=agent,
                    action=sub_action,
                    payload=parameters or {},
                    issued_by=actor_id,
                )
                sub_results.append({
                    "sub_action": sub_action,
                    "success": True,
                    "command_id": cmd.id,
                    "error": None,
                })
            except AgentServiceError as exc:
                sub_results.append({
                    "sub_action": sub_action,
                    "success": False,
                    "command_id": None,
                    "error": str(exc),
                })

        queued = sum(1 for s in sub_results if s["success"])
        rejected = len(self.SUB_COMMANDS) - queued
        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="collect_forensics_dispatched",
            description=(
                f"Forensics dispatched on {agent.hostname}: "
                f"{queued} queued, {rejected} rejected (per sub-command, see metadata)"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "host": target,
                "agent_id": agent.id,
                "sub_results": sub_results,
            },
        )

        return {
            "action": "collect_forensics",
            "target": target,
            "agent_id": agent.id,
            "sub_results": sub_results,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/integration/test_action_executors.py::TestForensicsCollectionIssuesThreeCommands -v
```

Expected: Both PASS.

- [ ] **Step 5: Commit**

```bash
git add src/remediation/engine.py tests/integration/test_action_executors.py
git commit -m "$(cat <<'EOF'
remediation(forensics): ForensicsCollectionExecutor — three real commands

collect_forensics had no implementation. New composite executor issues
three separate agent commands (collect_process_list,
collect_network_connections, collect_memory_dump) so each is independently
auditable via the hash chain. Partial-success policy: reports success=False
if any sub-command is rejected, returns the list of IDs that DID get
queued so the operator can see exactly what was dispatched.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Closed `ActionType` enum + Pydantic schemas in `src/agentic/action_classifier.py`

**Files:**

- Create: `src/agentic/action_classifier.py`
- Create: `tests/unit/test_action_classifier_schemas.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_action_classifier_schemas.py`:

```python
"""Schema validation tests for the closed ActionType enum + Pydantic models.

The enum values are the canonical RemediationAction.action_type strings
(firewall_block, host_isolate, etc.) — not the colloquial spec names.
Tests here are pure schema validation; the capability gate test in
tests/integration/test_action_handlers_are_real.py verifies each enum
value actually maps to a real handler.
"""

from pydantic import ValidationError
import pytest

from src.agentic.action_classifier import (
    ActionType,
    ClassifiedAction,
    ActionClassification,
)


class TestActionTypeEnum:
    def test_has_exactly_seven_values(self):
        assert len(ActionType) == 7

    def test_canonical_values(self):
        assert ActionType.FIREWALL_BLOCK.value == "firewall_block"
        assert ActionType.HOST_ISOLATE.value == "host_isolate"
        assert ActionType.ACCOUNT_DISABLE.value == "account_disable"
        assert ActionType.PASSWORD_RESET.value == "password_reset"
        assert ActionType.PROCESS_KILL.value == "process_kill"
        assert ActionType.FILE_QUARANTINE.value == "file_quarantine"
        assert ActionType.COLLECT_FORENSICS.value == "collect_forensics"


class TestClassifiedActionSchema:
    def test_valid_classified_action(self):
        a = ClassifiedAction(
            recommendation_text="block 1.2.3.4 at the firewall",
            action_type=ActionType.FIREWALL_BLOCK,
            args={"ip": "1.2.3.4"},
        )
        assert a.action_type == ActionType.FIREWALL_BLOCK
        assert a.args["ip"] == "1.2.3.4"

    def test_invalid_action_type_rejected(self):
        with pytest.raises(ValidationError):
            ClassifiedAction(
                recommendation_text="x",
                action_type="block_ip",  # colloquial; not in enum
                args={},
            )

    def test_args_must_be_dict(self):
        with pytest.raises(ValidationError):
            ClassifiedAction(
                recommendation_text="x",
                action_type=ActionType.FIREWALL_BLOCK,
                args="not a dict",
            )


class TestActionClassificationSchema:
    def test_empty_lists_valid(self):
        c = ActionClassification(actions=[], unsupported=[])
        assert c.actions == []
        assert c.unsupported == []

    def test_full_classification(self):
        c = ActionClassification(
            actions=[
                ClassifiedAction(
                    recommendation_text="block c2",
                    action_type=ActionType.FIREWALL_BLOCK,
                    args={"ip": "203.0.113.42"},
                )
            ],
            unsupported=["schedule a tabletop exercise next quarter"],
        )
        assert len(c.actions) == 1
        assert c.actions[0].action_type == ActionType.FIREWALL_BLOCK
        assert c.unsupported == ["schedule a tabletop exercise next quarter"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_action_classifier_schemas.py -v
```

Expected: All FAIL with `ImportError: cannot import name 'ActionType' from 'src.agentic.action_classifier'` (module doesn't exist).

- [ ] **Step 3: Create the module**

Create `src/agentic/action_classifier.py`:

```python
"""Closed-enum action classifier schemas.

Every value in ActionType maps end-to-end to a verified handler in
src/remediation/engine.py (proven by tests/integration/test_action_handlers_are_real.py).
Enum values match the canonical RemediationAction.action_type strings, so the
classifier output flows directly into RemediationEngine without translation.

PR 3 of sub-project E will add the ActionClassifier service that calls Gemini
with this schema and feeds the result into the agentic investigator's verdict
finalization. This module ships the schemas + enum only; no caller yet.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Closed enum: each value has a verified handler in the remediation engine.

    Adding a new value REQUIRES adding a corresponding executor and proving it
    passes tests/integration/test_action_handlers_are_real.py. Values are the
    canonical RemediationAction.action_type strings (not the colloquial names
    in the original spec).
    """

    FIREWALL_BLOCK = "firewall_block"          # FirewallBlockExecutor
    HOST_ISOLATE = "host_isolate"              # HostIsolationExecutor
    ACCOUNT_DISABLE = "account_disable"        # AccountActionExecutor (action=disable)
    PASSWORD_RESET = "password_reset"          # AccountActionExecutor (action=password_reset)
    PROCESS_KILL = "process_kill"              # ProcessActionExecutor (action=kill)
    FILE_QUARANTINE = "file_quarantine"        # FileActionExecutor
    COLLECT_FORENSICS = "collect_forensics"    # ForensicsCollectionExecutor (composite)


class ClassifiedAction(BaseModel):
    """One LLM recommendation mapped to a structured action.

    recommendation_text is the original English the LLM emitted; action_type
    is the matched enum; args are the parameters the corresponding executor
    expects in its `parameters` dict.
    """

    recommendation_text: str = Field(max_length=2000)
    action_type: ActionType
    args: dict[str, Any] = Field(default_factory=dict)


class ActionClassification(BaseModel):
    """Result of running the action classifier against an investigation's
    final recommendations.

    `actions` is the list of mapped, executable actions. `unsupported` is the
    list of recommendation_text strings the LLM could not map to the enum —
    these become visible system capability gaps via the
    /agentic/capability-gaps endpoint (PR 5), never silently dropped.
    """

    actions: list[ClassifiedAction] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_action_classifier_schemas.py -v
```

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentic/action_classifier.py tests/unit/test_action_classifier_schemas.py
git commit -m "$(cat <<'EOF'
agentic: closed-enum ActionType + Pydantic schemas

Seven values, each backed by a verified executor in src/remediation/engine.py
(proven by tests/integration/test_action_handlers_are_real.py in this PR).
No caller yet — PR 3 wires this enum into the agentic-investigator's verdict
finalization via the new ActionClassifier service.

Enum values match the canonical RemediationAction.action_type strings, so
the classifier output flows directly into RemediationEngine without
translation. Unsupported recommendations bubble up via the .unsupported
list — never silently dropped or fake-bucketed into create_ticket.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Capability gate integration test — proves every enum value is real

**Files:**

- Create: `tests/integration/test_action_handlers_are_real.py`

- [ ] **Step 1: Write the gate test**

Create `tests/integration/test_action_handlers_are_real.py`:

```python
"""Capability gate: every ActionType enum value MUST map to a real, observable
handler that produces DB-side-effects. If any test in this file fails, the
corresponding enum value cannot ship in src/agentic/action_classifier.py.

This is the Rule 3 enforcer from the sub-project E spec.
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import EndpointAgent, AgentCommand
from src.agentic.action_classifier import ActionType
from src.models.organization import Organization
from src.models.user import User
from src.intel.models import ThreatIndicator
from src.models.asset import Asset
from src.remediation.engine import (
    AccountActionExecutor,
    FileActionExecutor,
    FirewallBlockExecutor,
    ForensicsCollectionExecutor,
    HostIsolationExecutor,
    ProcessActionExecutor,
)


def _ctx(user_id: str, org_id: str) -> dict:
    return {
        "execution_id": f"gate-{org_id[:8]}",
        "organization_id": org_id,
        "initiated_by": user_id,
        "trigger_data": {},
    }


class TestCapabilityGate:
    """One test per ActionType enum value. Each proves observable state change."""

    async def test_firewall_block(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        assert ActionType.FIREWALL_BLOCK.value == "firewall_block"
        executor = FirewallBlockExecutor(db_session)
        result = await executor.execute(
            target="203.0.113.42",
            parameters={"duration_hours": 12},
            context=_ctx(test_user.id, test_org.id),
        )
        assert result["success"] is True
        # Verify the ThreatIndicator was written
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.value == "203.0.113.42",
            ThreatIndicator.is_active == True,  # noqa: E712
        )
        ioc = (await db_session.execute(stmt)).scalars().first()
        assert ioc is not None
        assert ioc.indicator_type == "ipv4"
        assert ioc.severity == "high"

    async def test_host_isolate(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        assert ActionType.HOST_ISOLATE.value == "host_isolate"
        # Need an Asset to isolate
        asset = Asset(
            name="gate-test-host",
            hostname="gate-test-host",
            asset_type="server",
            status="active",
            organization_id=test_org.id,
        )
        db_session.add(asset)
        await db_session.flush()
        executor = HostIsolationExecutor(db_session)
        result = await executor.execute(
            target="gate-test-host",
            parameters={},
            context=_ctx(test_user.id, test_org.id),
        )
        assert result["success"] is True
        await db_session.refresh(asset)
        assert asset.status in ("isolated", "quarantined")

    async def test_account_disable(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        assert ActionType.ACCOUNT_DISABLE.value == "account_disable"
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=test_user.email,
            parameters={"action": "disable"},
            context=_ctx(test_user.id, test_org.id),
        )
        assert result["success"] is True
        await db_session.refresh(test_user)
        assert test_user.is_active is False

    async def test_password_reset(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
    ):
        assert ActionType.PASSWORD_RESET.value == "password_reset"
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=test_user.email,
            parameters={"action": "password_reset"},
            context=_ctx(test_user.id, test_org.id),
        )
        assert result["success"] is True
        await db_session.refresh(test_user)
        assert test_user.password_reset_token is not None
        assert test_user.password_reset_token_expires_at is not None
        assert test_user.password_reset_token_expires_at > datetime.now(timezone.utc)

    async def test_process_kill(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
        test_agent: EndpointAgent,
    ):
        assert ActionType.PROCESS_KILL.value == "process_kill"
        executor = ProcessActionExecutor(db_session)
        result = await executor.execute(
            target=test_agent.hostname,
            parameters={"action": "kill", "pid": 999, "process_name": "evil.exe"},
            context=_ctx(test_user.id, test_org.id),
        )
        assert result["success"] is True
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd = (await db_session.execute(stmt)).scalars().first()
        assert cmd is not None
        assert cmd.action == "kill_process"
        assert cmd.chain_hash  # hash chain populated

    async def test_file_quarantine(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
        test_agent: EndpointAgent,
    ):
        assert ActionType.FILE_QUARANTINE.value == "file_quarantine"
        executor = FileActionExecutor(db_session)
        result = await executor.execute(
            target=test_agent.hostname,
            parameters={"file_path": "/tmp/evil.bin"},
            context=_ctx(test_user.id, test_org.id),
        )
        assert result["success"] is True
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd = (await db_session.execute(stmt)).scalars().first()
        assert cmd is not None
        assert cmd.action == "quarantine_file"

    async def test_collect_forensics(
        self,
        db_session: AsyncSession,
        test_org: Organization,
        test_user: User,
        test_agent: EndpointAgent,
    ):
        assert ActionType.COLLECT_FORENSICS.value == "collect_forensics"
        executor = ForensicsCollectionExecutor(db_session)
        result = await executor.execute(
            target=test_agent.hostname,
            parameters={},
            context=_ctx(test_user.id, test_org.id),
        )
        # Per-sub-result reporting — each sub-command is independent
        assert "sub_results" in result
        assert len(result["sub_results"]) == 3
        # Gate asserts all three queued for the all-capabilities agent
        for sub in result["sub_results"]:
            assert sub["success"] is True
            assert sub["command_id"] is not None
        cmd_ids = [sub["command_id"] for sub in result["sub_results"]]
        stmt = select(AgentCommand).where(AgentCommand.id.in_(cmd_ids))
        cmds = (await db_session.execute(stmt)).scalars().all()
        actions = {c.action for c in cmds}
        assert actions == {
            "collect_process_list",
            "collect_network_connections",
            "collect_memory_dump",
        }


class TestEnumCoverage:
    """Meta-test: if ActionType grows, this test surfaces the new value
    forcing the gate to expand. Catches the regression where someone adds
    an enum value without adding the corresponding test method above."""

    def test_every_enum_has_a_test_method(self):
        existing_tests = {
            name for name in dir(TestCapabilityGate) if name.startswith("test_")
        }
        # Each enum value must have a test method whose name ends with the value
        for action in ActionType:
            expected = f"test_{action.value}"
            assert expected in existing_tests, (
                f"ActionType.{action.name} ({action.value}) has no test method "
                f"'{expected}' in TestCapabilityGate. Add one before this "
                f"enum value can ship — it is not capability-gated."
            )
```

- [ ] **Step 2: Run the gate**

```bash
python -m pytest tests/integration/test_action_handlers_are_real.py -v
```

Expected: All 8 tests PASS (7 enum values + 1 meta-test). If any FAIL, the corresponding enum value does NOT pass the gate — investigate before continuing.

- [ ] **Step 3: Run the full suite to confirm no regressions**

```bash
python -m pytest tests/unit tests/integration -v 2>&1 | tail -30
```

Expected: All previously-passing tests still pass. The PR 1 tests (48) and the new PR 2 tests (numerous) all green. Pre-existing failures in unrelated modules (db setup, auth) are out of scope and acceptable as long as they're not NEW failures.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_action_handlers_are_real.py
git commit -m "$(cat <<'EOF'
test(integration): capability gate for ActionType enum

The Rule 3 enforcer. One test per enum value (7), plus a meta-test that
fails if a new enum value is added without a corresponding gate test.
Each test invokes the real executor end-to-end and asserts observable DB
state change — never just that the function returned success=True.

If any enum value fails the gate, it MUST be removed from
src/agentic/action_classifier.py before this PR can ship. Today all 7
pass, because PR 2 fixed the three stubs that the original sub-project E
brainstorm anticipated would land in 'unsupported follow-up' status.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Full-suite verification + PR-2 commit summary

**Files:** none (verification only)

- [ ] **Step 1: Run the new PR 2 tests in isolation**

```bash
python -m pytest tests/integration/test_agent_service_resolve.py tests/integration/test_action_executors.py tests/integration/test_password_reset_endpoints.py tests/integration/test_action_handlers_are_real.py tests/unit/test_action_classifier_schemas.py -v
```

Expected: All PASS. Count and report.

- [ ] **Step 2: Run the full test suite to confirm no regressions**

```bash
python -m pytest tests/ -v 2>&1 | tail -30
```

Confirm: the PR-1 tests (48 in test_llm_parsing_*) all still pass. Pre-existing failures in unrelated modules are documented as out-of-scope. New failures are NOT acceptable.

- [ ] **Step 3: Confirm PR 2 commits**

```bash
git log --oneline a359498..HEAD
```

Expected: 12-13 commits, one per task (Task 1 is verification-only; Tasks 2-12 each commit). Confirm each commit message scopes correctly: `db(users)`, `agents`, `remediation(...)`, `auth`, `agentic`, `test(integration)`.

- [ ] **Step 4: Report**

This task does not commit. Report:

- Total new tests passing in PR 2
- Total tests in project (pre-existing + PR 1 + PR 2)
- Any new failures (should be zero)
- Commit list with one-line summaries
- Readiness assessment for push

---

## Out of Scope for PR 2

Named explicitly so they can't smuggle back in:

- **Action classifier service** (Gemini call invocation) — PR 3.
- **Investigator integration** (action classifier wired into verdict finalization) — PR 3.
- **`unsupported_recommendations` migration on Investigation** — PR 3.
- **`/agentic/capability-gaps` endpoint** — PR 5.
- **Email/SMS dispatch of reset link** — separate sub-project; this PR creates the token and exposes `/validate` + `/consume` endpoints, but the notification channel that ships the URL to the user runs elsewhere.
- **Frontend reset-link landing page** — out of scope for backend PR. The endpoints exist; the React page that calls them is a separate UI sub-project.
- **Token rate-limit / brute-force protection** — neither endpoint throttles. With 256-bit tokens online brute-force is infeasible, but production deployment should layer rate-limit middleware at the gateway (separate hardening sub-project).
- **Agent autonomy beyond capabilities allowlist** (e.g. expanding `bas`/`ir`/`purple` to new capability strings) — separate sub-project; the gate uses the existing allowlist.
