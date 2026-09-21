"""AuditLogger: flush-not-commit, per-org hash chain, tamper detection, value cap.

Runs against the shared in-memory SQLite DB from ``tests/conftest.py`` so the
``uq_audit_trails_org_prev_hash`` unique index and the ORM columns added by
migration 020 are exercised for real; only the session itself is observed.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit_evidence.engine import AUDIT_VALUE_CAP_BYTES, AuditLogger, AuditWriteError, cap_audit_value
from src.audit_evidence.models import (
    AUDIT_CHAIN_FIELDS,
    AUDIT_GENESIS_HASH,
    AuditTrail,
    audit_row_hash,
    canonical_audit_json,
)
from src.models.organization import Organization


async def _org(db: AsyncSession, name: str) -> Organization:
    org = Organization(name=name, slug=name.lower().replace(" ", "-") + "-" + uuid.uuid4().hex[:6])
    db.add(org)
    await db.flush()
    return org


async def _log(logger: AuditLogger, i: int, **overrides: Any) -> AuditTrail:
    params: dict[str, Any] = dict(
        event_type="agent_tool",
        action=f"tool.executed.{i}",
        actor_type="user",
        actor_id=f"user-{i}",
        resource_type="incident",
        resource_id=f"inc-{i}",
        description=f"step {i}",
        new_value={"step": i},
        result="success",
        risk_level="low",
    )
    params.update(overrides)
    return await logger.log_event(**params)


async def _rows(db: AsyncSession, org_id: str) -> list[AuditTrail]:
    result = await db.scalars(
        select(AuditTrail)
        .where(AuditTrail.organization_id == org_id)
        .order_by(AuditTrail.created_at.asc(), AuditTrail.id.asc())
    )
    return list(result)


# ---------------------------------------------------------------------------
# Transaction ownership
# ---------------------------------------------------------------------------


async def test_log_event_flushes_but_never_commits(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    org = await _org(db_session, "Flush Org")
    await db_session.commit()

    calls: list[str] = []
    real_commit = db_session.commit
    real_rollback = db_session.rollback

    async def spy_commit() -> None:
        calls.append("commit")
        await real_commit()

    async def spy_rollback() -> None:
        calls.append("rollback")
        await real_rollback()

    monkeypatch.setattr(db_session, "commit", spy_commit)
    monkeypatch.setattr(db_session, "rollback", spy_rollback)

    logger = AuditLogger(db_session, org.id)
    row = await _log(logger, 1)
    assert calls == [], "log_event must not commit or roll back the shared session"

    # Flushed: visible inside the transaction ...
    count_in_txn = await db_session.scalar(
        select(func.count()).select_from(AuditTrail).where(AuditTrail.id == row.id)
    )
    assert count_in_txn == 1

    # ... and gone once the caller rolls back, because nothing was committed.
    monkeypatch.undo()
    await db_session.rollback()
    count_after = await db_session.scalar(
        select(func.count()).select_from(AuditTrail).where(AuditTrail.id == row.id)
    )
    assert count_after == 0


async def test_audit_write_failure_raises_typed_error(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    org = await _org(db_session, "Fail Org")
    await db_session.commit()

    async def broken_flush(*_: Any, **__: Any) -> None:
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(db_session, "flush", broken_flush)
    logger = AuditLogger(db_session, org.id)
    with pytest.raises(AuditWriteError, match="agent_tool/tool.executed.1"):
        await _log(logger, 1)


def test_logger_requires_organization() -> None:
    with pytest.raises(ValueError, match="organization"):
        AuditLogger(session=None, org_id="")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Hash chain
# ---------------------------------------------------------------------------


async def test_rows_are_chained_per_org_from_genesis(db_session: AsyncSession) -> None:
    org = await _org(db_session, "Chain Org")
    logger = AuditLogger(db_session, org.id)
    for i in range(3):
        await _log(logger, i, run_id="run-abc")
    await db_session.commit()

    rows = await _rows(db_session, org.id)
    assert len(rows) == 3
    assert rows[0].prev_hash == AUDIT_GENESIS_HASH
    assert rows[1].prev_hash == rows[0].row_hash
    assert rows[2].prev_hash == rows[1].row_hash
    for row in rows:
        assert row.row_hash == audit_row_hash(row.chain_fields(), row.prev_hash)
        assert row.run_id == "run-abc"
        assert row.request_id == "run-abc", "run_id doubles as request_id when none is given"
    assert len({r.row_hash for r in rows}) == 3

    result = await logger.verify_chain()
    assert result == {"ok": True, "first_bad_row": None, "checked": 3, "total": 3, "reason": None}


async def test_row_hash_is_sha256_of_canonical_json_plus_prev(db_session: AsyncSession) -> None:
    org = await _org(db_session, "Canon Org")
    logger = AuditLogger(db_session, org.id)
    row = await _log(logger, 7)
    await db_session.commit()

    canonical = canonical_audit_json(row.chain_fields())
    payload = json.loads(canonical)
    assert set(payload) == set(AUDIT_CHAIN_FIELDS)
    assert payload["created_at"].endswith("Z")
    expected = hashlib.sha256(canonical.encode("utf-8") + b"|" + AUDIT_GENESIS_HASH.encode()).hexdigest()
    assert row.row_hash == expected


async def test_verify_chain_detects_tampered_row(db_session: AsyncSession) -> None:
    org = await _org(db_session, "Tamper Org")
    logger = AuditLogger(db_session, org.id)
    for i in range(4):
        await _log(logger, i)
    await db_session.commit()
    rows = await _rows(db_session, org.id)
    victim = rows[2]

    # Edit the stored row directly, as an attacker with DB access would.
    await db_session.execute(
        text("UPDATE audit_trails SET description = :d WHERE id = :id"),
        {"d": "nothing happened here", "id": victim.id},
    )
    await db_session.commit()
    db_session.expire_all()

    result = await logger.verify_chain()
    assert result["ok"] is False
    assert result["first_bad_row"] == victim.id
    assert result["reason"] == "row_hash_mismatch"
    assert result["checked"] == 2, "the two rows before the tampered one verify"
    assert result["total"] == 4


async def test_verify_chain_detects_deleted_row(db_session: AsyncSession) -> None:
    org = await _org(db_session, "Delete Org")
    logger = AuditLogger(db_session, org.id)
    for i in range(3):
        await _log(logger, i)
    await db_session.commit()
    rows = await _rows(db_session, org.id)

    await db_session.execute(text("DELETE FROM audit_trails WHERE id = :id"), {"id": rows[1].id})
    await db_session.commit()
    db_session.expire_all()

    result = await logger.verify_chain()
    assert result["ok"] is False
    assert result["reason"] == "chain_broken"
    assert result["first_bad_row"] == rows[2].id
    assert result["checked"] == 1 and result["total"] == 2


async def test_verify_chain_flags_unhashed_legacy_row(db_session: AsyncSession) -> None:
    org = await _org(db_session, "Legacy Org")
    logger = AuditLogger(db_session, org.id)
    row = await _log(logger, 0)
    await db_session.commit()

    await db_session.execute(
        text("UPDATE audit_trails SET row_hash = NULL, prev_hash = NULL WHERE id = :id"), {"id": row.id}
    )
    await db_session.commit()
    db_session.expire_all()

    result = await logger.verify_chain()
    assert result == {"ok": False, "first_bad_row": row.id, "checked": 0, "total": 1, "reason": "row_unhashed"}


async def test_chains_are_independent_per_org_and_scoped(db_session: AsyncSession) -> None:
    org_a = await _org(db_session, "Org A")
    org_b = await _org(db_session, "Org B")
    org_a_id, org_b_id = org_a.id, org_b.id
    logger_a = AuditLogger(db_session, org_a_id)
    logger_b = AuditLogger(db_session, org_b_id)

    await _log(logger_a, 0)
    await _log(logger_b, 0)
    await _log(logger_a, 1)
    await _log(logger_b, 1)
    await db_session.commit()

    rows_a = await _rows(db_session, org_a_id)
    rows_b = await _rows(db_session, org_b_id)
    assert rows_a[0].prev_hash == AUDIT_GENESIS_HASH and rows_b[0].prev_hash == AUDIT_GENESIS_HASH
    assert rows_a[1].prev_hash == rows_a[0].row_hash
    assert rows_b[1].prev_hash == rows_b[0].row_hash
    assert {r.row_hash for r in rows_a}.isdisjoint({r.row_hash for r in rows_b})

    assert (await logger_a.verify_chain())["ok"] is True
    assert (await logger_b.verify_chain())["ok"] is True

    # Tampering with B does not touch A's verdict ...
    victim_id = rows_b[0].id
    await db_session.execute(text("UPDATE audit_trails SET result = 'denied' WHERE id = :id"), {"id": victim_id})
    await db_session.commit()
    db_session.expire_all()
    assert (await logger_a.verify_chain())["ok"] is True
    assert (await logger_b.verify_chain())["first_bad_row"] == victim_id

    # ... and a logger can never verify another tenant's chain.
    with pytest.raises(PermissionError):
        await logger_a.verify_chain(org_b_id)


async def test_empty_org_chain_verifies(db_session: AsyncSession) -> None:
    org = await _org(db_session, "Empty Org")
    await db_session.commit()
    result = await AuditLogger(db_session, org.id).verify_chain()
    assert result == {"ok": True, "first_bad_row": None, "checked": 0, "total": 0, "reason": None}


async def test_stale_head_writer_fails_closed(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two writers that read the same head cannot both append: the unique
    ``(organization_id, prev_hash)`` index rejects the second, which surfaces
    as ``AuditWriteError`` so the caller aborts the audited action."""
    org = await _org(db_session, "Race Org")
    org_id = org.id
    logger = AuditLogger(db_session, org_id)
    first = await _log(logger, 0)
    first_id, stale_head = first.id, first.prev_hash
    await db_session.commit()

    async def stale_chain_head() -> str:
        return stale_head

    monkeypatch.setattr(logger, "_chain_head", stale_chain_head)
    with pytest.raises(AuditWriteError):
        await _log(logger, 1)
    await db_session.rollback()

    rows = await _rows(db_session, org_id)
    assert [r.id for r in rows] == [first_id]


# ---------------------------------------------------------------------------
# Value cap
# ---------------------------------------------------------------------------


def test_cap_audit_value_small_values_verbatim() -> None:
    assert cap_audit_value(None) is None
    assert cap_audit_value({"b": 1, "a": [1, 2]}) == {"a": [1, 2], "b": 1}


def test_cap_audit_value_truncates_with_hash() -> None:
    big = {"args": "x" * (AUDIT_VALUE_CAP_BYTES * 3), "n": 1}
    canonical = json.dumps(big, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    capped = cap_audit_value(big)
    assert capped is not None
    assert capped["[truncated]"] is True
    assert capped["args_sha256"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert capped["original_bytes"] == len(canonical.encode("utf-8"))
    assert len(capped["preview"].encode("utf-8")) <= AUDIT_VALUE_CAP_BYTES
    assert "args" not in capped


async def test_log_event_caps_new_value_and_hashes_it(db_session: AsyncSession) -> None:
    org = await _org(db_session, "Cap Org")
    logger = AuditLogger(db_session, org.id)
    big = {"payload": "y" * 5000}
    row = await _log(logger, 0, new_value=big, old_value={"small": True})
    row_id = row.id
    await db_session.commit()
    db_session.expire_all()

    stored = await db_session.get(AuditTrail, row_id)
    assert stored is not None
    assert stored.old_value == {"small": True}
    assert stored.new_value["[truncated]"] is True
    assert len(json.dumps(stored.new_value).encode("utf-8")) < AUDIT_VALUE_CAP_BYTES + 512
    canonical = json.dumps(big, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert stored.new_value["args_sha256"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    # The hash covers what was stored, so the chain still verifies.
    assert (await logger.verify_chain())["ok"] is True
