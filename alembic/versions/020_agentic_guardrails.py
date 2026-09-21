"""Agentic SOC guardrails: run provenance, audit hash chain, LLM call logs, secrets envelope.

Revision ID: 020
Revises: 019
Create Date: 2026-09-20

Design v2 (docs/agentic-soc-rebuild-design.md) sections 7, 8, 10 and 11 in a
single revision:

* new tables ``llm_call_logs``, ``llm_usage_daily`` (design section 6/7; the
  ORM models live in WP1's ``src/llm/models.py``) and
  ``agent_run_transcripts`` (``src/agentic/transcript.py``);
* ``audit_trails.prev_hash/row_hash/run_id`` plus the composite index, with
  every existing row chained per organization (``AUDIT_GENESIS_HASH`` first);
* proposal/approval provenance on ``agent_actions``, sticky trust state on
  ``agent_chat_sessions``, honest outcomes on ``investigations``
  (``confidence_score`` becomes nullable: NULL unless ``outcome == verdict``);
* ``injection_score``/``injection_hits`` on the free-text tables the agent
  reads (populated by ingest-time scanning in phase 2);
* ``playbooks.organization_id`` backfilled from ``created_by ->
  users.organization_id`` (rows whose author has no organization stay NULL
  and are treated as legacy, never as "every org");
* ``playbook_executions.triggered_by_user_id``,
  ``agent_commands.initiated_by_user_id/run_id``;
* ``app_settings.value_pre020`` and the guarded secrets envelope step
  (design section 10).

Secrets step (runs FIRST, before any DDL, and hard-fails):
  1. ``settings.encryption_master_key`` must be set -> ``RuntimeError``;
  2. the ``_crypto_canary`` ``app_settings`` row must decrypt under that key
     (written here when absent, e.g. first migration under a new install);
  3. every other ``app_settings.value`` is copied verbatim to
     ``value_pre020`` (only when still NULL) and then every ``SECRET_KEYS``
     member that is not already an ``enc:v1:`` envelope is encrypted; the
     enveloped value must round-trip to the original before it is written.
  Re-running is a no-op: enveloped values are skipped and ``value_pre020``
  is never overwritten.

Dialects: Postgres is the production target; tests run the same file on
SQLite, so column changes go through ``batch_alter_table`` and Postgres-only
types (JSONB) are guarded by a dialect check. Note that pysqlite runs DDL
outside the transaction, so on SQLite this revision is not atomic; on
Postgres it is.
"""

from __future__ import annotations

import hashlib
import json
import secrets as _secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.engine import Connection

revision: str = "020"
down_revision: Union[str, None] = "019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# What this revision adds (also consumed by tests to build the pre-020 schema)
# ---------------------------------------------------------------------------

CRYPTO_CANARY_SECTION = "_crypto_canary"
AUDIT_CHAIN_BATCH = 1000

NEW_TABLES: tuple[str, ...] = ("llm_call_logs", "llm_usage_daily", "agent_run_transcripts")

NEW_COLUMNS: dict[str, tuple[str, ...]] = {
    "audit_trails": ("run_id", "prev_hash", "row_hash"),
    "agent_actions": (
        "run_id",
        "tool_name",
        "proposed_by_user_id",
        "proposed_by_agent_id",
        "source",
        "params_sha256",
        "evidence_sha256",
        "effective_targets",
        "suspect",
        "injection_tier",
        "expires_at",
        "approver_role",
        "approver_ip",
        "approval_reason",
    ),
    "agent_chat_sessions": ("trust_state",),
    "investigations": (
        "outcome",
        "failure_reason",
        "llm_provider",
        "llm_model",
        "tokens_used",
        "injection_tier",
        "run_ids",
    ),
    "alerts": ("injection_score", "injection_hits"),
    "log_entries": ("injection_score", "injection_hits"),
    "threat_indicators": ("injection_score", "injection_hits"),
    "ticket_comments": ("injection_score", "injection_hits"),
    "case_notes": ("injection_score", "injection_hits"),
    "playbooks": ("organization_id",),
    "playbook_executions": ("triggered_by_user_id",),
    "agent_commands": ("initiated_by_user_id", "run_id"),
    "app_settings": ("value_pre020",),
}

NEW_INDEXES: dict[str, tuple[str, ...]] = {
    "audit_trails": (
        "ix_audit_trails_run_id",
        "ix_audit_trails_org_event_action_created",
        "uq_audit_trails_org_prev_hash",
    ),
    "agent_actions": ("ix_agent_actions_run_id",),
    "investigations": ("ix_investigations_outcome",),
    "playbooks": ("ix_playbooks_organization_id",),
    "agent_commands": ("ix_agent_commands_run_id",),
}

# Columns whose nullability this revision relaxes (table, column).
RELAXED_NOT_NULL: tuple[tuple[str, str], ...] = (("investigations", "confidence_score"),)

# Batch mode (SQLite table recreate) refuses unnamed constraints; reflected
# legacy tables carry unnamed foreign keys, so give them deterministic names.
_NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
}


def _fk(table: str, column: str, target: str) -> sa.ForeignKey:
    """A named FK so the constraint is addressable on every dialect."""
    referred = target.split(".", 1)[0]
    return sa.ForeignKey(target, name=f"fk_{table}_{column}_{referred}")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _is_postgres(bind: Connection) -> bool:
    return bind.dialect.name == "postgresql"


def _json_type(bind: Connection) -> sa.types.TypeEngine:
    if _is_postgres(bind):
        from sqlalchemy.dialects.postgresql import JSONB

        return JSONB()
    return sa.JSON()


def _has_table(bind: Connection, name: str) -> bool:
    return sa.inspect(bind).has_table(name)


def _columns(bind: Connection, table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(bind).get_columns(table)}


def _indexes(bind: Connection, table: str) -> set[str]:
    return {i["name"] for i in sa.inspect(bind).get_indexes(table) if i.get("name")}


def _base_cols() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def _add_columns(bind: Connection, table: str, columns: list[sa.Column]) -> None:
    """Add the columns that do not exist yet (batch mode for SQLite)."""
    if not _has_table(bind, table):
        # Fresh installs create the table from the ORM (with these columns)
        # on first boot; nothing to alter here.
        return
    existing = _columns(bind, table)
    missing = [c for c in columns if c.name not in existing]
    if not missing:
        return
    with op.batch_alter_table(table, naming_convention=_NAMING_CONVENTION) as batch:
        for column in missing:
            batch.add_column(column)


def _create_index(bind: Connection, name: str, table: str, columns: list[str], unique: bool = False) -> None:
    if not _has_table(bind, table) or name in _indexes(bind, table):
        return
    op.create_index(name, table, columns, unique=unique)


def _drop_index(bind: Connection, name: str, table: str) -> None:
    if _has_table(bind, table) and name in _indexes(bind, table):
        op.drop_index(name, table_name=table)


def _drop_columns(bind: Connection, table: str, names: tuple[str, ...]) -> None:
    if not _has_table(bind, table):
        return
    existing = _columns(bind, table)
    present = [n for n in names if n in existing]
    if not present:
        return
    with op.batch_alter_table(table, naming_convention=_NAMING_CONVENTION) as batch:
        for name in present:
            batch.drop_column(name)


# ---------------------------------------------------------------------------
# Secrets envelope (design section 10)
# ---------------------------------------------------------------------------


def _app_settings_table(json_type: sa.types.TypeEngine, with_pre020: bool) -> sa.TableClause:
    cols = [
        sa.column("id", sa.String(36)),
        sa.column("organization_id", sa.String(36)),
        sa.column("section", sa.String(100)),
        sa.column("value", json_type),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    ]
    if with_pre020:
        cols.append(sa.column("value_pre020", json_type))
    return sa.table("app_settings", *cols)


def _require_master_key() -> Any:
    """Return an ``EncryptionService`` for ``settings.encryption_master_key`` or raise."""
    from src.core.config import settings
    from src.core.secrets import EncryptionService

    if not settings.encryption_master_key:
        raise RuntimeError(
            "migration 020 refuses to run: ENCRYPTION_MASTER_KEY is unset. "
            "Secret keys in app_settings would be encrypted under a throwaway key "
            "and become unreadable. Set the key and re-run `alembic upgrade head`."
        )
    return EncryptionService(master_key=settings.encryption_master_key)


def canary_payload(plaintext: str) -> dict[str, str]:
    """The ``app_settings.value`` shape of the ``_crypto_canary`` row (minus the envelope)."""
    return {"plaintext_sha256": hashlib.sha256(plaintext.encode("utf-8")).hexdigest()}


def verify_or_write_canary(bind: Connection, service: Any, json_type: sa.types.TypeEngine) -> str:
    """Prove the current master key can read what was encrypted before.

    Returns ``"verified"`` when an existing canary decrypted under the key and
    matched its stored digest, ``"written"`` when no canary existed yet and one
    was created (the first migration on this install). Raises ``RuntimeError``
    when the stored canary cannot be opened: the key changed and encrypting
    more rows under it would make the platform's secrets inconsistent.
    """
    from src.core.secrets import SecretUnreadable, decrypt_secret_json, encrypt_secret_json

    if not _has_table(bind, "app_settings"):
        raise RuntimeError("migration 020 requires the app_settings table (revision 017)")

    table = _app_settings_table(json_type, with_pre020=False)
    row = bind.execute(
        sa.select(table.c.id, table.c.value).where(
            table.c.section == CRYPTO_CANARY_SECTION, table.c.organization_id.is_(None)
        )
    ).first()

    if row is not None:
        value = row.value if isinstance(row.value, dict) else json.loads(row.value or "{}")
        envelope = value.get("envelope")
        expected = value.get("plaintext_sha256")
        if not envelope or not expected:
            raise RuntimeError("stored _crypto_canary row is malformed; refusing to encrypt secrets")
        try:
            opened = decrypt_secret_json(envelope, service=service, required=True)
        except SecretUnreadable as exc:
            raise RuntimeError(
                "ENCRYPTION_MASTER_KEY does not decrypt the stored _crypto_canary "
                f"({exc.reason}); refusing to encrypt app_settings secrets under a different key"
            ) from exc
        plaintext = opened.get("canary") if isinstance(opened, dict) else None
        if not isinstance(plaintext, str) or canary_payload(plaintext)["plaintext_sha256"] != expected:
            raise RuntimeError("_crypto_canary decrypted but does not match its stored digest")
        return "verified"

    plaintext = _secrets.token_hex(32)
    envelope = encrypt_secret_json({"canary": plaintext}, service=service)
    # Prove the envelope opens before persisting it.
    if decrypt_secret_json(envelope, service=service, required=True) != {"canary": plaintext}:
        raise RuntimeError("freshly written _crypto_canary failed to round-trip")
    now = datetime.now(timezone.utc)
    bind.execute(
        sa.insert(table).values(
            id=str(uuid.uuid4()),
            organization_id=None,
            section=CRYPTO_CANARY_SECTION,
            value={
                "envelope": envelope,
                **canary_payload(plaintext),
                "written_at": now.isoformat(),
                "written_by": "migration_020",
            },
            created_at=now,
            updated_at=now,
        )
    )
    return "written"


def _round_trips(old: Any, new: Any, service: Any) -> bool:
    """True when ``new`` equals ``old`` except for envelopes that decrypt to ``old``'s value.

    Values that were already enveloped before this step are compared
    verbatim (they are never rewritten), so a legacy envelope is neither
    opened nor trusted here; the canary check is the key-consistency guard.
    """
    from src.core.secrets import SecretUnreadable, decrypt_secret_json, is_enveloped

    if isinstance(old, dict) and isinstance(new, dict):
        return old.keys() == new.keys() and all(_round_trips(old[k], new[k], service) for k in old)
    if isinstance(old, list) and isinstance(new, list):
        return len(old) == len(new) and all(_round_trips(a, b, service) for a, b in zip(old, new, strict=True))
    if old == new:
        return True
    if not is_enveloped(new) or is_enveloped(old):
        return False
    try:
        return decrypt_secret_json(new, service=service, required=True) == old
    except SecretUnreadable:
        return False


def envelope_app_settings_secrets(bind: Connection, service: Any, json_type: sa.types.TypeEngine) -> dict[str, int]:
    """Copy ``value`` -> ``value_pre020`` and envelope ``SECRET_KEYS`` in every row.

    Returns counters ``{"rows": n, "backed_up": n, "enveloped": n, "secrets": n}``.
    Idempotent: enveloped values are untouched and ``value_pre020`` is only
    written when still NULL.
    """
    from src.core.secrets import envelope_secret_keys

    table = _app_settings_table(json_type, with_pre020=True)
    rows = bind.execute(
        sa.select(table.c.id, table.c.section, table.c.value, table.c.value_pre020).where(
            table.c.section != CRYPTO_CANARY_SECTION
        )
    ).all()

    stats = {"rows": len(rows), "backed_up": 0, "enveloped": 0, "secrets": 0}
    for row in rows:
        value = row.value if not isinstance(row.value, str) else json.loads(row.value)
        updates: dict[str, Any] = {}
        if row.value_pre020 is None:
            updates["value_pre020"] = value
            stats["backed_up"] += 1

        new_value, changed = envelope_secret_keys(value, service=service)
        if changed:
            if not _round_trips(value, new_value, service):
                raise RuntimeError(
                    f"app_settings row {row.id} ({row.section}) did not round-trip after enveloping; aborting"
                )
            updates["value"] = new_value
            stats["enveloped"] += 1
            stats["secrets"] += changed

        if updates:
            bind.execute(sa.update(table).where(table.c.id == row.id).values(**updates))
    return stats


# ---------------------------------------------------------------------------
# Audit hash chain backfill (design section 7)
# ---------------------------------------------------------------------------


def _audit_table() -> sa.TableClause:
    return sa.table(
        "audit_trails",
        sa.column("id", sa.String(36)),
        sa.column("organization_id", sa.String(36)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("event_type", sa.String(100)),
        sa.column("action", sa.String(100)),
        sa.column("actor_type", sa.String(50)),
        sa.column("actor_id", sa.String(255)),
        sa.column("actor_ip", sa.String(45)),
        sa.column("resource_type", sa.String(100)),
        sa.column("resource_id", sa.String(255)),
        sa.column("description", sa.Text()),
        sa.column("old_value", sa.JSON()),
        sa.column("new_value", sa.JSON()),
        sa.column("result", sa.String(20)),
        sa.column("risk_level", sa.String(20)),
        sa.column("session_id", sa.String(255)),
        sa.column("request_id", sa.String(255)),
        sa.column("run_id", sa.String(64)),
        sa.column("prev_hash", sa.String(64)),
        sa.column("row_hash", sa.String(64)),
    )


def backfill_audit_chain(bind: Connection) -> dict[str, int]:
    """Chain every organization's audit rows in ``(created_at, id)`` order.

    Uses the same pure ``audit_row_hash`` the runtime logger uses so
    ``AuditLogger.verify_chain`` accepts the result. Organizations whose rows
    are all hashed already are skipped; an organization with any unhashed
    row has its whole chain (re)computed so the result is linear.
    """
    from src.audit_evidence.models import AUDIT_CHAIN_FIELDS, AUDIT_GENESIS_HASH, audit_row_hash

    t = _audit_table()
    org_ids = [
        r[0]
        for r in bind.execute(
            sa.select(t.c.organization_id).where(t.c.row_hash.is_(None)).distinct()
        ).all()
        if r[0] is not None
    ]
    stats = {"organizations": len(org_ids), "rows": 0}
    for org_id in org_ids:
        rows = bind.execute(
            sa.select(*[getattr(t.c, name) for name in AUDIT_CHAIN_FIELDS])
            .where(t.c.organization_id == org_id)
            .order_by(t.c.created_at.asc(), t.c.id.asc())
        ).all()
        prev = AUDIT_GENESIS_HASH
        pending: list[dict[str, Any]] = []
        for row in rows:
            fields = dict(zip(AUDIT_CHAIN_FIELDS, row, strict=True))
            for name in ("old_value", "new_value"):
                if isinstance(fields[name], str):
                    fields[name] = json.loads(fields[name])
            row_hash = audit_row_hash(fields, prev)
            pending.append({"row_id": fields["id"], "prev": prev, "row": row_hash})
            prev = row_hash
            if len(pending) >= AUDIT_CHAIN_BATCH:
                _flush_chain(bind, t, pending)
                stats["rows"] += len(pending)
                pending = []
        if pending:
            _flush_chain(bind, t, pending)
            stats["rows"] += len(pending)
    return stats


def _flush_chain(bind: Connection, t: sa.TableClause, pending: list[dict[str, Any]]) -> None:
    stmt = (
        sa.update(t)
        .where(t.c.id == sa.bindparam("row_id"))
        .values(prev_hash=sa.bindparam("prev"), row_hash=sa.bindparam("row"))
    )
    bind.execute(stmt, pending)


# ---------------------------------------------------------------------------
# upgrade / downgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    bind = op.get_bind()
    json_type = _json_type(bind)

    # 1. Secrets guard (before any DDL): key present and canary readable.
    service = _require_master_key()
    verify_or_write_canary(bind, service, json_type)

    # 2. New tables ------------------------------------------------------
    if not _has_table(bind, "llm_call_logs"):
        op.create_table(
            "llm_call_logs",
            *_base_cols(),
            sa.Column("run_id", sa.String(64), nullable=False),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("actor_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("soc_agent_id", sa.String(36), sa.ForeignKey("soc_agents.id"), nullable=True),
            sa.Column("purpose", sa.String(40), nullable=False),
            sa.Column("mode", sa.String(20), nullable=False),
            sa.Column("role", sa.String(20), nullable=True),
            sa.Column("propose_actions", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("session_id", sa.String(36), nullable=True),
            sa.Column("investigation_id", sa.String(36), nullable=True),
            sa.Column("provider", sa.String(40), nullable=False),
            sa.Column("model", sa.String(120), nullable=False),
            sa.Column("credential_source", sa.String(20), nullable=False),
            sa.Column("prompt_version", sa.String(40), nullable=True),
            sa.Column("system_prompt_sha256", sa.String(64), nullable=True),
            sa.Column("tools_offered", sa.JSON(), nullable=True),
            sa.Column("messages_sha256", sa.String(64), nullable=True),
            sa.Column("input_uncached_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cache_read_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cache_write_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("thinking_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("total_billable_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("usage_estimated", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("latency_ms", sa.Integer(), nullable=True),
            sa.Column("stop_reason", sa.String(40), nullable=True),
            sa.Column("injection_tier", sa.String(20), nullable=True),
            sa.Column("request_id", sa.String(255), nullable=True),
            sa.Column("data_sent_bytes", sa.Integer(), nullable=True),
            sa.Column("redactions_applied", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_class", sa.String(120), nullable=True),
            sa.Column("request_body", sa.Text(), nullable=True),
            sa.Column("response_body", sa.Text(), nullable=True),
            sa.Column("cost_usd", sa.Float(), nullable=True),
        )
        op.create_index("ix_llm_call_logs_run_id", "llm_call_logs", ["run_id"])
        op.create_index("ix_llm_call_logs_org_created", "llm_call_logs", ["organization_id", "created_at"])
        op.create_index("ix_llm_call_logs_investigation_id", "llm_call_logs", ["investigation_id"])

    if not _has_table(bind, "llm_usage_daily"):
        op.create_table(
            "llm_usage_daily",
            *_base_cols(),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("day", sa.Date(), nullable=False),
            sa.Column("provider", sa.String(40), nullable=False),
            sa.Column("model", sa.String(120), nullable=False),
            sa.Column("purpose", sa.String(40), nullable=False),
            sa.Column("mode", sa.String(20), nullable=False),
            sa.Column("credential_source", sa.String(20), nullable=False),
            # "user:<id>" | "agent:<id>" | "-" so the bucket key is NOT NULL
            sa.Column("actor_key", sa.String(64), nullable=False, server_default="-"),
            sa.Column("calls", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("errors", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("input_uncached_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cache_read_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cache_write_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("thinking_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("total_billable_tokens", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cost_usd", sa.Float(), nullable=True),
            sa.UniqueConstraint(
                "organization_id",
                "day",
                "provider",
                "model",
                "purpose",
                "mode",
                "credential_source",
                "actor_key",
                name="uq_llm_usage_daily_bucket",
            ),
        )
        op.create_index("ix_llm_usage_daily_org_day", "llm_usage_daily", ["organization_id", "day"])

    if not _has_table(bind, "agent_run_transcripts"):
        op.create_table(
            "agent_run_transcripts",
            *_base_cols(),
            sa.Column("run_id", sa.String(64), nullable=False),
            sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
            sa.Column("mode", sa.String(20), nullable=False),
            sa.Column("actor_user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("soc_agent_id", sa.String(36), sa.ForeignKey("soc_agents.id"), nullable=True),
            sa.Column("session_id", sa.String(36), nullable=True),
            sa.Column("investigation_id", sa.String(36), nullable=True),
            sa.Column("steps", sa.Text(), nullable=True),  # EncryptedJSON at the ORM layer
            sa.Column("step_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("outcome", sa.String(40), nullable=True),
            sa.Column("injection_tier", sa.String(20), nullable=True),
            sa.Column("provider", sa.String(40), nullable=True),
            sa.Column("model", sa.String(120), nullable=True),
            sa.Column("tokens_used", sa.Integer(), nullable=True),
            sa.Column("error_class", sa.String(120), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("retention_until", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_agent_run_transcripts_run_id", "agent_run_transcripts", ["run_id"], unique=True)
        op.create_index("ix_agent_run_transcripts_organization_id", "agent_run_transcripts", ["organization_id"])
        op.create_index("ix_agent_run_transcripts_investigation_id", "agent_run_transcripts", ["investigation_id"])
        op.create_index("ix_agent_run_transcripts_retention_until", "agent_run_transcripts", ["retention_until"])
        op.create_index("ix_agent_run_transcripts_org_started", "agent_run_transcripts", ["organization_id", "started_at"])

    # 3. audit_trails: run id + hash chain --------------------------------
    _add_columns(
        bind,
        "audit_trails",
        [
            sa.Column("run_id", sa.String(64), nullable=True),
            sa.Column("prev_hash", sa.String(64), nullable=True),
            sa.Column("row_hash", sa.String(64), nullable=True),
        ],
    )
    if _has_table(bind, "audit_trails"):
        backfill_audit_chain(bind)
    _create_index(bind, "ix_audit_trails_run_id", "audit_trails", ["run_id"])
    _create_index(
        bind,
        "ix_audit_trails_org_event_action_created",
        "audit_trails",
        ["organization_id", "event_type", "action", "created_at"],
    )
    _create_index(bind, "uq_audit_trails_org_prev_hash", "audit_trails", ["organization_id", "prev_hash"], unique=True)

    # 4. agent_actions: proposal + approval provenance ---------------------
    _add_columns(
        bind,
        "agent_actions",
        [
            sa.Column("run_id", sa.String(64), nullable=True),
            sa.Column("tool_name", sa.String(100), nullable=True),
            sa.Column("proposed_by_user_id", sa.String(36), _fk("agent_actions", "proposed_by_user_id", "users.id"), nullable=True),
            sa.Column("proposed_by_agent_id", sa.String(36), _fk("agent_actions", "proposed_by_agent_id", "soc_agents.id"), nullable=True),
            sa.Column("source", sa.String(20), nullable=True),
            sa.Column("params_sha256", sa.String(64), nullable=True),
            sa.Column("evidence_sha256", sa.String(64), nullable=True),
            sa.Column("effective_targets", sa.JSON(), nullable=True),
            sa.Column("suspect", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("injection_tier", sa.String(20), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("approver_role", sa.String(20), nullable=True),
            sa.Column("approver_ip", sa.String(45), nullable=True),
            sa.Column("approval_reason", sa.Text(), nullable=True),
        ],
    )
    _create_index(bind, "ix_agent_actions_run_id", "agent_actions", ["run_id"])

    # 5. agent_chat_sessions.trust_state -----------------------------------
    _add_columns(bind, "agent_chat_sessions", [sa.Column("trust_state", sa.JSON(), nullable=True)])

    # 6. investigations: honest outcomes -----------------------------------
    _add_columns(
        bind,
        "investigations",
        [
            sa.Column("outcome", sa.String(40), nullable=True),
            sa.Column("failure_reason", sa.Text(), nullable=True),
            sa.Column("llm_provider", sa.String(40), nullable=True),
            sa.Column("llm_model", sa.String(120), nullable=True),
            sa.Column("tokens_used", sa.Integer(), nullable=True),
            sa.Column("injection_tier", sa.String(20), nullable=True),
            sa.Column("run_ids", sa.JSON(), nullable=True),
        ],
    )
    _create_index(bind, "ix_investigations_outcome", "investigations", ["outcome"])
    if _has_table(bind, "investigations") and "confidence_score" in _columns(bind, "investigations"):
        with op.batch_alter_table("investigations", naming_convention=_NAMING_CONVENTION) as batch:
            batch.alter_column("confidence_score", existing_type=sa.Float(), nullable=True)

    # 7. injection columns on free-text tables -----------------------------
    for table in ("alerts", "log_entries", "threat_indicators", "ticket_comments", "case_notes"):
        _add_columns(
            bind,
            table,
            [
                sa.Column("injection_score", sa.Float(), nullable=True),
                sa.Column("injection_hits", sa.JSON(), nullable=True),
            ],
        )

    # 8. playbooks.organization_id (+ backfill from created_by) ------------
    _add_columns(
        bind,
        "playbooks",
        [sa.Column("organization_id", sa.String(36), _fk("playbooks", "organization_id", "organizations.id"), nullable=True)],
    )
    _create_index(bind, "ix_playbooks_organization_id", "playbooks", ["organization_id"])
    if _has_table(bind, "playbooks") and _has_table(bind, "users"):
        bind.execute(
            sa.text(
                "UPDATE playbooks SET organization_id = ("
                "  SELECT u.organization_id FROM users u WHERE u.id = playbooks.created_by"
                ") WHERE organization_id IS NULL AND created_by IS NOT NULL"
            )
        )

    # 9. playbook_executions.triggered_by_user_id ---------------------------
    _add_columns(
        bind,
        "playbook_executions",
        [sa.Column("triggered_by_user_id", sa.String(36), _fk("playbook_executions", "triggered_by_user_id", "users.id"), nullable=True)],
    )

    # 10. agent_commands provenance -----------------------------------------
    _add_columns(
        bind,
        "agent_commands",
        [
            sa.Column("initiated_by_user_id", sa.String(36), _fk("agent_commands", "initiated_by_user_id", "users.id"), nullable=True),
            sa.Column("run_id", sa.String(64), nullable=True),
        ],
    )
    _create_index(bind, "ix_agent_commands_run_id", "agent_commands", ["run_id"])

    # 11. app_settings.value_pre020 + secrets envelope ----------------------
    _add_columns(bind, "app_settings", [sa.Column("value_pre020", json_type, nullable=True)])
    envelope_app_settings_secrets(bind, service, json_type)


def downgrade() -> None:
    """Restore the pre-020 schema.

    Secrets are restored from ``value_pre020`` (the verbatim pre-migration
    value) before that column is dropped, so a downgrade never leaves
    ``enc:v1:`` envelopes behind for code that cannot open them. The
    ``_crypto_canary`` row is kept: it is harmless and lets a later re-upgrade
    prove the key is unchanged. ``investigations.confidence_score`` NULLs are
    set to 0.0 to satisfy the pre-020 NOT NULL constraint (that was the old
    schema's default; the honest NULL semantics do not exist before 020).
    """
    bind = op.get_bind()
    json_type = _json_type(bind)

    # 11. app_settings: put the pre-020 values back, then drop the backup.
    if _has_table(bind, "app_settings") and "value_pre020" in _columns(bind, "app_settings"):
        table = _app_settings_table(json_type, with_pre020=True)
        rows = bind.execute(
            sa.select(table.c.id, table.c.value_pre020).where(table.c.value_pre020.is_not(None))
        ).all()
        for row in rows:
            bind.execute(sa.update(table).where(table.c.id == row.id).values(value=row.value_pre020))
    _drop_columns(bind, "app_settings", NEW_COLUMNS["app_settings"])

    # 10 / 9 / 8
    _drop_index(bind, "ix_agent_commands_run_id", "agent_commands")
    _drop_columns(bind, "agent_commands", NEW_COLUMNS["agent_commands"])
    _drop_columns(bind, "playbook_executions", NEW_COLUMNS["playbook_executions"])
    _drop_index(bind, "ix_playbooks_organization_id", "playbooks")
    _drop_columns(bind, "playbooks", NEW_COLUMNS["playbooks"])

    # 7
    for table in ("alerts", "log_entries", "threat_indicators", "ticket_comments", "case_notes"):
        _drop_columns(bind, table, NEW_COLUMNS[table])

    # 6
    if _has_table(bind, "investigations") and "confidence_score" in _columns(bind, "investigations"):
        bind.execute(sa.text("UPDATE investigations SET confidence_score = 0.0 WHERE confidence_score IS NULL"))
        with op.batch_alter_table("investigations", naming_convention=_NAMING_CONVENTION) as batch:
            batch.alter_column("confidence_score", existing_type=sa.Float(), nullable=False)
    _drop_index(bind, "ix_investigations_outcome", "investigations")
    _drop_columns(bind, "investigations", NEW_COLUMNS["investigations"])

    # 5 / 4
    _drop_columns(bind, "agent_chat_sessions", NEW_COLUMNS["agent_chat_sessions"])
    _drop_index(bind, "ix_agent_actions_run_id", "agent_actions")
    _drop_columns(bind, "agent_actions", NEW_COLUMNS["agent_actions"])

    # 3
    for name in NEW_INDEXES["audit_trails"]:
        _drop_index(bind, name, "audit_trails")
    _drop_columns(bind, "audit_trails", NEW_COLUMNS["audit_trails"])

    # 2
    for table in reversed(NEW_TABLES):
        if _has_table(bind, table):
            op.drop_table(table)
