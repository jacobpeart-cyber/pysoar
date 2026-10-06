#!/usr/bin/env python
"""Rotate ENCRYPTION_MASTER_KEY: re-encrypt every stored secret under a new key.

What it rotates (one database transaction for all writes):

* ``app_settings.value`` -- every ``enc:v1:`` envelope anywhere in the JSON
  (settings secret keys, ``integration:*`` / AI sections) including the
  ``_crypto_canary`` row (``organization_id IS NULL``), whose digest is
  re-checked under the new key before commit.
* ``installed_integrations.auth_credentials_encrypted`` -- ``enc:v1:``
  envelopes and legacy raw ``encrypt_field`` output. ``__plaintext__:`` rows
  (and legacy plain-JSON rows) are left untouched, counted and reported.
* ``users.mfa_secret`` / ``users.mfa_backup_codes`` -- raw ``encrypt_field``
  output (``EncryptedType`` / ``EncryptedJSON``).
* ``agent_run_transcripts.steps`` -- raw ``encrypt_field`` output (``EncryptedJSON``).

Re-encryption is decrypt-with-old then encrypt-with-new (every encryption
uses a fresh salt and nonce). A value that already opens under the new key
and not the old one is counted as "already rotated" and skipped, so the
script is safe to re-run. Before writing anything it refuses to start unless
the ``_crypto_canary`` opens (and matches its digest) under the old key -- or,
on a re-run, under the new key. After writing, every rotated value is re-read
and must open under the new key; otherwise the whole transaction is rolled
back and the exit code is non-zero. Each value costs a few PBKDF2 derivations
(600k iterations, ~0.2 s each), so large transcript tables take a while.

Keys are only ever read from environment variables (never CLI arguments,
which land in shell history and ``ps`` output) and are never logged.

Operator procedure (production, /opt/pysoar)::

    cd /opt/pysoar
    # 1. Generate the new key (copy it straight into the password manager).
    docker compose run --rm --no-deps -v "$PWD/scripts:/app/scripts:ro" \\
        api python scripts/rotate_master_key.py --generate
    # 2. Put the new key in this shell only (not in history), stop writers.
    read -rs ENCRYPTION_MASTER_KEY_NEW && export ENCRYPTION_MASTER_KEY_NEW
    docker compose stop api worker scheduler
    # 3. Dry run: counts only, nothing written. The old key comes from .env.
    docker compose run --rm -e ENCRYPTION_MASTER_KEY_NEW \\
        -v "$PWD/scripts:/app/scripts:ro" \\
        api python scripts/rotate_master_key.py --dry-run
    # 4. Rotate for real (exit 0 only when every value was rotated + verified).
    docker compose run --rm -e ENCRYPTION_MASTER_KEY_NEW \\
        -v "$PWD/scripts:/app/scripts:ro" \\
        api python scripts/rotate_master_key.py
    # 5. Set ENCRYPTION_MASTER_KEY=<new key> in /opt/pysoar/.env, then
    docker compose up -d api worker scheduler
    # 6. Verify every encrypted value opens under the (now current) key.
    docker compose run --rm -v "$PWD/scripts:/app/scripts:ro" \\
        api python scripts/rotate_master_key.py --verify-only
    unset ENCRYPTION_MASTER_KEY_NEW
    # 7. Store the new key in the password manager; retire the old key.

Exit codes: 0 success, 1 rotation/verification failed (rolled back),
2 refused to start (missing/invalid keys, canary mismatch).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import sqlalchemy as sa  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine  # noqa: E402

from src.core.logging import get_logger  # noqa: E402
from src.core.secrets import SECRET_ENVELOPE_PREFIX, EncryptionService, is_enveloped  # noqa: E402

logger = get_logger("pysoar.scripts.rotate_master_key")

OLD_KEY_ENV = "ENCRYPTION_MASTER_KEY"
NEW_KEY_ENV = "ENCRYPTION_MASTER_KEY_NEW"
CRYPTO_CANARY_SECTION = "_crypto_canary"
LEGACY_PLAINTEXT_MARKER = "__plaintext__:"
VERIFY_BATCH = 500

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

_JSON = sa.JSON().with_variant(JSONB(), "postgresql")

APP_SETTINGS = sa.table(
    "app_settings",
    sa.column("id", sa.String(36)),
    sa.column("organization_id", sa.String(36)),
    sa.column("section", sa.String(100)),
    sa.column("value", _JSON),
)
INSTALLED_INTEGRATIONS = sa.table(
    "installed_integrations",
    sa.column("id", sa.String(36)),
    sa.column("auth_credentials_encrypted", sa.Text()),
)
USERS = sa.table(
    "users",
    sa.column("id", sa.String(36)),
    sa.column("mfa_secret", sa.Text()),
    sa.column("mfa_backup_codes", sa.Text()),
)
AGENT_RUN_TRANSCRIPTS = sa.table(
    "agent_run_transcripts",
    sa.column("id", sa.String(36)),
    sa.column("steps", sa.Text()),
)

# (table, column, value format). "envelope_or_raw" = installed_integrations shapes.
RAW_TARGETS: tuple[tuple[sa.TableClause, str, str], ...] = (
    (INSTALLED_INTEGRATIONS, "auth_credentials_encrypted", "envelope_or_raw"),
    (USERS, "mfa_secret", "raw"),
    (USERS, "mfa_backup_codes", "raw"),
    (AGENT_RUN_TRANSCRIPTS, "steps", "raw"),
)


class Mode(str, Enum):
    ROTATE = "rotate"
    DRY_RUN = "dry_run"
    VERIFY = "verify_only"


class Outcome(str, Enum):
    ROTATE = "rotated"  # opens under the old key -> re-encrypted under the new
    ALREADY = "already_rotated"  # opens under the new key only
    PLAINTEXT = "skipped_plaintext"  # __plaintext__: marker / legacy plain JSON
    VERIFIED = "verified"  # verify-only: opens under the current key
    FAILED = "failed"


class RotationRefusedError(Exception):
    """Preconditions not met; nothing was written."""


@dataclass
class ColumnStats:
    target: str
    rotated: int = 0
    already_rotated: int = 0
    skipped_plaintext: int = 0
    verified: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)  # "row_id: reason" -- never values

    def record(self, outcome: Outcome, row_id: str, reason: str = "") -> None:
        if outcome is Outcome.ROTATE:
            self.rotated += 1
        elif outcome is Outcome.ALREADY:
            self.already_rotated += 1
        elif outcome is Outcome.PLAINTEXT:
            self.skipped_plaintext += 1
        elif outcome is Outcome.VERIFIED:
            self.verified += 1
        else:
            self.failed += 1
            self.failures.append(f"{row_id}: {reason or 'does not decrypt'}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "rotated": self.rotated,
            "already_rotated": self.already_rotated,
            "skipped_plaintext": self.skipped_plaintext,
            "verified": self.verified,
            "failed": self.failed,
        }


@dataclass
class RunResult:
    mode: Mode
    exit_code: int
    stats: dict[str, ColumnStats] = field(default_factory=dict)
    canary: str = ""  # "old" | "new" | "current" | ""
    error: str = ""
    committed: bool = False

    @property
    def total_failed(self) -> int:
        return sum(s.failed for s in self.stats.values())


class _VerificationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def _load_service(environ: Mapping[str, str], env_name: str, label: str) -> EncryptionService:
    raw = (environ.get(env_name) or "").strip()
    if not raw:
        raise RotationRefusedError(f"{label} key: environment variable {env_name} is not set")
    try:
        decoded = base64.b64decode(raw.encode(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RotationRefusedError(f"{label} key in {env_name} is not valid base64") from exc
    if len(decoded) != 32:
        raise RotationRefusedError(f"{label} key in {env_name} does not decode to 32 bytes")
    return EncryptionService(master_key=raw)


def _open(service: EncryptionService, ciphertext: str) -> Optional[str]:
    """Plaintext of a raw ``encrypt_field`` value, or ``None`` when it does not open."""
    try:
        return service.decrypt_field(ciphertext)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Per-value classification
# ---------------------------------------------------------------------------


@dataclass
class _Keys:
    mode: Mode
    old: EncryptionService  # in VERIFY mode: the current key
    new: Optional[EncryptionService]


def _classify_raw(ciphertext: str, keys: _Keys) -> tuple[Outcome, Optional[str]]:
    """Classify one raw ``encrypt_field`` value; return the replacement when it rotates."""
    plaintext = _open(keys.old, ciphertext)
    if keys.mode is Mode.VERIFY:
        return (Outcome.VERIFIED if plaintext is not None else Outcome.FAILED), None
    assert keys.new is not None
    if plaintext is not None:
        replacement = None if keys.mode is Mode.DRY_RUN else keys.new.encrypt_field(plaintext)
        return Outcome.ROTATE, replacement
    if _open(keys.new, ciphertext) is not None:
        return Outcome.ALREADY, None
    return Outcome.FAILED, None


def _classify_envelope(value: str, keys: _Keys) -> tuple[Outcome, Optional[str]]:
    outcome, replacement = _classify_raw(value[len(SECRET_ENVELOPE_PREFIX):], keys)
    if replacement is not None:
        replacement = SECRET_ENVELOPE_PREFIX + replacement
    return outcome, replacement


def _is_plain_json(value: str) -> bool:
    try:
        json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return False
    return True


def _classify_column_value(value: str, fmt: str, keys: _Keys) -> tuple[Outcome, Optional[str], str]:
    """Return ``(outcome, replacement, failure_reason)`` for one column value."""
    if fmt == "envelope_or_raw":
        if value.startswith(LEGACY_PLAINTEXT_MARKER):
            return Outcome.PLAINTEXT, None, ""
        if is_enveloped(value):
            outcome, replacement = _classify_envelope(value, keys)
            return outcome, replacement, "enc:v1 envelope does not decrypt"
    outcome, replacement = _classify_raw(value, keys)
    if outcome is Outcome.FAILED and fmt == "envelope_or_raw" and _is_plain_json(value):
        # Legacy row written before encryption was wired: plain JSON.
        return Outcome.PLAINTEXT, None, ""
    return outcome, replacement, "ciphertext does not decrypt"


def _rotate_json_tree(node: Any, keys: _Keys, stats: ColumnStats, row_id: str) -> tuple[Any, bool]:
    """Walk a JSON value; classify every ``enc:v1:`` string. Returns ``(new_tree, changed)``."""
    if isinstance(node, dict):
        changed = False
        out: dict[str, Any] = {}
        for key, child in node.items():
            out[key], child_changed = _rotate_json_tree(child, keys, stats, f"{row_id}.{key}")
            changed = changed or child_changed
        return out, changed
    if isinstance(node, list):
        changed = False
        items: list[Any] = []
        for index, child in enumerate(node):
            new_child, child_changed = _rotate_json_tree(child, keys, stats, f"{row_id}[{index}]")
            items.append(new_child)
            changed = changed or child_changed
        return items, changed
    if is_enveloped(node):
        outcome, replacement = _classify_envelope(node, keys)
        stats.record(outcome, row_id, "enc:v1 envelope does not decrypt")
        if replacement is not None:
            return replacement, True
    return node, False


def _iter_envelopes(node: Any) -> list[str]:
    if isinstance(node, dict):
        return [e for child in node.values() for e in _iter_envelopes(child)]
    if isinstance(node, list):
        return [e for child in node for e in _iter_envelopes(child)]
    return [node] if is_enveloped(node) else []


def _as_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


# ---------------------------------------------------------------------------
# Canary
# ---------------------------------------------------------------------------


def _canary_opens(value: Any, service: EncryptionService) -> bool:
    """True when the canary envelope opens under ``service`` and matches its digest."""
    if not isinstance(value, dict):
        return False
    envelope = value.get("envelope")
    expected = value.get("plaintext_sha256")
    if not is_enveloped(envelope) or not isinstance(expected, str):
        return False
    raw = _open(service, envelope[len(SECRET_ENVELOPE_PREFIX):])
    if raw is None:
        return False
    try:
        opened = json.loads(raw)
    except json.JSONDecodeError:
        return False
    plaintext = opened.get("canary") if isinstance(opened, dict) else None
    if not isinstance(plaintext, str):
        return False
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest() == expected


async def _read_canary(conn: AsyncConnection) -> Any:
    row = (
        await conn.execute(
            sa.select(APP_SETTINGS.c.value).where(
                APP_SETTINGS.c.section == CRYPTO_CANARY_SECTION,
                APP_SETTINGS.c.organization_id.is_(None),
            ),
        )
    ).first()
    if row is None:
        raise RotationRefusedError(
            "no _crypto_canary row in app_settings (migration 020 writes it); "
            "cannot prove which key the data is encrypted under",
        )
    return _as_json(row.value)


async def _check_canary(conn: AsyncConnection, keys: _Keys) -> str:
    value = await _read_canary(conn)
    if _canary_opens(value, keys.old):
        return "current" if keys.mode is Mode.VERIFY else "old"
    if keys.mode is Mode.VERIFY:
        raise RotationRefusedError("_crypto_canary does not decrypt under the current key (or digest mismatch)")
    assert keys.new is not None
    if _canary_opens(value, keys.new):
        return "new"
    raise RotationRefusedError(
        "_crypto_canary decrypts under neither the old nor the new key; "
        "refusing to touch any data (wrong old key?)",
    )


# ---------------------------------------------------------------------------
# Table passes
# ---------------------------------------------------------------------------


async def _existing_tables(conn: AsyncConnection) -> set[str]:
    return set(await conn.run_sync(lambda sync_conn: sa.inspect(sync_conn).get_table_names()))


async def _pass_app_settings(
    conn: AsyncConnection, keys: _Keys, stats: ColumnStats, touched: list[str],
) -> None:
    rows = (
        await conn.execute(
            sa.select(APP_SETTINGS.c.id, APP_SETTINGS.c.value)
            .order_by(APP_SETTINGS.c.id)
            .with_for_update(),
        )
    ).all()
    for row in rows:
        tree = _as_json(row.value)
        new_tree, changed = _rotate_json_tree(tree, keys, stats, str(row.id))
        if changed and keys.mode is Mode.ROTATE:
            await conn.execute(
                sa.update(APP_SETTINGS).where(APP_SETTINGS.c.id == row.id).values(value=new_tree),
            )
            touched.append(row.id)


async def _pass_raw_column(
    conn: AsyncConnection,
    table: sa.TableClause,
    column: str,
    fmt: str,
    keys: _Keys,
    stats: ColumnStats,
    touched: list[str],
) -> None:
    col = table.c[column]
    rows = (
        await conn.execute(
            sa.select(table.c.id, col)
            .where(col.is_not(None), col != "")
            .order_by(table.c.id)
            .with_for_update(),
        )
    ).all()
    for row in rows:
        value = row[1]
        outcome, replacement, reason = _classify_column_value(str(value), fmt, keys)
        stats.record(outcome, str(row.id), reason)
        if replacement is not None and keys.mode is Mode.ROTATE:
            await conn.execute(sa.update(table).where(table.c.id == row.id).values({column: replacement}))
            touched.append(row.id)


async def _verify_written(
    conn: AsyncConnection,
    new: EncryptionService,
    touched: dict[str, list[str]],
) -> None:
    """Re-read every rewritten row and require it to open under the new key."""
    ids = touched.get("app_settings.value", [])
    for start in range(0, len(ids), VERIFY_BATCH):
        chunk = ids[start:start + VERIFY_BATCH]
        rows = (
            await conn.execute(
                sa.select(APP_SETTINGS.c.id, APP_SETTINGS.c.section, APP_SETTINGS.c.organization_id, APP_SETTINGS.c.value)
                .where(APP_SETTINGS.c.id.in_(chunk)),
            )
        ).all()
        if len(rows) != len(chunk):
            raise _VerificationError("app_settings: rewritten rows missing on re-read")
        for row in rows:
            tree = _as_json(row.value)
            for envelope in _iter_envelopes(tree):
                if _open(new, envelope[len(SECRET_ENVELOPE_PREFIX):]) is None:
                    raise _VerificationError(f"app_settings {row.id}: rewritten envelope does not open under the new key")
            if row.section == CRYPTO_CANARY_SECTION and row.organization_id is None and not _canary_opens(tree, new):
                raise _VerificationError("_crypto_canary does not verify under the new key after rewrite")

    for table, column, _fmt in RAW_TARGETS:
        target = f"{table.name}.{column}"
        ids = touched.get(target, [])
        col = table.c[column]
        for start in range(0, len(ids), VERIFY_BATCH):
            chunk = ids[start:start + VERIFY_BATCH]
            rows = (await conn.execute(sa.select(table.c.id, col).where(table.c.id.in_(chunk)))).all()
            if len(rows) != len(chunk):
                raise _VerificationError(f"{target}: rewritten rows missing on re-read")
            for row in rows:
                value = str(row[1] or "")
                ciphertext = value[len(SECRET_ENVELOPE_PREFIX):] if is_enveloped(value) else value
                if _open(new, ciphertext) is None:
                    raise _VerificationError(f"{target} {row.id}: rewritten value does not open under the new key")


async def _run_passes(conn: AsyncConnection, keys: _Keys, result: RunResult) -> dict[str, list[str]]:
    tables = await _existing_tables(conn)
    touched: dict[str, list[str]] = {}

    target = "app_settings.value"
    result.stats[target] = ColumnStats(target)
    touched[target] = []
    await _pass_app_settings(conn, keys, result.stats[target], touched[target])
    logger.info("rotate_master_key.pass_done", target=target, mode=keys.mode.value, **result.stats[target].as_dict())

    for table, column, fmt in RAW_TARGETS:
        target = f"{table.name}.{column}"
        result.stats[target] = ColumnStats(target)
        touched[target] = []
        if table.name not in tables:
            logger.warning("rotate_master_key.table_absent", table=table.name)
            continue
        await _pass_raw_column(conn, table, column, fmt, keys, result.stats[target], touched[target])
        logger.info("rotate_master_key.pass_done", target=target, mode=keys.mode.value, **result.stats[target].as_dict())
    return touched


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Re-encrypt every stored secret from the old ENCRYPTION_MASTER_KEY to a new one.",
        epilog="Keys are read from environment variables only and are never printed.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--generate", action="store_true", help="print a fresh base64 32-byte key and exit")
    mode.add_argument("--dry-run", action="store_true", help="report counts without writing")
    mode.add_argument(
        "--verify-only",
        action="store_true",
        help="check every encrypted value opens under the CURRENT key (the --old-key-env variable)",
    )
    parser.add_argument(
        "--old-key-env",
        default=OLD_KEY_ENV,
        metavar="VAR",
        help=f"environment variable holding the old (current) key (default {OLD_KEY_ENV})",
    )
    parser.add_argument(
        "--new-key-env",
        default=NEW_KEY_ENV,
        metavar="VAR",
        help=f"environment variable holding the new key (default {NEW_KEY_ENV})",
    )
    return parser


def _log_summary(result: RunResult) -> None:
    for stats in result.stats.values():
        logger.info("rotate_master_key.summary", target=stats.target, mode=result.mode.value, **stats.as_dict())
        for failure in stats.failures:
            logger.error("rotate_master_key.value_failed", target=stats.target, location=failure)


async def run(
    argv: Optional[Sequence[str]] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    engine: Optional[AsyncEngine] = None,
) -> RunResult:
    """Parse ``argv`` and run the rotation. Never raises for operational errors."""
    args = _build_parser().parse_args(argv)
    env = os.environ if environ is None else environ

    if args.generate:
        print(EncryptionService.generate_key())
        return RunResult(mode=Mode.ROTATE, exit_code=EXIT_OK)

    mode = Mode.VERIFY if args.verify_only else Mode.DRY_RUN if args.dry_run else Mode.ROTATE
    result = RunResult(mode=mode, exit_code=EXIT_FAILED)

    try:
        old = _load_service(env, args.old_key_env, "old" if mode is not Mode.VERIFY else "current")
        new: Optional[EncryptionService] = None
        if mode is not Mode.VERIFY:
            new = _load_service(env, args.new_key_env, "new")
            if new.master_key == old.master_key:
                raise RotationRefusedError("old and new keys are identical")
    except RotationRefusedError as exc:
        result.exit_code, result.error = EXIT_REFUSED, str(exc)
        logger.error("rotate_master_key.refused", mode=mode.value, reason=result.error)
        return result
    keys = _Keys(mode=mode, old=old, new=new)

    if engine is None:
        from src.core.database import engine as default_engine

        engine = default_engine

    logger.info("rotate_master_key.start", mode=mode.value, dialect=engine.dialect.name)
    async with engine.connect() as conn:
        trans = await conn.begin()
        try:
            result.canary = await _check_canary(conn, keys)
            logger.info("rotate_master_key.canary_ok", opens_under=result.canary)
            touched = await _run_passes(conn, keys, result)
            if result.total_failed:
                raise _VerificationError(
                    f"{result.total_failed} value(s) open under neither key; nothing was committed",
                )
            if mode is Mode.ROTATE:
                assert new is not None
                await _verify_written(conn, new, touched)
                await trans.commit()
                result.committed = True
            else:
                await trans.rollback()
            result.exit_code = EXIT_OK
        except RotationRefusedError as exc:
            await trans.rollback()
            result.exit_code, result.error = EXIT_REFUSED, str(exc)
            logger.error("rotate_master_key.refused", mode=mode.value, reason=result.error)
        except _VerificationError as exc:
            await trans.rollback()
            result.exit_code, result.error = EXIT_FAILED, str(exc)
            logger.error("rotate_master_key.rolled_back", mode=mode.value, reason=result.error)
        except Exception as exc:  # any DB/driver error: roll back, report the class only
            await trans.rollback()
            # Only the class name: driver messages can echo bound parameters.
            result.exit_code, result.error = EXIT_FAILED, f"database error ({type(exc).__name__})"
            logger.error("rotate_master_key.rolled_back", mode=mode.value, reason=type(exc).__name__)

    _log_summary(result)
    logger.info(
        "rotate_master_key.finished",
        mode=mode.value,
        exit_code=result.exit_code,
        committed=result.committed,
        failed=result.total_failed,
    )
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    from src.core.logging import setup_logging

    setup_logging()
    return asyncio.run(run(argv)).exit_code


if __name__ == "__main__":
    sys.exit(main())
