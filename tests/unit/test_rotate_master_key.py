"""Tests for scripts/rotate_master_key.py (ENCRYPTION_MASTER_KEY rotation).

Rows in all four encrypted stores are written under key A with the real
``EncryptionService`` and envelope helpers, then rotated to key B through the
script's ``run`` entry point. All data here is synthetic test data.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.agentic.transcript import AgentRunTranscript
from src.core.secrets import (
    SECRET_ENVELOPE_PREFIX,
    EncryptionService,
    decrypt_secret_json,
    encrypt_secret_json,
)
from src.integrations.models import InstalledIntegration
from src.models.organization import Organization
from src.models.settings import AppSetting
from src.models.user import User

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "rotate_master_key.py"

KEY_A = EncryptionService.generate_key()
KEY_B = EncryptionService.generate_key()
KEY_WRONG = EncryptionService.generate_key()

CANARY_PLAINTEXT = "test-canary-" + "0" * 20
PLAINTEXT_CREDS = '__plaintext__:{"api_key": "test-plain"}'


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rotate_master_key", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["rotate_master_key"] = module
    spec.loader.exec_module(module)
    return module


rmk = _load_script()


def _svc(key: str) -> EncryptionService:
    return EncryptionService(master_key=key)


def _opens(service: EncryptionService, value: str) -> bool:
    raw = value[len(SECRET_ENVELOPE_PREFIX):] if value.startswith(SECRET_ENVELOPE_PREFIX) else value
    try:
        service.decrypt_field(raw)
    except ValueError:
        return False
    return True


def _env(old: str = KEY_A, new: str = KEY_B) -> dict[str, str]:
    return {"ENCRYPTION_MASTER_KEY": old, "ENCRYPTION_MASTER_KEY_NEW": new}


async def _seed(db: AsyncSession) -> dict[str, Any]:
    """Write one row per encrypted store under key A; return the ids."""
    a = _svc(KEY_A)
    org = Organization(name="Rotation Test Org", slug=f"rot-{uuid.uuid4().hex[:8]}")
    db.add(org)
    await db.flush()

    canary = AppSetting(
        organization_id=None,
        section="_crypto_canary",
        value={
            "envelope": encrypt_secret_json({"canary": CANARY_PLAINTEXT}, service=a),
            "plaintext_sha256": hashlib.sha256(CANARY_PLAINTEXT.encode()).hexdigest(),
            "written_by": "test",
        },
    )
    splunk = AppSetting(
        organization_id=org.id,
        section="integration:splunk",
        value={
            "url": "https://splunk.test.invalid",
            "api_key": encrypt_secret_json("test-splunk-key", service=a),
            "nested": {"password": encrypt_secret_json("test-pass", service=a)},
        },
    )
    general = AppSetting(organization_id=org.id, section="general", value={"timezone": "UTC"})

    connector_id = str(uuid.uuid4())
    ii_env = InstalledIntegration(
        organization_id=org.id,
        connector_id=connector_id,
        display_name="enveloped",
        config_encrypted="{}",
        auth_credentials_encrypted=encrypt_secret_json({"api_key": "test-env"}, service=a),
    )
    ii_raw = InstalledIntegration(
        organization_id=org.id,
        connector_id=connector_id,
        display_name="legacy raw",
        config_encrypted="{}",
        auth_credentials_encrypted=a.encrypt_field(json.dumps({"token": "test-raw"})),
    )
    ii_plain = InstalledIntegration(
        organization_id=org.id,
        connector_id=connector_id,
        display_name="plaintext marker",
        config_encrypted="{}",
        auth_credentials_encrypted=PLAINTEXT_CREDS,
    )
    user = User(email=f"rot-{uuid.uuid4().hex[:8]}@example.com", hashed_password="x", organization_id=org.id)
    transcript = AgentRunTranscript(run_id=f"run-{uuid.uuid4().hex}", organization_id=org.id, mode="autonomous")
    db.add_all([canary, splunk, general, ii_env, ii_raw, ii_plain, user, transcript])
    await db.flush()

    # Encrypted ORM columns: write the ciphertext directly (bypasses the
    # process-wide EncryptionService the TypeDecorators would use).
    await db.execute(
        text("UPDATE users SET mfa_secret = :s, mfa_backup_codes = :c WHERE id = :id"),
        {
            "s": a.encrypt_field("TESTMFASECRET"),
            "c": a.encrypt_field(json.dumps({"codes": ["test-1", "test-2"]})),
            "id": user.id,
        },
    )
    await db.execute(
        text("UPDATE agent_run_transcripts SET steps = :s WHERE id = :id"),
        {"s": a.encrypt_field(json.dumps([{"step": 1, "tool": "test"}])), "id": transcript.id},
    )
    await db.commit()
    return {
        "canary": canary.id,
        "splunk": splunk.id,
        "general": general.id,
        "ii_env": ii_env.id,
        "ii_raw": ii_raw.id,
        "ii_plain": ii_plain.id,
        "user": user.id,
        "transcript": transcript.id,
        "org": org.id,
    }


async def _snapshot(db: AsyncSession) -> dict[str, list[tuple]]:
    """Raw stored values of every column the script touches."""
    out = {
        "app_settings": (await db.execute(text("SELECT id, value FROM app_settings ORDER BY id"))).all(),
        "installed_integrations": (
            await db.execute(text("SELECT id, auth_credentials_encrypted FROM installed_integrations ORDER BY id"))
        ).all(),
        "users": (await db.execute(text("SELECT id, mfa_secret, mfa_backup_codes FROM users ORDER BY id"))).all(),
        "agent_run_transcripts": (
            await db.execute(text("SELECT id, steps FROM agent_run_transcripts ORDER BY id"))
        ).all(),
    }
    await db.commit()
    return {k: [tuple(r) for r in v] for k, v in out.items()}


async def _setting(db: AsyncSession, row_id: str) -> dict[str, Any]:
    raw = (await db.execute(text("SELECT value FROM app_settings WHERE id = :id"), {"id": row_id})).scalar_one()
    await db.commit()
    return json.loads(raw) if isinstance(raw, str) else raw


async def _scalar(db: AsyncSession, sql: str, row_id: str) -> str:
    value = (await db.execute(text(sql), {"id": row_id})).scalar_one()
    await db.commit()
    return value


# ---------------------------------------------------------------------------


async def test_rotation_reencrypts_every_store(db_session: AsyncSession) -> None:
    ids = await _seed(db_session)
    a, b = _svc(KEY_A), _svc(KEY_B)

    result = await rmk.run([], environ=_env())

    assert result.exit_code == 0, result.error
    assert result.committed and result.canary == "old"
    stats = {k: v.as_dict() for k, v in result.stats.items()}
    assert stats["app_settings.value"]["rotated"] == 3  # canary + api_key + nested password
    assert stats["installed_integrations.auth_credentials_encrypted"] == {
        "rotated": 2, "already_rotated": 0, "skipped_plaintext": 1, "verified": 0, "failed": 0,
    }
    assert stats["users.mfa_secret"]["rotated"] == 1
    assert stats["users.mfa_backup_codes"]["rotated"] == 1
    assert stats["agent_run_transcripts.steps"]["rotated"] == 1

    # Canary: re-encrypted under B, digest still matches, A no longer opens it.
    canary = await _setting(db_session, ids["canary"])
    opened = decrypt_secret_json(canary["envelope"], service=b)
    assert hashlib.sha256(opened["canary"].encode()).hexdigest() == canary["plaintext_sha256"]
    assert not _opens(a, canary["envelope"])

    splunk = await _setting(db_session, ids["splunk"])
    assert splunk["url"] == "https://splunk.test.invalid"
    assert decrypt_secret_json(splunk["api_key"], service=b) == "test-splunk-key"
    assert decrypt_secret_json(splunk["nested"]["password"], service=b) == "test-pass"
    assert not _opens(a, splunk["api_key"]) and not _opens(a, splunk["nested"]["password"])
    assert await _setting(db_session, ids["general"]) == {"timezone": "UTC"}

    sql_ii = "SELECT auth_credentials_encrypted FROM installed_integrations WHERE id = :id"
    env_val = await _scalar(db_session, sql_ii, ids["ii_env"])
    assert env_val.startswith(SECRET_ENVELOPE_PREFIX)
    assert decrypt_secret_json(env_val, service=b) == {"api_key": "test-env"}
    raw_val = await _scalar(db_session, sql_ii, ids["ii_raw"])
    assert not raw_val.startswith(SECRET_ENVELOPE_PREFIX)
    assert json.loads(b.decrypt_field(raw_val)) == {"token": "test-raw"}
    assert not _opens(a, env_val) and not _opens(a, raw_val)
    assert await _scalar(db_session, sql_ii, ids["ii_plain"]) == PLAINTEXT_CREDS

    mfa = await _scalar(db_session, "SELECT mfa_secret FROM users WHERE id = :id", ids["user"])
    codes = await _scalar(db_session, "SELECT mfa_backup_codes FROM users WHERE id = :id", ids["user"])
    steps = await _scalar(db_session, "SELECT steps FROM agent_run_transcripts WHERE id = :id", ids["transcript"])
    assert b.decrypt_field(mfa) == "TESTMFASECRET"
    assert json.loads(b.decrypt_field(codes)) == {"codes": ["test-1", "test-2"]}
    assert json.loads(b.decrypt_field(steps)) == [{"step": 1, "tool": "test"}]
    for value in (mfa, codes, steps):
        assert not _opens(a, value)

    # verify-only under the new current key succeeds; under the old key it refuses.
    ok = await rmk.run(["--verify-only"], environ={"ENCRYPTION_MASTER_KEY": KEY_B})
    assert ok.exit_code == 0, ok.error
    assert ok.total_failed == 0
    assert ok.stats["users.mfa_secret"].verified == 1
    stale = await rmk.run(["--verify-only"], environ={"ENCRYPTION_MASTER_KEY": KEY_A})
    assert stale.exit_code == 2


async def test_dry_run_writes_nothing(db_session: AsyncSession) -> None:
    await _seed(db_session)
    before = await _snapshot(db_session)

    result = await rmk.run(["--dry-run"], environ=_env())

    assert result.exit_code == 0, result.error
    assert not result.committed
    assert result.stats["app_settings.value"].rotated == 3
    assert result.stats["agent_run_transcripts.steps"].rotated == 1
    assert await _snapshot(db_session) == before


async def test_second_run_reports_already_rotated(db_session: AsyncSession) -> None:
    await _seed(db_session)
    first = await rmk.run([], environ=_env())
    assert first.exit_code == 0, first.error
    after_first = await _snapshot(db_session)

    second = await rmk.run([], environ=_env())

    assert second.exit_code == 0, second.error
    assert second.canary == "new"
    for stats in second.stats.values():
        assert stats.rotated == 0 and stats.failed == 0
    assert second.stats["app_settings.value"].already_rotated == 3
    assert second.stats["installed_integrations.auth_credentials_encrypted"].already_rotated == 2
    assert second.stats["installed_integrations.auth_credentials_encrypted"].skipped_plaintext == 1
    assert second.stats["users.mfa_secret"].already_rotated == 1
    assert second.stats["users.mfa_backup_codes"].already_rotated == 1
    assert second.stats["agent_run_transcripts.steps"].already_rotated == 1
    assert await _snapshot(db_session) == after_first


async def test_wrong_old_key_is_refused_before_any_write(db_session: AsyncSession) -> None:
    await _seed(db_session)
    before = await _snapshot(db_session)

    result = await rmk.run([], environ=_env(old=KEY_WRONG))

    assert result.exit_code == 2
    assert "canary" in result.error
    assert result.stats == {}
    assert await _snapshot(db_session) == before


async def test_corrupt_value_rolls_back_everything(db_session: AsyncSession) -> None:
    ids = await _seed(db_session)
    # A second transcript whose ciphertext opens under neither key. It is
    # processed after app_settings / integrations / users were rewritten.
    corrupt = AgentRunTranscript(run_id=f"run-{uuid.uuid4().hex}", organization_id=ids["org"], mode="autonomous")
    db_session.add(corrupt)
    await db_session.flush()
    await db_session.execute(
        text("UPDATE agent_run_transcripts SET steps = :s WHERE id = :id"),
        {"s": base64.b64encode(b"\x00" * 64).decode(), "id": corrupt.id},
    )
    await db_session.commit()
    before = await _snapshot(db_session)

    result = await rmk.run([], environ=_env())

    assert result.exit_code == 1
    assert not result.committed
    assert result.stats["users.mfa_secret"].rotated == 1  # was written, then rolled back
    assert result.stats["agent_run_transcripts.steps"].failed == 1
    assert result.stats["agent_run_transcripts.steps"].failures[0].startswith(corrupt.id)
    assert await _snapshot(db_session) == before
    canary = await _setting(db_session, ids["canary"])
    assert _opens(_svc(KEY_A), canary["envelope"])


async def test_post_write_verification_failure_rolls_back(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed(db_session)
    before = await _snapshot(db_session)

    async def _fail(*_args: Any, **_kwargs: Any) -> None:
        raise rmk._VerificationError("injected verification failure")

    monkeypatch.setattr(rmk, "_verify_written", _fail)
    result = await rmk.run([], environ=_env())

    assert result.exit_code == 1
    assert result.error == "injected verification failure"
    assert await _snapshot(db_session) == before


async def test_missing_or_invalid_keys_refused(db_session: AsyncSession) -> None:
    await _seed(db_session)
    before = await _snapshot(db_session)

    missing = await rmk.run([], environ={"ENCRYPTION_MASTER_KEY": KEY_A})
    assert missing.exit_code == 2 and "ENCRYPTION_MASTER_KEY_NEW" in missing.error
    short = await rmk.run([], environ=_env(new=base64.b64encode(b"x" * 16).decode()))
    assert short.exit_code == 2
    same = await rmk.run([], environ=_env(new=KEY_A))
    assert same.exit_code == 2
    for res in (missing, short, same):
        assert KEY_A not in res.error and KEY_B not in res.error
    assert await _snapshot(db_session) == before


async def test_generate_prints_a_valid_key(capsys: pytest.CaptureFixture[str]) -> None:
    result = await rmk.run(["--generate"], environ={})
    assert result.exit_code == 0
    key = capsys.readouterr().out.strip().splitlines()[-1]
    assert len(base64.b64decode(key)) == 32
