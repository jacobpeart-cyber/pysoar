"""docs/install/environment.md is generated from the code and must stay current.

The doc is rendered by scripts/gen_env_reference.py from the pydantic Settings
in src/core/config.py, direct os.environ reads under src/ and alembic/, and
docker-compose.yml interpolations. When this test fails, run:

    python scripts/gen_env_reference.py
"""

import importlib.util
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.core.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "gen_env_reference.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_env_reference", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve their module through sys.modules while the class body runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen():
    return _load_generator()


def test_environment_doc_is_current(gen):
    on_disk = gen.DOC_PATH.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert on_disk == gen.render(), (
        "docs/install/environment.md is stale: run `python scripts/gen_env_reference.py` and commit it"
    )


def test_check_mode_reports_a_stale_doc(gen, tmp_path, monkeypatch, capsys):
    stale = tmp_path / "environment.md"
    stale.write_text(gen.render().replace("`DATABASE_URL`", "`DATABASE_URI`"), encoding="utf-8")
    monkeypatch.setattr(gen, "DOC_PATH", stale)
    assert gen.main(["--check"]) == 1
    assert "stale" in capsys.readouterr().out


def test_every_setting_has_a_row(gen):
    doc = gen.DOC_PATH.read_text(encoding="utf-8")
    for name in Settings.model_fields:
        assert f"| `{name.upper()}`" in doc or f"`{name.upper()}`<br>" in doc or f"<br>`{name.upper()}`" in doc, name


def test_secret_settings_are_marked_secret(gen):
    doc = gen.DOC_PATH.read_text(encoding="utf-8")
    for name in ("SECRET_KEY", "JWT_SECRET_KEY", "ENCRYPTION_MASTER_KEY", "DATABASE_URL", "FIRST_ADMIN_PASSWORD"):
        row = next(line for line in doc.splitlines() if line.startswith(f"| `{name}` |"))
        assert row.split("|")[4].strip() == "yes", row


def test_unclassified_secret_looking_setting_fails_generation(gen, monkeypatch):
    trimmed = dict(gen.SECRET_FIELDS)
    trimmed.pop("smtp_password")
    monkeypatch.setattr(gen, "SECRET_FIELDS", trimmed)
    with pytest.raises(SystemExit, match="smtp_password"):
        gen._classify(set(Settings.model_fields))


def test_undescribed_validator_fails_generation(gen, monkeypatch):
    described = dict(gen.VALIDATOR_DESCRIPTIONS)
    described.pop("validate_database_ssl_mode")
    monkeypatch.setattr(gen, "VALIDATOR_DESCRIPTIONS", described)
    with pytest.raises(SystemExit, match="validate_database_ssl_mode"):
        gen._validators_by_field(Settings)


def test_production_rule_whose_code_moved_fails_generation(gen, monkeypatch):
    rule = gen.ProductionRule(("secret_key",), "x", "src/core/config.py", "this string is not in the file")
    monkeypatch.setattr(gen, "PRODUCTION_RULES", (rule,))
    with pytest.raises(SystemExit, match="no longer"):
        gen._check_rules(set(Settings.model_fields))


# The doc's production claims, exercised against the real Settings.


@pytest.mark.parametrize("mode", ["prefer", "allow", "verify-ca"])
def test_production_rejects_other_ssl_modes(mode):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", database_ssl_mode=mode)


@pytest.mark.parametrize("mode", ["require", "verify-full", "disable"])
def test_production_accepts_documented_ssl_modes(mode):
    assert Settings(_env_file=None, app_env="production", database_ssl_mode=mode).database_ssl_mode == mode


def test_default_secrets_fail_the_production_check_and_random_ones_pass():
    defaults = Settings(_env_file=None, app_env="production", database_ssl_mode="disable")
    warnings = " ".join(defaults.validate_production_secrets())
    assert "secret_key" in warnings and "jwt_secret_key" in warnings and "encryption_master_key" in warnings

    strong = Settings(
        _env_file=None,
        app_env="production",
        database_ssl_mode="disable",
        secret_key="Vq3xN8kLp2Rz7WmTb5YcHd9JfGs4Ua6E",
        jwt_secret_key="Kr7Bn2Xq9LmZ4Wc8Tv6Yp3Hd5Jf1Gs0A",
        encryption_master_key="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        first_admin_password="Xb7-Rq2-Lm9-Wz4-Tc8",
    )
    assert strong.validate_production_secrets() == []


# Every variable the operator docs name must be in the generated reference, or
# be a parameter of a named script/compose file (checked to appear there), or
# be a placeholder / third-party tool variable listed here with its reason.

OPERATOR_DOCS = (
    "docs/install/compose.md",
    "docs/install/kubernetes.md",
    "docs/operations/upgrade.md",
    "docs/operations/backup-restore.md",
)

SCRIPT_VARIABLES = {
    "PYSOAR_DIR": "deploy/restore-db.sh",
    "MIN_USERS": "deploy/restore-db.sh",
    "APP_SERVICES": "deploy/restore-db.sh",
    "PROXY_SERVICES": "deploy/restore-db.sh",
    "HEALTH_TIMEOUT": "deploy/restore-db.sh",
    "KEEP_DAILY": "deploy/backup-db.sh",
    "KEEP_WEEKLY": "deploy/backup-db.sh",
    "KEEP_MONTHLY": "deploy/backup-db.sh",
    "KEEP_EVENT_DAYS": "deploy/backup-db.sh",
    "MIN_BYTES": "deploy/backup-db.sh",
    "SHRINK_FLOOR_PERCENT": "deploy/backup-db.sh",
    "ALLOW_SHRINK": "deploy/backup-db.sh",
    "PYSOAR_OWNER": "deploy/certbot-deploy-hook.sh",
    "RENEWED_LINEAGE": "deploy/certbot-deploy-hook.sh",
    "POSTGRES_USER": "docker-compose.yml",
    "POSTGRES_DB": "docker-compose.yml",
}

NOT_ENVIRONMENT = {
    "NEW_PASSWORD": "placeholder in a command",
    "REDIS_PASSWORD_HERE": "placeholder in the .env template",
    "POSTGRES_PASSWORD_HERE": "placeholder in the .env template",
    "ON_ERROR_STOP": "psql variable",
    "MSYS_NO_PATHCONV": "Git Bash setting used in the drill record",
    "COMPOSE_PROJECT_NAME": "docker compose setting used in the drill record",
}


def test_operator_docs_name_only_documented_variables(gen):
    import re

    reference = gen.DOC_PATH.read_text(encoding="utf-8")
    documented = set(re.findall(r"\| `([A-Z][A-Z0-9_]+)`", reference)) | set(
        re.findall(r"<br>`([A-Z][A-Z0-9_]+)`", reference),
    )
    for script, path in SCRIPT_VARIABLES.items():
        assert script in (REPO_ROOT / path).read_text(encoding="utf-8"), (script, path)
    for doc in OPERATOR_DOCS:
        text = (REPO_ROOT / doc).read_text(encoding="utf-8")
        for name in sorted(set(re.findall(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b", text))):
            assert name in documented or name in SCRIPT_VARIABLES or name in NOT_ENVIRONMENT, (
                f"{doc} names {name}, which is not in docs/install/environment.md"
            )
