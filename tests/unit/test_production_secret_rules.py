"""FIRST_ADMIN_PASSWORD is held to the same weak-word rule as the other
production secrets: the code default ``changeme123`` used to pass because only
its entropy was checked (docs/install/compose.md, "Write .env")."""
from __future__ import annotations

import pytest

from src.core.config import Settings

STRONG = dict(
    secret_key="Vq3xN8kLp2Rz7WmTb5YcHd9JfGs4Ua6E",
    jwt_secret_key="Kr7Bn2Xq9LmZ4Wc8Tv6Yp3Hd5Jf1Gs0A",
    encryption_master_key="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
)


@pytest.mark.parametrize("password", ["changeme123", "Admin-2026-Rotated", "Secret!Value9", "PlaceholderX1"])
def test_default_or_guessable_first_admin_password_fails_the_production_check(password: str) -> None:
    s = Settings(_env_file=None, app_env="production", database_ssl_mode="disable", first_admin_password=password, **STRONG)
    warnings = s.validate_production_secrets()
    assert any("first_admin_password contains weak pattern" in w for w in warnings), warnings


def test_a_random_first_admin_password_passes() -> None:
    s = Settings(_env_file=None, app_env="production", database_ssl_mode="disable", first_admin_password="Xb7-Rq2-Lm9-Wz4-Tc8", **STRONG)
    assert s.validate_production_secrets() == []
