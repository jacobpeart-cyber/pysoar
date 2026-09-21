"""``src.core.secrets`` envelope helpers (design section 10) and the integrations re-export."""
from __future__ import annotations

import base64
import secrets as pysecrets

import pytest

from src.core import secrets as secrets_mod
from src.core.secrets import (
    SECRET_ENVELOPE_PREFIX,
    EncryptionService,
    SecretUnreadable,
    _decrypt_secret_json,
    _encrypt_secret_json,
    decrypt_secret_json,
    encrypt_secret_json,
    envelope_secret_keys,
    is_enveloped,
    open_secret_keys,
)


def _service() -> EncryptionService:
    return EncryptionService(master_key=base64.b64encode(pysecrets.token_bytes(32)).decode())


def test_round_trip_with_explicit_service() -> None:
    svc = _service()
    payload = {"api_key": "sk-ant-api03-abcdefghijklmnop", "url": "https://x", "n": 1}
    blob = encrypt_secret_json(payload, service=svc)
    assert blob.startswith(SECRET_ENVELOPE_PREFIX)
    assert "sk-ant" not in blob
    assert decrypt_secret_json(blob, service=svc) == payload


def test_required_rejects_plaintext_and_legacy_shapes() -> None:
    svc = _service()
    with pytest.raises(SecretUnreadable) as exc:
        decrypt_secret_json('{"api_key": "x"}', service=svc)
    assert exc.value.reason == "not_enveloped"
    with pytest.raises(SecretUnreadable) as exc2:
        decrypt_secret_json('__plaintext__:{"api_key": "x"}', service=svc)
    assert exc2.value.reason == "not_enveloped"
    with pytest.raises(SecretUnreadable):
        decrypt_secret_json(None, service=svc)
    with pytest.raises(SecretUnreadable):
        decrypt_secret_json("", service=svc)


def test_wrong_key_raises_decrypt_failed() -> None:
    blob = encrypt_secret_json({"token": "t"}, service=_service())
    with pytest.raises(SecretUnreadable) as exc:
        decrypt_secret_json(blob, service=_service())
    assert exc.value.reason == "decrypt_failed"


def test_non_required_returns_empty_dict_never_raises() -> None:
    blob = encrypt_secret_json({"token": "t"}, service=_service())
    assert decrypt_secret_json(blob, service=_service(), required=False) == {}
    assert decrypt_secret_json("not json", service=_service(), required=False) == {}
    assert decrypt_secret_json(None, required=False) == {}


def test_envelope_secret_keys_is_idempotent_and_walks_nesting() -> None:
    svc = _service()
    value = {
        "api_key": "k1",
        "url": "https://example",
        "nested": {"password": "p", "list": [{"token": "t"}]},
        "empty": {"api_key": ""},
        "none": {"secret": None},
    }
    once, changed = envelope_secret_keys(value, service=svc)
    assert changed == 3
    assert is_enveloped(once["api_key"]) and is_enveloped(once["nested"]["password"])
    assert is_enveloped(once["nested"]["list"][0]["token"])
    assert once["url"] == "https://example"
    assert once["empty"]["api_key"] == "" and once["none"]["secret"] is None
    twice, changed_again = envelope_secret_keys(once, service=svc)
    assert changed_again == 0 and twice == once
    assert open_secret_keys(twice, service=svc) == value


def test_open_secret_keys_raises_on_unreadable() -> None:
    enveloped, _ = envelope_secret_keys({"api_key": "k"}, service=_service())
    with pytest.raises(SecretUnreadable):
        open_secret_keys(enveloped, service=_service())


def test_encryption_service_without_key_raises_outside_dev(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.core.config import settings

    monkeypatch.setattr(settings, "app_env", "production")
    with pytest.raises(RuntimeError, match="ENCRYPTION_MASTER_KEY"):
        EncryptionService(master_key=None)
    monkeypatch.setattr(settings, "app_env", "test")
    svc = EncryptionService(master_key=None)  # loud warning, allowed
    assert len(svc.master_key) == 32


def test_default_service_refuses_when_no_master_key_outside_dev(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.core.config import settings

    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "encryption_master_key", None)
    with pytest.raises(SecretUnreadable) as exc:
        encrypt_secret_json({"api_key": "k"})
    assert exc.value.reason == "no_master_key"
    with pytest.raises(SecretUnreadable):
        decrypt_secret_json(SECRET_ENVELOPE_PREFIX + "AAAA")


def test_compat_wrappers_and_integrations_reexport(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = _service()
    monkeypatch.setattr(secrets_mod, "_resolve_service", lambda service: service or svc)
    blob = _encrypt_secret_json({"api_key": "k"})
    assert blob.startswith(SECRET_ENVELOPE_PREFIX)
    assert _decrypt_secret_json(blob) == {"api_key": "k"}
    assert _encrypt_secret_json(None) == ""
    assert _decrypt_secret_json("garbage") == {}

    from src.api.v1.endpoints import integrations

    assert integrations._encrypt_secret_json is _encrypt_secret_json
    assert integrations._decrypt_secret_json is _decrypt_secret_json
