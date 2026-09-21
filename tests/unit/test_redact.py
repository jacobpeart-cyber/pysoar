"""``src.core.redact`` -- the one redaction implementation applied at every sink."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.core.redact import REDACTED, is_secret_key, redact, redact_strict, redact_text


@pytest.mark.parametrize(
    "key",
    [
        "api_key", "API-KEY", "apikey", "token", "access_token", "secret", "client_secret",
        "password", "passwd", "PASSWORD", "private_key", "private-key", "authorization",
        "Authorization", "cookie", "credential", "credentials", "aws_secret_access_key",
        "max_tokens", "tokens_used",  # substring match per design; numeric values are exempt
    ],
)
def test_secret_key_regex_matches_design_keys(key: str) -> None:
    assert is_secret_key(key)


@pytest.mark.parametrize("key", ["hostname", "username", "tokenizer", "id", "secretary", "cookiejar"])
def test_secret_key_regex_leaves_counters_and_lookalikes(key: str) -> None:
    assert not is_secret_key(key)


def test_key_redaction_recurses_and_counts() -> None:
    payload = {
        "hostname": "web-01",
        "api_key": "abc123",
        "nested": {"Authorization": "Bearer xyz", "list": [{"password": "p"}, {"ok": 1}]},
        "max_tokens": 4096,
    }
    out, count = redact(payload)
    assert out["api_key"] == REDACTED
    assert out["nested"]["Authorization"] == REDACTED
    assert out["nested"]["list"][0]["password"] == REDACTED
    assert out["nested"]["list"][1] == {"ok": 1}
    assert out["hostname"] == "web-01"
    assert out["max_tokens"] == 4096
    assert count == 3
    # input untouched
    assert payload["api_key"] == "abc123"


def test_numeric_values_under_secret_keys_are_not_redacted() -> None:
    out, count = redact({"token_count": 12, "token": 5, "secret": None})
    assert out == {"token_count": 12, "token": 5, "secret": None}
    assert count == 0


@pytest.mark.parametrize(
    "value,label",
    [
        ("sk-ant-api03-abcdefghijklmnop", "anthropic_key"),
        ("sk-abcdefghijklmnopqrstuvwxyz0123", "sk_key"),
        ("AIzaSyA1234567890abcdefghijklmnop", "google_key"),
        ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123", "github_token"),
        ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "jwt"),
        ("Bearer abcdefghijklmnop", "http_auth"),
        ("Basic dXNlcjpwYXNzd29yZA==", "http_auth"),
    ],
)
def test_value_patterns(value: str, label: str) -> None:
    text = f"found {value} in log"
    out, count = redact_text(text)
    assert value not in out
    assert f"[REDACTED:{label}]" in out
    assert count == 1


def test_pem_block_is_redacted_whole() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nABCD\n-----END RSA PRIVATE KEY-----"
    out, count = redact_text(f"key:\n{pem}\ndone")
    assert "MIIEow" not in out
    assert out == "key:\n[REDACTED:pem]\ndone"
    assert count == 1


def test_value_patterns_apply_inside_nested_strings() -> None:
    payload = {"result": ["token seen: sk-ant-api03-abcdefghijklmnop", {"note": "AKIAIOSFODNN7EXAMPLE"}]}
    out, count = redact(payload)
    assert "sk-ant" not in out["result"][0]
    assert out["result"][1]["note"] == "[REDACTED:aws_access_key]"
    assert count == 2


def test_dataclass_fields_are_walked() -> None:
    @dataclass
    class Creds:
        user: str
        password: str

    out, count = redact(Creds(user="u", password="p"))
    assert out == {"user": "u", "password": REDACTED}
    assert count == 1
    nested, count = redact({"creds": Creds(user="u", password="p")})
    assert nested == {"creds": {"user": "u", "password": REDACTED}}
    assert count == 1


def test_strict_profile_removes_high_entropy_tokens() -> None:
    token = "Qx9v2LmT8pZr4Wc1Hs7Yb3Nd6Kf0Ja5Ug"  # 32 mixed chars
    plain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    out, count = redact_strict({"blob": f"{token} {plain}"})
    assert token not in out["blob"]
    assert plain in out["blob"]
    assert count == 1
    # default profile keeps it
    out2, count2 = redact({"blob": token})
    assert out2["blob"] == token and count2 == 0


def test_no_secrets_means_zero_count_and_equal_copy() -> None:
    payload = {"a": [1, 2, {"b": "plain text"}], "c": None, "d": 1.5}
    out, count = redact(payload)
    assert out == payload and count == 0
    assert out is not payload
