"""Single redaction implementation applied at every sink (design v2 section 7).

``redact(obj)`` walks any JSON-like structure and returns ``(redacted, count)``.

Two independent mechanisms run, in this order:

1. **Key redaction** -- a dict key matching :data:`SECRET_KEY_RE` has its value
   replaced by :data:`REDACTED` when that value is a string or a container
   (nested containers are replaced wholesale). Numeric / boolean / ``None``
   values under a matching key are left alone: ``max_tokens``, ``token_count``
   and similar counters are not secrets, and the LLM call log stores token
   usage under keys that contain ``token``.
2. **Value redaction** -- every string, wherever it sits, has the credential
   shapes in :data:`VALUE_PATTERNS` replaced by a labelled marker such as
   ``[REDACTED:jwt]``.

The count is the number of replacements made (keys + value matches) so a sink
can persist ``redactions_applied`` honestly.

Callers that need the strongest profile (``returns_sensitive`` tools) use
:func:`redact_strict`, which additionally redacts long high-entropy tokens.
"""
from __future__ import annotations

import dataclasses
import math
import re
from typing import Any, Final

REDACTED: Final[str] = "[REDACTED]"

# Design section 7 key regex, applied to each dict key as a whole word segment
# (optionally plural): ``access_token``, ``max_tokens``, ``api-key``,
# ``Authorization`` and ``client_secret`` match; ``tokenizer`` and ``secretary``
# do not. Numeric values under a matching key (``max_tokens: 4096``) are kept.
SECRET_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)(?:^|[^a-z0-9])"
    r"(api[_-]?key|token|secret|passw(?:or)?d|private[_-]?key|authorization|cookie|credential)"
    r"(?:s(?![a-z0-9]))?"
    r"(?:$|[^a-z0-9])"
)

# Value patterns from design section 7. Order matters: the most specific
# prefixes (``sk-ant-``) run before the generic ``sk-`` shape.
VALUE_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "pem",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        ),
    ),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")),
    ("sk_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")),
    ("http_auth", re.compile(r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9\-_=.+/]{8,}")),
)

# Strict profile: any 32+ character run of token characters with high entropy.
_HIGH_ENTROPY_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_\-+/=]{32,}")
_HIGH_ENTROPY_BITS: Final[float] = 4.0


def _shannon_bits(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_secret_key(key: Any) -> bool:
    """True when a dict key names a credential per the design section 7 regex."""
    return isinstance(key, str) and SECRET_KEY_RE.search(key) is not None


def redact_text(text: str, *, strict: bool = False) -> tuple[str, int]:
    """Apply the value patterns to one string. Returns ``(text, replacements)``."""
    count = 0
    for label, pattern in VALUE_PATTERNS:
        text, n = pattern.subn(f"[REDACTED:{label}]", text)
        count += n
    if strict:

        def _sub(match: re.Match[str]) -> str:
            nonlocal count
            token = match.group(0)
            if _shannon_bits(token) >= _HIGH_ENTROPY_BITS:
                count += 1
                return "[REDACTED:high_entropy]"
            return token

        text = _HIGH_ENTROPY_RE.sub(_sub, text)
    return text, count


def _redact_value(value: Any, *, strict: bool, counter: list[int]) -> Any:
    if isinstance(value, str):
        text, n = redact_text(value, strict=strict)
        counter[0] += n
        return text
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if is_secret_key(key) and (isinstance(item, (str, dict, list, tuple, set, bytes)) or dataclasses.is_dataclass(item)):
                counter[0] += 1
                out[key] = REDACTED
            else:
                out[key] = _redact_value(item, strict=strict, counter=counter)
        return out
    if isinstance(value, list):
        return [_redact_value(item, strict=strict, counter=counter) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, strict=strict, counter=counter) for item in value)
    if isinstance(value, (set, frozenset)):
        return [_redact_value(item, strict=strict, counter=counter) for item in value]
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return value
        text, n = redact_text(decoded, strict=strict)
        counter[0] += n
        return text
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        as_dict = {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
        return _redact_value(as_dict, strict=strict, counter=counter)
    return value


def redact(obj: Any, *, strict: bool = False) -> tuple[Any, int]:
    """Return ``(redacted_copy, replacements)`` for any JSON-like object.

    Dataclasses are converted to dicts. Unknown scalar types pass through
    untouched. The input is never mutated.
    """
    counter = [0]
    result = _redact_value(obj, strict=strict, counter=counter)
    return result, counter[0]


def redact_strict(obj: Any) -> tuple[Any, int]:
    """Strongest profile: :func:`redact` plus high-entropy token removal."""
    return redact(obj, strict=True)


__all__ = [
    "REDACTED",
    "SECRET_KEY_RE",
    "VALUE_PATTERNS",
    "is_secret_key",
    "redact",
    "redact_strict",
    "redact_text",
]
