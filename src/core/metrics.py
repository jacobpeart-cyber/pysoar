"""Agentic counters (design v2 section 9, *Prometheus* bullet).

``prometheus_client`` is **not** a dependency of this project (it is absent
from ``requirements.txt``) and there is no Prometheus scrape endpoint: the
existing ``/api/v1/metrics/*`` routes are product dashboards backed by SQL,
not an exposition format. So the three counters the design names are kept in
a process-local registry here and exposed as JSON by
``GET /api/v1/metrics/agentic`` (see ``src/api/v1/endpoints/health.py``).

Consequences of that choice, stated plainly:

* Counters are **per process** and reset on restart. With several API workers
  and Celery workers each process reports its own slice; the JSON endpoint
  says which process (``pid``) answered. They are an operability aid, not a
  billing or audit source -- ``llm_call_logs`` and ``audit_trails`` are.
* Swapping in ``prometheus_client`` later only requires replacing
  :func:`increment` and :func:`snapshot`; no call site changes.

Every increment also emits a structlog event (``metric_increment``) so the
counts survive in the log pipeline even though the registry does not.

Where the increments belong (this module does **not** wire them; WP5b/WP6 do):

* ``llm_calls_total{provider,stop_reason}`` -- ``src/llm/calllog.py``, in the
  function that writes the ``LLMCallLog`` row, so success and ``error`` rows
  are counted exactly once each.
* ``agent_policy_decisions_total{decision,reason}`` -- ``src/agentic/policy.py``,
  at the single return point of ``PolicyEngine.evaluate`` (one increment per
  decision, labelled with the primary reason code).
* ``agent_injection_events_total{tier}`` -- ``src/agentic/trust.py``, where the
  scanner settles the run's tier (``clean``/``suspect``/``lockdown``), once per
  scan.
* ``agent_transcripts_total{mode,outcome}`` -- ``src/agentic/transcript.py``,
  once per run transcript write (``written`` or ``failed``).
"""

from __future__ import annotations

import os
import threading
from typing import Any, Dict, Iterable, Mapping, Tuple

from src.core.logging import get_logger

logger = get_logger(__name__)

LLM_CALLS_TOTAL = "llm_calls_total"
AGENT_POLICY_DECISIONS_TOTAL = "agent_policy_decisions_total"
AGENT_INJECTION_EVENTS_TOTAL = "agent_injection_events_total"
AGENT_TRANSCRIPTS_TOTAL = "agent_transcripts_total"

# name -> ordered label names. A counter not listed here cannot be incremented:
# typos become loud errors instead of silent new series.
COUNTER_SPECS: Dict[str, Tuple[str, ...]] = {
    LLM_CALLS_TOTAL: ("provider", "stop_reason"),
    AGENT_POLICY_DECISIONS_TOTAL: ("decision", "reason"),
    AGENT_INJECTION_EVENTS_TOTAL: ("tier",),
    AGENT_TRANSCRIPTS_TOTAL: ("mode", "outcome"),
}

# Guards runaway cardinality from an unexpected label value (e.g. a provider
# error string leaking into ``stop_reason``). Past the cap the value is folded
# into ``__other__`` rather than growing the registry without bound.
MAX_SERIES_PER_COUNTER = 200
_OTHER = "__other__"
_UNKNOWN = "unknown"

_lock = threading.Lock()
_counters: Dict[str, Dict[Tuple[str, ...], int]] = {name: {} for name in COUNTER_SPECS}


class UnknownCounter(KeyError):
    """Raised when a caller increments a counter that is not in COUNTER_SPECS."""


def _normalize(value: Any) -> str:
    """Label values are short, printable strings; ``None`` becomes ``unknown``."""
    if value is None:
        return _UNKNOWN
    text = str(value).strip()
    if not text:
        return _UNKNOWN
    return text[:64]


def increment(name: str, *, amount: int = 1, **labels: Any) -> None:
    """Add ``amount`` to the ``name`` counter for the given label values.

    Unknown counter names raise :class:`UnknownCounter` (a programming error).
    Missing labels are recorded as ``unknown`` so a partially-labelled call
    still counts rather than being dropped. Never raises on label content.
    """
    spec = COUNTER_SPECS.get(name)
    if spec is None:
        raise UnknownCounter(name)
    key = tuple(_normalize(labels.get(label)) for label in spec)
    with _lock:
        series = _counters[name]
        if key not in series and len(series) >= MAX_SERIES_PER_COUNTER:
            key = tuple(_OTHER for _ in spec)
        series[key] = series.get(key, 0) + int(amount)
        total = series[key]
    logger.debug(
        "metric_increment",
        metric=name,
        amount=int(amount),
        value=total,
        **{label: key[idx] for idx, label in enumerate(spec)},
    )


def snapshot() -> Dict[str, Any]:
    """A JSON-safe copy of every counter: ``{name: {labels, series, total}}``."""
    with _lock:
        raw = {name: dict(series) for name, series in _counters.items()}
    out: Dict[str, Any] = {}
    for name, spec in COUNTER_SPECS.items():
        series = raw.get(name, {})
        out[name] = {
            "labels": list(spec),
            "series": [
                {
                    "labels": {label: key[idx] for idx, label in enumerate(spec)},
                    "value": value,
                }
                for key, value in sorted(series.items())
            ],
            "total": sum(series.values()),
        }
    return {"pid": os.getpid(), "scope": "process", "counters": out}


def reset(names: Iterable[str] | None = None) -> None:
    """Zero the named counters (all of them when ``names`` is None). Tests only."""
    targets = list(names) if names is not None else list(COUNTER_SPECS)
    with _lock:
        for name in targets:
            if name in _counters:
                _counters[name] = {}


def value(name: str, labels: Mapping[str, Any] | None = None) -> int:
    """Current value of one series (0 when it has never been incremented)."""
    spec = COUNTER_SPECS.get(name)
    if spec is None:
        raise UnknownCounter(name)
    key = tuple(_normalize((labels or {}).get(label)) for label in spec)
    with _lock:
        return _counters[name].get(key, 0)


__all__ = [
    "AGENT_INJECTION_EVENTS_TOTAL",
    "AGENT_POLICY_DECISIONS_TOTAL",
    "AGENT_TRANSCRIPTS_TOTAL",
    "COUNTER_SPECS",
    "LLM_CALLS_TOTAL",
    "MAX_SERIES_PER_COUNTER",
    "UnknownCounter",
    "increment",
    "reset",
    "snapshot",
    "value",
]
