"""DLP content scanner: policies evaluated over data the platform holds.

PySOAR has no inline inspection point (no mail gateway, proxy or endpoint
file hook), so DLP policies are evaluated where the platform really holds
content: stored SIEM log entries, compliance evidence text, ticket comments,
and incident / case-note text. Each policy resolves to

* ``active``: it has evaluable patterns and at least one monitored channel
  maps to a data source here; the scanner evaluates it, or
* ``inactive`` with the reason (disabled, no patterns, invalid pattern, every
  monitored channel has no data source in PySOAR, exfiltration rules that
  need transfer events).

The scan is bounded: per organisation and per source it reads windows of
``WINDOW_ROWS`` rows in (created_at, id) order from a stored cursor
(``dlp_scan_cursors``), at most ``MAX_ROWS_PER_SOURCE`` rows per run, and
inspects at most ``MAX_TEXT_CHARS`` characters per record. A source never
scanned before starts ``INITIAL_LOOKBACK_DAYS`` back. Every match becomes
one ``dlp_violations`` row per (policy, record) carrying the policy, the
location and an excerpt in which every match is redacted; a re-scan never
duplicates it.
"""

from __future__ import annotations

import json
import asyncio
import contextvars
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.dlp.isolated_match import match_custom_patterns
from src.dlp.engine import DLPEngine
from src.dlp.models import DLPPolicy, DLPScanCursor, DLPViolation

logger = get_logger(__name__)

WINDOW_ROWS = 200
MAX_ROWS_PER_SOURCE = 2_000
MAX_TEXT_CHARS = 20_000
#: Hard cap per record. Text up to it is scanned in overlapping chunks of
#: ``MAX_TEXT_CHARS`` (so nothing inside the cap is skipped); a record longer
#: than the cap gets a scan_incomplete finding for the unscanned remainder.
MAX_RECORD_CHARS = 1_000_000
CHUNK_OVERLAP = 256
MAX_CUSTOM_PATTERN_LENGTH = 500
INITIAL_LOOKBACK_DAYS = 30
EXCERPT_RADIUS = 120
MAX_ORGS_PER_SWEEP = 500

# Built-in detectors, by the names a policy's ``data_patterns`` may use.
BUILTIN_PATTERNS: dict[str, str] = {
    **DLPEngine.SENSITIVE_PATTERNS,
    **{f"medical_{k}": v for k, v in DLPEngine.MEDICAL_TERMS.items()},
}

# Detectors a policy type uses when the policy lists no ``data_patterns``.
# Types missing here (exfiltration_prevention, intellectual_property,
# custom_pattern) cannot be evaluated without explicit patterns.
TYPE_DEFAULT_PATTERNS: dict[str, list[str]] = {
    "pii_detection": ["ssn", "credit_card"],
    "pci_detection": ["credit_card"],
    "phi_detection": ["medical_diagnosis", "medical_medication", "medical_procedure"],
    "regulatory": ["ssn", "credit_card"],
    "data_classification": ["ssn", "credit_card", "aws_key", "private_key", "api_key"],
}

POLICY_TYPE_TO_VIOLATION: dict[str, str] = {
    "pii_detection": "pii_exposure",
    "phi_detection": "phi_exposure",
    "pci_detection": "pci_data_leak",
    "intellectual_property": "ip_theft",
    "regulatory": "pii_exposure",
}

# Channel names a policy may list in ``channels_monitored`` -> data sources.
CHANNEL_SOURCES: dict[str, list[str]] = {
    "logs": ["log_entries"],
    "log": ["log_entries"],
    "siem": ["log_entries"],
    "log_entries": ["log_entries"],
    "evidence": ["compliance_evidence"],
    "compliance_evidence": ["compliance_evidence"],
    "tickets": ["ticket_comments"],
    "ticket_comments": ["ticket_comments"],
    "cases": ["incidents", "case_notes"],
    "incidents": ["incidents"],
    "case_notes": ["case_notes"],
}


class InvalidPattern(ValueError):
    """A policy pattern that is neither a built-in name nor a valid regex."""


@dataclass
class PolicyPlan:
    """What the scanner can do with one policy."""

    policy: DLPPolicy
    status: str
    reason: Optional[str]
    patterns: dict[str, re.Pattern[str]] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    allow_values: set[str] = field(default_factory=set)
    excluded_sources: set[str] = field(default_factory=set)


def _json_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return [value]
        return parsed if isinstance(parsed, list) else [parsed]
    return [value]

# Custom patterns are tenant-authored and run in the shared worker over every
# tenant's content, so a catastrophic expression from one tenant must not
# stall the sweep for the others. Two defences: patterns with nested
# quantifiers, backreferences or huge counted repeats are refused when the
# policy is saved, and at run time each custom pattern gets a time budget per
# record; a pattern that exceeds it deactivates its policy for the run with
# the reason recorded on the policy.
#: Budget for one policy's custom patterns over one window of records; the
#: matching runs in a killable child process (src/dlp/isolated_match.py) and
#: records it did not finish are recorded as ``scan_incomplete`` findings.
POLICY_WINDOW_BUDGET_SECONDS = 10.0
#: Cumulative child-process time one organisation's run may spend across all
#: of its policies and windows; past it, remaining custom-pattern work is
#: recorded as scan_incomplete without spawning (a tenant with hundreds of
#: slow policies cannot multiply the per-policy budget into hours).
ORG_RUN_BUDGET_SECONDS = 60.0
#: Child-process time one policy may spend per run. Budgets are charged per
#: policy so a slow (or deliberately slowed) policy only exhausts itself: it is
#: then marked ``degraded`` (custom matching suspended until the policy is
#: edited; built-in detectors keep running) and the other policies are
#: unaffected. Policies run cheapest-first within a run.
POLICY_RUN_BUDGET_SECONDS = 20.0
#: A record whose chunks stall the child is a poison pill: it alone is flagged
#: and scanning resumes after it. A policy is degraded only after this many
#: poison records in one run, so one planted record cannot blind it.
MAX_POISON_RECORDS_PER_RUN = 3
#: Text handed to the child per policy and window; records beyond it are
#: recorded as unscanned rather than silently skipped.
MAX_WINDOW_CHARS_PER_POLICY = 5_000_000
_RUN_BUDGET: contextvars.ContextVar[dict[str, float] | None] = contextvars.ContextVar("_dlp_run_budget", default=None)
_NESTED_QUANTIFIER_RE = re.compile(r"(?:\([^()]*[+*][^()]*\)|\[[^\]]*\][+*]|[+*])\s*[+*{]")
_BACKREF_RE = re.compile(r"\\[1-9]|\(\?P=")
_HUGE_REPEAT_RE = re.compile(r"\{\s*(\d{4,})(?:\s*,\s*(\d*))?\s*\}|\{\s*\d*\s*,\s*(\d{4,})\s*\}")


def reject_catastrophic_pattern(entry: str) -> None:
    """Raise InvalidPattern for expressions that can backtrack exponentially."""
    if _NESTED_QUANTIFIER_RE.search(entry):
        raise InvalidPattern(
            f"pattern {entry[:40]!r} nests a quantifier inside a quantified group; "
            "rewrite it without nested repetition",
        )
    if _BACKREF_RE.search(entry):
        raise InvalidPattern(f"pattern {entry[:40]!r} uses a backreference, which is not allowed")
    if _HUGE_REPEAT_RE.search(entry):
        raise InvalidPattern(f"pattern {entry[:40]!r} uses a counted repeat above 999")


def compile_patterns(names: list[str]) -> dict[str, re.Pattern[str]]:
    """Compile built-in names and custom regexes; raise InvalidPattern."""
    compiled: dict[str, re.Pattern[str]] = {}
    for raw in names:
        entry = str(raw).strip()
        if not entry:
            continue
        if entry in BUILTIN_PATTERNS:
            compiled[entry] = re.compile(BUILTIN_PATTERNS[entry], re.IGNORECASE)
            continue
        if len(entry) > MAX_CUSTOM_PATTERN_LENGTH:
            raise InvalidPattern(
                f"pattern longer than {MAX_CUSTOM_PATTERN_LENGTH} characters: {entry[:40]}..."
            )
        reject_catastrophic_pattern(entry)
        try:
            compiled[f"custom:{entry}"] = re.compile(entry)
        except re.error as exc:
            raise InvalidPattern(f"invalid regular expression {entry!r}: {exc}") from exc
    return compiled


def validate_data_patterns(names: Optional[list[str]]) -> None:
    """Route-level validation (422 on failure)."""
    compile_patterns(list(names or []))


def resolve_sources(channels: list[Any]) -> tuple[list[str], list[str]]:
    """(data sources, channels with no data source in PySOAR)."""
    if not channels:
        return sorted({s for v in CHANNEL_SOURCES.values() for s in v}), []
    sources: list[str] = []
    unsupported: list[str] = []
    for ch in channels:
        key = str(ch).strip().lower()
        mapped = CHANNEL_SOURCES.get(key)
        if mapped is None:
            unsupported.append(str(ch))
            continue
        for s in mapped:
            if s not in sources:
                sources.append(s)
    return sources, unsupported


def plan_policy(policy: DLPPolicy, *, ignore_enabled: bool = False) -> PolicyPlan:
    """Decide whether (and how) the scanner evaluates ``policy``."""
    if not policy.enabled and not ignore_enabled:
        return PolicyPlan(policy, "inactive", "policy is disabled")

    names = [str(n) for n in _json_list(policy.data_patterns)]
    if not names:
        names = list(TYPE_DEFAULT_PATTERNS.get(policy.policy_type or "", []))
    if not names:
        if policy.policy_type == "exfiltration_prevention":
            reason = (
                "exfiltration rules need transfer events (destination, volume); no "
                "data source in PySOAR provides them; add data_patterns to scan stored content"
            )
        else:
            reason = (
                f"policy type {policy.policy_type!r} has no built-in detectors and the "
                "policy lists no data_patterns"
            )
        return PolicyPlan(policy, "inactive", reason)
    try:
        patterns = compile_patterns(names)
    except InvalidPattern as exc:
        return PolicyPlan(policy, "inactive", str(exc))
    if not patterns:
        return PolicyPlan(policy, "inactive", "the policy lists no usable data_patterns")

    sources, unsupported = resolve_sources(_json_list(policy.channels_monitored))
    if not sources:
        return PolicyPlan(
            policy,
            "inactive",
            "no data source for the monitored channel(s): "
            + ", ".join(unsupported)
            + "; PySOAR scans logs, evidence, tickets and cases",
        )

    allow_values: set[str] = set()
    excluded_sources: set[str] = set()
    for exc in _json_list(policy.exceptions):
        if isinstance(exc, dict):
            if exc.get("value"):
                allow_values.add(str(exc["value"]))
            if exc.get("source_type"):
                excluded_sources.add(str(exc["source_type"]))
    reason = None
    if unsupported:
        reason = "not scanned (no data source): " + ", ".join(unsupported)
    return PolicyPlan(
        policy, "active", reason, patterns, [s for s in sources if s not in excluded_sources],
        allow_values, excluded_sources,
    )


def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_matches(plan: PolicyPlan, text: str) -> list[tuple[str, int, int]]:
    """(pattern name, start, end) for every match in ``text`` (bounded)."""
    hits = _builtin_matches(plan, text)
    custom = {name: pattern.pattern for name, pattern in plan.patterns.items() if name.startswith("custom:")}
    if custom:
        found, unscanned, _timed_out = match_custom_patterns(custom, [("one", text)], POLICY_WINDOW_BUDGET_SECONDS)
        if unscanned:
            raise ScanIncomplete(POLICY_WINDOW_BUDGET_SECONDS, len(text))
        hits.extend(_filter_hits(plan, text, found.get("one", [])))
    hits.sort(key=lambda h: h[1])
    return hits


async def find_matches_async(plan: PolicyPlan, text: str) -> list[tuple[str, int, int]]:
    """``find_matches`` for async callers: the child process runs in a worker thread."""
    hits = _builtin_matches(plan, text)
    custom = {name: pattern.pattern for name, pattern in plan.patterns.items() if name.startswith("custom:")}
    if custom:
        found, unscanned, _timed_out = await asyncio.to_thread(
            match_custom_patterns, custom, [("one", text)], POLICY_WINDOW_BUDGET_SECONDS,
        )
        if unscanned:
            raise ScanIncomplete(POLICY_WINDOW_BUDGET_SECONDS, len(text))
        hits.extend(_filter_hits(plan, text, found.get("one", [])))
    hits.sort(key=lambda h: h[1])
    return hits


class ScanIncomplete(Exception):
    """The custom patterns did not finish within the budget for a record."""

    def __init__(self, budget: float, chars: int) -> None:
        super().__init__(f"custom pattern scan exceeded {budget:.0f}s on a {chars}-char record")
        self.budget = budget
        self.chars = chars


def _filter_hits(plan: PolicyPlan, text: str, raw: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for name, start, end in raw:
        value = text[start:end]
        if not value or value in plan.allow_values:
            continue
        if name == "credit_card" and not _luhn_ok(value):
            continue
        out.append((name, start, end))
    return out


def _builtin_matches(plan: PolicyPlan, text: str) -> list[tuple[str, int, int]]:
    """Trusted built-in detectors run inline."""
    hits: list[tuple[str, int, int]] = []
    for name, pattern in plan.patterns.items():
        if name.startswith("custom:"):
            continue
        for m in pattern.finditer(text):
            value = m.group(0)
            if not value or value in plan.allow_values:
                continue
            if name == "credit_card" and not _luhn_ok(value):
                continue
            hits.append((name, m.start(), m.end()))
    return hits


# Secrets redacted from every excerpt even when the policy did not look for
# them, so a finding never re-exposes another credential or identifier.
_ALWAYS_REDACT = {
    name: re.compile(BUILTIN_PATTERNS[name], re.IGNORECASE)
    for name in ("ssn", "credit_card", "api_key", "aws_key", "private_key")
}


def redacted_excerpt(text: str, hits: list[tuple[str, int, int]]) -> str:
    """Excerpt around the first policy match; every policy match and every
    other secret-shaped value in the text is redacted."""
    first = hits[0][1] if hits else 0
    extra = [
        (name, m.start(), m.end())
        for name, pattern in _ALWAYS_REDACT.items()
        for m in pattern.finditer(text)
    ]
    out = ""
    markers: list[tuple[int, int]] = []
    anchor: Optional[int] = None
    cursor = 0
    for name, start, end in sorted(hits + extra, key=lambda h: (h[1], -h[2])):
        if start < cursor:
            continue  # overlaps a match already redacted
        out += text[cursor:start]
        marker = f"[REDACTED:{name.split(':', 1)[0]}]"
        if anchor is None and start >= first:
            anchor = len(out)
        markers.append((len(out), len(out) + len(marker)))
        out += marker
        cursor = end
    out += text[cursor:]
    anchor = anchor or 0
    lo = max(0, anchor - EXCERPT_RADIUS)
    hi = min(len(out), anchor + EXCERPT_RADIUS * 2)
    # Never cut a marker in half at the window edges.
    for m_start, m_end in markers:
        if m_start < lo < m_end:
            lo = m_start
        if m_start < hi < m_end:
            hi = m_end
    return ("..." if lo > 0 else "") + out[lo:hi] + ("..." if hi < len(out) else "")


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------
@dataclass
class _Record:
    id: str
    created_at: Any
    text: str
    location: str
    user: Optional[str]


@dataclass
class _Source:
    key: str
    label: str
    fetch: Callable[[AsyncSession, str, Any, Optional[str], Any, int], Any]


def _keyset(model_created, model_id, last_created, last_id, floor):
    clauses = []
    if last_created is not None:
        clauses.append(
            or_(
                model_created > last_created,
                and_(model_created == last_created, model_id > (last_id or "")),
            )
        )
    elif floor is not None:
        clauses.append(model_created >= floor)
    return clauses


async def _fetch_log_entries(db, org_id, last_created, last_id, floor, limit):
    from src.siem.models import LogEntry

    stmt = (
        select(
            LogEntry.id, LogEntry.created_at, LogEntry.raw_log, LogEntry.message,
            LogEntry.source_name, LogEntry.timestamp, LogEntry.username,
        )
        .where(LogEntry.organization_id == org_id, *_keyset(LogEntry.created_at, LogEntry.id, last_created, last_id, floor))
        .order_by(LogEntry.created_at, LogEntry.id)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [
        _Record(
            r.id, r.created_at, "\n".join(x for x in (r.message, r.raw_log) if x),
            f"log_entries/{r.id} ({r.source_name}, {r.timestamp})", r.username,
        )
        for r in rows
    ]


async def _fetch_evidence(db, org_id, last_created, last_id, floor, limit):
    from src.compliance.models import ComplianceEvidence as E

    stmt = (
        select(E.id, E.created_at, E.title, E.description, E.content, E.collected_by)
        .where(E.organization_id == org_id, *_keyset(E.created_at, E.id, last_created, last_id, floor))
        .order_by(E.created_at, E.id)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [
        _Record(
            r.id, r.created_at, "\n".join(x for x in (r.title, r.description, r.content) if x),
            f"compliance_evidence/{r.id} ({(r.title or '')[:80]})", r.collected_by,
        )
        for r in rows
    ]


async def _fetch_ticket_comments(db, org_id, last_created, last_id, floor, limit):
    from src.tickethub.models import TicketComment as T

    stmt = (
        select(T.id, T.created_at, T.content, T.source_type, T.source_id, T.author_id)
        .where(T.organization_id == org_id, *_keyset(T.created_at, T.id, last_created, last_id, floor))
        .order_by(T.created_at, T.id)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [
        _Record(
            r.id, r.created_at, r.content or "",
            f"ticket_comments/{r.id} on {r.source_type}/{r.source_id}", r.author_id,
        )
        for r in rows
    ]


async def _fetch_incidents(db, org_id, last_created, last_id, floor, limit):
    from src.models.incident import Incident as I

    stmt = (
        select(I.id, I.created_at, I.title, I.description, I.resolution, I.root_cause)
        .where(I.organization_id == org_id, *_keyset(I.created_at, I.id, last_created, last_id, floor))
        .order_by(I.created_at, I.id)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [
        _Record(
            r.id, r.created_at,
            "\n".join(x for x in (r.title, r.description, r.resolution, r.root_cause) if x),
            f"incidents/{r.id} ({(r.title or '')[:80]})", None,
        )
        for r in rows
    ]


async def _fetch_case_notes(db, org_id, last_created, last_id, floor, limit):
    from src.models.case import CaseNote as N
    from src.models.incident import Incident as I

    stmt = (
        select(N.id, N.created_at, N.content, N.incident_id, N.author_id)
        .join(I, I.id == N.incident_id)
        .where(I.organization_id == org_id, *_keyset(N.created_at, N.id, last_created, last_id, floor))
        .order_by(N.created_at, N.id)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    return [
        _Record(r.id, r.created_at, r.content or "", f"case_notes/{r.id} on incident {r.incident_id}", r.author_id)
        for r in rows
    ]


SOURCES: dict[str, _Source] = {
    "log_entries": _Source("log_entries", "SIEM log entries", _fetch_log_entries),
    "compliance_evidence": _Source("compliance_evidence", "Compliance evidence", _fetch_evidence),
    "ticket_comments": _Source("ticket_comments", "Ticket comments", _fetch_ticket_comments),
    "incidents": _Source("incidents", "Incidents", _fetch_incidents),
    "case_notes": _Source("case_notes", "Case notes", _fetch_case_notes),
}


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
async def load_plans(db: AsyncSession, org_id: str, *, persist: bool = True) -> list[PolicyPlan]:
    """Plan every policy of the org and (optionally) store each status."""
    policies = (
        await db.execute(
            select(DLPPolicy).where(DLPPolicy.organization_id == org_id).order_by(DLPPolicy.created_at).limit(500)
        )
    ).scalars().all()
    plans = [plan_policy(p) for p in policies]
    if persist:
        for plan in plans:
            plan.policy.evaluation_status = plan.status
            plan.policy.evaluation_reason = plan.reason
    return plans


def apply_plan(policy: DLPPolicy) -> PolicyPlan:
    """Store the evaluation status on a policy just created / edited."""
    plan = plan_policy(policy)
    policy.evaluation_status = plan.status
    policy.evaluation_reason = plan.reason
    return plan


async def _cursor(db: AsyncSession, org_id: str, source: str) -> DLPScanCursor:
    row = (
        await db.execute(
            select(DLPScanCursor).where(
                DLPScanCursor.organization_id == org_id, DLPScanCursor.source_type == source
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = DLPScanCursor(organization_id=org_id, source_type=source, rows_scanned_total=0,
                            findings_total=0, last_run_rows=0, last_run_findings=0)
        db.add(row)
        await db.flush()
    return row


async def scan_organization(
    db: AsyncSession,
    org_id: str,
    *,
    max_rows_per_source: int = MAX_ROWS_PER_SOURCE,
    window_rows: int = WINDOW_ROWS,
) -> dict[str, Any]:
    """Evaluate the org's active policies over new stored records (bounded).

    The caller commits.
    """
    _RUN_BUDGET.set({"remaining": ORG_RUN_BUDGET_SECONDS, "per_policy": {}})
    now = datetime.now(timezone.utc)
    plans = await load_plans(db, org_id)
    active = [p for p in plans if p.status == "active"]
    summary: dict[str, Any] = {
        "organization_id": org_id,
        "policies_active": len(active),
        "policies_inactive": len(plans) - len(active),
        "inactive_policies": [
            {"policy_id": p.policy.id, "name": p.policy.name, "reason": p.reason}
            for p in plans if p.status != "active"
        ],
        "sources": {},
        "findings_created": 0,
        "rows_scanned": 0,
    }
    if not active:
        return summary

    floor = now - timedelta(days=INITIAL_LOOKBACK_DAYS)
    for key, source in SOURCES.items():
        source_plans = [p for p in active if key in p.sources]
        if not source_plans:
            continue
        cursor = await _cursor(db, org_id, key)
        scanned = 0
        created = 0
        error = None
        try:
            while scanned < max_rows_per_source:
                limit = min(window_rows, max_rows_per_source - scanned)
                # One savepoint per window: a failing window is rolled back on
                # its own (findings and cursor move together) and the
                # transaction stays usable for the other sources.
                async with db.begin_nested():
                    records = await source.fetch(
                        db, org_id, cursor.last_created_at, cursor.last_id, floor, limit
                    )
                    if not records:
                        break
                    window_created = await _evaluate_window(
                        db, org_id, key, source.label, source_plans, records, now
                    )
                    cursor.last_created_at = records[-1].created_at
                    cursor.last_id = records[-1].id
                    await db.flush()
                created += window_created
                scanned += len(records)
                if len(records) < limit:
                    break
        except Exception as exc:  # one source failing must not stop the others
            logger.error("dlp_scan_source_failed", organization_id=org_id, source=key, error=str(exc))
            error = f"{type(exc).__name__}: {str(exc)[:400]}"
            # The rolled-back savepoint expired what it touched; reload it
            # explicitly (no lazy IO under asyncio).
            await db.refresh(cursor)
            for plan in source_plans:
                await db.refresh(plan.policy)
        cursor.last_run_at = now
        cursor.last_run_rows = scanned
        cursor.last_run_findings = created
        cursor.rows_scanned_total = (cursor.rows_scanned_total or 0) + scanned
        cursor.findings_total = (cursor.findings_total or 0) + created
        cursor.last_error = error
        summary["sources"][key] = {"rows_scanned": scanned, "findings_created": created, "error": error}
        summary["rows_scanned"] += scanned
        summary["findings_created"] += created

    for plan in active:
        plan.policy.last_evaluated_at = now
        if plan.status == "degraded":
            plan.policy.evaluation_status = "degraded"
            plan.policy.evaluation_reason = plan.reason
    await db.flush()
    return summary


def _chunks(text: str) -> list[tuple[int, str]]:
    """``(offset, chunk)`` windows covering ``text`` with overlap, inside the hard cap."""
    body = text[:MAX_RECORD_CHARS]
    if len(body) <= MAX_TEXT_CHARS:
        return [(0, body)] if body else []
    out: list[tuple[int, str]] = []
    step = MAX_TEXT_CHARS - CHUNK_OVERLAP
    start = 0
    while start < len(body):
        out.append((start, body[start:start + MAX_TEXT_CHARS]))
        if start + MAX_TEXT_CHARS >= len(body):
            break
        start += step
    return out


async def _evaluate_window(
    db: AsyncSession,
    org_id: str,
    source_key: str,
    source_label: str,
    plans: list[PolicyPlan],
    records: list[_Record],
    now: datetime,
) -> int:
    ids = [r.id for r in records]
    existing = set(
        (
            await db.execute(
                select(DLPViolation.policy_id, DLPViolation.source_id).where(
                    DLPViolation.organization_id == org_id,
                    DLPViolation.source_type == source_key,
                    DLPViolation.source_id.in_(ids),
                )
            )
        ).all()
    )
    created = 0
    texts = {r.id: (r.text or "")[:MAX_RECORD_CHARS] for r in records}
    overflow = {r.id for r in records if len(r.text or "") > MAX_RECORD_CHARS}
    # Custom (tenant-authored) patterns run per policy in a killable child
    # process over the whole window; records it did not finish are recorded
    # as scan_incomplete findings rather than silently passed.
    custom_hits: dict[str, dict[str, list[tuple[str, int, int]]]] = {}
    unscanned: dict[str, set[str]] = {}
    state = _RUN_BUDGET.get()
    per_policy: dict[str, float] = state.setdefault("per_policy", {}) if state is not None else {}

    def _consumed(p: PolicyPlan) -> float:
        return POLICY_RUN_BUDGET_SECONDS - per_policy.get(p.policy.id, POLICY_RUN_BUDGET_SECONDS)

    # Cheapest policies first: a slow one cannot delay the others' window.
    for plan in sorted(plans, key=_consumed):
        custom = {name: p.pattern for name, p in plan.patterns.items() if name.startswith("custom:")}
        if not custom:
            continue
        todo = [
            (f"{rid}\x1f{offset}", chunk)
            for rid, text in texts.items() if text and (plan.policy.id, rid) not in existing
            for offset, chunk in _chunks(text)
        ]
        if not todo:
            continue
        if plan.policy.evaluation_status == "degraded":
            # Suspended custom matching is never silent: every record it would
            # have scanned is recorded as scan_incomplete for review.
            custom_hits[plan.policy.id] = {}
            unscanned[plan.policy.id] = {cid.split("\x1f", 1)[0] for cid, _ in todo}
            continue
        # Bound the text volume handed to the child per policy and window; the
        # records that do not fit are recorded as unscanned (fail closed).
        kept: list[tuple[str, str]] = []
        dropped: set[str] = set()
        total = 0
        for cid, chunk in todo:
            rid = cid.split("\x1f", 1)[0]
            if rid in dropped:
                continue
            if total + len(chunk) > MAX_WINDOW_CHARS_PER_POLICY:
                dropped.add(rid)
                continue
            kept.append((cid, chunk))
            total += len(chunk)
        kept = [(cid, chunk) for cid, chunk in kept if cid.split("\x1f", 1)[0] not in dropped]
        merged: dict[str, list[tuple[str, int, int]]] = {}
        unscanned_ids: set[str] = set(dropped)
        poison = 0
        pending = kept
        while pending:
            policy_remaining = per_policy.get(plan.policy.id, POLICY_RUN_BUDGET_SECONDS)
            org_remaining = state["remaining"] if state is not None else POLICY_WINDOW_BUDGET_SECONDS
            budget = min(POLICY_WINDOW_BUDGET_SECONDS, policy_remaining, org_remaining)
            if budget <= 0:
                unscanned_ids |= {cid.split("\x1f", 1)[0] for cid, _ in pending}
                break
            started = time.perf_counter()
            # The child-process call is synchronous: run it in a worker thread so
            # the event loop (and the other tenants' work) keeps moving.
            found, missing, timed_out = await asyncio.to_thread(match_custom_patterns, custom, pending, budget)
            spent = time.perf_counter() - started
            per_policy[plan.policy.id] = max(0.0, policy_remaining - spent)
            if state is not None:
                state["remaining"] = max(0.0, state["remaining"] - spent)
            for cid, chunk_hits in found.items():
                rid, offset = cid.split("\x1f", 1)
                base = int(offset)
                bucket = merged.setdefault(rid, [])
                for name, start, end in chunk_hits:
                    hit = (name, start + base, end + base)
                    if hit not in bucket:
                        bucket.append(hit)
            if not timed_out or not missing:
                break
            # The first unreported chunk belongs to the record that stalled the
            # child (the poison pill): flag that record alone and resume with the
            # records after it in a fresh child, charging this policy's budget.
            poison_rid = missing[0].split("\x1f", 1)[0]
            unscanned_ids.add(poison_rid)
            poison += 1
            done = {cid for cid in found}
            pending = [
                (cid, chunk) for cid, chunk in pending
                if cid not in done and cid.split("\x1f", 1)[0] != poison_rid
            ]
            if poison >= MAX_POISON_RECORDS_PER_RUN:
                unscanned_ids |= {cid.split("\x1f", 1)[0] for cid, _ in pending}
                plan.policy.evaluation_status = "degraded"
                plan.policy.evaluation_reason = (
                    f"custom patterns timed out on {poison} records in one run; custom matching is "
                    "suspended until the policy is edited (built-in detectors still run)"
                )
                plan.status = "degraded"
                plan.reason = plan.policy.evaluation_reason
                break
        custom_hits[plan.policy.id] = merged
        unscanned[plan.policy.id] = unscanned_ids
    for record in records:
        text = texts.get(record.id, "")
        if not text:
            continue
        for plan in plans:
            if (plan.policy.id, record.id) in existing:
                continue
            if record.id in unscanned.get(plan.policy.id, set()):
                db.add(DLPViolation(
                    organization_id=org_id,
                    policy_id=plan.policy.id,
                    violation_type="scan_incomplete",
                    severity=plan.policy.severity or "medium",
                    source_user=(record.user or None) and str(record.user)[:255],
                    source_application=source_label,
                    sensitive_data_types=json.dumps(["scan_timeout"]),
                    action_taken="scan_timeout",
                    status="new",
                    source_type=source_key,
                    source_id=record.id,
                    location=record.location[:2000],
                    redacted_excerpt=(
                        f"the policy's custom patterns did not finish within {POLICY_WINDOW_BUDGET_SECONDS:.0f}s "
                        f"on this {len(text)}-char record; it was NOT scanned. Simplify the pattern or review manually."
                    ),
                    detected_by="content_scan",
                ))
                existing.add((plan.policy.id, record.id))
                created += 1
                continue
            if record.id in overflow:
                db.add(DLPViolation(
                    organization_id=org_id,
                    policy_id=plan.policy.id,
                    violation_type="scan_incomplete",
                    severity=plan.policy.severity or "medium",
                    source_user=(record.user or None) and str(record.user)[:255],
                    source_application=source_label,
                    sensitive_data_types=json.dumps(["record_over_cap"]),
                    action_taken="scan_truncated",
                    status="new",
                    source_type=source_key,
                    source_id=f"{record.id}#overflow",
                    location=record.location[:2000],
                    redacted_excerpt=(
                        f"the record is longer than {MAX_RECORD_CHARS} characters; only the first "
                        f"{MAX_RECORD_CHARS} were scanned. Review the remainder manually."
                    ),
                    detected_by="content_scan",
                ))
                created += 1
            hits = _builtin_matches(plan, text)
            hits.extend(_filter_hits(plan, text, custom_hits.get(plan.policy.id, {}).get(record.id, [])))
            if not hits:
                continue
            hits.sort(key=lambda h: h[1])
            kinds = sorted({h[0] for h in hits})
            db.add(DLPViolation(
                organization_id=org_id,
                policy_id=plan.policy.id,
                violation_type=POLICY_TYPE_TO_VIOLATION.get(plan.policy.policy_type or "", "classification_violation"),
                severity=plan.policy.severity or "medium",
                source_user=(record.user or None) and str(record.user)[:255],
                source_application=source_label,
                sensitive_data_types=json.dumps(kinds),
                action_taken="logged",
                status="new",
                source_type=source_key,
                source_id=record.id,
                location=record.location[:2000],
                redacted_excerpt=redacted_excerpt(text, hits),
                detected_by="content_scan",
            ))
            existing.add((plan.policy.id, record.id))
            plan.policy.trigger_count = (plan.policy.trigger_count or 0) + 1
            plan.policy.last_triggered = now
            created += 1
    return created


async def reset_cursors(db: AsyncSession, org_id: str) -> int:
    """Rewind every source of the org to the initial lookback window."""
    rows = (
        await db.execute(select(DLPScanCursor).where(DLPScanCursor.organization_id == org_id))
    ).scalars().all()
    for row in rows:
        row.last_created_at = None
        row.last_id = None
    await db.flush()
    return len(rows)


async def scan_status(db: AsyncSession, org_id: str) -> dict[str, Any]:
    """Cursor state per source plus each policy's evaluation status."""
    plans = await load_plans(db, org_id, persist=False)
    cursors = {
        c.source_type: c
        for c in (
            await db.execute(select(DLPScanCursor).where(DLPScanCursor.organization_id == org_id))
        ).scalars().all()
    }
    sources = []
    for key, source in SOURCES.items():
        c = cursors.get(key)
        covering = [p.policy.id for p in plans if p.status == "active" and key in p.sources]
        sources.append({
            "source_type": key,
            "label": source.label,
            "policies_covering": len(covering),
            "last_run_at": c.last_run_at.isoformat() if c and c.last_run_at else None,
            "last_run_rows": c.last_run_rows if c else 0,
            "last_run_findings": c.last_run_findings if c else 0,
            "rows_scanned_total": c.rows_scanned_total if c else 0,
            "findings_total": c.findings_total if c else 0,
            "position": c.last_created_at.isoformat() if c and c.last_created_at else None,
            "last_error": c.last_error if c else None,
        })
    return {
        "organization_id": org_id,
        "window_rows": WINDOW_ROWS,
        "max_rows_per_source_per_run": MAX_ROWS_PER_SOURCE,
        "initial_lookback_days": INITIAL_LOOKBACK_DAYS,
        "sources": sources,
        "policies": [
            {"policy_id": p.policy.id, "name": p.policy.name, "evaluation_status": p.status,
             "evaluation_reason": p.reason, "sources": p.sources}
            for p in plans
        ],
    }
