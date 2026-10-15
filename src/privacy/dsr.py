"""Data subject request (DSR) workflow over the data PySOAR really holds.

A DSR names a subject by e-mail (and optionally an identifier such as a
username or IdP user id). ``SUBJECT_SOURCES`` lists every model in the
platform that holds personal data about people, how a subject is matched in
it, which fields an export contains (secrets such as password hashes, MFA
secrets and tracking tokens never leave), and what erasure does there:

* ``anonymise``: the row stays (other records reference it) but every field
  identifying the subject is replaced or cleared,
* ``redact``: free-text security records (alerts, incidents, logs) keep
  their content with the subject's e-mail / identifier replaced,
* ``delete``: the row is removed,
* ``retain``: kept under a stated legal obligation (consent proof, the DSR
  register itself) and reported as an exception.

Reads are bounded: an export holds at most ``EXPORT_CAP`` rows per source
(the count says when more exist) and erasure works through at most
``ERASE_CAP`` rows per source per run; when rows remain the request is left
``partially_complete`` with the remaining count, and re-running continues.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.csvsafe import csv_safe
from src.core.logging import get_logger
from src.privacy.models import DataSubjectRequest, DSRStatus

logger = get_logger(__name__)

EXPORT_CAP = 1_000
ERASE_CAP = 5_000
ERASED_TOKEN = "[erased-subject]"

# Allowed status transitions (PATCH and the workflow routes both use these).
TRANSITIONS: dict[str, set[str]] = {
    DSRStatus.RECEIVED.value: {DSRStatus.IDENTITY_VERIFIED.value, DSRStatus.DENIED.value},
    DSRStatus.IDENTITY_VERIFIED.value: {DSRStatus.PROCESSING.value, DSRStatus.DENIED.value},
    DSRStatus.PROCESSING.value: {
        DSRStatus.COMPLETED.value, DSRStatus.PARTIALLY_COMPLETE.value, DSRStatus.DENIED.value,
    },
    DSRStatus.PARTIALLY_COMPLETE.value: {DSRStatus.PROCESSING.value, DSRStatus.COMPLETED.value},
    DSRStatus.DENIED.value: {DSRStatus.APPEALED.value},
    DSRStatus.APPEALED.value: {DSRStatus.PROCESSING.value, DSRStatus.DENIED.value},
    DSRStatus.COMPLETED.value: set(),
}
OPEN_STATUSES = {
    DSRStatus.RECEIVED.value, DSRStatus.IDENTITY_VERIFIED.value, DSRStatus.PROCESSING.value,
    DSRStatus.PARTIALLY_COMPLETE.value, DSRStatus.APPEALED.value,
}
VERIFIED_STATUSES = {
    DSRStatus.IDENTITY_VERIFIED.value, DSRStatus.PROCESSING.value,
    DSRStatus.PARTIALLY_COMPLETE.value, DSRStatus.APPEALED.value,
}


class TransitionError(ValueError):
    """A status change the workflow does not allow."""


def check_transition(current: str, new: str) -> None:
    if new == current:
        return
    if new not in TRANSITIONS.get(current, set()):
        allowed = sorted(TRANSITIONS.get(current, set()))
        raise TransitionError(
            f"cannot move a DSR from {current!r} to {new!r}; allowed: {allowed or 'none (final)'}"
        )

# A DSR's needles are matched against free text (alert titles, descriptions,
# raw data, incident fields) and then redacted. A short or common identifier
# ("a", "admin", "1") would redact substrings across the tenant's records, so
# identifiers are validated when the request is created and again before any
# search or erasure, free-text matches are token-bounded, and an erasure that
# would touch more rows per source than ``ERASURE_MAX_ROWS_PER_SOURCE`` is
# refused unless an administrator explicitly forces it.
MIN_IDENTIFIER_LEN = 4
ERASURE_MAX_ROWS_PER_SOURCE = 200
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z0-9-]{2,}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+/\\-]{3,254}$")
_COMMON_TOKENS = frozenset({
    "admin", "administrator", "user", "users", "test", "root", "null", "none", "true", "false",
    "guest", "system", "service", "unknown", "anonymous", "default", "local", "localhost", "nobody",
})


class InvalidSubjectIdentifier(ValueError):
    """The subject e-mail or identifier is not safe to match against free text."""


class ErasureTooBroad(ValueError):
    """An erasure would touch more rows in a source than the configured limit."""

    def __init__(self, counts: dict[str, int], limit: int) -> None:
        super().__init__("erasure too broad")
        self.counts = counts
        self.limit = limit


def validate_subject_email(email: str) -> str:
    text = (email or "").strip().lower()
    if not _EMAIL_RE.fullmatch(text):
        raise InvalidSubjectIdentifier("subject_email must be a valid e-mail address")
    return text


def validate_subject_identifier(identifier: str | None) -> str | None:
    text = (identifier or "").strip()
    if not text:
        return None
    if len(text) < MIN_IDENTIFIER_LEN or not _IDENTIFIER_RE.fullmatch(text):
        raise InvalidSubjectIdentifier(
            f"subject_identifier must be at least {MIN_IDENTIFIER_LEN} characters of letters, digits and . _ @ + - /",
        )
    if text.isdigit() or text.lower() in _COMMON_TOKENS:
        raise InvalidSubjectIdentifier("subject_identifier is too generic to identify one person")
    return text


def _bounded(needle: str) -> re.Pattern[str]:
    """Match ``needle`` only where it is not glued to other identifier characters."""
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(needle) + r"(?![A-Za-z0-9])", re.IGNORECASE)


@dataclass
class Subject:
    email: str
    identifier: Optional[str]
    name: Optional[str]

    @property
    def needles(self) -> list[str]:
        out = [self.email]
        if self.identifier and self.identifier.lower() != self.email:
            out.append(self.identifier)
        return out


def subject_of(dsr: DataSubjectRequest) -> Subject:
    """Build the search subject; raises InvalidSubjectIdentifier for unsafe values."""
    return Subject(
        validate_subject_email(dsr.subject_email or ""),
        validate_subject_identifier(dsr.subject_identifier),
        dsr.subject_name,
    )


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _scrub(text: Optional[str], subject: Subject) -> Optional[str]:
    if not text:
        return text
    out = text
    for needle in subject.needles:
        out = _bounded(needle).sub(ERASED_TOKEN, out)
    return out


def _serialise(row: Any, fields: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for f in fields:
        v = getattr(row, f, None)
        if isinstance(v, datetime):
            v = v.isoformat()
        out[f] = v
    return out


def _erased_email(row_id: str) -> str:
    return f"erased-{str(row_id)[:12]}@erased.invalid"


@dataclass
class SubjectSource:
    key: str
    label: str
    erasure: str  # anonymise | redact | delete | retain
    fields: list[str]
    find: Callable[[AsyncSession, str, Subject, int], Awaitable[list[Any]]]
    count: Callable[[AsyncSession, str, Subject], Awaitable[int]]
    erase: Optional[Callable[[AsyncSession, Any, Subject], Awaitable[None]]] = None
    retain_reason: Optional[str] = None
    note: Optional[str] = None


def _lower_eq(col: Any, value: str) -> Any:
    return func.lower(col) == value.lower()


# ---------------------------------------------------------------------------
# Source definitions (lazy model imports keep this module import-light)
# ---------------------------------------------------------------------------
def _users_where(org_id: str, s: Subject):
    from src.models.user import User

    return [User.organization_id == org_id, _lower_eq(User.email, s.email)]


async def _users_find(db, org_id, s, limit):
    from src.models.user import User

    return list((await db.execute(select(User).where(*_users_where(org_id, s)).limit(limit))).scalars().all())


async def _users_count(db, org_id, s):
    from src.models.user import User

    return (await db.execute(select(func.count(User.id)).where(*_users_where(org_id, s)))).scalar() or 0


async def _users_erase(db, row, s):
    from src.core.security import get_password_hash

    row.email = _erased_email(row.id)
    row.full_name = None
    row.phone = None
    row.department = None
    row.avatar_url = None
    row.is_active = False
    row.mfa_secret = None
    row.mfa_backup_codes = None
    row.password_reset_token = None
    row.hashed_password = get_password_hash(secrets.token_urlsafe(32))


def _identity_where(org_id: str, s: Subject):
    from src.itdr.models import IdentityProfile as P

    conds = [_lower_eq(P.email, s.email)]
    if s.identifier:
        conds += [P.username == s.identifier, P.user_id == s.identifier]
    return [P.organization_id == org_id, or_(*conds)]


async def _identity_find(db, org_id, s, limit):
    from src.itdr.models import IdentityProfile as P

    return list((await db.execute(select(P).where(*_identity_where(org_id, s)).limit(limit))).scalars().all())


async def _identity_count(db, org_id, s):
    from src.itdr.models import IdentityProfile as P

    return (await db.execute(select(func.count(P.id)).where(*_identity_where(org_id, s)))).scalar() or 0


async def _identity_erase(db, row, s):
    row.email = _erased_email(row.id)
    row.username = f"erased-{str(row.id)[:12]}"
    row.user_id = f"erased-{str(row.id)[:12]}"
    row.display_name = None
    row.auth_baseline = None


async def _identity_ids(db, org_id, s) -> list[str]:
    from src.itdr.models import IdentityProfile as P

    return list((await db.execute(select(P.id).where(*_identity_where(org_id, s)).limit(ERASE_CAP))).scalars().all())


async def _exposure_find(db, org_id, s, limit):
    from src.itdr.models import CredentialExposure as C

    ids = await _identity_ids(db, org_id, s)
    if not ids:
        return []
    stmt = select(C).where(C.organization_id == org_id, C.identity_id.in_(ids)).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


async def _exposure_count(db, org_id, s):
    from src.itdr.models import CredentialExposure as C

    ids = await _identity_ids(db, org_id, s)
    if not ids:
        return 0
    stmt = select(func.count(C.id)).where(C.organization_id == org_id, C.identity_id.in_(ids))
    return (await db.execute(stmt)).scalar() or 0


async def _delete(db, row, s):
    await db.delete(row)


def _alerts_where(org_id: str, s: Subject):
    from src.models.alert import Alert as A

    conds = []
    for needle in s.needles:
        conds += [
            _lower_eq(A.username, needle),
            A.title.ilike(_like(needle), escape="\\"),
            A.description.ilike(_like(needle), escape="\\"),
            A.raw_data.ilike(_like(needle), escape="\\"),
        ]
    return [A.organization_id == org_id, or_(*conds)]


async def _alerts_find(db, org_id, s, limit):
    from src.models.alert import Alert as A

    stmt = select(A).where(*_alerts_where(org_id, s)).order_by(A.created_at).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


async def _alerts_count(db, org_id, s):
    from src.models.alert import Alert as A

    return (await db.execute(select(func.count(A.id)).where(*_alerts_where(org_id, s)))).scalar() or 0


async def _alerts_erase(db, row, s):
    row.title = _scrub(row.title, s) or row.title
    row.description = _scrub(row.description, s)
    row.raw_data = _scrub(row.raw_data, s)
    if row.username and row.username.lower() in {n.lower() for n in s.needles}:
        row.username = ERASED_TOKEN


def _incidents_where(org_id: str, s: Subject):
    from src.models.incident import Incident as I

    conds = []
    for needle in s.needles:
        conds += [
            I.title.ilike(_like(needle), escape="\\"),
            I.description.ilike(_like(needle), escape="\\"),
            I.affected_users.ilike(_like(needle), escape="\\"),
        ]
    return [I.organization_id == org_id, or_(*conds)]


async def _incidents_find(db, org_id, s, limit):
    from src.models.incident import Incident as I

    stmt = select(I).where(*_incidents_where(org_id, s)).order_by(I.created_at).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


async def _incidents_count(db, org_id, s):
    from src.models.incident import Incident as I

    return (await db.execute(select(func.count(I.id)).where(*_incidents_where(org_id, s)))).scalar() or 0


async def _incidents_erase(db, row, s):
    row.title = _scrub(row.title, s) or row.title
    row.description = _scrub(row.description, s)
    row.affected_users = _scrub(row.affected_users, s)


def _logs_where(org_id: str, s: Subject):
    from src.siem.models import LogEntry as L

    return [L.organization_id == org_id, or_(*[_lower_eq(L.username, n) for n in s.needles])]


async def _logs_find(db, org_id, s, limit):
    from src.siem.models import LogEntry as L

    stmt = select(L).where(*_logs_where(org_id, s)).order_by(L.created_at).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


async def _logs_count(db, org_id, s):
    from src.siem.models import LogEntry as L

    return (await db.execute(select(func.count(L.id)).where(*_logs_where(org_id, s)))).scalar() or 0


async def _logs_erase(db, row, s):
    row.username = ERASED_TOKEN
    row.message = _scrub(row.message, s)
    row.raw_log = _scrub(row.raw_log, s) or ""
    row.parsed_fields = _scrub(row.parsed_fields, s)
    row.normalized_fields = _scrub(row.normalized_fields, s)


def _targets_where(org_id: str, s: Subject):
    from src.phishing_sim.models import PhishingTarget as T

    return [T.organization_id == org_id, _lower_eq(T.recipient_email, s.email)]


async def _targets_find(db, org_id, s, limit):
    from src.phishing_sim.models import PhishingTarget as T

    return list((await db.execute(select(T).where(*_targets_where(org_id, s)).limit(limit))).scalars().all())


async def _targets_count(db, org_id, s):
    from src.phishing_sim.models import PhishingTarget as T

    return (await db.execute(select(func.count(T.id)).where(*_targets_where(org_id, s)))).scalar() or 0


async def _targets_erase(db, row, s):
    row.recipient_email = _erased_email(row.id)
    row.recipient_name = None
    row.recipient_department = None
    row.tracking_token = None


def _events_where(org_id: str, s: Subject):
    from src.phishing_sim.models import CampaignEvent as E

    return [E.organization_id == org_id, _lower_eq(E.target_email, s.email)]


async def _events_find(db, org_id, s, limit):
    from src.phishing_sim.models import CampaignEvent as E

    return list((await db.execute(select(E).where(*_events_where(org_id, s)).limit(limit))).scalars().all())


async def _events_count(db, org_id, s):
    from src.phishing_sim.models import CampaignEvent as E

    return (await db.execute(select(func.count(E.id)).where(*_events_where(org_id, s)))).scalar() or 0


async def _events_erase(db, row, s):
    row.target_email = _erased_email(row.id)
    row.target_name = None
    row.ip_address = None
    row.user_agent = None
    row.geo_location = None


async def _groups_matching(db, org_id, s, limit):
    """Target groups whose ``members`` JSON lists the subject (groups are
    read in a bounded window; membership is filtered in Python)."""
    from src.phishing_sim.models import TargetGroup as G

    groups = (await db.execute(select(G).where(G.organization_id == org_id).limit(ERASE_CAP))).scalars().all()
    out = []
    for g in groups:
        if any(
            isinstance(m, dict) and str(m.get("email", "")).strip().lower() == s.email
            for m in (g.members or [])
        ):
            out.append(g)
            if len(out) >= limit:
                break
    return out


async def _groups_count(db, org_id, s):
    return len(await _groups_matching(db, org_id, s, ERASE_CAP))


async def _groups_erase(db, row, s):
    kept = [
        m for m in (row.members or [])
        if not (isinstance(m, dict) and str(m.get("email", "")).strip().lower() == s.email)
    ]
    row.members = kept
    row.member_count = len(kept)


def _scores_where(org_id: str, s: Subject):
    from src.phishing_sim.models import SecurityAwarenessScore as S

    return [S.organization_id == org_id, _lower_eq(S.user_email, s.email)]


async def _scores_find(db, org_id, s, limit):
    from src.phishing_sim.models import SecurityAwarenessScore as S

    return list((await db.execute(select(S).where(*_scores_where(org_id, s)).limit(limit))).scalars().all())


async def _scores_count(db, org_id, s):
    from src.phishing_sim.models import SecurityAwarenessScore as S

    return (await db.execute(select(func.count(S.id)).where(*_scores_where(org_id, s)))).scalar() or 0


def _leaks_where(org_id: str, s: Subject):
    from src.darkweb.models import CredentialLeak as L

    conds = [_lower_eq(L.email, s.email)]
    if s.identifier:
        conds.append(L.username == s.identifier)
    return [L.organization_id == org_id, or_(*conds)]


async def _leaks_find(db, org_id, s, limit):
    from src.darkweb.models import CredentialLeak as L

    return list((await db.execute(select(L).where(*_leaks_where(org_id, s)).limit(limit))).scalars().all())


async def _leaks_count(db, org_id, s):
    from src.darkweb.models import CredentialLeak as L

    return (await db.execute(select(func.count(L.id)).where(*_leaks_where(org_id, s)))).scalar() or 0


def _consent_where(org_id: str, s: Subject):
    from src.privacy.models import ConsentRecord as C

    return [C.organization_id == org_id, or_(*[_lower_eq(C.subject_id, n) for n in s.needles])]


async def _consent_find(db, org_id, s, limit):
    from src.privacy.models import ConsentRecord as C

    return list((await db.execute(select(C).where(*_consent_where(org_id, s)).limit(limit))).scalars().all())


async def _consent_count(db, org_id, s):
    from src.privacy.models import ConsentRecord as C

    return (await db.execute(select(func.count(C.id)).where(*_consent_where(org_id, s)))).scalar() or 0


def _dsr_where(org_id: str, s: Subject):
    return [DataSubjectRequest.organization_id == org_id, _lower_eq(DataSubjectRequest.subject_email, s.email)]


async def _dsr_find(db, org_id, s, limit):
    stmt = select(DataSubjectRequest).where(*_dsr_where(org_id, s)).limit(limit)
    return list((await db.execute(stmt)).scalars().all())


async def _dsr_count(db, org_id, s):
    return (await db.execute(select(func.count(DataSubjectRequest.id)).where(*_dsr_where(org_id, s)))).scalar() or 0


SUBJECT_SOURCES: list[SubjectSource] = [
    SubjectSource(
        "users", "Platform user accounts", "anonymise",
        ["id", "email", "full_name", "role", "phone", "department", "is_active", "last_login", "created_at"],
        _users_find, _users_count, _users_erase,
        note="the account is deactivated and its identifying fields replaced; records it authored keep the user id",
    ),
    SubjectSource(
        "identities", "ITDR identity profiles", "anonymise",
        ["id", "user_id", "username", "email", "display_name", "identity_provider", "privilege_level",
         "mfa_enabled", "last_authentication", "last_password_change", "account_status", "source", "created_at"],
        _identity_find, _identity_count, _identity_erase,
        note="a directory sync re-creates the profile unless the subject is also removed in the identity provider",
    ),
    SubjectSource(
        "credential_exposures", "ITDR credential exposures", "delete",
        ["id", "identity_id", "exposure_source", "credential_type", "exposure_date", "discovery_date",
         "breach_name", "is_remediated", "remediation_date"],
        _exposure_find, _exposure_count, _delete,
    ),
    SubjectSource(
        "alerts", "Alerts mentioning the subject", "redact",
        ["id", "title", "description", "severity", "status", "source", "username", "hostname", "created_at"],
        _alerts_find, _alerts_count, _alerts_erase,
    ),
    SubjectSource(
        "incidents", "Incidents mentioning the subject", "redact",
        ["id", "title", "description", "severity", "status", "affected_users", "created_at"],
        _incidents_find, _incidents_count, _incidents_erase,
    ),
    SubjectSource(
        "log_entries", "SIEM log entries for the subject's username", "redact",
        ["id", "timestamp", "source_name", "log_type", "username", "hostname", "source_address",
         "action", "outcome", "message"],
        _logs_find, _logs_count, _logs_erase,
    ),
    SubjectSource(
        "phishing_targets", "Phishing simulation targets", "anonymise",
        ["id", "campaign_id", "recipient_email", "recipient_name", "recipient_department", "status", "sent_at"],
        _targets_find, _targets_count, _targets_erase,
    ),
    SubjectSource(
        "phishing_events", "Phishing simulation events", "anonymise",
        ["id", "campaign_id", "target_email", "target_name", "event_type", "event_timestamp", "ip_address",
         "user_agent", "device_type"],
        _events_find, _events_count, _events_erase,
    ),
    SubjectSource(
        "phishing_target_groups", "Phishing target-group membership", "anonymise",
        ["id", "name", "department"],
        _groups_matching, _groups_count, _groups_erase,
        note="the subject's member entry is removed from the group",
    ),
    SubjectSource(
        "awareness_scores", "Security awareness scores", "delete",
        ["id", "user_email", "user_name", "department", "overall_score", "phishing_score",
         "training_completion_rate", "campaigns_participated", "times_clicked", "times_reported",
         "times_submitted_credentials", "risk_category", "created_at"],
        _scores_find, _scores_count, _delete,
    ),
    SubjectSource(
        "darkweb_credential_leaks", "Dark-web credential leaks", "delete",
        ["id", "email", "username", "password_type", "breach_source", "breach_date", "is_valid",
         "is_remediated", "created_at"],
        _leaks_find, _leaks_count, _delete,
    ),
    SubjectSource(
        "consent_records", "Consent records", "retain",
        ["id", "subject_id", "purpose", "legal_basis", "consent_given", "consent_date", "withdrawal_date",
         "consent_mechanism", "evidence_location", "version"],
        _consent_find, _consent_count,
        retain_reason="legal obligation: proof of consent and of its withdrawal (GDPR Art. 7(1))",
    ),
    SubjectSource(
        "data_subject_requests", "Data subject requests", "retain",
        ["id", "request_type", "regulation", "status", "deadline", "created_at", "completed_at"],
        _dsr_find, _dsr_count,
        retain_reason="legal obligation: the DSR register evidences how the request was handled (GDPR Art. 5(2))",
    ),
]
SOURCE_KEYS = [s.key for s in SUBJECT_SOURCES]


def _sources(only: Optional[list[str]]) -> list[SubjectSource]:
    if not only:
        return SUBJECT_SOURCES
    unknown = sorted(set(only) - set(SOURCE_KEYS))
    if unknown:
        raise ValueError(f"unknown data source(s) {unknown}; known: {SOURCE_KEYS}")
    return [s for s in SUBJECT_SOURCES if s.key in only]


async def search_subject(
    db: AsyncSession, org_id: str, dsr: DataSubjectRequest, only: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Count the subject's rows in every source and record the result."""
    subject = subject_of(dsr)
    results: dict[str, Any] = {}
    for src in _sources(only):
        results[src.key] = {"label": src.label, "records": int(await src.count(db, org_id, subject)),
                            "erasure": src.erasure}
    now = datetime.now(timezone.utc)
    dsr.data_systems_searched = json.dumps([k for k, v in results.items() if v["records"] > 0])
    dsr.data_found = json.dumps({"searched_at": now.isoformat(), "sources": results})
    dsr.searched_at = now
    return {"searched_at": now.isoformat(), "sources": results,
            "total_records": sum(v["records"] for v in results.values())}


async def build_export(db: AsyncSession, org_id: str, dsr: DataSubjectRequest) -> dict[str, Any]:
    """The subject's rows from every source (bounded per source)."""
    subject = subject_of(dsr)
    sources: dict[str, Any] = {}
    total = 0
    for src in SUBJECT_SOURCES:
        if src.key == "data_subject_requests":
            rows = [r for r in await src.find(db, org_id, subject, EXPORT_CAP + 1) if r.id != dsr.id]
        else:
            rows = await src.find(db, org_id, subject, EXPORT_CAP + 1)
        truncated = len(rows) > EXPORT_CAP
        rows = rows[:EXPORT_CAP]
        if not rows:
            continue
        records = [_serialise(r, src.fields) for r in rows]
        total += len(records)
        sources[src.key] = {
            "label": src.label,
            "record_count": len(records),
            "truncated": truncated,
            "total_matching": int(await src.count(db, org_id, subject)) if truncated else len(records),
            "records": records,
        }
    return {
        "request_id": dsr.id,
        "request_type": dsr.request_type,
        "regulation": dsr.regulation,
        "subject": {"name": dsr.subject_name, "email": dsr.subject_email,
                    "identifier": dsr.subject_identifier},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources_searched": SOURCE_KEYS,
        "record_count": total,
        "sources": sources,
    }


def package_digest(package: dict[str, Any]) -> str:
    canonical = json.dumps(package, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def package_to_csv(package: dict[str, Any]) -> str:
    """One row per (source, record, field): formula-safe cells."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["source", "record_id", "field", "value"])
    for key, block in package["sources"].items():
        for record in block["records"]:
            rid = record.get("id")
            for field_name, value in record.items():
                if field_name == "id":
                    continue
                cell = json.dumps(value, default=str) if isinstance(value, (dict, list)) else value
                writer.writerow([csv_safe(key), csv_safe(rid), csv_safe(field_name), csv_safe(cell)])
    return buf.getvalue()


async def preflight_erasure(
    db: AsyncSession, org_id: str, dsr: DataSubjectRequest, *, force: bool = False,
) -> dict[str, int]:
    """Count what an erasure would touch per source; refuse an over-broad run.

    Raises ErasureTooBroad when any erasable source matches more than
    ``ERASURE_MAX_ROWS_PER_SOURCE`` rows and ``force`` is not set.
    """
    subject = subject_of(dsr)
    counts: dict[str, int] = {}
    for src in SUBJECT_SOURCES:
        if src.erasure == "retained":
            continue
        counts[src.key] = int(await src.count(db, org_id, subject))
    too_many = {k: v for k, v in counts.items() if v > ERASURE_MAX_ROWS_PER_SOURCE}
    if too_many and not force:
        raise ErasureTooBroad(too_many, ERASURE_MAX_ROWS_PER_SOURCE)
    return counts


async def execute_erasure(
    db: AsyncSession, org_id: str, dsr: DataSubjectRequest,
) -> dict[str, Any]:
    """Erase / anonymise / redact the subject's rows (bounded per source).

    Returns the per-source log; the caller writes the audit rows and
    commits. ``remaining`` > 0 on any source means another run is needed.
    """
    subject = subject_of(dsr)
    log: dict[str, Any] = {}
    remaining_total = 0
    for src in SUBJECT_SOURCES:
        if src.erasure == "retain":
            count = int(await src.count(db, org_id, subject))
            if src.key == "data_subject_requests":
                count = max(0, count - 1)
            log[src.key] = {"action": "retained", "records": count, "reason": src.retain_reason}
            continue
        rows = await src.find(db, org_id, subject, ERASE_CAP)
        for row in rows:
            await src.erase(db, row, subject)
        await db.flush()
        # Redacted / anonymised rows no longer match; deleted rows are gone:
        # anything still matching was beyond this run's cap.
        remaining = int(await src.count(db, org_id, subject))
        remaining_total += remaining
        entry: dict[str, Any] = {"action": src.erasure, "records": len(rows), "remaining": remaining}
        if src.note:
            entry["note"] = src.note
        log[src.key] = entry
    now = datetime.now(timezone.utc)
    return {
        "executed_at": now.isoformat(),
        "sources": log,
        "records_processed": sum(v["records"] for v in log.values() if v["action"] != "retained"),
        "records_retained": sum(v["records"] for v in log.values() if v["action"] == "retained"),
        "remaining": remaining_total,
    }


def deadline_state(dsr: DataSubjectRequest, now: Optional[datetime] = None) -> dict[str, Any]:
    """Days remaining / overdue against the stored deadline."""
    now = now or datetime.now(timezone.utc)
    if not dsr.deadline:
        return {"days_remaining": None, "overdue": False}
    try:
        deadline = datetime.fromisoformat(str(dsr.deadline).replace("Z", "+00:00"))
    except ValueError:
        return {"days_remaining": None, "overdue": False}
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    end = dsr.completed_at or now
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    delta = deadline - end
    days = delta.days
    return {"days_remaining": days, "overdue": delta.total_seconds() < 0}
