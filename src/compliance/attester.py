"""Control auto-attester (wave 4: asserts only what it checks).

Each rule inspects something the platform can actually read for the
organisation (row counts, configuration values, evidence rows, the result
of an integrity test) and returns one of three outcomes:

* ``pass``: the check ran and the stored state meets the rule's test;
* ``fail``: the check ran and the stored state does not meet it;
* ``not_assessed``: nothing the platform can read decides the control (a
  procedural control, an infrastructure setting outside the application,
  or no data yet). The reason is recorded.

Every outcome carries its ``basis``: the list of facts the rule read, each
``{"kind": "count" | "config" | "evidence" | "test", "source", "value"}``.

Status written to ``compliance_controls`` (only when the status was not set
by a person, ``status_source != "manual"``):

* ``pass`` with at least one approved, valid, unexpired, non-automated
  evidence row for the control -> ``implemented`` / ``satisfied``;
* ``pass`` without such evidence -> ``partially_implemented`` / ``satisfied``
  (the technical check passed; the procedural part has no approved evidence);
* ``fail`` -> ``not_implemented`` / ``other_than_satisfied``;
* ``not_assessed`` -> ``not_assessed`` / ``not_assessed``.

The previous attester returned ``implemented`` for 22 controls with no check
at all and for 7 more whatever their counts were, overwrote human-set status,
and inserted a new ``is_valid=True`` evidence row on every run. None of that
remains: the attester keeps one automated evidence row per control (updated
in place, valid only when the check passed) and a manual status is never
overwritten (its automated result is still recorded in ``assessment_basis``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import ComplianceControl, ComplianceEvidence
from src.core.logging import get_logger

logger = get_logger(__name__)

#: ``source_system`` of the one automated evidence row kept per control.
ATTESTER_SOURCE = "pysoar:auto-attester"

PASS = "pass"
FAIL = "fail"
NOT_ASSESSED = "not_assessed"

#: Thresholds the rules test against (FedRAMP Moderate parameter values
#: where the baseline defines one).
AC7_MAX_ATTEMPTS = 3              # AC-7: 3 consecutive invalid attempts
AC7_MIN_LOCKOUT_SECONDS = 30 * 60  # AC-7: account locked 30 minutes
AC2_DORMANT_DAYS = 90             # AC-2(3): disable after 90 days inactivity
AC12_MAX_SESSION_MINUTES = 60      # access-token lifetime that ends a session
AU11_RETENTION_DAYS = 365         # AU-11: 12 months online
RECENT_DAYS = 30
CM6_MIN_COMPLIANCE = 90.0
MAX_USERS_INSPECTED = 5_000
MAX_AGENT_CHAINS_VERIFIED = 50


@dataclass
class CheckOutcome:
    result: str
    summary: str
    basis: list[dict[str, Any]] = field(default_factory=list)
    reason: Optional[str] = None


def _fact(kind: str, source: str, value: Any) -> dict[str, Any]:
    return {"kind": kind, "source": source, "value": value}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _parse_ts(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return _aware(value)
    if not value:
        return None
    try:
        return _aware(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        return None


async def _count(db: AsyncSession, stmt: Any) -> int:
    return int((await db.scalar(stmt)) or 0)


def _not_assessed(reason: str, basis: Optional[list[dict[str, Any]]] = None) -> CheckOutcome:
    return CheckOutcome(NOT_ASSESSED, reason, basis or [], reason)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


async def _ac2_account_management(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.user import User

    rows = (await db.execute(
        select(User.id, User.is_active, User.last_login, User.created_at)
        .where(User.organization_id == org_id)
        .limit(MAX_USERS_INSPECTED)
    )).all()
    active = [r for r in rows if r.is_active]
    cutoff = _now() - timedelta(days=AC2_DORMANT_DAYS)
    dormant = 0
    for r in active:
        last = _parse_ts(r.last_login) or _aware(r.created_at)
        if last is not None and last < cutoff:
            dormant += 1
    basis = [
        _fact("count", "users.is_active", len(active)),
        _fact("count", "users (disabled)", len(rows) - len(active)),
        _fact("count", f"active users without a login in {AC2_DORMANT_DAYS} days", dormant),
    ]
    if not active:
        return _not_assessed("no active user accounts in this organisation", basis)
    if dormant:
        return CheckOutcome(
            FAIL, f"{dormant} of {len(active)} active accounts have been dormant for more than "
            f"{AC2_DORMANT_DAYS} days and are still enabled", basis,
            f"{dormant} dormant active account(s)",
        )
    return CheckOutcome(PASS, f"{len(active)} active accounts, none dormant for more than {AC2_DORMANT_DAYS} days", basis)


async def _ac6_least_privilege(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.user import User

    rows = (await db.execute(
        select(User.role, func.count(User.id))
        .where(User.organization_id == org_id, User.is_active.is_(True))
        .group_by(User.role)
    )).all()
    by_role = {str(role): int(n) for role, n in rows}
    return _not_assessed(
        "least privilege needs a reviewed access list; the role counts are recorded for the reviewer",
        [_fact("count", "active users by role", by_role)],
    )


async def _ac7_unsuccessful_logon(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.core.account_lockout import AccountLockoutManager

    attempts = int(AccountLockoutManager.DEFAULT_MAX_ATTEMPTS)
    duration = int(AccountLockoutManager.DEFAULT_LOCKOUT_DURATION)
    basis = [
        _fact("config", "src.core.account_lockout.AccountLockoutManager.DEFAULT_MAX_ATTEMPTS (used by POST /auth/login)", attempts),
        _fact("config", "src.core.account_lockout.AccountLockoutManager.DEFAULT_LOCKOUT_DURATION seconds", duration),
    ]
    problems = []
    if attempts > AC7_MAX_ATTEMPTS:
        problems.append(f"lockout after {attempts} attempts (parameter: {AC7_MAX_ATTEMPTS})")
    if duration < AC7_MIN_LOCKOUT_SECONDS:
        problems.append(f"lockout lasts {duration // 60} minutes (parameter: {AC7_MIN_LOCKOUT_SECONDS // 60})")
    if problems:
        return CheckOutcome(FAIL, "login lockout is enforced but " + "; ".join(problems), basis, "; ".join(problems))
    return CheckOutcome(PASS, f"login lockout after {attempts} failed attempts for {duration // 60} minutes", basis)


async def _ac12_session_termination(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.services.tenant_settings import session_timeout_minutes_for

    minutes = await session_timeout_minutes_for(db, org_id)
    basis = [_fact("config", "access-token lifetime minutes (tenant security/general settings or platform default)", minutes)]
    if minutes > AC12_MAX_SESSION_MINUTES:
        return CheckOutcome(
            FAIL, f"sessions last {minutes} minutes before the token expires (test: <= {AC12_MAX_SESSION_MINUTES})",
            basis, f"session lifetime {minutes} minutes",
        )
    return CheckOutcome(PASS, f"sessions end when the access token expires after {minutes} minutes", basis)


async def _ia2_mfa(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.user import User

    active = await _count(db, select(func.count(User.id)).where(
        User.organization_id == org_id, User.is_active.is_(True)))
    enrolled = await _count(db, select(func.count(User.id)).where(
        User.organization_id == org_id, User.is_active.is_(True), User.mfa_enabled.is_(True)))
    basis = [_fact("count", "active users", active), _fact("count", "active users with MFA enabled", enrolled)]
    if not active:
        return _not_assessed("no active user accounts in this organisation", basis)
    if enrolled < active:
        return CheckOutcome(
            FAIL, f"{active - enrolled} of {active} active users authenticate without MFA", basis,
            f"{active - enrolled} active user(s) without MFA",
        )
    return CheckOutcome(PASS, f"all {active} active users have MFA enabled", basis)


async def _audit_event_count(db: AsyncSession, org_id: str, days: int) -> int:
    from src.models.audit import AuditLog

    return await _count(db, select(func.count(AuditLog.id)).where(
        AuditLog.organization_id == org_id, AuditLog.created_at >= _now() - timedelta(days=days)))


async def _au2_event_logging(db: AsyncSession, org_id: str) -> CheckOutcome:
    recent = await _audit_event_count(db, org_id, RECENT_DAYS)
    basis = [_fact("count", f"audit_logs rows in the last {RECENT_DAYS} days", recent)]
    if recent == 0:
        return CheckOutcome(FAIL, f"no audit events were recorded in the last {RECENT_DAYS} days", basis,
                            "no audit events recorded")
    return CheckOutcome(PASS, f"{recent} audit events recorded in the last {RECENT_DAYS} days", basis)


async def _au3_record_content(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.audit import AuditLog

    rows = (await db.execute(
        select(AuditLog.action, AuditLog.resource_type, AuditLog.created_at, AuditLog.user_id,
               AuditLog.ip_address, AuditLog.success)
        .where(AuditLog.organization_id == org_id)
        .order_by(AuditLog.created_at.desc()).limit(200)
    )).all()
    if not rows:
        return _not_assessed("no audit records exist for this organisation yet",
                             [_fact("count", "audit_logs rows sampled", 0)])
    incomplete = sum(
        1 for r in rows
        if not (r.action and r.resource_type and r.created_at and (r.user_id or r.ip_address) and r.success is not None)
    )
    basis = [
        _fact("count", "audit_logs rows sampled (latest 200)", len(rows)),
        _fact("count", "sampled rows missing what/when/where/who/outcome", incomplete),
    ]
    if incomplete:
        return CheckOutcome(FAIL, f"{incomplete} of {len(rows)} sampled audit records lack required content",
                            basis, f"{incomplete} incomplete audit record(s)")
    return CheckOutcome(PASS, f"all {len(rows)} sampled audit records carry event type, time, resource, subject and outcome", basis)


async def _au9_protection(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.audit_evidence.engine import AuditLogger

    verdict = await AuditLogger(db, org_id).verify_chain()
    basis = [_fact("test", "audit_trails hash-chain verification", verdict)]
    if not verdict.get("total"):
        return _not_assessed("the audit trail has no rows to verify yet", basis)
    if not verdict.get("ok"):
        return CheckOutcome(FAIL, f"audit trail hash chain broken ({verdict.get('reason')})", basis,
                            str(verdict.get("reason")))
    return CheckOutcome(PASS, f"audit trail hash chain verified over {verdict.get('checked')} rows", basis)


async def _au10_non_repudiation(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.agents.models import EndpointAgent
    from src.agents.service import AgentService

    agents = list(await db.scalars(
        select(EndpointAgent).where(EndpointAgent.organization_id == org_id)
        .order_by(EndpointAgent.id).limit(MAX_AGENT_CHAINS_VERIFIED)
    ))
    service = AgentService(db)
    broken: list[str] = []
    verified = 0
    for agent in agents:
        verdict = await service.verify_chain(agent)
        verified += int(verdict.get("commands_verified") or 0)
        if not verdict.get("valid"):
            broken.append(agent.id)
    basis = [
        _fact("count", "endpoint agents whose command chain was verified", len(agents)),
        _fact("count", "agent commands verified", verified),
        _fact("test", "agents with a broken command chain", broken),
    ]
    if not agents:
        return _not_assessed("no endpoint agents are enrolled, so no signed command history exists to verify", basis)
    if broken:
        return CheckOutcome(FAIL, f"{len(broken)} agent command chain(s) failed verification", basis,
                            "agent command chain broken")
    return CheckOutcome(PASS, f"command hash chains verified for {len(agents)} agents ({verified} commands)", basis)


async def _au11_retention(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.audit import AuditLog

    oldest = _aware(await db.scalar(select(func.min(AuditLog.created_at)).where(AuditLog.organization_id == org_id)))
    if oldest is None:
        return _not_assessed("no audit records exist for this organisation yet",
                             [_fact("count", "audit_logs rows", 0)])
    age = (_now() - oldest).days
    basis = [_fact("count", "age in days of the oldest audit_logs row", age)]
    if age >= AU11_RETENTION_DAYS:
        return CheckOutcome(PASS, f"audit records are held for at least {age} days", basis)
    return _not_assessed(
        f"the oldest audit record is {age} days old; {AU11_RETENTION_DAYS}-day retention cannot be shown yet", basis)


async def _au12_record_generation(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.audit import AuditLog

    actions = (await db.execute(
        select(AuditLog.action).where(
            AuditLog.organization_id == org_id, AuditLog.created_at >= _now() - timedelta(days=RECENT_DAYS))
        .distinct().limit(100)
    )).scalars().all()
    basis = [_fact("count", f"distinct audit_logs actions in the last {RECENT_DAYS} days", len(actions))]
    if not actions:
        return CheckOutcome(FAIL, f"no audit records were generated in the last {RECENT_DAYS} days", basis,
                            "no audit records generated")
    return CheckOutcome(PASS, f"audit records generated for {len(actions)} distinct actions in {RECENT_DAYS} days", basis)


async def _ca7_continuous_monitoring(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.compliance.models import ComplianceAssessment

    last = _aware(await db.scalar(
        select(func.max(ComplianceAssessment.assessment_date)).where(
            ComplianceAssessment.organization_id == org_id,
            ComplianceAssessment.assessment_type == "conmon",
        )
    ))
    basis = [_fact("evidence", "latest persisted ConMon cycle (compliance_assessments, type conmon)",
                   last.isoformat() if last else None)]
    if last is None:
        return CheckOutcome(FAIL, "no continuous-monitoring cycle has been recorded", basis, "no ConMon cycle recorded")
    if last < _now() - timedelta(days=31):
        return CheckOutcome(FAIL, f"the last ConMon cycle ran {(_now() - last).days} days ago", basis,
                            "ConMon cycle older than 31 days")
    return CheckOutcome(PASS, f"a ConMon cycle ran on {last.date().isoformat()}", basis)


async def _cm6_configuration_settings(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.stig.models import STIGScanResult

    since = _now() - timedelta(days=RECENT_DAYS)
    row = (await db.execute(
        select(
            func.count(STIGScanResult.id),
            func.coalesce(func.sum(STIGScanResult.cat1_open), 0),
            func.coalesce(func.avg(STIGScanResult.compliance_percentage), 0.0),
        ).where(
            STIGScanResult.organization_id == org_id,
            STIGScanResult.status == "completed",
            STIGScanResult.completed_at >= since,
        )
    )).one()
    scans, cat1, avg = int(row[0] or 0), int(row[1] or 0), float(row[2] or 0.0)
    basis = [
        _fact("count", f"completed STIG scans in the last {RECENT_DAYS} days", scans),
        _fact("count", "open CAT I findings in those scans", cat1),
        _fact("count", "average compliance percentage of those scans", round(avg, 1)),
    ]
    if scans == 0:
        return _not_assessed(f"no STIG scan has completed in the last {RECENT_DAYS} days", basis)
    if cat1 or avg < CM6_MIN_COMPLIANCE:
        reason = f"{cat1} open CAT I finding(s); average compliance {avg:.1f}%"
        return CheckOutcome(FAIL, reason, basis, reason)
    return CheckOutcome(PASS, f"{scans} STIG scans, no open CAT I, average compliance {avg:.1f}%", basis)


async def _cm8_component_inventory(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.agents.models import EndpointAgent
    from src.models.asset import Asset

    assets = await _count(db, select(func.count(Asset.id)).where(Asset.organization_id == org_id))
    inventoried = select(Asset.hostname).where(Asset.organization_id == org_id, Asset.hostname.isnot(None))
    unmatched = await _count(db, select(func.count(EndpointAgent.id)).where(
        EndpointAgent.organization_id == org_id,
        EndpointAgent.status == "active",
        EndpointAgent.hostname.notin_(inventoried),
    ))
    basis = [
        _fact("count", "assets", assets),
        _fact("count", "active endpoint agents whose hostname is not in the asset inventory", unmatched),
    ]
    if assets == 0:
        return CheckOutcome(FAIL, "the asset inventory is empty", basis, "no assets inventoried")
    if unmatched:
        return CheckOutcome(FAIL, f"{unmatched} enrolled host(s) are missing from the asset inventory", basis,
                            "inventory incomplete")
    return CheckOutcome(PASS, f"{assets} assets inventoried; every active agent host is in the inventory", basis)


async def _ir4_incident_handling(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.incident import Incident

    since = _now() - timedelta(days=365)
    total = await _count(db, select(func.count(Incident.id)).where(
        Incident.organization_id == org_id, Incident.created_at >= since))
    closed = await _count(db, select(func.count(Incident.id)).where(
        Incident.organization_id == org_id, Incident.created_at >= since, Incident.status == "closed"))
    stale = await _count(db, select(func.count(Incident.id)).where(
        Incident.organization_id == org_id, Incident.status != "closed",
        Incident.created_at < _now() - timedelta(days=RECENT_DAYS)))
    basis = [
        _fact("count", "incidents opened in the last 365 days", total),
        _fact("count", "of which closed", closed),
        _fact("count", f"incidents still open after {RECENT_DAYS} days", stale),
    ]
    if total == 0:
        return _not_assessed("no incidents in the last 365 days, so incident handling has not been exercised", basis)
    if stale:
        return CheckOutcome(FAIL, f"{stale} incident(s) open for more than {RECENT_DAYS} days", basis,
                            "incidents left open")
    if closed == 0:
        return CheckOutcome(FAIL, "no incident has been handled to closure", basis, "no incident closed")
    return CheckOutcome(PASS, f"{closed} of {total} incidents handled to closure; none stale", basis)


async def _ir5_incident_monitoring(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.incident import Incident

    total = await _count(db, select(func.count(Incident.id)).where(
        Incident.organization_id == org_id, Incident.created_at >= _now() - timedelta(days=365)))
    basis = [_fact("count", "incidents tracked in the last 365 days", total)]
    if total == 0:
        return _not_assessed("no incidents tracked in the last 365 days", basis)
    return CheckOutcome(PASS, f"{total} incidents tracked with status history in the incidents table", basis)


async def _ir8_response_plan(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.models.playbook import Playbook

    enabled = await _count(db, select(func.count(Playbook.id)).where(
        Playbook.organization_id == org_id, Playbook.is_enabled.is_(True)))
    basis = [_fact("count", "enabled playbooks", enabled)]
    if enabled == 0:
        return CheckOutcome(FAIL, "no enabled incident-response playbooks", basis, "no playbooks")
    return CheckOutcome(PASS, f"{enabled} enabled response playbooks encode the plan's procedures", basis)


async def _ra5_vulnerability_scanning(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.vulnmgmt.models import VulnerabilityInstance

    recent = await _count(db, select(func.count(VulnerabilityInstance.id)).where(
        VulnerabilityInstance.organization_id == org_id,
        VulnerabilityInstance.updated_at >= _now() - timedelta(days=RECENT_DAYS)))
    basis = [_fact("count", f"vulnerability instances created or updated by a scan import in {RECENT_DAYS} days", recent)]
    if recent == 0:
        return CheckOutcome(FAIL, f"no vulnerability scan results were imported in the last {RECENT_DAYS} days",
                            basis, "no recent scan results")
    return CheckOutcome(PASS, f"{recent} vulnerability findings refreshed by scans in {RECENT_DAYS} days", basis)


async def _sc7_boundary_protection(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.zerotrust.models import MicroSegment, ZeroTrustPolicy

    segments = await _count(db, select(func.count(MicroSegment.id)).where(MicroSegment.organization_id == org_id))
    policies = await _count(db, select(func.count(ZeroTrustPolicy.id)).where(ZeroTrustPolicy.organization_id == org_id))
    basis = [_fact("count", "micro_segments", segments), _fact("count", "zero_trust_policies", policies)]
    if segments == 0 and policies == 0:
        return CheckOutcome(FAIL, "no segments or zero-trust policies are defined", basis, "no boundary policy")
    return CheckOutcome(PASS, f"{segments} segments and {policies} zero-trust policies defined", basis)


async def _encryption_at_rest(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.core.config import settings

    configured = bool(getattr(settings, "encryption_master_key", None))
    basis = [_fact("config", "ENCRYPTION_MASTER_KEY set (field-level AES-256-GCM for stored secrets)", configured)]
    if not configured:
        return CheckOutcome(FAIL, "no encryption master key is configured; stored secrets are not encrypted",
                            basis, "encryption key not configured")
    return CheckOutcome(PASS, "field-level encryption is configured for stored secrets", basis)


async def _si2_flaw_remediation(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.vulnmgmt.models import VulnerabilityInstance

    total = await _count(db, select(func.count(VulnerabilityInstance.id)).where(
        VulnerabilityInstance.organization_id == org_id))
    breached = await _count(db, select(func.count(VulnerabilityInstance.id)).where(
        VulnerabilityInstance.organization_id == org_id, VulnerabilityInstance.sla_status == "breached"))
    basis = [_fact("count", "vulnerability instances", total),
             _fact("count", "instances past their remediation SLA", breached)]
    if total == 0:
        return _not_assessed("no vulnerability findings are stored, so remediation timeliness cannot be measured", basis)
    if breached:
        return CheckOutcome(FAIL, f"{breached} vulnerability finding(s) are past their remediation deadline", basis,
                            f"{breached} SLA breach(es)")
    return CheckOutcome(PASS, f"none of {total} vulnerability findings is past its remediation deadline", basis)


async def _si4_system_monitoring(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.siem.models import DetectionRule, LogEntry

    logs = await _count(db, select(func.count(LogEntry.id)).where(
        LogEntry.organization_id == org_id, LogEntry.created_at >= _now() - timedelta(hours=24)))
    rules = await _count(db, select(func.count(DetectionRule.id)).where(
        DetectionRule.organization_id == org_id, DetectionRule.status == "active"))
    basis = [_fact("count", "log entries ingested in the last 24 hours", logs),
             _fact("count", "active detection rules", rules)]
    problems = []
    if logs == 0:
        problems.append("no logs ingested in 24 hours")
    if rules == 0:
        problems.append("no active detection rules")
    if problems:
        return CheckOutcome(FAIL, "; ".join(problems), basis, "; ".join(problems))
    return CheckOutcome(PASS, f"{logs} log entries in 24 hours evaluated by {rules} active detection rules", basis)


async def _si5_security_alerts(db: AsyncSession, org_id: str) -> CheckOutcome:
    from src.intel.models import ThreatFeed

    feeds = await _count(db, select(func.count(ThreatFeed.id)).where(
        ThreatFeed.organization_id == org_id, ThreatFeed.is_enabled.is_(True)))
    basis = [_fact("count", "enabled threat-intelligence / advisory feeds", feeds)]
    if feeds == 0:
        return CheckOutcome(FAIL, "no advisory or threat-intelligence feed is enabled", basis, "no feeds")
    return CheckOutcome(PASS, f"{feeds} advisory / threat-intelligence feeds enabled", basis)


async def _pl2_security_plan(db: AsyncSession, org_id: str) -> CheckOutcome:
    return _not_assessed(
        "a system security plan is a document: the control is implemented once an approved SSP is attached as evidence")


def _procedural(reason: str) -> Callable[[AsyncSession, str], Awaitable[CheckOutcome]]:
    async def _rule(db: AsyncSession, org_id: str) -> CheckOutcome:
        return _not_assessed(reason)
    return _rule


_RULES: dict[str, Callable[[AsyncSession, str], Awaitable[CheckOutcome]]] = {
    "AC-2": _ac2_account_management,
    "AC-3": _procedural("access enforcement is code behaviour; it needs a test record (e.g. an access-control test report) as evidence"),
    "AC-6": _ac6_least_privilege,
    "AC-7": _ac7_unsuccessful_logon,
    "AC-12": _ac12_session_termination,
    "AU-2": _au2_event_logging,
    "AU-3": _au3_record_content,
    "AU-4": _procedural("audit storage capacity is a host / database setting the application cannot read"),
    "AU-6": _procedural("audit review is a human activity; it needs review records as evidence"),
    "AU-8": _procedural("clock synchronisation (NTP) is a host setting the application cannot read"),
    "AU-9": _au9_protection,
    "AU-10": _au10_non_repudiation,
    "AU-11": _au11_retention,
    "AU-12": _au12_record_generation,
    "CA-7": _ca7_continuous_monitoring,
    "CM-3": _procedural("change control is a process; it needs change records as evidence"),
    "CM-6": _cm6_configuration_settings,
    "CM-7": _procedural("least functionality of hosts and images is not readable by the application"),
    "CM-8": _cm8_component_inventory,
    "CP-9": _procedural("backups run outside the application; it needs backup and restore-test records as evidence"),
    "IA-2": _ia2_mfa,
    "IA-5": _procedural("the password-policy settings are not enforced by a code path the attester can read"),
    "IR-4": _ir4_incident_handling,
    "IR-5": _ir5_incident_monitoring,
    "IR-6": _procedural("incident reporting to external parties needs reporting records as evidence"),
    "IR-7": _procedural("incident response assistance is an organisational service; it needs evidence"),
    "IR-8": _ir8_response_plan,
    "PL-2": _pl2_security_plan,
    "RA-5": _ra5_vulnerability_scanning,
    "SC-5": _procedural("denial-of-service protection sits at the network edge, outside the application"),
    "SC-7": _sc7_boundary_protection,
    "SC-8": _procedural("transport encryption is terminated by the reverse proxy, which the application cannot inspect"),
    "SC-12": _procedural("key establishment and rotation are operational procedures; they need key-management records"),
    "SC-13": _encryption_at_rest,
    "SC-28": _encryption_at_rest,
    "SI-2": _si2_flaw_remediation,
    "SI-3": _procedural("malicious-code protection runs on hosts; the application cannot read its state"),
    "SI-4": _si4_system_monitoring,
    "SI-5": _si5_security_alerts,
    "SI-7": _procedural("software integrity verification of deployed images is not readable by the application"),
}

#: Control codes the attester has a rule for (public for the routers).
SUPPORTED_CONTROLS = tuple(sorted(_RULES))


async def run_check(db: AsyncSession, org_id: str, control_code: str) -> Optional[CheckOutcome]:
    """Run the rule for ``control_code``; None when the attester has none."""
    rule = _RULES.get(control_code)
    if rule is None:
        return None
    return await rule(db, org_id)


def outcome_dict(code: str, outcome: CheckOutcome, checked_at: datetime) -> dict[str, Any]:
    return {
        "control": code,
        "result": outcome.result,
        "summary": outcome.summary,
        "reason": outcome.reason,
        "basis": outcome.basis,
        "checked_at": checked_at.isoformat(),
        "checked_by": ATTESTER_SOURCE,
    }


class ControlAutoAttester:
    """Run the rules for one organisation's controls and record the outcomes."""

    def __init__(self, db: AsyncSession, organization_id: str):
        self.db = db
        self.org_id = organization_id

    async def _approved_evidence(self, control_ids: list[str]) -> set[str]:
        if not control_ids:
            return set()
        now = _now()
        rows = (await self.db.execute(
            select(ComplianceEvidence.control_id_ref).where(
                ComplianceEvidence.organization_id == self.org_id,
                ComplianceEvidence.control_id_ref.in_(control_ids),
                ComplianceEvidence.review_status == "approved",
                ComplianceEvidence.is_valid.is_(True),
                ComplianceEvidence.is_automated.is_(False),
                or_(ComplianceEvidence.expires_at.is_(None), ComplianceEvidence.expires_at > now),
            ).distinct()
        )).scalars().all()
        return set(rows)

    async def _upsert_evidence(self, control: ComplianceControl, record: dict[str, Any]) -> None:
        content = json.dumps(record, sort_keys=True, default=str)
        row = (await self.db.execute(
            select(ComplianceEvidence).where(
                ComplianceEvidence.organization_id == self.org_id,
                ComplianceEvidence.control_id_ref == control.id,
                ComplianceEvidence.source_system == ATTESTER_SOURCE,
            ).limit(1)
        )).scalar_one_or_none()
        if row is None:
            row = ComplianceEvidence(
                control_id_ref=control.id,
                organization_id=self.org_id,
                evidence_type="automated_test",
                title=f"Automated check: {control.control_id}",
                source_system=ATTESTER_SOURCE,
                collected_by="system:auto-attester",
                is_automated=True,
            )
            self.db.add(row)
        row.description = record["summary"][:2000]
        row.content = content
        row.file_hash = hashlib.sha512(content.encode("utf-8")).hexdigest()
        row.collected_at = _now()
        row.is_valid = record["result"] == PASS
        row.review_status = "pending"

    async def attest_all(self, framework_id: Optional[str] = None) -> dict[str, Any]:
        """Run every rule that matches one of the organisation's controls."""
        stmt = select(ComplianceControl).where(
            ComplianceControl.organization_id == self.org_id,
            ComplianceControl.control_id.in_(list(_RULES)),
        )
        if framework_id:
            stmt = stmt.where(ComplianceControl.framework_id == framework_id)
        controls = list(await self.db.scalars(stmt))
        if not controls:
            return {
                "attested": 0, "status": "no_controls", "framework_id": framework_id,
                "passed": 0, "failed": 0, "not_assessed": 0, "implemented": 0,
                "partially_implemented": 0, "manual_status_kept": 0, "controls": [],
            }

        approved = await self._approved_evidence([c.id for c in controls])
        checked_at = _now()
        outcomes: dict[str, CheckOutcome] = {}
        tally = {PASS: 0, FAIL: 0, NOT_ASSESSED: 0}
        implemented = partial = kept = 0
        per_control: list[dict[str, Any]] = []
        for control in controls:
            code = control.control_id
            if code not in outcomes:
                try:
                    outcomes[code] = await _RULES[code](self.db, self.org_id)
                except Exception as exc:  # noqa: BLE001 - a broken rule is recorded, not hidden
                    logger.warning("attester_rule_failed", control=code, error=str(exc))
                    outcomes[code] = _not_assessed(f"the check could not run: {type(exc).__name__}")
            outcome = outcomes[code]
            tally[outcome.result] += 1
            record = outcome_dict(code, outcome, checked_at)
            has_evidence = control.id in approved
            record["approved_evidence"] = has_evidence

            control.assessment_basis = record
            control.last_assessed_at = checked_at.replace(tzinfo=None)
            control.last_assessment_result = {
                PASS: "satisfied", FAIL: "other_than_satisfied",
            }.get(outcome.result, "not_assessed")
            if control.status_source == "manual":
                kept += 1
            else:
                if outcome.result == PASS and has_evidence:
                    control.status, control.implementation_status = "implemented", 100.0
                    implemented += 1
                elif outcome.result == PASS:
                    control.status, control.implementation_status = "partially_implemented", 50.0
                    partial += 1
                elif outcome.result == FAIL:
                    control.status, control.implementation_status = "not_implemented", 0.0
                else:
                    control.status, control.implementation_status = "not_assessed", 0.0
                control.status_source = "attester"
            await self._upsert_evidence(control, record)
            per_control.append({
                "control_id": code, "control_record_id": control.id, "framework_id": control.framework_id,
                "result": outcome.result, "status": control.status, "reason": outcome.reason,
            })

        await self.db.flush()
        from src.compliance.engine import refresh_framework_score

        framework_ids = {c.framework_id for c in controls}
        for fw_id in framework_ids:
            await refresh_framework_score(self.db, self.org_id, fw_id)
        await self.db.commit()
        return {
            "attested": len(controls),
            "framework_id": framework_id,
            "passed": tally[PASS],
            "failed": tally[FAIL],
            "not_assessed": tally[NOT_ASSESSED],
            "implemented": implemented,
            "partially_implemented": partial,
            "manual_status_kept": kept,
            "checked_at": checked_at.isoformat(),
            "controls": per_control,
        }

