"""
Audit & Evidence Collection Engine

Core engine for audit logging, evidence collection, packaging,
continuous monitoring, and audit readiness checking.
"""

import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, ClassVar, Optional
from collections import defaultdict

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from src.core.logging import get_logger
from src.core.config import settings
from src.audit_evidence.models import (
    AUDIT_GENESIS_HASH,
    AuditTrail,
    AutomatedEvidenceRule,
    EvidencePackage,
    audit_row_hash,
)
from src.models.base import generate_uuid, utc_now

logger = get_logger(__name__)

# Maximum serialized size of ``old_value`` / ``new_value`` persisted on an
# audit row (design v2 §7: "capped 2 KB with [truncated] + args_sha256").
AUDIT_VALUE_CAP_BYTES = 2048

#: Evidence older than this (or past its expiry) is stale for ConMon and the
#: readiness freshness check (FedRAMP annual assessment cycle).
EVIDENCE_FRESH_DAYS = 365


class AuditWriteError(RuntimeError):
    """Raised when an audit row cannot be written; callers must fail closed."""


def _canonical_value_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def cap_audit_value(value: Optional[dict[str, Any]], limit: int = AUDIT_VALUE_CAP_BYTES) -> Optional[dict[str, Any]]:
    """Return the JSON-safe value to persist for an audit ``old_value``/``new_value``.

    Values that serialize to ``limit`` bytes or fewer are stored verbatim
    (after a JSON round-trip so non-JSON types such as datetimes become
    strings and what is hashed equals what is stored). Larger values are
    replaced by a marker dict carrying a truncated preview, the sha256 of
    the full canonical serialization and the original byte length, so the
    audit row stays bounded but the full payload remains verifiable.
    """
    if value is None:
        return None
    canonical = _canonical_value_json(value)
    encoded = canonical.encode("utf-8")
    if len(encoded) <= limit:
        return json.loads(canonical)
    preview = encoded[:limit].decode("utf-8", errors="ignore")
    return {
        "[truncated]": True,
        "preview": preview,
        "args_sha256": hashlib.sha256(encoded).hexdigest(),
        "original_bytes": len(encoded),
    }


class AuditLogger:
    """
    Audit Logger

    Comprehensive audit logging for system events with support for
    different event types, risk assessment, and activity anomaly detection.

    ``log_event`` only ever ``flush()``es: the caller owns the transaction
    and commits once per unit of work (an API request, or one agent step
    after audit + execution). It never commits or rolls back the shared
    session. Every row is chained to its predecessor for the organization
    via ``prev_hash``/``row_hash`` (see ``audit_row_hash``).
    """

    def __init__(self, session: AsyncSession, org_id: str):
        """Initialize audit logger"""
        if not org_id:
            raise ValueError("AuditLogger requires an organization id")
        self.session = session
        self.org_id = org_id

    async def _chain_head(self) -> Optional[str]:
        """``row_hash`` of the newest chained row for this organization."""
        result = await self.session.execute(
            select(AuditTrail.row_hash)
            .where(
                AuditTrail.organization_id == self.org_id,
                AuditTrail.row_hash.is_not(None),
            )
            .order_by(AuditTrail.created_at.desc(), AuditTrail.id.desc())
            .limit(1),
        )
        return result.scalar_one_or_none()

    async def log_event(
        self,
        event_type: str,
        action: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        description: str,
        old_value: Optional[dict[str, Any]] = None,
        new_value: Optional[dict[str, Any]] = None,
        result: str = "success",
        risk_level: str = "info",
        actor_ip: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> AuditTrail:
        """
        Log audit event

        Args:
            event_type: Type of event (access, change, admin, policy, etc.)
            action: Specific action (e.g., user.login, policy.update)
            actor_type: Type of actor (user, system, api, service)
            actor_id: ID of actor
            resource_type: Type of resource being acted upon
            resource_id: ID of resource
            description: Event description
            old_value: Previous value (for changes); capped at 2 KB
            new_value: New value (for changes); capped at 2 KB
            result: Result of action (success, failure, denied)
            risk_level: Risk level (critical, high, medium, low, info)
            actor_ip: IP address of actor (optional)
            session_id: Session identifier (optional)
            request_id: Request identifier (optional)
            run_id: Agent run identifier (optional); also used as
                ``request_id`` when that is not given

        Returns:
            The flushed (NOT committed) AuditTrail row. The caller commits.

        Raises:
            AuditWriteError: the row could not be flushed. The session is
                left in whatever state SQLAlchemy put it in; the caller must
                roll back and must not proceed with the audited action.
        """
        try:
            prev_hash = await self._chain_head() or AUDIT_GENESIS_HASH
            audit_trail = AuditTrail(
                id=generate_uuid(),
                created_at=utc_now(),
                event_type=event_type,
                action=action,
                actor_type=actor_type,
                actor_id=actor_id,
                actor_ip=actor_ip,
                resource_type=resource_type,
                resource_id=resource_id,
                description=description,
                old_value=cap_audit_value(old_value),
                new_value=cap_audit_value(new_value),
                result=result,
                risk_level=risk_level,
                session_id=session_id,
                request_id=request_id or run_id,
                run_id=run_id,
                organization_id=self.org_id,
                prev_hash=prev_hash,
            )
            audit_trail.row_hash = audit_row_hash(audit_trail.chain_fields(), prev_hash)

            self.session.add(audit_trail)
            await self.session.flush()
        except Exception as exc:  # noqa: BLE001 - re-raised as the typed error
            logger.error(
                "audit_event_write_failed",
                event_type=event_type,
                action=action,
                organization_id=self.org_id,
                error=str(exc),
            )
            raise AuditWriteError(f"audit write failed for {event_type}/{action}: {exc}") from exc

        logger.info(
            "audit_event_logged",
            event_type=event_type,
            action=action,
            result=result,
            actor=actor_id,
            resource=resource_id,
            risk_level=risk_level,
            run_id=run_id,
        )
        return audit_trail

    async def verify_chain(self, organization_id: Optional[str] = None) -> dict[str, Any]:
        """Walk the hash chain for one organization and report the first break.

        Returns ``{"ok": bool, "first_bad_row": str | None, "checked": int,
        "total": int, "reason": str | None}``. A row is "bad" when its
        recomputed hash differs from the stored ``row_hash`` (tampered
        fields), when the chain forks or has no successor although rows
        remain (deleted/inserted rows), or when a row has no hashes at all.
        ``organization_id`` defaults to this logger's org and is refused
        when it differs, so a caller cannot verify another tenant's chain.
        """
        org_id = organization_id or self.org_id
        if org_id != self.org_id:
            raise PermissionError("verify_chain is scoped to the logger's organization")

        rows = list(
            await self.session.scalars(
                select(AuditTrail)
                .where(AuditTrail.organization_id == org_id)
                .order_by(AuditTrail.created_at.asc(), AuditTrail.id.asc()),
            ),
        )
        total = len(rows)
        if total == 0:
            return {"ok": True, "first_bad_row": None, "checked": 0, "total": 0, "reason": None}

        by_prev: dict[str, list[AuditTrail]] = defaultdict(list)
        for row in rows:
            if row.row_hash is None or row.prev_hash is None:
                return {
                    "ok": False,
                    "first_bad_row": row.id,
                    "checked": 0,
                    "total": total,
                    "reason": "row_unhashed",
                }
            by_prev[row.prev_hash].append(row)

        checked = 0
        expected_prev = AUDIT_GENESIS_HASH
        while True:
            candidates = by_prev.get(expected_prev, [])
            if not candidates:
                break
            if len(candidates) > 1:
                return {
                    "ok": False,
                    "first_bad_row": sorted(c.id for c in candidates)[0],
                    "checked": checked,
                    "total": total,
                    "reason": "chain_fork",
                }
            row = candidates[0]
            recomputed = audit_row_hash(row.chain_fields(), row.prev_hash)
            if recomputed != row.row_hash:
                return {
                    "ok": False,
                    "first_bad_row": row.id,
                    "checked": checked,
                    "total": total,
                    "reason": "row_hash_mismatch",
                }
            checked += 1
            expected_prev = row.row_hash

        if checked != total:
            reached: set[str] = set()
            expected_prev = AUDIT_GENESIS_HASH
            while expected_prev in by_prev:
                row = by_prev[expected_prev][0]
                reached.add(row.id)
                expected_prev = row.row_hash or ""
            orphan = next(r for r in rows if r.id not in reached)
            return {
                "ok": False,
                "first_bad_row": orphan.id,
                "checked": checked,
                "total": total,
                "reason": "chain_broken",
            }
        return {"ok": True, "first_bad_row": None, "checked": checked, "total": total, "reason": None}

    async def log_access(
        self,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        result: str = "success",
        actor_ip: Optional[str] = None,
    ) -> AuditTrail:
        """Log access event"""
        return await self.log_event(
            event_type="access",
            action=f"{resource_type}.access",
            actor_type="user",
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            description=f"Accessed {resource_type} {resource_id}",
            result=result,
            risk_level="info",
            actor_ip=actor_ip,
        )

    async def log_change(
        self,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        old_value: dict[str, Any],
        new_value: dict[str, Any],
    ) -> AuditTrail:
        """Log change event"""
        return await self.log_event(
            event_type="change",
            action=f"{resource_type}.modify",
            actor_type="user",
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            description=f"Modified {resource_type} {resource_id}",
            old_value=old_value,
            new_value=new_value,
            result="success",
            risk_level="medium",
        )

    async def search_audit_trail(
        self,
        filters: dict[str, Any],
        offset: int = 0,
        limit: Optional[int] = None,
    ) -> list[AuditTrail]:
        """
        Search audit trail with filters

        Args:
            filters: Search filters (event_type, actor_id, resource_type, date_range, etc.)

        Returns:
            Matching audit trail entries
        """
        query = select(AuditTrail).where(AuditTrail.organization_id == self.org_id)

        if "event_type" in filters:
            query = query.where(AuditTrail.event_type == filters["event_type"])

        if "actor_id" in filters:
            query = query.where(AuditTrail.actor_id == filters["actor_id"])

        if "resource_type" in filters:
            query = query.where(
                AuditTrail.resource_type == filters["resource_type"],
            )

        if "result" in filters:
            query = query.where(AuditTrail.result == filters["result"])

        if "risk_level" in filters:
            query = query.where(AuditTrail.risk_level == filters["risk_level"])

        if "date_from" in filters:
            query = query.where(AuditTrail.created_at >= filters["date_from"])

        if "date_to" in filters:
            query = query.where(AuditTrail.created_at <= filters["date_to"])

        query = query.order_by(AuditTrail.created_at.desc()).offset(offset)
        if limit is not None:
            query = query.limit(limit)
        results = await self.session.scalars(query)
        return list(results)

    async def generate_audit_report(
        self, date_range: tuple[datetime, datetime], event_types: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Generate audit report for date range

        Args:
            date_range: (start_date, end_date)
            event_types: Optional filter by event types

        Returns:
            Audit report with statistics
        """
        query = select(AuditTrail).where(
            (AuditTrail.organization_id == self.org_id)
            & (AuditTrail.created_at >= date_range[0])
            & (AuditTrail.created_at <= date_range[1]),
        )

        if event_types:
            query = query.where(AuditTrail.event_type.in_(event_types))

        entries = await self.session.scalars(query)
        entry_list = list(entries)

        # Aggregate statistics
        stats = {
            "total_events": len(entry_list),
            "by_event_type": defaultdict(int),
            "by_actor": defaultdict(int),
            "by_result": defaultdict(int),
            "by_risk_level": defaultdict(int),
            "failures": 0,
            "critical_events": 0,
        }

        for entry in entry_list:
            stats["by_event_type"][entry.event_type] += 1
            stats["by_actor"][entry.actor_id] += 1
            stats["by_result"][entry.result] += 1
            stats["by_risk_level"][entry.risk_level] += 1

            if entry.result == "failure":
                stats["failures"] += 1
            if entry.risk_level == "critical":
                stats["critical_events"] += 1

        return {
            "date_range": {
                "start": date_range[0].isoformat(),
                "end": date_range[1].isoformat(),
            },
            "statistics": dict(stats),
            "total_entries": len(entry_list),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def detect_suspicious_activity(self, actor_id: str) -> list[dict[str, Any]]:
        """
        Detect suspicious activity for actor

        Args:
            actor_id: Actor ID to analyze

        Returns:
            List of suspicious activities
        """
        # Look for multiple failures, rapid access patterns, etc.
        query = select(AuditTrail).where(
            (AuditTrail.actor_id == actor_id)
            & (AuditTrail.organization_id == self.org_id)
            & (AuditTrail.created_at >= datetime.now(timezone.utc) - timedelta(hours=24)),
        )

        entries = await self.session.scalars(query)
        entry_list = list(entries)

        suspicious = []

        # Count failures
        failures = len([e for e in entry_list if e.result == "failure"])
        if failures >= 5:
            suspicious.append({
                "type": "multiple_failures",
                "count": failures,
                "description": f"{failures} failed attempts in 24 hours",
                "severity": "high",
            })

        # Count access events
        access_events = len([e for e in entry_list if e.event_type == "access"])
        if access_events > 100:
            suspicious.append({
                "type": "unusual_access_frequency",
                "count": access_events,
                "description": f"{access_events} access events in 24 hours",
                "severity": "medium",
            })

        return suspicious


class EvidenceCollector:
    """
    Evidence Collector

    Collects evidence from various sources (APIs, logs, configs, scans, metrics)
    and packages evidence for compliance audits and assessments.
    """

    def __init__(self, session: AsyncSession, org_id: str):
        """Initialize evidence collector"""
        self.session = session
        self.org_id = org_id

    #: ``config_check`` may snapshot only these tenant settings sections, and
    #: values whose key looks like a secret are redacted.
    CONFIG_SECTIONS = ("security", "general", "notifications")
    SECRET_KEY_MARKERS = ("password", "secret", "token", "key", "webhook", "credential")
    METRICS = ("active_users", "mfa_enabled_users", "open_incidents", "open_alerts", "open_poams")

    @staticmethod
    def _rule_control_codes(rule: AutomatedEvidenceRule) -> list[str]:
        raw = rule.control_ids or {}
        if isinstance(raw, dict):
            listed = raw.get("controls") or raw.get("control_ids")
            codes = listed if isinstance(listed, list) else list(raw.keys())
        elif isinstance(raw, list):
            codes = raw
        else:
            codes = []
        return [str(c).strip() for c in codes if str(c).strip()]

    async def collect_evidence(self, rule_id: str) -> dict[str, Any]:
        """
        Run one automated evidence rule and store what it collected.

        Every collector reads this organisation's stored rows or settings and
        the result is written as one ``compliance_evidence`` row per control
        the rule maps to (content JSON, SHA-512 hash, ``is_automated``,
        review pending). ``api_query`` rules need an external integration the
        platform does not call yet and return ``awaiting_integration`` without
        writing evidence (they used to report success around a stub).

        Raises:
            LookupError: the rule is not in this organisation.
        """
        from src.compliance.models import ComplianceControl, ComplianceEvidence

        rule = await self.session.scalar(
            select(AutomatedEvidenceRule).where(
                AutomatedEvidenceRule.id == rule_id,
                AutomatedEvidenceRule.organization_id == self.org_id,
            ),
        )
        if not rule:
            raise LookupError(f"Rule {rule_id} not found")

        collectors = {
            "log_query": self._collect_from_logs,
            "config_check": self._collect_from_config,
            "scan_result": self._collect_from_scan,
            "metric_snapshot": self._collect_metric,
        }
        now = datetime.now(timezone.utc)
        base = {"rule_id": rule.id, "rule_name": rule.name, "collection_method": rule.collection_method}
        collector = collectors.get(rule.collection_method)
        if collector is None:
            reason = (
                "api_query evidence needs an external API integration, which the evidence collector does not call"
                if rule.collection_method == "api_query"
                else f"unknown collection method {rule.collection_method!r}"
            )
            return {**base, "status": "awaiting_integration", "reason": reason, "evidence_written": 0}

        try:
            data = await collector(rule.collection_config or {})
        except ValueError as exc:
            return {**base, "status": "failed", "reason": str(exc), "evidence_written": 0}

        codes = self._rule_control_codes(rule)
        controls = []
        if codes:
            controls = list(await self.session.scalars(
                select(ComplianceControl).where(
                    ComplianceControl.organization_id == self.org_id,
                    ComplianceControl.control_id.in_(codes),
                ),
            ))
        content = json.dumps({**base, "collected_at": now.isoformat(), "data": data}, sort_keys=True, default=str)
        digest = self._calculate_hash(content)
        evidence_ids: list[str] = []
        for control in controls:
            row = ComplianceEvidence(
                control_id_ref=control.id,
                organization_id=self.org_id,
                evidence_type=rule.evidence_type or "automated_test",
                title=f"{rule.name} ({now.date().isoformat()})",
                description=f"Collected by automated evidence rule {rule.name} ({rule.collection_method})",
                content=content,
                file_hash=digest,
                source_system=f"pysoar:evidence-rule:{rule.id}",
                collected_at=now,
                collected_by="system:evidence-rule",
                is_automated=True,
                is_valid=True,
                review_status="pending",
            )
            self.session.add(row)
            await self.session.flush()
            evidence_ids.append(row.id)

        rule.last_collected_at = now
        await self.session.commit()
        logger.info("evidence_rule_collected", rule_id=rule.id, evidence_written=len(evidence_ids))
        return {
            **base,
            "status": "collected" if evidence_ids else "no_matching_controls",
            "reason": None if evidence_ids else (
                "the rule maps to no control of this organisation; nothing was stored"),
            "evidence_written": len(evidence_ids),
            "evidence_ids": evidence_ids,
            "content_sha512": digest,
            "data": data,
        }

    async def collect_all_automated(self, family: Optional[str] = None) -> dict[str, Any]:
        """Run every enabled rule (optionally only rules mapping to a control family code)."""
        rules = list(await self.session.scalars(
            select(AutomatedEvidenceRule).where(
                AutomatedEvidenceRule.organization_id == self.org_id,
                AutomatedEvidenceRule.is_enabled.is_(True),
            ).order_by(AutomatedEvidenceRule.id).limit(500),
        ))
        prefix = (family or "").strip().upper()
        results: dict[str, Any] = {}
        for rule in rules:
            if prefix and not any(c.upper().startswith(prefix + "-") for c in self._rule_control_codes(rule)):
                continue
            try:
                results[rule.id] = await self.collect_evidence(rule.id)
            except LookupError as exc:
                results[rule.id] = {"status": "failed", "reason": str(exc), "evidence_written": 0}
        return results

    async def add_evidence_to_package(self, package_id: str, evidence_ids: list[str]) -> dict[str, Any]:
        """Attach evidence rows of this organisation to a package (by id)."""
        from src.compliance.models import ComplianceControl, ComplianceEvidence

        package = await self.session.scalar(select(EvidencePackage).where(
            EvidencePackage.id == package_id, EvidencePackage.organization_id == self.org_id))
        if not package:
            raise LookupError(f"Package {package_id} not found")
        rows = (await self.session.execute(
            select(ComplianceEvidence, ComplianceControl.control_id)
            .outerjoin(ComplianceControl, ComplianceControl.id == ComplianceEvidence.control_id_ref)
            .where(
                ComplianceEvidence.organization_id == self.org_id,
                ComplianceEvidence.id.in_(evidence_ids),
            ),
        )).all()
        found = {ev.id for ev, _ in rows}
        missing = [e for e in evidence_ids if e not in found]
        items = dict(package.evidence_items or {})
        mappings = dict(package.control_mappings or {})
        for ev, code in rows:
            items[ev.id] = {
                "title": ev.title,
                "control": code,
                "evidence_type": ev.evidence_type,
                "file_hash": ev.file_hash,
                "review_status": ev.review_status,
                "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
            }
            if code:
                mappings.setdefault(code, [])
                if ev.id not in mappings[code]:
                    mappings[code] = [*mappings[code], ev.id]
        package.evidence_items = items
        package.control_mappings = mappings
        package.package_hash = None  # contents changed; re-package to seal
        await self.session.commit()
        return {
            "package_id": package_id,
            "added": len(found),
            "not_found": missing,
            "evidence_count": len(items),
        }

    async def package_evidence(self, package_id: str) -> dict[str, Any]:
        """
        Seal a package: hash its evidence items (ids and file hashes) and move
        it to ``review``. An empty package cannot be sealed (``ValueError``).
        """
        package = await self.session.scalar(select(EvidencePackage).where(
            EvidencePackage.id == package_id, EvidencePackage.organization_id == self.org_id))
        if not package:
            raise LookupError(f"Package {package_id} not found")
        items = package.evidence_items or {}
        if not items:
            raise ValueError("the package holds no evidence; attach evidence before packaging")
        manifest = json.dumps(
            {"name": package.name, "evidence_items": items, "control_mappings": package.control_mappings or {}},
            sort_keys=True, default=str,
        )
        package.package_hash = self._calculate_hash(manifest)
        package.status = "review"
        await self.session.commit()
        logger.info("evidence_package_sealed", package_id=package_id, items=len(items))
        return {
            "package_id": package_id,
            "name": package.name,
            "status": "review",
            "package_hash": package.package_hash,
            "evidence_count": len(items),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def verify_evidence_integrity(
        self,
        evidence_id: str,
        resolve_local_path: Optional[Callable[[str], str]] = None,
    ) -> dict[str, Any]:
        """
        Re-hash a stored ComplianceEvidence file and compare it with the
        hash recorded at upload.

        Before 2026-10-08 this read ``self.db`` (AttributeError, so it always
        answered False), looked up AutomatedEvidenceRule instead of evidence,
        and answered True when no hash was stored.

        Args:
            evidence_id: ComplianceEvidence id (must belong to this org)
            resolve_local_path: maps the stored path to a safe local path
                (raises if it lies outside the org's evidence root)

        Returns:
            ``{"status": "verified" | "mismatch" | "unverifiable",
            "integrity_valid": True | False | None, "reason": ...}``

        Raises:
            LookupError: the evidence is not in this organisation.
        """
        import os

        from src.compliance.models import ComplianceEvidence

        evidence = await self.session.scalar(
            select(ComplianceEvidence).where(
                ComplianceEvidence.id == evidence_id,
                ComplianceEvidence.organization_id == self.org_id,
            ),
        )
        if evidence is None:
            raise LookupError(f"Evidence {evidence_id} not found")

        def _unverifiable(reason: str) -> dict[str, Any]:
            return {"status": "unverifiable", "integrity_valid": None, "reason": reason}

        stored_hash = (evidence.file_hash or "").strip().lower()
        location = evidence.file_path or ""
        if not stored_hash:
            return _unverifiable("no hash was recorded for this evidence")
        if not location:
            return _unverifiable("no file is stored for this evidence")
        if "://" in location:
            return _unverifiable("remote evidence objects are not re-hashed by the platform")
        algorithms = {128: hashlib.sha512, 64: hashlib.sha256}
        algorithm = algorithms.get(len(stored_hash))
        if algorithm is None:
            return _unverifiable("the recorded hash is not a SHA-256 or SHA-512 digest")

        path = resolve_local_path(location) if resolve_local_path else location
        if not os.path.isfile(path):
            return {
                "status": "mismatch",
                "integrity_valid": False,
                "reason": "the evidence file is missing from storage",
            }
        hasher = algorithm()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        matches = hasher.hexdigest() == stored_hash
        return {
            "status": "verified" if matches else "mismatch",
            "integrity_valid": matches,
            "reason": None if matches else "the file's hash differs from the hash recorded at upload",
        }

    async def generate_evidence_report(self, package_id: str) -> dict[str, Any]:
        """Package metadata plus its attached evidence items."""
        stmt = select(EvidencePackage).where(
            EvidencePackage.id == package_id,
            EvidencePackage.organization_id == self.org_id,
        )
        package = await self.session.scalar(stmt)

        if not package:
            raise LookupError(f"Package {package_id} not found")

        return {
            "package_id": package_id,
            "name": package.name,
            "package_type": package.package_type,
            "status": package.status,
            "assessor": package.assessor,
            "due_date": package.due_date.isoformat() if package.due_date else None,
            "submitted_at": package.submitted_at.isoformat() if package.submitted_at else None,
            "evidence_count": len(package.evidence_items or {}),
            "evidence_items": package.evidence_items or {},
            "control_mappings": package.control_mappings,
            "package_hash": package.package_hash,
            "metadata": package.extra_metadata,
            "created_at": package.created_at.isoformat(),
            "updated_at": package.updated_at.isoformat(),
        }

    async def _collect_from_logs(self, config: dict[str, Any]) -> dict[str, Any]:
        """Counts of this organisation's audit_logs / log_entries / audit_trails rows."""
        from src.models.audit import AuditLog
        from src.siem.models import LogEntry

        source = str(config.get("source") or "audit_logs")
        try:
            days = max(1, min(int(config.get("days") or 30), 365))
        except (TypeError, ValueError) as exc:
            raise ValueError("days must be an integer") from exc
        since = datetime.now(timezone.utc) - timedelta(days=days)
        models = {
            "audit_logs": (AuditLog, AuditLog.action),
            "log_entries": (LogEntry, LogEntry.log_type),
            "audit_trails": (AuditTrail, AuditTrail.event_type),
        }
        if source not in models:
            raise ValueError(f"log_query source must be one of {sorted(models)}")
        model, group_col = models[source]
        rows = (await self.session.execute(
            select(group_col, func.count(model.id))
            .where(model.organization_id == self.org_id, model.created_at >= since)
            .group_by(group_col),
        )).all()
        breakdown = {str(k): int(n) for k, n in rows}
        return {
            "source": source,
            "window_days": days,
            "total": sum(breakdown.values()),
            "breakdown": breakdown,
        }

    async def _collect_from_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Snapshot of one tenant settings section, secrets redacted."""
        from src.services.tenant_settings import load_tenant_section

        section = str(config.get("section") or "security")
        if section not in self.CONFIG_SECTIONS:
            raise ValueError(f"config_check section must be one of {list(self.CONFIG_SECTIONS)}")
        values = await load_tenant_section(self.session, self.org_id, section)
        snapshot = {
            k: ("[redacted]" if any(m in k.lower() for m in self.SECRET_KEY_MARKERS) else v)
            for k, v in (values or {}).items()
        }
        return {"source": f"tenant settings: {section}", "values": snapshot, "configured": bool(values)}

    async def _collect_from_scan(self, config: dict[str, Any]) -> dict[str, Any]:
        """Latest stored STIG or vulnerability scan results."""
        scan_type = str(config.get("scan_type") or "stig")
        if scan_type == "stig":
            from src.stig.models import STIGScanResult

            rows = (await self.session.execute(
                select(STIGScanResult.id, STIGScanResult.target_host, STIGScanResult.status,
                       STIGScanResult.compliance_percentage, STIGScanResult.open_findings,
                       STIGScanResult.cat1_open, STIGScanResult.completed_at)
                .where(STIGScanResult.organization_id == self.org_id)
                .order_by(STIGScanResult.created_at.desc()).limit(50),
            )).all()
            return {
                "source": "stig_scan_results",
                "scans": [
                    {
                        "scan_id": r.id, "host": r.target_host, "status": r.status,
                        "compliance_percentage": r.compliance_percentage if r.status == "completed" else None,
                        "open_findings": r.open_findings, "cat1_open": r.cat1_open,
                        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    }
                    for r in rows
                ],
            }
        if scan_type == "vulnerability":
            from src.vulnmgmt.models import VulnerabilityInstance

            rows = (await self.session.execute(
                select(VulnerabilityInstance.status, VulnerabilityInstance.sla_status,
                       func.count(VulnerabilityInstance.id))
                .where(VulnerabilityInstance.organization_id == self.org_id)
                .group_by(VulnerabilityInstance.status, VulnerabilityInstance.sla_status),
            )).all()
            return {
                "source": "vulnerability_instances",
                "by_status_and_sla": [{"status": s, "sla_status": sla, "count": int(n)} for s, sla, n in rows],
            }
        raise ValueError("scan_result scan_type must be 'stig' or 'vulnerability'")

    async def _collect_metric(self, config: dict[str, Any]) -> dict[str, Any]:
        """One counted metric of this organisation's rows."""
        from src.compliance.models import POAM
        from src.models.alert import Alert
        from src.models.incident import Incident
        from src.models.user import User

        metric = str(config.get("metric") or "")
        queries = {
            "active_users": select(func.count(User.id)).where(
                User.organization_id == self.org_id, User.is_active.is_(True)),
            "mfa_enabled_users": select(func.count(User.id)).where(
                User.organization_id == self.org_id, User.is_active.is_(True), User.mfa_enabled.is_(True)),
            "open_incidents": select(func.count(Incident.id)).where(
                Incident.organization_id == self.org_id, Incident.status != "closed"),
            "open_alerts": select(func.count(Alert.id)).where(
                Alert.organization_id == self.org_id, Alert.status.notin_(("closed", "resolved"))),
            "open_poams": select(func.count(POAM.id)).where(
                POAM.organization_id == self.org_id, POAM.status.in_(("open", "in_progress", "delayed"))),
        }
        if metric not in queries:
            raise ValueError(f"metric_snapshot metric must be one of {list(self.METRICS)}")
        value = int((await self.session.execute(queries[metric])).scalar() or 0)
        return {"metric": metric, "value": value}

    def _calculate_hash(self, content: str) -> str:
        """Calculate SHA-512 hash of content"""
        return hashlib.sha512(content.encode()).hexdigest()


class ContinuousMonitor:
    """
    Continuous Monitoring (ConMon)

    Each check is computed from the organisation's stored rows: vulnerability
    findings, STIG scan results, incidents, POA&Ms and evidence. A check with
    no data to judge is ``not_assessed`` (it used to score 100% "compliant"),
    and a cycle run through ``run_and_persist`` is stored as a
    ``compliance_assessments`` row (type ``conmon``) whose time is the real
    ``lastRun``.
    """

    #: Statuses that count as a passing check.
    PASSING = ("compliant", "on_track")
    LABELS: ClassVar[dict[str, str]] = {
        "vulnerability_scanning": "Vulnerability Scanning (RA-5 / SI-2)",
        "configuration_baseline": "Configuration Baseline (CM-6)",
        "incident_reporting": "Incident Reporting (IR-6)",
        "poam_progress": "POA&M Progress (CA-5)",
        "evidence_currency": "Evidence Currency (CA-7)",
    }

    def __init__(self, session: AsyncSession, org_id: str):
        """Initialize continuous monitor"""
        self.session = session
        self.org_id = org_id

    @staticmethod
    def _not_assessed(control: str, reason: str, **facts: Any) -> dict[str, Any]:
        return {
            "control": control,
            "status": "not_assessed",
            "reason": reason,
            "compliance_percentage": None,
            **facts,
        }

    async def run_conmon_cycle(self) -> dict[str, Any]:
        """Compute every check (nothing is persisted; see ``run_and_persist``)."""
        return {
            "vulnerability_scanning": await self.check_vulnerability_scanning(),
            "configuration_baseline": await self.check_configuration_baseline(),
            "incident_reporting": await self.check_incident_reporting(),
            "poam_progress": await self.check_poam_progress(),
            "evidence_currency": await self.check_evidence_currency(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def check_vulnerability_scanning(self) -> dict[str, Any]:
        """RA-5 / SI-2: scan results in the last 30 days and SLA breaches."""
        from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance

        control = "RA-5 / SI-2 (monthly scanning, remediation within SLA)"
        org = VulnerabilityInstance.organization_id == self.org_id
        total = (await self.session.execute(select(func.count(VulnerabilityInstance.id)).where(org))).scalar() or 0
        if not total:
            return self._not_assessed(control, "no vulnerability scan results are stored", total_vulnerabilities=0)
        since = datetime.now(timezone.utc) - timedelta(days=30)
        recent = (await self.session.execute(
            select(func.count(VulnerabilityInstance.id)).where(org, VulnerabilityInstance.updated_at >= since),
        )).scalar() or 0
        sev_rows = (await self.session.execute(
            select(Vulnerability.severity, func.count(VulnerabilityInstance.id))
            .join(Vulnerability, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
            .where(org)
            .group_by(Vulnerability.severity),
        )).all()
        by_severity = {str(sev): int(count) for sev, count in sev_rows}
        overdue = (await self.session.execute(
            select(func.count(VulnerabilityInstance.id)).where(org, VulnerabilityInstance.sla_status == "breached"),
        )).scalar() or 0
        compliance_percentage = (total - overdue) / total * 100.0
        if not recent:
            status, reason = "non_compliant", "no scan results were imported in the last 30 days"
        elif overdue:
            status, reason = "non_compliant", f"{overdue} finding(s) are past their remediation SLA"
        else:
            status, reason = "compliant", None
        return {
            "control": control,
            "status": status,
            "reason": reason,
            "total_vulnerabilities": int(total),
            "findings": int(total),
            "updated_last_30_days": int(recent),
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "overdue_remediations": int(overdue),
            "compliance_percentage": round(compliance_percentage, 2),
        }

    async def check_configuration_baseline(self) -> dict[str, Any]:
        """CM-6: STIG scans completed in the last 30 days."""
        from src.stig.models import STIGScanResult

        control = "CM-6 (configuration settings, STIG scans)"
        since = datetime.now(timezone.utc) - timedelta(days=30)
        row = (await self.session.execute(
            select(
                func.count(STIGScanResult.id),
                func.coalesce(func.sum(STIGScanResult.not_a_finding), 0),
                func.coalesce(func.sum(STIGScanResult.open_findings), 0),
                func.coalesce(func.sum(STIGScanResult.not_reviewed), 0),
                func.coalesce(func.sum(STIGScanResult.cat1_open), 0),
            ).where(
                STIGScanResult.organization_id == self.org_id,
                STIGScanResult.status == "completed",
                STIGScanResult.completed_at >= since,
            ),
        )).one()
        scans, passing, open_findings, not_reviewed, cat1 = (int(v or 0) for v in row)
        not_run = (await self.session.execute(
            select(func.count(STIGScanResult.id)).where(
                STIGScanResult.organization_id == self.org_id,
                STIGScanResult.status.in_(("not_run", "failed")),
                STIGScanResult.created_at >= since,
            ),
        )).scalar() or 0
        if not scans:
            return self._not_assessed(
                control, "no STIG scan completed in the last 30 days",
                scan_result_count=0, scans_not_run=int(not_run),
            )
        judged = passing + open_findings + not_reviewed
        compliance_percentage = passing / judged * 100.0 if judged else 0.0
        if cat1:
            status, reason = "non_compliant", f"{cat1} open CAT I finding(s)"
        elif compliance_percentage < 90.0:
            status, reason = "non_compliant", f"{compliance_percentage:.1f}% of evaluated rules pass (threshold 90%)"
        else:
            status, reason = "compliant", None
        return {
            "control": control,
            "status": status,
            "reason": reason,
            "scan_result_count": scans,
            "scans_not_run": int(not_run),
            "total_checks": judged,
            "checks_passing": passing,
            "open_findings": open_findings,
            "not_reviewed": not_reviewed,
            "cat1_open": cat1,
            "compliance_percentage": round(compliance_percentage, 2),
        }

    async def check_incident_reporting(self) -> dict[str, Any]:
        """IR-6: incidents of the last 30 days recorded within an hour of detection."""
        from src.models.incident import Incident

        control = "IR-6 (incident reporting)"
        cutoff_30d = datetime.now(timezone.utc) - timedelta(days=30)
        rows = (await self.session.execute(
            select(Incident.created_at, Incident.detected_at).where(
                Incident.organization_id == self.org_id,
                Incident.created_at >= cutoff_30d,
            ).limit(5000),
        )).all()
        if not rows:
            return self._not_assessed(control, "no incidents in the last 30 days", incidents_this_month=0)

        reported_on_time = 0
        undated = 0
        for created_at, detected_raw in rows:
            if not detected_raw:
                undated += 1
                continue
            try:
                detected_dt = datetime.fromisoformat(str(detected_raw).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                undated += 1
                continue
            if detected_dt.tzinfo is None:
                detected_dt = detected_dt.replace(tzinfo=timezone.utc)
            created = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
            if abs((created - detected_dt).total_seconds()) <= 3600:
                reported_on_time += 1

        total = len(rows)
        compliance_percentage = reported_on_time / total * 100.0
        status = "compliant" if compliance_percentage >= 95.0 else "non_compliant"
        return {
            "control": control,
            "status": status,
            "reason": None if status == "compliant" else (
                f"{total - reported_on_time} of {total} incidents were not recorded within an hour of detection"
                + (f" ({undated} without a detection time)" if undated else "")
            ),
            "incidents_this_month": total,
            "reported_on_time": reported_on_time,
            "without_detection_time": undated,
            "compliance_percentage": round(compliance_percentage, 2),
            "last_incident": max(r[0] for r in rows).isoformat(),
        }

    async def check_poam_progress(self) -> dict[str, Any]:
        """CA-5: open POA&M items past their scheduled completion date."""
        from src.compliance.models import POAM

        control = "CA-5 (plan of action and milestones)"
        rows = (await self.session.execute(
            select(POAM.status, func.count(POAM.id)).where(POAM.organization_id == self.org_id).group_by(POAM.status),
        )).all()
        counts = {status: int(count) for status, count in rows}
        total = sum(counts.values())
        if not total:
            return self._not_assessed(control, "no POA&M items are recorded", total_items=0)
        closed_states = ("completed", "cancelled", "accepted")
        active = sum(n for s, n in counts.items() if s not in closed_states)
        overdue = (await self.session.execute(
            select(func.count(POAM.id)).where(
                POAM.organization_id == self.org_id,
                POAM.status.notin_(closed_states),
                POAM.scheduled_completion_date < datetime.now(timezone.utc),
            ),
        )).scalar() or 0
        compliance_percentage = (active - overdue) / active * 100.0 if active else 100.0
        return {
            "control": control,
            "status": "on_track" if not overdue else "at_risk",
            "reason": f"{overdue} open item(s) past their scheduled completion date" if overdue else None,
            "total_items": total,
            "active_items": active,
            "overdue_items": int(overdue),
            "completed": counts.get("completed", 0),
            "in_progress": counts.get("in_progress", 0),
            "open": counts.get("open", 0),
            "delayed": counts.get("delayed", 0),
            "status_breakdown": counts,
            "compliance_percentage": round(compliance_percentage, 2),
        }

    async def check_evidence_currency(self) -> dict[str, Any]:
        """CA-7: valid evidence collected within the last year."""
        from src.compliance.models import ComplianceEvidence

        control = "CA-7 (evidence currency)"
        now = datetime.now(timezone.utc)
        base = (ComplianceEvidence.organization_id == self.org_id, ComplianceEvidence.is_valid.is_(True))
        total = (await self.session.execute(select(func.count(ComplianceEvidence.id)).where(*base))).scalar() or 0
        if not total:
            return self._not_assessed(control, "no valid evidence is stored", evidence_items=0)
        stale = (await self.session.execute(
            select(func.count(ComplianceEvidence.id)).where(
                *base,
                (ComplianceEvidence.collected_at < now - timedelta(days=EVIDENCE_FRESH_DAYS))
                | (ComplianceEvidence.expires_at < now),
            ),
        )).scalar() or 0
        fresh = total - stale
        compliance_percentage = fresh / total * 100.0
        return {
            "control": control,
            "status": "compliant" if compliance_percentage >= 90.0 else "non_compliant",
            "reason": None if compliance_percentage >= 90.0 else f"{stale} of {total} evidence items are stale or expired",
            "evidence_items": int(total),
            "fresh": int(fresh),
            "stale_or_expired": int(stale),
            "compliance_percentage": round(compliance_percentage, 2),
        }

    @classmethod
    def overall_status(cls, checks: dict[str, Any]) -> str:
        statuses = [c.get("status") for c in checks.values() if isinstance(c, dict)]
        assessed = [s for s in statuses if s != "not_assessed"]
        if not assessed:
            return "not_assessed"
        if any(s not in cls.PASSING for s in assessed):
            return "non_compliant"
        return "compliant" if len(assessed) == len(statuses) else "partially_assessed"

    async def generate_conmon_report(self) -> dict[str, Any]:
        """Compute the ConMon report (not persisted)."""
        cycle_results = await self.run_conmon_cycle()
        now = datetime.now(timezone.utc)
        return {
            "report_type": "FedRAMP ConMon Monthly",
            "period": {
                "start": (now - timedelta(days=30)).isoformat(),
                "end": now.isoformat(),
            },
            "overall_status": self.overall_status(cycle_results),
            "checks": cycle_results,
            "generated_at": now.isoformat(),
        }

    async def latest_cycle(self) -> Optional[dict[str, Any]]:
        """The last persisted cycle (``compliance_assessments`` type conmon)."""
        from src.compliance.models import ComplianceAssessment

        row = (await self.session.execute(
            select(ComplianceAssessment).where(
                ComplianceAssessment.organization_id == self.org_id,
                ComplianceAssessment.assessment_type == "conmon",
            ).order_by(ComplianceAssessment.assessment_date.desc()).limit(1),
        )).scalar_one_or_none()
        if row is None:
            return None
        return {
            "assessment_id": row.id,
            "ran_at": row.assessment_date.isoformat() if row.assessment_date else None,
            "overall_status": row.overall_result,
            "report": row.results or {},
        }

    async def run_and_persist(self, assessor: str) -> dict[str, Any]:
        """Run a cycle and store it (on the organisation's FedRAMP framework,
        seeded on demand) so ``lastRun`` and the report history are real."""
        from src.compliance.models import ComplianceAssessment
        from src.compliance.seeder import ensure_framework

        report = await self.generate_conmon_report()
        framework = await ensure_framework(self.session, self.org_id, "fedramp_moderate")
        checks = {k: v for k, v in report["checks"].items() if isinstance(v, dict)}
        passing = sum(1 for c in checks.values() if c.get("status") in self.PASSING)
        failing = sum(1 for c in checks.values() if c.get("status") not in (*self.PASSING, "not_assessed"))
        row = ComplianceAssessment(
            framework_id=framework.id,
            assessment_type="conmon",
            assessor=assessor,
            assessment_date=datetime.now(timezone.utc),
            status="completed",
            findings_count=failing,
            satisfied_count=passing,
            other_than_satisfied_count=failing,
            overall_result=report["overall_status"],
            results=report,
            organization_id=self.org_id,
        )
        self.session.add(row)
        await self.session.flush()
        report["assessment_id"] = row.id
        report["persisted"] = True
        return report


class AuditReadinessChecker:
    """
    Audit Readiness Checker

    Readiness, evidence coverage and evidence freshness computed from the
    organisation's control and evidence rows (coverage and freshness used to
    return fixed numbers: 150 / 142 / 94.7% and 128 / 14 / 90.1%).
    """

    def __init__(self, session: AsyncSession, org_id: str):
        """Initialize readiness checker"""
        self.session = session
        self.org_id = org_id

    async def _framework(self, framework: str):
        from src.compliance.models import ComplianceFramework

        if not framework:
            return None
        return (await self.session.scalars(
            select(ComplianceFramework).where(
                ComplianceFramework.organization_id == self.org_id,
                (ComplianceFramework.id == framework)
                | (func.lower(ComplianceFramework.short_name) == framework.lower())
                | (func.lower(ComplianceFramework.name) == framework.lower()),
            ),
        )).first()

    async def _controls(self, framework_id: str) -> list[Any]:
        from src.compliance.models import ComplianceControl

        return list((await self.session.execute(
            select(ComplianceControl.id, ComplianceControl.control_id, ComplianceControl.title,
                   ComplianceControl.status)
            .where(
                ComplianceControl.organization_id == self.org_id,
                ComplianceControl.framework_id == framework_id,
            ),
        )).all())

    async def check_readiness(self, framework: str) -> dict[str, Any]:
        """Readiness of one framework (id, short name or name) from its control statuses."""
        fw = await self._framework(framework)
        empty = {
            "framework": framework,
            "framework_id": None,
            "overall_readiness": "unknown",
            "readiness_percentage": 0.0,
            "total_controls": 0,
            "implemented": 0,
            "partially_implemented": 0,
            "planned": 0,
            "not_implemented": 0,
            "not_assessed": 0,
            "not_applicable": 0,
            "gaps": [],
            "gap_count": 0,
        }
        if fw is None:
            return {**empty, "recommendations": [
                f"No framework named {framework!r} is enabled for this organisation"]}
        controls = await self._controls(fw.id)
        if not controls:
            return {**empty, "framework_id": fw.id, "recommendations": [
                "This framework has no controls; seed or import its catalogue"]}

        status_counts: dict[str, int] = defaultdict(int)
        gaps: list[dict[str, Any]] = []
        for c in controls:
            status_counts[c.status] += 1
            if c.status in ("not_implemented", "planned", "partially_implemented", "not_assessed"):
                gaps.append({"control": c.control_id, "description": c.title, "status": c.status})

        total = len(controls)
        implemented = status_counts.get("implemented", 0)
        partial = status_counts.get("partially_implemented", 0)
        na = status_counts.get("not_applicable", 0)
        effective_total = total - na
        readiness_percentage = (
            (implemented + partial * 0.5) / effective_total * 100.0 if effective_total > 0 else 0.0
        )
        overall = (
            "ready" if readiness_percentage >= 90.0
            else "partial" if readiness_percentage >= 60.0
            else "not_ready"
        )
        recommendations: list[str] = []
        for key, verb in (
            ("not_implemented", "Implement"), ("not_assessed", "Assess (attach evidence or run the attester for)"),
            ("planned", "Execute on"), ("partially_implemented", "Complete"),
        ):
            if status_counts.get(key):
                recommendations.append(f"{verb} {status_counts[key]} {key.replace('_', ' ')} controls")

        return {
            "framework": framework,
            "framework_id": fw.id,
            "overall_readiness": overall,
            "readiness_percentage": round(readiness_percentage, 2),
            "total_controls": total,
            "implemented": implemented,
            "partially_implemented": partial,
            "planned": status_counts.get("planned", 0),
            "not_implemented": status_counts.get("not_implemented", 0),
            "not_assessed": status_counts.get("not_assessed", 0),
            "not_applicable": na,
            "gaps": gaps[:25],
            "gap_count": len(gaps),
            "recommendations": recommendations,
        }

    async def _evidence_rows(self, control_pks: list[str]) -> list[Any]:
        from src.compliance.models import ComplianceEvidence

        if not control_pks:
            return []
        return list((await self.session.execute(
            select(ComplianceEvidence.control_id_ref, ComplianceEvidence.collected_at,
                   ComplianceEvidence.expires_at, ComplianceEvidence.review_status)
            .where(
                ComplianceEvidence.organization_id == self.org_id,
                ComplianceEvidence.control_id_ref.in_(control_pks),
                ComplianceEvidence.is_valid.is_(True),
            ),
        )).all())

    async def check_evidence_coverage(self, framework_id: str) -> dict[str, Any]:
        """Controls of the framework with at least one valid evidence row."""
        fw = await self._framework(framework_id)
        if fw is None:
            raise LookupError(f"Framework {framework_id} not found")
        controls = await self._controls(fw.id)
        rows = await self._evidence_rows([c.id for c in controls])
        covered = {r.control_id_ref for r in rows}
        approved = {r.control_id_ref for r in rows if r.review_status == "approved"}
        missing = [{"id": c.control_id, "control_record_id": c.id, "title": c.title}
                   for c in controls if c.id not in covered]
        total = len(controls)
        return {
            "framework_id": fw.id,
            "total_controls": total,
            "controls_with_evidence": len(covered),
            "controls_with_approved_evidence": len(approved),
            "controls_without_evidence": len(missing),
            "coverage_percentage": round(len(covered) / total * 100.0, 2) if total else 0.0,
            "controls_missing_evidence": missing[:200],
            "basis": "valid compliance_evidence rows per control",
        }

    async def check_evidence_freshness(self, framework_id: str) -> dict[str, Any]:
        """Evidence collected within EVIDENCE_FRESH_DAYS and not expired."""
        fw = await self._framework(framework_id)
        if fw is None:
            raise LookupError(f"Framework {framework_id} not found")
        controls = await self._controls(fw.id)
        codes = {c.id: c.control_id for c in controls}
        rows = await self._evidence_rows(list(codes))
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=EVIDENCE_FRESH_DAYS)

        def _aware(value: Optional[datetime]) -> Optional[datetime]:
            if value is None:
                return None
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

        fresh = stale = 0
        newest: dict[str, datetime] = {}
        for r in rows:
            collected = _aware(r.collected_at)
            expires = _aware(r.expires_at)
            if collected is None or collected < cutoff or (expires is not None and expires < now):
                stale += 1
            else:
                fresh += 1
            if collected is not None and (r.control_id_ref not in newest or collected > newest[r.control_id_ref]):
                newest[r.control_id_ref] = collected
        stale_controls = sorted(
            (
                {"control": codes.get(pk, pk), "last_updated": ts.isoformat(), "days_old": (now - ts).days}
                for pk, ts in newest.items() if ts < cutoff
            ),
            key=lambda item: -item["days_old"],
        )
        judged = fresh + stale
        return {
            "framework_id": fw.id,
            "assessment_date": now.isoformat(),
            "fresh_evidence_count": fresh,
            "stale_evidence_count": stale,
            "freshness_percentage": round(fresh / judged * 100.0, 2) if judged else 0.0,
            "stale_controls": stale_controls[:200],
            "freshness_window_days": EVIDENCE_FRESH_DAYS,
            "status": "assessed" if judged else "no_evidence",
        }

    async def generate_assessor_package(self, framework_id: str) -> dict[str, Any]:
        """Coverage + freshness summary for external assessors."""
        coverage = await self.check_evidence_coverage(framework_id)
        freshness = await self.check_evidence_freshness(framework_id)
        now = datetime.now(timezone.utc)
        return {
            "package_id": f"assessor_{coverage['framework_id']}_{now.strftime('%Y%m%dT%H%M%SZ')}",
            "framework_id": coverage["framework_id"],
            "coverage": coverage,
            "freshness": freshness,
            "generated_at": now.isoformat(),
            "ready_for_assessment": (
                coverage["total_controls"] > 0
                and coverage["coverage_percentage"] >= 90.0
                and freshness["freshness_percentage"] >= 90.0
            ),
        }
