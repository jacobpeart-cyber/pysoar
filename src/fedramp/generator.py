"""
FedRAMP document and report generator (wave 4).

Control status comes from the organisation's ``compliance_controls`` rows of
its ``fedramp_moderate`` framework (seeded on demand from the real Moderate
catalogue when missing). The SSP, IRP, CMP and ConMon plan are built from the
organisation's stored system facts (``src.compliance.system_facts``) and
plan inputs read from its rows (playbooks, incidents, STIG benchmarks and
scans, the beat schedule, the last ConMon cycle). What the platform does not
record is an explicit ``[TO BE COMPLETED: ...]`` placeholder: the previous
generator described a hosting environment (AWS GovCloud, RDS Multi-AZ,
ElastiCache, CloudFront, FIPS endpoints) and processes (CAB approval, signed
deployments, 24/7 SOC, weekly authenticated scans) that nobody recorded.
"""

from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from src.compliance.system_facts import placeholder
from src.fedramp.controls import (
    CONTROLS_BY_ID,
    FAMILY_CODES,
    FEDRAMP_MODERATE_CONTROLS,
)

FEDRAMP_FRAMEWORK = "fedramp_moderate"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class FedRAMPGenerator:
    """Generator for FedRAMP compliance documentation and reports."""

    IMPLEMENTATION_STATUSES = [
        "implemented",
        "partially_implemented",
        "planned",
        "alternative",
        "not_implemented",
        "not_applicable",
    ]

    #: Status reported for a baseline control that nobody assessed: no row,
    #: or the seeded default (``not_implemented`` never set by a person or
    #: the attester, never assessed).
    NOT_ASSESSED = "not_assessed"

    #: Stored statuses that count as a gap in the readiness report.
    GAP_STATUSES = ("planned", "partially_implemented", "not_implemented", "non_compliant")

    # ------------------------------------------------ Control Status Query
    async def get_control_implementation_status(
        self,
        db: Any,
        organization_id: Optional[str] = None,
        seed_if_missing: bool = True,
    ) -> List[Dict[str, Any]]:
        """The Moderate baseline enriched with the organisation's control rows.

        The organisation's ``fedramp_moderate`` framework is seeded from the
        real catalogue when it does not exist yet (``seed_if_missing``).
        """
        from sqlalchemy import select as sa_select

        from src.compliance.engine import FEDRAMP_SHORT_NAME_PREFIX
        from src.compliance.models import (
            ComplianceControl,
            ComplianceEvidence,
            ComplianceFramework,
        )
        from src.compliance.seeder import ensure_framework

        if seed_if_missing and organization_id:
            existing = (await db.execute(
                sa_select(ComplianceFramework.id).where(
                    ComplianceFramework.organization_id == organization_id,
                    ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
                ).limit(1)
            )).scalar_one_or_none()
            if existing is None:
                await ensure_framework(db, organization_id, FEDRAMP_FRAMEWORK)
                await db.commit()

        rows = (
            await db.execute(
                sa_select(ComplianceControl, ComplianceFramework.short_name)
                .join(
                    ComplianceFramework,
                    ComplianceControl.framework_id == ComplianceFramework.id,
                )
                .where(
                    ComplianceFramework.organization_id == organization_id,
                    ComplianceControl.organization_id == organization_id,
                    ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
                )
            )
        ).all()

        chosen: Dict[str, Any] = {}
        chosen_framework: Dict[str, str] = {}
        for control_row, short_name in rows:
            current = chosen_framework.get(control_row.control_id)
            if current is None or (short_name == FEDRAMP_FRAMEWORK and current != FEDRAMP_FRAMEWORK):
                chosen[control_row.control_id] = control_row
                chosen_framework[control_row.control_id] = short_name

        evidence_by_control: Dict[str, List[Dict[str, Any]]] = {}
        control_pks = [c.id for c in chosen.values()]
        if control_pks:
            evidence_rows = (
                await db.execute(
                    sa_select(ComplianceEvidence).where(
                        ComplianceEvidence.organization_id == organization_id,
                        ComplianceEvidence.control_id_ref.in_(control_pks),
                        ComplianceEvidence.is_valid.is_(True),
                    )
                )
            ).scalars().all()
            for ev in evidence_rows:
                evidence_by_control.setdefault(ev.control_id_ref, []).append({
                    "id": ev.id,
                    "title": ev.title,
                    "evidence_type": ev.evidence_type,
                    "review_status": ev.review_status,
                    "is_automated": bool(ev.is_automated),
                    "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
                })

        enriched: List[Dict[str, Any]] = []
        for ctrl in FEDRAMP_MODERATE_CONTROLS:
            entry = dict(ctrl)
            row = chosen.get(ctrl["id"])
            if row is None:
                entry.update({
                    "implementation_status": self.NOT_ASSESSED,
                    "evidence_artifacts": [],
                    "last_assessed": "",
                    "assessor_notes": "",
                    "control_record_id": None,
                    "framework": None,
                    "assessment_basis": None,
                    "status_source": None,
                    "last_assessment_result": None,
                })
                enriched.append(entry)
                continue
            stored = row.status or self.NOT_ASSESSED
            untouched_default = (
                stored == "not_implemented" and not row.status_source and row.last_assessed_at is None
            )
            artifacts = list(evidence_by_control.get(row.id, []))
            known = {a["id"] for a in artifacts}
            artifacts.extend({"id": ev_id} for ev_id in (row.evidence_ids or []) if ev_id not in known)
            entry.update({
                "implementation_status": self.NOT_ASSESSED if untouched_default else stored,
                "evidence_artifacts": artifacts,
                "last_assessed": row.last_assessed_at.isoformat() if row.last_assessed_at else "",
                # No assessor-notes column exists; the key is kept for the
                # response shape and is always empty.
                "assessor_notes": "",
                "control_record_id": row.id,
                "framework": chosen_framework.get(ctrl["id"]),
                "assessment_basis": row.assessment_basis,
                "status_source": row.status_source,
                "last_assessment_result": row.last_assessment_result,
                "responsible_party": row.responsible_party,
            })
            if row.implementation_details:
                entry["implementation_narrative"] = row.implementation_details
            enriched.append(entry)
        return enriched

    # ---------------------------------------------------------- Readiness
    def generate_readiness_report(
        self,
        controls_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Readiness score, per-family breakdown, gaps and recommendations,
        all computed from ``controls_data`` (the output of
        ``get_control_implementation_status``)."""
        if controls_data is None:
            controls_data = [dict(c, implementation_status=self.NOT_ASSESSED) for c in FEDRAMP_MODERATE_CONTROLS]

        total = len(controls_data)
        status_counts: Dict[str, int] = {s: 0 for s in self.IMPLEMENTATION_STATUSES}
        status_counts[self.NOT_ASSESSED] = 0

        family_stats: Dict[str, Dict[str, Any]] = {}
        gaps: List[Dict[str, Any]] = []
        implemented_without_evidence: List[str] = []

        for ctrl in controls_data:
            st = ctrl.get("implementation_status", self.NOT_ASSESSED)
            status_counts[st] = status_counts.get(st, 0) + 1

            fam = ctrl.get("family", "Unknown")
            if fam not in family_stats:
                family_stats[fam] = {"total": 0, "implemented": 0, "not_assessed": 0, "gaps": []}
            family_stats[fam]["total"] += 1

            if st == "implemented":
                family_stats[fam]["implemented"] += 1
                if not ctrl.get("evidence_artifacts"):
                    implemented_without_evidence.append(ctrl["id"])
            elif st == self.NOT_ASSESSED:
                family_stats[fam]["not_assessed"] += 1
            elif st in self.GAP_STATUSES:
                basis = ctrl.get("assessment_basis") or {}
                gap_entry = {
                    "control_id": ctrl["id"],
                    "title": ctrl.get("title", ""),
                    "family": fam,
                    "current_status": st,
                    "priority": ctrl.get("priority", "P3"),
                    "pysoar_mapping": ctrl.get("pysoar_mapping", ""),
                    "reason": basis.get("reason") or basis.get("summary"),
                    "recommendation": (
                        f"Resolve: {basis['reason']}" if basis.get("reason")
                        else f"Complete the implementation of {ctrl['id']} and attach evidence."
                    ),
                }
                gaps.append(gap_entry)
                family_stats[fam]["gaps"].append(gap_entry)

        implemented = status_counts.get("implemented", 0)
        partial = status_counts.get("partially_implemented", 0)
        scored = total - status_counts.get("not_applicable", 0)
        readiness_score = round(((implemented + 0.5 * partial) / scored) * 100, 2) if scored else 0.0

        for stats in family_stats.values():
            t = stats["total"]
            stats["readiness_pct"] = round((stats["implemented"] / t) * 100, 2) if t else 0.0

        not_assessed = status_counts.get(self.NOT_ASSESSED, 0)
        if total and not_assessed == total:
            assessment_status = "not_assessed"
        elif not_assessed:
            assessment_status = "partially_assessed"
        else:
            assessment_status = "assessed"

        priority_order = {"P1": 0, "P2": 1, "P3": 2}
        gaps.sort(key=lambda g: priority_order.get(g.get("priority", "P3"), 3))

        return {
            "report_title": "FedRAMP Moderate Readiness Assessment",
            "generated_at": _now_iso(),
            "overall_readiness_score": readiness_score,
            "assessment_status": assessment_status,
            "not_assessed_controls": not_assessed,
            "assessment_basis": (
                "Computed from this organization's FedRAMP control records "
                "(compliance_controls). Controls without a record, or still at the "
                "seeded default, are not_assessed and count as not implemented in the score."
            ),
            "total_controls": total,
            "status_breakdown": status_counts,
            "family_readiness": family_stats,
            "gap_analysis": {
                "total_gaps": len(gaps),
                "p1_gaps": sum(1 for g in gaps if g["priority"] == "P1"),
                "p2_gaps": sum(1 for g in gaps if g["priority"] == "P2"),
                "p3_gaps": sum(1 for g in gaps if g["priority"] == "P3"),
                "gaps": gaps,
            },
            "recommendations_basis": "computed_from_gaps",
            "recommendations": self._recommendations(gaps, family_stats, not_assessed, implemented_without_evidence),
        }

    @staticmethod
    def _recommendations(
        gaps: List[Dict[str, Any]],
        family_stats: Dict[str, Dict[str, Any]],
        not_assessed: int,
        implemented_without_evidence: List[str],
    ) -> List[Dict[str, Any]]:
        """Recommendations derived from this organisation's gaps (they used
        to be five fixed strings for every tenant)."""
        recs: List[Dict[str, Any]] = []
        p1 = [g for g in gaps if g.get("priority") == "P1"]
        if p1:
            by_family: Dict[str, List[str]] = {}
            for g in p1:
                by_family.setdefault(g["family"], []).append(g["control_id"])
            for family, ids in sorted(by_family.items(), key=lambda kv: -len(kv[1]))[:5]:
                recs.append({
                    "priority": "Critical",
                    "title": f"Close {len(ids)} P1 gap(s) in {family}",
                    "action": f"Close P1 gaps: {', '.join(ids[:10])}",
                    "control_family": family,
                })
        other_gaps = len(gaps) - len(p1)
        if other_gaps:
            recs.append({
                "priority": "High",
                "title": f"Close {other_gaps} P2/P3 gap(s)",
                "action": "Work the remaining gaps in priority order (see gap_analysis).",
            })
        if implemented_without_evidence:
            recs.append({
                "priority": "High",
                "title": f"Attach evidence to {len(implemented_without_evidence)} implemented control(s)",
                "action": f"No valid evidence for: {', '.join(implemented_without_evidence[:10])}",
            })
        if not_assessed:
            worst = sorted(family_stats.items(), key=lambda kv: -kv[1].get("not_assessed", 0))[:3]
            recs.append({
                "priority": "Medium",
                "title": f"Assess {not_assessed} control(s) that have no assessment",
                "action": (
                    "Run POST /compliance/frameworks/{id}/attest and record status for the controls no "
                    "automated check covers; most unassessed families: "
                    + ", ".join(f"{fam} ({stats.get('not_assessed', 0)})" for fam, stats in worst)
                ),
            })
        return recs

    # ------------------------------------------------------------- POA&M
    def generate_poam_report(
        self,
        poams: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Formatted POA&M report with a monthly due-date timeline."""
        now_dt = datetime.now(timezone.utc)
        severity_order = {"very_high": 0, "critical": 0, "high": 1, "moderate": 2, "low": 3}
        sorted_poams = sorted(poams, key=lambda p: severity_order.get(str(p.get("severity", "low")).lower(), 4))

        status_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        overdue: List[Dict[str, Any]] = []
        timeline: Dict[str, Dict[str, int]] = {}
        closed_states = ("completed", "closed", "cancelled", "accepted")

        for p in sorted_poams:
            s = p.get("status", "open")
            status_counts[s] = status_counts.get(s, 0) + 1
            sev = str(p.get("severity", "low")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            due = p.get("scheduled_completion_date")
            due_dt: Optional[datetime] = None
            if isinstance(due, datetime):
                due_dt = due
            elif isinstance(due, date):
                due_dt = datetime.combine(due, datetime.min.time())
            elif isinstance(due, str) and due:
                try:
                    due_dt = datetime.fromisoformat(due.replace("Z", "+00:00"))
                except ValueError:
                    due_dt = None
            if due_dt is not None and due_dt.tzinfo is None:
                due_dt = due_dt.replace(tzinfo=timezone.utc)
            if due_dt is not None:
                bucket = timeline.setdefault(due_dt.strftime("%Y-%m"), {"due": 0, "completed": 0, "open": 0})
                bucket["due"] += 1
                bucket["completed" if s in closed_states else "open"] += 1
                if s not in closed_states and due_dt < now_dt:
                    overdue.append(p)

        formatted_items = []
        for idx, p in enumerate(sorted_poams, start=1):
            ctrl = CONTROLS_BY_ID.get(p.get("control_id", ""))
            formatted_items.append({
                "item_number": idx,
                "poam_id": p.get("poam_id", f"POAM-{idx:04d}"),
                "control_id": p.get("control_id", ""),
                "control_title": ctrl["title"] if ctrl else "",
                "weakness_description": p.get("weakness_description", ""),
                "severity": p.get("severity", "low"),
                "status": p.get("status", "open"),
                "scheduled_completion_date": str(p.get("scheduled_completion_date", "")),
                "milestones": p.get("milestones", []),
                "responsible_party": p.get("responsible_party", ""),
                "resources_required": p.get("resources_required", ""),
                "vendor_dependency": p.get("vendor_dependency", False),
                "risk_acceptance": p.get("status") == "accepted",
                "comments": p.get("comments", ""),
            })

        return {
            "report_title": "Plan of Action and Milestones (POA&M)",
            "generated_at": _now_iso(),
            "summary": {
                "total_items": len(poams),
                "status_breakdown": status_counts,
                "severity_breakdown": severity_counts,
                "overdue_items": len(overdue),
            },
            "items": formatted_items,
            "overdue_items": [
                {
                    "poam_id": o.get("poam_id", ""),
                    "control_id": o.get("control_id", ""),
                    "scheduled_completion_date": str(o.get("scheduled_completion_date", "")),
                    "severity": o.get("severity", ""),
                }
                for o in overdue
            ],
            # Items due per month (completed vs still open), from the stored
            # scheduled completion dates.
            "timeline": [{"month": month, **counts} for month, counts in sorted(timeline.items())],
        }

    # --------------------------------------------------------- plan inputs
    async def collect_plan_inputs(self, db: Any, organization_id: str) -> Dict[str, Any]:
        """Rows the IRP / CMP / ConMon plan state as facts."""
        from sqlalchemy import func, select

        from src.audit_evidence.engine import ContinuousMonitor
        from src.models.incident import Incident
        from src.models.playbook import Playbook
        from src.stig.models import STIGBenchmark, STIGScanResult
        from src.workers.celery_app import celery_app

        playbooks = [
            {"name": r.name, "trigger_type": getattr(r, "trigger_type", None)}
            for r in (await db.execute(
                select(Playbook.name, Playbook.trigger_type).where(
                    Playbook.organization_id == organization_id, Playbook.is_enabled.is_(True))
                .order_by(Playbook.name).limit(50)
            )).all()
        ]
        since = datetime.now(timezone.utc) - timedelta(days=365)
        incidents_by_severity = {
            str(sev): int(n) for sev, n in (await db.execute(
                select(Incident.severity, func.count(Incident.id)).where(
                    Incident.organization_id == organization_id, Incident.created_at >= since)
                .group_by(Incident.severity)
            )).all()
        }
        benchmarks = [
            {"benchmark_id": r.benchmark_id, "title": r.title, "version": r.version, "platform": r.platform,
             "last_scan_at": r.last_scan_at.isoformat() if r.last_scan_at else None}
            for r in (await db.execute(
                select(STIGBenchmark.benchmark_id, STIGBenchmark.title, STIGBenchmark.version,
                       STIGBenchmark.platform, STIGBenchmark.last_scan_at)
                .where(STIGBenchmark.organization_id == organization_id).limit(50)
            )).all()
        ]
        scan_counts = {
            str(st): int(n) for st, n in (await db.execute(
                select(STIGScanResult.status, func.count(STIGScanResult.id))
                .where(STIGScanResult.organization_id == organization_id, STIGScanResult.created_at >= since)
                .group_by(STIGScanResult.status)
            )).all()
        }
        schedule = []
        for name, entry in sorted((celery_app.conf.beat_schedule or {}).items()):
            task = str(entry.get("task", ""))
            if any(key in task for key in ("stig", "compliance", "audit_evidence", "vulnmgmt", "exposure", "siem")):
                schedule.append({"name": name, "task": task, "schedule": str(entry.get("schedule"))})
        monitor = ContinuousMonitor(db, organization_id)
        return {
            "enabled_playbooks": playbooks,
            "incidents_last_365_days_by_severity": incidents_by_severity,
            "stig_benchmarks": benchmarks,
            "stig_scans_last_365_days_by_status": scan_counts,
            "scheduled_monitoring_tasks": schedule,
            "last_conmon_cycle": await monitor.latest_cycle(),
            "current_conmon_checks": await monitor.run_conmon_cycle(),
        }

    # ------------------------------------------------------------------ SSP
    @staticmethod
    def _metadata(title: str, org_name: str, scope: Optional[List[str]] = None) -> Dict[str, Any]:
        meta = {
            "title": title,
            "version": "draft",
            "date_prepared": date.today().isoformat(),
            "last_updated": _now_iso(),
            "prepared_by": org_name,
            "fedramp_baseline": "Moderate",
            "nist_revision": "Rev 5",
            "document_status": "Draft generated from stored platform records",
        }
        if scope:
            meta["control_family_scope"] = scope
        return meta

    def _control_entry(self, c: Dict[str, Any]) -> Dict[str, Any]:
        basis = c.get("assessment_basis") or {}
        narrative = c.get("implementation_narrative")
        if not narrative and basis.get("summary"):
            narrative = f"Automated check ({basis.get('result')}): {basis['summary']}"
        return {
            "control_id": c["id"],
            "title": c.get("title", ""),
            "description": c.get("description", ""),
            "family": c.get("family", ""),
            "implementation_status": c.get("implementation_status", self.NOT_ASSESSED),
            "pysoar_mapping": c.get("pysoar_mapping", ""),
            "implementation_narrative": narrative or placeholder(f"implementation narrative for {c['id']}"),
            "responsible_role": c.get("responsible_party") or placeholder(f"responsible role for {c['id']}"),
            "assessment_basis": basis or None,
            "evidence_artifacts": c.get("evidence_artifacts", []),
        }

    def _family_controls_from_data(
        self,
        controls_data: List[Dict[str, Any]],
        family_codes: List[str],
    ) -> List[Dict[str, Any]]:
        """Controls of the given family codes, as SSP / plan entries."""
        return [
            self._control_entry(c)
            for c in controls_data
            if any(c["id"].startswith(f + "-") for f in family_codes)
        ]

    def generate_ssp(
        self,
        org_name: str,
        system_name: str,
        controls_data: Optional[List[Dict[str, Any]]] = None,
        facts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """System Security Plan from stored facts and control rows."""
        if controls_data is None:
            controls_data = [dict(c, implementation_status=self.NOT_ASSESSED) for c in FEDRAMP_MODERATE_CONTROLS]
        facts = facts or {}
        org = facts.get("organization") or {}
        deployment = facts.get("deployment") or {}
        hosting = facts.get("hosting") or {}
        roles = facts.get("roles") or {}

        family_sections = {}
        for family_code, family_name in FAMILY_CODES.items():
            family_sections[family_code] = {
                "family_name": family_name,
                "controls": self._family_controls_from_data(controls_data, [family_code]),
            }

        counts: Dict[str, int] = {}
        for c in controls_data:
            st = c.get("implementation_status", self.NOT_ASSESSED)
            counts[st] = counts.get(st, 0) + 1

        return {
            "document_metadata": self._metadata(f"System Security Plan — {system_name}", org_name),
            "system_information": {
                "system_name": system_name,
                "organization": org,
                "system_description": org.get("description") or placeholder("system description"),
                "system_owner": roles.get("system_owner") or placeholder("system owner"),
                "authorizing_official": roles.get("authorizing_official") or placeholder("authorising official"),
                "information_system_security_officer": roles.get("isso") or placeholder("ISSO"),
                "security_categorization": placeholder("FIPS 199 categorisation (C/I/A) and its rationale"),
                "cloud_service_model": placeholder("service model"),
                "cloud_deployment_model": placeholder("deployment model"),
            },
            "system_environment": {
                "hosting": hosting,
                "deployment": deployment,
                "assets_by_type": facts.get("assets_by_type", {}),
                "endpoint_agents": facts.get("endpoint_agents", []),
                "users": facts.get("users", {}),
                "policies": facts.get("policies", {}),
            },
            "authorization_boundary": {
                "description": hosting.get("authorization_boundary") or placeholder("authorisation boundary"),
                "external_interconnections": facts.get("installed_integrations", []),
            },
            "security_controls": family_sections,
            "control_summary": {
                "total_controls": len(controls_data),
                "families_covered": len(family_sections),
                "baseline": "FedRAMP Moderate",
                "status_counts": counts,
            },
            "missing_facts": facts.get("missing_facts", []),
            "facts_basis": facts.get("basis"),
        }

    # ------------------------------------------------------------- plans
    def generate_irp(
        self,
        org_name: str,
        system_name: str,
        controls_data: Optional[List[Dict[str, Any]]] = None,
        facts: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Incident Response Plan (IR family) from stored playbooks and incidents."""
        controls_data = controls_data or []
        facts = facts or {}
        inputs = inputs or {}
        playbooks = inputs.get("enabled_playbooks") or []
        integrations = facts.get("installed_integrations") or []
        return {
            "document_metadata": self._metadata(
                f"Incident Response Plan — {system_name}", org_name, ["IR - Incident Response"]),
            "purpose": (
                f"Incident response process of {org_name} for {system_name}. Sections the "
                "platform cannot derive from its records are marked TO BE COMPLETED."
            ),
            "scope": {
                "system": system_name,
                "covered_events": placeholder("incident categories in scope"),
                "incidents_last_365_days_by_severity": inputs.get("incidents_last_365_days_by_severity", {}),
            },
            "roles_and_responsibilities": [
                {"role": "Incident Commander", "responsibility": placeholder("named incident commander and duties")},
                {"role": "Incident Response Team", "responsibility": placeholder("team members and duties")},
                {"role": "ISSO", "responsibility": placeholder("ISSO reporting duties")},
            ],
            "incident_lifecycle": {
                "response_playbooks": playbooks or placeholder("response playbooks (none are enabled)"),
                "notification_integrations": [
                    i for i in integrations if any(
                        k in str(i.get("connector_id", "")).lower()
                        for k in ("slack", "teams", "pagerduty", "opsgenie", "email", "smtp", "jira", "servicenow"))
                ],
                "post_incident": placeholder("lessons-learned process"),
            },
            "reporting_obligations": {
                "requirement": (
                    "FedRAMP Incident Communications Procedure: report incidents to US-CERT/CISA and "
                    "the FedRAMP PMO within one hour of identification."
                ),
                "implementation": placeholder("who reports, through which channel"),
            },
            "severity_matrix": placeholder("severity levels and response times"),
            "control_implementation": {
                "family": "IR - Incident Response",
                "controls": self._family_controls_from_data(controls_data, ["IR"]),
            },
            "testing_and_exercises": {
                "requirement": "IR-3: test the incident response capability at least annually.",
                "last_test_date": None,
                "next_scheduled": None,
                "record": placeholder("incident response test records"),
            },
            "missing_facts": facts.get("missing_facts", []),
        }

    def generate_cmp(
        self,
        org_name: str,
        system_name: str,
        controls_data: Optional[List[Dict[str, Any]]] = None,
        facts: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Configuration Management Plan (CM family) from stored baselines and inventory."""
        controls_data = controls_data or []
        facts = facts or {}
        inputs = inputs or {}
        benchmarks = inputs.get("stig_benchmarks") or []
        return {
            "document_metadata": self._metadata(
                f"Configuration Management Plan — {system_name}", org_name, ["CM - Configuration Management"]),
            "purpose": (
                f"Configuration management of {system_name} for {org_name}, from the baselines and "
                "inventory recorded in the platform."
            ),
            "configuration_baselines": benchmarks or placeholder("configuration baselines (no STIG benchmark is loaded)"),
            "change_control_process": {
                "request": placeholder("how changes are requested"),
                "review": placeholder("who reviews changes"),
                "approval": placeholder("approval authority"),
                "testing": placeholder("pre-production testing"),
                "deployment": placeholder("deployment procedure"),
                "rollback": placeholder("rollback procedure"),
            },
            "configuration_monitoring": {
                "stig_scans_last_365_days_by_status": inputs.get("stig_scans_last_365_days_by_status", {}),
                "scheduled_tasks": [
                    t for t in inputs.get("scheduled_monitoring_tasks", []) if "stig" in t.get("task", "")
                ],
            },
            "least_functionality": placeholder("disabled ports, protocols and services"),
            "inventory_management": {
                "assets_by_type": facts.get("assets_by_type", {}),
                "endpoint_agents": facts.get("endpoint_agents", []),
                "source": "assets table and enrolled endpoint agents",
            },
            "control_implementation": {
                "family": "CM - Configuration Management",
                "controls": self._family_controls_from_data(controls_data, ["CM"]),
            },
            "software_usage_restrictions": placeholder("software usage restrictions"),
            "missing_facts": facts.get("missing_facts", []),
        }

    def generate_conmon_plan(
        self,
        org_name: str,
        system_name: str,
        controls_data: Optional[List[Dict[str, Any]]] = None,
        facts: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Continuous Monitoring Plan (CA / SI) from the beat schedule and the ConMon checks."""
        controls_data = controls_data or []
        facts = facts or {}
        inputs = inputs or {}
        checks = {
            k: {"status": v.get("status"), "reason": v.get("reason"),
                "compliance_percentage": v.get("compliance_percentage")}
            for k, v in (inputs.get("current_conmon_checks") or {}).items() if isinstance(v, dict)
        }
        return {
            "document_metadata": self._metadata(
                f"Continuous Monitoring Plan — {system_name}", org_name,
                ["CA - Security Assessment and Authorization", "SI - System and Information Integrity"]),
            "purpose": (
                f"Continuous monitoring of {system_name} for {org_name}: what the platform runs on a "
                "schedule and what its checks report today."
            ),
            "monitoring_strategy": {
                "scheduled_tasks": inputs.get("scheduled_monitoring_tasks", []),
                "control_assessments": "POST /compliance/frameworks/{id}/attest and the daily attestation sweep",
                "manual_activities": placeholder("manual monitoring activities and their frequency"),
            },
            "deliverables": [
                {
                    "name": "Monthly ConMon Report",
                    "source": "GET /audit-evidence/reports/monthly",
                    "last_cycle": inputs.get("last_conmon_cycle"),
                    "recipient": placeholder("ConMon report recipient"),
                },
                {"name": "POA&M", "source": "GET /fedramp/poam/report", "recipient": placeholder("POA&M recipient")},
            ],
            "metrics_and_indicators": checks,
            "tooling": [t.get("task") for t in inputs.get("scheduled_monitoring_tasks", [])],
            "significant_change_criteria": placeholder("significant change criteria"),
            "control_implementation": {
                "families": ["CA - Security Assessment and Authorization", "SI - System and Information Integrity"],
                "controls": self._family_controls_from_data(controls_data, ["CA", "SI"]),
            },
            "missing_facts": facts.get("missing_facts", []),
        }
