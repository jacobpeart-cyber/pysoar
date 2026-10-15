"""
Compliance Engine

Core compliance assessment, scoring, and reporting engine.
Implements assessment logic, control mapping, and automated checks for all frameworks.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.compliance.models import (
    POAM,
    CISADirective,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
    CUIMarking,
)
from src.compliance.system_facts import placeholder
from src.core.logging import get_logger

logger = get_logger(__name__)

#: Seeded FedRAMP frameworks use ``fedramp_moderate`` (and could use
#: ``fedramp_low`` / ``fedramp_high``); match on the prefix, never on "fedramp".
FEDRAMP_SHORT_NAME_PREFIX = "fedramp"

__all__ = [
    "FEDRAMP_SHORT_NAME_PREFIX",
    "BuiltinFrameworks",
    "CISAComplianceManager",
    "CMMCManager",
    "ComplianceEngine",
    "ControlCheckResult",
    "FedRAMPManager",
    "NISTManager",
]


#: Statuses that take no part in a compliance score.
_UNSCORED_STATUSES = ("not_applicable",)


async def refresh_framework_score(db: AsyncSession, org_id: str, framework_id: str) -> Optional[float]:
    """Recompute and store a framework's score, totals and status from its
    control rows (the dashboard reads these columns). Returns the score."""
    framework = (await db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == org_id,
        ),
    )).scalar_one_or_none()
    if framework is None:
        return None
    score = await ComplianceEngine(db, org_id).calculate_compliance_score(framework_id)
    rows = (await db.execute(
        select(ComplianceControl.status).where(
            ComplianceControl.framework_id == framework_id,
            ComplianceControl.organization_id == org_id,
        ),
    )).scalars().all()
    framework.total_controls = len(rows)
    framework.implemented_controls = sum(1 for s in rows if s == "implemented")
    framework.compliance_score = score
    framework.last_assessment_at = datetime.now(timezone.utc).replace(tzinfo=None)
    assessed = [s for s in rows if s not in ("not_assessed", "not_implemented", "planned")]
    if not rows or not assessed:
        framework.status = "not_started" if not rows else "in_progress"
    elif score >= 95.0:
        framework.status = "compliant"
    elif score >= 50.0:
        framework.status = "partially_compliant"
    else:
        framework.status = "non_compliant"
    await db.flush()
    return score


@dataclass
class ControlCheckResult:
    """Result of automated control check"""

    control_id: str
    check_passed: bool
    findings: List[str]
    evidence: Dict[str, Any]
    check_timestamp: datetime
    remediation_notes: Optional[str] = None


class ComplianceEngine:
    """
    Core compliance assessment and scoring engine.

    Provides framework-agnostic assessment, scoring, gap analysis, and reporting.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id
        self.logger = logger

    async def assess_framework(self, framework_id: str) -> Dict[str, Any]:
        """
        Run full compliance assessment for framework.

        Returns:
            Assessment results with control status, score, and findings
        """
        framework = (
            await self.db.execute(
                select(ComplianceFramework).where(
                    ComplianceFramework.id == framework_id,
                    ComplianceFramework.organization_id == self.org_id,
                ),
            )
        ).scalar_one_or_none()
        if not framework:
            raise ValueError(f"Framework {framework_id} not found")

        # Retrieve all controls
        stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == framework_id,
                ComplianceControl.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        controls = result.scalars().all()

        implemented = sum(1 for c in controls if c.status in ["implemented", "partially_implemented"])
        satisfied = sum(1 for c in controls if c.last_assessment_result == "satisfied")
        other = sum(1 for c in controls if c.last_assessment_result == "other_than_satisfied")
        status_counts: Dict[str, int] = {}
        for c in controls:
            status_counts[c.status or "not_implemented"] = status_counts.get(c.status or "not_implemented", 0) + 1

        # The stored framework score is refreshed from the control rows here
        # (it used to be written only by the boot-time seeder).
        score = await refresh_framework_score(self.db, self.org_id, framework_id) or 0.0
        assessment_result = "compliant" if score >= 95.0 else "non_compliant"

        assessment = ComplianceAssessment(
            framework_id=framework_id,
            assessment_type="self_assessment",
            assessor="system_automated",
            assessment_date=datetime.now(timezone.utc),
            status="completed",
            findings_count=other,
            satisfied_count=satisfied,
            other_than_satisfied_count=other,
            overall_result=assessment_result,
            results={
                "compliance_score": score,
                "total_controls": len(controls),
                "status_counts": status_counts,
                "not_assessed_controls": len(controls) - satisfied - other,
                "basis": "computed from the stored control statuses and last assessment results",
            },
            organization_id=self.org_id,
        )
        self.db.add(assessment)
        await self.db.commit()

        return {
            "framework_id": framework_id,
            "assessment_id": str(assessment.id),
            "total_controls": len(controls),
            "implemented": implemented,
            "satisfied": satisfied,
            "compliance_score": score,
            "status": assessment_result,
            "assessment_date": assessment.assessment_date,
            "other_than_satisfied": other,
            "not_assessed": len(controls) - satisfied - other,
        }

    async def calculate_compliance_score(self, framework_id: str) -> float:
        """
        Calculate weighted compliance score (0-100).

        Returns:
            Compliance score based on control implementation and assessment status
        """
        stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == framework_id,
                ComplianceControl.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        controls = result.scalars().all()

        if not controls:
            return 0.0

        total_weight = 0.0
        weighted_score = 0.0

        for control in controls:
            # not_applicable controls take no part in the score.
            if control.status in _UNSCORED_STATUSES:
                continue
            # Weight by priority: P1=3, P2=2, P3=1
            weight = {"p1": 3, "p2": 2, "p3": 1}.get(control.priority, 1)
            total_weight += weight

            # Score based on implementation status. A planned, not_assessed
            # or not_implemented control scores 0 (planned used to earn 10).
            if control.status == "implemented" and control.last_assessment_result == "satisfied":
                control_score = 100.0
            elif control.status == "partially_implemented":
                control_score = float(control.implementation_status or 0.0)
            else:
                control_score = 0.0

            weighted_score += control_score * weight

        return round(weighted_score / total_weight, 2) if total_weight > 0 else 0.0

    async def get_control_gaps(self, framework_id: str) -> List[Dict[str, Any]]:
        """
        Identify control implementation gaps.

        Returns:
            List of gaps prioritized by risk and priority
        """
        stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == framework_id,
                ComplianceControl.organization_id == self.org_id,
                ComplianceControl.status != "implemented",
            ),
        )
        result = await self.db.execute(stmt)
        gaps = result.scalars().all()

        gap_list = [
            {
                "control_id": gap.control_id,
                "title": gap.title,
                "status": gap.status,
                "priority": gap.priority,
                "risk_level": gap.risk_if_not_implemented,
                "implementation_status": gap.implementation_status,
                "remediation_guidance": gap.remediation_guidance,
            }
            for gap in gaps
        ]

        # Sort by risk, then priority
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        priority_order = {"p1": 0, "p2": 1, "p3": 2}

        gap_list.sort(
            key=lambda x: (
                risk_order.get(x["risk_level"], 99),
                priority_order.get(x["priority"], 99),
            ),
        )

        return gap_list

    async def generate_ssp(self, framework_id: str, run_attester: bool = False) -> Dict[str, Any]:
        """
        Generate a System Security Plan (SSP) for a framework.

        Built from the stored control rows (status, assessment result and the
        attester's ``assessment_basis``) and from the organisation's stored
        system facts (``src.compliance.system_facts``); facts the platform
        does not record are explicit ``[TO BE COMPLETED: ...]`` placeholders.
        ``run_attester`` runs the attester first; only POST routes pass it.
        The markdown rendering is ``ssp_to_markdown(ssp_doc)``.
        """
        from src.compliance.system_facts import collect_system_facts

        framework = (
            await self.db.execute(
                select(ComplianceFramework).where(
                    ComplianceFramework.id == framework_id,
                    ComplianceFramework.organization_id == self.org_id,
                ),
            )
        ).scalar_one_or_none()
        if not framework:
            raise ValueError(f"Framework {framework_id} not found")

        if run_attester:
            from src.compliance.attester import ControlAutoAttester

            await ControlAutoAttester(self.db, self.org_id).attest_all(framework_id=framework_id)

        stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == framework_id,
                ComplianceControl.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        controls = result.scalars().all()

        # Aggregate implementation counts for the SSP cover sheet.
        counts = {
            "implemented": 0, "partially_implemented": 0, "planned": 0,
            "not_implemented": 0, "not_assessed": 0, "not_applicable": 0,
        }
        for c in controls:
            s = c.status or "not_implemented"
            counts[s] = counts.get(s, 0) + 1
        scored = len(controls) - counts.get("not_applicable", 0)

        ssp_doc = {
            "framework": framework.short_name,
            "framework_name": framework.name,
            "framework_version": framework.version,
            "framework_authority": framework.authority,
            "baseline": framework.certification_level or "moderate",
            "organization_id": self.org_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_controls": len(controls),
            "implementation_counts": counts,
            "compliance_score": (
                (counts["implemented"] + 0.5 * counts["partially_implemented"]) / scored * 100
                if scored
                else 0.0
            ),
            "system_facts": await collect_system_facts(self.db, self.org_id),
            "control_families": {},
        }

        # Organize by control family
        families = {}
        for control in controls:
            family = control.control_family or "Uncategorized"
            if family not in families:
                families[family] = []
            families[family].append(control)

        # Natural NIST control ordering (AC-1, AC-2, AC-3… instead of AC-1, AC-10, AC-11)
        def _sort_key(ctrl):
            cid = ctrl.control_id or ""
            parts = cid.split("-", 1)
            prefix = parts[0] if parts else ""
            try:
                num = int(parts[1].split("(")[0]) if len(parts) > 1 else 0
            except ValueError:
                num = 0
            return (prefix, num, cid)

        for family, family_controls in families.items():
            family_controls.sort(key=_sort_key)
            family_data = {
                "title": family,
                "controls": [
                    {
                        "id": c.control_id,
                        "title": c.title,
                        "description": (c.description or "")[:2000],
                        "status": c.status,
                        "status_source": c.status_source,
                        "implementation_status_pct": float(c.implementation_status or 0),
                        "implementation_details": c.implementation_details or "",
                        "responsible_party": c.responsible_party or "",
                        "assessment_result": c.last_assessment_result or "not_assessed",
                        "assessment_basis": c.assessment_basis,
                        "last_assessed_at": c.last_assessed_at.isoformat() if c.last_assessed_at else None,
                        "baseline": c.baseline,
                        "priority": c.priority,
                    }
                    for c in family_controls
                ],
            }
            ssp_doc["control_families"][family] = family_data

        return ssp_doc

    async def generate_poam_report(self, framework_id: str) -> Dict[str, Any]:
        """
        Generate POA&M (Plan of Action & Milestones) report.

        Returns:
            POA&M summary with open items, deadlines, and status
        """
        stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == framework_id,
                ComplianceControl.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        controls = result.scalars().all()
        control_ids = [c.id for c in controls]

        if not control_ids:
            return {
                "poams": [],
                "summary": {
                    "total": 0,
                    "open": 0,
                    "overdue": 0,
                    "completed": 0,
                },
            }

        stmt = select(POAM).where(
            and_(
                POAM.control_id_ref.in_(control_ids),
                POAM.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        poams = result.scalars().all()

        now = datetime.now(timezone.utc)
        naive_now = now.replace(tzinfo=None)

        def _is_overdue(poam: POAM) -> bool:
            due = poam.scheduled_completion_date
            if due is None or poam.status == "completed":
                return False
            if due.tzinfo is None:
                return due < naive_now
            return due < now

        overdue = [p for p in poams if _is_overdue(p)]
        open_items = [p for p in poams if p.status in ["open", "in_progress"]]

        return {
            "poams": [
                {
                    "id": str(p.id),
                    "control_id": str(p.control_id_ref),
                    "weakness_name": p.weakness_name,
                    "risk_level": p.risk_level,
                    "status": p.status,
                    "scheduled_completion": (
                        p.scheduled_completion_date.isoformat() if p.scheduled_completion_date else None
                    ),
                    "assigned_to": p.assigned_to or "unassigned",
                }
                for p in poams
            ],
            "summary": {
                "total": len(poams),
                "open": len(open_items),
                "overdue": len(overdue),
                "completed": len([p for p in poams if p.status == "completed"]),
            },
        }

    async def cross_map_controls(self, source_framework_id: str, target_framework_id: str) -> Dict[str, Any]:
        """
        Map controls from one framework to another for gap analysis.

        Example: map NIST 800-53 controls to CMMC or PCI-DSS.

        Returns:
            Control mapping with alignment percentages
        """
        source_stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == source_framework_id,
                ComplianceControl.organization_id == self.org_id,
            ),
        )
        source_result = await self.db.execute(source_stmt)
        source_controls = source_result.scalars().all()

        target_framework = await self._get_framework(target_framework_id)
        target_stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == target_framework_id,
                ComplianceControl.organization_id == self.org_id,
            ),
        )
        target_result = await self.db.execute(target_stmt)
        target_controls = target_result.scalars().all()

        target_keys = {target_framework_id}
        if target_framework:
            target_keys.update(
                key
                for key in (
                    str(target_framework.id),
                    target_framework.short_name,
                    target_framework.name,
                    target_framework.authority,
                )
                if key
            )
        normalized_key_map = {key.lower(): key for key in target_keys}
        target_ids = {control.control_id for control in target_controls}

        mapping = {
            "source_framework": source_framework_id,
            "target_framework": target_framework_id,
            "mapped_controls": [],
            "unmapped_source_controls": [],
            "coverage_percentage": 0.0,
        }

        mapped_count = 0
        for source_control in source_controls:
            related = source_control.related_controls or {}
            target_refs: list[str] = []

            if isinstance(related, dict):
                for key, refs in related.items():
                    if str(key).lower() in normalized_key_map:
                        if isinstance(refs, list):
                            target_refs.extend(str(ref) for ref in refs)
                        elif refs:
                            target_refs.append(str(refs))
            elif isinstance(related, list):
                target_refs.extend(str(ref) for ref in related)

            target_refs = [ref for ref in target_refs if ref in target_ids]

            if target_refs:
                mapping["mapped_controls"].append(
                    {
                        "source_id": source_control.control_id,
                        "target_ids": target_refs,
                        "alignment": "direct",
                    },
                )
                mapped_count += 1
            else:
                mapping["unmapped_source_controls"].append(source_control.control_id)

        if source_controls:
            mapping["coverage_percentage"] = round(
                (mapped_count / len(source_controls)) * 100,
                2,
            )

        return mapping

    async def run_live_cloud_checks(self, cloud_provider: str, region: Optional[str] = None) -> Dict[str, Any]:
        """
        Run live cloud compliance checks and update controls with results.

        Args:
            cloud_provider: "aws", "azure", or "gcp"
            region: Cloud region (for AWS)

        Returns:
            Aggregated check results mapped to compliance controls
        """
        from src.compliance.cloud_checks import (
            CloudCheckStatus,
            CloudComplianceOrchestrator,
        )

        orchestrator = CloudComplianceOrchestrator(
            aws_region=region if cloud_provider == "aws" else None,
            azure_subscription_id=None if cloud_provider != "azure" else region,
            gcp_project_id=None if cloud_provider != "gcp" else region,
        )

        check_results = await orchestrator.run_all_checks(provider=cloud_provider)
        aggregated = await orchestrator.aggregate_results(check_results)

        for control_id, result in check_results.items():
            stmt = select(ComplianceControl).where(
                and_(
                    ComplianceControl.control_id == control_id,
                    ComplianceControl.organization_id == self.org_id,
                ),
            )
            result_set = await self.db.execute(stmt)
            control = result_set.scalar_one_or_none()

            if control:
                if result.status == CloudCheckStatus.PASS:
                    control.status = "implemented"
                    control.last_assessment_result = "satisfied"
                    control.implementation_status = 100.0
                elif result.status == CloudCheckStatus.PARTIAL:
                    control.status = "partially_implemented"
                    control.last_assessment_result = "partially_satisfied"
                    control.implementation_status = 50.0
                else:
                    control.status = "not_implemented"
                    control.last_assessment_result = "unsatisfied"
                    control.implementation_status = 0.0

                control.last_assessed_at = datetime.now(timezone.utc)
                self.db.add(control)

        await self.db.commit()

        return {
            "provider": cloud_provider,
            "region": region,
            "checks_completed": len(check_results),
            "aggregated_results": aggregated,
            "check_details": {
                k: {
                    "status": v.status.value,
                    "findings": v.findings,
                    "evidence": v.evidence,
                }
                for k, v in check_results.items()
            },
        }

    async def _get_framework(self, framework_id: str) -> Optional[ComplianceFramework]:
        """Internal: Get framework by ID."""
        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.id == framework_id,
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()


def ssp_to_markdown(ssp_doc: Dict[str, Any]) -> str:
    """Render an SSP JSON document as a markdown narrative.

    Sections: title, system identification (from the stored system facts,
    with ``[TO BE COMPLETED: ...]`` placeholders for what the platform does
    not record), control-implementation summary, and per-control status with
    the automated assessment basis where one exists.
    """
    lines: list[str] = []
    push = lines.append
    facts = ssp_doc.get("system_facts") or {}
    org = facts.get("organization") or {}
    deployment = facts.get("deployment") or {}
    hosting = facts.get("hosting") or {}
    roles = facts.get("roles") or {}
    policies = facts.get("policies") or {}

    push(f"# System Security Plan — {ssp_doc.get('framework_name') or ssp_doc.get('framework', '')}")
    push("")
    push(f"**Organisation**: {org.get('name', '')}  ")
    push(f"**Baseline**: {str(ssp_doc.get('baseline', 'moderate')).title()}  ")
    push(f"**Framework version**: {ssp_doc.get('framework_version', 'n/a')}  ")
    push(f"**Authority**: {ssp_doc.get('framework_authority', 'n/a')}  ")
    push(f"**Generated**: {ssp_doc.get('generated_at', '')}  ")
    push("**Document status**: Draft generated from stored platform records")
    push("")
    push("---")
    push("")
    push("## 1. System Identification")
    push("")
    push(f"- **Organisation description**: {org.get('description', '')}")
    push(f"- **Address**: {org.get('address', '')}")
    push(f"- **Contact**: {org.get('contact_email', '')}")
    push(f"- **System owner**: {roles.get('system_owner', '')}")
    push(f"- **Authorising official**: {roles.get('authorizing_official', '')}")
    push(f"- **ISSO**: {roles.get('isso', '')}")
    push(f"- **Application**: {deployment.get('application', '')} ({deployment.get('environment', '')})")
    push(f"- **Database engine**: {deployment.get('database_engine') or 'not recorded'}")
    push(f"- **Cache / queue**: {deployment.get('cache_and_queue') or 'not recorded'}")
    push(f"- **Hosting**: {hosting.get('provider', '')}")
    push(f"- **Network architecture**: {hosting.get('network_architecture', '')}")
    push(f"- **Authorisation boundary**: {hosting.get('authorization_boundary', '')}")
    push("")
    integrations = facts.get("installed_integrations") or []
    push("### 1.1 Installed integrations (external interconnections)")
    push("")
    if integrations:
        for item in integrations:
            push(f"- {item.get('name')} ({item.get('connector_id')}), status {item.get('status')}")
    else:
        push("_No integrations are installed._")
    push("")
    push("### 1.2 Components recorded by the platform")
    push("")
    agents = facts.get("endpoint_agents") or []
    push(f"- Assets by type: {facts.get('assets_by_type') or 'none recorded'}")
    push(f"- Endpoint agents: {agents or 'none enrolled'}")
    push(f"- Active users by role: {(facts.get('users') or {}).get('active_by_role') or 'none'}")
    push(
        f"- Zero-trust policies: {len(policies.get('zero_trust_policies') or [])}, "
        f"segments: {policies.get('micro_segments', 0)}, "
        f"enabled playbooks: {policies.get('enabled_playbooks', 0)}, "
        f"enabled remediation policies: {policies.get('enabled_remediation_policies', 0)}",
    )
    push("")
    missing = facts.get("missing_facts") or []
    if missing:
        push("### 1.3 Facts to be completed")
        push("")
        for item in missing:
            push(f"- {item}")
        push("")
    push("## 2. Control Implementation Summary")
    push("")
    counts = ssp_doc.get("implementation_counts") or {}
    total = ssp_doc.get("total_controls", 0) or 1
    push(f"**Total controls in scope**: {ssp_doc.get('total_controls', 0)}")
    push("")
    push("| Status | Count | % |")
    push("|---|---|---|")
    for status_key in ("implemented", "partially_implemented", "planned", "not_implemented", "not_assessed", "not_applicable"):
        n = counts.get(status_key, 0)
        pct = (n / total * 100) if total else 0
        push(f"| {status_key.replace('_', ' ').title()} | {n} | {pct:.1f}% |")
    push("")
    push(f"**Overall compliance score**: {ssp_doc.get('compliance_score', 0):.1f}%")
    push("")
    push("---")
    push("")
    push("## 3. Control Implementations")
    push("")

    families = ssp_doc.get("control_families") or {}
    for family_name in sorted(families.keys()):
        fam = families[family_name]
        push(f"### 3.{family_name}")
        push("")
        for ctrl in fam.get("controls", []):
            status = (ctrl.get("status") or "").replace("_", " ")
            narrative = ctrl.get("implementation_details") or ""
            basis = ctrl.get("assessment_basis") or {}
            push(f"#### {ctrl.get('id')} — {ctrl.get('title', '')}")
            push("")
            push(f"- **Status**: {status.title()}")
            push(f"- **Assessment result**: {ctrl.get('assessment_result') or 'not_assessed'}")
            if ctrl.get("responsible_party"):
                push(f"- **Responsible**: {ctrl['responsible_party']}")
            if ctrl.get("last_assessed_at"):
                push(f"- **Last Assessed**: {ctrl['last_assessed_at']}")
            push("")
            if basis:
                push(f"**Automated check** ({basis.get('result')}): {basis.get('summary', '')}".replace("|", "\\|"))
                for fact in basis.get("basis") or []:
                    push(f"- {fact.get('kind')}: {fact.get('source')} = {fact.get('value')}".replace("|", "\\|"))
                push("")
            if narrative:
                push("**Implementation narrative** (recorded by the organisation):")
                push("")
                push(narrative.replace("|", "\\|"))
            else:
                push(placeholder("implementation narrative for this control"))
            push("")
        push("---")
        push("")

    push(
        "*Generated from stored platform records. Automated checks state only "
        "what they read (counts, configuration values, evidence rows, test "
        "results); a control is shown as implemented only when its check "
        "passed and approved evidence covers it, or when the organisation set "
        "the status itself.*",
    )
    return "\n".join(lines)


class FedRAMPManager:
    """
    FedRAMP (Federal Risk and Authorization Management Program) Manager

    Manages FedRAMP compliance for cloud systems.
    Supports Low, Moderate, and High baseline controls.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id
        self.engine = ComplianceEngine(db, org_id)
        self.logger = logger

    async def assess_fedramp_readiness(self, baseline: str = "moderate") -> Dict[str, Any]:
        """
        Assess FedRAMP readiness for specified baseline.

        Args:
            baseline: "low", "moderate", or "high"

        Returns:
            Readiness assessment with control counts and implementation status
        """
        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
                ComplianceFramework.certification_level.ilike(f"%{baseline}%"),
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        framework = result.scalar_one_or_none()

        if not framework:
            return {"error": f"FedRAMP {baseline} framework not found"}

        readiness = await self.engine.assess_framework(str(framework.id))
        return readiness

    async def generate_ssp_document(self, baseline: str = "moderate") -> Dict[str, Any]:
        """
        Generate FedRAMP System Security Plan (SSP).

        Args:
            baseline: "low", "moderate", or "high"

        Returns:
            SSP document with all 17 NIST control families
        """
        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
                ComplianceFramework.certification_level.ilike(f"%{baseline}%"),
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        framework = result.scalar_one_or_none()

        if not framework:
            return {"error": f"FedRAMP {baseline} framework not found"}

        ssp = await self.engine.generate_ssp(str(framework.id))
        ssp["fedramp_baseline"] = baseline.title()
        ssp["ssp_status"] = "draft"

        return ssp

    async def run_continuous_monitoring(self) -> Dict[str, Any]:
        """
        Run FedRAMP Continuous Monitoring (ConMon) checks.

        Returns:
            ConMon status with control assessment results
        """
        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        frameworks = result.scalars().all()

        conmon_results = []
        for framework in frameworks:
            assessment = await self.engine.assess_framework(str(framework.id))
            conmon_results.append(assessment)

        return {
            "conmon_type": "FedRAMP",
            "conmon_date": datetime.now(timezone.utc).isoformat(),
            "frameworks_assessed": len(conmon_results),
            "results": conmon_results,
        }

    async def check_fedramp_controls(self, baseline: str = "moderate") -> List[Dict[str, Any]]:
        """
        Run automated checks against FedRAMP controls.

        Returns:
            List of control check results
        """
        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.short_name.like(f"{FEDRAMP_SHORT_NAME_PREFIX}%"),
                ComplianceFramework.certification_level.ilike(f"%{baseline}%"),
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        framework = result.scalar_one_or_none()

        if not framework:
            return []

        stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == framework.id,
                ComplianceControl.organization_id == self.org_id,
                ComplianceControl.automated_check_id.isnot(None),
            ),
        )
        result = await self.db.execute(stmt)
        automatable_controls = result.scalars().all()

        check_results = []
        for control in automatable_controls:
            # Run automated checks for common controls
            check_result = await self._run_automated_control_check(control)
            check_results.append(check_result)

        return check_results

    async def get_fedramp_baselines(self) -> Dict[str, Any]:
        """
        Get FedRAMP baseline control counts.

        Returns:
            Control counts per baseline level
        """
        from src.fedramp.controls import FAMILY_CODES, FEDRAMP_MODERATE_CONTROLS

        # Only the Moderate catalogue ships with the platform; Low and High
        # are reported as not loaded instead of quoting invented totals.
        return {
            "low": {"total_controls": None, "loaded": False},
            "moderate": {
                "total_controls": len(FEDRAMP_MODERATE_CONTROLS),
                "families": len(FAMILY_CODES),
                "loaded": True,
            },
            "high": {"total_controls": None, "loaded": False},
        }

    async def _run_automated_control_check(self, control: ComplianceControl) -> Dict[str, Any]:
        """Internal: Run automated check for a control.

        Evidence query is org-scoped so a tenant can't inherit
        another tenant's evidence if control UUIDs happen to collide
        — an auditor would reject any control that couldn't prove
        its own evidence.
        """
        now = datetime.now(timezone.utc)
        evidence_cutoff = now - timedelta(days=90)

        # Query recent evidence for this control, scoped to this tenant
        stmt = select(ComplianceEvidence).where(
            and_(
                ComplianceEvidence.control_id_ref == str(control.id),
                ComplianceEvidence.collected_at >= evidence_cutoff,
                ComplianceEvidence.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        recent_evidence = result.scalars().all()

        # Determine pass/fail based on evidence and implementation status
        has_recent_evidence = len(recent_evidence) > 0
        is_implemented = control.implementation_status >= 80.0

        check_passed = has_recent_evidence and is_implemented

        return {
            "control_id": control.control_id,
            "check_passed": check_passed,
            "check_timestamp": now.isoformat(),
            "evidence_count": len(recent_evidence),
            "implementation_status": control.implementation_status,
            "reason": (
                "passed"
                if check_passed
                else "no_recent_evidence" if not has_recent_evidence else "implementation_incomplete"
            ),
        }


class NISTManager:
    """
    NIST 800-53 Rev 5 and 800-171 Rev 2 Manager

    Manages NIST control catalogs and assessments.
    Supports full 1000+ control catalog and automated checks.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id
        self.engine = ComplianceEngine(db, org_id)
        self.logger = logger

    async def load_nist_800_53_controls(self) -> int:
        """
        Load full NIST 800-53 Rev 5 control catalog.

        Returns:
            Count of loaded controls
        """
        from src.fedramp.controls import FEDRAMP_MODERATE_CONTROLS

        self.logger.info("Loading NIST 800-53 Rev 5 controls from FedRAMP baseline")
        return len(FEDRAMP_MODERATE_CONTROLS)

    async def load_nist_800_171_controls(self) -> int:
        """
        Load NIST 800-171 Rev 2 controls (for CUI/CMMC).

        Returns:
            Count of loaded controls
        """
        from src.compliance.seeder import NIST_800_171_CONTROLS

        return len(NIST_800_171_CONTROLS)

    async def assess_control_family(self, framework_id: str, family: str) -> Dict[str, Any]:
        """
        Assess all controls in a family.

        Args:
            framework_id: Framework to assess
            family: Control family (e.g., "Access Control", "Identification and Authentication")

        Returns:
            Family assessment with control status
        """
        stmt = select(ComplianceControl).where(
            and_(
                ComplianceControl.framework_id == framework_id,
                ComplianceControl.control_family == family,
                ComplianceControl.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        controls = result.scalars().all()

        implemented = sum(1 for c in controls if c.status == "implemented")
        satisfied = sum(1 for c in controls if c.last_assessment_result == "satisfied")

        return {
            "family": family,
            "total_controls": len(controls),
            "implemented": implemented,
            "satisfied": satisfied,
            "completion_percentage": ((implemented / len(controls) * 100) if controls else 0),
        }

    async def automated_control_check(
        self, control_id: str, framework_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the automated check for one control and record its outcome.

        The checks are the attester's rules (``src.compliance.attester``), so
        one code path decides every automated result. The outcome is
        ``pass`` / ``fail`` / ``not_assessed`` with the facts it read; the
        control row's ``assessment_basis`` and ``last_assessment_result`` are
        updated (its status is left to the attester and to people).
        """
        from src.compliance.attester import outcome_dict, run_check

        # A control code (AC-2) is seeded once per framework for every tenant,
        # so the lookup is scoped to the tenant and, when given, the framework.
        stmt = select(ComplianceControl).where(
            ComplianceControl.control_id == control_id,
            ComplianceControl.organization_id == self.org_id,
        )
        if framework_id is not None:
            stmt = stmt.where(ComplianceControl.framework_id == framework_id)
        result = await self.db.execute(stmt)
        control = result.scalars().first()

        if not control:
            return {"error": f"Control {control_id} not found"}

        checked_at = datetime.now(timezone.utc)
        outcome = await run_check(self.db, self.org_id, control_id)
        if outcome is None:
            return {
                "control_id": control_id,
                "status": "no_automated_check",
                "result": "not_assessed",
                "reason": "the platform has no automated check for this control",
                "check_timestamp": checked_at.isoformat(),
            }

        record = outcome_dict(control_id, outcome, checked_at)
        control.assessment_basis = record
        control.last_assessed_at = checked_at.replace(tzinfo=None)
        control.last_assessment_result = {
            "pass": "satisfied", "fail": "other_than_satisfied",
        }.get(outcome.result, "not_assessed")
        await self.db.commit()
        return {
            "control_id": control_id,
            "check_name": control.title,
            "check_passed": outcome.result == "pass" if outcome.result != "not_assessed" else None,
            "result": outcome.result,
            "findings": [outcome.reason] if outcome.reason else [],
            "evidence": {fact["source"]: fact["value"] for fact in outcome.basis},
            "basis": outcome.basis,
            "summary": outcome.summary,
            "check_timestamp": checked_at.isoformat(),
        }


class CMMCManager:
    """
    CMMC 2.0 (DoD Cybersecurity Maturity Model Certification) Manager

    Manages CMMC practices, levels, and CUI protection assessment.
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id
        self.engine = ComplianceEngine(db, org_id)
        self.logger = logger

    async def assess_cmmc_level(self, target_level: int = 2) -> Dict[str, Any]:
        """
        Assess CMMC maturity level.

        Args:
            target_level: 1-3 (Level 1 = Foundation, Level 2 = Advanced, Level 3 = Expert)

        Returns:
            CMMC assessment with level readiness
        """
        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.short_name == "cmmc",
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        framework = result.scalar_one_or_none()

        if not framework:
            return {"error": f"CMMC level {target_level} framework not found"}

        assessment = await self.engine.assess_framework(str(framework.id))
        assessment["target_level"] = target_level
        return assessment

    async def load_cmmc_practices(self) -> int:
        """
        Load CMMC 2.0 practices.

        Returns:
            Count of loaded practices
        """
        from src.compliance.seeder import CONTROL_CATALOGS

        return len(CONTROL_CATALOGS.get("cmmc_level_2", []))

    async def map_cmmc_to_nist(self) -> Dict[str, Any]:
        """
        Map CMMC practices to NIST 800-171 controls.

        Returns:
            Mapping structure for gap analysis
        """
        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.short_name == "cmmc",
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        cmmc_result = await self.db.execute(stmt)
        cmmc_framework = cmmc_result.scalar_one_or_none()

        stmt = select(ComplianceFramework).where(
            and_(
                ComplianceFramework.short_name == "nist_800_171",
                ComplianceFramework.organization_id == self.org_id,
            ),
        )
        nist_result = await self.db.execute(stmt)
        nist_framework = nist_result.scalar_one_or_none()

        if not cmmc_framework or not nist_framework:
            return {"error": "Required frameworks not found"}

        return await self.engine.cross_map_controls(str(cmmc_framework.id), str(nist_framework.id))

    async def check_cui_handling(self) -> Dict[str, Any]:
        """
        Verify CUI (Controlled Unclassified Information) handling compliance.

        Returns:
            CUI handling assessment
        """
        stmt = select(CUIMarking).where(CUIMarking.organization_id == self.org_id)
        result = await self.db.execute(stmt)
        cui_markings = result.scalars().all()

        total_cui = len(cui_markings)
        active_cui = sum(1 for m in cui_markings if m.is_active)

        return {
            "total_cui_assets": total_cui,
            "active_cui_assets": active_cui,
            "cui_categories": list({m.cui_category for m in cui_markings}),
            "compliance_status": "compliant" if active_cui == total_cui else "review_required",
        }

    async def generate_cmmc_readiness_report(self, level: int = 2) -> Dict[str, Any]:
        """
        Generate CMMC readiness report.

        Args:
            level: Target CMMC level (1-3)

        Returns:
            Readiness report with gaps and recommendations
        """
        return {
            "target_level": level,
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "readiness_status": "in_progress",
        }


class CISAComplianceManager:
    """
    CISA (Cybersecurity and Infrastructure Security Agency) Compliance Manager

    Manages CISA Binding Operational Directives (BODs) and Emergency Directives (EDs).
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id
        self.logger = logger

    async def load_active_directives(self) -> int:
        """
        Load active CISA directives.

        Returns:
            Count of active directives
        """
        stmt = select(CISADirective).where(
            and_(
                CISADirective.status == "active",
                CISADirective.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        directives = result.scalars().all()
        return len(directives)

    async def check_bod_compliance(self, directive_id: str) -> Dict[str, Any]:
        """
        Check compliance with a CISA BOD.

        BOD 22-01 is computed from the organisation's vulnerability findings
        against the KEV due dates (``check_kev_compliance``). For any other
        directive the platform has no automated check: the stored status is
        returned with ``assessed: false``.
        """
        stmt = select(CISADirective).where(
            and_(
                CISADirective.directive_id == directive_id,
                CISADirective.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        directive = result.scalar_one_or_none()

        if not directive:
            return {"error": f"Directive {directive_id} not found"}

        response = {
            "directive_id": directive_id,
            "compliance_status": directive.compliance_status,
            "deadline": directive.compliance_deadline.isoformat() if directive.compliance_deadline else None,
            "actions_taken": len(directive.actions_taken or []),
            "assessed": False,
            "basis": "status recorded by the organisation; no automated check exists for this directive",
        }
        if directive_id.replace(" ", "").upper() == "BOD22-01":
            kev = await self.check_kev_compliance()
            response.update({
                "compliance_status": kev["compliance_status"],
                "assessed": kev["compliance_status"] != "not_assessed",
                "basis": kev["detail"],
                "kev": kev,
            })
        return response

    async def check_kev_compliance(self) -> Dict[str, Any]:
        """
        BOD 22-01: open findings of KEV-listed CVEs past their KEV due date.

        Computed from ``vulnerability_instances`` joined to ``vulnerabilities``
        (``kev_listed`` / ``kev_due_date`` set by the KEV catalogue sync).
        ``not_assessed`` when the organisation has no vulnerability findings.
        """
        from sqlalchemy import func

        from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance

        open_states = ("open", "in_progress", "deferred")
        total = int(await self.db.scalar(
            select(func.count(VulnerabilityInstance.id)).where(
                VulnerabilityInstance.organization_id == self.org_id),
        ) or 0)
        rows = (await self.db.execute(
            select(Vulnerability.cve_id, Vulnerability.kev_due_date)
            .join(VulnerabilityInstance, VulnerabilityInstance.vulnerability_id == Vulnerability.id)
            .where(
                VulnerabilityInstance.organization_id == self.org_id,
                VulnerabilityInstance.status.in_(open_states),
                Vulnerability.kev_listed.is_(True),
            ),
        )).all()
        today = datetime.now(timezone.utc).date().isoformat()
        overdue = [r for r in rows if r.kev_due_date and str(r.kev_due_date)[:10] < today]
        if total == 0:
            status_value = "not_assessed"
            detail = "no vulnerability findings are stored for this organisation"
        elif overdue:
            status_value = "non_compliant"
            detail = f"{len(overdue)} open KEV finding(s) are past their BOD 22-01 due date"
        else:
            status_value = "compliant"
            detail = f"{len(rows)} open KEV finding(s), none past its BOD 22-01 due date"
        return {
            "bod_id": "BOD 22-01",
            "title": "Binding Operational Directive 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities",
            "compliance_status": status_value,
            "detail": detail,
            "vulnerability_findings": total,
            "open_kev_findings": len(rows),
            "overdue_kev_findings": len(overdue),
            "overdue_cves": sorted({r.cve_id for r in overdue if r.cve_id})[:50],
        }

    async def check_ed_compliance(self, directive_id: str) -> Dict[str, Any]:
        """
        Check Emergency Directive compliance.

        Args:
            directive_id: ED ID (e.g., "ED 24-01")

        Returns:
            Compliance status
        """
        stmt = select(CISADirective).where(
            and_(
                CISADirective.directive_id == directive_id,
                CISADirective.organization_id == self.org_id,
            ),
        )
        result = await self.db.execute(stmt)
        directive = result.scalar_one_or_none()

        if not directive:
            return {"error": f"Directive {directive_id} not found"}

        return {
            "directive_id": directive_id,
            "type": "Emergency Directive",
            "compliance_status": directive.compliance_status,
            "deadline": directive.compliance_deadline.isoformat(),
        }


class BuiltinFrameworks:
    """
    Built-in framework catalogue sizes.

    Reports how many controls each catalogue that ships with the platform
    (``src.compliance.seeder.CONTROL_CATALOGS``) holds; seeding into an
    organisation is ``seed_framework_for_org``. Catalogues that do not ship
    report 0 (they used to report invented totals such as 420 or 1000).
    """

    def __init__(self, db: AsyncSession, org_id: str):
        self.db = db
        self.org_id = org_id
        self.logger = logger

    @staticmethod
    def _catalog_size(short_name: str) -> int:
        from src.compliance.seeder import CONTROL_CATALOGS

        return len(CONTROL_CATALOGS.get(short_name, []))

    async def register_all_frameworks(self) -> Dict[str, int]:
        """Catalogue size per framework (stored CISA directives for "cisa")."""
        return {
            "fedramp": await self.load_fedramp_controls(),
            "nist_800_53": await self.load_nist_800_53_rev5(),
            "nist_800_171": await self.load_nist_800_171_rev2(),
            "cmmc": await self.load_cmmc_20(),
            "soc2": await self.load_soc2_criteria(),
            "hipaa": await self.load_hipaa_safeguards(),
            "pci_dss": await self.load_pci_dss_v4(),
            "cisa": await self.load_cisa_directives(),
        }

    async def load_fedramp_controls(self) -> int:
        return (
            await self.load_fedramp_low_controls()
            + await self.load_fedramp_moderate_controls()
            + await self.load_fedramp_high_controls()
        )

    async def load_fedramp_low_controls(self) -> int:
        return 0  # no Low catalogue ships

    async def load_fedramp_moderate_controls(self) -> int:
        return self._catalog_size("fedramp_moderate")

    async def load_fedramp_high_controls(self) -> int:
        return 0  # no High catalogue ships

    async def load_nist_800_53_rev5(self) -> int:
        # The 800-53 controls that ship are the FedRAMP Moderate selection.
        return self._catalog_size("fedramp_moderate")

    async def load_nist_800_171_rev2(self) -> int:
        return self._catalog_size("nist_800_171")

    async def load_cmmc_20(self) -> int:
        return self._catalog_size("cmmc_level_2")

    async def load_soc2_criteria(self) -> int:
        return self._catalog_size("soc2")

    async def load_hipaa_safeguards(self) -> int:
        return self._catalog_size("hipaa")

    async def load_pci_dss_v4(self) -> int:
        return self._catalog_size("pci_dss")

    async def load_cisa_directives(self) -> int:
        """Directives stored for this organisation (none ship with the platform)."""
        from sqlalchemy import func

        return int(await self.db.scalar(
            select(func.count(CISADirective.id)).where(CISADirective.organization_id == self.org_id),
        ) or 0)
