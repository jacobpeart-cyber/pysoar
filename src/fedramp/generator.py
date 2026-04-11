"""
FedRAMP SSP and Compliance Report Generator

Generates System Security Plans, readiness reports, POA&M reports,
and maps PySOAR features to FedRAMP Moderate baseline controls.
"""

from datetime import datetime, date
from typing import Any, Dict, List, Optional

from src.fedramp.controls import (
    FEDRAMP_MODERATE_CONTROLS,
    CONTROLS_BY_ID,
    CONTROLS_BY_FAMILY,
    FAMILY_CODES,
)


class FedRAMPGenerator:
    """Generator for FedRAMP compliance documentation and reports."""

    IMPLEMENTATION_STATUSES = [
        "implemented",
        "partially_implemented",
        "planned",
        "alternative",
        "not_applicable",
    ]

    # ------------------------------------------------------------------ SSP
    def generate_ssp(
        self,
        org_name: str,
        system_name: str,
        controls_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate a System Security Plan (SSP) document structure.

        Args:
            org_name: The name of the organization that owns the system.
            system_name: The information system name (e.g. "PySOAR").
            controls_data: Optional list of control dicts with implementation
                details.  When *None*, the full moderate baseline from
                ``controls.py`` is used with default placeholder text.

        Returns:
            A nested dict representing the full SSP in the FedRAMP
            Rev 5 template structure.
        """
        if controls_data is None:
            controls_data = FEDRAMP_MODERATE_CONTROLS

        now = datetime.utcnow().isoformat() + "Z"
        today = date.today().isoformat()

        # Build per-family control implementation sections
        family_sections = {}
        for family_code, family_name in FAMILY_CODES.items():
            family_controls = [
                c for c in controls_data if c["id"].startswith(family_code + "-")
            ]
            family_sections[family_code] = {
                "family_name": family_name,
                "controls": [
                    {
                        "control_id": c["id"],
                        "title": c.get("title", ""),
                        "description": c.get("description", ""),
                        "implementation_status": c.get(
                            "implementation_status", "planned"
                        ),
                        "pysoar_mapping": c.get("pysoar_mapping", ""),
                        "implementation_narrative": c.get(
                            "implementation_narrative",
                            f"{system_name} addresses {c['id']} through the "
                            f"{c.get('pysoar_mapping', 'relevant module')}.",
                        ),
                        "responsible_role": c.get(
                            "responsible_role", "System Administrator"
                        ),
                    }
                    for c in family_controls
                ],
            }

        ssp: Dict[str, Any] = {
            "document_metadata": {
                "title": f"System Security Plan — {system_name}",
                "version": "1.0",
                "date_prepared": today,
                "last_updated": now,
                "prepared_by": org_name,
                "fedramp_baseline": "Moderate",
                "nist_revision": "Rev 5",
                "document_status": "Draft",
            },
            "system_information": {
                "system_name": system_name,
                "system_identifier": f"{system_name.upper().replace(' ', '-')}-001",
                "system_description": (
                    f"{system_name} is a Security Orchestration, Automation and "
                    "Response (SOAR) platform that provides unified security "
                    "operations including SIEM, threat intelligence, incident "
                    "response, vulnerability management, UEBA, and compliance "
                    "management capabilities."
                ),
                "system_owner": org_name,
                "authorizing_official": f"{org_name} — Authorizing Official",
                "information_system_security_officer": f"{org_name} — ISSO",
                "security_categorization": {
                    "confidentiality": "Moderate",
                    "integrity": "Moderate",
                    "availability": "Moderate",
                    "overall": "Moderate",
                },
                "system_type": "Major Application",
                "cloud_service_model": "SaaS",
                "cloud_deployment_model": "Community Cloud",
            },
            "system_environment": {
                "hosting": {
                    "primary_provider": "AWS GovCloud",
                    "regions": ["us-gov-west-1", "us-gov-east-1"],
                    "compute": "Amazon EC2 (Docker containers on ECS/EKS)",
                    "database": "Amazon RDS for PostgreSQL (encrypted, Multi-AZ)",
                    "cache": "Amazon ElastiCache for Redis (encrypted, cluster mode)",
                    "storage": "Amazon S3 (SSE-S3 / SSE-KMS)",
                    "load_balancer": "Application Load Balancer with WAF",
                    "cdn": "Amazon CloudFront",
                },
                "software_components": [
                    {"name": "PySOAR API", "version": "latest", "language": "Python 3.12"},
                    {"name": "PostgreSQL", "version": "16.x", "role": "Primary datastore"},
                    {"name": "Redis", "version": "7.x", "role": "Cache / message broker"},
                    {"name": "Nginx", "version": "1.25.x", "role": "Reverse proxy / TLS termination"},
                    {"name": "Docker", "version": "24.x", "role": "Container runtime"},
                    {"name": "Celery", "version": "5.x", "role": "Async task processing"},
                ],
                "network_architecture": {
                    "vpc": "Dedicated VPC with public/private subnets",
                    "segmentation": "Application tier, data tier, management tier",
                    "firewalls": "Security Groups + NACLs + WAF",
                    "encryption_in_transit": "TLS 1.2+ (FIPS 140-2 validated modules)",
                    "encryption_at_rest": "AES-256 (AWS KMS with FIPS endpoints)",
                },
            },
            "information_types": [
                {
                    "type": "Security Event Data",
                    "nist_category": "C.3.5.1",
                    "confidentiality_impact": "Moderate",
                    "integrity_impact": "Moderate",
                    "availability_impact": "Moderate",
                },
                {
                    "type": "Audit Logs",
                    "nist_category": "D.3.1.1",
                    "confidentiality_impact": "Moderate",
                    "integrity_impact": "High",
                    "availability_impact": "Moderate",
                },
                {
                    "type": "Threat Intelligence",
                    "nist_category": "C.3.5.2",
                    "confidentiality_impact": "Moderate",
                    "integrity_impact": "Moderate",
                    "availability_impact": "Low",
                },
                {
                    "type": "Incident Records",
                    "nist_category": "C.3.5.3",
                    "confidentiality_impact": "Moderate",
                    "integrity_impact": "High",
                    "availability_impact": "Moderate",
                },
                {
                    "type": "Vulnerability Data",
                    "nist_category": "C.3.5.4",
                    "confidentiality_impact": "Moderate",
                    "integrity_impact": "Moderate",
                    "availability_impact": "Low",
                },
                {
                    "type": "User Identity Information",
                    "nist_category": "D.5.1",
                    "confidentiality_impact": "Moderate",
                    "integrity_impact": "Moderate",
                    "availability_impact": "Moderate",
                },
            ],
            "authorization_boundary": {
                "description": (
                    f"The {system_name} authorization boundary encompasses all "
                    "components deployed within the AWS GovCloud VPC, including "
                    "application servers, databases, caches, load balancers, and "
                    "management infrastructure.  External integrations (SIEM feeds, "
                    "threat intel sources, ticketing systems) connect via encrypted "
                    "API channels and are documented as interconnections."
                ),
                "components_in_boundary": [
                    "PySOAR Application Servers (Docker/ECS)",
                    "PostgreSQL Database (RDS Multi-AZ)",
                    "Redis Cache Cluster (ElastiCache)",
                    "Nginx Reverse Proxy",
                    "Celery Worker Nodes",
                    "Application Load Balancer",
                    "AWS WAF",
                    "S3 Evidence / Artifact Storage",
                    "CloudWatch Logging",
                    "AWS KMS Encryption Keys",
                ],
                "external_interconnections": [
                    "Threat Intelligence Feeds (TAXII/STIX)",
                    "Ticketing Systems (Jira, ServiceNow)",
                    "Email / Notification Services (SES)",
                    "Identity Provider (SAML/OIDC SSO)",
                    "Vulnerability Scanners (API)",
                ],
            },
            "security_controls": family_sections,
            "control_summary": {
                "total_controls": len(controls_data),
                "families_covered": len(family_sections),
                "baseline": "FedRAMP Moderate",
            },
        }
        return ssp

    # ---------------------------------------------------------- Readiness
    def generate_readiness_report(
        self,
        controls_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generate a FedRAMP readiness assessment report.

        Args:
            controls_data: List of control dicts, each optionally containing
                an ``implementation_status`` key.  Defaults to the full
                moderate baseline (all treated as *planned*).

        Returns:
            Dict with readiness score, per-family breakdown, gap analysis,
            and prioritized recommendations.
        """
        if controls_data is None:
            controls_data = FEDRAMP_MODERATE_CONTROLS

        total = len(controls_data)
        status_counts: Dict[str, int] = {s: 0 for s in self.IMPLEMENTATION_STATUSES}

        family_stats: Dict[str, Dict[str, Any]] = {}
        gaps: List[Dict[str, str]] = []

        for ctrl in controls_data:
            st = ctrl.get("implementation_status", "planned")
            status_counts[st] = status_counts.get(st, 0) + 1

            fam = ctrl.get("family", "Unknown")
            if fam not in family_stats:
                family_stats[fam] = {"total": 0, "implemented": 0, "gaps": []}
            family_stats[fam]["total"] += 1

            if st == "implemented":
                family_stats[fam]["implemented"] += 1
            elif st in ("planned", "partially_implemented"):
                gap_entry = {
                    "control_id": ctrl["id"],
                    "title": ctrl.get("title", ""),
                    "family": fam,
                    "current_status": st,
                    "priority": ctrl.get("priority", "P3"),
                    "pysoar_mapping": ctrl.get("pysoar_mapping", ""),
                    "recommendation": (
                        f"Complete implementation of {ctrl['id']} via "
                        f"{ctrl.get('pysoar_mapping', 'the mapped module')}."
                    ),
                }
                gaps.append(gap_entry)
                family_stats[fam]["gaps"].append(gap_entry)

        implemented = status_counts.get("implemented", 0)
        partial = status_counts.get("partially_implemented", 0)
        readiness_score = round(
            ((implemented + 0.5 * partial) / total) * 100, 2
        ) if total else 0.0

        # Compute per-family readiness
        for fam, stats in family_stats.items():
            t = stats["total"]
            stats["readiness_pct"] = (
                round((stats["implemented"] / t) * 100, 2) if t else 0.0
            )

        # Sort gaps by priority (P1 first)
        priority_order = {"P1": 0, "P2": 1, "P3": 2}
        gaps.sort(key=lambda g: priority_order.get(g.get("priority", "P3"), 3))

        return {
            "report_title": "FedRAMP Moderate Readiness Assessment",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "overall_readiness_score": readiness_score,
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
            "recommendations": [
                {
                    "priority": "Critical",
                    "action": "Address all P1 gaps before FedRAMP assessment.",
                },
                {
                    "priority": "High",
                    "action": "Complete implementation narratives for every control.",
                },
                {
                    "priority": "High",
                    "action": "Collect evidence artifacts for all implemented controls.",
                },
                {
                    "priority": "Medium",
                    "action": "Conduct internal control assessment / tabletop review.",
                },
                {
                    "priority": "Medium",
                    "action": "Engage a 3PAO for an independent readiness assessment.",
                },
            ],
        }

    # ------------------------------------------------------------- POA&M
    def generate_poam_report(
        self,
        poams: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate a formatted Plan of Action and Milestones report.

        Args:
            poams: List of POA&M item dicts.  Each should include at least:
                ``poam_id``, ``control_id``, ``weakness_description``,
                ``severity``, ``status``, ``scheduled_completion_date``,
                ``milestones``, ``responsible_party``.

        Returns:
            Formatted POA&M report dict.
        """
        now = datetime.utcnow().isoformat() + "Z"

        severity_order = {"critical": 0, "high": 1, "moderate": 2, "low": 3}
        sorted_poams = sorted(
            poams,
            key=lambda p: severity_order.get(
                p.get("severity", "low").lower(), 4
            ),
        )

        status_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        overdue: List[Dict[str, Any]] = []

        for p in sorted_poams:
            s = p.get("status", "open")
            status_counts[s] = status_counts.get(s, 0) + 1

            sev = p.get("severity", "low").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            due = p.get("scheduled_completion_date")
            if due and s != "closed":
                if isinstance(due, str):
                    try:
                        due_dt = datetime.fromisoformat(due)
                    except ValueError:
                        due_dt = None
                elif isinstance(due, (date, datetime)):
                    due_dt = datetime.combine(due, datetime.min.time()) if isinstance(due, date) else due
                else:
                    due_dt = None

                if due_dt and due_dt < datetime.utcnow():
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
                "risk_acceptance": p.get("risk_acceptance", False),
                "comments": p.get("comments", ""),
            })

        return {
            "report_title": "Plan of Action and Milestones (POA&M)",
            "generated_at": now,
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
                    "scheduled_completion_date": str(
                        o.get("scheduled_completion_date", "")
                    ),
                    "severity": o.get("severity", ""),
                }
                for o in overdue
            ],
        }

    # ------------------------------------------------ Control Status Query
    async def get_control_implementation_status(
        self,
        db: Any,
        organization_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query the compliance controls table and map results to the
        FedRAMP Moderate baseline (tenant-scoped).

        Args:
            db: An async SQLAlchemy session.
            organization_id: Tenant id. Queries filter by this when provided.

        Returns:
            List of control dicts enriched with their persisted
            implementation status and evidence references.
        """
        persisted: Dict[str, Dict[str, Any]] = {}
        try:
            from src.compliance.models import ComplianceControl  # noqa: F811
            from sqlalchemy import select as sa_select

            stmt = sa_select(ComplianceControl).where(
                ComplianceControl.framework == "FedRAMP"
            )
            if organization_id is not None and hasattr(
                ComplianceControl, "organization_id"
            ):
                stmt = stmt.where(
                    ComplianceControl.organization_id == organization_id
                )

            result = await db.scalars(stmt)
            rows = result.all()

            for row in rows:
                persisted[row.control_id] = {
                    "implementation_status": getattr(row, "status", "planned"),
                    "evidence_artifacts": getattr(row, "evidence_artifacts", []),
                    "last_assessed": str(getattr(row, "last_assessed", "")),
                    "assessor_notes": getattr(row, "assessor_notes", ""),
                }
        except Exception as exc:
            # Fall back to empty mapping — log so the failure isn't silent
            import logging
            logging.getLogger(__name__).warning(
                f"FedRAMP generator DB query failed: {exc}"
            )
            persisted = {}

        enriched: List[Dict[str, Any]] = []
        for ctrl in FEDRAMP_MODERATE_CONTROLS:
            entry = dict(ctrl)
            db_record = persisted.get(ctrl["id"], {})
            entry["implementation_status"] = db_record.get(
                "implementation_status", "planned"
            )
            entry["evidence_artifacts"] = db_record.get(
                "evidence_artifacts", []
            )
            entry["last_assessed"] = db_record.get("last_assessed", "")
            entry["assessor_notes"] = db_record.get("assessor_notes", "")
            enriched.append(entry)

        return enriched
