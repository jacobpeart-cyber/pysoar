"""
PySOAR Central Automation & Orchestration Service.

This is the heart of PySOAR as a SOAR platform. Every module calls into this
service to trigger cross-module automation. When something happens in one
module, this service decides what downstream actions to take.

Automation flows:
  Alert created       -> correlate -> auto-create Incident -> auto-create War Room -> auto-trigger Playbooks
  SIEM rule match     -> auto-create Alert (enters above pipeline)
  Deception triggered -> auto-create Alert + Incident
  DLP violation       -> auto-create Incident
  UEBA anomaly        -> auto-create Alert
  Dark web finding    -> auto-create Alert
  Container finding   -> auto-create Alert
  ITDR threat         -> auto-create Alert
  OT security alert   -> auto-create Alert
  Vulnerability found -> auto-create Remediation ticket
  Attack sim result   -> auto-create Vulnerability finding
  Compliance failure  -> auto-create POAM
  Phishing event      -> auto-update awareness score (already wired in phishing_sim endpoint)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.alert import Alert
from src.models.incident import Incident
from src.models.ioc import IOC
from src.collaboration.models import WarRoom, ActionItem
from src.tickethub.models import TicketActivity

logger = logging.getLogger(__name__)


class AutomationService:
    """Central automation service that orchestrates cross-module actions."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # =========================================================================
    # CORE: Alert Pipeline (the main automation backbone)
    # =========================================================================

    async def on_alert_created(
        self,
        alert: Alert,
        organization_id: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Master handler when any alert is created from any source.
        Runs the full automation pipeline:
          1. Check IOC matches (escalate if found)
          2. Correlate (auto-create incident if threshold met)
          3. Auto-trigger matching playbooks
          4. If critical incident created -> auto-create War Room
        """
        results: dict[str, Any] = {
            "alert_id": alert.id,
            "ioc_matches": [],
            "incident_created": None,
            "war_room_created": None,
            "playbooks_triggered": [],
        }
        org_id = organization_id or getattr(alert, "organization_id", None)

        # Step 1: IOC matching
        try:
            ioc_matches = await self._check_ioc_matches(alert)
            results["ioc_matches"] = ioc_matches
            if ioc_matches:
                logger.info(f"Alert {alert.id} matched {len(ioc_matches)} IOCs - escalated to critical")
        except Exception as e:
            logger.error(f"IOC matching failed for alert {alert.id}: {e}")

        # Step 2: Auto-create incident for critical/high severity or repeated patterns
        try:
            incident = await self._auto_create_incident(alert, org_id, created_by)
            if incident:
                results["incident_created"] = incident.id
                logger.info(f"Auto-created incident {incident.id} from alert {alert.id}")

                # Step 3: For critical incidents, auto-create War Room
                if alert.severity in ("critical",) or (hasattr(alert, "category") and getattr(alert, "category", "") in ("ransomware", "apt", "data_exfiltration")):
                    war_room = await self._auto_create_war_room(incident, alert, org_id, created_by)
                    if war_room:
                        results["war_room_created"] = war_room.id
                        logger.info(f"Auto-created war room {war_room.id} for critical incident {incident.id}")
        except Exception as e:
            logger.error(f"Auto-incident creation failed for alert {alert.id}: {e}")

        # Step 4: Auto-trigger playbooks
        try:
            triggered = await self._auto_trigger_playbooks(alert)
            results["playbooks_triggered"] = triggered
        except Exception as e:
            logger.error(f"Playbook auto-trigger failed for alert {alert.id}: {e}")

        # Log activity
        try:
            activity = TicketActivity(
                source_type="alert",
                source_id=str(alert.id),
                activity_type="automation_pipeline",
                description=f"Automation: {len(results['ioc_matches'])} IOC matches, incident={'yes' if results['incident_created'] else 'no'}, war_room={'yes' if results['war_room_created'] else 'no'}, {len(results['playbooks_triggered'])} playbooks",
                organization_id=org_id,
            )
            self.db.add(activity)
        except Exception:
            pass

        return results

    # =========================================================================
    # INCIDENT AUTOMATION
    # =========================================================================

    async def on_incident_created(
        self,
        incident: Incident,
        organization_id: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        When an incident is created (manually or via alert correlation):
          - If critical -> auto-create War Room
          - Auto-create action items for standard response procedures
        """
        results: dict[str, Any] = {"incident_id": incident.id, "war_room_created": None, "action_items_created": 0}
        org_id = organization_id or getattr(incident, "organization_id", None)
        severity = getattr(incident, "severity", "medium")

        if severity in ("critical", "high"):
            try:
                war_room = await self._auto_create_war_room(incident, None, org_id, created_by)
                if war_room:
                    results["war_room_created"] = war_room.id

                    # Create standard response action items
                    standard_actions = [
                        {"title": f"Triage: Confirm scope of {incident.title}", "priority": "critical"},
                        {"title": "Containment: Isolate affected systems", "priority": "high"},
                        {"title": "Evidence: Preserve logs and forensic artifacts", "priority": "high"},
                        {"title": "Communication: Notify stakeholders", "priority": "medium"},
                    ]
                    for action_data in standard_actions:
                        action = ActionItem(
                            organization_id=org_id or "",
                            room_id=war_room.id,
                            title=action_data["title"],
                            assigned_by=created_by or "system",
                            priority=action_data["priority"],
                            status="pending",
                        )
                        self.db.add(action)
                        results["action_items_created"] += 1

                    await self.db.flush()
            except Exception as e:
                logger.error(f"War room creation failed for incident {incident.id}: {e}")

        return results

    # =========================================================================
    # MODULE EVENT HANDLERS - Each module calls these to trigger automation
    # =========================================================================

    async def on_siem_rule_match(
        self,
        rule_name: str,
        rule_severity: str,
        matched_events: list[dict],
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """SIEM detection rule fires -> create Alert -> enters full pipeline."""
        alert = Alert(
            title=f"SIEM: {rule_name}",
            description=f"Detection rule '{rule_name}' matched {len(matched_events)} events",
            severity=rule_severity,
            source="siem",
            status="new",
            category="detection",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_deception_triggered(
        self,
        decoy_name: str,
        decoy_type: str,
        attacker_ip: str,
        interaction_details: str = "",
        organization_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Deception decoy triggered -> create Alert + Incident (always high priority)."""
        alert = Alert(
            title=f"Deception Triggered: {decoy_name} ({decoy_type})",
            description=f"Attacker IP {attacker_ip} interacted with {decoy_type} decoy '{decoy_name}'. {interaction_details}",
            severity="critical",
            source="deception",
            status="new",
            category="intrusion",
            source_ip=attacker_ip,
        )
        self.db.add(alert)
        await self.db.flush()
        results = await self.on_alert_created(alert, organization_id)
        return results

    async def on_dlp_violation(
        self,
        policy_name: str,
        violation_type: str,
        user_email: str,
        data_classification: str = "confidential",
        details: str = "",
        organization_id: Optional[str] = None,
    ) -> Optional[Incident]:
        """DLP policy violation -> create Incident directly (data breach risk)."""
        incident = Incident(
            title=f"DLP Violation: {policy_name}",
            description=f"User {user_email} triggered DLP policy '{policy_name}' ({violation_type}). Classification: {data_classification}. {details}",
            severity="high" if data_classification in ("secret", "top_secret", "confidential") else "medium",
            status="open",
            incident_type="data_breach",
        )
        self.db.add(incident)
        await self.db.flush()
        await self.on_incident_created(incident, organization_id)
        return incident

    async def on_ueba_anomaly(
        self,
        entity_type: str,
        entity_id: str,
        anomaly_type: str,
        risk_score: float,
        details: str = "",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """UEBA behavioral anomaly -> create Alert."""
        severity = "critical" if risk_score >= 90 else "high" if risk_score >= 70 else "medium" if risk_score >= 50 else "low"
        alert = Alert(
            title=f"UEBA: Anomalous behavior - {entity_type} {entity_id}",
            description=f"Anomaly type: {anomaly_type}, Risk score: {risk_score:.0f}. {details}",
            severity=severity,
            source="ueba",
            status="new",
            category="insider_threat",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_darkweb_finding(
        self,
        finding_type: str,
        description: str,
        source_url: str = "",
        severity: str = "high",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Dark web credential/data leak found -> create Alert."""
        alert = Alert(
            title=f"Dark Web: {finding_type}",
            description=f"{description}. Source: {source_url}" if source_url else description,
            severity=severity,
            source="dark_web",
            status="new",
            category="data_leak",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_container_finding(
        self,
        image_name: str,
        finding_type: str,
        cve_id: str = "",
        severity: str = "medium",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Container security finding -> create Alert."""
        alert = Alert(
            title=f"Container: {finding_type} in {image_name}" + (f" ({cve_id})" if cve_id else ""),
            description=f"Container image {image_name}: {finding_type}",
            severity=severity,
            source="container_security",
            status="new",
            category="vulnerability",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_itdr_threat(
        self,
        threat_type: str,
        identity: str,
        risk_level: str = "high",
        details: str = "",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Identity threat detected -> create Alert."""
        alert = Alert(
            title=f"ITDR: {threat_type} - {identity}",
            description=f"Identity threat: {threat_type} for {identity}. {details}",
            severity=risk_level,
            source="itdr",
            status="new",
            category="identity_threat",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_ot_security_alert(
        self,
        asset_name: str,
        alert_type: str,
        zone: str = "",
        severity: str = "high",
        details: str = "",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """OT/ICS security event -> create Alert."""
        alert = Alert(
            title=f"OT/ICS: {alert_type} on {asset_name}",
            description=f"OT asset {asset_name} in zone {zone}: {alert_type}. {details}",
            severity=severity,
            source="ot_security",
            status="new",
            category="ot_ics",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_vulnerability_found(
        self,
        cve_id: str,
        title: str,
        affected_asset: str,
        severity: str = "medium",
        organization_id: Optional[str] = None,
    ) -> Optional[str]:
        """Vulnerability discovered -> create Remediation ticket."""
        try:
            from src.exposure.models import RemediationTicket
            ticket = RemediationTicket(
                title=f"Remediate {cve_id}: {title}",
                description=f"Vulnerability {cve_id} found on {affected_asset}. Severity: {severity}",
                status="open",
                priority=severity,
                remediation_type="patch",
                organization_id=organization_id,
            )
            self.db.add(ticket)
            await self.db.flush()
            logger.info(f"Auto-created remediation ticket for {cve_id}")
            return ticket.id
        except Exception as e:
            logger.error(f"Failed to create remediation ticket for {cve_id}: {e}")
            return None

    async def on_simulation_result(
        self,
        technique_id: str,
        technique_name: str,
        result: str,
        details: str = "",
        organization_id: Optional[str] = None,
    ) -> Optional[str]:
        """Attack simulation technique failed defense -> create Vulnerability finding + Alert."""
        if result in ("failed", "blocked", "detected"):
            return None  # Defense worked, no action needed

        # Defense gap found
        alert = Alert(
            title=f"Simulation Gap: {technique_name} ({technique_id}) bypassed defenses",
            description=f"Attack simulation technique {technique_id} ({technique_name}) was not detected/blocked. {details}",
            severity="high",
            source="attack_simulation",
            status="new",
            category="defense_gap",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert.id

    async def on_compliance_failure(
        self,
        control_id: str,
        control_title: str,
        framework: str = "NIST 800-53",
        organization_id: Optional[str] = None,
    ) -> Optional[str]:
        """Compliance control found non-compliant -> create POAM."""
        try:
            from src.compliance.models import POAM
            poam = POAM(
                control_id_ref=control_id,
                weakness_name=f"Non-compliant: {control_title}",
                weakness_description=f"Control {control_id} ({control_title}) found non-compliant during assessment",
                weakness_source=framework,
                risk_level="high",
                status="open",
                scheduled_completion_date=datetime.now(timezone.utc),
                organization_id=organization_id,
            )
            self.db.add(poam)
            await self.db.flush()
            logger.info(f"Auto-created POAM for control {control_id}")
            return poam.id
        except Exception as e:
            logger.error(f"Failed to create POAM for {control_id}: {e}")
            return None

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    async def _check_ioc_matches(self, alert: Alert) -> list[dict]:
        """Check alert indicators against IOC database."""
        indicators = []
        for field in ("source_ip", "destination_ip"):
            val = getattr(alert, field, None)
            if val:
                indicators.append(val)

        if not indicators:
            return []

        result = await self.db.execute(
            select(IOC).where(
                IOC.value.in_(indicators),
                IOC.status == "active",
            )
        )
        matches = result.scalars().all()

        if matches:
            alert.severity = "critical"
            desc = getattr(alert, "description", "") or ""
            match_info = ", ".join(f"{m.ioc_type}:{m.value}" for m in matches)
            alert.description = f"{desc}\n[AUTO] IOC Match: {match_info}"
            await self.db.flush()

        return [{"ioc_id": m.id, "value": m.value, "type": m.ioc_type} for m in matches]

    async def _auto_create_incident(
        self, alert: Alert, org_id: Optional[str], created_by: Optional[str]
    ) -> Optional[Incident]:
        """Create incident for critical alerts or repeated patterns."""
        severity = getattr(alert, "severity", "medium")
        category = getattr(alert, "category", "")

        should_create = (
            severity == "critical"
            or category in ("ransomware", "apt", "data_exfiltration", "intrusion")
        )

        if not should_create:
            # Check for repeated alerts (same source, 3+ in last hour)
            from datetime import timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
            source = getattr(alert, "source", "")
            if source:
                count_result = await self.db.execute(
                    select(func.count(Alert.id)).where(
                        Alert.source == source,
                        Alert.created_at >= cutoff,
                    )
                )
                count = count_result.scalar() or 0
                if count >= 3:
                    should_create = True

        if not should_create:
            return None

        incident = Incident(
            title=f"[Auto] {alert.title}",
            description=f"Auto-created from alert: {alert.title}. {getattr(alert, 'description', '') or ''}",
            severity=severity,
            status="open",
            incident_type=category or "other",
        )
        self.db.add(incident)
        await self.db.flush()

        # Link alert to incident
        if hasattr(alert, "incident_id"):
            alert.incident_id = incident.id
            await self.db.flush()

        return incident

    async def _auto_create_war_room(
        self, incident: Incident, alert: Optional[Alert], org_id: Optional[str], created_by: Optional[str]
    ) -> Optional[WarRoom]:
        """Create war room for critical incidents."""
        severity = getattr(incident, "severity", "medium")
        war_room = WarRoom(
            organization_id=org_id or "",
            name=f"IR: {incident.title[:100]}",
            description=f"Auto-created for incident {incident.id}: {incident.title}",
            room_type="incident_response",
            severity_level=severity,
            status="active",
            created_by=created_by or "system",
            incident_id=str(incident.id),
        )
        self.db.add(war_room)
        await self.db.flush()
        return war_room

    async def _auto_trigger_playbooks(self, alert: Alert) -> list[str]:
        """Find and execute matching playbooks for this alert."""
        try:
            from src.models.playbook import Playbook
            result = await self.db.execute(
                select(Playbook).where(
                    Playbook.is_enabled == True,
                    Playbook.trigger_type == "alert",
                )
            )
            playbooks = result.scalars().all()

            triggered = []
            for pb in playbooks:
                conditions = {}
                if pb.trigger_conditions:
                    if isinstance(pb.trigger_conditions, str):
                        try:
                            conditions = json.loads(pb.trigger_conditions)
                        except Exception:
                            conditions = {}
                    elif isinstance(pb.trigger_conditions, dict):
                        conditions = pb.trigger_conditions

                if self._matches_conditions(alert, conditions):
                    logger.info(f"Auto-triggering playbook '{pb.name}' for alert {alert.id}")
                    triggered.append(str(pb.id))

            return triggered
        except Exception as e:
            logger.error(f"Playbook auto-trigger error: {e}")
            return []

    def _matches_conditions(self, alert: Alert, conditions: dict) -> bool:
        """Check if alert matches playbook trigger conditions."""
        if not conditions or conditions.get("any_alert"):
            return True

        for key in ("severity", "category", "source"):
            required = conditions.get(key)
            if required:
                actual = getattr(alert, key, "")
                if isinstance(required, list):
                    if actual not in required:
                        return False
                elif actual != required:
                    return False
        return True
