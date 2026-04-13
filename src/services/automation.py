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
from src.intel.models import ThreatIndicator as IOC
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

        failures: list[dict] = []

        # Step 1: IOC matching
        try:
            ioc_matches = await self._check_ioc_matches(alert)
            results["ioc_matches"] = ioc_matches
            if ioc_matches:
                logger.info(f"Alert {alert.id} matched {len(ioc_matches)} IOCs - escalated to critical")
        except Exception as e:
            logger.error(f"IOC matching failed for alert {alert.id}: {e}")
            failures.append({"step": "ioc_matching", "error": str(e)[:300]})

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
            failures.append({"step": "auto_incident", "error": str(e)[:300]})

        # Step 4: Auto-trigger playbooks
        try:
            triggered = await self._auto_trigger_playbooks(alert)
            results["playbooks_triggered"] = triggered
        except Exception as e:
            logger.error(f"Playbook auto-trigger failed for alert {alert.id}: {e}")
            failures.append({"step": "playbook_trigger", "error": str(e)[:300]})

        # Step 5: Evaluate remediation policies against this alert.
        # Any enabled RemediationPolicy whose trigger_type matches and
        # whose severity threshold is met will fire its configured
        # action — firewall_block on source_ip, isolate_host on the
        # hostname, disable_account on the user, etc. Each fired
        # policy creates a RemediationExecution row the operator can
        # track in the Remediation page. Policies marked
        # requires_approval=True land in awaiting_approval rather than
        # executing immediately, matching the second-analyst sign-off
        # contract the audit team expects.
        try:
            remediations = await self._evaluate_remediation_policies(alert, org_id)
            results["remediations_triggered"] = remediations
        except Exception as e:  # noqa: BLE001
            logger.error(f"Remediation policy evaluation failed for alert {alert.id}: {e}")
            failures.append({"step": "remediation_eval", "error": str(e)[:300]})

        # Dead-letter trail: record any pipeline failures as an activity so
        # operators can retry them later. (scheduled retry task can query this.)
        if failures:
            results["failures"] = failures
            try:
                dlq = TicketActivity(
                    source_type="alert",
                    source_id=str(alert.id),
                    activity_type="automation_pipeline_failure",
                    description=f"DLQ: {json.dumps(failures)[:800]}",
                    organization_id=org_id,
                )
                self.db.add(dlq)
            except Exception:
                pass

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

        # ------------------------------------------------------------------
        # Agent-driven containment proposals
        # ------------------------------------------------------------------
        # If a Live Response agent is enrolled for any of the incident's
        # affected systems, queue a triage bundle automatically:
        #   - collect_process_list and collect_network_connections run
        #     immediately (read-only, no approval gate)
        #   - isolate_host is queued as awaiting_approval so the human
        #     signs off before the host actually goes dark
        # This is the "agentic" part of the SOC story — PySOAR proposes
        # the containment actions but never pulls the trigger on high-
        # blast ones without a second-analyst approval.
        try:
            results["agent_commands_queued"] = await self._queue_incident_containment(
                incident=incident,
                organization_id=org_id,
                created_by=created_by,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Agent containment proposals failed for incident {incident.id}: {e}")
            results["agent_commands_queued"] = 0

        return results

    async def _queue_incident_containment(
        self,
        *,
        incident: Incident,
        organization_id: Optional[str],
        created_by: Optional[str],
    ) -> int:
        """For each affected system that has an active IR-capable agent,
        dispatch a triage + proposed containment command bundle."""
        import json as _json

        from sqlalchemy import and_, select

        from src.agents.capabilities import AgentAction, AgentCapability
        from src.agents.models import EndpointAgent
        from src.agents.service import AgentService

        # Parse affected_systems (stored as JSON string in Incident model)
        raw = getattr(incident, "affected_systems", None)
        if not raw:
            return 0
        try:
            hosts = _json.loads(raw) if isinstance(raw, str) else list(raw)
        except Exception:  # noqa: BLE001
            return 0
        if not isinstance(hosts, list) or not hosts:
            return 0

        svc = AgentService(self.db)
        queued = 0
        severity = (getattr(incident, "severity", "medium") or "medium").lower()

        for host in hosts:
            if not host:
                continue
            agent_q = select(EndpointAgent).where(
                and_(
                    EndpointAgent.hostname == str(host),
                    EndpointAgent.status == "active",
                )
            )
            if organization_id:
                agent_q = agent_q.where(EndpointAgent.organization_id == organization_id)

            agents = list((await self.db.execute(agent_q)).scalars().all())
            if not agents:
                continue

            # Prefer an IR-capable agent; fall back to BAS for the
            # read-only collects if no IR agent is present.
            ir_agent = next(
                (a for a in agents if AgentCapability.LIVE_RESPONSE.value in (a.capabilities or [])),
                None,
            )
            triage_agent = ir_agent or next(
                (a for a in agents if AgentCapability.BAS.value in (a.capabilities or [])),
                None,
            )
            if triage_agent is None:
                continue

            # Read-only triage: queue immediately, no approval needed
            for action in (
                AgentAction.COLLECT_PROCESS_LIST.value,
                AgentAction.COLLECT_NETWORK_CONNECTIONS.value,
            ):
                try:
                    await svc.issue_command(
                        agent=triage_agent,
                        action=action,
                        payload={},
                        issued_by=created_by,
                        incident_id=incident.id,
                    )
                    queued += 1
                except Exception as e:  # noqa: BLE001
                    logger.warning(
                        f"Failed to queue {action} for host={host} incident={incident.id}: {e}"
                    )

            # Proposed containment: isolate_host -> awaiting_approval.
            # Only propose on high/critical incidents so automation
            # doesn't spam the approval queue with low-severity noise.
            if ir_agent is not None and severity in ("critical", "high"):
                try:
                    await svc.issue_command(
                        agent=ir_agent,
                        action=AgentAction.ISOLATE_HOST.value,
                        payload={"reason": f"proposed by incident {incident.id} ({severity})"},
                        issued_by=created_by,
                        incident_id=incident.id,
                    )
                    queued += 1
                except Exception as e:  # noqa: BLE001
                    logger.warning(
                        f"Failed to propose isolate_host for host={host} incident={incident.id}: {e}"
                    )

        return queued

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
    # ADDITIONAL MODULE HANDLERS
    # =========================================================================

    async def on_threat_hunt_finding(
        self,
        hunt_name: str,
        finding_title: str,
        severity: str = "medium",
        details: str = "",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Threat hunting finding -> create Alert."""
        alert = Alert(
            title=f"Hunt Finding: {finding_title}",
            description=f"Threat hunt '{hunt_name}' found: {finding_title}. {details}",
            severity=severity,
            source="threat_hunting",
            status="new",
            category="hunt_finding",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_threat_model_risk(
        self,
        model_name: str,
        threat_name: str,
        stride_category: str,
        risk_level: str = "medium",
        organization_id: Optional[str] = None,
    ) -> Optional[str]:
        """Threat modeling identifies a high/critical risk -> create Remediation ticket."""
        try:
            from src.exposure.models import RemediationTicket
            ticket = RemediationTicket(
                title=f"Threat Model: {threat_name} ({stride_category})",
                description=f"Threat model '{model_name}' identified {stride_category} risk: {threat_name}. Risk level: {risk_level}",
                status="open",
                priority=risk_level,
                remediation_type="design_change",
                organization_id=organization_id,
            )
            self.db.add(ticket)
            await self.db.flush()
            logger.info(f"Auto-created remediation ticket for threat model finding: {threat_name}")
            return ticket.id
        except Exception as e:
            logger.error(f"Failed to create ticket for threat model {model_name}: {e}")
            return None

    async def on_risk_scenario_high_loss(
        self,
        scenario_name: str,
        loss_expectancy_usd: float,
        organization_id: Optional[str] = None,
    ) -> Optional[Incident]:
        """Risk quantification: scenario with high loss expectancy -> create Incident for review."""
        if loss_expectancy_usd < 100000:
            return None  # Only significant losses
        incident = Incident(
            title=f"Risk Scenario Review: {scenario_name}",
            description=f"Risk scenario '{scenario_name}' has loss expectancy of ${loss_expectancy_usd:,.0f}. Review and mitigate.",
            severity="high" if loss_expectancy_usd >= 1000000 else "medium",
            status="open",
            incident_type="risk_review",
        )
        self.db.add(incident)
        await self.db.flush()
        await self.on_incident_created(incident, organization_id)
        return incident

    async def on_privacy_dsr_created(
        self,
        dsr_id: str,
        subject_email: str,
        request_type: str,
        regulation: str,
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Privacy DSR created -> create Alert for SOC tracking (regulatory deadline)."""
        alert = Alert(
            title=f"Privacy DSR: {request_type} from {subject_email}",
            description=f"Data Subject Request under {regulation}: {request_type}. DSR ID: {dsr_id}. Regulatory deadline applies.",
            severity="medium",
            source="privacy",
            status="new",
            category="privacy_request",
        )
        self.db.add(alert)
        await self.db.flush()
        # No full automation pipeline — DSRs don't need war rooms, just tracking
        return alert

    async def on_zerotrust_policy_violation(
        self,
        policy_name: str,
        user_email: str,
        violation_type: str,
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Zero trust policy violation -> create Alert."""
        alert = Alert(
            title=f"Zero Trust Violation: {policy_name}",
            description=f"User {user_email} violated zero trust policy '{policy_name}': {violation_type}",
            severity="high",
            source="zero_trust",
            status="new",
            category="policy_violation",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_supply_chain_vuln(
        self,
        vendor_name: str,
        component_name: str,
        cve_id: str,
        severity: str = "high",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Supply chain vulnerability discovered -> create Alert + Remediation ticket."""
        alert = Alert(
            title=f"Supply Chain: {cve_id} in {component_name} ({vendor_name})",
            description=f"Vendor {vendor_name} component {component_name} has vulnerability {cve_id}",
            severity=severity,
            source="supply_chain",
            status="new",
            category="vulnerability",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        # Also create remediation ticket
        await self.on_vulnerability_found(cve_id, f"{component_name} ({vendor_name})", component_name, severity, organization_id)
        return alert

    async def on_api_security_threat(
        self,
        api_endpoint: str,
        threat_type: str,
        severity: str = "high",
        details: str = "",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """API security threat detected -> create Alert."""
        alert = Alert(
            title=f"API Threat: {threat_type} on {api_endpoint}",
            description=f"API endpoint {api_endpoint} threat: {threat_type}. {details}",
            severity=severity,
            source="api_security",
            status="new",
            category="api_attack",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    async def on_fedramp_evidence_gap(
        self,
        control_id: str,
        control_title: str,
        organization_id: Optional[str] = None,
    ) -> Optional[str]:
        """FedRAMP evidence gap found -> create POAM."""
        return await self.on_compliance_failure(control_id, control_title, framework="FedRAMP", organization_id=organization_id)

    async def on_stig_finding(
        self,
        benchmark: str,
        finding_title: str,
        severity: str = "medium",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """STIG/SCAP scan finding -> create Alert."""
        alert = Alert(
            title=f"STIG {benchmark}: {finding_title}",
            description=f"STIG benchmark {benchmark} finding: {finding_title}",
            severity=severity,
            source="stig",
            status="new",
            category="compliance",
        )
        self.db.add(alert)
        await self.db.flush()
        return alert

    async def on_data_lake_anomaly(
        self,
        data_source: str,
        anomaly_description: str,
        severity: str = "medium",
        organization_id: Optional[str] = None,
    ) -> Optional[Alert]:
        """Data lake query anomaly -> create Alert."""
        alert = Alert(
            title=f"Data Lake Anomaly: {data_source}",
            description=anomaly_description,
            severity=severity,
            source="data_lake",
            status="new",
            category="data_anomaly",
        )
        self.db.add(alert)
        await self.db.flush()
        await self.on_alert_created(alert, organization_id)
        return alert

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    async def _check_ioc_matches(self, alert: Alert) -> list[dict]:
        """Check alert indicators against unified threat_indicators table."""
        indicators = []
        for field in ("source_ip", "destination_ip", "hostname", "domain", "url", "file_hash"):
            val = getattr(alert, field, None)
            if val:
                indicators.append(val)

        if not indicators:
            return []

        result = await self.db.execute(
            select(IOC).where(
                IOC.value.in_(indicators),
                IOC.is_active == True,  # noqa: E712
                IOC.is_whitelisted == False,  # noqa: E712
            )
        )
        matches = result.scalars().all()

        if matches:
            alert.severity = "critical"
            desc = getattr(alert, "description", "") or ""
            match_info = ", ".join(f"{m.indicator_type}:{m.value}" for m in matches)
            alert.description = f"{desc}\n[AUTO] IOC Match: {match_info}"
            # Bump sighting counters
            now = datetime.now(timezone.utc)
            for m in matches:
                m.sighting_count = (m.sighting_count or 0) + 1
                m.last_sighting_at = now
                m.last_seen = now
            await self.db.flush()

        return [
            {
                "ioc_id": m.id,
                "value": m.value,
                "type": m.indicator_type,
                "severity": m.severity,
                "source": m.source,
            }
            for m in matches
        ]

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

    async def _evaluate_remediation_policies(
        self,
        alert: Alert,
        organization_id: Optional[str],
    ) -> list[str]:
        """Find enabled RemediationPolicy rows that match this alert and
        fire them. Returns a list of execution IDs created.

        Matching rules:
          * ``trigger_type`` == "alert" or "alert_severity"
          * ``trigger_conditions.severity`` (list or string) must match
            alert.severity if set
          * Policy's cooldown is respected (don't fire the same policy
            twice inside its cooldown_minutes window)

        For each matching policy we write a RemediationExecution row
        with ``status=awaiting_approval`` if the policy requires
        approval, otherwise ``status=pending`` (the worker task or UI
        button picks it up from there).
        """
        from datetime import datetime, timezone, timedelta

        from src.remediation.models import (
            RemediationExecution,
            RemediationPolicy,
        )

        created_ids: list[str] = []

        stmt = select(RemediationPolicy).where(
            and_(
                RemediationPolicy.is_enabled == True,  # noqa: E712
                RemediationPolicy.trigger_type.in_(["alert", "alert_severity"]),
            )
        )
        if organization_id:
            stmt = stmt.where(
                RemediationPolicy.organization_id == organization_id
            )

        result = await self.db.execute(stmt)
        policies = list(result.scalars().all())
        if not policies:
            return []

        alert_severity = (getattr(alert, "severity", None) or "").lower()
        now = datetime.now(timezone.utc)

        for policy in policies:
            # Cooldown enforcement
            if policy.last_executed_at and policy.cooldown_minutes:
                last = policy.last_executed_at
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if now - last < timedelta(minutes=policy.cooldown_minutes):
                    continue

            # Severity match
            conds = policy.trigger_conditions or {}
            required_sev = conds.get("severity")
            if required_sev:
                if isinstance(required_sev, list):
                    if alert_severity not in [s.lower() for s in required_sev]:
                        continue
                elif alert_severity != str(required_sev).lower():
                    continue

            # Resolve target from the alert
            target_entity = (
                getattr(alert, "source_ip", None)
                or getattr(alert, "hostname", None)
                or str(alert.id)
            )
            target_type = "ip" if getattr(alert, "source_ip", None) else "host"

            # Decide initial status based on policy's approval gate
            initial_status = (
                "awaiting_approval" if policy.requires_approval else "pending"
            )

            execution = RemediationExecution(
                policy_id=policy.id,
                trigger_source="alert",
                trigger_id=str(alert.id),
                trigger_details={
                    "alert_id": str(alert.id),
                    "alert_severity": alert_severity,
                    "alert_source": getattr(alert, "source", None),
                    "alert_title": getattr(alert, "title", None),
                },
                status=initial_status,
                target_entity=target_entity,
                target_type=target_type,
                actions_planned=policy.actions or [],
                actions_completed=[],
                organization_id=organization_id or "",
                created_by=None,  # auto-triggered, no human actor
            )
            self.db.add(execution)
            try:
                await self.db.flush()
                await self.db.refresh(execution)
                created_ids.append(execution.id)

                policy.last_executed_at = now
                policy.execution_count = (policy.execution_count or 0) + 1
                await self.db.flush()

                logger.info(
                    f"Remediation policy '{policy.name}' triggered by alert "
                    f"{alert.id} (execution={execution.id}, status={initial_status})"
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    f"Failed to create remediation execution for policy "
                    f"{policy.id}: {exc}"
                )

        return created_ids
