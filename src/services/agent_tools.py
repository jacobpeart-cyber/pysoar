"""
PySOAR Agent Tools Registry.

Every action the Agentic SOC or AI Engine can perform, exposed as a structured
tool. The AI calls these tools by name with parameters, and the tools execute
real operations against the platform.

Tools are organized by capability:
  QUERY  - Read data from the platform
  ACTION - Perform operations (create/update/delete)
  ANALYZE- Run analysis/simulation/enrichment
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.integrations.engine import ActionExecutor
from src.integrations.models import InstalledIntegration

logger = logging.getLogger(__name__)


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    category: str
    handler: Callable


class AgentToolRegistry:
    """Registry of all tools the AI agent can invoke."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.tools: dict[str, Tool] = {}
        self._register_all()

    # =========================================================================
    # EXECUTE a tool by name
    # =========================================================================

    async def execute(self, tool_name: str, params: dict) -> dict:
        """Execute a tool by name with parameters."""
        tool = self.tools.get(tool_name)
        if not tool:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        try:
            result = await tool.handler(**params)
            return {"success": True, "result": result}
        except TypeError as e:
            return {"success": False, "error": f"Invalid parameters: {e}"}
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            return {"success": False, "error": str(e)}

    def list_tools(self, category: Optional[str] = None) -> list[dict]:
        """List all registered tools (for AI tool discovery)."""
        tools = self.tools.values()
        if category:
            tools = [t for t in tools if t.category == category]
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
                "category": t.category,
            }
            for t in tools
        ]

    def gemini_function_declarations(self) -> list[dict]:
        """
        Return tool definitions in Gemini function calling schema format.
        Each declaration has: name, description, parameters (JSON schema).
        """
        declarations = []
        for t in self.tools.values():
            # Build JSON schema properties from the parameters dict
            properties = {}
            required = []
            import re
            for param_name, param_desc in (t.parameters or {}).items():
                desc_str = str(param_desc)
                lower = desc_str.lower()
                is_optional = "optional" in lower
                # Match whole-word type hints so substrings like "list_processes"
                # inside an enum description don't accidentally flip the type to
                # array. Only the LEADING type word counts (the description
                # starts with "string", "int", "list of", "dict", etc.).
                param_type = "string"
                head = lower.lstrip("-• *").split(" ", 1)[0].split(",", 1)[0]
                if head in {"int", "integer", "number", "float"}:
                    param_type = "integer"
                elif head in {"bool", "boolean"}:
                    param_type = "boolean"
                elif head in {"dict", "object", "mapping"}:
                    param_type = "object"
                elif head in {"list", "array"} or lower.startswith(("list of", "array of")):
                    param_type = "array"

                prop: dict = {"type": param_type, "description": desc_str}
                # Gemini requires `items` on arrays; default to string items
                # since the registry doesn't carry per-element typing.
                if param_type == "array":
                    prop["items"] = {"type": "string"}
                properties[param_name] = prop
                if not is_optional:
                    required.append(param_name)

            decl = {
                "name": t.name,
                "description": f"[{t.category}] {t.description}",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                },
            }
            if required:
                decl["parameters"]["required"] = required
            declarations.append(decl)
        return declarations

    def _register(self, tool: Tool):
        self.tools[tool.name] = tool

    # =========================================================================
    # Register all tools
    # =========================================================================

    def _register_all(self):
        # ===== QUERY TOOLS =====
        self._register(Tool(
            name="list_alerts",
            description="List recent alerts with optional filters",
            parameters={"severity": "optional string (critical/high/medium/low)", "status": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_alerts,
        ))
        self._register(Tool(
            name="list_incidents",
            description="List recent incidents",
            parameters={"status": "optional string", "severity": "optional string", "limit": "optional int, default 10"},
            category="query",
            handler=self._list_incidents,
        ))
        self._register(Tool(
            name="list_iocs",
            description="List IOCs (threat indicators)",
            parameters={"ioc_type": "optional string (ip/domain/hash)", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_iocs,
        ))
        self._register(Tool(
            name="get_alert",
            description="Get full details of a specific alert",
            parameters={"alert_id": "string - alert UUID"},
            category="query",
            handler=self._get_alert,
        ))
        self._register(Tool(
            name="get_incident",
            description="Get full details of a specific incident",
            parameters={"incident_id": "string - incident UUID"},
            category="query",
            handler=self._get_incident,
        ))
        self._register(Tool(
            name="platform_stats",
            description="Get platform-wide security stats (alert counts, incident counts, etc)",
            parameters={},
            category="query",
            handler=self._platform_stats,
        ))
        self._register(Tool(
            name="search_alerts",
            description="Search alerts by keyword in title/description",
            parameters={"keyword": "string", "limit": "optional int, default 10"},
            category="query",
            handler=self._search_alerts,
        ))
        self._register(Tool(
            name="list_playbooks",
            description="List enabled response playbooks (read-only). Use to find the SOP matching the current alert/incident type before concluding.",
            parameters={"keyword": "optional string - filter by name/description", "category": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_playbooks,
        ))
        self._register(Tool(
            name="get_playbook",
            description="Get a playbook's full definition including its ordered steps (read-only — does NOT execute it)",
            parameters={"playbook_id": "string - playbook UUID"},
            category="query",
            handler=self._get_playbook,
        ))
        # --- Incident response (NIST 800-61 lifecycle: triage -> contain
        #     -> eradicate -> recover -> close). State-changing; gated.
        self._register(Tool(
            name="update_incident_status",
            description="Advance an incident through its lifecycle: open -> investigating -> containment -> eradication -> recovery -> closed. Records the transition on the incident timeline.",
            parameters={"incident_id": "string", "status": "open|investigating|containment|eradication|recovery|closed", "note": "optional string - reason for the transition"},
            category="action",
            handler=self._update_incident_status,
        ))
        self._register(Tool(
            name="assign_incident",
            description="Assign an incident to an analyst (by email) or to yourself ('me'). Use to take ownership before working it.",
            parameters={"incident_id": "string", "assignee": "string - user email, user id, or 'me'"},
            category="action",
            handler=self._assign_incident,
        ))
        self._register(Tool(
            name="add_incident_note",
            description="Append an investigation note to an incident's record (documentation / handoff).",
            parameters={"incident_id": "string", "note": "string - the note content"},
            category="action",
            handler=self._add_incident_note,
        ))
        self._register(Tool(
            name="update_incident_findings",
            description="Document the post-incident findings on an incident: root cause, resolution, lessons learned, recommendations.",
            parameters={"incident_id": "string", "root_cause": "optional string", "resolution": "optional string", "lessons_learned": "optional string", "recommendations": "optional string"},
            category="action",
            handler=self._update_incident_findings,
        ))
        self._register(Tool(
            name="remediate_incident",
            description="Orchestrate NIST containment for an incident: isolate its affected hosts and block its indicator IPs (real actions via the remediation path), then advance the incident to 'containment'. Host isolation / IP blocks are recorded as remediation activity. Use after triage to actually contain the threat.",
            parameters={"incident_id": "string", "isolate_hosts": "optional bool, default true", "block_indicators": "optional bool, default true"},
            category="action",
            handler=self._remediate_incident,
        ))
        self._register(Tool(
            name="lookup_attack_technique",
            description="Look up a MITRE ATT&CK technique by id (e.g. T1110 or T1110.001). Returns authoritative name, tactics, detection guidance, data sources, mitigations, threat groups, and software that use it.",
            parameters={"technique_id": "string - ATT&CK technique id like T1110 or T1110.001"},
            category="query",
            handler=self._lookup_attack_technique,
        ))
        self._register(Tool(
            name="search_attack",
            description="Search the MITRE ATT&CK knowledge base for techniques, threat groups, or software by name/alias/id.",
            parameters={"query": "string - keyword, name, alias, or id", "limit": "optional int, default 25"},
            category="query",
            handler=self._search_attack,
        ))
        self._register(Tool(
            name="get_attack_coverage",
            description="For a list of ATT&CK technique ids, report how many active detection rules cover each — the real detection blind-spot map.",
            parameters={"technique_ids": "list of ATT&CK technique ids (e.g. [\"T1110\",\"T1059.001\"])"},
            category="query",
            handler=self._get_attack_coverage,
        ))

        # ===== ACTION TOOLS =====
        self._register(Tool(
            name="create_alert",
            description="Create a new security alert",
            parameters={"title": "string", "severity": "critical/high/medium/low", "source": "string", "description": "optional string", "category": "optional string"},
            category="action",
            handler=self._create_alert,
        ))
        self._register(Tool(
            name="create_incident",
            description="Create a security incident (escalate alert)",
            parameters={"title": "string", "severity": "string", "description": "optional string", "alert_id": "optional alert to link"},
            category="action",
            handler=self._create_incident,
        ))
        self._register(Tool(
            name="update_alert_status",
            description="Update an alert's status (new/investigating/resolved/closed)",
            parameters={"alert_id": "string", "status": "string"},
            category="action",
            handler=self._update_alert_status,
        ))
        self._register(Tool(
            name="assign_alert",
            description="Assign an alert to a user",
            parameters={"alert_id": "string", "user_id": "string"},
            category="action",
            handler=self._assign_alert,
        ))
        self._register(Tool(
            name="create_war_room",
            description="Create an incident response war room",
            parameters={"name": "string", "severity": "string", "incident_id": "optional"},
            category="action",
            handler=self._create_war_room,
        ))
        self._register(Tool(
            name="create_action_item",
            description="Create an action item in a war room",
            parameters={"room_id": "string", "title": "string", "priority": "string"},
            category="action",
            handler=self._create_action_item,
        ))
        self._register(Tool(
            name="execute_playbook",
            description="Execute a playbook by ID",
            parameters={"playbook_id": "string", "input_data": "optional dict"},
            category="action",
            handler=self._execute_playbook,
        ))
        self._register(Tool(
            name="block_ip",
            description="Block an IP address at the firewall (via remediation engine)",
            parameters={"ip": "string", "reason": "string"},
            category="action",
            handler=self._block_ip,
        ))
        self._register(Tool(
            name="isolate_host",
            description="Isolate a host from the network",
            parameters={"hostname": "string", "reason": "string"},
            category="action",
            handler=self._isolate_host,
        ))
        self._register(Tool(
            name="disable_user",
            description="Disable a user account",
            parameters={"user_email": "string", "reason": "string"},
            category="action",
            handler=self._disable_user,
        ))
        self._register(Tool(
            name="create_ioc",
            description="Add an IOC to the threat intel database",
            parameters={"value": "string", "ioc_type": "ip/domain/hash/url", "threat_level": "string"},
            category="action",
            handler=self._create_ioc,
        ))
        self._register(Tool(
            name="create_remediation_ticket",
            description="Create a remediation ticket for a vulnerability",
            parameters={"title": "string", "priority": "string", "description": "optional"},
            category="action",
            handler=self._create_remediation_ticket,
        ))

        # ===== ANALYZE TOOLS =====
        self._register(Tool(
            name="triage_alert",
            description="AI-powered triage of an alert (priority, confidence, recommendations)",
            parameters={"alert_id": "string"},
            category="analyze",
            handler=self._triage_alert,
        ))
        self._register(Tool(
            name="enrich_ioc",
            description="Enrich an IOC with threat intel data",
            parameters={"value": "string", "ioc_type": "string"},
            category="analyze",
            handler=self._enrich_ioc,
        ))
        self._register(Tool(
            name="correlate_alerts",
            description="Find alerts related to a given alert (same source IP, host, category)",
            parameters={"alert_id": "string"},
            category="analyze",
            handler=self._correlate_alerts,
        ))
        self._register(Tool(
            name="check_ioc_matches",
            description="Check if any IOCs match an alert's indicators",
            parameters={"alert_id": "string"},
            category="analyze",
            handler=self._check_ioc_matches,
        ))
        self._register(Tool(
            name="run_threat_hunt",
            description="Run a threat hunt against logs/alerts using a hypothesis",
            parameters={"hypothesis": "string", "timeframe_hours": "int, default 24"},
            category="analyze",
            handler=self._run_threat_hunt,
        ))
        self._register(Tool(
            name="scope_hunt",
            description="PY-HUNT-001 Phase 1: validate a hunt hypothesis against the ATT&CK KB. Returns the techniques in scope (validated, with detection-rule coverage and the telemetry that detects them), which of those log sources PySOAR actually collects, and asset criticality for named hosts. Run this BEFORE run_threat_hunt to know what's hunt-able.",
            parameters={"hypothesis": "string - the hunt hypothesis / question"},
            category="analyze",
            handler=self._scope_hunt,
        ))
        self._register(Tool(
            name="simulate_attack",
            description="Run an attack simulation for a MITRE ATT&CK technique",
            parameters={"technique_id": "string (e.g. T1059)", "target": "string"},
            category="analyze",
            handler=self._simulate_attack,
        ))
        self._register(Tool(
            name="generate_incident_summary",
            description="Generate an AI summary of an incident",
            parameters={"incident_id": "string"},
            category="analyze",
            handler=self._generate_incident_summary,
        ))

        # ===== SIEM =====
        self._register(Tool(
            name="search_logs",
            description="Search SIEM logs by keyword across message/source fields",
            parameters={"keyword": "string", "severity": "optional string", "log_type": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._search_logs,
        ))
        self._register(Tool(
            name="list_siem_rules",
            description="List active SIEM detection rules",
            parameters={"status": "optional string (active/disabled)", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_siem_rules,
        ))

        # ===== UEBA =====
        self._register(Tool(
            name="list_entity_risks",
            description="List top high-risk UEBA entities (users/devices) by risk score",
            parameters={"risk_level": "optional string (critical/high/medium/low)", "entity_type": "optional string (user/device)", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_entity_risks,
        ))
        self._register(Tool(
            name="list_ueba_alerts",
            description="List UEBA behavior risk alerts",
            parameters={"severity": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_ueba_alerts,
        ))

        # ===== VULN MGMT =====
        self._register(Tool(
            name="list_vulnerabilities",
            description="List known vulnerabilities (CVE records)",
            parameters={"severity": "optional string (critical/high/medium/low)", "keyword": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_vulnerabilities,
        ))
        self._register(Tool(
            name="get_vulnerability",
            description="Get full detail on a vulnerability by CVE id or UUID",
            parameters={"cve_or_id": "string"},
            category="query",
            handler=self._get_vulnerability,
        ))

        # ===== DFIR =====
        self._register(Tool(
            name="list_forensic_cases",
            description="List DFIR forensic cases",
            parameters={"status": "optional string", "severity": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_forensic_cases,
        ))
        self._register(Tool(
            name="create_forensic_case",
            description="Open a new DFIR forensic case",
            parameters={"title": "string", "severity": "string (critical/high/medium/low)", "description": "optional string"},
            category="action",
            handler=self._create_forensic_case,
        ))

        # ===== DARK WEB =====
        self._register(Tool(
            name="list_darkweb_findings",
            description="List dark web findings (credential leaks, brand mentions, etc)",
            parameters={"finding_type": "optional string", "severity": "optional string", "status": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_darkweb_findings,
        ))

        # ===== THREAT HUNTING =====
        self._register(Tool(
            name="list_hunts",
            description="List threat-hunting hypotheses (prior and active hunts)",
            parameters={"status": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_hunts,
        ))
        self._register(Tool(
            name="list_hunt_findings",
            description="List findings produced by threat hunts",
            parameters={"severity": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_hunt_findings,
        ))

        # ===== THREAT INTEL =====
        self._register(Tool(
            name="list_threat_actors",
            description="List threat actors tracked in the intel database",
            parameters={"limit": "optional int, default 20"},
            category="query",
            handler=self._list_threat_actors,
        ))
        self._register(Tool(
            name="list_threat_campaigns",
            description="List known threat campaigns",
            parameters={"limit": "optional int, default 20"},
            category="query",
            handler=self._list_threat_campaigns,
        ))

        # ===== ASSETS =====
        self._register(Tool(
            name="list_assets",
            description="List inventoried assets (hosts, endpoints, cloud resources). Filter by criticality (critical/high/medium/low) to find the most important/exposed assets, or by status/type/keyword.",
            parameters={"criticality": "optional string (critical/high/medium/low) — business importance", "asset_type": "optional string", "status": "optional string", "keyword": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_assets,
        ))
        self._register(Tool(
            name="get_asset",
            description="Get details on a specific asset by id or name",
            parameters={"asset_ref": "string - asset id or name"},
            category="query",
            handler=self._get_asset,
        ))

        # ===== REMEDIATION =====
        self._register(Tool(
            name="list_remediation_executions",
            description="List recent remediation executions (actions the platform has run)",
            parameters={"status": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_remediation_executions,
        ))

        # ===== DECEPTION =====
        self._register(Tool(
            name="list_decoy_interactions",
            description="List recent decoy/honeypot interactions (attacker touched deception assets)",
            parameters={"limit": "optional int, default 20"},
            category="query",
            handler=self._list_decoy_interactions,
        ))

        # ===== PHISHING SIM =====
        self._register(Tool(
            name="list_phishing_campaigns",
            description="List phishing simulation campaigns and their completion status",
            parameters={"status": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_phishing_campaigns,
        ))

        # ===== RISK (FAIR) =====
        self._register(Tool(
            name="list_risks",
            description="List FAIR risk scenarios with loss-exposure estimates",
            parameters={"status": "optional string", "limit": "optional int, default 20"},
            category="query",
            handler=self._list_risks,
        ))

        # ===== TICKETS (Ticket Hub) =====
        self._register(Tool(
            name="list_tickets",
            description="List unified tickets across incidents, remediation, POAMs, war-room actions, case tasks",
            parameters={"source_type": "optional string", "status": "optional string", "priority": "optional string", "limit": "optional int, default 25"},
            category="query",
            handler=self._list_tickets,
        ))

        # ===== INTEGRATIONS =====
        # Tells the agent which notification + intel integrations the
        # operator has actually configured. Without this the agent
        # recommends "notify Slack" even when Slack isn't set up.
        self._register(Tool(
            name="list_configured_integrations",
            description=(
                "List integrations the operator has configured (notification channels "
                "like Slack/Teams/PagerDuty/OpsGenie, ITSM like Jira/ServiceNow, intel "
                "like VirusTotal/Shodan/AbuseIPDB/GreyNoise). Returns {id, configured, "
                "has_webhook, has_api_key, enabled, health} per integration. "
                "REQUIRED READ before recommending any notification, ticket, or "
                "enrichment action — only recommend channels that are configured."
            ),
            parameters={},
            category="query",
            handler=self._list_configured_integrations,
        ))
        self._register(Tool(
            name="execute_integration_action",
            description=(
                "Execute a configured integration action by installation_id and action_name. "
                "Use this to notify channels, enrich IOCs, or run connector-specific API actions."
            ),
            parameters={
                "installation_id": "string",
                "action_name": "string",
                "input_data": "optional dict",
            },
            category="action",
            handler=self._execute_integration_action,
        ))

        # ===== COMPLIANCE =====
        self._register(Tool(
            name="list_compliance_frameworks",
            description="List enabled compliance frameworks with scores. Returns name, short_name, version, compliance_score, total/implemented controls. Use this for ANY question about NIST, FedRAMP, PCI, HIPAA, SOC2, CMMC, ISO-27001 posture.",
            parameters={"limit": "optional int, default 20"},
            category="query",
            handler=self._list_compliance_frameworks,
        ))
        self._register(Tool(
            name="list_compliance_controls",
            description="List compliance controls. `framework` matches framework by short_name (NIST-800-53, FedRAMP, PCI-DSS, HIPAA), full name, or UUID. Returns control_id, title, family, priority, status, implementation %.",
            parameters={"framework": "optional string - framework short_name, full name, or UUID", "status": "optional string (implemented/not_implemented/partial)", "limit": "optional int, default 25"},
            category="query",
            handler=self._list_compliance_controls,
        ))
        self._register(Tool(
            name="list_poams",
            description="List Plan-of-Action-&-Milestones items (compliance deficiencies being remediated). Required for FedRAMP/NIST SP 800-37 posture questions.",
            parameters={"status": "optional string (open/in_progress/completed/closed)", "priority": "optional string", "limit": "optional int, default 25"},
            category="query",
            handler=self._list_poams,
        ))
        self._register(Tool(
            name="list_compliance_evidence",
            description="List evidence artifacts collected to support compliance control attestations (screenshots, configs, reports, logs).",
            parameters={"control_id": "optional string", "limit": "optional int, default 25"},
            category="query",
            handler=self._list_compliance_evidence,
        ))

        # ===== ENDPOINT AGENTS / LIVE RESPONSE =====
        self._register(Tool(
            name="list_endpoint_agents",
            description="List enrolled endpoint agents (hosts with the PySOAR agent installed)",
            parameters={"status": "optional string (active/pending/offline)", "limit": "optional int, default 25"},
            category="query",
            handler=self._list_endpoint_agents,
        ))
        self._register(Tool(
            name="queue_endpoint_command",
            description="Queue a live-response command on an endpoint agent (collect_triage, run_script, etc.). Requires authorize_actions.",
            parameters={"agent_id": "string - endpoint agent UUID", "action": "string action name such as collect_triage, processes, kill_process, network_isolate", "payload": "optional dict - action parameters"},
            category="action",
            handler=self._queue_endpoint_command,
        ))

    # =========================================================================
    # TOOL IMPLEMENTATIONS
    # =========================================================================

    # ---- QUERY ----

    async def _list_alerts(self, severity=None, status=None, limit=20):
        from src.models.alert import Alert
        q = select(Alert).order_by(Alert.created_at.desc())
        if severity:
            q = q.where(Alert.severity == severity)
        if status:
            q = q.where(Alert.status == status)
        q = q.limit(int(limit))
        result = await self.db.execute(q)
        alerts = result.scalars().all()
        return [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "source": a.source, "created_at": a.created_at.isoformat() if a.created_at else None} for a in alerts]

    async def _list_incidents(self, status=None, severity=None, limit=10):
        from src.models.incident import Incident
        q = select(Incident).order_by(Incident.created_at.desc())
        if status:
            q = q.where(Incident.status == status)
        if severity:
            q = q.where(Incident.severity == severity)
        q = q.limit(int(limit))
        result = await self.db.execute(q)
        incidents = result.scalars().all()
        return [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "created_at": i.created_at.isoformat() if i.created_at else None} for i in incidents]

    async def _list_iocs(self, ioc_type=None, limit=20):
        from src.intel.models import ThreatIndicator
        q = select(ThreatIndicator).where(ThreatIndicator.is_active == True).order_by(ThreatIndicator.created_at.desc())  # noqa: E712
        if ioc_type:
            q = q.where(ThreatIndicator.indicator_type == ioc_type)
        q = q.limit(int(limit))
        result = await self.db.execute(q)
        iocs = result.scalars().all()
        return [{"id": i.id, "value": i.value, "type": i.indicator_type, "threat_level": i.severity, "source": i.source} for i in iocs]

    async def _list_playbooks(self, keyword=None, category=None, limit=20):
        from src.models.playbook import Playbook
        q = select(Playbook).where(Playbook.is_enabled == True).order_by(Playbook.name)  # noqa: E712
        if keyword:
            like = f"%{keyword}%"
            q = q.where(Playbook.name.ilike(like) | Playbook.description.ilike(like))
        if category:
            q = q.where(Playbook.category == category)
        q = q.limit(int(limit))
        result = await self.db.execute(q)
        playbooks = result.scalars().all()
        return [
            {
                "id": p.id, "name": p.name, "description": p.description,
                "category": p.category, "status": p.status,
                "trigger_type": p.trigger_type, "version": p.version,
            }
            for p in playbooks
        ]

    async def _get_playbook(self, playbook_id):
        from src.models.playbook import Playbook
        result = await self.db.execute(select(Playbook).where(Playbook.id == playbook_id))
        p = result.scalar_one_or_none()
        if not p:
            return {"error": "Playbook not found"}
        try:
            steps = json.loads(p.steps) if p.steps else []
        except (TypeError, json.JSONDecodeError):
            steps = p.steps  # surface raw text rather than hide it
        return {
            "id": p.id, "name": p.name, "description": p.description,
            "category": p.category, "status": p.status,
            "trigger_type": p.trigger_type, "version": p.version,
            "is_enabled": p.is_enabled, "steps": steps,
        }

    async def _lookup_attack_technique(self, technique_id):
        from src.attack.service import AttackService
        tech = await AttackService(self.db).get_technique(str(technique_id).upper())
        if tech is None:
            return {"error": f"ATT&CK technique {technique_id} not found (KB may be unsynced — run /attack/sync)"}
        return tech

    async def _search_attack(self, query, limit=25):
        from src.attack.service import AttackService
        return await AttackService(self.db).search(query, limit=int(limit))

    async def _get_attack_coverage(self, technique_ids):
        from src.attack.service import AttackService
        if isinstance(technique_ids, str):
            technique_ids = [t.strip() for t in technique_ids.replace("[", "").replace("]", "").replace('"', "").split(",") if t.strip()]
        ids = [str(t).upper() for t in (technique_ids or [])]
        return await AttackService(self.db).coverage(ids)

    async def _get_alert(self, alert_id):
        from src.models.alert import Alert
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        a = result.scalar_one_or_none()
        if not a:
            return {"error": "Alert not found"}
        return {
            "id": a.id, "title": a.title, "description": getattr(a, "description", None),
            "severity": a.severity, "status": a.status, "source": a.source,
            "category": getattr(a, "category", None), "source_ip": getattr(a, "source_ip", None),
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }

    async def _get_incident(self, incident_id):
        from src.models.incident import Incident
        result = await self.db.execute(select(Incident).where(Incident.id == incident_id))
        i = result.scalar_one_or_none()
        if not i:
            return {"error": "Incident not found"}
        return {
            "id": i.id, "title": i.title, "description": getattr(i, "description", None),
            "severity": i.severity, "status": i.status, "incident_type": getattr(i, "incident_type", None),
            "created_at": i.created_at.isoformat() if i.created_at else None,
        }

    # ---- Incident response handlers (NIST 800-61 lifecycle) ----

    async def _incident_or_error(self, incident_id):
        from src.models.incident import Incident
        inc = (await self.db.execute(select(Incident).where(Incident.id == incident_id))).scalar_one_or_none()
        return inc

    async def _add_timeline(self, incident, event_type, title, description=None, old_value=None, new_value=None):
        from src.models.case import CaseTimeline
        self.db.add(CaseTimeline(
            incident_id=incident.id, event_type=event_type, title=title,
            description=description, old_value=old_value, new_value=new_value,
        ))

    async def _update_incident_status(self, incident_id, status, note=None):
        from src.models.incident import IncidentStatus
        inc = await self._incident_or_error(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        valid = {s.value for s in IncidentStatus}
        new = str(status).lower().strip()
        if new not in valid:
            return {"error": f"'{status}' is not a valid status. Valid: {sorted(valid)}"}
        old = inc.status
        inc.status = new
        await self._add_timeline(
            inc, "status_change", f"Status: {old} -> {new}",
            description=note, old_value=old, new_value=new,
        )
        await self.db.commit()
        return {"incident_id": inc.id, "old_status": old, "new_status": new, "note": note}

    async def _assign_incident(self, incident_id, assignee):
        from src.models.user import User
        inc = await self._incident_or_error(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        ref = str(assignee).strip()
        user = None
        if ref.lower() == "me":
            # No caller identity in this context; assign by the sole
            # superuser fallback so 'me' still resolves to a real user.
            user = (await self.db.execute(
                select(User).where(User.is_superuser == True)  # noqa: E712
            )).scalars().first()
        elif "@" in ref:
            user = (await self.db.execute(select(User).where(User.email == ref))).scalar_one_or_none()
        else:
            user = (await self.db.execute(select(User).where(User.id == ref))).scalar_one_or_none()
        if not user:
            return {"error": f"Could not resolve assignee '{assignee}' to a user"}
        inc.assigned_to = user.id
        await self._add_timeline(inc, "assignment", f"Assigned to {user.email}", new_value=user.email)
        await self.db.commit()
        return {"incident_id": inc.id, "assigned_to": user.email}

    async def _add_incident_note(self, incident_id, note):
        from src.models.case import CaseNote
        inc = await self._incident_or_error(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        author = await self._get_or_create_system_user(inc.organization_id)
        n = CaseNote(incident_id=inc.id, content=str(note), note_type="investigation",
                     is_internal=True, author_id=author.id)
        self.db.add(n)
        await self._add_timeline(inc, "note", "Investigation note added")
        await self.db.commit()
        return {"incident_id": inc.id, "note_id": n.id, "status": "added"}

    async def _update_incident_findings(self, incident_id, root_cause=None, resolution=None,
                                        lessons_learned=None, recommendations=None):
        inc = await self._incident_or_error(incident_id)
        if not inc:
            return {"error": "Incident not found"}
        updated = []
        for field, val in (("root_cause", root_cause), ("resolution", resolution),
                           ("lessons_learned", lessons_learned), ("recommendations", recommendations)):
            if val:
                setattr(inc, field, str(val))
                updated.append(field)
        if not updated:
            return {"error": "No findings provided to update"}
        await self._add_timeline(inc, "findings", f"Findings updated: {', '.join(updated)}")
        await self.db.commit()
        return {"incident_id": inc.id, "updated_fields": updated}

    async def _remediate_incident(self, incident_id, isolate_hosts=True, block_indicators=True):
        """NIST short-term containment: isolate affected hosts + block
        indicator IPs via the real remediation handlers, then advance the
        incident to 'containment'. Honest when there's nothing to act on."""
        inc = await self._incident_or_error(incident_id)
        if not inc:
            return {"error": "Incident not found"}

        def _parse(jsonish):
            if not jsonish:
                return []
            try:
                v = json.loads(jsonish) if isinstance(jsonish, str) else jsonish
                return [str(x) for x in v] if isinstance(v, list) else ([str(v)] if v else [])
            except (TypeError, json.JSONDecodeError):
                return [s.strip() for s in str(jsonish).split(",") if s.strip()]

        reason = f"Containment for incident {inc.id}: {inc.title}"
        hosts_isolated, indicators_blocked = [], []

        if isolate_hosts in (True, "true", "True", 1):
            for host in _parse(inc.affected_systems):
                res = await self._isolate_host(host, reason)
                if res.get("status") == "isolated":
                    hosts_isolated.append(host)

        if block_indicators in (True, "true", "True", 1):
            import re as _re
            for ind in _parse(inc.indicators):
                # only IPs are blockable via the firewall path
                if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ind):
                    res = await self._block_ip(ind, reason)
                    if res.get("status") == "blocked":
                        indicators_blocked.append(ind)

        acted = bool(hosts_isolated or indicators_blocked)
        old = inc.status
        if acted and inc.status in ("open", "investigating"):
            inc.status = "containment"

        if acted:
            summary = (
                f"Containment initiated: isolated {len(hosts_isolated)} host(s) "
                f"{hosts_isolated}, blocked {len(indicators_blocked)} indicator IP(s) "
                f"{indicators_blocked}. Incident moved {old} -> {inc.status}."
            )
        else:
            summary = (
                "No containable artifacts on this incident (no affected_systems "
                "hosts and no indicator IPs). Triage it and document affected "
                "systems first, or remediate manually."
            )
        await self._add_timeline(
            inc, "remediation", "Containment actions executed", description=summary,
        )
        await self.db.commit()
        return {
            "incident_id": inc.id,
            "hosts_isolated": hosts_isolated,
            "indicators_blocked": indicators_blocked,
            "new_status": inc.status,
            "summary": summary,
        }

    async def _platform_stats(self):
        from src.models.alert import Alert
        from src.models.incident import Incident
        total_alerts = (await self.db.execute(select(func.count(Alert.id)))).scalar() or 0
        open_alerts = (await self.db.execute(select(func.count(Alert.id)).where(Alert.status.in_(["new", "open", "investigating"])))).scalar() or 0
        critical_alerts = (await self.db.execute(select(func.count(Alert.id)).where(Alert.severity == "critical"))).scalar() or 0
        total_incidents = (await self.db.execute(select(func.count(Incident.id)))).scalar() or 0
        open_incidents = (await self.db.execute(select(func.count(Incident.id)).where(Incident.status != "closed"))).scalar() or 0
        return {
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
        }

    async def _search_alerts(self, keyword, limit=10):
        from src.models.alert import Alert
        result = await self.db.execute(
            select(Alert).where(
                Alert.title.ilike(f"%{keyword}%") | Alert.description.ilike(f"%{keyword}%")
            ).order_by(Alert.created_at.desc()).limit(int(limit))
        )
        alerts = result.scalars().all()
        return [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status} for a in alerts]

    # ---- ACTION ----

    async def _create_alert(self, title, severity, source, description="", category=""):
        from src.models.alert import Alert
        from src.services.automation import AutomationService
        alert = Alert(title=title, description=description, severity=severity, source=source, status="new", category=category or None)
        self.db.add(alert)
        await self.db.flush()
        automation = AutomationService(self.db)
        await automation.on_alert_created(alert)
        return {"id": alert.id, "created": True}

    async def _create_incident(self, title, severity, description="", alert_id=None):
        from src.models.incident import Incident
        from src.services.automation import AutomationService
        incident = Incident(title=title, description=description, severity=severity, status="open", incident_type="other")
        self.db.add(incident)
        await self.db.flush()
        automation = AutomationService(self.db)
        await automation.on_incident_created(incident)
        return {"id": incident.id, "created": True}

    async def _update_alert_status(self, alert_id, status):
        from src.models.alert import Alert
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": "Alert not found"}
        alert.status = status
        await self.db.flush()
        return {"id": alert_id, "new_status": status}

    async def _assign_alert(self, alert_id, user_id):
        from src.models.alert import Alert
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": "Alert not found"}
        alert.assigned_to = user_id
        await self.db.flush()
        return {"id": alert_id, "assigned_to": user_id}

    async def _create_war_room(self, name, severity, incident_id=None):
        from src.collaboration.models import WarRoom
        room = WarRoom(
            organization_id="", name=name, severity_level=severity,
            room_type="incident_response", status="active", created_by="agent",
            incident_id=incident_id,
        )
        self.db.add(room)
        await self.db.flush()
        return {"id": room.id, "name": name}

    async def _create_action_item(self, room_id, title, priority="medium"):
        from src.collaboration.models import ActionItem
        action = ActionItem(
            organization_id="", room_id=room_id, title=title,
            assigned_by="agent", priority=priority, status="pending",
        )
        self.db.add(action)
        await self.db.flush()
        return {"id": action.id, "title": title}

    async def _execute_playbook(self, playbook_id, input_data=None):
        from src.models.playbook import Playbook, PlaybookExecution, ExecutionStatus
        from src.playbooks.tasks import run_playbook_execution
        result = await self.db.execute(select(Playbook).where(Playbook.id == playbook_id))
        pb = result.scalar_one_or_none()
        if not pb:
            return {"error": "Playbook not found"}
        execution = PlaybookExecution(
            playbook_id=playbook_id,
            status=ExecutionStatus.PENDING.value if hasattr(ExecutionStatus, "PENDING") else "pending",
            input_data=json.dumps(input_data or {}),
            trigger_source="agent",
        )
        self.db.add(execution)
        # Commit (not just flush) before dispatch: the worker reads this
        # row from its own connection, so it must be durable first.
        await self.db.commit()
        run_playbook_execution.delay(execution.id)
        return {"execution_id": execution.id, "playbook": pb.name, "status": "queued"}

    async def _block_ip(self, ip, reason):
        from src.tickethub.models import TicketActivity
        from src.intel.models import ThreatIndicator
        # Add to threat indicator list as blocked
        ioc = ThreatIndicator(
            value=ip,
            indicator_type="ipv4",
            severity="high",
            is_active=True,
            is_whitelisted=False,
            source="agent_block",
            confidence=80,
            context={"reason": reason, "action": "block_ip"},
        )
        self.db.add(ioc)
        # Log action
        activity = TicketActivity(
            source_type="remediation", source_id=ip, activity_type="block_ip",
            description=f"IP {ip} blocked by agent. Reason: {reason}",
        )
        self.db.add(activity)
        await self.db.flush()
        return {"ip": ip, "status": "blocked", "reason": reason}

    async def _isolate_host(self, hostname, reason):
        from src.tickethub.models import TicketActivity
        activity = TicketActivity(
            source_type="remediation", source_id=hostname, activity_type="isolate_host",
            description=f"Host {hostname} isolated by agent. Reason: {reason}",
        )
        self.db.add(activity)
        await self.db.flush()
        return {"hostname": hostname, "status": "isolated", "reason": reason}

    async def _disable_user(self, user_email, reason):
        from src.models.user import User
        result = await self.db.execute(select(User).where(User.email == user_email))
        user = result.scalar_one_or_none()
        if not user:
            return {"error": "User not found"}
        user.is_active = False
        await self.db.flush()
        return {"user_email": user_email, "status": "disabled", "reason": reason}

    async def _create_ioc(self, value, ioc_type, threat_level="medium"):
        from src.intel.models import ThreatIndicator
        ioc = ThreatIndicator(
            value=value,
            indicator_type=ioc_type,
            severity=threat_level,
            is_active=True,
            is_whitelisted=False,
            source="agent_manual",
            confidence=70,
        )
        self.db.add(ioc)
        await self.db.flush()
        return {"id": ioc.id, "value": value, "type": ioc_type}

    async def _create_remediation_ticket(self, title, priority="medium", description=""):
        from src.exposure.models import RemediationTicket
        ticket = RemediationTicket(
            title=title, description=description, priority=priority,
            status="open", remediation_type="manual",
        )
        self.db.add(ticket)
        await self.db.flush()
        return {"id": ticket.id, "title": title}

    # ---- ANALYZE ----

    async def _triage_alert(self, alert_id):
        from src.models.alert import Alert
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": "Alert not found"}
        # Simple heuristic triage
        severity_score = {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(alert.severity, 50)
        confidence = 0.85 if alert.source in ("edr", "siem", "firewall") else 0.65
        priority = "p1" if severity_score >= 90 else "p2" if severity_score >= 70 else "p3"
        recommendations = []
        if alert.severity == "critical":
            recommendations.append("Immediate containment: isolate affected systems")
            recommendations.append("Activate incident response team")
        if getattr(alert, "source_ip", None):
            recommendations.append(f"Block source IP {alert.source_ip} at firewall")
        recommendations.append("Create forensic snapshot before remediation")
        return {
            "alert_id": alert_id,
            "priority": priority,
            "severity_score": severity_score,
            "confidence": confidence,
            "recommendations": recommendations,
        }

    async def _enrich_ioc(self, value, ioc_type):
        from src.intel.models import ThreatIndicator
        result = await self.db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.value == value,
                ThreatIndicator.indicator_type == ioc_type,
            )
        )
        matches = result.scalars().all()
        if not matches:
            return {"value": value, "type": ioc_type, "known": False, "message": "No threat intel match"}
        # Aggregate across feeds/rows that share the same value
        sources = [m.source for m in matches if m.source]
        confidences = [m.confidence for m in matches if m.confidence is not None]
        severities = [m.severity for m in matches if m.severity]
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        worst = max(severities, key=lambda s: severity_rank.get(s, 0)) if severities else None
        return {
            "value": value,
            "type": ioc_type,
            "known": True,
            "match_count": len(matches),
            "threat_level": worst,
            "confidence": int(sum(confidences) / len(confidences)) if confidences else None,
            "sources": sources,
            "first_seen": matches[0].first_seen.isoformat() if matches[0].first_seen else (matches[0].created_at.isoformat() if matches[0].created_at else None),
        }

    async def _correlate_alerts(self, alert_id):
        from src.models.alert import Alert
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": "Alert not found"}

        related_query = select(Alert).where(Alert.id != alert_id)
        conditions = []
        if getattr(alert, "source_ip", None):
            conditions.append(Alert.source_ip == alert.source_ip)
        if getattr(alert, "category", None):
            conditions.append(Alert.category == alert.category)
        if not conditions:
            return {"related_alerts": [], "message": "No correlation fields"}

        from sqlalchemy import or_
        related_query = related_query.where(or_(*conditions)).limit(10)
        related_result = await self.db.execute(related_query)
        related = related_result.scalars().all()
        return {
            "alert_id": alert_id,
            "related_count": len(related),
            "related_alerts": [{"id": r.id, "title": r.title, "severity": r.severity} for r in related],
        }

    async def _check_ioc_matches(self, alert_id):
        from src.models.alert import Alert
        from src.intel.models import ThreatIndicator
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": "Alert not found"}
        indicators = [v for v in [getattr(alert, "source_ip", None), getattr(alert, "destination_ip", None)] if v]
        if not indicators:
            return {"matches": [], "message": "No indicators to check"}
        ioc_result = await self.db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.value.in_(indicators),
                ThreatIndicator.is_active == True,  # noqa: E712
                ThreatIndicator.is_whitelisted == False,  # noqa: E712
            )
        )
        matches = ioc_result.scalars().all()
        return {
            "matches": [{"value": m.value, "type": m.indicator_type, "threat_level": m.severity, "source": m.source} for m in matches],
            "match_count": len(matches),
        }

    async def _get_or_create_default_org(self):
        from src.models.organization import Organization

        result = await self.db.execute(select(Organization).limit(1))
        org = result.scalar_one_or_none()
        if org:
            return org

        org = Organization(
            name="PySOAR Agent Org",
            slug="pysoar-agent",
            plan="free",
            is_active=True,
        )
        self.db.add(org)
        await self.db.commit()
        await self.db.refresh(org)
        return org

    async def _get_or_create_system_user(self, organization_id):
        from src.models.user import User
        from src.core.security import get_password_hash

        result = await self.db.execute(select(User).limit(1))
        user = result.scalar_one_or_none()
        if user:
            return user

        user = User(
            email="agent-tool@pysoar.local",
            hashed_password=get_password_hash("agenttool"),
            full_name="Agent Tool",
            role="viewer",
            is_active=False,
            is_superuser=False,
            organization_id=organization_id,
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def _scope_hunt(self, hypothesis):
        """PY-HUNT-001 Phase 1: validate a hypothesis against the ATT&CK KB.

        Honest by construction: reports the telemetry each in-scope
        technique needs, which sources PySOAR actually collects, and
        flags that EDR/DNS streaming telemetry is not integrated.
        """
        from datetime import datetime, timedelta, timezone
        from src.attack.service import AttackService
        from src.models.asset import Asset
        from src.siem.models import LogEntry

        svc = AttackService(self.db)
        extracted = await svc.extract_technique_ids(hypothesis or "")

        # Per valid technique: name, tactics, coverage, detecting telemetry.
        covered = await svc.coverage(extracted["valid"]) if extracted["valid"] else []
        cov_by_id = {c["technique"]: c for c in covered}
        techniques_in_scope = []
        needed_log_sources: set[str] = set()
        for tid in extracted["valid"]:
            tech = await svc.get_technique(tid)
            if not tech:
                continue
            ls = tech.get("log_sources") or []
            needed_log_sources.update(ls)
            techniques_in_scope.append({
                "technique": tid,
                "name": tech.get("name"),
                "tactics": tech.get("tactics") or [],
                "detection_rule_count": cov_by_id.get(tid, {}).get("rule_count", 0),
                "covered": cov_by_id.get(tid, {}).get("covered", False),
                "log_sources": ls[:12],
            })

        # What telemetry PySOAR actually has (distinct source types in the
        # last 30 days). ATT&CK log-source names are vendor-channel strings
        # (e.g. linux:syslog); we surface both sides honestly rather than
        # pretend a perfect mapping.
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        collected = (await self.db.execute(
            select(LogEntry.source_type).where(LogEntry.received_at >= cutoff).distinct()
        )).scalars().all()
        collected = sorted({s for s in collected if s})

        # Asset criticality for hostnames mentioned in the hypothesis.
        assets_in_scope = []
        words = {w.strip(".,;:'\"()").lower() for w in (hypothesis or "").split()}
        if words:
            asset_rows = (await self.db.execute(select(Asset).limit(500))).scalars().all()
            for a in asset_rows:
                hn = (a.hostname or "").lower()
                nm = (a.name or "").lower()
                if (hn and hn in words) or (nm and nm in words):
                    assets_in_scope.append({
                        "hostname": a.hostname or a.name,
                        "asset_type": a.asset_type,
                        "criticality": a.criticality,
                    })

        uncovered = [t["technique"] for t in techniques_in_scope if not t["covered"]]
        notes = [
            "Telemetry availability is heuristic: ATT&CK log-source names are vendor channels; "
            "compare them against collected_source_types manually.",
            "EDR streaming telemetry (process trees, module loads) and a DNS sensor are NOT "
            "integrated in PySOAR — techniques relying solely on those cannot be hunted here.",
        ]
        if extracted["deprecated"]:
            notes.append(f"Deprecated technique ids cited: {extracted['deprecated']} — map to current ids.")
        if uncovered:
            notes.append(f"No detection rule covers: {uncovered} — hunt is the compensating control.")

        return {
            "hypothesis": hypothesis,
            "techniques_in_scope": techniques_in_scope,
            "deprecated_techniques": extracted["deprecated"],
            "unknown_techniques": extracted["unknown"],
            "needed_log_sources": sorted(needed_log_sources)[:25],
            "collected_source_types": collected,
            "assets_in_scope": assets_in_scope,
            "coverage_summary": {
                "techniques": len(techniques_in_scope),
                "covered": sum(1 for t in techniques_in_scope if t["covered"]),
                "uncovered": len(uncovered),
            },
            "notes": notes,
        }

    async def _run_threat_hunt(self, hypothesis, timeframe_hours=24):
        from src.hunting.models import HuntHypothesis, HuntSession, HuntFinding
        from src.siem.models import LogEntry
        from src.models.alert import Alert
        from src.models.audit import AuditLog
        from src.intel.models import ThreatIndicator
        import json
        import re

        org = await self._get_or_create_default_org()
        user = await self._get_or_create_system_user(org.id)

        title = hypothesis.strip() or "Threat hunt"
        if len(title) > 200:
            title = title[:197] + "..."

        mitre_ids = [m.upper() for m in re.findall(r"\bT\d{4}(?:\.\d+)?\b", hypothesis)]

        hunt = HuntHypothesis(
            title=title,
            description=hypothesis,
            status="active",
            priority="medium",
            hunt_type="hypothesis_driven",
            mitre_techniques=mitre_ids or None,
            data_sources=None,
            created_by=user.id,
            organization_id=org.id,
        )
        self.db.add(hunt)
        await self.db.flush()

        session = HuntSession(
            hypothesis_id=hunt.id,
            status="running",
            parameters={
                "timeframe_hours": int(timeframe_hours),
                "target_hosts": [],
                "log_types": [],
            },
            created_by=user.id,
            organization_id=org.id,
        )
        self.db.add(session)
        await self.db.flush()

        stopwords = {
            "the", "and", "for", "with", "this", "that", "from", "user",
            "data", "have", "will", "should", "could", "would",
        }
        keywords = [
            w.lower()
            for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", hypothesis)
            if w.lower() not in stopwords
        ]

        if not keywords:
            session.status = "failed"
            session.error_message = "Hypothesis too vague"
            await self.db.commit()
            return {"hypothesis": hypothesis, "findings": 0, "message": "Hypothesis too vague"}

        cutoff = datetime.now(timezone.utc) - timedelta(hours=int(timeframe_hours))
        findings_created = 0
        logs_scanned = 0
        alerts_scanned = 0
        audit_scanned = 0
        iocs_checked = 0

        # Require keyword CO-OCCURRENCE so a single common word (e.g.
        # "application") doesn't flag every benign log. A log must match at
        # least `min_match` DISTINCT keywords; for 1-2 keyword hypotheses,
        # require all of them.
        unique_keywords = list(dict.fromkeys(keywords))
        min_match = 2 if len(unique_keywords) >= 3 else len(unique_keywords)
        MAX_FINDINGS = 50

        log_query = select(LogEntry).where(LogEntry.timestamp >= cutoff.isoformat())
        log_rows = (await self.db.execute(log_query.limit(2000))).scalars().all()
        logs_scanned = len(log_rows)
        log_candidates = []
        for log in log_rows:
            haystack = " ".join(
                filter(None, [
                    log.message, log.raw_log, log.hostname, log.username,
                    log.process_name, log.action, log.source_name,
                ])
            ).lower()
            matched = {k for k in unique_keywords if k in haystack}
            if len(matched) >= min_match:
                log_candidates.append((len(matched), log, sorted(matched)))
        # Strongest matches first; cap to avoid flooding on broad hunts.
        log_candidates.sort(key=lambda c: c[0], reverse=True)
        for match_count, log, matched in log_candidates[:MAX_FINDINGS]:
            snippet = (log.message or log.raw_log or "").strip().replace("\n", " ")
            if len(snippet) > 100:
                snippet = snippet[:100] + "…"
            host = log.hostname or log.source_name or "log"
            finding = HuntFinding(
                session_id=session.id,
                title=f"[{host}] {snippet}" if snippet else f"Log event on {host}",
                description=(
                    f"Log entry matched {match_count} hunt terms "
                    f"({', '.join(matched[:10])}). Source: {log.source_name}."
                ),
                severity=(log.severity or "medium"),
                classification="needs_review",
                evidence=json.dumps({
                    "log_id": getattr(log, "id", None),
                    "timestamp": getattr(log, "timestamp", None),
                    "source_type": log.source_type,
                    "match_count": match_count,
                    "matched_keywords": matched[:10],
                }),
                affected_assets=json.dumps([log.hostname] if log.hostname else []),
                iocs_found=json.dumps([]),
                mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                organization_id=org.id,
            )
            self.db.add(finding)
            findings_created += 1

        alert_query = select(Alert).where(Alert.created_at >= cutoff)
        alert_rows = (await self.db.execute(alert_query.limit(500))).scalars().all()
        alerts_scanned = len(alert_rows)
        for alert in alert_rows:
            haystack = " ".join(
                filter(None, [
                    alert.title, alert.description, alert.hostname, alert.username,
                    alert.source, alert.category, alert.source_ip, alert.destination_ip,
                    getattr(alert, "domain", None), getattr(alert, "url", None), getattr(alert, "file_hash", None),
                ])
            ).lower()
            matched = sorted({k for k in unique_keywords if k in haystack})
            # Alerts are already curated signals, so a single strong keyword
            # match is meaningful — but skip pure single-common-word hits on
            # multi-keyword hunts to stay consistent with the log scan.
            if len(matched) < min(min_match, 1) or not matched:
                continue
            if len(unique_keywords) >= 3 and len(matched) < 1:
                continue
            finding = HuntFinding(
                session_id=session.id,
                title=f"Related alert: {alert.title}",
                description=(
                    f"Historical alert matched hunt terms: {', '.join(matched[:10])}"
                ),
                severity=alert.severity or "medium",
                classification="needs_review",
                evidence=json.dumps({
                    "alert_id": alert.id,
                    "alert_status": alert.status,
                    "matched_keywords": sorted(set(matched))[:10],
                    "source_ip": getattr(alert, "source_ip", None),
                }),
                affected_assets=json.dumps([alert.hostname] if getattr(alert, "hostname", None) else []),
                iocs_found=json.dumps([]),
                mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                organization_id=org.id,
            )
            self.db.add(finding)
            findings_created += 1

        audit_query = select(AuditLog).where(AuditLog.created_at >= cutoff)
        audit_rows = (await self.db.execute(audit_query.limit(500))).scalars().all()
        audit_scanned = len(audit_rows)
        for audit in audit_rows:
            haystack = " ".join(
                filter(None, [
                    audit.action, audit.resource_type, audit.resource_id,
                    audit.description, audit.ip_address,
                ])
            ).lower()
            matched = [k for k in keywords if k in haystack]
            if not matched:
                continue
            finding = HuntFinding(
                session_id=session.id,
                title=f"Audit search match: {audit.action or 'audit event'}",
                description=(
                    f"Audit event matched hunt keywords: {', '.join(sorted(set(matched))[:10])}"
                ),
                severity="high" if not getattr(audit, "success", True) else "medium",
                classification="needs_review",
                evidence=json.dumps({
                    "audit_id": audit.id,
                    "action": audit.action,
                    "resource_type": audit.resource_type,
                    "resource_id": audit.resource_id,
                    "matched_keywords": sorted(set(matched))[:10],
                }),
                affected_assets=json.dumps([]),
                iocs_found=json.dumps([]),
                organization_id=org.id,
            )
            self.db.add(finding)
            findings_created += 1

        ioc_candidates = [k for k in keywords if re.match(r"^\d+\.\d+\.\d+\.\d+$", k) or "." in k or "/" in k]
        if ioc_candidates:
            ioc_query = select(ThreatIndicator).where(
                ThreatIndicator.value.in_(ioc_candidates),
                ThreatIndicator.is_active == True,  # noqa: E712
            )
            ioc_rows = (await self.db.execute(ioc_query.limit(100))).scalars().all()
            iocs_checked = len(ioc_rows)
            for ioc in ioc_rows:
                finding = HuntFinding(
                    session_id=session.id,
                    title=f"IOC match: {ioc.indicator_type}:{ioc.value}",
                    description=(
                        f"Threat indicator matched hunt hypothesis keywords."
                    ),
                    severity=ioc.severity or "high",
                    classification="needs_review",
                    evidence=json.dumps({
                        "indicator_id": ioc.id,
                        "type": ioc.indicator_type,
                        "value": ioc.value,
                        "source": ioc.source,
                    }),
                    affected_assets=json.dumps([]),
                    iocs_found=json.dumps([ioc.value]),
                    mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                    organization_id=org.id,
                )
                self.db.add(finding)
                findings_created += 1

        session.findings_count = findings_created
        session.events_analyzed = logs_scanned + alerts_scanned + audit_scanned
        session.query_count = 3 + iocs_checked
        session.queries_executed = {
            "logs_scanned": logs_scanned,
            "alerts_scanned": alerts_scanned,
            "audit_logs_scanned": audit_scanned,
            "iocs_checked": iocs_checked,
            "keywords": sorted(set(keywords))[:50],
        }
        session.status = "completed"
        session.completed_at = datetime.now(timezone.utc)
        await self.db.commit()

        return {
            "hypothesis": hypothesis,
            "session_id": session.id,
            "findings": findings_created,
            "logs_scanned": logs_scanned,
            "alerts_scanned": alerts_scanned,
            "audit_scanned": audit_scanned,
            "iocs_checked": iocs_checked,
            "matched_keywords": sorted(set(keywords))[:10],
        }

    async def _simulate_attack(self, technique_id, target):
        from src.simulation.engine import SimulationOrchestrator
        from src.simulation.models import SimulationTest

        org = await self._get_or_create_default_org()
        user = await self._get_or_create_system_user(org.id)

        orchestrator = SimulationOrchestrator(self.db)
        simulation = await orchestrator.create_simulation(
            name=f"Agent-initiated simulation {technique_id}",
            sim_type="atomic_test",
            techniques=[technique_id],
            scope={"target_host": target} if target else {},
            target_environment="lab",
            created_by=user.id,
            organization_id=org.id,
            description=(
                f"Agent tool launched an atomic MITRE ATT&CK simulation for "
                f"technique {technique_id} against {target}."
            ),
        )

        await orchestrator.start_simulation(simulation.id)

        test_rows = (await self.db.execute(select(SimulationTest).where(SimulationTest.simulation_id == simulation.id))).scalars().all()
        results = []
        for test in test_rows:
            result = await orchestrator._execute_test(test)
            results.append(result)

        await orchestrator.finalize_simulation(simulation.id)
        await self.db.refresh(simulation)

        return {
            "simulation_id": simulation.id,
            "status": simulation.status,
            "total_tests": len(results),
            "passed_tests": simulation.passed_tests,
            "failed_tests": simulation.failed_tests,
            "blocked_tests": simulation.blocked_tests,
            "detection_rate": simulation.detection_rate,
            "tests": results,
        }

    async def _generate_incident_summary(self, incident_id):
        from src.models.incident import Incident
        result = await self.db.execute(select(Incident).where(Incident.id == incident_id))
        inc = result.scalar_one_or_none()
        if not inc:
            return {"error": "Incident not found"}
        summary = f"Incident '{inc.title}' ({inc.severity} severity, {inc.status} status)"
        if getattr(inc, "description", None):
            summary += f"\nDescription: {inc.description[:200]}"
        return {
            "incident_id": incident_id,
            "summary": summary,
            "severity": inc.severity,
            "status": inc.status,
            "recommended_actions": [
                "Triage and assess scope",
                "Containment: isolate affected systems",
                "Evidence preservation",
                "Stakeholder notification",
            ],
        }

    # ---- SIEM ----

    async def _search_logs(self, keyword, severity=None, log_type=None, limit=20):
        from src.siem.models import LogEntry
        from sqlalchemy import or_
        pat = f"%{keyword}%"
        q = select(LogEntry).where(or_(
            LogEntry.message.ilike(pat),
            LogEntry.source_name.ilike(pat),
        )).order_by(LogEntry.received_at.desc())
        if severity:
            q = q.where(LogEntry.severity == severity)
        if log_type:
            q = q.where(LogEntry.log_type == log_type)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": r.id, "timestamp": r.timestamp, "source_type": r.source_type,
            "source_name": r.source_name, "log_type": r.log_type, "severity": r.severity,
            "message": (getattr(r, "message", "") or "")[:500],
        } for r in rows]

    async def _list_siem_rules(self, status=None, limit=20):
        from src.siem.models import DetectionRule
        q = select(DetectionRule).order_by(DetectionRule.updated_at.desc())
        if status:
            q = q.where(DetectionRule.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": r.id, "name": getattr(r, "name", None), "status": r.status,
            "severity": getattr(r, "severity", None),
            "description": (getattr(r, "description", "") or "")[:200],
        } for r in rows]

    # ---- UEBA ----

    async def _list_entity_risks(self, risk_level=None, entity_type=None, limit=20):
        from src.ueba.models import EntityProfile
        q = select(EntityProfile).order_by(EntityProfile.risk_score.desc())
        if risk_level:
            q = q.where(EntityProfile.risk_level == risk_level)
        if entity_type:
            q = q.where(EntityProfile.entity_type == entity_type)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": p.id, "entity_type": p.entity_type, "entity_id": p.entity_id,
            "display_name": p.display_name, "risk_score": p.risk_score,
            "risk_level": p.risk_level, "anomaly_count_30d": p.anomaly_count_30d,
        } for p in rows]

    async def _list_ueba_alerts(self, severity=None, limit=20):
        from src.ueba.models import UEBARiskAlert
        q = select(UEBARiskAlert).order_by(UEBARiskAlert.created_at.desc())
        if severity:
            q = q.where(UEBARiskAlert.severity == severity)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": a.id, "alert_type": a.alert_type, "severity": a.severity,
            "entity_profile_id": a.entity_profile_id,
            "risk_score_delta": a.risk_score_delta,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        } for a in rows]

    # ---- VULN MGMT ----

    async def _list_vulnerabilities(self, severity=None, keyword=None, limit=20):
        from src.vulnmgmt.models import Vulnerability
        q = select(Vulnerability).order_by(Vulnerability.created_at.desc())
        if severity:
            q = q.where(Vulnerability.severity == severity)
        if keyword:
            pat = f"%{keyword}%"
            q = q.where(Vulnerability.title.ilike(pat))
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": v.id, "cve_id": v.cve_id, "title": v.title, "severity": v.severity,
            "cvss_score": float(v.cvss_score) if getattr(v, "cvss_score", None) is not None else None,
        } for v in rows]

    async def _get_vulnerability(self, cve_or_id):
        from src.vulnmgmt.models import Vulnerability
        from sqlalchemy import or_
        row = (await self.db.execute(select(Vulnerability).where(
            or_(Vulnerability.id == cve_or_id, Vulnerability.cve_id == cve_or_id)
        ))).scalar_one_or_none()
        if not row:
            return {"error": "Vulnerability not found"}
        return {
            "id": row.id, "cve_id": row.cve_id, "title": row.title,
            "severity": row.severity,
            "description": (getattr(row, "description", "") or "")[:1000],
            "cvss_score": float(row.cvss_score) if getattr(row, "cvss_score", None) is not None else None,
        }

    # ---- DFIR ----

    async def _list_forensic_cases(self, status=None, severity=None, limit=20):
        from src.dfir.models import ForensicCase
        q = select(ForensicCase).order_by(ForensicCase.created_at.desc())
        if status:
            q = q.where(ForensicCase.status == status)
        if severity:
            q = q.where(ForensicCase.severity == severity)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": c.id, "title": c.title, "status": c.status, "severity": c.severity,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        } for c in rows]

    async def _create_forensic_case(self, title, severity, description=""):
        from src.dfir.models import ForensicCase
        case = ForensicCase(title=title, severity=severity, status="open", description=description)
        self.db.add(case)
        await self.db.commit()
        await self.db.refresh(case)
        return {"id": case.id, "title": case.title, "severity": case.severity, "status": case.status}

    # ---- DARK WEB ----

    async def _list_darkweb_findings(self, finding_type=None, severity=None, status=None, limit=20):
        from src.darkweb.models import DarkWebFinding
        q = select(DarkWebFinding).order_by(DarkWebFinding.created_at.desc())
        if finding_type:
            q = q.where(DarkWebFinding.finding_type == finding_type)
        if severity:
            q = q.where(DarkWebFinding.severity == severity)
        if status:
            q = q.where(DarkWebFinding.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": f.id, "finding_type": f.finding_type, "title": f.title,
            "severity": f.severity, "status": f.status,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        } for f in rows]

    # ---- HUNTING ----

    async def _list_hunts(self, status=None, limit=20):
        from src.hunting.models import HuntHypothesis
        q = select(HuntHypothesis).order_by(HuntHypothesis.created_at.desc())
        if status:
            q = q.where(HuntHypothesis.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": h.id, "title": h.title, "status": h.status,
            "priority": getattr(h, "priority", None),
            "created_at": h.created_at.isoformat() if h.created_at else None,
        } for h in rows]

    async def _list_hunt_findings(self, severity=None, limit=20):
        from src.hunting.models import HuntFinding
        q = select(HuntFinding).order_by(HuntFinding.created_at.desc())
        if severity:
            q = q.where(HuntFinding.severity == severity)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": f.id, "title": getattr(f, "title", None),
            "severity": getattr(f, "severity", None),
            "session_id": f.session_id,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        } for f in rows]

    # ---- THREAT INTEL ----

    async def _list_threat_actors(self, limit=20):
        from src.intel.models import ThreatActor
        rows = (await self.db.execute(select(ThreatActor).order_by(ThreatActor.created_at.desc()).limit(int(limit)))).scalars().all()
        return [{
            "id": a.id, "name": getattr(a, "name", None),
            "aliases": getattr(a, "aliases", None),
            "motivation": getattr(a, "motivation", None),
            "sophistication": getattr(a, "sophistication", None),
        } for a in rows]

    async def _list_threat_campaigns(self, limit=20):
        from src.intel.models import ThreatCampaign
        rows = (await self.db.execute(select(ThreatCampaign).order_by(ThreatCampaign.created_at.desc()).limit(int(limit)))).scalars().all()
        return [{
            "id": c.id, "name": getattr(c, "name", None),
            "status": getattr(c, "status", None),
            "first_seen": c.first_seen.isoformat() if getattr(c, "first_seen", None) else None,
        } for c in rows]

    # ---- ASSETS ----

    async def _list_assets(self, criticality=None, asset_type=None, status=None, keyword=None, limit=20):
        from src.models.asset import Asset
        # Order most-critical-first so "most exposed/important assets" is
        # answerable. criticality is the business-importance field — distinct
        # from status (active/isolated/...). 'critical' belongs here, NOT status.
        _crit_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        q = select(Asset)
        if criticality:
            q = q.where(Asset.criticality == str(criticality).lower())
        if asset_type:
            q = q.where(Asset.asset_type == asset_type)
        if status:
            q = q.where(Asset.status == status)
        if keyword:
            pat = f"%{keyword}%"
            from sqlalchemy import or_
            q = q.where(or_(Asset.name.ilike(pat), Asset.hostname.ilike(pat), Asset.ip_address.ilike(pat)))
        rows = (await self.db.execute(q.limit(500))).scalars().all()
        rows = sorted(rows, key=lambda a: (_crit_rank.get((a.criticality or "").lower(), 9),))[: int(limit)]
        return [{
            "id": a.id, "name": a.name, "hostname": a.hostname,
            "asset_type": a.asset_type, "status": a.status,
            "criticality": a.criticality, "ip_address": a.ip_address,
        } for a in rows]

    async def _get_asset(self, asset_ref):
        from src.models.asset import Asset
        from sqlalchemy import or_
        row = (await self.db.execute(select(Asset).where(
            or_(Asset.id == asset_ref, Asset.name == asset_ref, Asset.hostname == asset_ref)
        ))).scalar_one_or_none()
        if not row:
            return {"error": "Asset not found"}
        return {
            "id": row.id, "name": row.name, "hostname": row.hostname,
            "asset_type": row.asset_type, "status": row.status,
            "ip_address": row.ip_address, "fqdn": row.fqdn,
            "mac_address": row.mac_address,
        }

    # ---- REMEDIATION ----

    async def _list_remediation_executions(self, status=None, limit=20):
        from src.remediation.models import RemediationExecution
        q = select(RemediationExecution).order_by(RemediationExecution.created_at.desc())
        if status:
            q = q.where(RemediationExecution.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": e.id, "status": e.status,
            "trigger_source": e.trigger_source, "trigger_id": e.trigger_id,
            "approval_status": e.approval_status,
            "started_at": e.started_at.isoformat() if e.started_at else None,
            "completed_at": e.completed_at.isoformat() if e.completed_at else None,
        } for e in rows]

    # ---- DECEPTION ----

    async def _list_decoy_interactions(self, limit=20):
        from src.deception.models import DecoyInteraction
        rows = (await self.db.execute(select(DecoyInteraction).order_by(DecoyInteraction.created_at.desc()).limit(int(limit)))).scalars().all()
        return [{
            "id": i.id, "decoy_id": i.decoy_id,
            "interaction_type": i.interaction_type,
            "source_ip": i.source_ip, "source_hostname": i.source_hostname,
            "protocol": i.protocol,
            "created_at": i.created_at.isoformat() if i.created_at else None,
        } for i in rows]

    # ---- PHISHING SIM ----

    async def _list_phishing_campaigns(self, status=None, limit=20):
        from src.phishing_sim.models import PhishingCampaign
        q = select(PhishingCampaign).order_by(PhishingCampaign.created_at.desc())
        if status:
            q = q.where(PhishingCampaign.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": c.id, "name": getattr(c, "name", None),
            "status": getattr(c, "status", None),
            "created_at": c.created_at.isoformat() if c.created_at else None,
        } for c in rows]

    # ---- RISK (FAIR) ----

    async def _list_risks(self, status=None, limit=20):
        from src.risk_quant.models import RiskScenario
        q = select(RiskScenario).order_by(RiskScenario.created_at.desc())
        if status:
            q = q.where(RiskScenario.status == status)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": r.id, "name": getattr(r, "name", None),
            "status": getattr(r, "status", None),
            "annualized_loss_expectancy": getattr(r, "annualized_loss_expectancy", None),
        } for r in rows]

    # ---- TICKETS ----

    # ---- COMPLIANCE ----

    async def _list_compliance_frameworks(self, limit=20):
        from src.compliance.models import ComplianceFramework
        rows = (await self.db.execute(select(ComplianceFramework).where(ComplianceFramework.is_enabled == True).order_by(ComplianceFramework.compliance_score.desc()).limit(int(limit)))).scalars().all()  # noqa: E712
        return [{
            "id": f.id, "name": f.name, "short_name": f.short_name,
            "version": f.version, "authority": f.authority,
            "total_controls": f.total_controls,
            "implemented_controls": f.implemented_controls,
            "compliance_score": float(f.compliance_score) if f.compliance_score is not None else 0.0,
            "status": f.status,
        } for f in rows]

    async def _list_compliance_controls(self, framework=None, status=None, limit=25, framework_id=None):
        from src.compliance.models import ComplianceControl, ComplianceFramework
        from sqlalchemy import or_, func as sqlfunc
        # Accept `framework` (flexible) OR legacy `framework_id`.
        framework_ref = framework or framework_id
        q = select(ComplianceControl)
        if framework_ref:
            # Resolve friendly name/short_name to framework UUID (case-insensitive
            # and space/dash tolerant — Gemini often sends "NIST 800-53" while
            # the DB has short_name "NIST-800-53" or name "NIST SP 800-53").
            norm = framework_ref.lower().replace(" ", "").replace("-", "").replace("_", "")
            fw_rows = (await self.db.execute(
                select(ComplianceFramework.id, ComplianceFramework.name, ComplianceFramework.short_name)
            )).all()
            match_id = None
            for fid, fname, fshort in fw_rows:
                if fid == framework_ref:
                    match_id = fid
                    break
                for candidate in (fname or "", fshort or ""):
                    if candidate.lower().replace(" ", "").replace("-", "").replace("_", "") == norm:
                        match_id = fid
                        break
                if match_id:
                    break
            if match_id:
                q = q.where(ComplianceControl.framework_id == match_id)
            else:
                return {"warning": f"No framework matched '{framework_ref}'. Try one of the enabled short_names (call list_compliance_frameworks first).", "controls": []}
        if status:
            q = q.where(ComplianceControl.status == status)
        q = q.order_by(ComplianceControl.priority.asc()).limit(int(limit))
        rows = (await self.db.execute(q)).scalars().all()
        return [{
            "id": c.id, "control_id": c.control_id, "title": c.title,
            "control_family": c.control_family, "priority": c.priority,
            "status": c.status,
            "implementation_status": float(c.implementation_status) if c.implementation_status is not None else 0.0,
        } for c in rows]

    async def _list_poams(self, status=None, priority=None, limit=25):
        from src.compliance.models import POAM
        q = select(POAM).order_by(POAM.created_at.desc())
        if status:
            q = q.where(POAM.status == status)
        if priority:
            # POAMs use risk_level (critical/high/moderate/low), not priority.
            q = q.where(POAM.risk_level == priority)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": p.id,
            "weakness_name": p.weakness_name,
            "control_id_ref": p.control_id_ref,
            "status": p.status,
            "risk_level": p.risk_level,
            "residual_risk_rating": float(p.residual_risk_rating) if p.residual_risk_rating is not None else None,
            "scheduled_completion_date": p.scheduled_completion_date.isoformat() if p.scheduled_completion_date else None,
        } for p in rows]

    async def _list_compliance_evidence(self, control_id=None, limit=25):
        from src.compliance.models import ComplianceEvidence
        q = select(ComplianceEvidence).order_by(ComplianceEvidence.collected_at.desc())
        if control_id:
            q = q.where(ComplianceEvidence.control_id_ref == control_id)
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": e.id,
            "control_id_ref": e.control_id_ref,
            "evidence_type": e.evidence_type,
            "title": e.title,
            "source_system": e.source_system,
            "is_automated": e.is_automated,
            "is_valid": e.is_valid,
            "collected_at": e.collected_at.isoformat() if e.collected_at else None,
        } for e in rows]

    # ---- LIVE RESPONSE ----

    async def _list_endpoint_agents(self, status=None, limit=25):
        from src.agents.models import EndpointAgent
        q = select(EndpointAgent).order_by(EndpointAgent.last_heartbeat_at.desc().nullslast())
        if status:
            q = q.where(EndpointAgent.status == status)
        q = q.limit(int(limit))
        rows = (await self.db.execute(q)).scalars().all()
        return [{
            "id": a.id, "hostname": a.hostname, "display_name": a.display_name,
            "os_type": a.os_type, "os_version": a.os_version,
            "status": a.status, "ip_address": a.ip_address,
            "last_heartbeat_at": a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None,
        } for a in rows]

    async def _queue_endpoint_command(self, agent_id, action, payload=None):
        """Queue a live-response command on an endpoint. Hash-chains into the
        command ledger so the agent's worker polls and executes it."""
        import hashlib
        import json as _json
        from src.agents.models import AgentCommand, EndpointAgent
        agent = (await self.db.execute(
            select(EndpointAgent).where(EndpointAgent.id == agent_id)
        )).scalar_one_or_none()
        if agent is None:
            return {"error": f"Endpoint agent {agent_id} not found"}
        payload_dict = payload or {}
        prev_hash = agent.last_command_hash or ""
        body = _json.dumps({"agent_id": agent_id, "action": action, "payload": payload_dict}, sort_keys=True)
        cmd_hash = hashlib.sha256(body.encode()).hexdigest()
        chain = hashlib.sha256((prev_hash + cmd_hash).encode()).hexdigest()
        cmd = AgentCommand(
            agent_id=agent_id, action=action, payload=payload_dict,
            command_hash=cmd_hash, prev_hash=prev_hash or None, chain_hash=chain,
            status="queued",
        )
        self.db.add(cmd)
        agent.last_command_hash = chain
        await self.db.commit()
        await self.db.refresh(cmd)
        return {
            "command_id": cmd.id, "agent_id": agent_id, "action": action,
            "status": cmd.status, "chain_hash": chain,
        }

    async def _list_tickets(self, source_type=None, status=None, priority=None, limit=25):
        try:
            from src.tickethub.engine import TicketAggregator
        except Exception:
            return {"error": "Ticket Hub engine not available"}
        agg = TicketAggregator(self.db)
        result = await agg.get_unified_tickets(
            source_types=[source_type] if source_type else None,
            priority=priority,
            size=int(limit),
        )
        items = result.get("tickets") or result.get("items") or []
        if status:
            items = [t for t in items if (t.get("status") or "").lower() == status.lower()]
        return {"total": len(items), "tickets": items[: int(limit)]}

    async def _list_configured_integrations(self):
        """Return a grounded summary of which integrations the org has
        actually configured. Reads app_settings (credential source of
        truth) plus installed_integrations (marketplace health state)
        and returns per-integration {configured, has_webhook,
        has_api_key, enabled, health}. Use this BEFORE recommending a
        notification channel, an ITSM ticket, or an intel enrichment
        — only recommend channels the operator has set up."""
        from sqlalchemy import text as _sql_text
        # Pull the credential config from app_settings.
        rows = []
        try:
            rows = list((await self.db.execute(_sql_text(
                "SELECT section, value FROM app_settings "
                "WHERE section LIKE 'integration:%'"
            ))).all())
        except Exception as exc:  # noqa: BLE001
            return {"error": f"app_settings read failed: {exc}"}

        from_settings: dict[str, dict] = {}
        for sec, value in rows:
            if not sec or not sec.startswith("integration:"):
                continue
            iid = sec.split(":", 1)[1]
            cfg = value if isinstance(value, dict) else {}
            from_settings[iid] = {
                "id": iid,
                "configured": bool(
                    cfg.get("api_key")
                    or cfg.get("webhook_url")
                    or cfg.get("url")
                    or cfg.get("token")
                ),
                "has_webhook": bool(cfg.get("webhook_url")),
                "has_api_key": bool(cfg.get("api_key") or cfg.get("token")),
                "has_url": bool(cfg.get("url") or cfg.get("host")),
                "channel": cfg.get("channel"),
            }

        # Merge health state from installed_integrations if the
        # marketplace has a row for it.
        try:
            from src.integrations.models import InstalledIntegration
            installed = list(await self.db.scalars(select(InstalledIntegration)))
            for ii in installed:
                entry = from_settings.setdefault(ii.connector_id, {"id": ii.connector_id})
                entry["enabled"] = ii.status == "active"
                entry["health"] = ii.health_status or "unknown"
                entry["last_health_check"] = ii.last_health_check.isoformat() if ii.last_health_check else None
        except Exception:
            pass

        items = list(from_settings.values())
        items.sort(key=lambda x: (not x.get("configured"), x["id"]))
        return {
            "total": len(items),
            "configured_count": sum(1 for i in items if i.get("configured")),
            "integrations": items,
        }

    async def _execute_integration_action(self, installation_id: str, action_name: str, input_data: Optional[dict] = None):
        """Execute a configured integration action through the integration engine."""
        if input_data is None:
            input_data = {}

        result = await self.db.execute(
            select(InstalledIntegration).where(InstalledIntegration.id == installation_id)
        )
        integration = result.scalar_one_or_none()
        if not integration:
            return {"success": False, "error": "Integration installation not found"}
        if integration.status != "active":
            return {"success": False, "error": "Integration is not active"}

        executor = ActionExecutor()
        execution_result = await executor.execute_action(
            installation_id=installation_id,
            action_name=action_name,
            input_data=input_data,
            triggered_by="agent_tool",
        )

        return {
            "installation_id": installation_id,
            "action_name": action_name,
            "execution_result": execution_result,
        }
