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
            description="List inventoried assets (hosts, endpoints, cloud resources)",
            parameters={"asset_type": "optional string", "status": "optional string", "keyword": "optional string", "limit": "optional int, default 20"},
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

        # ===== COMPLIANCE =====
        self._register(Tool(
            name="list_compliance_frameworks",
            description="List compliance frameworks enabled for the org (NIST, FedRAMP, PCI, HIPAA, etc.)",
            parameters={"limit": "optional int, default 20"},
            category="query",
            handler=self._list_compliance_frameworks,
        ))
        self._register(Tool(
            name="list_compliance_controls",
            description="List compliance controls, optionally filtered by framework or status",
            parameters={"framework_id": "optional string", "status": "optional string", "limit": "optional int, default 25"},
            category="query",
            handler=self._list_compliance_controls,
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
        await self.db.flush()
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

    async def _run_threat_hunt(self, hypothesis, timeframe_hours=24):
        from src.models.alert import Alert
        cutoff = datetime.now(timezone.utc) - timedelta(hours=int(timeframe_hours))
        # Simple hunt: search alerts matching hypothesis keywords
        keywords = [w.lower() for w in hypothesis.split() if len(w) > 3]
        if not keywords:
            return {"findings": 0, "message": "Hypothesis too vague"}
        q = select(Alert).where(Alert.created_at >= cutoff)
        for kw in keywords[:3]:
            q = q.where(Alert.title.ilike(f"%{kw}%") | Alert.description.ilike(f"%{kw}%"))
        q = q.limit(20)
        result = await self.db.execute(q)
        matches = result.scalars().all()
        return {
            "hypothesis": hypothesis,
            "timeframe_hours": timeframe_hours,
            "findings": len(matches),
            "matched_alerts": [{"id": m.id, "title": m.title, "severity": m.severity} for m in matches],
        }

    async def _simulate_attack(self, technique_id, target):
        # Create a simulated attack alert
        from src.models.alert import Alert
        alert = Alert(
            title=f"Simulation: {technique_id} against {target}",
            description=f"Attack simulation for MITRE technique {technique_id} targeting {target}",
            severity="medium",
            source="attack_simulation",
            status="new",
            category="simulation",
        )
        self.db.add(alert)
        await self.db.flush()
        return {
            "technique_id": technique_id,
            "target": target,
            "simulation_alert_id": alert.id,
            "result": "executed",
            "note": "Check if this triggered detection rules and auto-correlation",
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

    async def _list_assets(self, asset_type=None, status=None, keyword=None, limit=20):
        from src.models.asset import Asset
        q = select(Asset).order_by(Asset.created_at.desc())
        if asset_type:
            q = q.where(Asset.asset_type == asset_type)
        if status:
            q = q.where(Asset.status == status)
        if keyword:
            pat = f"%{keyword}%"
            from sqlalchemy import or_
            q = q.where(or_(Asset.name.ilike(pat), Asset.hostname.ilike(pat), Asset.ip_address.ilike(pat)))
        rows = (await self.db.execute(q.limit(int(limit)))).scalars().all()
        return [{
            "id": a.id, "name": a.name, "hostname": a.hostname,
            "asset_type": a.asset_type, "status": a.status,
            "ip_address": a.ip_address,
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

    async def _list_compliance_controls(self, framework_id=None, status=None, limit=25):
        from src.compliance.models import ComplianceControl
        q = select(ComplianceControl)
        if framework_id:
            q = q.where(ComplianceControl.framework_id == framework_id)
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
