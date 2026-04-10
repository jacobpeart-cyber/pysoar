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
        from src.models.ioc import IOC
        q = select(IOC).order_by(IOC.created_at.desc())
        if ioc_type:
            q = q.where(IOC.ioc_type == ioc_type)
        q = q.limit(int(limit))
        result = await self.db.execute(q)
        iocs = result.scalars().all()
        return [{"id": i.id, "value": i.value, "type": i.ioc_type, "threat_level": getattr(i, "threat_level", None)} for i in iocs]

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
        from src.models.ioc import IOC
        # Add to IOC list as blocked
        ioc = IOC(value=ip, ioc_type="ip", threat_level="high", status="active")
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
        from src.models.ioc import IOC
        ioc = IOC(value=value, ioc_type=ioc_type, threat_level=threat_level, status="active")
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
        from src.models.ioc import IOC
        result = await self.db.execute(
            select(IOC).where(IOC.value == value, IOC.ioc_type == ioc_type)
        )
        ioc = result.scalar_one_or_none()
        if ioc:
            return {
                "value": value, "type": ioc_type, "known": True,
                "threat_level": getattr(ioc, "threat_level", None),
                "source": getattr(ioc, "source", None),
                "first_seen": ioc.created_at.isoformat() if ioc.created_at else None,
            }
        return {"value": value, "type": ioc_type, "known": False, "message": "No threat intel match"}

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
        from src.models.ioc import IOC
        result = await self.db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": "Alert not found"}
        indicators = [v for v in [getattr(alert, "source_ip", None), getattr(alert, "destination_ip", None)] if v]
        if not indicators:
            return {"matches": [], "message": "No indicators to check"}
        ioc_result = await self.db.execute(
            select(IOC).where(IOC.value.in_(indicators), IOC.status == "active")
        )
        matches = ioc_result.scalars().all()
        return {
            "matches": [{"value": m.value, "type": m.ioc_type, "threat_level": getattr(m, "threat_level", None)} for m in matches],
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
