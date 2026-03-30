"""
LLM Tool Definitions for Function Calling

Defines tools that the LLM can invoke during investigations, along with
execution and validation logic.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class SecurityTools:
    """Tool definitions for security investigations"""

    TOOLS = [
        {
            "name": "search_siem_events",
            "description": "Search SIEM for events matching query",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "SIEM search query (e.g., 'source=10.0.0.1 AND action=failed_login')",
                    },
                    "time_range": {
                        "type": "string",
                        "description": "Time range (e.g., '24h', '7d', '1h')",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max results to return",
                    },
                },
                "required": ["query"],
            },
        },
        {
            "name": "lookup_ioc",
            "description": "Check indicator of compromise against threat intelligence",
            "input_schema": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "IOC value (IP, domain, hash, etc)",
                    },
                    "indicator_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "url", "hash", "email"],
                        "description": "Type of IOC",
                    },
                },
                "required": ["indicator", "indicator_type"],
            },
        },
        {
            "name": "get_asset_info",
            "description": "Retrieve detailed asset information",
            "input_schema": {
                "type": "object",
                "properties": {
                    "identifier": {
                        "type": "string",
                        "description": "IP address or hostname",
                    },
                },
                "required": ["identifier"],
            },
        },
        {
            "name": "check_user_activity",
            "description": "Check user activity from UEBA system",
            "input_schema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username to investigate",
                    },
                    "hours": {
                        "type": "integer",
                        "description": "Hours of activity to check",
                    },
                },
                "required": ["username"],
            },
        },
        {
            "name": "isolate_host",
            "description": "Isolate compromised host from network",
            "input_schema": {
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Hostname to isolate",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for isolation",
                    },
                },
                "required": ["hostname", "reason"],
            },
        },
        {
            "name": "block_ip",
            "description": "Block IP address at firewall",
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "IP to block",
                    },
                    "duration_hours": {
                        "type": "integer",
                        "description": "Block duration in hours (0 for permanent)",
                    },
                },
                "required": ["ip_address"],
            },
        },
        {
            "name": "get_alert_context",
            "description": "Get alert with full context and enrichment",
            "input_schema": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "Alert ID",
                    },
                },
                "required": ["alert_id"],
            },
        },
        {
            "name": "search_darkweb",
            "description": "Search dark web for organization mentions",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                    "days": {
                        "type": "integer",
                        "description": "Days back to search",
                    },
                },
                "required": ["query"],
            },
        },
        {
            "name": "run_vulnerability_scan",
            "description": "Initiate vulnerability scan on target",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, hostname, or CIDR",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "standard", "deep"],
                        "description": "Scan intensity",
                    },
                },
                "required": ["target"],
            },
        },
        {
            "name": "query_compliance_status",
            "description": "Check compliance status against framework",
            "input_schema": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["pci-dss", "hipaa", "sox", "gdpr", "nist"],
                        "description": "Compliance framework",
                    },
                },
                "required": ["framework"],
            },
        },
    ]

    @classmethod
    def get_tools_for_llm(cls) -> List[Dict[str, Any]]:
        """Get tools formatted for Claude/OpenAI function calling"""
        tools = []
        for tool in cls.TOOLS:
            tools.append(
                {
                    "name": tool["name"],
                    "description": tool["description"],
                    "input_schema": tool["input_schema"],
                }
            )
        return tools


class ToolExecutor:
    """Executes tool calls from LLM with validation and error handling"""

    def __init__(
        self,
        tool_handlers: Optional[Dict[str, Callable]] = None,
    ):
        """
        Initialize executor

        Args:
            tool_handlers: Dict mapping tool names to handler functions
        """
        self.tool_handlers = tool_handlers or {}
        self.audit_logger = ToolAuditLogger()

    def register_handler(self, tool_name: str, handler: Callable) -> None:
        """Register a handler for a tool"""
        self.tool_handlers[tool_name] = handler
        logger.info(f"Registered handler for tool: {tool_name}")

    async def execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a tool call

        Args:
            tool_name: Name of tool to execute
            arguments: Tool arguments
            user_id: User performing the action
            organization_id: Organization context

        Returns:
            Tool execution result
        """
        try:
            # Validate tool exists
            valid_tools = [t["name"] for t in SecurityTools.TOOLS]
            if tool_name not in valid_tools:
                raise ValueError(f"Unknown tool: {tool_name}")

            # Get handler
            handler = self.tool_handlers.get(
                tool_name,
                self._default_handler,
            )

            # Execute tool
            logger.info(f"Executing tool: {tool_name}")
            result = await handler(tool_name, arguments)

            # Audit log
            await self.audit_logger.log_tool_execution(
                tool_name=tool_name,
                arguments=arguments,
                result=result,
                user_id=user_id,
                organization_id=organization_id,
                success=True,
            )

            return {
                "success": True,
                "tool": tool_name,
                "result": result,
            }

        except Exception as e:
            logger.error(f"Tool execution failed: {tool_name}: {e}")

            # Audit log failure
            await self.audit_logger.log_tool_execution(
                tool_name=tool_name,
                arguments=arguments,
                result=None,
                user_id=user_id,
                organization_id=organization_id,
                success=False,
                error=str(e),
            )

            return {
                "success": False,
                "tool": tool_name,
                "error": str(e),
            }

    async def _default_handler(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Default handler routes to database-backed implementations"""
        handlers = {
            "search_siem_events": self._search_siem_events,
            "lookup_ioc": self._lookup_ioc,
            "get_asset_info": self._get_asset_info,
            "check_user_activity": self._check_user_activity,
            "isolate_host": self._isolate_host,
            "block_ip": self._block_ip,
            "get_alert_context": self._get_alert_context,
            "search_darkweb": self._search_darkweb,
            "run_vulnerability_scan": self._run_vulnerability_scan,
            "query_compliance_status": self._query_compliance_status,
        }

        handler = handlers.get(tool_name)
        if handler:
            return await handler(arguments)

        return {"status": "no_handler", "tool": tool_name}

    async def _search_siem_events(self, args: Dict) -> Dict:
        """Search alerts as SIEM events"""
        from sqlalchemy import select, or_, func
        from src.core.database import async_session_factory
        from src.models.alert import Alert

        query_str = args.get("query", "")
        limit = args.get("limit", 20)

        async with async_session_factory() as db:
            query = select(Alert)
            if query_str:
                query = query.where(or_(
                    Alert.title.ilike(f"%{query_str}%"),
                    Alert.description.ilike(f"%{query_str}%"),
                    Alert.source_ip.ilike(f"%{query_str}%"),
                    Alert.hostname.ilike(f"%{query_str}%"),
                ))
            query = query.order_by(Alert.created_at.desc()).limit(limit)
            result = await db.execute(query)
            alerts = result.scalars().all()

            total = (await db.execute(select(func.count(Alert.id)))).scalar() or 0

            return {
                "query": query_str,
                "events_found": len(alerts),
                "total_events": total,
                "events": [
                    {
                        "id": a.id,
                        "timestamp": str(a.created_at),
                        "title": a.title,
                        "severity": a.severity,
                        "source_ip": a.source_ip,
                        "hostname": a.hostname,
                        "source": a.source,
                    }
                    for a in alerts
                ],
            }

    async def _lookup_ioc(self, args: Dict) -> Dict:
        """Look up IOC in threat intelligence database"""
        from sqlalchemy import select
        from src.core.database import async_session_factory
        from src.models.ioc import IOC

        indicator = args.get("indicator", "")

        async with async_session_factory() as db:
            result = await db.execute(
                select(IOC).where(IOC.value == indicator)
            )
            ioc = result.scalars().first()

            if ioc:
                return {
                    "indicator": indicator,
                    "found": True,
                    "threat_level": ioc.threat_level,
                    "ioc_type": ioc.ioc_type,
                    "description": ioc.description,
                    "source": ioc.source,
                    "status": ioc.status,
                    "first_seen": str(ioc.created_at),
                }
            return {
                "indicator": indicator,
                "found": False,
                "threat_level": "unknown",
            }

    async def _get_asset_info(self, args: Dict) -> Dict:
        """Look up asset information"""
        from sqlalchemy import select, or_
        from src.core.database import async_session_factory
        from src.models.asset import Asset

        identifier = args.get("identifier", "")

        async with async_session_factory() as db:
            result = await db.execute(
                select(Asset).where(or_(
                    Asset.name == identifier,
                    Asset.ip_address == identifier,
                    Asset.hostname == identifier,
                ))
            )
            asset = result.scalars().first()

            if asset:
                return {
                    "identifier": identifier,
                    "found": True,
                    "name": asset.name,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "asset_type": asset.asset_type,
                    "status": asset.status,
                    "criticality": asset.criticality,
                    "os": asset.operating_system,
                }
            return {"identifier": identifier, "found": False}

    async def _check_user_activity(self, args: Dict) -> Dict:
        """Check user login/audit activity"""
        from sqlalchemy import select, func
        from src.core.database import async_session_factory
        from src.models.audit import AuditLog

        username = args.get("username", "")

        async with async_session_factory() as db:
            count = (await db.execute(
                select(func.count(AuditLog.id)).where(
                    AuditLog.user_id == username
                )
            )).scalar() or 0

            recent = await db.execute(
                select(AuditLog)
                .where(AuditLog.user_id == username)
                .order_by(AuditLog.created_at.desc())
                .limit(10)
            )
            logs = recent.scalars().all()

            return {
                "username": username,
                "activity_count": count,
                "recent_actions": [
                    {
                        "time": str(l.created_at),
                        "action": l.action,
                        "resource": l.resource_type,
                    }
                    for l in logs
                ],
            }

    async def _isolate_host(self, args: Dict) -> Dict:
        """Request host isolation (creates an action record)"""
        import uuid
        from src.core.database import async_session_factory
        from src.agentic.models import AgentAction

        hostname = args.get("hostname", "")
        reason = args.get("reason", "Automated isolation request")

        async with async_session_factory() as db:
            action = AgentAction(
                id=str(uuid.uuid4()),
                action_type="isolate_host",
                target=hostname,
                parameters=json.dumps({"reason": reason}),
                requires_approval=True,
                execution_status="pending_approval",
            )
            db.add(action)
            await db.commit()

            return {
                "hostname": hostname,
                "status": "pending_approval",
                "action_id": action.id,
                "reason": reason,
            }

    async def _block_ip(self, args: Dict) -> Dict:
        """Request IP block (creates an action record)"""
        import uuid
        from src.core.database import async_session_factory
        from src.agentic.models import AgentAction

        ip_address = args.get("ip_address", "")
        duration = args.get("duration_hours", 24)

        async with async_session_factory() as db:
            action = AgentAction(
                id=str(uuid.uuid4()),
                action_type="block_ip",
                target=ip_address,
                parameters=json.dumps({"duration_hours": duration}),
                requires_approval=True,
                execution_status="pending_approval",
            )
            db.add(action)
            await db.commit()

            return {
                "ip_address": ip_address,
                "status": "pending_approval",
                "action_id": action.id,
                "duration_hours": duration,
            }

    async def _get_alert_context(self, args: Dict) -> Dict:
        """Get full alert context from database"""
        from sqlalchemy import select, func
        from src.core.database import async_session_factory
        from src.models.alert import Alert

        alert_id = args.get("alert_id", "")

        async with async_session_factory() as db:
            result = await db.execute(
                select(Alert).where(Alert.id == alert_id)
            )
            alert = result.scalars().first()

            if alert:
                similar_count = (await db.execute(
                    select(func.count(Alert.id)).where(
                        Alert.source_ip == alert.source_ip,
                        Alert.id != alert.id,
                    )
                )).scalar() or 0

                return {
                    "alert_id": alert_id,
                    "found": True,
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity,
                    "status": alert.status,
                    "source": alert.source,
                    "source_ip": alert.source_ip,
                    "hostname": alert.hostname,
                    "created_at": str(alert.created_at),
                    "similar_alerts_from_source": similar_count,
                }
            return {"alert_id": alert_id, "found": False}

    async def _search_darkweb(self, args: Dict) -> Dict:
        """Search dark web findings"""
        from sqlalchemy import select, or_
        from src.core.database import async_session_factory
        from src.darkweb.models import DarkWebFinding

        query_str = args.get("query", "")

        async with async_session_factory() as db:
            result = await db.execute(
                select(DarkWebFinding)
                .where(or_(
                    DarkWebFinding.title.ilike(f"%{query_str}%"),
                    DarkWebFinding.description.ilike(f"%{query_str}%"),
                ))
                .limit(10)
            )
            findings = result.scalars().all()

            return {
                "query": query_str,
                "results_found": len(findings),
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "source": getattr(f, "source", "darkweb"),
                    }
                    for f in findings
                ],
            }

    async def _run_vulnerability_scan(self, args: Dict) -> Dict:
        """Query vulnerability data for a target"""
        from sqlalchemy import select, func, or_
        from src.core.database import async_session_factory
        from src.vulnmgmt.models import Vulnerability

        target = args.get("target", "")

        async with async_session_factory() as db:
            result = await db.execute(
                select(Vulnerability)
                .where(or_(
                    Vulnerability.affected_asset.ilike(f"%{target}%"),
                    Vulnerability.title.ilike(f"%{target}%"),
                ))
                .limit(20)
            )
            vulns = result.scalars().all()

            return {
                "target": target,
                "vulnerabilities_found": len(vulns),
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "title": v.title,
                        "severity": v.severity,
                        "status": v.status,
                    }
                    for v in vulns
                ],
            }

    async def _query_compliance_status(self, args: Dict) -> Dict:
        """Query compliance status from database"""
        from sqlalchemy import select, func
        from src.core.database import async_session_factory
        from src.compliance.models import ComplianceControl

        framework = args.get("framework", "")

        async with async_session_factory() as db:
            query = select(ComplianceControl)
            if framework:
                query = query.where(ComplianceControl.framework.ilike(f"%{framework}%"))

            total = (await db.execute(
                select(func.count(ComplianceControl.id)).select_from(query.subquery())
            )).scalar() or 0

            compliant = (await db.execute(
                select(func.count(ComplianceControl.id)).where(
                    ComplianceControl.framework.ilike(f"%{framework}%"),
                    ComplianceControl.status == "compliant",
                )
            )).scalar() or 0

            score = round(compliant / total, 2) if total > 0 else 0.0

            return {
                "framework": framework,
                "total_controls": total,
                "compliant_controls": compliant,
                "compliance_score": score,
                "status": "compliant" if score >= 0.95 else "compliant_with_exceptions" if score >= 0.7 else "non_compliant",
            }


class ToolAuditLogger:
    """Audit log all tool invocations"""

    async def log_tool_execution(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Any,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """Log tool execution for audit trail"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "tool_execution",
            "tool": tool_name,
            "user_id": user_id,
            "organization_id": organization_id,
            "success": success,
            "argument_keys": list(arguments.keys()),
            "error": error,
        }

        if success:
            logger.info(json.dumps(log_entry))
        else:
            logger.warning(json.dumps(log_entry))

    async def get_execution_history(
        self,
        tool_name: Optional[str] = None,
        user_id: Optional[str] = None,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Retrieve tool execution history"""
        # This would query audit logs from database or logging system
        return []
