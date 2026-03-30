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
        """Default handler for tools without custom implementation"""
        logger.warning(f"Using default handler for {tool_name}")

        # Return simulated results for demo purposes
        handlers = {
            "search_siem_events": self._mock_search_siem,
            "lookup_ioc": self._mock_lookup_ioc,
            "get_asset_info": self._mock_get_asset_info,
            "check_user_activity": self._mock_check_user_activity,
            "isolate_host": self._mock_isolate_host,
            "block_ip": self._mock_block_ip,
            "get_alert_context": self._mock_get_alert_context,
            "search_darkweb": self._mock_search_darkweb,
            "run_vulnerability_scan": self._mock_run_vulnerability_scan,
            "query_compliance_status": self._mock_query_compliance_status,
        }

        handler = handlers.get(tool_name)
        if handler:
            return await handler(arguments)

        return {"status": "not_implemented"}

    async def _mock_search_siem(self, args: Dict) -> Dict:
        """Mock SIEM search"""
        return {
            "query": args.get("query"),
            "events_found": 42,
            "time_range": args.get("time_range", "24h"),
            "sample_events": [
                {"timestamp": "2026-03-24T10:30:00Z", "source": "10.0.0.1", "action": "failed_login"},
                {"timestamp": "2026-03-24T10:31:00Z", "source": "10.0.0.1", "action": "failed_login"},
            ],
        }

    async def _mock_lookup_ioc(self, args: Dict) -> Dict:
        """Mock IOC lookup"""
        return {
            "indicator": args.get("indicator"),
            "found": True,
            "threat_level": "HIGH",
            "sources": ["alienvault", "abuse.ch"],
            "context": "Known C2 server",
        }

    async def _mock_get_asset_info(self, args: Dict) -> Dict:
        """Mock asset info"""
        return {
            "identifier": args.get("identifier"),
            "hostname": "workstation-01.corp.local",
            "ip": "10.0.0.100",
            "os": "Windows 10",
            "last_seen": "2026-03-24T10:00:00Z",
            "vulnerabilities": 3,
        }

    async def _mock_check_user_activity(self, args: Dict) -> Dict:
        """Mock user activity check"""
        return {
            "username": args.get("username"),
            "activity_count": 125,
            "anomaly_score": 0.72,
            "recent_actions": [
                {"time": "2026-03-24T10:30:00Z", "action": "login"},
                {"time": "2026-03-24T10:35:00Z", "action": "file_access"},
            ],
        }

    async def _mock_isolate_host(self, args: Dict) -> Dict:
        """Mock host isolation"""
        return {
            "hostname": args.get("hostname"),
            "status": "isolation_requested",
            "reason": args.get("reason"),
            "isolation_key": "iso_12345",
        }

    async def _mock_block_ip(self, args: Dict) -> Dict:
        """Mock IP blocking"""
        return {
            "ip": args.get("ip_address"),
            "status": "blocked",
            "duration_hours": args.get("duration_hours", 0),
            "rule_id": "fw_rule_67890",
        }

    async def _mock_get_alert_context(self, args: Dict) -> Dict:
        """Mock alert context"""
        return {
            "alert_id": args.get("alert_id"),
            "title": "Suspicious Login",
            "severity": "HIGH",
            "source_ip": "192.168.1.100",
            "user": "jsmith",
            "timestamp": "2026-03-24T10:30:00Z",
            "enrichment": {
                "threat_intel": "Known attacker IP",
                "similar_alerts": 5,
            },
        }

    async def _mock_search_darkweb(self, args: Dict) -> Dict:
        """Mock dark web search"""
        return {
            "query": args.get("query"),
            "results_found": 0,
            "status": "no_mentions",
        }

    async def _mock_run_vulnerability_scan(self, args: Dict) -> Dict:
        """Mock vulnerability scan"""
        return {
            "target": args.get("target"),
            "status": "scan_initiated",
            "scan_id": "vs_11111",
            "estimated_completion": "2026-03-24T12:00:00Z",
        }

    async def _mock_query_compliance_status(self, args: Dict) -> Dict:
        """Mock compliance query"""
        return {
            "framework": args.get("framework"),
            "compliance_score": 0.87,
            "status": "compliant_with_exceptions",
            "findings": 3,
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
