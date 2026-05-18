"""Skill registry for composing higher-level agent behaviors.

Skills are named callables that can orchestrate multiple tool invocations
and provide a single, audited entrypoint for common tasks.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Dict, Optional


class SkillRegistry:
    """Registry of skills exposed to agent orchestration and UIs.

    Supports both sync and async callables. Use `run_skill` to execute a
    registered skill; `run_skill` will await coroutine functions as needed.
    """

    def __init__(self) -> None:
        self._skills: Dict[str, Callable[..., Any]] = {}

    def register(self, name: str):
        def _decorator(fn: Callable[..., Any]):
            self._skills[name] = fn
            return fn

        return _decorator

    def get(self, name: str) -> Optional[Callable[..., Any]]:
        return self._skills.get(name)

    def list_skills(self) -> list[str]:
        return list(self._skills.keys())

    async def run_skill(self, name: str, tool_executor: Any = None, db: Any = None, **kwargs) -> Any:
        """Run a skill by name, passing the ToolExecutor and optional DB session.

        Returns whatever the skill callable returns. If not found, raises KeyError.
        """
        fn = self.get(name)
        if not fn:
            raise KeyError(f"skill_not_found:{name}")

        if asyncio.iscoroutinefunction(fn):
            return await fn(tool_executor, db=db, **kwargs)
        else:
            # run sync function in thread if it's blocking
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, lambda: fn(tool_executor, **kwargs))


# Global registry instance
registry = SkillRegistry()


# --- Concrete SOC skills ---
@registry.register("triage_gather_evidence")
async def triage_gather_evidence(tool_executor: Any, db: Any = None, alert_id: str = "", limit: int = 20) -> Dict[str, Any]:
    """Gather read-only context for initial triage using existing tools."""
    results: Dict[str, Any] = {}

    if tool_executor is None:
        return {"status": "error", "error": "tool_executor_required"}

    # 1) Get alert context
    try:
        res = await tool_executor.execute(
            "get_alert_context",
            {"alert_id": alert_id},
            organization_id=(getattr(db, 'organization_id', None) if db else None),
        )
        results["get_alert_context"] = res
    except Exception as e:
        results["get_alert_context"] = {"error": str(e)}

    # 2) Search related SIEM events
    try:
        query = f"alert_id:{alert_id}" if alert_id else ""
        res = await tool_executor.execute(
            "search_siem_events",
            {"query": query, "limit": limit},
            organization_id=(getattr(db, 'organization_id', None) if db else None),
        )
        results["search_siem_events"] = res
    except Exception as e:
        results["search_siem_events"] = {"error": str(e)}

    # 3) Lookup primary IOC(s) if present in alert context
    try:
        alert_ctx = results.get("get_alert_context", {}).get("result") if isinstance(results.get("get_alert_context"), dict) else None
        indicator = None
        if alert_ctx and isinstance(alert_ctx, dict):
            indicator = alert_ctx.get("source_ip") or alert_ctx.get("domain") or alert_ctx.get("file_hash")
        if indicator:
            res = await tool_executor.execute("lookup_ioc", {"indicator": indicator, "indicator_type": "ip"}, organization_id=(getattr(db, 'organization_id', None) if db else None))
            results["lookup_ioc"] = res
        else:
            results["lookup_ioc"] = {"skipped": True}
    except Exception as e:
        results["lookup_ioc"] = {"error": str(e)}

    return results


@registry.register("threat_hunt_from_alert")
async def threat_hunt_from_alert(tool_executor: Any, db: Any = None, alert_id: str = "", limit: int = 25) -> Dict[str, Any]:
    """Perform an expert threat hunt from an alert by correlating asset, IOC, and SIEM context."""
    if tool_executor is None:
        return {"status": "error", "error": "tool_executor_required"}

    results: Dict[str, Any] = {}
    alert_ctx = {}

    try:
        alert_ctx = await tool_executor.execute(
            "get_alert_context",
            {"alert_id": alert_id},
            organization_id=(getattr(db, "organization_id", None) if db else None),
        )
        results["alert_context"] = alert_ctx
    except Exception as e:
        results["alert_context"] = {"error": str(e)}

    query = ""
    if alert_ctx and isinstance(alert_ctx, dict):
        source_ip = alert_ctx.get("result", {}).get("source_ip") if isinstance(alert_ctx.get("result"), dict) else None
        hostname = alert_ctx.get("result", {}).get("hostname") if isinstance(alert_ctx.get("result"), dict) else None
        query = source_ip or hostname or alert_id

    if query:
        try:
            results["siem_correlation"] = await tool_executor.execute(
                "search_siem_events",
                {"query": query, "limit": limit},
                organization_id=(getattr(db, "organization_id", None) if db else None),
            )
        except Exception as e:
            results["siem_correlation"] = {"error": str(e)}

    if alert_ctx and isinstance(alert_ctx, dict):
        indicator = alert_ctx.get("result", {}).get("source_ip") if isinstance(alert_ctx.get("result"), dict) else None
        if indicator:
            try:
                results["ioc_enrichment"] = await tool_executor.execute(
                    "lookup_ioc",
                    {"indicator": indicator, "indicator_type": "ip"},
                    organization_id=(getattr(db, "organization_id", None) if db else None),
                )
            except Exception as e:
                results["ioc_enrichment"] = {"error": str(e)}

    return results


@registry.register("ioc_contextualization")
async def ioc_contextualization(tool_executor: Any, db: Any = None, indicator: str = "") -> Dict[str, Any]:
    """Contextualize an IOC and determine its likely operational impact."""
    if tool_executor is None:
        return {"status": "error", "error": "tool_executor_required"}

    results: Dict[str, Any] = {}
    try:
        results["ioc_lookup"] = await tool_executor.execute(
            "lookup_ioc",
            {"indicator": indicator, "indicator_type": "ip"},
            organization_id=(getattr(db, "organization_id", None) if db else None),
        )
    except Exception as e:
        results["ioc_lookup"] = {"error": str(e)}

    try:
        results["asset_info"] = await tool_executor.execute(
            "get_asset_info",
            {"identifier": indicator},
            organization_id=(getattr(db, "organization_id", None) if db else None),
        )
    except Exception as e:
        results["asset_info"] = {"error": str(e)}

    try:
        results["darkweb_references"] = await tool_executor.execute(
            "search_darkweb",
            {"query": indicator, "days": 14},
            organization_id=(getattr(db, "organization_id", None) if db else None),
        )
    except Exception as e:
        results["darkweb_references"] = {"error": str(e)}

    return results


@registry.register("incident_response_recommendation")
async def incident_response_recommendation(tool_executor: Any, db: Any = None, incident_summary: str = "", severity: str = "medium") -> Dict[str, Any]:
    """Recommend response actions based on incident severity and summary."""
    recommendations: Dict[str, Any] = {
        "severity": severity,
        "incident_summary": incident_summary,
        "recommended_actions": [],
        "analyst_level": "expert",
    }

    if severity.lower() in ("critical", "high"):
        recommendations["recommended_actions"] = [
            "Notify incident response team",
            "Create containment action request",
            "Begin forensic evidence collection",
            "Review lateral movement indicators",
        ]
    elif severity.lower() == "medium":
        recommendations["recommended_actions"] = [
            "Collect additional telemetry",
            "Validate IOC and affected hosts",
            "Review access patterns",
        ]
    else:
        recommendations["recommended_actions"] = [
            "Monitor activity",
            "Validate false positive potential",
            "Update detection rules if needed",
        ]

    return recommendations


@registry.register("evidence_enrichment")
async def evidence_enrichment(tool_executor: Any, db: Any = None, indicator: str = "") -> Dict[str, Any]:
    """Enrich an IOC across multiple sources."""
    results: Dict[str, Any] = {}
    try:
        results["lookup_ioc"] = await tool_executor.execute("lookup_ioc", {"indicator": indicator, "indicator_type": "ip"}, organization_id=(getattr(db, 'organization_id', None) if db else None))
    except Exception as e:
        results["lookup_ioc"] = {"error": str(e)}

    try:
        results["get_asset_info"] = await tool_executor.execute("get_asset_info", {"identifier": indicator}, organization_id=(getattr(db, 'organization_id', None) if db else None))
    except Exception as e:
        results["get_asset_info"] = {"error": str(e)}

    try:
        results["search_darkweb"] = await tool_executor.execute("search_darkweb", {"query": indicator, "days": 30}, organization_id=(getattr(db, 'organization_id', None) if db else None))
    except Exception as e:
        results["search_darkweb"] = {"error": str(e)}

    return results


@registry.register("safe_containment_request")
async def safe_containment_request(tool_executor: Any, db: Any = None, investigation_id: str = "", target: str = "", reason: str = "") -> Dict[str, Any]:
    """Create an AgentAction record requesting containment; does not perform network blocks directly."""
    # Defer to DB-backed AgentAction model for approval workflow
    try:
        import uuid
        from src.agentic.models import AgentAction

        action = AgentAction(
            investigation_id=investigation_id,
            organization_id=getattr(db, 'organization_id', '') if db else '',
            action_type="isolate_host",
            target=target,
            parameters={"reason": reason},
            requires_approval=True,
            execution_status="pending_approval",
        )
        if db is not None:
            db.add(action)
            await db.flush()
            return {"status": "created", "action_id": action.id}
        else:
            return {"status": "created_offline", "action": json.dumps({"action_type": "isolate_host", "target": target, "reason": reason})}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@registry.register("summarize_investigation")
async def summarize_investigation(tool_executor: Any, db: Any = None, investigation_id: str = "") -> Dict[str, Any]:
    """Produce a short human-readable summary of an investigation."""
    try:
        investigation = await db.get(__import__("src.agentic.models", fromlist=["Investigation"]).Investigation, investigation_id) if db else None
        if not investigation:
            return {"status": "not_found"}

        summary = {
            "title": investigation.title,
            "status": investigation.status,
            "confidence": investigation.confidence_score,
            "steps": len(investigation.reasoning_steps) if getattr(investigation, 'reasoning_steps', None) else 0,
        }
        return {"status": "ok", "summary": summary}
    except Exception as e:
        return {"status": "error", "error": str(e)}
