"""Classic playbook execution engine.

Every step runs inside the execution's tenant (``PlaybookExecution.organization_id``)
on the engine's own database session, and records ``status``, ``started_at``,
``finished_at``, ``result`` and ``error``. A step whose status is ``failed``
fails the run unless the step sets ``continue_on_error``.

Step types and what they really do
----------------------------------
Containment (``src.services.containment``; agent command queue or an installed
integration via ``src.integrations.engine``; one AuditLog row per call):

* ``block_ip``, ``isolate_host``, ``disable_user``, ``quarantine_file``. The
  step status is the containment status: ``completed`` (command queued /
  integration call succeeded), ``queued_for_approval`` (high-blast agent
  command waiting in the agent approval queue), ``awaiting_integration``
  (no enrolled agent or capable integration; ``missing_dependency`` names it,
  including the ``detection_only`` case), ``manual_required`` (a run with no
  human behind it, e.g. scheduled or auto-triggered, whose only path would
  execute immediately: containment is called with ``unattended=True``). A
  failed integration call fails the step.

Notifications (tenant Settings only, ``src.services.tenant_settings``):

* ``notify`` / ``send_notification`` (``channel`` = email | slack | teams),
  ``send_email``, ``send_slack``. With no SMTP / webhook configured for the
  organisation the step is ``awaiting_integration``; a delivery error fails it.

Tickets and integrations (``src.integrations.engine.ActionExecutor``):

* ``create_ticket``: Jira ``create_issue`` or ServiceNow ``create_incident``
  through the organisation's installed integration; none installed is
  ``awaiting_integration``. No local placeholder ticket is written.
* ``integration_action`` / ``execute_integration_action`` and
  ``http_request``: an installed integration of this organisation;
  ``http_request`` is confined to that integration's base URL by the engine's
  SSRF guard. Arbitrary URLs are refused.

Enrichment:

* ``enrich`` / ``enrich_ioc`` / ``enrich_ip`` / ``enrich_domain`` /
  ``enrich_hash``: the organisation's threat indicators plus the configured
  threat-intel providers. No provider configured and no local match is
  ``awaiting_integration``; no default score is invented.

Case work (scoped to the organisation): ``update_alert``, ``update_incident``,
``create_incident``, ``add_comment``, ``assign_to``.

Flow: ``wait`` (capped at 60 s), ``condition`` (``on_success`` /
``on_failure`` = ``"skip"`` or a 0-based step index).

``run_script`` is REMOVED. It executed bash / PowerShell / Python on the
shared API host for any tenant admin. Playbook create/update rejects it and a
stored ``run_script`` step fails with an explanatory error. Host-side work
belongs on an enrolled endpoint agent (bounded, allowlisted actions).

Unknown step types fail the step (and therefore the run).
"""

from __future__ import annotations

import asyncio
import json
import re
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.models.playbook import ExecutionStatus, Playbook, PlaybookExecution

logger = get_logger(__name__)

#: Step statuses.
STEP_COMPLETED = "completed"
STEP_FAILED = "failed"
STEP_AWAITING_INTEGRATION = "awaiting_integration"
STEP_QUEUED_FOR_APPROVAL = "queued_for_approval"
#: Containment for a run with no human behind it (scheduled / auto-triggered)
#: whose only path would execute immediately: an operator must act.
STEP_MANUAL_REQUIRED = "manual_required"
STEP_SKIPPED = "skipped"

#: Run status when every step ran but at least one did not complete
#: (awaiting an integration, waiting for approval, or failed with
#: ``continue_on_error``). Never reported as ``completed``.
RUN_PARTIAL = "partial"

#: Steps that a playbook may contain. ``run_script`` is deliberately absent.
SUPPORTED_ACTIONS: frozenset[str] = frozenset({
    "block_ip", "isolate_host", "disable_user", "quarantine_file",
    "notify", "send_notification", "send_email", "send_slack",
    "create_ticket", "integration_action", "execute_integration_action", "http_request",
    "enrich", "enrich_ioc", "enrich_ip", "enrich_domain", "enrich_hash",
    "update_alert", "update_incident", "create_incident", "add_comment", "assign_to",
    "wait", "condition",
})

REMOVED_ACTIONS: dict[str, str] = {
    "run_script": (
        "run_script was removed: it executed code on the shared API host. Use an endpoint-agent "
        "action (isolate_host, quarantine_file, ...) or an integration_action instead."
    ),
}


#: Steps that actuate containment directly.
CONTAINMENT_ACTIONS: frozenset[str] = frozenset({"block_ip", "isolate_host", "disable_user", "quarantine_file"})

#: Integration actions an analyst may run: lookups only. Anything else an
#: integration can do (contain_host, create/delete rules, ...) is privileged.
READ_ONLY_INTEGRATION_PREFIXES: tuple[str, ...] = ("get_", "list_", "search_", "lookup_")
READ_ONLY_INTEGRATION_ACTIONS: frozenset[str] = frozenset({"query", "enrich"})


def is_read_only_integration_action(action_name: Any) -> bool:
    name = str(action_name or "").lower()
    return name in READ_ONLY_INTEGRATION_ACTIONS or name.startswith(READ_ONLY_INTEGRATION_PREFIXES)


def is_privileged_step(action: str, parameters: Optional[dict[str, Any]] = None) -> bool:
    """True when a step can change something outside PySOAR's case data.

    Classified by capability, fail closed: containment, raw endpoint-agent
    commands, outbound HTTP, and any integration action that is not on the
    read-only allowlist. notify / condition / wait / enrich* / create_ticket
    and case updates are analyst-level.
    """
    params = parameters or {}
    if action in CONTAINMENT_ACTIONS or action in ("agent_command", "http_request", "api_call"):
        return True
    if action in ("integration_action", "execute_integration_action"):
        return not is_read_only_integration_action(params.get("action_name"))
    return False


@dataclass
class StepRuntime:
    """What a step handler needs besides its parameters: the session and the principal."""

    db: AsyncSession
    organization_id: str
    execution_id: str
    actor: str  # user id, or ``system:playbook:<execution_id>``
    actor_user_id: Optional[str]


_RUNTIME: ContextVar[Optional[StepRuntime]] = ContextVar("playbook_step_runtime", default=None)


def current_runtime() -> Optional[StepRuntime]:
    """The runtime of the step being executed (``None`` outside the engine)."""
    return _RUNTIME.get()


async def run_step_in_runtime(
    runtime: StepRuntime, action: str, parameters: dict[str, Any], context: dict[str, Any],
) -> dict[str, Any]:
    """Run one step handler under ``runtime`` (used by the visual builder's action nodes)."""
    token = _RUNTIME.set(runtime)
    try:
        return await PlaybookAction.execute(action, parameters, context)
    finally:
        _RUNTIME.reset(token)


def _ok(action: str, details: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"success": True, "status": STEP_COMPLETED, "action": action, "details": details, **extra}


def _fail(action: str, error: str, details: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"success": False, "status": STEP_FAILED, "action": action, "error": error, "details": details or {}}


def _awaiting(action: str, missing: str, details: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {
        "success": False, "status": STEP_AWAITING_INTEGRATION, "action": action,
        "missing_dependency": missing, "details": details or {},
    }


def _no_runtime(action: str) -> dict[str, Any]:
    return _fail(action, "step must run inside a playbook execution (no tenant runtime)")


Handler = Callable[[dict, dict], Awaitable[dict]]


class PlaybookAction:
    """Step handlers. ``execute(action, parameters, context)`` dispatches one step."""

    @staticmethod
    async def execute(
        action: str,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute an action and return its result dict (``success``, ``status``, ...)."""
        if action in REMOVED_ACTIONS:
            return _fail(action, REMOVED_ACTIONS[action])
        handlers: dict[str, Handler] = {
            "block_ip": PlaybookAction._block_ip,
            "isolate_host": PlaybookAction._isolate_host,
            "disable_user": PlaybookAction._disable_user,
            "quarantine_file": PlaybookAction._quarantine_file,
            "notify": PlaybookAction._notify,
            "send_notification": PlaybookAction._notify,
            "send_email": PlaybookAction._send_email,
            "send_slack": PlaybookAction._send_slack,
            "create_ticket": PlaybookAction._create_ticket,
            "integration_action": PlaybookAction._integration_action,
            "execute_integration_action": PlaybookAction._integration_action,
            "http_request": PlaybookAction._http_request,
            "enrich": PlaybookAction._enrich,
            "enrich_ioc": PlaybookAction._enrich,
            "enrich_ip": PlaybookAction._enrich_ip,
            "enrich_domain": PlaybookAction._enrich_domain,
            "enrich_hash": PlaybookAction._enrich_hash,
            "update_alert": PlaybookAction._update_alert,
            "update_incident": PlaybookAction._update_incident,
            "create_incident": PlaybookAction._create_incident,
            "add_comment": PlaybookAction._add_comment,
            "assign_to": PlaybookAction._assign_to,
            "wait": PlaybookAction._wait,
            "condition": PlaybookAction._condition,
        }
        handler = handlers.get(action)
        if handler is None:
            return _fail(action or "unknown", f"Unknown action type: {action!r}")
        return await handler(parameters or {}, context)

    # ------------------------------------------------------------------
    # Containment
    # ------------------------------------------------------------------

    @staticmethod
    def _containment_step(action: str, res: Any) -> dict[str, Any]:
        details = res.to_dict()
        if res.failed:
            return _fail(action, res.error or res.detail, details)
        if res.status == "executed":
            return _ok(action, details)
        if res.status == "queued_for_approval":
            return {"success": False, "status": STEP_QUEUED_FOR_APPROVAL, "action": action, "details": details}
        if res.status == "manual_required":
            return {"success": False, "status": STEP_MANUAL_REQUIRED, "action": action,
                    "missing_dependency": res.detail, "details": details}
        return _awaiting(action, res.missing_dependency or res.detail, details)

    @staticmethod
    def _reason(params: dict, context: dict, action: str) -> str:
        return str(params.get("reason") or f"playbook step {action} (execution {context.get('playbook_execution_id', '')})")

    @staticmethod
    async def _block_ip(params: dict, context: dict) -> dict:
        from src.services import containment

        rt = current_runtime()
        if rt is None:
            return _no_runtime("block_ip")
        ip = PlaybookAction._substitute_vars(str(params.get("ip") or context.get("source_ip") or ""), context)
        if not ip:
            return _fail("block_ip", "No IP address provided (parameter 'ip' or context 'source_ip')")
        res = await containment.block_ip(
            rt.db, rt.organization_id, ip=ip, actor=rt.actor, reason=PlaybookAction._reason(params, context, "block_ip"),
            execution_ref=f"playbook_execution:{rt.execution_id}", unattended=rt.actor_user_id is None,
        )
        return PlaybookAction._containment_step("block_ip", res)

    @staticmethod
    async def _isolate_host(params: dict, context: dict) -> dict:
        from src.services import containment

        rt = current_runtime()
        if rt is None:
            return _no_runtime("isolate_host")
        hostname = PlaybookAction._substitute_vars(str(params.get("hostname") or context.get("hostname") or ""), context)
        if not hostname:
            return _fail("isolate_host", "No hostname provided (parameter or context 'hostname')")
        res = await containment.isolate_host(
            rt.db, rt.organization_id, hostname=hostname, actor=rt.actor,
            reason=PlaybookAction._reason(params, context, "isolate_host"),
            execution_ref=f"playbook_execution:{rt.execution_id}", unattended=rt.actor_user_id is None,
        )
        return PlaybookAction._containment_step("isolate_host", res)

    @staticmethod
    async def _disable_user(params: dict, context: dict) -> dict:
        from src.services import containment

        rt = current_runtime()
        if rt is None:
            return _no_runtime("disable_user")
        username = PlaybookAction._substitute_vars(str(params.get("username") or context.get("username") or ""), context)
        if not username:
            return _fail("disable_user", "No username provided (parameter or context 'username')")
        hostname = params.get("hostname") or context.get("hostname")
        res = await containment.disable_user(
            rt.db, rt.organization_id, username=username,
            hostname=PlaybookAction._substitute_vars(str(hostname), context) if hostname else None,
            actor=rt.actor, reason=PlaybookAction._reason(params, context, "disable_user"),
            execution_ref=f"playbook_execution:{rt.execution_id}", unattended=rt.actor_user_id is None,
        )
        return PlaybookAction._containment_step("disable_user", res)

    @staticmethod
    async def _quarantine_file(params: dict, context: dict) -> dict:
        from src.services import containment

        rt = current_runtime()
        if rt is None:
            return _no_runtime("quarantine_file")
        hostname = PlaybookAction._substitute_vars(str(params.get("hostname") or context.get("hostname") or ""), context)
        file_path = PlaybookAction._substitute_vars(str(params.get("file_path") or context.get("file_path") or ""), context)
        if not hostname or not file_path:
            return _fail("quarantine_file", "hostname and file_path are required")
        res = await containment.quarantine_file(
            rt.db, rt.organization_id, hostname=hostname, file_path=file_path, actor=rt.actor,
            reason=PlaybookAction._reason(params, context, "quarantine_file"),
            execution_ref=f"playbook_execution:{rt.execution_id}", unattended=rt.actor_user_id is None,
        )
        return PlaybookAction._containment_step("quarantine_file", res)

    # ------------------------------------------------------------------
    # Notifications (tenant settings only)
    # ------------------------------------------------------------------

    @staticmethod
    async def _notify(params: dict, context: dict) -> dict:
        channel = str(params.get("channel") or "email").lower()
        if channel == "email":
            recipients = params.get("recipients") or params.get("to") or []
            return await PlaybookAction._send_email(
                {**params, "to": recipients, "body": params.get("body") or params.get("message", "")}, context,
            )
        if channel in ("slack", "teams"):
            return await PlaybookAction._send_webhook(channel, params, context, action="notify")
        return _fail("notify", f"Unsupported notification channel {channel!r} (email, slack or teams)")

    @staticmethod
    async def _send_email(params: dict, context: dict) -> dict:
        from src.services.email_service import EmailService

        rt = current_runtime()
        if rt is None:
            return _no_runtime("send_email")
        to = params.get("to") or []
        recipients = [to] if isinstance(to, str) else [str(r) for r in to]
        recipients = [r for r in recipients if r]
        subject = PlaybookAction._substitute_vars(str(params.get("subject") or "PySOAR Notification"), context)
        body = PlaybookAction._substitute_vars(str(params.get("body") or ""), context)
        if not recipients:
            return _fail("send_email", "No recipients provided")
        email_service = await EmailService.for_organization(rt.db, rt.organization_id)
        if not email_service.is_configured:
            return _awaiting("send_email", "SMTP settings for this organisation (Settings > Notifications)",
                             {"to": recipients, "subject": subject})
        try:
            sent = await email_service.send_email(to=recipients, subject=subject, body=body, html_body=params.get("html_body"))
        except Exception as exc:  # SMTP / network errors surface as a failed step
            return _fail("send_email", f"email delivery failed: {exc}", {"to": recipients, "subject": subject})
        if not sent:
            return _fail("send_email", "email delivery failed", {"to": recipients, "subject": subject})
        return _ok("send_email", {"to": recipients, "subject": subject, "sent": True})

    @staticmethod
    async def _send_slack(params: dict, context: dict) -> dict:
        return await PlaybookAction._send_webhook("slack", params, context, action="send_slack")

    @staticmethod
    async def _send_webhook(channel: str, params: dict, context: dict, *, action: str) -> dict:
        from src.services.notifications import _post_json
        from src.services.tenant_settings import notification_webhook_for

        rt = current_runtime()
        if rt is None:
            return _no_runtime(action)
        message = PlaybookAction._substitute_vars(str(params.get("message") or params.get("body") or ""), context)
        if not message:
            return _fail(action, "No message provided")
        webhook = await notification_webhook_for(rt.db, rt.organization_id, channel)
        if not webhook:
            return _awaiting(action, f"{channel} webhook for this organisation (Settings > Notifications)",
                             {"channel": channel})
        payload: dict[str, Any] = {"text": message}
        if channel == "slack" and params.get("channel_name"):
            payload["channel"] = params["channel_name"]
        ok, info = await _post_json(webhook, payload)
        details = {"channel": channel, "message_preview": message[:100], "response": info}
        if not ok:
            return _fail(action, f"{channel} webhook delivery failed: {info}", details)
        return _ok(action, {**details, "sent": True})

    # ------------------------------------------------------------------
    # Integrations
    # ------------------------------------------------------------------

    @staticmethod
    async def _org_integration(installation_id: str) -> Any:
        from sqlalchemy.orm import selectinload

        from src.integrations.models import InstalledIntegration

        rt = current_runtime()
        assert rt is not None
        q = (
            select(InstalledIntegration)
            .options(selectinload(InstalledIntegration.connector))
            .where(InstalledIntegration.id == installation_id, InstalledIntegration.organization_id == rt.organization_id)
        )
        return (await rt.db.execute(q)).scalar_one_or_none()

    @staticmethod
    async def _run_integration(action: str, installation_id: str, action_name: str, input_data: dict) -> dict:
        from src.integrations.engine import ActionExecutor

        rt = current_runtime()
        assert rt is not None
        integ = await PlaybookAction._org_integration(installation_id)
        if integ is None:
            return _fail(action, f"Installed integration {installation_id} not found in this organisation")
        if integ.status != "active":
            return _fail(action, f"Integration {integ.display_name} is {integ.status}, not active")
        execution = await ActionExecutor().execute_action(
            installation_id=integ.id, action_name=action_name, input_data=input_data,
            triggered_by="playbook", playbook_run_id=rt.execution_id,
        )
        details = {"installation_id": integ.id, "integration": integ.display_name, "action_name": action_name,
                   "integration_execution_id": execution.get("execution_id"), "output": execution.get("output_data")}
        await PlaybookAction._audit(rt, f"playbook_{action}", integ.id, details,
                                    success=execution.get("status") == "success", error=execution.get("error_message"))
        if execution.get("status") != "success":
            return _fail(action, execution.get("error_message") or "integration action failed", details)
        output = execution.get("output_data")
        if isinstance(output, dict) and (output.get("error") or output.get("result") == "error"):
            return _fail(action, str(output.get("error") or f"integration returned HTTP {output.get('status_code')}"), details)
        return _ok(action, details)

    @staticmethod
    async def _audit(rt: StepRuntime, audit_action: str, resource_id: Optional[str], details: dict,
                     *, success: bool, error: Optional[str] = None) -> None:
        from src.models.audit import AuditLog

        rt.db.add(AuditLog(
            user_id=rt.actor_user_id, organization_id=rt.organization_id, action=audit_action,
            resource_type="playbook_execution", resource_id=rt.execution_id,
            description=f"{audit_action} by {rt.actor} (resource {resource_id})"[:4000],
            new_value=json.dumps({**details, "actor": rt.actor}, default=str)[:20000],
            success=success, error_message=error,
        ))
        await rt.db.flush()

    @staticmethod
    async def _integration_action(params: dict, context: dict) -> dict:
        if current_runtime() is None:
            return _no_runtime("integration_action")
        installation_id = params.get("installation_id")
        action_name = params.get("action_name")
        if not installation_id or not action_name:
            return _fail("integration_action", "installation_id and action_name are required")
        input_data = params.get("input_data") or {}
        if not isinstance(input_data, dict):
            return _fail("integration_action", "input_data must be an object")
        return await PlaybookAction._run_integration("integration_action", str(installation_id), str(action_name), input_data)

    @staticmethod
    async def _http_request(params: dict, context: dict) -> dict:
        if current_runtime() is None:
            return _no_runtime("http_request")
        installation_id = params.get("installation_id")
        url = PlaybookAction._substitute_vars(str(params.get("url") or ""), context)
        if not installation_id:
            return _fail("http_request", "http_request requires installation_id: outbound HTTP goes through an installed "
                                         "integration and is confined to its base URL")
        if not url:
            return _fail("http_request", "No URL provided")
        input_data = {
            "url": url, "method": str(params.get("method") or "GET").upper(),
            "headers": params.get("headers") or {}, "body": params.get("body") or {},
            "params": params.get("params") or {}, "timeout": min(int(params.get("timeout_seconds") or 30), 120),
        }
        return await PlaybookAction._run_integration("http_request", str(installation_id), "http_request", input_data)

    @staticmethod
    async def _create_ticket(params: dict, context: dict) -> dict:
        from sqlalchemy.orm import selectinload

        from src.integrations.models import InstalledIntegration

        rt = current_runtime()
        if rt is None:
            return _no_runtime("create_ticket")
        wanted = str(params.get("system") or "").lower()
        if wanted and wanted not in ("jira", "servicenow"):
            return _fail("create_ticket", f"Unsupported ticketing system {wanted!r} (jira or servicenow)")
        title = PlaybookAction._substitute_vars(str(params.get("title") or "Security Incident"), context)
        description = PlaybookAction._substitute_vars(str(params.get("description") or ""), context)
        q = (
            select(InstalledIntegration)
            .options(selectinload(InstalledIntegration.connector))
            .where(InstalledIntegration.organization_id == rt.organization_id, InstalledIntegration.status == "active")
        )
        candidates = [
            i for i in (await rt.db.execute(q)).scalars().all()
            if i.connector is not None and i.connector.name in ((wanted,) if wanted else ("jira", "servicenow"))
        ]
        if not candidates:
            return _awaiting("create_ticket", f"an active {wanted or 'Jira or ServiceNow'} integration for this organisation",
                             {"title": title})
        integ = candidates[0]
        if integ.connector.name == "jira":
            project = params.get("project")
            if not project:
                return _fail("create_ticket", "Jira tickets need the 'project' parameter (project key)")
            input_data = {"project": project, "summary": title, "description": description,
                          "issue_type": params.get("issue_type", "Task"),
                          "priority": str(params.get("priority", "Medium")).capitalize()}
            return await PlaybookAction._run_integration("create_ticket", integ.id, "create_issue", input_data)
        input_data = {"data": {"short_description": title, "description": description}}
        return await PlaybookAction._run_integration("create_ticket", integ.id, "create_incident", input_data)

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    @staticmethod
    async def _local_intel(value: str) -> list[dict[str, Any]]:
        from src.intel.models import ThreatIndicator

        rt = current_runtime()
        assert rt is not None
        rows = (await rt.db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.organization_id == rt.organization_id,
                ThreatIndicator.value == value,
                ThreatIndicator.is_active == True,  # noqa: E712
            ).limit(20)
        )).scalars().all()
        return [
            {"id": r.id, "type": r.indicator_type, "confidence": r.confidence, "severity": r.severity,
             "source": r.source, "tags": r.tags}
            for r in rows
        ]

    @staticmethod
    async def _enrich_value(action: str, value: str, ioc_type: str, providers: Optional[list[str]]) -> dict:
        from src.integrations.manager import threat_intel_manager

        if current_runtime() is None:
            return _no_runtime(action)
        if not value:
            return _fail(action, "No indicator value provided")
        local = await PlaybookAction._local_intel(value)
        configured = threat_intel_manager.get_configured_providers()
        external: Optional[dict[str, Any]] = None
        if configured:
            lookup = {
                "ip": threat_intel_manager.enrich_ip,
                "domain": threat_intel_manager.enrich_domain,
                "hash": threat_intel_manager.enrich_hash,
            }.get(ioc_type)
            if lookup is None:
                return _fail(action, f"Unsupported indicator type {ioc_type!r} (ip, domain or hash)")
            try:
                external = await lookup(value, providers)
            except Exception as exc:  # provider transport errors fail the step
                return _fail(action, f"threat-intel lookup failed: {exc}")
        details = {"value": value, "type": ioc_type, "local_indicators": local,
                   "providers_configured": configured, "external": external}
        if external is None and not local:
            return _awaiting(action, "a threat-intel provider API key (VirusTotal, AbuseIPDB, Shodan or GreyNoise)", details)
        return _ok(action, details)

    @staticmethod
    async def _enrich(params: dict, context: dict) -> dict:
        value = PlaybookAction._substitute_vars(str(params.get("value") or ""), context)
        return await PlaybookAction._enrich_value("enrich", value, str(params.get("type") or "ip").lower(), params.get("providers"))

    @staticmethod
    async def _enrich_ip(params: dict, context: dict) -> dict:
        value = PlaybookAction._substitute_vars(str(params.get("ip") or context.get("source_ip") or ""), context)
        return await PlaybookAction._enrich_value("enrich_ip", value, "ip", params.get("providers"))

    @staticmethod
    async def _enrich_domain(params: dict, context: dict) -> dict:
        value = PlaybookAction._substitute_vars(str(params.get("domain") or context.get("domain") or ""), context)
        return await PlaybookAction._enrich_value("enrich_domain", value, "domain", params.get("providers"))

    @staticmethod
    async def _enrich_hash(params: dict, context: dict) -> dict:
        value = PlaybookAction._substitute_vars(str(params.get("hash") or context.get("file_hash") or ""), context)
        return await PlaybookAction._enrich_value("enrich_hash", value, "hash", params.get("providers"))

    # ------------------------------------------------------------------
    # Case work (tenant scoped)
    # ------------------------------------------------------------------

    @staticmethod
    async def _update_alert(params: dict, context: dict) -> dict:
        from src.models.alert import Alert

        rt = current_runtime()
        if rt is None:
            return _no_runtime("update_alert")
        alert_id = params.get("alert_id") or context.get("alert_id")
        updates = params.get("updates")
        if not isinstance(updates, dict):
            updates = {k: v for k, v in params.items() if k != "alert_id"}
        allowed = {"status", "priority", "assigned_to", "severity", "resolution_notes"}
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not alert_id:
            return _fail("update_alert", "No alert_id provided", {"updates": filtered})
        alert = (await rt.db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.organization_id == rt.organization_id)
        )).scalar_one_or_none()
        if alert is None:
            return _fail("update_alert", f"Alert {alert_id} not found in this organisation")
        for field_name, value in filtered.items():
            setattr(alert, field_name, value)
        if filtered.get("status") == "resolved":
            alert.resolved_at = datetime.now(timezone.utc).isoformat()
        await rt.db.flush()
        return _ok("update_alert", {"alert_id": alert_id, "updates": filtered})

    @staticmethod
    async def _update_incident(params: dict, context: dict) -> dict:
        from src.models.incident import Incident

        rt = current_runtime()
        if rt is None:
            return _no_runtime("update_incident")
        incident_id = params.get("incident_id") or context.get("incident_id")
        updates = params.get("updates") or {}
        allowed = {"status", "priority", "assigned_to", "severity", "resolution",
                   "root_cause", "impact", "lessons_learned", "recommendations"}
        filtered = {k: v for k, v in updates.items() if k in allowed}
        if not incident_id:
            return _fail("update_incident", "No incident_id provided", {"updates": filtered})
        incident = (await rt.db.execute(
            select(Incident).where(Incident.id == incident_id, Incident.organization_id == rt.organization_id)
        )).scalar_one_or_none()
        if incident is None:
            return _fail("update_incident", f"Incident {incident_id} not found in this organisation")
        for field_name, value in filtered.items():
            setattr(incident, field_name, value)
        if filtered.get("status") == "closed":
            incident.resolved_at = datetime.now(timezone.utc).isoformat()
        await rt.db.flush()
        return _ok("update_incident", {"incident_id": incident_id, "updates": filtered})

    @staticmethod
    async def _create_incident(params: dict, context: dict) -> dict:
        from src.models.incident import Incident

        rt = current_runtime()
        if rt is None:
            return _no_runtime("create_incident")
        title = PlaybookAction._substitute_vars(str(params.get("title") or context.get("alert_title") or ""), context)
        if not title:
            return _fail("create_incident", "No incident title provided")
        incident = Incident(
            organization_id=rt.organization_id,
            title=title,
            description=PlaybookAction._substitute_vars(
                str(params.get("description") or f"Created by playbook execution {rt.execution_id}"), context,
            ),
            severity=str(params.get("severity") or context.get("severity") or "medium"),
            status="open",
            incident_type=str(params.get("type") or params.get("incident_type") or "other"),
        )
        rt.db.add(incident)
        await rt.db.flush()
        context.setdefault("incident_id", incident.id)
        return _ok("create_incident", {"incident_id": incident.id, "title": title, "severity": incident.severity})

    @staticmethod
    async def _add_comment(params: dict, context: dict) -> dict:
        from src.models.alert import Alert
        from src.models.incident import Incident
        from src.tickethub.models import TicketComment

        rt = current_runtime()
        if rt is None:
            return _no_runtime("add_comment")
        target_type = str(params.get("target_type") or ("incident" if context.get("incident_id") else "alert"))
        target_id = params.get("target_id") or context.get("incident_id") or context.get("alert_id")
        comment_text = PlaybookAction._substitute_vars(str(params.get("comment") or ""), context)
        if not target_id or not comment_text:
            return _fail("add_comment", "target_id and comment are required")
        model = {"incident": Incident, "alert": Alert}.get(target_type)
        if model is None:
            return _fail("add_comment", f"Unsupported target_type {target_type!r} (incident or alert)")
        found = (await rt.db.execute(
            select(model.id).where(model.id == target_id, model.organization_id == rt.organization_id)
        )).scalar_one_or_none()
        if found is None:
            return _fail("add_comment", f"{target_type} {target_id} not found in this organisation")
        if not rt.actor_user_id:
            return _fail("add_comment", "comments need a human author; this execution has no triggering user")
        row = TicketComment(source_type=target_type, source_id=target_id, content=comment_text,
                            author_id=rt.actor_user_id, organization_id=rt.organization_id)
        rt.db.add(row)
        await rt.db.flush()
        return _ok("add_comment", {"target_type": target_type, "target_id": target_id, "comment_id": row.id,
                                   "comment_preview": comment_text[:100]})

    @staticmethod
    async def _assign_to(params: dict, context: dict) -> dict:
        from src.models.alert import Alert
        from src.models.incident import Incident
        from src.models.user import User

        rt = current_runtime()
        if rt is None:
            return _no_runtime("assign_to")
        target_type = str(params.get("target_type") or "incident")
        target_id = params.get("target_id") or context.get("incident_id") or context.get("alert_id")
        assignee = params.get("assignee")
        if not target_id or not assignee:
            return _fail("assign_to", "target_id and assignee are required")
        model = {"incident": Incident, "alert": Alert}.get(target_type)
        if model is None:
            return _fail("assign_to", f"Unsupported target_type {target_type!r} (incident or alert)")
        user_ok = (await rt.db.execute(
            select(User.id).where(User.id == assignee, User.organization_id == rt.organization_id)
        )).scalar_one_or_none()
        if user_ok is None:
            return _fail("assign_to", f"Assignee {assignee} is not a user of this organisation")
        record = (await rt.db.execute(
            select(model).where(model.id == target_id, model.organization_id == rt.organization_id)
        )).scalar_one_or_none()
        if record is None:
            return _fail("assign_to", f"{target_type} {target_id} not found in this organisation")
        record.assigned_to = assignee
        await rt.db.flush()
        return _ok("assign_to", {"target_type": target_type, "target_id": target_id, "assignee": assignee})

    # ------------------------------------------------------------------
    # Flow
    # ------------------------------------------------------------------

    @staticmethod
    async def _wait(params: dict, context: dict) -> dict:
        try:
            seconds = max(0.0, float(params.get("seconds", 5)))
        except (TypeError, ValueError):
            return _fail("wait", "seconds must be a number")
        waited = min(seconds, 60.0)  # cap for safety
        await asyncio.sleep(waited)
        return _ok("wait", {"waited_seconds": waited})

    @staticmethod
    async def _condition(params: dict, context: dict) -> dict:
        field_name = params.get("field", "")
        operator = params.get("operator", "equals")
        value = params.get("value", "")
        actual_value = context.get(field_name, "")
        try:
            if operator == "equals":
                result = str(actual_value) == str(value)
            elif operator == "not_equals":
                result = str(actual_value) != str(value)
            elif operator == "contains":
                result = str(value) in str(actual_value)
            elif operator == "greater_than":
                result = float(actual_value) > float(value)
            elif operator == "less_than":
                result = float(actual_value) < float(value)
            else:
                return _fail("condition", f"Unsupported operator {operator!r}")
        except (TypeError, ValueError) as exc:
            return _fail("condition", f"cannot compare {field_name!r}: {exc}")
        out = _ok("condition", {"field": field_name, "operator": operator, "expected": value,
                                "actual": actual_value, "result": result})
        out["condition_result"] = result
        return out

    @staticmethod
    def _substitute_vars(text: str, context: dict) -> str:
        """Substitute {{variable}} placeholders with context values"""

        def replace(match: re.Match) -> str:
            var_name = match.group(1)
            return str(context.get(var_name, match.group(0)))

        return re.sub(r"\{\{(\w+)\}\}", replace, text)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _step_status(step_result: dict[str, Any]) -> str:
    status = step_result.get("status")
    if status in (STEP_COMPLETED, STEP_FAILED, STEP_AWAITING_INTEGRATION, STEP_QUEUED_FOR_APPROVAL, STEP_MANUAL_REQUIRED):
        return status
    return STEP_COMPLETED if step_result.get("success") else STEP_FAILED


def summarize_steps(step_results: list[dict[str, Any]]) -> dict[str, int]:
    """Count of steps per status."""
    summary: dict[str, int] = {}
    for s in step_results:
        key = s.get("status") or STEP_FAILED
        summary[key] = summary.get(key, 0) + 1
    return summary


class PlaybookEngine:
    """Engine for executing playbooks"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _is_current_admin(self, user_id: Optional[str], org_id: str) -> bool:
        """True when ``user_id`` is, right now, an admin of ``org_id`` or a platform superuser."""
        if not user_id:
            return False
        from src.models.user import User

        row = (await self.db.execute(
            select(User.role, User.is_superuser, User.is_active).where(User.id == user_id, User.organization_id == org_id)
        )).first()
        if row is None or not row.is_active:
            return False
        return bool(row.is_superuser) or row.role == "admin"

    async def _actor(self, execution: PlaybookExecution, org_id: str) -> tuple[str, Optional[str]]:
        from src.models.user import User

        for candidate in (execution.triggered_by_user_id, execution.triggered_by):
            if not candidate:
                continue
            found = (await self.db.execute(
                select(User.id).where(User.id == candidate, User.organization_id == org_id)
            )).scalar_one_or_none()
            if found:
                return found, found
        return f"system:playbook:{execution.id}", None

    async def execute(
        self,
        execution_id: str,
        notify_callback: Optional[Callable[..., Awaitable[Any]]] = None,
    ) -> PlaybookExecution:
        """Execute a playbook and update execution record"""
        execution = (await self.db.execute(
            select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
        )).scalar_one_or_none()
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")

        playbook = (await self.db.execute(
            select(Playbook).where(Playbook.id == execution.playbook_id)
        )).scalar_one_or_none()
        if not playbook:
            raise ValueError(f"Playbook {execution.playbook_id} not found")

        steps = json.loads(playbook.steps) if playbook.steps else []
        execution.total_steps = len(steps)
        if not steps:
            execution.status = ExecutionStatus.COMPLETED.value
            execution.started_at = execution.started_at or _now()
            execution.completed_at = _now()
            execution.step_results = json.dumps([])
            await self.db.flush()
            return execution

        # Build context from input data and playbook variables
        context: dict[str, Any] = {}
        if execution.input_data:
            context.update(json.loads(execution.input_data))
        if playbook.variables:
            context.update(json.loads(playbook.variables))
        # Tenant scope comes from the execution row (falling back to the
        # playbook's own org), never from caller-supplied input_data or
        # playbook variables: any organization_id they carry is overwritten.
        scoped_org = execution.organization_id or playbook.organization_id
        if scoped_org:
            context["organization_id"] = scoped_org
            execution.organization_id = scoped_org
        else:
            context.pop("organization_id", None)
        context["playbook_execution_id"] = execution.id

        execution.status = ExecutionStatus.RUNNING.value
        execution.started_at = _now()
        execution.current_step = 0
        await self.db.flush()

        if notify_callback:
            await notify_callback("execution_started", {
                "execution_id": execution_id, "playbook_id": playbook.id, "playbook_name": playbook.name,
            })

        if not scoped_org:
            execution.status = ExecutionStatus.FAILED.value
            execution.completed_at = _now()
            execution.error_message = "Playbook execution has no organisation; refusing to run steps without a tenant scope"
            execution.step_results = json.dumps([])
            await self.db.flush()
            return execution

        actor, actor_user_id = await self._actor(execution, scoped_org)

        # Run-time privilege re-check (parity with the visual-builder runner):
        # the dispatch route refuses analysts for privileged steps, but
        # auto-triggered and scheduled runs never pass through it, and a
        # playbook can be edited between dispatch and execution. Privileged
        # steps run only when the attending user, or for unattended runs the
        # playbook's author, is an admin right now.
        privileged_steps = [
            (idx + 1, str(step.get("action") or ""))
            for idx, step in enumerate(steps)
            if isinstance(step, dict) and is_privileged_step(str(step.get("action") or ""), step.get("parameters") or {})
        ]
        if privileged_steps:
            authoriser = actor_user_id or playbook.created_by
            if not await self._is_current_admin(authoriser, scoped_org):
                execution.status = ExecutionStatus.FAILED.value
                execution.completed_at = _now()
                execution.error_message = (
                    "forbidden_privileged_step: step(s) "
                    + ", ".join(f"{n} ({action})" for n, action in privileged_steps)
                    + f" need an admin; run attended by {actor}"
                    + ("" if actor_user_id else f", playbook authored by {playbook.created_by or 'unknown'}")
                )
                execution.step_results = json.dumps([
                    {"step": n, "action": action, "status": "forbidden_privileged_step",
                     "error": "privileged step requires an admin", "started_at": None, "finished_at": None}
                    for n, action in privileged_steps
                ])
                await self.db.flush()
                logger.warning(
                    "playbook_privileged_steps_refused", execution_id=execution.id, playbook_id=playbook.id,
                    organization_id=scoped_org, actor=actor, steps=[n for n, _ in privileged_steps],
                )
                return execution

        runtime = StepRuntime(db=self.db, organization_id=scoped_org, execution_id=execution.id,
                              actor=actor, actor_user_id=actor_user_id)
        token = _RUNTIME.set(runtime)
        step_results: list[dict[str, Any]] = []
        failure: Optional[str] = None
        try:
            i = 0
            guard = 0
            max_iterations = max(len(steps) * 10, 50)
            while i < len(steps):
                guard += 1
                if guard > max_iterations:
                    failure = f"Execution aborted after {max_iterations} step iterations (condition loop)"
                    break
                step = steps[i] if isinstance(steps[i], dict) else {}
                execution.current_step = i + 1
                await self.db.flush()

                step_name = step.get("name") or f"Step {i + 1}"
                action = step.get("action", "")
                parameters = step.get("parameters") or {}
                timeout = step.get("timeout_seconds") or 300
                continue_on_error = bool(step.get("continue_on_error", False))

                logger.info("playbook_step_started", execution_id=execution_id, step=i + 1, action=action)
                if notify_callback:
                    await notify_callback("step_started", {
                        "execution_id": execution_id, "step_number": i + 1, "step_name": step_name, "action": action,
                    })

                started = _now()
                try:
                    step_result = await asyncio.wait_for(
                        PlaybookAction.execute(action, parameters, context), timeout=timeout,
                    )
                    if not isinstance(step_result, dict):
                        step_result = _fail(action, "step handler returned no result")
                except asyncio.TimeoutError:
                    step_result = _fail(action, f"Step {step_name} timed out after {timeout}s")
                except Exception as exc:  # a handler crash is a failed step, never a silent success
                    logger.error("playbook_step_crashed", execution_id=execution_id, action=action, error=str(exc))
                    step_result = _fail(action, str(exc))

                status = _step_status(step_result)
                record = {
                    "step": i + 1,
                    "name": step_name,
                    "action": action,
                    "status": status,
                    "started_at": started,
                    "finished_at": _now(),
                    "executed_at": started,
                    "result": step_result,
                    "error": step_result.get("error"),
                    "missing_dependency": step_result.get("missing_dependency"),
                }
                step_results.append(record)
                execution.step_results = json.dumps(step_results, default=str)

                if status == STEP_COMPLETED:
                    context[f"step_{i + 1}_result"] = step_result.get("details", {})

                if notify_callback:
                    await notify_callback("step_completed", {
                        "execution_id": execution_id, "step_number": i + 1, "step_name": step_name,
                        "status": status, "success": status == STEP_COMPLETED,
                    })

                if status == STEP_FAILED and not continue_on_error:
                    failure = f"Step {i + 1} ({step_name}) failed: {step_result.get('error') or 'no detail'}"
                    break

                next_i = i + 1
                if action == "condition" and status == STEP_COMPLETED:
                    branch = step.get("on_success" if step_result.get("condition_result") else "on_failure")
                    if branch == "skip":
                        next_i = i + 2
                    elif isinstance(branch, int) and not isinstance(branch, bool) and 0 <= branch < len(steps):
                        next_i = branch
                i = next_i
        finally:
            _RUNTIME.reset(token)

        execution.completed_at = _now()
        execution.step_results = json.dumps(step_results, default=str)
        summary = summarize_steps(step_results)
        context["step_summary"] = summary
        execution.output_data = json.dumps(context, default=str)
        if failure:
            execution.status = ExecutionStatus.FAILED.value
            execution.error_message = failure
            execution.error_step = execution.current_step
            logger.error("playbook_execution_failed", execution_id=execution_id, error=failure)
            if notify_callback:
                await notify_callback("execution_failed", {
                    "execution_id": execution_id, "playbook_id": playbook.id, "error": failure,
                    "failed_step": execution.current_step,
                })
        else:
            all_done = all(s["status"] == STEP_COMPLETED for s in step_results)
            execution.status = ExecutionStatus.COMPLETED.value if all_done else RUN_PARTIAL
            logger.info("playbook_execution_finished", execution_id=execution_id, status=execution.status, steps=summary)
            if notify_callback:
                await notify_callback("execution_completed", {
                    "execution_id": execution_id, "playbook_id": playbook.id, "status": execution.status,
                    "step_summary": summary,
                })
        await self.db.flush()
        return execution
