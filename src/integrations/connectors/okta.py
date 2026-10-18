"""Okta connector (Okta Management API, developer.okta.com/docs/api/openapi/okta-management).

Authentication: an Okta API token sent as ``Authorization: SSWS <token>``
(developer.okta.com/docs/guides/create-an-api-token). The token acts with the
privileges of the admin who created it; read actions need a read-only admin
role, the lifecycle / session / factor actions need an admin role that can
manage the target user (Help Desk, Group or Org Administrator).

Base URL ``https://<domain>`` where ``domain`` is the Okta org hostname
(``acme.okta.com``, ``acme.oktapreview.com`` or a custom domain).

Rate limits: every response carries ``x-rate-limit-limit``,
``x-rate-limit-remaining`` and ``x-rate-limit-reset`` (epoch seconds)
(developer.okta.com/docs/reference/rl-best-practices); they are recorded in
``self.rate_limit`` and a request is refused locally while the bucket is
known to be empty.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from src.core.exceptions import IntegrationError
from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
    path_segment,
)

logger = get_logger(__name__)

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")

_USER_ID = {"type": "string", "minLength": 1, "description": "Okta user id (00u...)"}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": 200}


def okta_domain(value: Any) -> str:
    """The Okta org hostname, else ValueError (the value is never echoed).

    Refuses a scheme, path, port, ``@``, ``?``, ``#``, whitespace and IP
    literals: only ``<label>.<label>[...]`` hostnames are accepted, so the
    API token can only be sent to the host the operator named.
    """
    text = str(value or "")
    if text != text.strip() or not _HOST_RE.fullmatch(text) or text.rsplit(".", 1)[-1].isdigit():
        raise ValueError("domain must be the Okta org hostname, e.g. acme.okta.com (no scheme, path or port)")
    return text.lower()


def user_ref(value: Any) -> str:
    """A user id, or a login (``ada@corp.io``) percent-encoded as one path segment."""
    text = str(value or "").strip()
    if text.count("@") == 1:
        local, _, host = text.partition("@")
        path_segment(local)
        path_segment(host)
        return quote(text, safe="")
    return path_segment(text)


class OktaConnector(BaseConnector):
    """Okta identity provider: user lookup, groups, factors, System Log, lifecycle containment."""

    name = "okta"

    CREDENTIAL_FIELDS = [
        field_spec("domain", "Okta domain", "Org hostname without scheme, e.g. acme.okta.com (custom domains allowed)"),
        field_spec("api_token", "API token", "Okta API token (sent as SSWS)", secret=True),
    ]
    TEST_CALL = "GET /api/v1/users?limit=1"
    ACTIONS = {
        "get_user": ActionSpec(
            # developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/getUser
            "Read one user by id or login (GET /api/v1/users/{idOrLogin}).",
            object_schema({"user": {"type": "string", "minLength": 1, "description": "user id or login"}}, ["user"]),
            "id, status, login, email, name, created, last login, password changed",
            idempotent=True, side_effect=False, action_type="query", display_name="Get user",
        ),
        "search_users": ActionSpec(
            # .../tag/User/#tag/User/operation/listUsers (search parameter, SCIM filter syntax)
            "Search users with an Okta search expression, e.g. profile.email eq \"ada@corp.io\" "
            "(GET /api/v1/users?search=...&limit=).",
            object_schema({"search": {"type": "string", "minLength": 1}, "limit": _LIMIT}, ["search"]),
            "user count and users (id, status, login, email, name)",
            idempotent=True, side_effect=False, action_type="query", display_name="Search users",
        ),
        "list_user_groups": ActionSpec(
            # .../tag/User/#tag/User/operation/listUserGroups
            "Groups the user belongs to (GET /api/v1/users/{id}/groups).",
            object_schema({"user_id": _USER_ID}, ["user_id"]),
            "group count and groups (id, name, type)",
            idempotent=True, side_effect=False, action_type="query", display_name="List user groups",
        ),
        "list_user_factors": ActionSpec(
            # .../tag/UserFactor/#tag/UserFactor/operation/listFactors
            "Enrolled MFA factors (GET /api/v1/users/{id}/factors).",
            object_schema({"user_id": _USER_ID}, ["user_id"]),
            "factor count and factors (id, factorType, provider, status)",
            idempotent=True, side_effect=False, action_type="query", display_name="List user factors",
        ),
        "list_logs": ActionSpec(
            # .../tag/SystemLog/#tag/SystemLog/operation/listLogEvents
            "System Log events (GET /api/v1/logs?filter=&since=&limit=); filter uses the System Log expression "
            "syntax, e.g. actor.id eq \"00u1\".",
            object_schema({
                "filter": {"type": "string"},
                "since": {"type": "string", "description": "ISO 8601 timestamp; Okta's default is 7 days ago"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            }),
            "event count and events (uuid, published, eventType, severity, actor, outcome, client IP, display message)",
            idempotent=True, side_effect=False, action_type="query", display_name="List System Log events",
        ),
        "suspend_user": ActionSpec(
            # .../tag/UserLifecycle/#tag/UserLifecycle/operation/suspendUser
            "Suspend an ACTIVE user; they cannot sign in until unsuspended (POST /api/v1/users/{id}/lifecycle/suspend).",
            object_schema({"user_id": _USER_ID}, ["user_id"]),
            "user id and new status SUSPENDED",
            idempotent=False, side_effect=True, action_type="remediate", display_name="Suspend user",
        ),
        "unsuspend_user": ActionSpec(
            # .../tag/UserLifecycle/#tag/UserLifecycle/operation/unsuspendUser
            "Return a SUSPENDED user to ACTIVE (POST /api/v1/users/{id}/lifecycle/unsuspend).",
            object_schema({"user_id": _USER_ID}, ["user_id"]),
            "user id and new status ACTIVE",
            idempotent=False, side_effect=True, action_type="remediate", display_name="Unsuspend user",
        ),
        "deactivate_user": ActionSpec(
            # .../tag/UserLifecycle/#tag/UserLifecycle/operation/deactivateUser
            "Deactivate a user: removes app assignments; reversible only by reactivation, which resets the "
            "credential (POST /api/v1/users/{id}/lifecycle/deactivate?sendEmail=false).",
            object_schema({"user_id": _USER_ID}, ["user_id"]),
            "user id and new status DEPROVISIONED",
            idempotent=False, side_effect=True, action_type="remediate", display_name="Deactivate user",
        ),
        "revoke_sessions": ActionSpec(
            # .../tag/UserSessions/#tag/UserSessions/operation/revokeUserSessions
            "End every Okta session of the user; with oauth_tokens also revoke the OAuth / OIDC tokens Okta "
            "issued to them (DELETE /api/v1/users/{id}/sessions).",
            object_schema({"user_id": _USER_ID, "oauth_tokens": {"type": "boolean"}}, ["user_id"]),
            "user id and revoked flag",
            idempotent=True, side_effect=True, action_type="remediate", display_name="Revoke sessions",
        ),
        "expire_password": ActionSpec(
            # .../tag/UserCred/#tag/UserCred/operation/expirePassword
            "Expire the user's password so they must change it at next sign-in "
            "(POST /api/v1/users/{id}/lifecycle/expire_password).",
            object_schema({"user_id": _USER_ID}, ["user_id"]),
            "user id and status PASSWORD_EXPIRED",
            idempotent=True, side_effect=True, action_type="remediate", display_name="Expire password",
        ),
        "reset_factor": ActionSpec(
            # .../tag/UserFactor/#tag/UserFactor/operation/unenrollFactor
            "Unenroll one MFA factor, e.g. a factor an attacker registered (DELETE /api/v1/users/{id}/factors/{factorId}).",
            object_schema({
                "user_id": _USER_ID,
                "factor_id": {"type": "string", "minLength": 1, "description": "factor id from list_user_factors"},
            }, ["user_id", "factor_id"]),
            "user id, factor id and removed flag",
            idempotent=True, side_effect=True, action_type="remediate", display_name="Reset factor",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(config, credentials)
        domain = self.credentials.get("domain")
        self.domain = okta_domain(domain) if domain else ""
        self.base_url = f"https://{self.domain}" if self.domain else ""

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        domain = (credentials or {}).get("domain")
        if domain:
            try:
                okta_domain(domain)
            except ValueError:
                return ["domain"]
        return []

    def _get_headers(self) -> Dict[str, str]:
        headers = super()._get_headers()
        headers["Content-Type"] = "application/json"
        token = self.credentials.get("api_token")
        if token:
            headers["Authorization"] = f"SSWS {token}"
        return headers

    async def _request(self, method: str, endpoint: str, *args: Any, **kwargs: Any) -> httpx.Response:
        if self.rate_limit.is_exceeded():
            raise IntegrationError(self.name, f"Okta rate limit exhausted until {self.rate_limit.reset_at:%Y-%m-%dT%H:%M:%SZ}")
        response = await super()._request(method, endpoint, *args, **kwargs)
        self._track_rate_limit(response)
        return response

    def _track_rate_limit(self, response: httpx.Response) -> None:
        remaining = response.headers.get("x-rate-limit-remaining")
        if remaining is None or not remaining.isdigit():
            return
        reset = response.headers.get("x-rate-limit-reset")
        reset_at = (
            datetime.fromtimestamp(int(reset), timezone.utc).replace(tzinfo=None) if reset and reset.isdigit() else None
        )
        self.rate_limit.update(int(remaining), reset_at)
        limit = response.headers.get("x-rate-limit-limit")
        if limit and limit.isdigit():
            self.rate_limit.limit = int(limit)

    async def test_connection(self) -> ConnectionTestResult:
        return await self._probe(self.TEST_CALL, lambda: self._make_request("GET", "/api/v1/users", params={"limit": 1}))

    @staticmethod
    def _user_summary(user: Dict[str, Any]) -> Dict[str, Any]:
        profile = user.get("profile") or {}
        return {
            "id": user.get("id"),
            "status": user.get("status"),
            "login": profile.get("login"),
            "email": profile.get("email"),
            "name": " ".join(p for p in (profile.get("firstName"), profile.get("lastName")) if p) or None,
        }

    async def get_user(self, user: str) -> Dict[str, Any]:
        """Get user - GET /api/v1/users/{idOrLogin}"""
        data = await self._make_request("GET", f"/api/v1/users/{user_ref(user)}")
        return {
            "provider": self.name,
            **self._user_summary(data),
            "created": data.get("created"),
            "last_login": data.get("lastLogin"),
            "password_changed": data.get("passwordChanged"),
        }

    async def search_users(self, search: str, limit: int = 200) -> Dict[str, Any]:
        """Search users - GET /api/v1/users?search=...&limit="""
        data = await self._make_request("GET", "/api/v1/users", params={"search": search, "limit": limit})
        users = [self._user_summary(u) for u in data if isinstance(u, dict)] if isinstance(data, list) else []
        return {"provider": self.name, "user_count": len(users), "users": users}

    async def list_user_groups(self, user_id: str) -> Dict[str, Any]:
        """List user groups - GET /api/v1/users/{id}/groups"""
        data = await self._make_request("GET", f"/api/v1/users/{path_segment(user_id)}/groups")
        groups = [
            {"id": g.get("id"), "name": (g.get("profile") or {}).get("name"), "type": g.get("type")}
            for g in (data if isinstance(data, list) else []) if isinstance(g, dict)
        ]
        return {"provider": self.name, "user_id": user_id, "group_count": len(groups), "groups": groups}

    async def list_user_factors(self, user_id: str) -> Dict[str, Any]:
        """List factors - GET /api/v1/users/{id}/factors"""
        data = await self._make_request("GET", f"/api/v1/users/{path_segment(user_id)}/factors")
        factors = [
            {"id": f.get("id"), "factor_type": f.get("factorType"), "provider": f.get("provider"), "status": f.get("status")}
            for f in (data if isinstance(data, list) else []) if isinstance(f, dict)
        ]
        return {"provider": self.name, "user_id": user_id, "factor_count": len(factors), "factors": factors}

    async def list_logs(self, filter: str = "", since: str = "", limit: int = 100) -> Dict[str, Any]:  # noqa: A002 (Okta's parameter name)
        """System Log - GET /api/v1/logs?filter=&since=&limit="""
        params: Dict[str, Any] = {"limit": limit}
        if filter:
            params["filter"] = filter
        if since:
            params["since"] = since
        data = await self._make_request("GET", "/api/v1/logs", params=params)
        events = []
        for e in data if isinstance(data, list) else []:
            if not isinstance(e, dict):
                continue
            events.append({
                "uuid": e.get("uuid"),
                "published": e.get("published"),
                "event_type": e.get("eventType"),
                "severity": e.get("severity"),
                "display_message": e.get("displayMessage"),
                "actor": {k: (e.get("actor") or {}).get(k) for k in ("id", "type", "alternateId", "displayName")},
                "outcome": (e.get("outcome") or {}).get("result"),
                "client_ip": (e.get("client") or {}).get("ipAddress"),
            })
        return {"provider": self.name, "event_count": len(events), "events": events}

    async def _lifecycle(self, user_id: str, operation: str, status: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        await self._make_request("POST", f"/api/v1/users/{path_segment(user_id)}/lifecycle/{operation}", params=params)
        return {"provider": self.name, "success": True, "user_id": user_id, "status": status}

    async def suspend_user(self, user_id: str) -> Dict[str, Any]:
        """Suspend - POST /api/v1/users/{id}/lifecycle/suspend"""
        return await self._lifecycle(user_id, "suspend", "SUSPENDED")

    async def unsuspend_user(self, user_id: str) -> Dict[str, Any]:
        """Unsuspend - POST /api/v1/users/{id}/lifecycle/unsuspend"""
        return await self._lifecycle(user_id, "unsuspend", "ACTIVE")

    async def deactivate_user(self, user_id: str) -> Dict[str, Any]:
        """Deactivate - POST /api/v1/users/{id}/lifecycle/deactivate?sendEmail=false"""
        return await self._lifecycle(user_id, "deactivate", "DEPROVISIONED", params={"sendEmail": "false"})

    async def expire_password(self, user_id: str) -> Dict[str, Any]:
        """Expire password - POST /api/v1/users/{id}/lifecycle/expire_password"""
        return await self._lifecycle(user_id, "expire_password", "PASSWORD_EXPIRED")

    async def revoke_sessions(self, user_id: str, oauth_tokens: bool = False) -> Dict[str, Any]:
        """Revoke sessions - DELETE /api/v1/users/{id}/sessions (204)"""
        params = {"oauthTokens": "true"} if oauth_tokens else None
        await self._make_request("DELETE", f"/api/v1/users/{path_segment(user_id)}/sessions", params=params)
        return {"provider": self.name, "success": True, "user_id": user_id, "revoked": True, "oauth_tokens": oauth_tokens}

    async def reset_factor(self, user_id: str, factor_id: str) -> Dict[str, Any]:
        """Unenroll factor - DELETE /api/v1/users/{id}/factors/{factorId} (204)"""
        await self._make_request("DELETE", f"/api/v1/users/{path_segment(user_id)}/factors/{path_segment(factor_id)}")
        return {"provider": self.name, "success": True, "user_id": user_id, "factor_id": factor_id, "removed": True}
