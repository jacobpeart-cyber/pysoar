"""Microsoft Entra ID (Azure AD) connector (Microsoft Graph v1.0, learn.microsoft.com/graph/api).

Authentication: Microsoft identity platform client-credentials grant
(learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow),
``POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`` with a
form-encoded body and ``scope=https://graph.microsoft.com/.default``; Graph
calls carry ``Authorization: Bearer <token>``. The app registration needs the
Graph *application* permissions named in each action's description, granted
with admin consent.

``MicrosoftClientCredentials`` is shared with the Defender for Endpoint
connector (same flow, different scope).
"""

import re
import secrets
import string
import time
from typing import Any, Dict, List, Optional

from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
    path_segment,
)
from src.integrations.connectors.okta import user_ref

logger = get_logger(__name__)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

MICROSOFT_APP_FIELDS = [
    field_spec("tenant_id", "Tenant id", "Microsoft Entra tenant id (GUID) or primary domain"),
    field_spec("client_id", "Client id", "Application (client) id of the app registration"),
    field_spec("client_secret", "Client secret", "Client secret of the app registration", secret=True),
]

_USER = {"type": "string", "minLength": 1, "description": "user object id (GUID) or userPrincipalName"}
_USER_GUID = {"type": "string", "minLength": 1, "description": "user object id (GUID)"}
_TOP = {"type": "integer", "minimum": 1, "maximum": 999}
_USER_SELECT = "id,userPrincipalName,displayName,accountEnabled,mail,jobTitle,department"


def odata_string(value: str) -> str:
    """An OData string literal body: single quotes doubled (OData ABNF ``SQUOTE-in-string``)."""
    return str(value).replace("'", "''")


def guid(value: Any, what: str = "id") -> str:
    text = str(value or "").strip()
    if not GUID_RE.fullmatch(text):
        raise ValueError(f"{what} must be an object id (GUID)")
    return text


class MicrosoftClientCredentials:
    """Client-credentials token for one scope (mixin for ``BaseConnector`` subclasses)."""

    TOKEN_SCOPE: str = ""
    _token: Optional[str] = None
    _token_expiry: float = 0

    @classmethod
    def tenant_invalid(cls, credentials: Optional[Dict[str, Any]]) -> List[str]:
        tenant = (credentials or {}).get("tenant_id")
        return ["tenant_id"] if tenant and not TENANT_RE.fullmatch(str(tenant).strip()) else []

    @staticmethod
    def checked_tenant(value: Any) -> str:
        text = str(value or "").strip()
        if not TENANT_RE.fullmatch(text):
            raise ValueError("credential field tenant_id has an invalid format")
        return text

    async def _client_credentials_token(self, tenant: str, client_id: str, client_secret: str) -> str:
        """POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token (form body, no Authorization header)"""
        if self._token and time.time() < self._token_expiry:
            return self._token
        data = await self._make_request(  # type: ignore[attr-defined]
            "POST",
            f"https://login.microsoftonline.com/{self.checked_tenant(tenant)}/oauth2/v2.0/token",
            form_data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": self.TOKEN_SCOPE,
            },
            auth=False,
        )
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise ValueError("token response carried no access_token")
        self._token = token
        self._token_expiry = time.time() + int(data.get("expires_in", 3600)) - 60
        return token

    def _bearer(self, headers: Dict[str, str]) -> Dict[str, str]:
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers


def generate_password(length: int = 20) -> str:
    """A random password meeting the Entra policy (8-256 chars, 3 of 4 character classes): all four used."""
    symbols = "!@#$%^&*-_=+?"
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, symbols]
    chars = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class EntraIDConnector(MicrosoftClientCredentials, BaseConnector):
    """Microsoft Entra ID: users, sign-in logs, Identity Protection risky users, account containment."""

    name = "azure_ad"
    base_url = "https://graph.microsoft.com/v1.0"
    TOKEN_SCOPE = GRAPH_SCOPE

    CREDENTIAL_FIELDS = list(MICROSOFT_APP_FIELDS)
    TEST_CALL = "POST login.microsoftonline.com/<tenant>/oauth2/v2.0/token, then GET /v1.0/organization?$select=id,displayName"
    ACTIONS = {
        "get_user": ActionSpec(
            # learn.microsoft.com/graph/api/user-get
            "Read one user (GET /users/{id|upn}?$select=...). Permission: User.Read.All.",
            object_schema({"user": _USER}, ["user"]),
            "id, userPrincipalName, displayName, accountEnabled, mail, jobTitle, department",
            idempotent=True, side_effect=False, action_type="query", display_name="Get user",
        ),
        "search_users": ActionSpec(
            # learn.microsoft.com/graph/api/user-list (startswith $filter)
            "Users whose displayName or userPrincipalName starts with the text "
            "(GET /users?$filter=startswith(...)&$top=). Permission: User.Read.All.",
            object_schema({"query": {"type": "string", "minLength": 1}, "top": _TOP}, ["query"]),
            "user count and users (id, userPrincipalName, displayName, accountEnabled, mail)",
            idempotent=True, side_effect=False, action_type="query", display_name="Search users",
        ),
        "list_sign_ins": ActionSpec(
            # learn.microsoft.com/graph/api/signin-list
            "Sign-in log entries of one user (GET /auditLogs/signIns?$filter=userId eq '{id}'&$top=). "
            "Permission: AuditLog.Read.All (and Directory.Read.All); needs an Entra ID P1 or P2 licence.",
            object_schema({"user_id": _USER_GUID, "top": _TOP}, ["user_id"]),
            "sign-in count and sign-ins (time, app, IP, location, status code, risk level, conditional access)",
            idempotent=True, side_effect=False, action_type="query", display_name="List sign-ins",
        ),
        "list_risky_users": ActionSpec(
            # learn.microsoft.com/graph/api/riskyuser-list
            "Identity Protection risky users (GET /identityProtection/riskyUsers?$filter=riskState eq '...'&$top=). "
            "Permission: IdentityRiskyUser.Read.All; needs an Entra ID P2 licence.",
            object_schema({
                "risk_state": {"type": "string", "enum": ["atRisk", "confirmedCompromised", "remediated", "dismissed"]},
                "top": _TOP,
            }),
            "risky user count and users (id, userPrincipalName, riskLevel, riskState, riskDetail, last updated)",
            idempotent=True, side_effect=False, action_type="query", display_name="List risky users",
        ),
        "disable_user": ActionSpec(
            # learn.microsoft.com/graph/api/user-update (accountEnabled)
            "Block sign-in: PATCH /users/{id} {\"accountEnabled\": false}. Existing tokens stay valid until "
            "they expire; pair with revoke_sign_in_sessions. Permission: User.EnableDisableAccount.All and User.Read.All.",
            object_schema({"user": _USER}, ["user"]),
            "user and accountEnabled false",
            idempotent=True, side_effect=True, action_type="remediate", display_name="Disable user",
        ),
        "enable_user": ActionSpec(
            # learn.microsoft.com/graph/api/user-update (accountEnabled)
            "Allow sign-in again: PATCH /users/{id} {\"accountEnabled\": true}. "
            "Permission: User.EnableDisableAccount.All and User.Read.All.",
            object_schema({"user": _USER}, ["user"]),
            "user and accountEnabled true",
            idempotent=True, side_effect=True, action_type="remediate", display_name="Enable user",
        ),
        "revoke_sign_in_sessions": ActionSpec(
            # learn.microsoft.com/graph/api/user-revokesigninsessions
            "Invalidate the user's refresh tokens and session cookies (POST /users/{id}/revokeSignInSessions). "
            "Permission: User.RevokeSessions.All.",
            object_schema({"user": _USER}, ["user"]),
            "user and revoked flag",
            idempotent=True, side_effect=True, action_type="remediate", display_name="Revoke sign-in sessions",
        ),
        "reset_password": ActionSpec(
            # learn.microsoft.com/graph/api/user-update (passwordProfile) and
            # learn.microsoft.com/graph/api/resources/passwordprofile
            "Lock the current credential out: replace the password with a random value that is never returned, "
            "logged or stored, with forceChangePasswordNextSignIn true (PATCH /users/{id} passwordProfile); the user "
            "recovers through self-service password reset or the help desk. Permission: User-PasswordProfile.ReadWrite.All, "
            "and the app must also hold a privileged Entra role able to reset this user's password (e.g. User "
            "Administrator, or Privileged Authentication Administrator for admins).",
            object_schema({"user": _USER}, ["user"]),
            "user, force_change_password_next_sign_in true and a note that the new password was not stored",
            idempotent=False, side_effect=True, action_type="remediate", display_name="Reset password",
        ),
        "confirm_compromised": ActionSpec(
            # learn.microsoft.com/graph/api/riskyuser-confirmcompromised
            "Mark users as compromised in Identity Protection, setting their user risk to high "
            "(POST /identityProtection/riskyUsers/confirmCompromised). Permission: IdentityRiskyUser.ReadWrite.All.",
            object_schema({"user_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1}}, ["user_ids"]),
            "user ids and confirmed flag",
            idempotent=True, side_effect=True, action_type="update", display_name="Confirm compromised",
        ),
        "dismiss_risk": ActionSpec(
            # learn.microsoft.com/graph/api/riskyuser-dismiss
            "Dismiss the user risk of users (POST /identityProtection/riskyUsers/dismiss). "
            "Permission: IdentityRiskyUser.ReadWrite.All.",
            object_schema({"user_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1}}, ["user_ids"]),
            "user ids and dismissed flag",
            idempotent=True, side_effect=True, action_type="update", display_name="Dismiss risk",
        ),
    }

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        return cls.tenant_invalid(credentials)

    def _get_headers(self) -> Dict[str, str]:
        return self._bearer(super()._get_headers())

    def _secret_values(self) -> List[str]:
        return super()._secret_values() + list(getattr(self, "_transient_secrets", []))

    async def _get_oauth_token(self) -> str:
        return await self._client_credentials_token(
            str(self.credentials.get("tenant_id") or ""),
            str(self.credentials.get("client_id") or ""),
            str(self.credentials.get("client_secret") or ""),
        )

    async def _graph(self, method: str, path: str, **kwargs: Any) -> Any:
        await self._get_oauth_token()
        return await self._make_request(method, path, **kwargs)

    async def test_connection(self) -> ConnectionTestResult:
        async def _check() -> Any:
            return await self._graph("GET", "/organization", params={"$select": "id,displayName"})

        return await self._probe(self.TEST_CALL, _check)

    async def get_user(self, user: str) -> Dict[str, Any]:
        """Get user - GET /users/{id | userPrincipalName}"""
        data = await self._graph("GET", f"/users/{user_ref(user)}", params={"$select": _USER_SELECT})
        return {"provider": self.name, **{k: data.get(k) for k in _USER_SELECT.split(",")}}

    async def search_users(self, query: str, top: int = 25) -> Dict[str, Any]:
        """List users - GET /users?$filter=startswith(displayName,'x') or startswith(userPrincipalName,'x')"""
        q = odata_string(query)
        data = await self._graph("GET", "/users", params={
            "$filter": f"startswith(displayName,'{q}') or startswith(userPrincipalName,'{q}')",
            "$select": "id,userPrincipalName,displayName,accountEnabled,mail",
            "$top": top,
        })
        users = [
            {k: u.get(k) for k in ("id", "userPrincipalName", "displayName", "accountEnabled", "mail")}
            for u in data.get("value") or [] if isinstance(u, dict)
        ]
        return {"provider": self.name, "user_count": len(users), "users": users}

    async def list_sign_ins(self, user_id: str, top: int = 50) -> Dict[str, Any]:
        """List sign-ins - GET /auditLogs/signIns?$filter=userId eq '{id}'"""
        uid = guid(user_id, "user_id")
        data = await self._graph("GET", "/auditLogs/signIns", params={"$filter": f"userId eq '{uid}'", "$top": top})
        sign_ins = []
        for s in data.get("value") or []:
            if not isinstance(s, dict):
                continue
            status = s.get("status") or {}
            location = s.get("location") or {}
            sign_ins.append({
                "id": s.get("id"),
                "created": s.get("createdDateTime"),
                "user_principal_name": s.get("userPrincipalName"),
                "app": s.get("appDisplayName"),
                "ip_address": s.get("ipAddress"),
                "location": ", ".join(str(v) for v in (location.get("city"), location.get("countryOrRegion")) if v) or None,
                "error_code": status.get("errorCode"),
                "failure_reason": status.get("failureReason"),
                "risk_level": s.get("riskLevelDuringSignIn"),
                "conditional_access_status": s.get("conditionalAccessStatus"),
            })
        return {"provider": self.name, "user_id": uid, "sign_in_count": len(sign_ins), "sign_ins": sign_ins}

    async def list_risky_users(self, risk_state: str = "atRisk", top: int = 50) -> Dict[str, Any]:
        """List riskyUsers - GET /identityProtection/riskyUsers?$filter=riskState eq '...'"""
        data = await self._graph("GET", "/identityProtection/riskyUsers", params={
            "$filter": f"riskState eq '{odata_string(risk_state)}'", "$top": top,
        })
        users = [
            {
                "id": u.get("id"),
                "user_principal_name": u.get("userPrincipalName"),
                "risk_level": u.get("riskLevel"),
                "risk_state": u.get("riskState"),
                "risk_detail": u.get("riskDetail"),
                "last_updated": u.get("riskLastUpdatedDateTime"),
            }
            for u in data.get("value") or [] if isinstance(u, dict)
        ]
        return {"provider": self.name, "risk_state": risk_state, "user_count": len(users), "users": users}

    async def _set_enabled(self, user: str, enabled: bool) -> Dict[str, Any]:
        await self._graph("PATCH", f"/users/{user_ref(user)}", json_data={"accountEnabled": enabled})
        return {"provider": self.name, "success": True, "user": user, "account_enabled": enabled}

    async def disable_user(self, user: str) -> Dict[str, Any]:
        """Update user - PATCH /users/{id} {"accountEnabled": false} (204)"""
        return await self._set_enabled(user, False)

    async def enable_user(self, user: str) -> Dict[str, Any]:
        """Update user - PATCH /users/{id} {"accountEnabled": true} (204)"""
        return await self._set_enabled(user, True)

    async def revoke_sign_in_sessions(self, user: str) -> Dict[str, Any]:
        """revokeSignInSessions - POST /users/{id}/revokeSignInSessions"""
        data = await self._graph("POST", f"/users/{user_ref(user)}/revokeSignInSessions")
        return {"provider": self.name, "success": True, "user": user, "revoked": bool(data.get("value", True))}

    async def reset_password(self, user: str) -> Dict[str, Any]:
        """Update user - PATCH /users/{id} {"passwordProfile": {...}} (204); the random password is discarded"""
        password = generate_password()
        # Redacted from any vendor error text that might echo the request body.
        self._transient_secrets = [password]
        try:
            await self._graph("PATCH", f"/users/{user_ref(user)}", json_data={
                "passwordProfile": {"forceChangePasswordNextSignIn": True, "password": password},
            })
        finally:
            del password  # never returned, logged or stored
        return {
            "provider": self.name,
            "success": True,
            "user": user,
            "force_change_password_next_sign_in": True,
            "password_status": "password replaced with an unstored random value; the user recovers through "
                               "self-service password reset or the help desk",
        }

    async def _risky_users(self, operation: str, user_ids: List[str]) -> List[str]:
        ids = [guid(u, "user_ids item") for u in user_ids]
        await self._graph("POST", f"/identityProtection/riskyUsers/{path_segment(operation)}", json_data={"userIds": ids})
        return ids

    async def confirm_compromised(self, user_ids: List[str]) -> Dict[str, Any]:
        """confirmCompromised - POST /identityProtection/riskyUsers/confirmCompromised (204)"""
        ids = await self._risky_users("confirmCompromised", user_ids)
        return {"provider": self.name, "success": True, "user_ids": ids, "confirmed_compromised": True}

    async def dismiss_risk(self, user_ids: List[str]) -> Dict[str, Any]:
        """dismiss - POST /identityProtection/riskyUsers/dismiss (204)"""
        ids = await self._risky_users("dismiss", user_ids)
        return {"provider": self.name, "success": True, "user_ids": ids, "dismissed": True}
