"""ITDR identity sources: directory sync, CSV import and identity-provider actions.

Until wave 3 the only producer of ``IdentityProfile`` rows was a manual
``POST /itdr/identities`` no UI called, so every ITDR widget ran on an empty
table. This module is the ingestion side.

Sources
-------
* **Okta** (installed integration, connector ``okta``): ``config.base_url``
  (``https://<org>.okta.com``) and an API token in the credentials
  (``api_key`` / ``token`` / ``api_token``, sent as ``SSWS``). Users come from
  ``GET /api/v1/users`` (200 per page, ``Link: rel="next"``); admin-role
  holders from ``GET /api/v1/iam/assignees/users``; MFA from
  ``GET /api/v1/users/{id}/factors`` (one call per user, at most
  ``MAX_MFA_LOOKUPS`` per sync; the rest keep their stored MFA state and are
  counted as ``mfa_unchecked``).
* **Entra ID** (connector ``azure_ad``): ``tenant_id``, ``client_id`` and
  ``client_secret`` (credentials or config) for the client-credentials flow
  against ``login.microsoftonline.com``. Users from Microsoft Graph
  ``/v1.0/users`` (``signInActivity`` when the app may read it, otherwise
  retried without it), admin flag and MFA registration from
  ``/v1.0/reports/authenticationMethods/userRegistrationDetails`` (left
  unknown when the app lacks ``AuditLog.Read.All``).
* **Active Directory**: PySOAR has no LDAP connector, so AD identities come
  in through the validated CSV import (``Get-ADUser`` export column names are
  accepted as aliases, see ``CSV_ALIASES``). AD response actions therefore
  report ``awaiting_integration``.

Every sync is capped at ``MAX_SYNC_USERS`` users and upserts page by page,
so memory stays at one page plus small per-user lookup sets.

Outbound calls
--------------
Okta calls are pinned to the integration's configured ``base_url`` through
the integration engine's guard (``ActionExecutor._resolve_generic_target``:
same origin as the stored base URL, DNS resolved once, internal addresses
refused, connection to the vetted IP). Microsoft endpoints are fixed vendor
URLs vetted with ``resolve_and_vet``. Redirects are never followed and every
request has a timeout. ``ActionExecutor.execute_action`` itself is not used
for these calls: it persists the request ``input_data`` (headers included)
into ``integration_executions``, which would store the identity-provider
token in clear text. Each provider action writes an ``AuditLog`` row instead
(actor, identity, provider, outcome).
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote, urlsplit

import httpx
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.integrations.models import InstalledIntegration, IntegrationStatus
from src.integrations.netguard import OutboundTargetRefused, merge_pinned_kwargs, resolve_and_vet
from src.itdr.models import IdentityProfile, IdentityProvider, PrivilegeLevel
from src.models.audit import AuditLog

logger = get_logger(__name__)

#: Connector names with a real directory implementation.
SUPPORTED_CONNECTORS: tuple[str, ...] = ("okta", "azure_ad")
#: Response actions an identity provider can carry out.
IDP_ACTIONS: tuple[str, ...] = ("disable_account", "enable_account", "force_password_reset", "revoke_sessions")

MAX_SYNC_USERS = 20_000
MAX_MFA_LOOKUPS = 1_000
OKTA_PAGE_SIZE = 200
GRAPH_PAGE_SIZE = 999
UPSERT_CHUNK = 500
HTTP_TIMEOUT = httpx.Timeout(20.0, connect=10.0)
#: No successful sign-in for this long marks a directory identity dormant.
DORMANT_DAYS = 90

CSV_MAX_BYTES = 5 * 1024 * 1024
CSV_MAX_ROWS = 50_000
CSV_MAX_ERRORS_REPORTED = 200

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
MS_LOGIN_ROOT = "https://login.microsoftonline.com"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class DirectoryError(Exception):
    """A directory call failed. The message never contains credentials."""


def _inner_transport() -> Optional[httpx.AsyncBaseTransport]:
    """httpx transport for directory calls (None = default). Tests replace it."""
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Optional[str]:
    """Normalised ISO-8601 UTC string from a provider / CSV timestamp, else None."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"unrecognised timestamp {text!r}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Normalised directory record and upsert
# ---------------------------------------------------------------------------


@dataclass
class DirectoryUser:
    """One identity as a source reports it. ``None`` means "the source did not say"."""

    user_id: str
    username: str
    email: str
    display_name: Optional[str] = None
    identity_provider: str = IdentityProvider.ACTIVE_DIRECTORY.value
    account_status: Optional[str] = None
    mfa_enabled: Optional[bool] = None
    mfa_methods: Optional[list[str]] = None
    is_admin: Optional[bool] = None
    privilege_level: Optional[str] = None
    role_assignments: Optional[list[str]] = None
    group_memberships: Optional[list[str]] = None
    is_service_account: Optional[bool] = None
    last_authentication: Optional[str] = None
    last_password_change: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


def _dormant(last_auth: Optional[str], now: datetime) -> Optional[bool]:
    if not last_auth:
        return None
    try:
        dt = datetime.fromisoformat(last_auth.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < now - timedelta(days=DORMANT_DAYS)


def _apply(row: IdentityProfile, rec: DirectoryUser, source: str, integration_id: Optional[str], now_iso: str,
           now: datetime) -> None:
    previous_source = row.source
    row.user_id = rec.user_id[:255]
    row.username = rec.username[:255]
    row.email = rec.email[:255]
    row.identity_provider = rec.identity_provider
    row.source = source
    row.source_integration_id = integration_id
    row.last_synced_at = now_iso
    if rec.display_name is not None:
        row.display_name = rec.display_name[:500]
    if rec.account_status is not None:
        row.account_status = rec.account_status[:50]
    if rec.mfa_enabled is not None:
        row.mfa_enabled = rec.mfa_enabled
    if rec.mfa_methods is not None:
        row.mfa_methods = rec.mfa_methods
    if rec.role_assignments is not None:
        row.role_assignments = rec.role_assignments
    if rec.group_memberships is not None:
        row.group_memberships = rec.group_memberships
    if rec.is_service_account is not None:
        row.is_service_account = rec.is_service_account
    if rec.privilege_level is not None:
        row.privilege_level = rec.privilege_level
    elif rec.is_admin is True:
        row.privilege_level = PrivilegeLevel.ADMIN.value
    elif rec.is_admin is False and row.privilege_level == PrivilegeLevel.ADMIN.value and previous_source == source:
        # The provider says this account no longer holds an admin role.
        row.privilege_level = PrivilegeLevel.STANDARD.value
    if rec.last_authentication is not None:
        row.last_authentication = rec.last_authentication
    if rec.last_password_change is not None:
        row.last_password_change = rec.last_password_change
    dormant = _dormant(row.last_authentication, now)
    if dormant is not None:
        row.is_dormant = dormant


async def upsert_identities(
    db: AsyncSession,
    org_id: str,
    records: list[DirectoryUser],
    *,
    source: str,
    integration_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict[str, int]:
    """Create or update ``IdentityProfile`` rows of ``org_id`` (flushes, does not commit).

    A record matches an existing identity of the organisation by
    ``(source_integration_id, user_id)`` first, then case-insensitive
    username, then case-insensitive email.
    """
    now = now or _now()
    now_iso = now.isoformat()
    created = updated = 0
    for offset in range(0, len(records), UPSERT_CHUNK):
        chunk = records[offset:offset + UPSERT_CHUNK]
        user_ids = [r.user_id for r in chunk]
        names = [r.username.lower() for r in chunk]
        emails = [r.email.lower() for r in chunk]
        conds = [func.lower(IdentityProfile.username).in_(names), func.lower(IdentityProfile.email).in_(emails)]
        if integration_id:
            conds.append(IdentityProfile.user_id.in_(user_ids))
        existing = list((await db.execute(
            select(IdentityProfile).where(IdentityProfile.organization_id == org_id, or_(*conds)),
        )).scalars().all())
        by_ext = {(e.source_integration_id, e.user_id): e for e in existing if e.source_integration_id}
        by_name = {(e.username or "").lower(): e for e in existing}
        by_email = {(e.email or "").lower(): e for e in existing}
        for rec in chunk:
            row = (
                (by_ext.get((integration_id, rec.user_id)) if integration_id else None)
                or by_name.get(rec.username.lower())
                or by_email.get(rec.email.lower())
            )
            if row is None:
                row = IdentityProfile(
                    organization_id=org_id, user_id=rec.user_id[:255], username=rec.username[:255],
                    email=rec.email[:255], privilege_level=PrivilegeLevel.STANDARD.value,
                    mfa_enabled=False, is_service_account=False, is_dormant=False, risk_score=0.0,
                )
                db.add(row)
                created += 1
            else:
                updated += 1
            _apply(row, rec, source, integration_id, now_iso, now)
            by_name[rec.username.lower()] = row
            by_email[rec.email.lower()] = row
        await db.flush()
    return {"created": created, "updated": updated}


# ---------------------------------------------------------------------------
# Installed identity-provider integrations
# ---------------------------------------------------------------------------


def connector_name(integration: InstalledIntegration) -> str:
    connector = integration.connector
    return (connector.name if connector is not None else str(integration.connector_id or "")).lower()


async def identity_integrations(db: AsyncSession, org_id: str) -> list[InstalledIntegration]:
    """Active Okta / Entra ID integrations installed by ``org_id``."""
    rows = (await db.execute(
        select(InstalledIntegration)
        .options(selectinload(InstalledIntegration.connector))
        .where(
            InstalledIntegration.organization_id == org_id,
            InstalledIntegration.status == IntegrationStatus.ACTIVE.value,
        ),
    )).scalars().all()
    return [row for row in rows if connector_name(row) in SUPPORTED_CONNECTORS]


def _secrets(integration: InstalledIntegration) -> tuple[dict[str, Any], dict[str, Any]]:
    """(config, credentials) of an installed integration, decrypted the engine's way."""
    from src.integrations.engine import ActionExecutor

    config = safe_json_loads(integration.config_encrypted, {}) or {}
    credentials = ActionExecutor()._decrypt_secret_json(integration.auth_credentials_encrypted)
    return (config if isinstance(config, dict) else {}), (credentials if isinstance(credentials, dict) else {})


class _Client:
    """Outbound HTTP for one provider: every URL vetted and pinned before the request."""

    def __init__(self, config: dict[str, Any], pin_to_base: bool) -> None:
        self.config = config
        self.pin_to_base = pin_to_base
        self.http = httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=False, transport=_inner_transport())

    async def __aenter__(self) -> "_Client":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.http.aclose()

    async def request(self, method: str, url: str, headers: dict[str, str], **kwargs: Any) -> httpx.Response:
        if self.pin_to_base:
            from src.integrations.engine import ActionExecutor

            pinned = await ActionExecutor()._resolve_generic_target(url, self.config)
            target = pinned.target
        else:
            target = await resolve_and_vet(url)
        pin = merge_pinned_kwargs(target, headers)
        try:
            return await self.http.request(
                method, target.pinned_url, headers=pin["headers"], extensions=pin["extensions"], **kwargs,
            )
        except httpx.HTTPError as exc:
            raise DirectoryError(f"{method} {urlsplit(url).path}: {type(exc).__name__}") from exc


def _http_error(resp: httpx.Response, what: str) -> DirectoryError:
    detail = ""
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            detail = str(err.get("message") or "")
        else:
            detail = str(body.get("errorSummary") or body.get("error_description") or err or "")
    return DirectoryError(f"{what}: HTTP {resp.status_code}{(' ' + detail[:200]) if detail else ''}")


def _next_link(link_header: str) -> Optional[str]:
    for part in (link_header or "").split(","):
        if 'rel="next"' in part:
            match = re.search(r"<([^>]+)>", part)
            if match:
                return match.group(1)
    return None


# ---------------------------------------------------------------------------
# Okta
# ---------------------------------------------------------------------------


def _okta_auth(config: dict[str, Any], credentials: dict[str, Any]) -> tuple[str, dict[str, str]]:
    base = str(config.get("base_url") or config.get("url") or "").strip().rstrip("/")
    token = credentials.get("api_key") or credentials.get("token") or credentials.get("api_token")
    if not base or not token:
        raise DirectoryError("Okta integration needs config.base_url and an API token (credentials.api_key)")
    if urlsplit(base).scheme != "https":
        raise DirectoryError("Okta base_url must be https")
    return base, {"Authorization": f"SSWS {token}", "Accept": "application/json", "Content-Type": "application/json"}


_OKTA_INACTIVE = {"SUSPENDED", "DEPROVISIONED", "LOCKED_OUT"}


async def _okta_users(client: _Client, base: str, headers: dict[str, str], summary: dict[str, Any]):
    """Yield pages of Okta users (raw dicts), at most ``MAX_SYNC_USERS``."""
    url: Optional[str] = f"{base}/api/v1/users?limit={OKTA_PAGE_SIZE}"
    seen = 0
    while url:
        resp = await client.request("GET", url, headers)
        if resp.status_code != 200:
            raise _http_error(resp, "Okta list users")
        page = resp.json()
        if not isinstance(page, list):
            raise DirectoryError("Okta list users: unexpected response shape")
        remaining = MAX_SYNC_USERS - seen
        url = _next_link(resp.headers.get("link", ""))
        if len(page) > remaining:
            page = page[:remaining]
            url = None
            summary["capped"] = True
        seen += len(page)
        yield page
        if seen >= MAX_SYNC_USERS and url:
            summary["capped"] = True
            return


async def _okta_admin_ids(client: _Client, base: str, headers: dict[str, str], summary: dict[str, Any]) -> Optional[set[str]]:
    ids: set[str] = set()
    url: Optional[str] = f"{base}/api/v1/iam/assignees/users?limit={OKTA_PAGE_SIZE}"
    while url and len(ids) < MAX_SYNC_USERS:
        resp = await client.request("GET", url, headers)
        if resp.status_code in (401, 403, 404):
            summary["warnings"].append(f"Okta admin-role listing unavailable (HTTP {resp.status_code}); privilege levels unchanged")
            return None
        if resp.status_code != 200:
            raise _http_error(resp, "Okta list admin assignees")
        body = resp.json()
        items = body.get("value", []) if isinstance(body, dict) else body
        for item in items or []:
            if isinstance(item, dict) and item.get("id"):
                ids.add(str(item["id"]))
        url = _next_link(resp.headers.get("link", ""))
    return ids


async def _okta_factors(client: _Client, base: str, headers: dict[str, str], user_id: str) -> Optional[list[str]]:
    resp = await client.request("GET", f"{base}/api/v1/users/{quote(user_id, safe='')}/factors", headers)
    if resp.status_code != 200:
        return None
    factors = resp.json()
    if not isinstance(factors, list):
        return None
    return sorted({str(f.get("factorType")) for f in factors if isinstance(f, dict) and f.get("status") == "ACTIVE" and f.get("factorType")})


def _okta_record(user: dict[str, Any], admin_ids: Optional[set[str]]) -> Optional[DirectoryUser]:
    profile = user.get("profile") or {}
    login = str(profile.get("login") or "").strip()
    email = str(profile.get("email") or login).strip()
    uid = str(user.get("id") or "").strip()
    if not uid or not login or not _EMAIL_RE.match(email):
        return None
    name = profile.get("displayName") or " ".join(p for p in (profile.get("firstName"), profile.get("lastName")) if p) or None
    status = str(user.get("status") or "").upper() or None
    return DirectoryUser(
        user_id=uid, username=login, email=email, display_name=name,
        identity_provider=IdentityProvider.OKTA.value, account_status=status,
        is_admin=(uid in admin_ids) if admin_ids is not None else None,
        last_authentication=_safe_iso(user.get("lastLogin")),
        last_password_change=_safe_iso(user.get("passwordChanged")),
        role_assignments=["okta_admin"] if admin_ids is not None and uid in admin_ids else None,
    )


def _safe_iso(value: Any) -> Optional[str]:
    try:
        return _iso(value)
    except ValueError:
        return None


async def _sync_okta(db: AsyncSession, org_id: str, integration: InstalledIntegration, summary: dict[str, Any]) -> None:
    config, credentials = _secrets(integration)
    base, headers = _okta_auth(config, credentials)
    mfa_budget = MAX_MFA_LOOKUPS
    async with _Client(config, pin_to_base=True) as client:
        admin_ids = await _okta_admin_ids(client, base, headers, summary)
        async for page in _okta_users(client, base, headers, summary):
            records: list[DirectoryUser] = []
            for user in page:
                rec = _okta_record(user, admin_ids)
                if rec is None:
                    summary["skipped"] += 1
                    continue
                if mfa_budget > 0:
                    mfa_budget -= 1
                    methods = await _okta_factors(client, base, headers, rec.user_id)
                    if methods is not None:
                        rec.mfa_methods = methods
                        rec.mfa_enabled = bool(methods)
                    else:
                        summary["mfa_unchecked"] += 1
                else:
                    summary["mfa_unchecked"] += 1
                records.append(rec)
            counts = await upsert_identities(db, org_id, records, source="okta", integration_id=integration.id)
            summary["created"] += counts["created"]
            summary["updated"] += counts["updated"]
            summary["fetched"] += len(page)


async def _okta_action(integration: InstalledIntegration, identity: IdentityProfile, action: str) -> dict[str, Any]:
    config, credentials = _secrets(integration)
    base, headers = _okta_auth(config, credentials)
    ref = identity.user_id if identity.source_integration_id == integration.id else (identity.username or identity.email)
    user_path = f"{base}/api/v1/users/{quote(str(ref), safe='')}"
    calls = {
        "disable_account": [("POST", f"{user_path}/lifecycle/suspend")],
        "enable_account": [("POST", f"{user_path}/lifecycle/unsuspend")],
        "force_password_reset": [("POST", f"{user_path}/lifecycle/expire_password"), ("DELETE", f"{user_path}/sessions")],
        "revoke_sessions": [("DELETE", f"{user_path}/sessions")],
    }[action]
    steps = []
    async with _Client(config, pin_to_base=True) as client:
        for method, url in calls:
            resp = await client.request(method, url, headers)
            steps.append({"call": f"{method} {urlsplit(url).path}", "http_status": resp.status_code})
            if resp.status_code not in (200, 202, 204):
                raise _http_error(resp, f"Okta {action}")
    return {"steps": steps, "account_status": {"disable_account": "SUSPENDED", "enable_account": "ACTIVE"}.get(action)}


# ---------------------------------------------------------------------------
# Entra ID (Microsoft Graph)
# ---------------------------------------------------------------------------


def _entra_creds(config: dict[str, Any], credentials: dict[str, Any]) -> tuple[str, str, str]:
    def pick(key: str) -> str:
        return str(credentials.get(key) or config.get(key) or "").strip()

    tenant, client_id, secret = pick("tenant_id"), pick("client_id"), pick("client_secret")
    if not (tenant and client_id and secret):
        raise DirectoryError("Entra ID integration needs tenant_id, client_id and client_secret")
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,100}", tenant):
        raise DirectoryError("Entra ID tenant_id is not a tenant id or domain")
    return tenant, client_id, secret


async def _graph_token(client: _Client, config: dict[str, Any], credentials: dict[str, Any]) -> dict[str, str]:
    tenant, client_id, secret = _entra_creds(config, credentials)
    resp = await client.request(
        "POST", f"{MS_LOGIN_ROOT}/{tenant}/oauth2/v2.0/token", {"Accept": "application/json"},
        data={
            "grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
            "scope": "https://graph.microsoft.com/.default",
        },
    )
    if resp.status_code != 200:
        raise _http_error(resp, "Entra ID token")
    token = (resp.json() or {}).get("access_token")
    if not token:
        raise DirectoryError("Entra ID token: no access_token in response")
    return {"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"}


def _graph_next(body: dict[str, Any]) -> Optional[str]:
    nxt = body.get("@odata.nextLink")
    if nxt and urlsplit(str(nxt)).hostname == "graph.microsoft.com":
        return str(nxt)
    return None


async def _graph_registration(client: _Client, headers: dict[str, str], summary: dict[str, Any]) -> Optional[dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, Any]] = {}
    url: Optional[str] = f"{GRAPH_ROOT}/reports/authenticationMethods/userRegistrationDetails?$top={GRAPH_PAGE_SIZE}"
    while url and len(out) < MAX_SYNC_USERS:
        resp = await client.request("GET", url, headers)
        if resp.status_code in (401, 403):
            summary["warnings"].append(
                f"Entra ID registration details unavailable (HTTP {resp.status_code}; needs AuditLog.Read.All): "
                "MFA and admin flags unchanged",
            )
            return None
        if resp.status_code != 200:
            raise _http_error(resp, "Entra ID registration details")
        body = resp.json() or {}
        for item in body.get("value") or []:
            if isinstance(item, dict) and item.get("id"):
                out[str(item["id"])] = item
        url = _graph_next(body)
    return out


async def _sync_entra(db: AsyncSession, org_id: str, integration: InstalledIntegration, summary: dict[str, Any]) -> None:
    config, credentials = _secrets(integration)
    select_fields = "id,userPrincipalName,mail,displayName,accountEnabled,lastPasswordChangeDateTime"
    async with _Client(config, pin_to_base=False) as client:
        headers = await _graph_token(client, config, credentials)
        registration = await _graph_registration(client, headers, summary)
        url: Optional[str] = f"{GRAPH_ROOT}/users?$select={select_fields},signInActivity&$top={GRAPH_PAGE_SIZE}"
        retried = False
        while url:
            resp = await client.request("GET", url, headers)
            if resp.status_code == 403 and not retried and "signInActivity" in url:
                retried = True
                summary["warnings"].append("Entra ID signInActivity unavailable (HTTP 403); last sign-in not synced")
                url = f"{GRAPH_ROOT}/users?$select={select_fields}&$top={GRAPH_PAGE_SIZE}"
                continue
            if resp.status_code != 200:
                raise _http_error(resp, "Entra ID list users")
            body = resp.json() or {}
            page = [u for u in body.get("value") or [] if isinstance(u, dict)]
            if summary["fetched"] + len(page) > MAX_SYNC_USERS:
                page = page[:MAX_SYNC_USERS - summary["fetched"]]
                summary["capped"] = True
                url = None
            else:
                url = _graph_next(body)
            records: list[DirectoryUser] = []
            for user in page:
                upn = str(user.get("userPrincipalName") or "").strip()
                email = str(user.get("mail") or upn).strip()
                uid = str(user.get("id") or "")
                if not uid or not upn or not _EMAIL_RE.match(email):
                    summary["skipped"] += 1
                    continue
                reg = registration.get(uid) if registration is not None else None
                enabled = user.get("accountEnabled")
                records.append(DirectoryUser(
                    user_id=uid, username=upn, email=email, display_name=user.get("displayName"),
                    identity_provider=IdentityProvider.AZURE_AD.value,
                    account_status=None if enabled is None else ("enabled" if enabled else "disabled"),
                    mfa_enabled=bool(reg.get("isMfaRegistered")) if reg is not None else None,
                    mfa_methods=[str(m) for m in reg.get("methodsRegistered") or []] if reg is not None else None,
                    is_admin=bool(reg.get("isAdmin")) if reg is not None else None,
                    role_assignments=(["entra_admin"] if reg.get("isAdmin") else None) if reg is not None else None,
                    last_authentication=_safe_iso((user.get("signInActivity") or {}).get("lastSignInDateTime")),
                    last_password_change=_safe_iso(user.get("lastPasswordChangeDateTime")),
                ))
                if reg is None:
                    summary["mfa_unchecked"] += 1
            counts = await upsert_identities(db, org_id, records, source="azure_ad", integration_id=integration.id)
            summary["created"] += counts["created"]
            summary["updated"] += counts["updated"]
            summary["fetched"] += len(page)


async def _entra_action(integration: InstalledIntegration, identity: IdentityProfile, action: str) -> dict[str, Any]:
    config, credentials = _secrets(integration)
    ref = identity.user_id if identity.source_integration_id == integration.id else (identity.username or identity.email)
    user_url = f"{GRAPH_ROOT}/users/{quote(str(ref), safe='@')}"
    calls: list[tuple[str, str, Optional[dict[str, Any]]]] = {
        "disable_account": [("PATCH", user_url, {"accountEnabled": False}), ("POST", f"{user_url}/revokeSignInSessions", None)],
        "enable_account": [("PATCH", user_url, {"accountEnabled": True})],
        "force_password_reset": [
            ("PATCH", user_url, {"passwordProfile": {"forceChangePasswordNextSignIn": True}}),
            ("POST", f"{user_url}/revokeSignInSessions", None),
        ],
        "revoke_sessions": [("POST", f"{user_url}/revokeSignInSessions", None)],
    }[action]
    steps = []
    async with _Client(config, pin_to_base=False) as client:
        headers = await _graph_token(client, config, credentials)
        for method, url, body in calls:
            kwargs: dict[str, Any] = {"content": json.dumps(body)} if body is not None else {}
            resp = await client.request(method, url, headers, **kwargs)
            steps.append({"call": f"{method} {urlsplit(url).path}", "http_status": resp.status_code})
            if resp.status_code not in (200, 202, 204):
                raise _http_error(resp, f"Entra ID {action}")
    return {"steps": steps, "account_status": {"disable_account": "disabled", "enable_account": "enabled"}.get(action)}


# ---------------------------------------------------------------------------
# Sync entry point
# ---------------------------------------------------------------------------


async def sync_integration(db: AsyncSession, org_id: str, integration: InstalledIntegration) -> dict[str, Any]:
    """Sync one installed Okta / Entra ID integration into ``IdentityProfile`` rows.

    Flushes; the caller commits on success and rolls back on error. Raises
    ``DirectoryError`` / ``OutboundTargetRefused`` with a credential-free message.
    """
    if integration.organization_id != org_id:
        raise ValueError("integration belongs to another organization")
    name = connector_name(integration)
    summary: dict[str, Any] = {
        "integration_id": integration.id, "provider": name, "fetched": 0, "created": 0, "updated": 0,
        "skipped": 0, "mfa_unchecked": 0, "capped": False, "warnings": [],
    }
    if name == "okta":
        await _sync_okta(db, org_id, integration, summary)
    elif name == "azure_ad":
        await _sync_entra(db, org_id, integration, summary)
    else:
        raise DirectoryError(f"connector {name!r} has no directory sync")
    return summary


# ---------------------------------------------------------------------------
# Response actions against the identity provider
# ---------------------------------------------------------------------------


async def provider_for_identity(db: AsyncSession, org_id: str, identity: IdentityProfile) -> Optional[InstalledIntegration]:
    """The active integration that can act on ``identity``, if any.

    The integration the identity was synced from wins; otherwise an installed
    integration whose connector matches the identity's ``identity_provider``
    (the account is then addressed by username / email).
    """
    integrations = await identity_integrations(db, org_id)
    if identity.source_integration_id:
        for integ in integrations:
            if integ.id == identity.source_integration_id:
                return integ
    for integ in integrations:
        if connector_name(integ) == (identity.identity_provider or "").lower():
            return integ
    return None


def awaiting_integration_detail(identity: IdentityProfile) -> str:
    provider = identity.identity_provider or "unknown"
    if provider == IdentityProvider.ACTIVE_DIRECTORY.value:
        return (
            "PySOAR has no Active Directory (LDAP) connector: act on the account in AD, or install an "
            "Okta / Entra ID integration if the account lives there"
        )
    return f"an active Okta or Entra ID integration for this {provider} identity"


async def run_identity_action(
    db: AsyncSession,
    org_id: str,
    identity: IdentityProfile,
    action: str,
    *,
    actor_user_id: Optional[str],
    reason: str,
) -> dict[str, Any]:
    """Carry out ``action`` on the identity's provider, or say honestly why not.

    ``actor_user_id`` must be the admin who asked (unattended callers are
    refused with ``PermissionError``).

    Statuses: ``executed`` (every provider call succeeded), ``failed`` (a call
    failed or was refused; ``error`` says why), ``awaiting_integration`` (no
    installed integration can act on this identity; ``missing_dependency``
    names it). Writes one ``AuditLog`` row either way.
    """
    if action not in IDP_ACTIONS:
        raise ValueError(f"unsupported identity action {action!r}")
    if not actor_user_id:
        # Only an interactive admin (POST /itdr/identities/{id}/actions/{action})
        # may act on a directory account; background tasks and automation never do.
        raise PermissionError("identity_provider_action_requires_human_actor")
    integration = await provider_for_identity(db, org_id, identity)
    result: dict[str, Any] = {
        "action": action, "identity_id": identity.id, "username": identity.username,
        "provider": None, "integration_id": None, "status": "awaiting_integration",
        "detail": "", "missing_dependency": None, "error": None, "steps": [],
    }
    if integration is None:
        result["missing_dependency"] = awaiting_integration_detail(identity)
        result["detail"] = f"No identity-provider integration can {action.replace('_', ' ')} for {identity.username}; nothing was changed."
    else:
        name = connector_name(integration)
        result.update(provider=name, integration_id=integration.id)
        try:
            done = await (_okta_action if name == "okta" else _entra_action)(integration, identity, action)
            result["steps"] = done["steps"]
            result["status"] = "executed"
            result["detail"] = f"{name} {action} for {identity.username}: done"
            if done.get("account_status"):
                identity.account_status = done["account_status"]
        except (DirectoryError, OutboundTargetRefused) as exc:
            result["status"] = "failed"
            result["error"] = str(exc)[:500]
            result["detail"] = f"{name} {action} for {identity.username} failed"
    db.add(AuditLog(
        user_id=actor_user_id,
        organization_id=org_id,
        action=f"itdr_identity_{action}",
        resource_type="identity_profile",
        resource_id=identity.id,
        description=f"{action} {identity.username}: {result['status']}. {reason}"[:4000],
        new_value=json.dumps(result, default=str),
        success=result["status"] == "executed",
        error_message=result["error"],
    ))
    await db.flush()
    logger.info(
        "itdr_identity_action", organization_id=org_id, identity_id=identity.id, action=action,
        status=result["status"], provider=result["provider"],
    )
    return result


# ---------------------------------------------------------------------------
# CSV import (Active Directory exports and any other directory)
# ---------------------------------------------------------------------------

#: Accepted header names (case-insensitive, spaces / underscores ignored) per field.
CSV_ALIASES: dict[str, tuple[str, ...]] = {
    "username": ("username", "samaccountname", "login", "userprincipalname", "upn"),
    "email": ("email", "mail", "emailaddress", "userprincipalname", "upn"),
    "user_id": ("userid", "id", "objectguid", "objectsid", "employeeid"),
    "display_name": ("displayname", "name", "fullname"),
    "identity_provider": ("identityprovider", "provider", "source"),
    "privilege_level": ("privilegelevel", "privilege"),
    "mfa_enabled": ("mfaenabled", "mfa"),
    "mfa_methods": ("mfamethods",),
    "group_memberships": ("groups", "groupmemberships", "memberof"),
    "role_assignments": ("roles", "roleassignments"),
    "is_service_account": ("isserviceaccount", "serviceaccount"),
    "account_status": ("accountstatus", "status"),
    "enabled": ("enabled", "accountenabled"),
    "last_authentication": ("lastauthentication", "lastlogon", "lastlogondate", "lastlogin", "lastlogontimestamp"),
    "last_password_change": ("lastpasswordchange", "passwordlastset", "pwdlastset"),
}
_TRUE = {"true", "yes", "y", "1", "enabled"}
_FALSE = {"false", "no", "n", "0", "disabled", ""}


def _norm_header(name: str) -> str:
    return re.sub(r"[\s_\-]", "", (name or "").strip().lower())


def _bool(value: str, column: str) -> bool:
    v = (value or "").strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ValueError(f"{column}: expected true/false, got {value!r}")


def _list(value: str) -> list[str]:
    return [p.strip() for p in re.split(r"[;|]", value or "") if p.strip()]


@dataclass
class CsvParseResult:
    records: list[DirectoryUser]
    errors: list[dict[str, Any]]
    rows_read: int
    columns: dict[str, str]
    error_count: int = 0


def parse_identity_csv(content: bytes) -> CsvParseResult:
    """Validate an identity CSV export. Raises ValueError for a file-level problem."""
    if len(content) > CSV_MAX_BYTES:
        raise ValueError(f"file is larger than {CSV_MAX_BYTES // (1024 * 1024)} MB")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("file is not UTF-8 text") from exc
    reader = csv.DictReader(io.StringIO(text))
    headers = reader.fieldnames or []
    if not headers:
        raise ValueError("file has no header row")
    normalised = {_norm_header(h): h for h in headers if h}
    columns: dict[str, str] = {}
    for fld, aliases in CSV_ALIASES.items():
        for alias in aliases:
            if alias in normalised:
                columns[fld] = normalised[alias]
                break
    missing = [f for f in ("username", "email") if f not in columns]
    if missing:
        raise ValueError(
            f"missing required column(s): {', '.join(missing)} "
            f"(accepted names: {', '.join(CSV_ALIASES['username'])} / {', '.join(CSV_ALIASES['email'])})",
        )
    providers = {p.value for p in IdentityProvider}
    levels = {p.value for p in PrivilegeLevel}
    records: list[DirectoryUser] = []
    errors: list[dict[str, Any]] = []
    error_count = 0
    seen: set[str] = set()
    rows = 0
    for line_no, row in enumerate(reader, start=2):
        rows += 1
        if rows > CSV_MAX_ROWS:
            raise ValueError(f"file has more than {CSV_MAX_ROWS} rows")

        def get(fld: str, _row: dict = row) -> str:
            col = columns.get(fld)
            return str(_row.get(col) or "").strip() if col else ""

        try:
            username = get("username")
            email = get("email")
            if not username:
                raise ValueError("username is empty")
            if len(username) > 255:
                raise ValueError("username is longer than 255 characters")
            if not _EMAIL_RE.match(email) or len(email) > 255:
                raise ValueError(f"email {email!r} is not an email address")
            key = username.lower()
            if key in seen:
                raise ValueError(f"duplicate username {username!r} in file")
            provider = (get("identity_provider") or IdentityProvider.ACTIVE_DIRECTORY.value).lower()
            if provider not in providers:
                raise ValueError(f"identity_provider must be one of {sorted(providers)}")
            level = get("privilege_level").lower() or None
            if level is not None and level not in levels:
                raise ValueError(f"privilege_level must be one of {sorted(levels)}")
            status = get("account_status") or None
            if status is None and get("enabled"):
                status = "enabled" if _bool(get("enabled"), "enabled") else "disabled"
            groups = _list(get("group_memberships")) if columns.get("group_memberships") else None
            roles = _list(get("role_assignments")) if columns.get("role_assignments") else None
            rec = DirectoryUser(
                user_id=(get("user_id") or username)[:255],
                username=username,
                email=email,
                display_name=get("display_name") or None,
                identity_provider=provider,
                account_status=status,
                mfa_enabled=_bool(get("mfa_enabled"), "mfa_enabled") if columns.get("mfa_enabled") else None,
                mfa_methods=_list(get("mfa_methods")) if columns.get("mfa_methods") else None,
                privilege_level=level,
                role_assignments=roles,
                group_memberships=groups,
                is_service_account=(
                    _bool(get("is_service_account"), "is_service_account") if columns.get("is_service_account") else None
                ),
                last_authentication=_iso(get("last_authentication")) if get("last_authentication") else None,
                last_password_change=_iso(get("last_password_change")) if get("last_password_change") else None,
            )
            if rec.privilege_level is None and (roles is not None or groups is not None):
                # An admin role or group (e.g. AD "Domain Admins") marks the account admin.
                if any("admin" in r.lower() for r in (roles or []) + (groups or [])):
                    rec.privilege_level = PrivilegeLevel.ADMIN.value
            seen.add(key)
            records.append(rec)
        except ValueError as exc:
            error_count += 1
            if len(errors) < CSV_MAX_ERRORS_REPORTED:
                errors.append({"line": line_no, "error": str(exc)})
    return CsvParseResult(records=records, errors=errors, rows_read=rows, columns=columns, error_count=error_count)
