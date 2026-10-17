"""SCIM 2.0 provisioning (RFC 7643 / RFC 7644) for one organisation per token.

An identity provider (Okta, Microsoft Entra ID...) calls ``/api/v1/scim/v2``
with a bearer token an organisation admin issued (``SCIMToken``; only its
SHA-256 is stored). The token is the whole authority: it selects the
organisation and nothing else; the platform superuser is never visible or
editable through SCIM, and ids from another organisation answer 404.

Users. A SCIM User is a PySOAR ``User`` of the token's organisation:
``userName`` is the sign-in email (it must be an email address), ``name`` /
``displayName`` share the single ``full_name`` column (``name.givenName`` /
``name.familyName`` are read back by splitting ``full_name`` at the first
space: the schema has no separate columns), ``externalId`` is
``User.external_id``, ``phoneNumbers`` the single ``phone`` column, the
enterprise extension's ``department`` is ``department``. Attributes PySOAR
does not store are accepted and dropped; the audit row lists them
(``ignored_attributes``). Provisioned users get ``identity_source = scim`` and
a password nobody holds: they sign in through the organisation's SSO. A
``password`` attribute is ignored (``changePassword`` is unsupported).
Deactivation (``active: false`` or ``DELETE``) sets ``is_active = false`` and
revokes every token of the user (``TokenBlacklist.revoke_all_user_tokens``);
nothing is ever hard-deleted.

Local accounts. An account with ``identity_source = local`` is managed in
PySOAR: SCIM can read it and update its profile (name, externalId, phone,
department), but changing its ``userName``, its ``active`` state, deleting it
or setting its role through a group answers 403 ``mutability`` (role changes
are skipped). ``POST /Users`` with the email of any existing account answers
409 ``uniqueness``: a SCIM token never takes an account over. A full admin
converts a local account explicitly (``POST /settings/scim/users/{id}/link``,
audited ``scim_user_linked``; ``DELETE`` on the same path returns it to local
management); the IdP then finds it with a ``userName`` filter and manages it in
full. A sign-in email change on a
managed account must be in the SSO configuration's ``allowed_email_domains``
when that list is set, clears ``sso_subject`` and any password reset token,
and revokes the user's tokens.

Groups. There is no groups table (migration 037 has none): a SCIM Group is a
role mapping keyed by its ``displayName``. Group records (id, displayName,
externalId, member ids) are kept as JSON in ``Organization.settings`` under the
``scim_groups`` key (read-modify-write under a row lock, see
``load_group_store``). The role a group grants is
``SSOConfiguration.group_role_map[displayName]`` when the organisation has an
SSO configuration holding that key, else the record's own ``role`` (set by an
admin through ``PUT /settings/scim/groups/{id}``). Membership changes in a
mapped group recompute the member's role from every mapped group they belong
to (``admin`` > ``analyst`` > custom role > ``viewer``; ties by displayName);
a member left in no mapped group falls back to the organisation's default
role (the SSO configuration's ``default_role``, else ``viewer``). Custom roles
are assigned only through ``src.identity.roles.apply_custom_role`` after
``assignment_error`` (which floors the built-in role to ``viewer``).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.identity import roles as identity_roles
from src.identity.models import BUILTIN_ROLE_TIERS, Role, SCIMToken, SSOConfiguration
from src.models.organization import Organization
from src.models.user import User

logger = get_logger(__name__)

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

MEDIA_TYPE = "application/scim+json"
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 100
TOKEN_PREFIX = "scim_"
#: ``last_used_at`` is written at most once per this interval per token.
LAST_USED_RESOLUTION = timedelta(minutes=1)
#: Key of the group store inside ``Organization.settings`` (JSON text).
SETTINGS_KEY = "scim_groups"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FILTER_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_.:]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.IGNORECASE)
_VALUE_FILTER_PATH_RE = re.compile(
    r'^\s*([A-Za-z]+)\[\s*([A-Za-z]+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\](?:\.([A-Za-z]+))?\s*$', re.IGNORECASE,
)

#: Filter attributes each resource supports (lower case) -> internal key.
USER_FILTERS: dict[str, str] = {"username": "email", "emails.value": "email", "externalid": "external_id", "id": "id"}
GROUP_FILTERS: dict[str, str] = {"displayname": "displayName", "externalid": "externalId", "id": "id"}

_BUILTIN_RANK: dict[str, int] = {"admin": 3, "analyst": 2, "viewer": 0}
_CUSTOM_RANK = 1


class SCIMError(Exception):
    """An error answered with a SCIM error body (RFC 7644 section 3.12)."""

    def __init__(self, status: int, detail: str, scim_type: Optional[str] = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schemas": [SCHEMA_ERROR], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            out["scimType"] = self.scim_type
        return out


def not_found(kind: str = "resource") -> SCIMError:
    return SCIMError(404, f"{kind} not found")


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def display_prefix(token: str) -> str:
    return token[:12]


def aware(value: Optional[datetime]) -> Optional[datetime]:
    """SQLite hands back naive datetimes from tz-aware columns; treat them as UTC."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def token_status(token: SCIMToken, now: Optional[datetime] = None) -> str:
    now = now or utcnow()
    if token.revoked_at is not None:
        return "revoked"
    expires = aware(token.expires_at)
    if expires is not None and expires <= now:
        return "expired"
    return "active"


def iso(value: Optional[datetime]) -> Optional[str]:
    value = aware(value)
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


# ---------------------------------------------------------------------------
# Filters, paging, projection
# ---------------------------------------------------------------------------


def _unquote(raw: str) -> str:
    try:
        return json.loads(f'"{raw}"')
    except ValueError as exc:
        raise SCIMError(400, "filter value is not a valid string", "invalidFilter") from exc


def parse_filter(expression: Optional[str], supported: dict[str, str]) -> Optional[tuple[str, str]]:
    """``attr eq "value"`` -> (internal key, value); ``None`` for no filter.

    Only single ``eq`` comparisons on the supported attributes are accepted;
    anything else is 400 ``invalidFilter`` (never silently ignored, which
    would hand the IdP an unfiltered list it may treat as a match).
    """
    if expression is None or not expression.strip():
        return None
    match = _FILTER_RE.match(expression)
    if not match:
        raise SCIMError(
            400,
            "unsupported filter: only `<attribute> eq \"<value>\"` is supported, on "
            + ", ".join(sorted(supported)),
            "invalidFilter",
        )
    attr = match.group(1).lower()
    for prefix in (SCHEMA_USER.lower() + ":", SCHEMA_GROUP.lower() + ":"):
        if attr.startswith(prefix):
            attr = attr[len(prefix):]
    if attr not in supported:
        raise SCIMError(400, f"filtering on {match.group(1)!r} is not supported", "invalidFilter")
    return supported[attr], _unquote(match.group(2))


def page_bounds(start_index: Optional[int], count: Optional[int]) -> tuple[int, int]:
    """(1-based start, page size) per RFC 7644 3.4.2.4 (start < 1 means 1; count capped)."""
    start = start_index if start_index is not None and start_index >= 1 else 1
    size = DEFAULT_PAGE_SIZE if count is None else max(0, min(int(count), MAX_PAGE_SIZE))
    return start, size


def list_response(resources: list[dict[str, Any]], total: int, start: int) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_LIST],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


_ALWAYS_RETURNED = {"schemas", "id", "meta"}


def project(resource: dict[str, Any], attributes: Optional[str], excluded: Optional[str]) -> dict[str, Any]:
    """Apply ``attributes`` / ``excludedAttributes`` at top-level granularity
    (``name.givenName`` selects ``name``)."""

    def names(raw: Optional[str]) -> set[str]:
        out: set[str] = set()
        for part in (raw or "").split(","):
            part = part.strip()
            if not part:
                continue
            low = part.lower()
            for prefix in (SCHEMA_USER.lower() + ":", SCHEMA_GROUP.lower() + ":"):
                if low.startswith(prefix):
                    low = low[len(prefix):]
            out.add(low.split(".", 1)[0] if not low.startswith("urn:") else low)
        return out

    wanted = names(attributes)
    dropped = names(excluded)
    if not wanted and not dropped:
        return resource
    out: dict[str, Any] = {}
    for key, value in resource.items():
        low = key.lower()
        if key in _ALWAYS_RETURNED:
            out[key] = value
        elif wanted and low not in wanted:
            continue
        elif low in dropped:
            continue
        else:
            out[key] = value
    return out


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def split_name(full_name: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """(givenName, familyName) read back from the single ``full_name`` column."""
    if not full_name or not full_name.strip():
        return None, None
    parts = full_name.strip().split(" ", 1)
    return parts[0], (parts[1].strip() if len(parts) > 1 and parts[1].strip() else None)


def user_resource(user: User, base_url: str, groups: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
    given, family = split_name(user.full_name)
    name: dict[str, Any] = {}
    if user.full_name:
        name["formatted"] = user.full_name
    if given:
        name["givenName"] = given
    if family:
        name["familyName"] = family
    resource: dict[str, Any] = {
        "schemas": [SCHEMA_USER, SCHEMA_ENTERPRISE] if user.department else [SCHEMA_USER],
        "id": str(user.id),
        "userName": user.email,
        "active": bool(user.is_active),
        "emails": [{"value": user.email, "type": "work", "primary": True}],
        "groups": [
            {"value": g["id"], "display": g["displayName"], "$ref": f"{base_url}/Groups/{g['id']}"}
            for g in (groups or [])
        ],
        "meta": {
            "resourceType": "User",
            "created": iso(user.created_at),
            "lastModified": iso(user.updated_at or user.created_at),
            "location": f"{base_url}/Users/{user.id}",
        },
    }
    if user.external_id:
        resource["externalId"] = user.external_id
    if name:
        resource["name"] = name
    if user.full_name:
        resource["displayName"] = user.full_name
    if user.phone:
        resource["phoneNumbers"] = [{"value": user.phone, "type": "work"}]
    if user.department:
        resource[SCHEMA_ENTERPRISE] = {"department": user.department}
    return resource


def _as_bool(value: Any) -> bool:
    """SCIM booleans; Entra ID has sent ``"True"`` / ``"False"`` strings."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise SCIMError(400, f"{value!r} is not a boolean", "invalidValue")


def _as_str(value: Any, attr: str, max_len: int = 255) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        raise SCIMError(400, f"{attr} must be a string", "invalidValue")
    value = value.strip()
    if len(value) > max_len:
        raise SCIMError(400, f"{attr} is longer than {max_len} characters", "invalidValue")
    return value or None


def normalise_email(value: Any) -> str:
    email = _as_str(value, "userName")
    if not email or not _EMAIL_RE.match(email):
        raise SCIMError(400, "userName must be the user's email address (PySOAR signs users in by email)", "invalidValue")
    return email.lower()


def _pick_multi(values: Any, preferred: tuple[str, ...]) -> Optional[str]:
    """The value of a multi-valued attribute: primary, else a preferred type, else the first."""
    if isinstance(values, dict):
        values = [values]
    if not isinstance(values, list):
        return None
    items = [v for v in values if isinstance(v, dict) and v.get("value") not in (None, "")]
    if not items:
        return None
    for item in items:
        if item.get("primary") in (True, "true", "True"):
            return str(item["value"])
    for kind in preferred:
        for item in items:
            if str(item.get("type", "")).lower() == kind:
                return str(item["value"])
    return str(items[0]["value"])


class UserState:
    """The SCIM-writable view of a user, mutated by PUT / PATCH and written back."""

    FIELDS = ("email", "given", "family", "formatted", "display", "external_id", "active", "phone", "department")

    def __init__(self, user: Optional[User] = None) -> None:
        given, family = split_name(user.full_name if user else None)
        self.values: dict[str, Any] = {
            "email": user.email if user else None,
            "given": given,
            "family": family,
            "formatted": user.full_name if user else None,
            "display": user.full_name if user else None,
            "external_id": user.external_id if user else None,
            "active": bool(user.is_active) if user else True,
            "phone": user.phone if user else None,
            "department": user.department if user else None,
        }
        self.touched: set[str] = set()
        self.ignored: list[str] = []
        #: ``emails`` values that differ from ``userName`` (not stored: userName is the sign-in email).
        self.email_mismatch: list[str] = []

    def set(self, key: str, value: Any) -> None:
        self.values[key] = value
        self.touched.add(key)

    def full_name(self) -> Optional[str]:
        v = self.values
        if "display" in self.touched and v["display"]:
            return v["display"]
        if "formatted" in self.touched and v["formatted"]:
            return v["formatted"]
        if self.touched & {"given", "family"}:
            joined = " ".join(p for p in (v["given"], v["family"]) if p)
            return joined or None
        if self.touched & {"display", "formatted"}:
            return v["display"] or v["formatted"] or None
        return v["formatted"]

    def changes(self) -> dict[str, Any]:
        """Final values of the touched fields (with ``full_name`` folded)."""
        out: dict[str, Any] = {}
        for key in ("email", "external_id", "active", "phone", "department"):
            if key in self.touched:
                out[key] = self.values[key]
        if self.touched & {"given", "family", "formatted", "display"}:
            out["full_name"] = self.full_name()
        return out

    # -- attribute paths -------------------------------------------------

    def apply(self, path: str, value: Any, *, remove: bool = False) -> None:
        """Set (or with ``remove`` clear) one attribute path."""
        raw = path.strip()
        low = raw.lower()
        for prefix in (SCHEMA_USER.lower() + ":",):
            if low.startswith(prefix):
                low = low[len(prefix):]
                raw = raw[len(prefix):]
        ent = SCHEMA_ENTERPRISE.lower()
        if low == ent:
            if remove:
                self.set("department", None)
                return
            if isinstance(value, dict):
                for key, sub in value.items():
                    self.apply(f"{SCHEMA_ENTERPRISE}:{key}", sub)
                return
            raise SCIMError(400, "the enterprise extension value must be an object", "invalidValue")
        if low.startswith(ent + ":"):
            sub = low[len(ent) + 1:]
            if sub == "department":
                self.set("department", None if remove else _as_str(value, "department", 100))
            else:
                self.ignored.append(f"{SCHEMA_ENTERPRISE}:{raw[len(SCHEMA_ENTERPRISE) + 1:]}")
            return
        if low == "active":
            if remove:
                raise SCIMError(400, "active cannot be removed", "mutability")
            self.set("active", _as_bool(value))
        elif low == "username":
            if remove:
                raise SCIMError(400, "userName is required and cannot be removed", "mutability")
            self.set("email", normalise_email(value))
        elif low == "externalid":
            self.set("external_id", None if remove else _as_str(value, "externalId"))
        elif low == "displayname":
            self.set("display", None if remove else _as_str(value, "displayName"))
        elif low == "name":
            if remove:
                for key in ("given", "family", "formatted"):
                    self.set(key, None)
                return
            if not isinstance(value, dict):
                raise SCIMError(400, "name must be an object", "invalidValue")
            for key, sub in value.items():
                self.apply(f"name.{key}", sub)
        elif low in ("name.givenname", "name.familyname", "name.formatted"):
            key = {"name.givenname": "given", "name.familyname": "family", "name.formatted": "formatted"}[low]
            self.set(key, None if remove else _as_str(value, raw))
        elif low == "emails":
            if remove:
                return  # the sign-in email cannot be removed; nothing else is stored
            self._email_value(_pick_multi(value, ("work",)))
        elif low == "phonenumbers":
            self.set("phone", None if remove else _clip(_pick_multi(value, ("work", "mobile")), 50))
        else:
            vf = _VALUE_FILTER_PATH_RE.match(raw)
            if vf and vf.group(1).lower() in ("emails", "phonenumbers") and vf.group(2).lower() == "type" and (
                vf.group(4) is None or vf.group(4).lower() == "value"
            ):
                attr = vf.group(1).lower()
                if isinstance(value, list):
                    value = _pick_multi(value, (vf.group(3).lower(),))
                elif isinstance(value, dict):
                    value = value.get("value")
                if attr == "emails":
                    if not remove:
                        self._email_value(_as_str(value, raw))
                else:
                    self.set("phone", None if remove else _clip(_as_str(value, raw), 50))
            else:
                self.ignored.append(raw)

    def _email_value(self, value: Optional[str]) -> None:
        if not value:
            return
        email = value.strip().lower()
        current = self.values["email"]
        if current is None:
            # No userName yet (POST without one): the work email is the sign-in email.
            self.set("email", normalise_email(email))
        elif email != current:
            self.email_mismatch.append(email)

    def load_resource(self, body: dict[str, Any]) -> None:
        """Replace from a full User resource (POST / PUT)."""
        for key in ("given", "family", "formatted", "display", "external_id", "phone", "department"):
            self.set(key, None)
        handled = {"schemas", "id", "meta", "password", "groups"}
        if "userName" in body or "username" in {k.lower() for k in body}:
            name_key = next(k for k in body if k.lower() == "username")
            self.apply("userName", body[name_key])
        for key, value in body.items():
            low = key.lower()
            if low in handled or low == "username":
                continue
            self.apply(key, value)
        if "active" not in self.touched:
            self.set("active", True)
        if self.values["email"] is None:
            raise SCIMError(400, "userName is required", "invalidValue")


def _clip(value: Optional[str], n: int) -> Optional[str]:
    return value[:n] if value else value


def normalise_external_id(value: Any) -> Optional[str]:
    return _as_str(value, "externalId")


_MEMBER_VALUE_PATH_RE = re.compile(r'^\s*members\[\s*value\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\]\s*$', re.IGNORECASE)


def member_value_path(path: str) -> Optional[str]:
    """The user id of a ``members[value eq "<id>"]`` path (Okta / Entra member removal), else None."""
    match = _MEMBER_VALUE_PATH_RE.match(path or "")
    return _unquote(match.group(1)) if match else None


def apply_patch(state: UserState, body: Any) -> None:
    """Apply a PatchOp body (RFC 7644 3.5.2) to ``state``."""
    ops = operations(body)
    for op_name, path, value in ops:
        remove = op_name == "remove"
        if path:
            state.apply(path, value, remove=remove)
        elif remove:
            raise SCIMError(400, "remove needs a path", "noTarget")
        elif isinstance(value, dict):
            for key, sub in value.items():
                state.apply(key, sub)
        else:
            raise SCIMError(400, "an operation without a path needs an object value", "invalidValue")


def operations(body: Any) -> list[tuple[str, Optional[str], Any]]:
    """Validated ``(op, path, value)`` triples of a PatchOp body."""
    if not isinstance(body, dict):
        raise SCIMError(400, "PATCH body must be a PatchOp object", "invalidSyntax")
    ops = body.get("Operations", body.get("operations"))
    if not isinstance(ops, list) or not ops:
        raise SCIMError(400, "PATCH body needs a non-empty Operations list", "invalidSyntax")
    out: list[tuple[str, Optional[str], Any]] = []
    for op in ops:
        if not isinstance(op, dict):
            raise SCIMError(400, "each operation must be an object", "invalidSyntax")
        name = str(op.get("op", "")).strip().lower()
        if name not in ("add", "replace", "remove"):
            raise SCIMError(400, f"unsupported op {op.get('op')!r} (add, replace, remove)", "invalidSyntax")
        path = op.get("path")
        if path is not None and not isinstance(path, str):
            raise SCIMError(400, "path must be a string", "invalidPath")
        out.append((name, path.strip() if isinstance(path, str) and path.strip() else None, op.get("value")))
    return out


# ---------------------------------------------------------------------------
# Group store (Organization.settings["scim_groups"])
# ---------------------------------------------------------------------------


def _settings_dict(org: Organization) -> dict[str, Any]:
    raw = org.settings
    if raw is None or not str(raw).strip():
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise SCIMError(500, "the organisation's settings are not valid JSON; refusing to overwrite them") from exc
    if not isinstance(parsed, dict):
        raise SCIMError(500, "the organisation's settings are not a JSON object; refusing to overwrite them")
    return parsed


class GroupStore:
    """The organisation's SCIM groups: ``{group_id: {displayName, externalId,
    members, role, created, lastModified}}``. ``save`` writes them back into
    ``Organization.settings`` (other keys preserved)."""

    def __init__(self, org: Organization) -> None:
        self.org = org
        self._settings = _settings_dict(org)
        groups = self._settings.get(SETTINGS_KEY) or {}
        self.groups: dict[str, dict[str, Any]] = groups if isinstance(groups, dict) else {}

    def save(self) -> None:
        self._settings[SETTINGS_KEY] = self.groups
        self.org.settings = json.dumps(self._settings, sort_keys=True)

    def by_name(self, display_name: str, exclude: Optional[str] = None) -> Optional[str]:
        low = display_name.strip().lower()
        for gid, g in self.groups.items():
            if gid != exclude and str(g.get("displayName", "")).strip().lower() == low:
                return gid
        return None

    def groups_of(self, user_id: str) -> list[dict[str, Any]]:
        return sorted(
            ({"id": gid, **g} for gid, g in self.groups.items() if user_id in (g.get("members") or [])),
            key=lambda g: str(g.get("displayName", "")).lower(),
        )

    def new_group(self, display_name: str, external_id: Optional[str]) -> str:
        gid = str(uuid.uuid4())
        stamp = iso(utcnow())
        self.groups[gid] = {
            "displayName": display_name, "externalId": external_id, "members": [], "role": None,
            "created": stamp, "lastModified": stamp,
        }
        return gid

    def touch(self, gid: str) -> None:
        self.groups[gid]["lastModified"] = iso(utcnow())


async def load_group_store(db: AsyncSession, org_id: str, *, for_update: bool = False) -> GroupStore:
    """The organisation's group store; ``for_update`` takes a row lock on the
    organisation (Postgres ``SELECT ... FOR UPDATE``; SQLite serialises writers
    itself) so concurrent PATCHes from the IdP cannot lose each other's members."""
    stmt = select(Organization).where(Organization.id == org_id)
    if for_update:
        stmt = stmt.with_for_update()
        org = (await db.execute(stmt.execution_options(populate_existing=True))).scalar_one_or_none()
    else:
        org = (await db.execute(stmt)).scalar_one_or_none()
    if org is None:
        raise SCIMError(401, "the token's organisation no longer exists")
    return GroupStore(org)


def group_resource(gid: str, group: dict[str, Any], base_url: str, members: list[User]) -> dict[str, Any]:
    resource: dict[str, Any] = {
        "schemas": [SCHEMA_GROUP],
        "id": gid,
        "displayName": group.get("displayName"),
        "members": [
            {"value": str(u.id), "display": u.email, "type": "User", "$ref": f"{base_url}/Users/{u.id}"}
            for u in members
        ],
        "meta": {
            "resourceType": "Group",
            "created": group.get("created"),
            "lastModified": group.get("lastModified") or group.get("created"),
            "location": f"{base_url}/Groups/{gid}",
        },
    }
    if group.get("externalId"):
        resource["externalId"] = group["externalId"]
    return resource


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------


async def sso_configuration(db: AsyncSession, org_id: str) -> Optional[SSOConfiguration]:
    return (
        await db.execute(select(SSOConfiguration).where(SSOConfiguration.organization_id == org_id))
    ).scalar_one_or_none()


def mapping_of(group: dict[str, Any], config: Optional[SSOConfiguration]) -> tuple[Optional[str], Optional[str]]:
    """(role value, source) a group maps to (see the module docstring)."""
    name = str(group.get("displayName") or "")
    role_map = dict(config.group_role_map or {}) if config is not None else {}
    if name in role_map and str(role_map[name]).strip():
        return str(role_map[name]).strip(), "sso_group_role_map"
    if group.get("role"):
        return str(group["role"]), "scim_groups"
    return None, None


async def resolve_role(db: AsyncSession, org_id: str, value: Optional[str]) -> Optional[tuple[str, Optional[Role]]]:
    """``(built-in role, None)`` or ``("viewer", custom Role)`` for a mapped
    value (built-in name, or a custom role of ``org_id`` by id or name); ``None``
    when it names nothing."""
    value = (value or "").strip()
    if not value:
        return None
    if value in BUILTIN_ROLE_TIERS:
        return value, None
    role = (
        await db.execute(select(Role).where(Role.organization_id == org_id, (Role.id == value) | (Role.name == value)))
    ).scalars().first()
    return ("viewer", role) if role is not None else None


async def default_role(db: AsyncSession, org_id: str, config: Optional[SSOConfiguration]) -> tuple[str, Optional[Role]]:
    """The role a provisioned user starts with: the SSO configuration's
    ``default_role`` when it resolves, else ``viewer``."""
    if config is not None:
        resolved = await resolve_role(db, org_id, config.default_role)
        if resolved is not None:
            return resolved
        logger.warning("scim_default_role_unresolved", organization_id=org_id, value=config.default_role)
    return "viewer", None


def role_snapshot(user: User) -> dict[str, Any]:
    return {"role": user.role, "custom_role_id": user.custom_role_id}


def assign_role(user: User, target: tuple[str, Optional[Role]], org_id: str) -> Optional[dict[str, str]]:
    """Give ``user`` a resolved role; returns the refusal from ``assignment_error`` (or None)."""
    builtin, role = target
    if user.is_superuser:
        return {"error": "superuser_not_managed", "detail": "platform superusers are not managed through SCIM"}
    if role is None:
        if user.custom_role_id:
            identity_roles.apply_custom_role(user, None)
        user.role = builtin
        return None
    err = identity_roles.assignment_error(user, role, org_id)
    if err is not None:
        return err
    identity_roles.apply_custom_role(user, role)
    return None


async def mapped_target(
    db: AsyncSession, org_id: str, group: dict[str, Any], config: Optional[SSOConfiguration],
) -> Optional[tuple[str, Optional[Role]]]:
    value, _source = mapping_of(group, config)
    if value is None:
        return None
    resolved = await resolve_role(db, org_id, value)
    if resolved is None:
        logger.warning("scim_group_mapping_unresolved", organization_id=org_id,
                       group=group.get("displayName"), value=value)
    return resolved


async def recompute_role(
    db: AsyncSession, org_id: str, user: User, store: GroupStore, config: Optional[SSOConfiguration],
) -> Optional[dict[str, Any]]:
    """Set ``user``'s role from the mapped groups they belong to (default role
    when none). Returns ``{"from", "to"}`` when the role changed, else None.

    Only identity-provider-managed accounts (``identity_source`` scim / oidc)
    take roles from SCIM groups: a local account (an administrator's included)
    can be listed as a member but its role is managed in PySOAR, so a
    provisioning token cannot demote or promote it."""
    if user.is_superuser or (user.identity_source or "local") not in ("scim", "oidc", "saml"):
        return None
    best: Optional[tuple[int, str, tuple[str, Optional[Role]]]] = None
    for group in store.groups_of(str(user.id)):
        target = await mapped_target(db, org_id, group, config)
        if target is None:
            continue
        rank = _BUILTIN_RANK[target[0]] if target[1] is None else _CUSTOM_RANK
        name = str(group.get("displayName", "")).lower()
        if best is None or rank > best[0] or (rank == best[0] and name < best[1]):
            best = (rank, name, target)
    target = best[2] if best is not None else await default_role(db, org_id, config)
    before = role_snapshot(user)
    err = assign_role(user, target, org_id)
    if err is not None:
        logger.warning("scim_role_assignment_refused", organization_id=org_id, user_id=str(user.id), **err)
        return None
    after = role_snapshot(user)
    return {"from": before, "to": after} if after != before else None


# ---------------------------------------------------------------------------
# Discovery documents
# ---------------------------------------------------------------------------


def _attr(name: str, type_: str = "string", *, multi: bool = False, required: bool = False,
          mutability: str = "readWrite", returned: str = "default", uniqueness: str = "none",
          case_exact: bool = False, sub: Optional[list[dict[str, Any]]] = None, description: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": name, "type": type_, "multiValued": multi, "description": description, "required": required,
        "mutability": mutability, "returned": returned, "uniqueness": uniqueness,
    }
    if type_ in ("string", "reference"):
        out["caseExact"] = case_exact
    if sub is not None:
        out["subAttributes"] = sub
    return out


def schema_documents(base_url: str) -> list[dict[str, Any]]:
    """The schemas this service provider implements: only the attributes it stores."""
    user_attrs = [
        _attr("userName", required=True, uniqueness="server",
              description="The user's sign-in email address (unique across PySOAR)."),
        _attr("name", "complex", sub=[
            _attr("formatted", description="Full name (stored)."),
            _attr("givenName", description="Read back as the first word of the full name."),
            _attr("familyName", description="Read back as the rest of the full name."),
        ], description="Stored as a single full name."),
        _attr("displayName", description="Same stored value as name.formatted."),
        _attr("active", "boolean", description="false deactivates the user and revokes their tokens."),
        _attr("emails", "complex", multi=True, sub=[
            _attr("value"), _attr("type"), _attr("primary", "boolean"),
        ], description="Returned as the sign-in email; a different value is not stored."),
        _attr("phoneNumbers", "complex", multi=True, sub=[_attr("value"), _attr("type")],
              description="One phone number is stored."),
        _attr("groups", "complex", multi=True, mutability="readOnly", sub=[
            _attr("value", mutability="readOnly"), _attr("display", mutability="readOnly"),
            _attr("$ref", "reference", mutability="readOnly"),
        ], description="SCIM groups the user belongs to (managed through /Groups)."),
    ]
    group_attrs = [
        _attr("displayName", required=True, uniqueness="server",
              description="Group name; the key of the group's role mapping."),
        _attr("members", "complex", multi=True, sub=[
            _attr("value", mutability="immutable"), _attr("display", mutability="readOnly"),
            _attr("type", mutability="immutable"), _attr("$ref", "reference", mutability="immutable"),
        ], description="Users of the organisation; membership in a mapped group sets the member's role."),
    ]
    enterprise_attrs = [_attr("department")]
    docs = [
        (SCHEMA_USER, "User", "User Account", user_attrs),
        (SCHEMA_GROUP, "Group", "Group (a role mapping)", group_attrs),
        (SCHEMA_ENTERPRISE, "EnterpriseUser", "Enterprise User (department only)", enterprise_attrs),
    ]
    return [
        {
            "schemas": [SCHEMA_SCHEMA],
            "id": sid, "name": name, "description": desc, "attributes": attrs,
            "meta": {"resourceType": "Schema", "location": f"{base_url}/Schemas/{sid}"},
        }
        for sid, name, desc, attrs in docs
    ]


def resource_type_documents(base_url: str) -> list[dict[str, Any]]:
    return [
        {
            "schemas": [SCHEMA_RESOURCE_TYPE],
            "id": "User", "name": "User", "endpoint": "/Users", "description": "User Account",
            "schema": SCHEMA_USER,
            "schemaExtensions": [{"schema": SCHEMA_ENTERPRISE, "required": False}],
            "meta": {"resourceType": "ResourceType", "location": f"{base_url}/ResourceTypes/User"},
        },
        {
            "schemas": [SCHEMA_RESOURCE_TYPE],
            "id": "Group", "name": "Group", "endpoint": "/Groups", "description": "Group (a role mapping)",
            "schema": SCHEMA_GROUP,
            "meta": {"resourceType": "ResourceType", "location": f"{base_url}/ResourceTypes/Group"},
        },
    ]


def service_provider_config(base_url: str) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_SPC],
        "documentationUri": None,
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_PAGE_SIZE},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "A SCIM token issued under Settings > Identity (POST /api/v1/settings/scim/tokens).",
                "primary": True,
            }
        ],
        "meta": {"resourceType": "ServiceProviderConfig", "location": f"{base_url}/ServiceProviderConfig"},
    }
