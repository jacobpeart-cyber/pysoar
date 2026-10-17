"""Custom roles: per-area access tiers.

An *area* is the first path segment after the API prefix (``/api/v1/alerts/...``
is ``alerts``). Each request is judged at one of four tiers
(``none < read < write < admin``, see ``src.identity.models``):

* ``require_role([ADMIN])`` needs tier ``admin`` in the request's area;
  ``require_role([ADMIN, ANALYST])`` needs ``write`` (in general: the lowest
  built-in tier among the allowed roles).
* Every authenticated request refuses tier ``none`` with 403 ``area_denied``,
  except in the areas listed in ``EXEMPT_AREAS`` and on self routes (below).

Effective tier: platform superuser = ``admin`` everywhere; a user holding a
custom role (``User.custom_role_id``) gets the role's override for the area,
else its ``default_tier``; anyone else gets the built-in mapping of
``User.role`` (viewer = read, analyst = write, admin = admin). Users without a
custom role are therefore judged exactly as before: ``src.api.deps`` only runs
the tier logic for custom-role holders.

Built-in role floor. Assigning a custom role sets the built-in ``role`` to
``viewer`` (``apply_custom_role``), so any check that still reads ``User.role``
/ ``User.is_admin`` treats the holder as a viewer (fail closed), while every
dependency gate (``require_role``, ``AdminUser``, ``get_current_superuser``)
uses the custom role's tiers. SSO JIT and SCIM provisioning must assign custom
roles through ``apply_custom_role`` too.

Handler checks. Admin-only branches inside handlers (containment steps in
playbooks, note / comment / attachment deletion by non-authors, bulk alert
delete, admin-permission API keys, legal-hold release, team visibility, the
agent role ladder...) ask ``has_tier(user, "<area>", "<tier>")`` instead of
``User.role``, so a custom role's tiers decide them exactly like the
dependency gates; for users without a custom role ``has_tier`` is the built-in
mapping, so their behaviour is unchanged. Background code (Celery playbook
runs) has no request cache and uses ``user_has_tier``, which loads the role
from the database.

The checks that deliberately stay on the built-in role are the *full admin*
ones (``is_full_admin``: a built-in admin without a custom role, or the
platform superuser): SSO trust settings, SCIM tokens and links.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from src.core.config import settings
from src.identity.models import BUILTIN_ROLE_TIERS, TIER_ORDER, Role, Tier

#: Areas never denied by tier (``area_denied``), with the reason. They are not
#: tenant data: they are the caller's own credentials, probes or documentation.
#: Role gates inside them (``require_role``) still apply.
EXEMPT_AREAS: dict[str, str] = {
    "auth": "sign-in, token refresh, logout, the caller's own profile and password",
    "mfa": "the caller's own second factor",
    "api-keys": "the caller's own API keys (admin-wide listing keeps its own admin check)",
    "health": "liveness and readiness probes; no tenant data",
    "": "API root document",
    "docs": "API documentation",
    "redoc": "API documentation",
    "openapi.json": "API schema document",
}

#: Self routes inside a gated area: ``users/{caller's own id}`` (read and edit
#: your own profile) is never denied by tier.
SELF_ROUTE_AREAS: frozenset[str] = frozenset({"users"})

#: Human labels for known areas; unknown areas are shown as the raw segment.
AREA_LABELS: dict[str, str] = {
    "agentic": "Agentic SOC",
    "agents": "Endpoint agents",
    "ai": "AI / ML engine",
    "alerts": "Alerts",
    "api-keys": "API keys",
    "api-security": "API security",
    "assets": "Assets",
    "attack": "MITRE ATT&CK",
    "audit": "Audit log",
    "audit-evidence": "Audit evidence",
    "auth": "Authentication",
    "backup": "Backup and restore",
    "collaboration": "Collaboration / war rooms",
    "compliance": "Compliance",
    "container-security": "Container security",
    "darkweb": "Dark web monitoring",
    "data-lake": "Data lake",
    "deception": "Deception",
    "dfir": "DFIR / forensics",
    "dlp": "Data loss prevention",
    "exposure": "Exposure management",
    "fedramp": "FedRAMP",
    "health": "Health probes",
    "hunting": "Threat hunting",
    "incidents": "Incidents",
    "integrations": "Integrations",
    "iocs": "Indicators (IOCs)",
    "itdr": "Identity threat detection",
    "metrics": "Metrics and dashboards",
    "mfa": "Multi-factor authentication",
    "monitoring": "Monitoring",
    "organizations": "Organizations",
    "ot_security": "OT / ICS security",
    "phishing_sim": "Phishing simulation",
    "playbook-builder": "Playbook builder",
    "playbooks": "Playbooks",
    "privacy": "Privacy engineering",
    "remediation": "Remediation",
    "reports": "Reports",
    "risk-quantification": "Risk quantification",
    "roles": "Roles",
    "scim": "SCIM provisioning",
    "settings": "Settings",
    "siem": "SIEM",
    "simulation": "Attack simulation",
    "stig": "STIG / SCAP",
    "supplychain": "Supply chain",
    "teams": "Teams",
    "threat-intel": "Threat intelligence",
    "threat-modeling": "Threat modeling",
    "tickethub": "TicketHub",
    "ueba": "UEBA",
    "users": "Users",
    "vulnmgmt": "Vulnerability management",
    "ws": "Live updates (WebSocket)",
    "zerotrust": "Zero trust",
}

#: Areas left out of the catalogue: documentation, not something a role grants.
_HIDDEN_AREAS: frozenset[str] = frozenset({"", "docs", "redoc", "openapi.json"})

#: Attribute ``src.api.deps`` sets on gate dependencies (``require_role``'s
#: checker, ``get_current_admin_user``...) naming the tier they require; the
#: catalogue reads it to count each area's write- and admin-gated routes.
REQUIRED_TIER_ATTR = "pysoar_required_tier"

#: Attribute ``src.api.deps.get_current_user`` sets on a custom-role holder's
#: ``User`` instance for the duration of the request (the loaded ``Role``, or
#: ``None`` when it could not be loaded, which denies everything).
CUSTOM_ROLE_ATTR = "_pysoar_custom_role"


def area_of_path(path: str) -> Optional[str]:
    """The area of an request path, or ``None`` outside the API prefix."""
    prefix = settings.api_v1_prefix.rstrip("/")
    if path == prefix:
        return ""
    if not path.startswith(prefix + "/"):
        return None
    return path[len(prefix) + 1:].split("/", 1)[0]


#: Fixed self paths inside a gated area, never denied by tier: ``GET
#: /roles/me`` (what the caller's own role grants) must answer even for a role
#: with ``none`` over ``roles``.
SELF_PATHS: frozenset[tuple[str, str]] = frozenset({("roles", "me")})


def is_self_route(path: str, user_id: str) -> bool:
    """``/api/v1/users/<caller's own id>`` and ``/api/v1/roles/me`` (and nothing under them)."""
    area = area_of_path(path)
    if not area:
        return False
    rest = path[len(settings.api_v1_prefix.rstrip("/")) + 1 + len(area):].strip("/")
    if (area, rest) in SELF_PATHS:
        return True
    if area not in SELF_ROUTE_AREAS:
        return False
    return rest == str(user_id)


def tier_at_least(tier: str, required: str) -> bool:
    return TIER_ORDER.get(tier, 0) >= TIER_ORDER.get(required, TIER_ORDER[Tier.ADMIN.value])


def required_tier_for_roles(allowed_roles: Iterable[Any]) -> str:
    """The tier a ``require_role([...])`` gate needs: the lowest built-in tier
    among the allowed roles (``[ADMIN]`` -> admin, ``[ADMIN, ANALYST]`` -> write)."""
    tiers = [
        BUILTIN_ROLE_TIERS.get(getattr(r, "value", r), Tier.ADMIN.value) for r in allowed_roles
    ]
    if not tiers:
        return Tier.ADMIN.value
    return min(tiers, key=lambda t: TIER_ORDER[t])


def has_custom_role(user: Any) -> bool:
    return bool(getattr(user, "custom_role_id", None)) and not getattr(user, "is_superuser", False)


def effective_tier(user: Any, area: Optional[str], role: Optional[Role] = None) -> str:
    """The tier ``user`` holds in ``area`` (see the module docstring).

    ``role`` is the user's loaded custom role; when omitted it is taken from
    the request cache ``src.api.deps.get_current_user`` fills. A custom-role
    holder whose role could not be loaded (deleted, other organisation) holds
    ``none`` everywhere.
    """
    if getattr(user, "is_superuser", False):
        return Tier.ADMIN.value
    if getattr(user, "custom_role_id", None):
        if role is None:
            role = getattr(user, CUSTOM_ROLE_ATTR, None)
        if role is None or str(role.id) != str(user.custom_role_id) or (
            str(role.organization_id) != str(getattr(user, "organization_id", "") or "")
        ):
            return Tier.NONE.value
        return role.tier_for(area) if area is not None else (
            role.default_tier if role.default_tier in TIER_ORDER else Tier.NONE.value
        )
    return BUILTIN_ROLE_TIERS.get(getattr(user, "role", ""), Tier.NONE.value)


def has_tier(user: Any, area: Optional[str], required: str, role: Optional[Role] = None) -> bool:
    """Whether ``user`` holds at least ``required`` in ``area``. For users
    without a custom role this is the built-in mapping, so ``has_tier(u,
    "users", "admin")`` equals ``u.is_admin`` for them. ``role`` as in
    ``effective_tier`` (request handlers omit it)."""
    return tier_at_least(effective_tier(user, area, role), required)


def has_tier_everywhere(user: Any, required: str, role: Optional[Role] = None) -> bool:
    """Whether ``user`` holds at least ``required`` in every area (for grants
    not confined to one area, such as a ``*`` API-key permission). Built-in
    users: their one tier; a custom role: its default tier and every override;
    a custom role that cannot be loaded: nothing."""
    if getattr(user, "is_superuser", False):
        return True
    if not getattr(user, "custom_role_id", None):
        return has_tier(user, None, required)
    if role is None:
        role = getattr(user, CUSTOM_ROLE_ATTR, None)
    if role is None or str(role.id) != str(user.custom_role_id) or (
        str(role.organization_id) != str(getattr(user, "organization_id", "") or "")
    ):
        return False
    tiers = [role.default_tier, *(role.area_tiers or {}).values()]
    return all(tier_at_least(t if t in TIER_ORDER else Tier.NONE.value, required) for t in tiers)


#: The built-in role whose tier equals a tier (``none`` maps to the viewer
#: floor; callers that need more than read refuse it anyway).
_TIER_TO_BUILTIN: dict[str, str] = {
    Tier.ADMIN.value: "admin", Tier.WRITE.value: "analyst", Tier.READ.value: "viewer", Tier.NONE.value: "viewer",
}


def builtin_equivalent(user: Any, area: Optional[str], role: Optional[Role] = None) -> str:
    """The built-in role name (``admin`` / ``analyst`` / ``viewer``) matching
    the tier ``user`` holds in ``area``, for code that keeps a role ladder (the
    agent context, the role recorded on a playbook run). For users without a
    custom role it is their own role (superusers: ``admin``; an unknown role
    value: ``viewer``)."""
    return _TIER_TO_BUILTIN[effective_tier(user, area, role)]


def is_full_admin(user: Any) -> bool:
    """A built-in admin without a custom role, or the platform superuser."""
    return bool(getattr(user, "is_superuser", False)) or (
        getattr(user, "role", None) == "admin" and not getattr(user, "custom_role_id", None)
    )


def tiers_over(user: Any, areas: Iterable[str], role: Optional[Role] = None) -> dict[str, str]:
    """``{area: effective tier}`` for each of ``areas``."""
    return {area: effective_tier(user, area, role) for area in areas}


def exempt_area_names() -> list[str]:
    """The exempt areas a client can see (documentation paths left out)."""
    return sorted(a for a in EXEMPT_AREAS if a not in _HIDDEN_AREAS)


async def load_custom_role(db: Any, user: Any) -> Optional[Role]:
    """Load ``user``'s custom role outside a request (no ``get_current_user``
    cache): ``None`` when the user has none, or when it is missing or belongs
    to another organisation (``effective_tier`` then grants ``none``)."""
    if not getattr(user, "custom_role_id", None):
        return None
    role = await db.get(Role, str(user.custom_role_id))
    if role is None or str(role.organization_id) != str(getattr(user, "organization_id", "") or ""):
        return None
    return role


async def user_has_tier(db: Any, user_id: Optional[str], org_id: str, area: str, required: str) -> bool:
    """Background-code form of ``has_tier``: whether the *active* user
    ``user_id`` of ``org_id`` holds ``required`` in ``area`` right now (role and
    custom role read from the database). False for an unknown, inactive or
    other-organisation user."""
    if not user_id:
        return False
    from sqlalchemy import select

    from src.models.user import User

    user = (await db.execute(
        select(User).where(User.id == user_id, User.organization_id == org_id),
    )).scalar_one_or_none()
    if user is None or not user.is_active:
        return False
    role = await load_custom_role(db, user) if has_custom_role(user) else None
    return has_tier(user, area, required, role)


def area_denied_detail(area: str) -> dict[str, str]:
    return {
        "error": "area_denied",
        "area": area,
        "detail": f"your role grants no access to {AREA_LABELS.get(area, area) or 'this area'}",
    }


def insufficient_tier_detail(area: Optional[str], required: str, held: str) -> dict[str, Any]:
    return {
        "error": "insufficient_tier",
        "area": area,
        "required": required,
        "tier": held,
        "detail": f"this action needs {required} access to "
        f"{AREA_LABELS.get(area or '', area or 'this area') or 'this area'}; your role grants {held}",
    }


def apply_custom_role(user: Any, role: Optional[Role]) -> None:
    """Assign (or with ``None`` clear) a custom role on ``user``.

    Assigning sets the built-in ``role`` to ``viewer`` (the floor described in
    the module docstring). Clearing leaves ``role`` as it is (``viewer`` after
    a custom role) for the caller to set. Callers validate the organisation
    and the superuser rule first (``assignment_error``).
    """
    if role is None:
        user.custom_role_id = None
        return
    user.custom_role_id = str(role.id)
    user.role = "viewer"


def assignment_error(user: Any, role: Role, org_id: str) -> Optional[dict[str, str]]:
    """Why ``role`` cannot be assigned to ``user`` in ``org_id`` (or ``None``)."""
    if getattr(user, "is_superuser", False):
        return {
            "error": "superuser_custom_role",
            "detail": "a platform superuser cannot hold a custom role",
        }
    if str(role.organization_id) != str(org_id):
        return {"error": "role_not_found", "detail": "custom role not found in this organisation"}
    return None


def escalation_areas(caller: Any, default_tier: str, area_tiers: dict[str, str], areas: Iterable[str]) -> list[str]:
    """Areas where a role (``default_tier`` + ``area_tiers`` over ``areas``)
    would grant more than ``caller`` holds. Empty for built-in admins and
    superusers; a custom-role holder with admin over ``roles`` / ``users`` can
    never mint or assign a role broader than their own."""
    over: list[str] = []
    for area in sorted(set(areas) | set(area_tiers)):
        granted = area_tiers.get(area, default_tier)
        if not tier_at_least(effective_tier(caller, area), granted):
            over.append(area)
    return over


# ---------------------------------------------------------------------------
# Area catalogue
# ---------------------------------------------------------------------------

_CATALOGUE_CACHE: dict[int, list[dict[str, Any]]] = {}


def _walk_routes(routes: Iterable[Any], prefix: str = "") -> Iterable[tuple[str, Any]]:
    """(full path, route) for every HTTP route, including routers FastAPI keeps
    lazy (``_IncludedRouter``) and mounted sub-routers."""
    for r in routes:
        ctx = getattr(r, "include_context", None)
        original = getattr(r, "original_router", None)
        if ctx is not None and original is not None:
            yield from _walk_routes(original.routes, prefix + (getattr(ctx, "prefix", "") or ""))
            continue
        sub = getattr(r, "routes", None)
        methods = getattr(r, "methods", None)
        if sub is not None and not methods:
            yield from _walk_routes(sub, prefix + getattr(r, "path", ""))
            continue
        path = getattr(r, "path", None)
        if path and methods:
            yield prefix + path, r


def _route_gate(route: Any) -> str:
    """The strongest tier gate among a route's dependencies (``read`` when the
    route has none: any authenticated member)."""
    best = Tier.READ.value
    stack = list(getattr(getattr(route, "dependant", None), "dependencies", []) or [])
    seen = 0
    while stack and seen < 500:
        seen += 1
        dep = stack.pop()
        tier = getattr(getattr(dep, "call", None), REQUIRED_TIER_ATTR, None)
        if tier in TIER_ORDER and TIER_ORDER[tier] > TIER_ORDER[best]:
            best = tier
        stack.extend(getattr(dep, "dependencies", []) or [])
    return best


def area_catalogue(app: Any) -> list[dict[str, Any]]:
    """Every area the app serves, derived from ``app.routes`` (cached per app).

    Each entry: ``area``, ``label``, ``routes`` (HTTP route count),
    ``write_routes`` / ``admin_routes`` (routes gated at that tier),
    ``exempt`` with ``exempt_reason`` (never denied by tier), and
    ``builtin_tiers`` (what viewer / analyst / admin hold there).
    """
    key = id(app)
    cached = _CATALOGUE_CACHE.get(key)
    if cached is not None:
        return cached
    counts: dict[str, dict[str, int]] = {}
    for path, route in _walk_routes(getattr(app, "routes", [])):
        area = area_of_path(path)
        if area is None or area in _HIDDEN_AREAS:
            continue
        gate = _route_gate(route)
        n_methods = len([m for m in route.methods if m not in ("HEAD", "OPTIONS")]) or 1
        entry = counts.setdefault(area, {"routes": 0, "write": 0, "admin": 0})
        entry["routes"] += n_methods
        if gate == Tier.WRITE.value:
            entry["write"] += n_methods
        elif gate == Tier.ADMIN.value:
            entry["admin"] += n_methods
    catalogue = [
        {
            "area": area,
            "label": AREA_LABELS.get(area, area),
            "routes": c["routes"],
            "write_routes": c["write"],
            "admin_routes": c["admin"],
            "exempt": area in EXEMPT_AREAS,
            "exempt_reason": EXEMPT_AREAS.get(area),
            "builtin_tiers": dict(BUILTIN_ROLE_TIERS),
        }
        for area, c in sorted(counts.items())
    ]
    _CATALOGUE_CACHE[key] = catalogue
    return catalogue


def known_areas(app: Any) -> set[str]:
    return {entry["area"] for entry in area_catalogue(app)}
