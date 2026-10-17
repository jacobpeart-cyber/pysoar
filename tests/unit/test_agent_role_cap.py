"""The agent role ladder's ADMIN rung needs admin everywhere: agent tools act
across areas, so a custom role with admin only over ``agentic`` is capped at
ANALYST (privileged tools then need an administrator's approval)."""
from __future__ import annotations

from types import SimpleNamespace

from src.api.v1.endpoints.agentic import _agent_role
from src.identity.models import Role
from src.identity.roles import CUSTOM_ROLE_ATTR
from src.models.user import UserRole


def _holder(role: Role) -> SimpleNamespace:
    user = SimpleNamespace(role="viewer", custom_role_id=role.id, organization_id=role.organization_id, is_superuser=False)
    setattr(user, CUSTOM_ROLE_ATTR, role)
    return user


def test_builtin_roles_map_as_before() -> None:
    assert _agent_role(SimpleNamespace(role="admin", custom_role_id=None, is_superuser=False)) == UserRole.ADMIN
    assert _agent_role(SimpleNamespace(role="analyst", custom_role_id=None, is_superuser=False)) == UserRole.ANALYST
    assert _agent_role(SimpleNamespace(role="viewer", custom_role_id=None, is_superuser=False)) == UserRole.VIEWER
    assert _agent_role(SimpleNamespace(role="viewer", custom_role_id=None, is_superuser=True)) == UserRole.ADMIN


def test_admin_only_over_agentic_is_capped_at_analyst() -> None:
    local_admin = Role(id="r1", organization_id="o1", name="SOC operator", default_tier="read", area_tiers={"agentic": "admin"})
    assert _agent_role(_holder(local_admin), "agentic") == UserRole.ANALYST
    assert _agent_role(_holder(local_admin), "users") == UserRole.VIEWER


def test_admin_everywhere_keeps_the_admin_rung() -> None:
    everywhere = Role(id="r2", organization_id="o1", name="Deputy", default_tier="admin", area_tiers={})
    assert _agent_role(_holder(everywhere), "agentic") == UserRole.ADMIN
    writer = Role(id="r3", organization_id="o1", name="Responder", default_tier="write", area_tiers={})
    assert _agent_role(_holder(writer), "agentic") == UserRole.ANALYST
