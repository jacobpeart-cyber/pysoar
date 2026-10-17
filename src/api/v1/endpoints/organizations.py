"""Organization and Team management endpoints"""

from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import (
    CurrentUser,
    DatabaseSession,
    PlatformSuperUser,
    require_role,
    resolve_organization_scope,
)
from src.core.logging import get_logger
from src.identity import roles as identity_roles
from src.models.organization import (
    Organization,
    OrganizationMember,
    OrganizationRole,
    Team,
    TeamMember,
    TeamRole,
)
from src.models.user import User, UserRole

logger = get_logger(__name__)

router = APIRouter()

#: Organisation configuration (PATCH, membership): tenant admin (of that
#: organisation, checked by ``_get_organization``) or platform superuser.
OrgAdminUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]
#: Team writes (create, update, delete, membership): analyst or admin of the
#: team's organisation. Viewers read only.
TeamWriter = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]

#: Roles a tenant admin may grant through organisation membership. ``owner``
#: is reserved for the organisation's creator.
_ASSIGNABLE_MEMBER_ROLES: frozenset[str] = frozenset(
    {OrganizationRole.ADMIN.value, OrganizationRole.MEMBER.value, OrganizationRole.VIEWER.value},
)


# Schemas
class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    description: Optional[str] = None
    plan: str = Field(default="free")


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    plan: Optional[str] = None
    is_active: Optional[bool] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    plan: str = "free"
    max_users: int = 10
    is_active: bool = True
    member_count: int = 0
    created_at: Optional[Any] = None

    class Config:
        from_attributes = True


class MemberResponse(BaseModel):
    id: str
    user_id: str
    role: str
    is_primary: bool
    user: dict

    class Config:
        from_attributes = True


class AddMemberRequest(BaseModel):
    # Accept either user_id OR email. Frontend typically sends email.
    user_id: Optional[str] = None
    email: Optional[str] = None
    role: str = Field(default="member")


class TeamCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    organization_id: Optional[str] = None
    is_default: bool = False


class TeamUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None


class TeamResponse(BaseModel):
    id: str = ""
    name: str = ""
    description: Optional[str] = None
    organization_id: str = ""
    is_default: bool = False
    member_count: int = 0
    created_at: Optional[Any] = None

    class Config:
        from_attributes = True


# Organization endpoints
@router.get("/organizations", response_model=list[OrganizationResponse])
async def list_organizations(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
):
    """List organizations visible to the caller.

    Listing every organisation is a platform-superuser action. Everyone else,
    tenant admins included, sees only their own organisation
    (``users.organization_id``); an org-less non-superuser gets 403
    ``organization_required``. ``OrganizationMember`` rows grant no
    visibility into other tenants.
    """
    if current_user.is_superuser:
        query = select(Organization)
    else:
        own_org = resolve_organization_scope(current_user, None)
        query = select(Organization).where(Organization.id == own_org)

    query = query.offset(skip).limit(limit).order_by(Organization.created_at.desc())
    result = await db.execute(query)
    organizations = result.scalars().all()

    # Get member counts
    response = []
    for org in organizations:
        count_result = await db.execute(
            select(func.count(OrganizationMember.id)).where(
                OrganizationMember.organization_id == org.id,
            ),
        )
        member_count = count_result.scalar() or 0
        response.append({
            **_format_organization(org),
            "member_count": member_count,
        })

    return response


@router.post("/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    data: OrganizationCreate,
    db: DatabaseSession = None,
    current_user: PlatformSuperUser = None,
):
    """Create a new organization (platform superuser only).

    Creating a tenant is a platform-level action: tenant admins (and every
    other tenant role) get 403 ``platform_superuser_required``.
    """
    # Check if slug is unique
    existing = await db.execute(
        select(Organization).where(Organization.slug == data.slug),
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization with this slug already exists",
        )

    # Create organization
    org = Organization(
        name=data.name,
        slug=data.slug,
        description=data.description,
        plan=data.plan,
    )
    db.add(org)
    await db.flush()

    # Add creator as owner
    member = OrganizationMember(
        organization_id=org.id,
        user_id=current_user.id,
        role=OrganizationRole.OWNER.value,
        is_primary=True,
    )
    db.add(member)

    await db.commit()
    await db.refresh(org)

    logger.info("organization_created", organization_id=org.id, actor_id=current_user.id)
    return {**_format_organization(org), "member_count": 1}


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get an organization by ID: the caller's own (any role), or any for a
    platform superuser. Another tenant's organisation is reported as missing."""
    org = await _get_organization(org_id, current_user, db)

    count_result = await db.execute(
        select(func.count(OrganizationMember.id)).where(
            OrganizationMember.organization_id == org.id,
        ),
    )
    member_count = count_result.scalar() or 0

    return {**_format_organization(org), "member_count": member_count}


@router.patch("/organizations/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: str,
    data: OrganizationUpdate,
    db: DatabaseSession = None,
    current_user: OrgAdminUser = None,
):
    """Update an organization: a tenant admin may update only their own
    organisation's name and description; ``plan`` and ``is_active`` are
    platform-superuser only."""
    org = await _get_organization(org_id, current_user, db, require_admin=True)

    if (data.plan is not None or data.is_active is not None) and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "platform_superuser_required",
                "detail": "plan and is_active are managed by platform superusers",
            },
        )

    if data.name is not None:
        org.name = data.name
    if data.description is not None:
        org.description = data.description
    if data.plan is not None:
        org.plan = data.plan
    if data.is_active is not None:
        org.is_active = data.is_active

    await db.commit()
    await db.refresh(org)

    return _format_organization(org)


@router.delete("/organizations/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: str,
    db: DatabaseSession = None,
    admin_user: PlatformSuperUser = None,
):
    """Delete an organization (platform superuser only)"""
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    await db.delete(org)
    await db.commit()
    logger.info("organization_deleted", organization_id=org_id, actor_id=admin_user.id)


# Organization members
@router.get("/organizations/{org_id}/members", response_model=list[MemberResponse])
async def list_organization_members(
    org_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """List members of an organization"""
    await _get_organization(org_id, current_user, db)

    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(OrganizationMember.organization_id == org_id),
    )
    members = result.scalars().all()

    return [
        {
            "id": m.id,
            "user_id": m.user_id,
            "role": m.role,
            "is_primary": m.is_primary,
            "user": {
                "id": m.user.id,
                "email": m.user.email,
                "full_name": m.user.full_name,
            },
        }
        for m in members
    ]


@router.post("/organizations/{org_id}/members", status_code=status.HTTP_201_CREATED)
async def add_organization_member(
    org_id: str,
    data: AddMemberRequest,
    db: DatabaseSession = None,
    current_user: OrgAdminUser = None,
):
    """Add a member to an organization.

    Admin of that organisation (or a platform superuser) only. The user must
    already belong to the organisation (``users.organization_id``): lookups by
    id or email never see other tenants' users, so this is neither an
    enumeration oracle nor a way to attach a foreign user. ``owner`` cannot be
    granted.
    """
    await _get_organization(org_id, current_user, db, require_admin=True)

    if data.role not in _ASSIGNABLE_MEMBER_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"role must be one of {sorted(_ASSIGNABLE_MEMBER_ROLES)}",
        )

    if not data.user_id and not data.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either user_id or email must be provided",
        )

    user_query = select(User).where(User.organization_id == org_id)
    if data.user_id:
        user_query = user_query.where(User.id == data.user_id)
    else:
        user_query = user_query.where(User.email == (data.email or "").lower().strip())
    user_row = (await db.execute(user_query)).scalar_one_or_none()
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in this organization",
        )
    target_user_id = user_row.id

    # Check if already a member
    existing = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == target_user_id,
        ),
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a member",
        )

    member = OrganizationMember(
        organization_id=org_id,
        user_id=target_user_id,
        role=data.role,
    )
    db.add(member)
    await db.commit()

    logger.info(
        "organization_member_added",
        organization_id=org_id,
        user_id=target_user_id,
        role=data.role,
        actor_id=current_user.id,
    )
    return {"status": "success", "message": "Member added", "user_id": target_user_id}


@router.delete("/organizations/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_organization_member(
    org_id: str,
    user_id: str,
    db: DatabaseSession = None,
    current_user: OrgAdminUser = None,
):
    """Remove a member from an organization (admin of that organisation or a
    platform superuser)."""
    await _get_organization(org_id, current_user, db, require_admin=True)

    result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user_id,
        ),
    )
    member = result.scalar_one_or_none()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    # Can't remove the owner
    if member.role == OrganizationRole.OWNER.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove organization owner",
        )

    await db.delete(member)
    await db.commit()


# Team endpoints
@router.get("/teams", response_model=list[TeamResponse])
async def list_teams(
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
    organization_id: Optional[str] = None,
):
    """List teams in the caller's organization.

    Only platform superusers may list another organization's teams (by
    passing ``organization_id``); everyone else is scoped to their own
    (403 ``organization_mismatch`` for another, ``organization_required``
    without one).
    """
    scope_org = resolve_organization_scope(current_user, organization_id)
    query = select(Team).where(Team.organization_id == scope_org)

    if not identity_roles.has_tier(current_user, "teams", "admin"):
        # Get teams the user is a member of
        member_subquery = select(TeamMember.team_id).where(
            TeamMember.user_id == current_user.id,
        )
        query = query.where(Team.id.in_(member_subquery))

    result = await db.execute(query.order_by(Team.created_at.desc()))
    teams = result.scalars().all()

    response = []
    for team in teams:
        count_result = await db.execute(
            select(func.count(TeamMember.id)).where(TeamMember.team_id == team.id),
        )
        member_count = count_result.scalar() or 0
        response.append({
            **_format_team(team),
            "member_count": member_count,
        })

    return response


@router.post("/teams", response_model=TeamResponse, status_code=status.HTTP_201_CREATED)
async def create_team(
    data: TeamCreate,
    db: DatabaseSession = None,
    current_user: TeamWriter = None,
):
    """Create a team in the caller's organisation (analyst or admin).

    ``organization_id`` defaults to the caller's own; a different one is
    refused (403 ``organization_mismatch``) unless the caller is a platform
    superuser naming an existing organisation.
    """
    team_org = resolve_organization_scope(current_user, data.organization_id)
    await _get_organization(team_org, current_user, db)

    team = Team(
        name=data.name,
        description=data.description,
        organization_id=team_org,
        is_default=data.is_default,
    )
    db.add(team)
    await db.flush()

    # Add creator as lead
    member = TeamMember(
        team_id=team.id,
        user_id=current_user.id,
        role=TeamRole.LEAD.value,
    )
    db.add(member)

    await db.commit()
    await db.refresh(team)

    return {**_format_team(team), "member_count": 1}


@router.get("/teams/{team_id}", response_model=TeamResponse)
async def get_team(
    team_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get a team by ID"""
    team = await _get_team(db, team_id, current_user)

    count_result = await db.execute(
        select(func.count(TeamMember.id)).where(TeamMember.team_id == team.id),
    )
    member_count = count_result.scalar() or 0

    return {**_format_team(team), "member_count": member_count}


@router.patch("/teams/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: str,
    data: TeamUpdate,
    db: DatabaseSession = None,
    current_user: TeamWriter = None,
):
    """Update a team"""
    team = await _get_team(db, team_id, current_user)

    if data.name is not None:
        team.name = data.name
    if data.description is not None:
        team.description = data.description

    await db.commit()
    await db.refresh(team)

    return _format_team(team)


@router.delete("/teams/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_team(
    team_id: str,
    db: DatabaseSession = None,
    current_user: TeamWriter = None,
):
    """Delete a team"""
    team = await _get_team(db, team_id, current_user)

    if team.is_default:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete default team",
        )

    # TeamMember.team_id is NOT NULL and the relationship has no delete
    # cascade: without removing the memberships first the ORM nulls their
    # team_id and the delete fails (every team has at least its creator).
    await db.execute(sa_delete(TeamMember).where(TeamMember.team_id == team.id))
    await db.delete(team)
    await db.commit()


# Team members
@router.get("/teams/{team_id}/members")
async def list_team_members(
    team_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """List members of a team"""
    await _get_team(db, team_id, current_user)

    result = await db.execute(
        select(TeamMember)
        .options(selectinload(TeamMember.user))
        .where(TeamMember.team_id == team_id),
    )
    members = result.scalars().all()

    return [
        {
            "id": m.id,
            "user_id": m.user_id,
            "role": m.role,
            "user": {
                "id": m.user.id,
                "email": m.user.email,
                "full_name": m.user.full_name,
            },
        }
        for m in members
    ]


@router.post("/teams/{team_id}/members", status_code=status.HTTP_201_CREATED)
async def add_team_member(
    team_id: str,
    data: AddMemberRequest,
    db: DatabaseSession = None,
    current_user: TeamWriter = None,
):
    """Add a member to a team"""
    team = await _get_team(db, team_id, current_user)

    if not data.user_id and not data.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either user_id or email must be provided",
        )

    # The new member must belong to the team's organization, for every
    # caller (platform superusers included): a team never spans tenants.
    user_query = select(User).where(User.organization_id == team.organization_id)
    if data.user_id:
        user_query = user_query.where(User.id == data.user_id)
    else:
        user_query = user_query.where(User.email == (data.email or "").lower().strip())
    user_row = (await db.execute(user_query)).scalar_one_or_none()
    if user_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in this organization",
        )
    target_user_id = user_row.id

    # Check if already a member
    existing = await db.execute(
        select(TeamMember).where(
            TeamMember.team_id == team_id,
            TeamMember.user_id == target_user_id,
        ),
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already a team member",
        )

    member = TeamMember(
        team_id=team_id,
        user_id=target_user_id,
        role=data.role,
    )
    db.add(member)
    await db.commit()

    return {"status": "success", "message": "Member added"}


@router.delete("/teams/{team_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_team_member(
    team_id: str,
    user_id: str,
    db: DatabaseSession = None,
    current_user: TeamWriter = None,
):
    """Remove a member from a team"""
    await _get_team(db, team_id, current_user)

    result = await db.execute(
        select(TeamMember).where(
            TeamMember.team_id == team_id,
            TeamMember.user_id == user_id,
        ),
    )
    member = result.scalar_one_or_none()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    await db.delete(member)
    await db.commit()


# Helper functions
async def _get_organization(
    org_id: str,
    user: User,
    db: AsyncSession,
    require_admin: bool = False,
) -> Organization:
    """Get an organization with a tenant access check.

    Platform superusers reach any organisation. Everyone else reaches only
    their own (``users.organization_id``, the tenancy key used everywhere);
    another tenant's organisation is reported as missing (404) so its
    existence does not leak. ``OrganizationMember`` rows grant no access.
    ``require_admin`` additionally needs the tenant ``admin`` role.
    """
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    if user.is_superuser:
        return org

    own_org = getattr(user, "organization_id", None)
    if not own_org or str(own_org) != str(org.id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    if require_admin and not identity_roles.has_tier(user, "organizations", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return org


async def _get_team(
    db: AsyncSession,
    team_id: str,
    user: User,
) -> Team:
    """Get a team with access check.

    Signature matches every caller's argument order (``db, team_id,
    current_user``). The previous ``team_id, user, db`` order meant
    every callsite was passing an ``AsyncSession`` where the UUID
    string should have been, and SQLAlchemy blew up on
    ``Team.id == <AsyncSession>`` — all team GET/PATCH/DELETE/members
    endpoints were broken until this was fixed.
    """
    result = await db.execute(select(Team).where(Team.id == team_id))
    team = result.scalar_one_or_none()

    # A team outside the caller's organization is reported as missing, so
    # tenant admins can neither read nor modify another tenant's teams.
    # Only platform superusers cross organizations.
    if team is not None and not getattr(user, "is_superuser", False):
        own_org = getattr(user, "organization_id", None)
        if not own_org or team.organization_id != own_org:
            team = None

    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found",
        )

    # Check access (admin over teams, or team member)
    if not identity_roles.has_tier(user, "teams", "admin"):
        member_result = await db.execute(
            select(TeamMember).where(
                TeamMember.team_id == team_id,
                TeamMember.user_id == user.id,
            ),
        )
        if not member_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not a member of this team",
            )

    return team


def _format_organization(org: Organization) -> dict:
    """Format organization for response"""
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "description": org.description,
        "plan": org.plan,
        "max_users": org.max_users,
        "is_active": org.is_active,
        "created_at": org.created_at,
    }


def _format_team(team: Team) -> dict:
    """Format team for response"""
    return {
        "id": team.id,
        "name": team.name,
        "description": team.description,
        "organization_id": team.organization_id,
        "is_default": team.is_default,
        "created_at": team.created_at,
    }
