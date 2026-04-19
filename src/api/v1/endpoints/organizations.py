"""Organization and Team management endpoints"""

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession, get_current_admin_user
from src.models.organization import (
    Organization,
    OrganizationMember,
    OrganizationRole,
    Team,
    TeamMember,
    TeamRole,
)
from src.models.user import User

router = APIRouter()


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

    Platform superusers see every organization. Every other role — including
    per-tenant ``admin`` role — only sees organizations they are members of
    (via OrganizationMember) or the one matching their primary
    ``users.organization_id``. This stops a tenant admin from enumerating
    every other customer's organization via this endpoint.
    """
    if getattr(current_user, "is_superuser", False):
        query = select(Organization)
    else:
        member_subquery = select(OrganizationMember.organization_id).where(
            OrganizationMember.user_id == current_user.id
        )
        filters = [Organization.id.in_(member_subquery)]
        primary_org = getattr(current_user, "organization_id", None)
        if primary_org:
            filters.append(Organization.id == primary_org)
        from sqlalchemy import or_ as _or
        query = select(Organization).where(_or(*filters))

    query = query.offset(skip).limit(limit).order_by(Organization.created_at.desc())
    result = await db.execute(query)
    organizations = result.scalars().all()

    # Get member counts
    response = []
    for org in organizations:
        count_result = await db.execute(
            select(func.count(OrganizationMember.id)).where(
                OrganizationMember.organization_id == org.id
            )
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
    current_user: CurrentUser = None,
):
    """Create a new organization"""
    # Check if slug is unique
    existing = await db.execute(
        select(Organization).where(Organization.slug == data.slug)
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

    return {**_format_organization(org), "member_count": 1}


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Get an organization by ID"""
    org = await _get_organization(org_id, current_user, db)

    count_result = await db.execute(
        select(func.count(OrganizationMember.id)).where(
            OrganizationMember.organization_id == org.id
        )
    )
    member_count = count_result.scalar() or 0

    return {**_format_organization(org), "member_count": member_count}


@router.patch("/organizations/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: str,
    data: OrganizationUpdate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Update an organization"""
    org = await _get_organization(org_id, current_user, db, require_admin=True)

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
    admin_user: User = Depends(get_current_admin_user),
):
    """Delete an organization (platform superuser only)"""
    if not getattr(admin_user, "is_superuser", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only platform superusers can delete organizations",
        )

    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    await db.delete(org)
    await db.commit()


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
        .where(OrganizationMember.organization_id == org_id)
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
    current_user: CurrentUser = None,
):
    """Add a member to an organization"""
    await _get_organization(org_id, current_user, db, require_admin=True)

    # Resolve user_id from email if not provided directly
    target_user_id = data.user_id
    if not target_user_id and data.email:
        by_email = await db.execute(
            select(User).where(User.email == data.email.lower().strip())
        )
        user_row = by_email.scalar_one_or_none()
        if not user_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No user found with email {data.email}",
            )
        target_user_id = user_row.id
    if not target_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either user_id or email must be provided",
        )

    # Check if user exists
    user_result = await db.execute(select(User).where(User.id == target_user_id))
    if not user_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check if already a member
    existing = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == target_user_id,
        )
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

    return {"status": "success", "message": "Member added", "user_id": target_user_id}


@router.delete("/organizations/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_organization_member(
    org_id: str,
    user_id: str,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
):
    """Remove a member from an organization"""
    await _get_organization(org_id, current_user, db, require_admin=True)

    result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user_id,
        )
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
    """List all teams"""
    query = select(Team)

    if organization_id:
        query = query.where(Team.organization_id == organization_id)

    if not current_user.is_admin:
        # Get teams the user is a member of
        member_subquery = select(TeamMember.team_id).where(
            TeamMember.user_id == current_user.id
        )
        query = query.where(Team.id.in_(member_subquery))

    result = await db.execute(query.order_by(Team.created_at.desc()))
    teams = result.scalars().all()

    response = []
    for team in teams:
        count_result = await db.execute(
            select(func.count(TeamMember.id)).where(TeamMember.team_id == team.id)
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
    current_user: CurrentUser = None,
):
    """Create a new team"""
    if not data.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID is required",
        )

    # Verify organization access
    await _get_organization(data.organization_id, current_user, db, require_admin=True)

    team = Team(
        name=data.name,
        description=data.description,
        organization_id=data.organization_id,
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
        select(func.count(TeamMember.id)).where(TeamMember.team_id == team.id)
    )
    member_count = count_result.scalar() or 0

    return {**_format_team(team), "member_count": member_count}


@router.patch("/teams/{team_id}", response_model=TeamResponse)
async def update_team(
    team_id: str,
    data: TeamUpdate,
    db: DatabaseSession = None,
    current_user: CurrentUser = None,
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
    current_user: CurrentUser = None,
):
    """Delete a team"""
    team = await _get_team(db, team_id, current_user)

    if team.is_default:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete default team",
        )

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
        .where(TeamMember.team_id == team_id)
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
    current_user: CurrentUser = None,
):
    """Add a member to a team"""
    await _get_team(db, team_id, current_user)

    # Resolve user_id from email if not provided
    target_user_id = data.user_id
    if not target_user_id and data.email:
        by_email = await db.execute(
            select(User).where(User.email == data.email.lower().strip())
        )
        user_row = by_email.scalar_one_or_none()
        if not user_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No user found with email {data.email}",
            )
        target_user_id = user_row.id
    if not target_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either user_id or email must be provided",
        )

    # Check if already a member
    existing = await db.execute(
        select(TeamMember).where(
            TeamMember.team_id == team_id,
            TeamMember.user_id == target_user_id,
        )
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
    current_user: CurrentUser = None,
):
    """Remove a member from a team"""
    await _get_team(db, team_id, current_user)

    result = await db.execute(
        select(TeamMember).where(
            TeamMember.team_id == team_id,
            TeamMember.user_id == user_id,
        )
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
    """Get an organization with a real access check.

    Only platform superusers bypass the membership check. Per-tenant admin
    role no longer grants cross-tenant access — they must be members of the
    specific organization they're trying to touch.
    """
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()

    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    if getattr(user, "is_superuser", False):
        return org

    # Must be a member (or primary org) to access.
    member_result = await db.execute(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user.id,
        )
    )
    member = member_result.scalar_one_or_none()

    primary_org = getattr(user, "organization_id", None)
    if not member and primary_org != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this organization",
        )

    if require_admin:
        is_org_admin = member and member.role in [
            OrganizationRole.OWNER.value,
            OrganizationRole.ADMIN.value,
        ]
        if not is_org_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

    return org


async def _get_team(
    team_id: str,
    user: User,
    db: AsyncSession,
) -> Team:
    """Get a team with access check"""
    result = await db.execute(select(Team).where(Team.id == team_id))
    team = result.scalar_one_or_none()

    if not team:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Team not found",
        )

    # Check access (admin or team member)
    if not user.is_admin:
        member_result = await db.execute(
            select(TeamMember).where(
                TeamMember.team_id == team_id,
                TeamMember.user_id == user.id,
            )
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
