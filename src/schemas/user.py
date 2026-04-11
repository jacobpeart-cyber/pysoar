"""User schemas for API request/response validation"""

from datetime import datetime
from typing import Optional

from src.schemas.base import DBModel
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    """Base user schema"""

    email: EmailStr
    full_name: Optional[str] = None
    role: str = "analyst"
    is_active: bool = True
    phone: Optional[str] = None
    department: Optional[str] = None


class UserCreate(UserBase):
    """Schema for creating a user"""

    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    """Schema for updating a user"""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)


class UserResponse(UserBase, DBModel):
    """Schema for user response"""

    id: str = ""
    is_superuser: bool = False
    avatar_url: Optional[str] = None
    last_login: Optional[str] = None
    # Exposed so the frontend can subscribe to per-org WebSocket
    # channels (agents:<org_id>, purple:<org_id>:<sim_id>) without
    # needing a second round-trip to fetch organization membership.
    organization_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Schema for paginated user list"""

    items: list[UserResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0
