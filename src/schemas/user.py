"""User schemas for API request/response validation"""

from datetime import datetime
from typing import Optional

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


class UserResponse(UserBase):
    """Schema for user response"""

    id: str
    is_superuser: bool
    avatar_url: Optional[str] = None
    last_login: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Schema for paginated user list"""

    items: list[UserResponse]
    total: int
    page: int
    size: int
    pages: int
