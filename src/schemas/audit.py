"""Audit log schemas"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class AuditLogBase(BaseModel):
    """Base audit log schema"""
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    description: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None


class AuditLogCreate(AuditLogBase):
    """Schema for creating audit logs"""
    user_id: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None


class AuditLogResponse(AuditLogBase):
    """Schema for audit log responses"""
    id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    """Paginated list of audit logs"""
    items: List[AuditLogResponse]
    total: int
    page: int
    size: int
    pages: int
