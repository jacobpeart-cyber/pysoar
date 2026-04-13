"""Audit log schemas"""

from datetime import datetime
from typing import Any, Optional, List
from src.schemas.base import DBModel
from pydantic import BaseModel


class AuditLogBase(BaseModel):
    """Base audit log schema"""
    action: str = ""
    resource_type: str = ""
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


class AuditLogResponse(AuditLogBase, DBModel):
    """Schema for audit log responses"""
    id: str = ""
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    # old_value/new_value are stored as JSON strings on the model. DBModel's
    # validator JSON-parses any string starting with { or [, so we accept
    # either a dict/list (after parsing) or a raw string passthrough.
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    """Paginated list of audit logs"""
    items: List[AuditLogResponse]
    total: int = 0
    page: int = 0
    size: int = 0
    pages: int = 0
