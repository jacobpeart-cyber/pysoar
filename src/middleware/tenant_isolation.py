"""Tenant isolation module for multi-tenant data security"""

from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from src.core.logging import get_logger

logger = get_logger(__name__)

# Tables exempt from tenant isolation filtering
TENANT_EXEMPT_TABLES = {
    "users",
    "organizations",
    "organization_members",
    "alembic_version",
    "audit_logs",
    "system_settings",
}


async def get_user_organization_id(user_id: str, db: AsyncSession) -> Optional[str]:
    """
    Get the organization ID for a user using parameterized SQL query

    Args:
        user_id: User ID to lookup
        db: AsyncSession database connection

    Returns:
        Organization ID if found, None otherwise
    """
    try:
        query = text(
            "SELECT organization_id FROM organization_members WHERE user_id = :uid LIMIT 1"
        )
        result = await db.execute(query, {"uid": user_id})
        row = result.fetchone()
        return row[0] if row else None
    except Exception as e:
        logger.error(
            f"Failed to get user organization ID: {str(e)}",
            extra={"user_id": user_id},
        )
        return None


def enforce_tenant_filter(
    query_result: Any, organization_id: str, model_class: Any
) -> Any:
    """
    Python-level safety net filter to ensure tenant isolation

    Validates that query results belong to the expected organization.
    This is a secondary defense layer after database-level filters.

    Args:
        query_result: Result from database query
        organization_id: Expected organization ID for the user
        model_class: SQLAlchemy model class to check organization_id attribute

    Returns:
        Filtered query result or None if tenant mismatch detected

    Raises:
        ValueError: If tenant mismatch is detected (potential data leak attempt)
    """
    if query_result is None:
        return None

    # Check if model has organization_id attribute
    if not hasattr(model_class, "organization_id"):
        # Exempt tables don't need tenant filtering
        return query_result

    # Verify organization_id matches
    result_org_id = getattr(query_result, "organization_id", None)

    if result_org_id is None:
        # No organization_id attribute - may be exempt table
        return query_result

    if result_org_id != organization_id:
        logger.error(
            "Tenant isolation violation detected: attempted access to data from different organization",
            extra={
                "expected_org_id": organization_id,
                "actual_org_id": result_org_id,
                "model_class": model_class.__name__,
            },
        )
        raise ValueError(
            f"Access denied: data belongs to different organization"
        )

    return query_result
