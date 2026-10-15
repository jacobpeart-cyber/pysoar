"""Separation of duties for compliance evidence review.

The person who uploaded a piece of evidence cannot approve it (NIST SP 800-53
AC-5): an approval must come from a second administrator. Both approval
routes (``PUT /compliance/evidence/{id}/review`` and
``POST /audit-evidence/evidence/{id}/approve``) call ``ensure_not_uploader``.

``ComplianceEvidence.collected_by`` holds the uploader's user id. Rows
uploaded through the audit-evidence route before wave 5 hold the uploader's
full name or email instead, so those are matched too (a false match only
means a different administrator has to approve).
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

SEPARATION_OF_DUTIES = "separation_of_duties"


def is_uploader(evidence: Any, user: Any) -> bool:
    collected_by = (getattr(evidence, "collected_by", None) or "").strip()
    if not collected_by:
        return False
    user_id = str(getattr(user, "id", "") or "")
    if user_id and collected_by == user_id:
        return True
    email = (getattr(user, "email", None) or "").strip()
    if email and collected_by.casefold() == email.casefold():
        return True
    full_name = (getattr(user, "full_name", None) or "").strip()
    return bool(full_name) and collected_by == full_name


def ensure_not_uploader(evidence: Any, user: Any) -> None:
    """409 ``separation_of_duties`` when ``user`` uploaded ``evidence``."""
    if is_uploader(evidence, user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": SEPARATION_OF_DUTIES,
                "detail": "evidence cannot be approved by the user who uploaded it; another administrator must approve",
            },
        )
