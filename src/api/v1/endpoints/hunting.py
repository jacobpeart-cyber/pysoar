"""Threat hunting endpoints"""

import json
import math
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.services.automation import AutomationService

logger = get_logger(__name__)
from src.hunting.models import (
    HuntFinding,
    HuntHypothesis,
    HuntSession,
    HuntTemplate,
    HuntNotebook,
)
from src.schemas.hunting import (
    HuntFindingCreate,
    HuntFindingListResponse,
    HuntFindingResponse,
    HuntFindingUpdate,
    HuntHypothesisCreate,
    HuntHypothesisListResponse,
    HuntHypothesisResponse,
    HuntHypothesisUpdate,
    HuntNotebookCreate,
    HuntNotebookListResponse,
    HuntNotebookResponse,
    HuntNotebookUpdate,
    HuntNotebookCellExecute,
    HuntSessionCreate,
    HuntSessionListResponse,
    HuntSessionResponse,
    HuntStatsResponse,
    HuntTemplateResponse,
)

router = APIRouter(prefix="/hunting", tags=["hunting"])


async def get_hypothesis_or_404(db: AsyncSession, hypothesis_id: str) -> HuntHypothesis:
    """Get hypothesis by ID or raise 404"""
    result = await db.execute(
        select(HuntHypothesis).where(HuntHypothesis.id == hypothesis_id)
    )
    hypothesis = result.scalar_one_or_none()
    if not hypothesis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hunt hypothesis not found",
        )
    return hypothesis


async def get_session_or_404(db: AsyncSession, session_id: str) -> HuntSession:
    """Get hunt session by ID or raise 404"""
    result = await db.execute(
        select(HuntSession).where(HuntSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hunt session not found",
        )
    return session


async def get_finding_or_404(db: AsyncSession, finding_id: str) -> HuntFinding:
    """Get finding by ID or raise 404"""
    result = await db.execute(
        select(HuntFinding).where(HuntFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hunt finding not found",
        )
    return finding


async def get_notebook_or_404(db: AsyncSession, notebook_id: str) -> HuntNotebook:
    """Get notebook by ID or raise 404"""
    result = await db.execute(
        select(HuntNotebook).where(HuntNotebook.id == notebook_id)
    )
    notebook = result.scalar_one_or_none()
    if not notebook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Hunt notebook not found",
        )
    return notebook


async def get_sessions_count(db: AsyncSession, hypothesis_id: str) -> int:
    """Get the number of sessions for a hypothesis"""
    result = await db.execute(
        select(func.count(HuntSession.id)).where(HuntSession.hypothesis_id == hypothesis_id)
    )
    return result.scalar() or 0


async def hypothesis_to_response(db: AsyncSession, hypothesis: HuntHypothesis) -> HuntHypothesisResponse:
    """Convert hypothesis model to response with sessions_count"""
    sessions_count = await get_sessions_count(db, hypothesis.id)
    data = HuntHypothesisResponse.model_validate(hypothesis)
    data.sessions_count = sessions_count
    return data


async def execute_hunt_session(session_id: str):  # noqa: C901
    """Background task to run a real hunt against the SIEM logs + IOC DB.

    The hunt engine:
      1. Marks the session RUNNING
      2. Loads the hypothesis (data_sources, mitre_techniques, description)
      3. For each indicator mentioned in the hypothesis description, checks
         against the unified threat_indicators table
      4. Queries the SIEM LogEntry table for keywords / techniques in the
         last 24 hours and creates HuntFinding rows for matches
      5. Counts and writes back the aggregate counts
      6. Marks the session COMPLETED with duration

    Best-effort: any exception marks the session FAILED (not silently
    rolled back and left dangling as it was before).
    """
    logger.info(f"execute_hunt_session START session_id={session_id}")
    async with async_session_factory() as db:
        session = None
        try:
            # Fetch session directly (can't use the request-bound
            # get_session_or_404 helper from a background task).
            session_result = await db.execute(
                select(HuntSession).where(HuntSession.id == session_id)
            )
            session = session_result.scalar_one_or_none()
            if not session:
                logger.warning(f"execute_hunt_session: session {session_id} not found")
                return

            hyp_result = await db.execute(
                select(HuntHypothesis).where(HuntHypothesis.id == session.hypothesis_id)
            )
            hypothesis = hyp_result.scalar_one_or_none()

            session.status = "RUNNING"
            session.started_at = datetime.now(timezone.utc)
            await db.flush()

            findings_created = 0
            iocs_checked = 0
            logs_scanned = 0

            if hypothesis:
                # Step 1 — derive search keywords. Title + description words
                # longer than 3 chars, plus MITRE technique IDs.
                import re as _re
                text = f"{hypothesis.title or ''} {hypothesis.description or ''}"
                keywords = {
                    w.lower() for w in _re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", text)
                    if w.lower() not in {"the", "and", "for", "with", "this", "that", "from", "user", "data"}
                }
                mitre_ids = safe_json_loads(hypothesis.mitre_techniques, []) or []

                # Step 2 — scan recent SIEM logs (last 24h) for any keyword match
                from src.siem.models import LogEntry
                since = datetime.now(timezone.utc) - timedelta(days=1)
                log_query = select(LogEntry).where(
                    LogEntry.timestamp >= since.isoformat()
                ).limit(500)
                log_result = await db.execute(log_query)
                candidate_logs = list(log_result.scalars().all())
                logs_scanned = len(candidate_logs)

                for log in candidate_logs:
                    haystack = " ".join(filter(None, [
                        log.message, log.raw_log, log.hostname, log.username,
                        log.process_name, log.action,
                    ])).lower()
                    matched_keywords = [k for k in keywords if k in haystack]
                    if matched_keywords:
                        finding = HuntFinding(
                            session_id=session_id,
                            title=f"Log match: {log.message[:120] if log.message else log.raw_log[:120]}",
                            description=(
                                f"Log matched {len(matched_keywords)} hypothesis keywords: "
                                + ", ".join(matched_keywords[:5])
                            ),
                            severity=log.severity or "medium",
                            evidence=json.dumps({
                                "log_id": log.id,
                                "timestamp": log.timestamp,
                                "source_type": log.source_type,
                                "matched_keywords": matched_keywords[:10],
                            }),
                            mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                        )
                        db.add(finding)
                        findings_created += 1

                # Step 3 — check active threat indicators. Two modes:
                #   (a) explicit data_sources list on the hypothesis
                #       (analyst says "investigate these IPs/domains")
                #   (b) broad scan — any active IOC whose value or source
                #       mentions a hypothesis keyword.
                from src.intel.models import ThreatIndicator
                data_sources = safe_json_loads(hypothesis.data_sources, []) or []
                for src_value in data_sources[:50]:
                    if not isinstance(src_value, str):
                        continue
                    ioc_result = await db.execute(
                        select(ThreatIndicator).where(
                            ThreatIndicator.value == src_value,
                            ThreatIndicator.is_active == True,  # noqa: E712
                        )
                    )
                    matches = ioc_result.scalars().all()
                    iocs_checked += 1
                    for ioc in matches:
                        finding = HuntFinding(
                            session_id=session_id,
                            title=f"IOC match: {ioc.indicator_type}:{ioc.value}",
                            description=(
                                f"Hypothesis data source matched a known threat indicator "
                                f"from feed '{ioc.source or 'unknown'}'"
                            ),
                            severity=ioc.severity or "high",
                            evidence=json.dumps({
                                "indicator_id": ioc.id,
                                "type": ioc.indicator_type,
                                "value": ioc.value,
                                "source": ioc.source,
                                "tags": ioc.tags or [],
                            }),
                        )
                        db.add(finding)
                        findings_created += 1

                # Step 4 — hunt the alerts table (last 14 days) for any
                # matching keyword. This surfaces prior detections the
                # hypothesis may have been written to find. Alerts are
                # usually present even when raw logs are not, so this is
                # the most valuable hunt source on most deployments.
                from src.models.alert import Alert
                alerts_scanned = 0
                if keywords:
                    alert_since = datetime.now(timezone.utc) - timedelta(days=14)
                    alert_q = select(Alert).where(Alert.created_at >= alert_since).limit(2000)
                    alert_res = await db.execute(alert_q)
                    for a in alert_res.scalars().all():
                        alerts_scanned += 1
                        hay = " ".join(filter(None, [
                            a.title, a.description, a.hostname, a.username,
                            a.source, a.category, a.source_ip, a.destination_ip,
                            a.domain, a.url, a.file_hash,
                        ])).lower()
                        matched = [k for k in keywords if k in hay]
                        if matched:
                            db.add(HuntFinding(
                                session_id=session_id,
                                title=f"Alert match: {a.title}",
                                description=(
                                    f"Historical alert from {a.source or 'unknown source'} "
                                    f"matched {len(matched)} hypothesis keywords."
                                ),
                                severity=a.severity or "medium",
                                evidence=json.dumps({
                                    "alert_id": a.id,
                                    "alert_status": a.status,
                                    "created_at": a.created_at.isoformat() if a.created_at else None,
                                    "matched_keywords": matched[:10],
                                    "source_ip": a.source_ip,
                                    "hostname": a.hostname,
                                }),
                                mitre_techniques=json.dumps(mitre_ids) if mitre_ids else None,
                            ))
                            findings_created += 1

                # Step 5 — hunt audit_logs for keyword matches on actions.
                # This catches abuse of platform actions (e.g. "playbook
                # execution on critical host" matching "lateral movement"
                # keywords).
                from src.models.audit import AuditLog
                audit_scanned = 0
                if keywords:
                    audit_since = datetime.now(timezone.utc) - timedelta(days=14)
                    audit_q = select(AuditLog).where(AuditLog.created_at >= audit_since).limit(2000)
                    audit_res = await db.execute(audit_q)
                    for al in audit_res.scalars().all():
                        audit_scanned += 1
                        hay = " ".join(filter(None, [
                            al.action, al.resource_type, al.resource_id,
                            al.description, al.ip_address,
                        ])).lower()
                        matched = [k for k in keywords if k in hay]
                        if matched:
                            db.add(HuntFinding(
                                session_id=session_id,
                                title=f"Audit log match: {al.action} on {al.resource_type}",
                                description=(
                                    f"Audit event matched {len(matched)} hypothesis keywords."
                                ),
                                severity="medium" if al.success else "high",
                                evidence=json.dumps({
                                    "audit_id": al.id,
                                    "action": al.action,
                                    "resource_type": al.resource_type,
                                    "resource_id": al.resource_id,
                                    "user_id": al.user_id,
                                    "success": al.success,
                                    "matched_keywords": matched[:10],
                                }),
                            ))
                            findings_created += 1

            # Flush the new findings before counting so the count query
            # can see them in this session's transaction.
            await db.flush()
            findings_count_result = await db.execute(
                select(func.count(HuntFinding.id)).where(HuntFinding.session_id == session_id)
            )
            session.findings_count = findings_count_result.scalar() or 0
            # events_analyzed is the sum of rows actually inspected across
            # every hunt source, so the UI's "analyzed N events" number
            # reflects real work.
            session.events_analyzed = logs_scanned + alerts_scanned + audit_scanned
            # query_count is the number of distinct queries we ran: one
            # SIEM log scan, one alerts scan, one audit scan, plus one
            # per IOC lookup against the threat_indicators table.
            session.query_count = 3 + iocs_checked

            # Store per-run hunt telemetry for the UI to display.
            session.queries_executed = json.dumps({
                "logs_scanned": logs_scanned,
                "alerts_scanned": alerts_scanned,
                "audit_logs_scanned": audit_scanned,
                "iocs_checked": iocs_checked,
                "findings_created_this_run": findings_created,
                "keywords_used": sorted(list(keywords))[:30],
                "mitre_techniques": mitre_ids,
            })

            completed_at = datetime.now(timezone.utc)
            session.status = "COMPLETED"
            session.completed_at = completed_at
            if session.started_at:
                session.duration_seconds = int(
                    (completed_at - session.started_at).total_seconds()
                )
            await db.commit()
            logger.info(
                f"execute_hunt_session DONE session_id={session_id} "
                f"findings_created={findings_created} logs_scanned={logs_scanned} "
                f"iocs_checked={iocs_checked}"
            )
        except Exception as e:
            logger.error(f"execute_hunt_session FAILED session_id={session_id}: {e}", exc_info=True)
            try:
                await db.rollback()
                # Re-fetch the session in a clean state and mark it failed
                fail_result = await db.execute(
                    select(HuntSession).where(HuntSession.id == session_id)
                )
                fail_session = fail_result.scalar_one_or_none()
                if fail_session:
                    fail_session.status = "FAILED"
                    fail_session.completed_at = datetime.now(timezone.utc)
                    fail_session.error_message = str(e)[:500]
                    await db.commit()
            except Exception as inner:
                logger.error(f"Could not mark session {session_id} as FAILED: {inner}")
                await db.rollback()


# ============================================================================
# HUNT HYPOTHESES ENDPOINTS
# ============================================================================


@router.get("/hypotheses", response_model=HuntHypothesisListResponse)
async def list_hypotheses(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[int] = None,
    hunt_type: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List hunt hypotheses with filtering and pagination"""
    query = select(HuntHypothesis)

    # Apply filters
    if search:
        search_filter = f"%{search}%"
        query = query.where(
            (HuntHypothesis.title.ilike(search_filter))
            | (HuntHypothesis.description.ilike(search_filter))
        )

    if status:
        query = query.where(HuntHypothesis.status == status)

    if priority:
        query = query.where(HuntHypothesis.priority == priority)

    if hunt_type:
        query = query.where(HuntHypothesis.hunt_type == hunt_type)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting — whitelist sortable columns
    _ALLOWED_HYP_SORTS = {
        "created_at", "updated_at", "title", "priority", "status", "hunt_type",
    }
    if sort_by not in _ALLOWED_HYP_SORTS:
        sort_by = "created_at"
    sort_column = getattr(HuntHypothesis, sort_by, HuntHypothesis.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    hypotheses = list(result.scalars().all())

    items = [await hypothesis_to_response(db, h) for h in hypotheses]

    return HuntHypothesisListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/hypotheses", response_model=HuntHypothesisResponse, status_code=status.HTTP_201_CREATED)
async def create_hypothesis(
    hypothesis_data: HuntHypothesisCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new hunt hypothesis"""
    hypothesis = HuntHypothesis(
        title=hypothesis_data.title,
        description=hypothesis_data.description,
        priority=str(hypothesis_data.priority),
        hunt_type=hypothesis_data.hunt_type,
        mitre_tactics=json.dumps(hypothesis_data.mitre_tactics) if hypothesis_data.mitre_tactics else None,
        mitre_techniques=json.dumps(hypothesis_data.mitre_techniques) if hypothesis_data.mitre_techniques else None,
        data_sources=json.dumps(hypothesis_data.data_sources) if hypothesis_data.data_sources else None,
        expected_evidence=json.dumps(hypothesis_data.expected_evidence) if hypothesis_data.expected_evidence else None,
        tags=json.dumps(hypothesis_data.tags) if hypothesis_data.tags else None,
        status="DRAFT",
        created_by=current_user.id,
    )

    db.add(hypothesis)
    await db.flush()
    await db.refresh(hypothesis)

    return await hypothesis_to_response(db, hypothesis)


@router.get("/hypotheses/{hypothesis_id}", response_model=HuntHypothesisResponse)
async def get_hypothesis(
    hypothesis_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a hypothesis by ID"""
    hypothesis = await get_hypothesis_or_404(db, hypothesis_id)
    return await hypothesis_to_response(db, hypothesis)


@router.put("/hypotheses/{hypothesis_id}", response_model=HuntHypothesisResponse)
async def update_hypothesis(
    hypothesis_id: str,
    hypothesis_data: HuntHypothesisUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a hypothesis"""
    hypothesis = await get_hypothesis_or_404(db, hypothesis_id)

    update_data = hypothesis_data.model_dump(exclude_unset=True, exclude_none=True)

    # Coerce priority to string (DB column is VARCHAR)
    if "priority" in update_data and update_data["priority"] is not None:
        update_data["priority"] = str(update_data["priority"])

    # Handle JSON serialization
    if "mitre_tactics" in update_data:
        update_data["mitre_tactics"] = json.dumps(update_data["mitre_tactics"])
    if "mitre_techniques" in update_data:
        update_data["mitre_techniques"] = json.dumps(update_data["mitre_techniques"])
    if "data_sources" in update_data:
        update_data["data_sources"] = json.dumps(update_data["data_sources"])
    if "expected_evidence" in update_data:
        update_data["expected_evidence"] = json.dumps(update_data["expected_evidence"])
    if "tags" in update_data:
        update_data["tags"] = json.dumps(update_data["tags"])

    for key, value in update_data.items():
        setattr(hypothesis, key, value)

    hypothesis.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(hypothesis)

    return await hypothesis_to_response(db, hypothesis)


@router.delete("/hypotheses/{hypothesis_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_hypothesis(
    hypothesis_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Delete a hypothesis (only if DRAFT)"""
    hypothesis = await get_hypothesis_or_404(db, hypothesis_id)

    if hypothesis.status != "DRAFT":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only delete hypotheses in DRAFT status",
        )

    await db.delete(hypothesis)
    await db.flush()


@router.post("/hypotheses/{hypothesis_id}/activate", response_model=HuntHypothesisResponse)
async def activate_hypothesis(
    hypothesis_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Activate a hypothesis (set status to ACTIVE)"""
    hypothesis = await get_hypothesis_or_404(db, hypothesis_id)

    if hypothesis.status != "DRAFT":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only activate hypotheses in DRAFT status",
        )

    hypothesis.status = "ACTIVE"
    hypothesis.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(hypothesis)

    return await hypothesis_to_response(db, hypothesis)


# ============================================================================
# HUNT SESSIONS ENDPOINTS
# ============================================================================


@router.post("/sessions", response_model=HuntSessionResponse, status_code=status.HTTP_201_CREATED)
async def create_session(session_data: HuntSessionCreate, current_user: CurrentUser = None, db: DatabaseSession = None, background_tasks: BackgroundTasks = None):
    """Create and start a hunt session"""
    hypothesis = await get_hypothesis_or_404(db, session_data.hypothesis_id)

    hunt_session = HuntSession(
        hypothesis_id=session_data.hypothesis_id,
        status="PENDING",
        parameters=json.dumps(session_data.parameters) if session_data.parameters else None,
        created_by=current_user.id,
    )

    db.add(hunt_session)
    await db.flush()
    await db.refresh(hunt_session)

    # EXPLICIT commit before scheduling the background task — otherwise
    # the task (which opens a fresh AsyncSession) races with get_db()'s
    # post-yield commit and may not see this row yet, resulting in a
    # silent "session not found" failure.
    await db.commit()

    # Trigger background execution
    background_tasks.add_task(execute_hunt_session, hunt_session.id)

    return HuntSessionResponse.model_validate(hunt_session)


@router.get("/sessions", response_model=HuntSessionListResponse)
async def list_sessions(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    hypothesis_id: Optional[str] = None,
    session_status: Optional[str] = Query(None, alias="status"),
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List hunt sessions with filtering and pagination"""
    query = select(HuntSession)

    if hypothesis_id:
        query = query.where(HuntSession.hypothesis_id == hypothesis_id)

    if session_status:
        query = query.where(func.upper(HuntSession.status) == session_status.upper())

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting — whitelist sortable columns
    _ALLOWED_SESSION_SORTS = {
        "created_at", "started_at", "completed_at", "status", "duration_seconds",
        "findings_count", "events_analyzed",
    }
    if sort_by not in _ALLOWED_SESSION_SORTS:
        sort_by = "created_at"
    sort_column = getattr(HuntSession, sort_by, HuntSession.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    sessions = list(result.scalars().all())

    return HuntSessionListResponse(
        items=[HuntSessionResponse.model_validate(s) for s in sessions],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.get("/sessions/{session_id}", response_model=HuntSessionResponse)
async def get_session(
    session_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a hunt session by ID"""
    session = await get_session_or_404(db, session_id)
    return HuntSessionResponse.model_validate(session)


@router.post("/sessions/{session_id}/pause", response_model=HuntSessionResponse)
async def pause_session(
    session_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Pause a hunt session"""
    session = await get_session_or_404(db, session_id)

    if session.status != "RUNNING":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only pause RUNNING sessions",
        )

    session.status = "PAUSED"
    await db.flush()
    await db.refresh(session)

    return HuntSessionResponse.model_validate(session)


@router.post("/sessions/{session_id}/resume", response_model=HuntSessionResponse)
async def resume_session(
    session_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Resume a paused hunt session"""
    session = await get_session_or_404(db, session_id)

    if session.status != "PAUSED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can only resume PAUSED sessions",
        )

    session.status = "RUNNING"
    await db.flush()
    await db.refresh(session)

    return HuntSessionResponse.model_validate(session)


@router.post("/sessions/{session_id}/cancel", response_model=HuntSessionResponse)
async def cancel_session(
    session_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Cancel a hunt session"""
    session = await get_session_or_404(db, session_id)

    if session.status in ["COMPLETED", "FAILED", "CANCELLED"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel session in {session.status} status",
        )

    session.status = "CANCELLED"
    session.completed_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(session)

    return HuntSessionResponse.model_validate(session)


# ============================================================================
# HUNT FINDINGS ENDPOINTS
# ============================================================================


@router.get("/findings", response_model=HuntFindingListResponse)
async def list_findings(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    session_id: Optional[str] = None,
    severity: Optional[str] = None,
    classification: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
):
    """List hunt findings with filtering and pagination"""
    query = select(HuntFinding)

    if session_id:
        query = query.where(HuntFinding.session_id == session_id)

    if severity:
        query = query.where(HuntFinding.severity == severity)

    if classification:
        query = query.where(HuntFinding.classification == classification)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting — whitelist sortable columns
    _ALLOWED_FINDING_SORTS = {
        "created_at", "updated_at", "severity", "classification", "title", "status",
    }
    if sort_by not in _ALLOWED_FINDING_SORTS:
        sort_by = "created_at"
    sort_column = getattr(HuntFinding, sort_by, HuntFinding.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    findings = list(result.scalars().all())

    return HuntFindingListResponse(
        items=[HuntFindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/findings", response_model=HuntFindingResponse, status_code=status.HTTP_201_CREATED)
async def create_finding(
    finding_data: HuntFindingCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new hunt finding"""
    # Verify session exists
    session = await get_session_or_404(db, finding_data.session_id)

    finding = HuntFinding(
        session_id=finding_data.session_id,
        title=finding_data.title,
        description=finding_data.description,
        severity=finding_data.severity,
        evidence=json.dumps(finding_data.evidence) if finding_data.evidence else None,
        affected_assets=json.dumps(finding_data.affected_assets) if finding_data.affected_assets else None,
        iocs_found=json.dumps(finding_data.iocs_found) if finding_data.iocs_found else None,
        mitre_techniques=json.dumps(finding_data.mitre_techniques) if finding_data.mitre_techniques else None,
        analyst_notes=finding_data.analyst_notes,
    )

    db.add(finding)
    await db.flush()
    await db.refresh(finding)

    try:
        org_id = getattr(current_user, "organization_id", None)
        automation = AutomationService(db)
        await automation.on_threat_hunt_finding(
            hunt_name="hunt",
            finding_title=finding.title,
            severity=finding.severity,
            organization_id=org_id,
        )
    except Exception as automation_exc:
        logger.warning(f"Automation on_threat_hunt_finding failed: {automation_exc}")

    return HuntFindingResponse.model_validate(finding)


@router.get("/findings/{finding_id}", response_model=HuntFindingResponse)
async def get_finding(
    finding_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a finding by ID"""
    finding = await get_finding_or_404(db, finding_id)
    return HuntFindingResponse.model_validate(finding)


@router.put("/findings/{finding_id}", response_model=HuntFindingResponse)
async def update_finding(
    finding_id: str,
    finding_data: HuntFindingUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a finding"""
    finding = await get_finding_or_404(db, finding_id)

    update_data = finding_data.model_dump(exclude_unset=True, exclude_none=True)

    for key, value in update_data.items():
        setattr(finding, key, value)

    await db.flush()
    await db.refresh(finding)

    return HuntFindingResponse.model_validate(finding)


@router.post("/findings/{finding_id}/escalate", response_model=None)
async def escalate_finding(
    finding_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Escalate a hunt finding to a real Incident.

    Previously this endpoint just generated a random UUID and pretended
    the finding was escalated, without ever creating a case. Now it
    creates a real Incident record, links the finding to it, and fires
    the cross-module automation pipeline (which auto-creates a war
    room for critical/high severity findings).
    """
    from src.models.incident import Incident, IncidentStatus

    finding = await get_finding_or_404(db, finding_id)

    if finding.escalated_to_case and finding.case_id:
        # Idempotent — return the existing incident link
        return {
            "status": "already_escalated",
            "finding_id": finding.id,
            "case_id": finding.case_id,
        }

    # Map finding severity onto a sensible incident severity
    sev_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    incident_severity = sev_map.get((finding.severity or "").lower(), "medium")

    incident = Incident(
        title=f"Hunt escalation: {finding.title}",
        description=(
            (finding.description or "") + "\n\n---\n"
            f"Escalated from hunt finding {finding.id}.\n"
            f"Session: {finding.session_id}"
        ),
        severity=incident_severity,
        status=IncidentStatus.OPEN.value,
        incident_type="hunt_finding",
        detected_at=datetime.now(timezone.utc).isoformat(),
    )
    db.add(incident)
    await db.flush()

    finding.escalated_to_case = True
    finding.case_id = incident.id

    # Fire the incident automation pipeline (war room + action items
    # for critical/high severity)
    try:
        automation = AutomationService(db)
        await automation.on_incident_created(
            incident,
            organization_id=getattr(current_user, "organization_id", None) if current_user else None,
            created_by=str(current_user.id) if current_user else None,
        )
    except Exception as automation_exc:
        logger.warning(f"Automation on_incident_created failed after escalation: {automation_exc}")

    await db.flush()
    await db.refresh(finding)

    return {
        "status": "success",
        "finding_id": finding.id,
        "incident_id": incident.id,
        "case_id": finding.case_id,
        "incident_severity": incident_severity,
        "message": f"Finding escalated to incident {incident.id}",
    }


# ============================================================================
# HUNT TEMPLATES ENDPOINTS
# ============================================================================


@router.get("/templates", response_model=list[HuntTemplateResponse])
async def list_templates(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    hunt_type: Optional[str] = None,
):
    """List hunt templates with filtering"""
    query = select(HuntTemplate).where(HuntTemplate.enabled == True)

    if category:
        query = query.where(HuntTemplate.category == category)

    if difficulty:
        query = query.where(HuntTemplate.difficulty == difficulty)

    if hunt_type:
        query = query.where(HuntTemplate.hunt_type == hunt_type)

    result = await db.execute(query)
    templates = list(result.scalars().all())

    return [HuntTemplateResponse.model_validate(t) for t in templates]


@router.get("/templates/{template_id}", response_model=HuntTemplateResponse)
async def get_template(
    template_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a template by ID"""
    result = await db.execute(
        select(HuntTemplate).where(HuntTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found",
        )

    return HuntTemplateResponse.model_validate(template)


@router.post("/templates/{template_id}/instantiate", response_model=HuntHypothesisResponse, status_code=status.HTTP_201_CREATED)
async def instantiate_template(
    template_id: str,
    parameters: dict = Body(default={}),
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a hypothesis from a template"""
    result = await db.execute(
        select(HuntTemplate).where(HuntTemplate.id == template_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found",
        )

    # Create hypothesis from template
    hypothesis = HuntHypothesis(
        title=parameters.get("title", template.name),
        description=template.hypothesis_template,
        hunt_type=template.hunt_type,
        priority=str(parameters.get("priority", 3)),
        mitre_tactics=template.mitre_tactics,
        mitre_techniques=template.mitre_techniques,
        tags=json.dumps(template.tags) if template.tags else None,
        status="DRAFT",
        created_by=current_user.id,
    )

    db.add(hypothesis)
    await db.flush()
    await db.refresh(hypothesis)

    return await hypothesis_to_response(db, hypothesis)


# ============================================================================
# HUNT NOTEBOOKS ENDPOINTS
# ============================================================================


def notebook_to_response(notebook: HuntNotebook) -> HuntNotebookResponse:
    """Build a HuntNotebookResponse, coercing the JSON content column.

    The content column is stored as JSON (Postgres). asyncpg may return
    it as a native list/dict, a JSON-encoded string (legacy writes), or
    None (fresh notebook). Pydantic's `list[HuntNotebookCell]` field
    can't parse a string, so we coerce first.
    """
    return HuntNotebookResponse(
        id=notebook.id,
        session_id=notebook.session_id,
        title=notebook.title,
        content=_coerce_notebook_cells(notebook.content),
        version=notebook.version,
        is_published=notebook.is_published,
        published_at=notebook.published_at,
        created_at=notebook.created_at,
        updated_at=notebook.updated_at,
    )


@router.get("/notebooks", response_model=HuntNotebookListResponse)
async def list_notebooks(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    session_id: Optional[str] = None,
):
    """List hunt notebooks with pagination"""
    query = select(HuntNotebook)

    if session_id:
        query = query.where(HuntNotebook.session_id == session_id)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting and pagination
    query = query.order_by(HuntNotebook.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    notebooks = list(result.scalars().all())

    return HuntNotebookListResponse(
        items=[notebook_to_response(n) for n in notebooks],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if total > 0 else 0,
    )


@router.post("/notebooks", response_model=HuntNotebookResponse, status_code=status.HTTP_201_CREATED)
async def create_notebook(
    notebook_data: HuntNotebookCreate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Create a new hunt notebook"""
    # Verify session exists
    session = await get_session_or_404(db, notebook_data.session_id)

    notebook = HuntNotebook(
        session_id=notebook_data.session_id,
        title=notebook_data.title,
        content=[],
        version=1,
        is_published=False,
    )

    db.add(notebook)
    await db.flush()
    await db.refresh(notebook)

    return notebook_to_response(notebook)


@router.get("/notebooks/{notebook_id}", response_model=HuntNotebookResponse)
async def get_notebook(
    notebook_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a notebook by ID"""
    notebook = await get_notebook_or_404(db, notebook_id)
    return notebook_to_response(notebook)


@router.put("/notebooks/{notebook_id}", response_model=HuntNotebookResponse)
async def update_notebook(
    notebook_id: str,
    notebook_data: HuntNotebookUpdate,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Update a notebook"""
    notebook = await get_notebook_or_404(db, notebook_id)

    update_data = notebook_data.model_dump(exclude_unset=True, exclude_none=True)

    if "title" in update_data:
        notebook.title = update_data["title"]

    if "content" in update_data:
        # Store as native list/dict — the Postgres JSON column accepts
        # Python objects directly via asyncpg. json.dumps()-ing and
        # storing a string is the bug that caused the crash chain.
        notebook.content = update_data["content"]
        notebook.version += 1

    notebook.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(notebook)

    return notebook_to_response(notebook)


@router.post("/notebooks/{notebook_id}/execute-cell", response_model=None)
async def execute_notebook_cell(
    notebook_id: str,
    cell_data: HuntNotebookCellExecute,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Execute a query cell in a notebook.

    Supports a small DSL for hunt notebook cells:
      - "findings"          -> list all findings for this hunt session
      - "findings severity:<level>" -> filter
      - "logs <keyword>"    -> search SIEM log messages (last 24h)
      - "ioc <value>"       -> look up a threat indicator
      - "session"           -> session-level stats

    Anything else falls back to showing the session's findings.
    """
    notebook = await get_notebook_or_404(db, notebook_id)

    start_time = datetime.now(timezone.utc)
    cells = _coerce_notebook_cells(notebook.content)

    if cell_data.cell_index < 0 or cell_data.cell_index >= len(cells):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cell index {cell_data.cell_index} out of range (notebook has {len(cells)} cells)",
        )

    cell = cells[cell_data.cell_index]
    query_text = (cell_data.query or cell.get("query") or cell.get("content") or "").strip()
    query_lower = query_text.lower()

    results: list[dict] = []
    result_type = "findings"

    if query_lower.startswith("logs"):
        # logs <keyword>
        keyword = query_text[4:].strip()
        from src.siem.models import LogEntry
        since = datetime.now(timezone.utc) - timedelta(days=1)
        log_query = select(LogEntry).where(LogEntry.timestamp >= since.isoformat())
        if keyword:
            like = f"%{keyword}%"
            log_query = log_query.where(
                (LogEntry.message.ilike(like)) | (LogEntry.raw_log.ilike(like))
            )
        log_query = log_query.order_by(LogEntry.timestamp.desc()).limit(100)
        log_result = await db.execute(log_query)
        for lg in log_result.scalars().all():
            results.append({
                "id": lg.id,
                "timestamp": lg.timestamp,
                "severity": lg.severity,
                "source_type": lg.source_type,
                "hostname": lg.hostname,
                "message": (lg.message or lg.raw_log or "")[:300],
            })
        result_type = "logs"

    elif query_lower.startswith("ioc"):
        # ioc <value>
        ioc_value = query_text[3:].strip()
        if ioc_value:
            from src.intel.models import ThreatIndicator
            ioc_result = await db.execute(
                select(ThreatIndicator).where(ThreatIndicator.value == ioc_value).limit(25)
            )
            for ind in ioc_result.scalars().all():
                results.append({
                    "id": ind.id,
                    "type": ind.indicator_type,
                    "value": ind.value,
                    "severity": ind.severity,
                    "source": ind.source,
                    "confidence": ind.confidence,
                    "is_active": ind.is_active,
                    "is_whitelisted": ind.is_whitelisted,
                    "sighting_count": ind.sighting_count,
                })
        result_type = "indicators"

    elif query_lower.startswith("session"):
        # Session stats
        session_result = await db.execute(
            select(HuntSession).where(HuntSession.id == notebook.session_id)
        )
        s = session_result.scalar_one_or_none()
        if s:
            results.append({
                "session_id": s.id,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "duration_seconds": s.duration_seconds,
                "query_count": s.query_count,
                "events_analyzed": s.events_analyzed,
                "findings_count": s.findings_count,
            })
        result_type = "session_stats"

    else:
        # Default: findings for this session, optionally filtered
        f_query = select(HuntFinding).where(HuntFinding.session_id == notebook.session_id)
        if "severity:" in query_lower:
            sev = query_lower.split("severity:", 1)[1].split()[0]
            f_query = f_query.where(HuntFinding.severity == sev)
        f_query = f_query.order_by(HuntFinding.created_at.desc()).limit(100)
        f_result = await db.execute(f_query)
        for f in f_result.scalars().all():
            results.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "classification": f.classification,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            })
        result_type = "findings"

    elapsed_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

    # Persist the cell output back onto the notebook
    cells[cell_data.cell_index]["output"] = results
    cells[cell_data.cell_index]["execution_time_ms"] = elapsed_ms
    cells[cell_data.cell_index]["executed_at"] = datetime.now(timezone.utc).isoformat()
    cells[cell_data.cell_index]["result_type"] = result_type
    notebook.content = cells
    await db.flush()

    return {
        "status": "success",
        "cell_index": cell_data.cell_index,
        "result_type": result_type,
        "result_count": len(results),
        "execution_time_ms": elapsed_ms,
        "result": results,
    }


@router.post("/notebooks/{notebook_id}/publish", response_model=HuntNotebookResponse)
async def publish_notebook(
    notebook_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Publish a notebook as a report"""
    notebook = await get_notebook_or_404(db, notebook_id)

    notebook.is_published = True
    notebook.published_at = datetime.now(timezone.utc)
    notebook.version += 1
    await db.flush()
    await db.refresh(notebook)

    return notebook_to_response(notebook)


@router.get("/notebooks/{notebook_id}/export", response_model=None)
async def export_notebook(
    notebook_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    format: str = Query("json", pattern="^(json|markdown|html)$"),
):
    """Export a notebook in the specified format.

    Supports json (structured payload), markdown (human-readable), or
    html (browsable). Previously crashed with AttributeError because it
    referenced `notebook.tags` — the HuntNotebook model has no `tags`
    column.
    """
    notebook = await get_notebook_or_404(db, notebook_id)

    cells = _coerce_notebook_cells(notebook.content)

    payload = {
        "notebook_id": notebook.id,
        "title": notebook.title,
        "version": notebook.version,
        "is_published": notebook.is_published,
        "published_at": notebook.published_at.isoformat() if notebook.published_at else None,
        "created_at": notebook.created_at.isoformat() if notebook.created_at else None,
        "updated_at": notebook.updated_at.isoformat() if notebook.updated_at else None,
        "cells": cells,
    }

    if format == "markdown":
        lines = [f"# {notebook.title}", ""]
        if notebook.published_at:
            lines.append(f"*Published: {notebook.published_at.isoformat()}*")
        lines.append("")
        for idx, cell in enumerate(cells):
            cell_type = cell.get("cell_type", "text")
            content = cell.get("content", "")
            lines.append(f"## Cell {idx + 1} — {cell_type}")
            if cell_type == "markdown":
                lines.append(str(content))
            else:
                lines.append("```")
                lines.append(str(content))
                lines.append("```")
            if cell.get("output") is not None:
                lines.append("")
                lines.append("**Output:**")
                lines.append("```json")
                lines.append(json.dumps(cell["output"], indent=2, default=str))
                lines.append("```")
            lines.append("")
        return {
            "format": "markdown",
            "filename": f"{notebook.title.replace(' ', '_')}.md",
            "content": "\n".join(lines),
        }

    if format == "html":
        html_body = [f"<h1>{notebook.title}</h1>"]
        for idx, cell in enumerate(cells):
            cell_type = cell.get("cell_type", "text")
            content = str(cell.get("content", "")).replace("<", "&lt;").replace(">", "&gt;")
            html_body.append(f"<h2>Cell {idx + 1} — {cell_type}</h2>")
            if cell_type == "markdown":
                html_body.append(f"<div>{content}</div>")
            else:
                html_body.append(f"<pre><code>{content}</code></pre>")
            if cell.get("output") is not None:
                out = json.dumps(cell["output"], indent=2, default=str).replace("<", "&lt;")
                html_body.append(f"<details><summary>Output</summary><pre>{out}</pre></details>")
        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>{notebook.title}</title></head><body>" + "".join(html_body) + "</body></html>"
        )
        return {
            "format": "html",
            "filename": f"{notebook.title.replace(' ', '_')}.html",
            "content": html,
        }

    return {
        "format": "json",
        "filename": f"{notebook.title.replace(' ', '_')}.json",
        "data": payload,
    }


def _coerce_notebook_cells(raw) -> list[dict]:
    """Normalize a HuntNotebook.content value into a list of cell dicts.

    The JSON Postgres column may come back as a native list (asyncpg),
    a JSON-encoded string (legacy write path), or None (freshly created).
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, str):
        parsed = safe_json_loads(raw, [])
        return parsed if isinstance(parsed, list) else []
    return []


# ============================================================================
# HUNT STATISTICS ENDPOINT
# ============================================================================


@router.get("/stats", response_model=HuntStatsResponse)
async def get_hunting_stats(
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get hunting statistics"""
    # Total hypotheses
    total_hyp_result = await db.execute(select(func.count(HuntHypothesis.id)))
    total_hypotheses = total_hyp_result.scalar() or 0

    # Active hunts
    active_result = await db.execute(
        select(func.count(HuntSession.id)).where(HuntSession.status == "RUNNING")
    )
    active_hunts = active_result.scalar() or 0

    # Completed hunts
    completed_result = await db.execute(
        select(func.count(HuntSession.id)).where(HuntSession.status == "COMPLETED")
    )
    completed_hunts = completed_result.scalar() or 0

    # Total findings
    total_find_result = await db.execute(select(func.count(HuntFinding.id)))
    total_findings = total_find_result.scalar() or 0

    # Findings by classification
    class_result = await db.execute(
        select(HuntFinding.classification, func.count(HuntFinding.id))
        .group_by(HuntFinding.classification)
    )
    findings_by_classification = dict(class_result.all()) or {}

    # Findings by severity
    sev_result = await db.execute(
        select(HuntFinding.severity, func.count(HuntFinding.id))
        .group_by(HuntFinding.severity)
    )
    findings_by_severity = dict(sev_result.all()) or {}

    # Average hunt duration
    avg_dur_result = await db.execute(
        select(func.avg(HuntSession.duration_seconds)).where(
            HuntSession.status == "COMPLETED"
        )
    )
    avg_duration_seconds = avg_dur_result.scalar() or 0
    avg_hunt_duration_minutes = avg_duration_seconds / 60 if avg_duration_seconds else 0

    # Top MITRE techniques - cast JSON to text for grouping
    from sqlalchemy import cast, String
    top_mitre_result = await db.execute(
        select(cast(HuntFinding.mitre_techniques, String), func.count(HuntFinding.id))
        .where(HuntFinding.mitre_techniques.isnot(None))
        .group_by(cast(HuntFinding.mitre_techniques, String))
        .order_by(func.count(HuntFinding.id).desc())
        .limit(10)
    )
    top_mitre_techniques = []
    for row in top_mitre_result.all():
        if row[0]:
            import json as json_mod
            try:
                techniques = json_mod.loads(row[0]) if isinstance(row[0], str) else row[0]
                if isinstance(techniques, list):
                    top_mitre_techniques.extend(techniques)
                else:
                    top_mitre_techniques.append(str(techniques))
            except (json_mod.JSONDecodeError, TypeError):
                top_mitre_techniques.append(str(row[0]))

    return HuntStatsResponse(
        total_hypotheses=total_hypotheses,
        active_hunts=active_hunts,
        completed_hunts=completed_hunts,
        total_findings=total_findings,
        findings_by_classification=findings_by_classification,
        findings_by_severity=findings_by_severity,
        avg_hunt_duration_minutes=avg_hunt_duration_minutes,
        top_mitre_techniques=top_mitre_techniques,
    )
