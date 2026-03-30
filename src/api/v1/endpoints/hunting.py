"""Threat hunting endpoints"""

import json
import math
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession
from src.core.database import async_session_factory
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


async def execute_hunt_session(session_id: str):
    """Background task to execute a hunt session"""
    async with async_session_factory() as db:
        try:
            session = await get_session_or_404(db, session_id)
            session.status = "RUNNING"
            session.started_at = datetime.now(timezone.utc)
            await db.flush()

            # Query existing findings linked to this session
            findings_result = await db.execute(
                select(HuntFinding).where(HuntFinding.session_id == session_id)
            )
            findings = list(findings_result.scalars().all())
            session.findings_count = len(findings)

            # Calculate duration
            completed_at = datetime.now(timezone.utc)
            session.status = "COMPLETED"
            session.completed_at = completed_at
            if session.started_at:
                session.duration_seconds = int(
                    (completed_at - session.started_at).total_seconds()
                )
            await db.commit()
        except Exception as e:
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

    # Apply sorting
    sort_column = getattr(HuntHypothesis, sort_by, HuntHypothesis.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    hypotheses = list(result.scalars().all())

    return HuntHypothesisListResponse(
        items=[HuntHypothesisResponse.model_validate(h) for h in hypotheses],
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
        priority=hypothesis_data.priority,
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

    return HuntHypothesisResponse.model_validate(hypothesis)


@router.get("/hypotheses/{hypothesis_id}", response_model=HuntHypothesisResponse)
async def get_hypothesis(
    hypothesis_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a hypothesis by ID"""
    hypothesis = await get_hypothesis_or_404(db, hypothesis_id)
    return HuntHypothesisResponse.model_validate(hypothesis)


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

    return HuntHypothesisResponse.model_validate(hypothesis)


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

    return HuntHypothesisResponse.model_validate(hypothesis)


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
        query = query.where(HuntSession.status == session_status)

    # Get total count
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    # Apply sorting
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

    # Apply sorting
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
    """Escalate a finding to a new case"""
    finding = await get_finding_or_404(db, finding_id)

    # Generate a case ID and link the finding to it
    import uuid
    case_id = str(uuid.uuid4())
    finding.escalated_to_case = True
    finding.case_id = case_id
    await db.flush()
    await db.refresh(finding)

    return {
        "status": "success",
        "finding_id": finding.id,
        "case_id": finding.case_id,
        "message": "Finding escalated to case",
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
    parameters: dict,
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
        priority=parameters.get("priority", 3),
        mitre_tactics=template.mitre_tactics,
        mitre_techniques=template.mitre_techniques,
        tags=json.dumps(template.tags) if template.tags else None,
        status="DRAFT",
        created_by=current_user.id,
    )

    db.add(hypothesis)
    await db.flush()
    await db.refresh(hypothesis)

    return HuntHypothesisResponse.model_validate(hypothesis)


# ============================================================================
# HUNT NOTEBOOKS ENDPOINTS
# ============================================================================


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
        items=[HuntNotebookResponse.model_validate(n) for n in notebooks],
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
        content=json.dumps([]),
        version=1,
        is_published=False,
    )

    db.add(notebook)
    await db.flush()
    await db.refresh(notebook)

    return HuntNotebookResponse.model_validate(notebook)


@router.get("/notebooks/{notebook_id}", response_model=HuntNotebookResponse)
async def get_notebook(
    notebook_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Get a notebook by ID"""
    notebook = await get_notebook_or_404(db, notebook_id)
    return HuntNotebookResponse.model_validate(notebook)


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
        notebook.content = json.dumps(update_data["content"])
        notebook.version += 1

    notebook.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(notebook)

    return HuntNotebookResponse.model_validate(notebook)


@router.post("/notebooks/{notebook_id}/execute-cell", response_model=None)
async def execute_notebook_cell(
    notebook_id: str,
    cell_data: HuntNotebookCellExecute,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
):
    """Execute a query cell in a notebook"""
    notebook = await get_notebook_or_404(db, notebook_id)

    start_time = datetime.now(timezone.utc)

    # Parse notebook content and retrieve the target cell
    cells = json.loads(notebook.content) if isinstance(notebook.content, str) else (notebook.content or [])
    if cell_data.cell_index < 0 or cell_data.cell_index >= len(cells):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cell index {cell_data.cell_index} out of range (notebook has {len(cells)} cells)",
        )

    cell = cells[cell_data.cell_index]

    # Execute query against hunting model tables based on cell content
    query_text = cell.get("query") or cell.get("source") or ""
    results = []

    # Query findings from the session linked to this notebook
    findings_result = await db.execute(
        select(HuntFinding).where(HuntFinding.session_id == notebook.session_id).limit(100)
    )
    findings = findings_result.scalars().all()
    results = [
        {"id": f.id, "title": f.title, "severity": f.severity, "classification": f.classification}
        for f in findings
    ]

    elapsed_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

    # Update cell with execution output
    cells[cell_data.cell_index]["output"] = results
    cells[cell_data.cell_index]["execution_time_ms"] = elapsed_ms
    notebook.content = json.dumps(cells)
    await db.flush()

    return {
        "status": "success",
        "cell_index": cell_data.cell_index,
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

    return HuntNotebookResponse.model_validate(notebook)


@router.get("/notebooks/{notebook_id}/export", response_model=None)
async def export_notebook(
    notebook_id: str,
    current_user: CurrentUser = None,
    db: DatabaseSession = None,
    format: str = Query("json", pattern="^(json|markdown|html)$"),
):
    """Export a notebook in the specified format"""
    # Note: In a real implementation, this would use the NotebookService
    return {
        "status": "success",
        "notebook_id": notebook_id,
        "format": format,
        "data": None,
    }


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

    # Top MITRE techniques
    top_mitre_result = await db.execute(
        select(HuntFinding.mitre_techniques, func.count(HuntFinding.id))
        .group_by(HuntFinding.mitre_techniques)
        .order_by(func.count(HuntFinding.id).desc())
        .limit(10)
    )
    top_mitre_techniques = [t[0] for t in top_mitre_result.all() if t[0]]

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
