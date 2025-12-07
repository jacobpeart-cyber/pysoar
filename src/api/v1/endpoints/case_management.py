"""Case management endpoints for notes, tasks, attachments, and timeline"""

import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import CurrentUser, DatabaseSession
from src.models.case import (
    AttachmentType,
    CaseAttachment,
    CaseNote,
    CaseTimeline,
    NoteType,
    Task,
    TimelineEventType,
)
from src.models.incident import Incident
from src.models.user import User

router = APIRouter()

# Configure upload directory
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads/attachments")
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 50 * 1024 * 1024))  # 50MB default


# =============================================================================
# Schemas
# =============================================================================


class NoteCreate(BaseModel):
    """Schema for creating a note"""

    content: str = Field(..., min_length=1)
    note_type: str = Field(default=NoteType.GENERAL.value)
    is_internal: bool = Field(default=True)


class NoteUpdate(BaseModel):
    """Schema for updating a note"""

    content: Optional[str] = Field(None, min_length=1)
    note_type: Optional[str] = None
    is_internal: Optional[bool] = None
    is_pinned: Optional[bool] = None


class NoteResponse(BaseModel):
    """Schema for note response"""

    id: str
    content: str
    note_type: str
    is_internal: bool
    is_pinned: bool
    incident_id: str
    author_id: str
    author_name: Optional[str] = None
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class TaskCreate(BaseModel):
    """Schema for creating a task"""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    priority: int = Field(default=3, ge=1, le=5)
    due_date: Optional[str] = None
    assigned_to: Optional[str] = None


class TaskUpdate(BaseModel):
    """Schema for updating a task"""

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=5)
    due_date: Optional[str] = None
    assigned_to: Optional[str] = None


class TaskResponse(BaseModel):
    """Schema for task response"""

    id: str
    title: str
    description: Optional[str]
    status: str
    priority: int
    due_date: Optional[str]
    completed_at: Optional[str]
    incident_id: str
    assigned_to: Optional[str]
    assignee_name: Optional[str] = None
    created_by: str
    creator_name: Optional[str] = None
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class AttachmentResponse(BaseModel):
    """Schema for attachment response"""

    id: str
    filename: str
    original_filename: str
    file_size: int
    mime_type: str
    file_hash: Optional[str]
    attachment_type: str
    description: Optional[str]
    is_malware: bool
    is_encrypted: bool
    incident_id: str
    uploaded_by: str
    uploader_name: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


class TimelineResponse(BaseModel):
    """Schema for timeline response"""

    id: str
    event_type: str
    title: str
    description: Optional[str]
    old_value: Optional[str]
    new_value: Optional[str]
    metadata: Optional[dict] = None
    incident_id: str
    actor_id: Optional[str]
    actor_name: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


class TimelineCreate(BaseModel):
    """Schema for creating a custom timeline event"""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    event_type: str = Field(default=TimelineEventType.CUSTOM.value)


# =============================================================================
# Helper Functions
# =============================================================================


async def get_incident_or_404(db: AsyncSession, incident_id: str) -> Incident:
    """Get incident by ID or raise 404"""
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return incident


async def add_timeline_event(
    db: AsyncSession,
    incident_id: str,
    event_type: str,
    title: str,
    actor_id: Optional[str] = None,
    description: Optional[str] = None,
    old_value: Optional[str] = None,
    new_value: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> CaseTimeline:
    """Add a timeline event to an incident"""
    event = CaseTimeline(
        incident_id=incident_id,
        event_type=event_type,
        title=title,
        description=description,
        old_value=old_value,
        new_value=new_value,
        metadata=json.dumps(metadata) if metadata else None,
        actor_id=actor_id,
    )
    db.add(event)
    return event


# =============================================================================
# Notes Endpoints
# =============================================================================


@router.get("/incidents/{incident_id}/notes", response_model=list[NoteResponse])
async def list_notes(
    incident_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
    include_internal: bool = Query(default=True),
):
    """List all notes for an incident"""
    await get_incident_or_404(db, incident_id)

    query = (
        select(CaseNote)
        .options(selectinload(CaseNote.author))
        .where(CaseNote.incident_id == incident_id)
    )

    if not include_internal:
        query = query.where(CaseNote.is_internal == False)

    query = query.order_by(CaseNote.is_pinned.desc(), CaseNote.created_at.desc())

    result = await db.execute(query)
    notes = result.scalars().all()

    return [
        NoteResponse(
            id=note.id,
            content=note.content,
            note_type=note.note_type,
            is_internal=note.is_internal,
            is_pinned=note.is_pinned,
            incident_id=note.incident_id,
            author_id=note.author_id,
            author_name=note.author.full_name if note.author else None,
            created_at=note.created_at,
            updated_at=note.updated_at,
        )
        for note in notes
    ]


@router.post(
    "/incidents/{incident_id}/notes",
    response_model=NoteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_note(
    incident_id: str,
    data: NoteCreate,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Create a new note for an incident"""
    await get_incident_or_404(db, incident_id)

    # Validate note type
    valid_types = [t.value for t in NoteType]
    if data.note_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid note type. Must be one of: {', '.join(valid_types)}",
        )

    note = CaseNote(
        content=data.content,
        note_type=data.note_type,
        is_internal=data.is_internal,
        incident_id=incident_id,
        author_id=current_user.id,
    )

    db.add(note)

    # Add timeline event
    await add_timeline_event(
        db=db,
        incident_id=incident_id,
        event_type=TimelineEventType.NOTE_ADDED.value,
        title="Note added",
        actor_id=current_user.id,
        description=f"Added {data.note_type} note",
    )

    await db.commit()
    await db.refresh(note)

    return NoteResponse(
        id=note.id,
        content=note.content,
        note_type=note.note_type,
        is_internal=note.is_internal,
        is_pinned=note.is_pinned,
        incident_id=note.incident_id,
        author_id=note.author_id,
        author_name=current_user.full_name,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@router.patch("/incidents/{incident_id}/notes/{note_id}", response_model=NoteResponse)
async def update_note(
    incident_id: str,
    note_id: str,
    data: NoteUpdate,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Update a note"""
    await get_incident_or_404(db, incident_id)

    result = await db.execute(
        select(CaseNote)
        .options(selectinload(CaseNote.author))
        .where(CaseNote.id == note_id, CaseNote.incident_id == incident_id)
    )
    note = result.scalar_one_or_none()

    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found",
        )

    # Only author or admin can update
    if note.author_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this note",
        )

    if data.content is not None:
        note.content = data.content
    if data.note_type is not None:
        note.note_type = data.note_type
    if data.is_internal is not None:
        note.is_internal = data.is_internal
    if data.is_pinned is not None:
        note.is_pinned = data.is_pinned

    await db.commit()
    await db.refresh(note)

    return NoteResponse(
        id=note.id,
        content=note.content,
        note_type=note.note_type,
        is_internal=note.is_internal,
        is_pinned=note.is_pinned,
        incident_id=note.incident_id,
        author_id=note.author_id,
        author_name=note.author.full_name if note.author else None,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@router.delete(
    "/incidents/{incident_id}/notes/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_note(
    incident_id: str,
    note_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Delete a note"""
    await get_incident_or_404(db, incident_id)

    result = await db.execute(
        select(CaseNote).where(
            CaseNote.id == note_id, CaseNote.incident_id == incident_id
        )
    )
    note = result.scalar_one_or_none()

    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found",
        )

    # Only author or admin can delete
    if note.author_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this note",
        )

    await db.delete(note)
    await db.commit()


# =============================================================================
# Tasks Endpoints
# =============================================================================


@router.get("/incidents/{incident_id}/tasks", response_model=list[TaskResponse])
async def list_tasks(
    incident_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
    status_filter: Optional[str] = Query(None, alias="status"),
    assigned_to: Optional[str] = None,
):
    """List all tasks for an incident"""
    await get_incident_or_404(db, incident_id)

    query = (
        select(Task)
        .options(selectinload(Task.assignee), selectinload(Task.creator))
        .where(Task.incident_id == incident_id)
    )

    if status_filter:
        query = query.where(Task.status == status_filter)
    if assigned_to:
        query = query.where(Task.assigned_to == assigned_to)

    query = query.order_by(Task.priority.asc(), Task.created_at.desc())

    result = await db.execute(query)
    tasks = result.scalars().all()

    return [
        TaskResponse(
            id=task.id,
            title=task.title,
            description=task.description,
            status=task.status,
            priority=task.priority,
            due_date=task.due_date,
            completed_at=task.completed_at,
            incident_id=task.incident_id,
            assigned_to=task.assigned_to,
            assignee_name=task.assignee.full_name if task.assignee else None,
            created_by=task.created_by,
            creator_name=task.creator.full_name if task.creator else None,
            created_at=task.created_at,
            updated_at=task.updated_at,
        )
        for task in tasks
    ]


@router.post(
    "/incidents/{incident_id}/tasks",
    response_model=TaskResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_task(
    incident_id: str,
    data: TaskCreate,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Create a new task for an incident"""
    await get_incident_or_404(db, incident_id)

    # Validate assignee if provided
    assignee = None
    if data.assigned_to:
        result = await db.execute(
            select(User).where(User.id == data.assigned_to)
        )
        assignee = result.scalar_one_or_none()
        if not assignee:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assigned user not found",
            )

    task = Task(
        title=data.title,
        description=data.description,
        priority=data.priority,
        due_date=data.due_date,
        incident_id=incident_id,
        assigned_to=data.assigned_to,
        created_by=current_user.id,
    )

    db.add(task)

    # Add timeline event
    await add_timeline_event(
        db=db,
        incident_id=incident_id,
        event_type=TimelineEventType.CUSTOM.value,
        title="Task created",
        actor_id=current_user.id,
        description=f"Task: {data.title}",
    )

    await db.commit()
    await db.refresh(task)

    return TaskResponse(
        id=task.id,
        title=task.title,
        description=task.description,
        status=task.status,
        priority=task.priority,
        due_date=task.due_date,
        completed_at=task.completed_at,
        incident_id=task.incident_id,
        assigned_to=task.assigned_to,
        assignee_name=assignee.full_name if assignee else None,
        created_by=task.created_by,
        creator_name=current_user.full_name,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


@router.patch("/incidents/{incident_id}/tasks/{task_id}", response_model=TaskResponse)
async def update_task(
    incident_id: str,
    task_id: str,
    data: TaskUpdate,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Update a task"""
    await get_incident_or_404(db, incident_id)

    result = await db.execute(
        select(Task)
        .options(selectinload(Task.assignee), selectinload(Task.creator))
        .where(Task.id == task_id, Task.incident_id == incident_id)
    )
    task = result.scalar_one_or_none()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    old_status = task.status

    if data.title is not None:
        task.title = data.title
    if data.description is not None:
        task.description = data.description
    if data.priority is not None:
        task.priority = data.priority
    if data.due_date is not None:
        task.due_date = data.due_date
    if data.assigned_to is not None:
        task.assigned_to = data.assigned_to
    if data.status is not None:
        task.status = data.status
        if data.status == "completed" and old_status != "completed":
            task.completed_at = datetime.now(timezone.utc).isoformat()

    await db.commit()
    await db.refresh(task)

    # Reload relationships
    result = await db.execute(
        select(Task)
        .options(selectinload(Task.assignee), selectinload(Task.creator))
        .where(Task.id == task_id)
    )
    task = result.scalar_one()

    return TaskResponse(
        id=task.id,
        title=task.title,
        description=task.description,
        status=task.status,
        priority=task.priority,
        due_date=task.due_date,
        completed_at=task.completed_at,
        incident_id=task.incident_id,
        assigned_to=task.assigned_to,
        assignee_name=task.assignee.full_name if task.assignee else None,
        created_by=task.created_by,
        creator_name=task.creator.full_name if task.creator else None,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


@router.delete(
    "/incidents/{incident_id}/tasks/{task_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_task(
    incident_id: str,
    task_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Delete a task"""
    await get_incident_or_404(db, incident_id)

    result = await db.execute(
        select(Task).where(Task.id == task_id, Task.incident_id == incident_id)
    )
    task = result.scalar_one_or_none()

    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    await db.delete(task)
    await db.commit()


# =============================================================================
# Attachments Endpoints
# =============================================================================


@router.get(
    "/incidents/{incident_id}/attachments", response_model=list[AttachmentResponse]
)
async def list_attachments(
    incident_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """List all attachments for an incident"""
    await get_incident_or_404(db, incident_id)

    result = await db.execute(
        select(CaseAttachment)
        .options(selectinload(CaseAttachment.uploader))
        .where(CaseAttachment.incident_id == incident_id)
        .order_by(CaseAttachment.created_at.desc())
    )
    attachments = result.scalars().all()

    return [
        AttachmentResponse(
            id=att.id,
            filename=att.filename,
            original_filename=att.original_filename,
            file_size=att.file_size,
            mime_type=att.mime_type,
            file_hash=att.file_hash,
            attachment_type=att.attachment_type,
            description=att.description,
            is_malware=att.is_malware,
            is_encrypted=att.is_encrypted,
            incident_id=att.incident_id,
            uploaded_by=att.uploaded_by,
            uploader_name=att.uploader.full_name if att.uploader else None,
            created_at=att.created_at,
        )
        for att in attachments
    ]


@router.post(
    "/incidents/{incident_id}/attachments",
    response_model=AttachmentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_attachment(
    incident_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
    file: UploadFile = File(...),
    attachment_type: str = Form(default=AttachmentType.OTHER.value),
    description: Optional[str] = Form(default=None),
):
    """Upload an attachment for an incident"""
    await get_incident_or_404(db, incident_id)

    # Validate attachment type
    valid_types = [t.value for t in AttachmentType]
    if attachment_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid attachment type. Must be one of: {', '.join(valid_types)}",
        )

    # Read file content
    content = await file.read()

    # Check file size
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024 * 1024)}MB",
        )

    # Generate unique filename
    file_ext = os.path.splitext(file.filename or "")[1]
    unique_filename = f"{uuid.uuid4()}{file_ext}"

    # Calculate hash
    file_hash = hashlib.sha256(content).hexdigest()

    # Create upload directory if needed
    incident_dir = os.path.join(UPLOAD_DIR, incident_id)
    os.makedirs(incident_dir, exist_ok=True)

    # Save file
    file_path = os.path.join(incident_dir, unique_filename)
    with open(file_path, "wb") as f:
        f.write(content)

    # Create attachment record
    attachment = CaseAttachment(
        filename=unique_filename,
        original_filename=file.filename or "unknown",
        file_path=file_path,
        file_size=len(content),
        mime_type=file.content_type or "application/octet-stream",
        file_hash=file_hash,
        attachment_type=attachment_type,
        description=description,
        incident_id=incident_id,
        uploaded_by=current_user.id,
    )

    db.add(attachment)

    # Add timeline event
    await add_timeline_event(
        db=db,
        incident_id=incident_id,
        event_type=TimelineEventType.ATTACHMENT_ADDED.value,
        title="Attachment uploaded",
        actor_id=current_user.id,
        description=f"Uploaded: {file.filename}",
    )

    await db.commit()
    await db.refresh(attachment)

    return AttachmentResponse(
        id=attachment.id,
        filename=attachment.filename,
        original_filename=attachment.original_filename,
        file_size=attachment.file_size,
        mime_type=attachment.mime_type,
        file_hash=attachment.file_hash,
        attachment_type=attachment.attachment_type,
        description=attachment.description,
        is_malware=attachment.is_malware,
        is_encrypted=attachment.is_encrypted,
        incident_id=attachment.incident_id,
        uploaded_by=attachment.uploaded_by,
        uploader_name=current_user.full_name,
        created_at=attachment.created_at,
    )


@router.delete(
    "/incidents/{incident_id}/attachments/{attachment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_attachment(
    incident_id: str,
    attachment_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Delete an attachment"""
    await get_incident_or_404(db, incident_id)

    result = await db.execute(
        select(CaseAttachment).where(
            CaseAttachment.id == attachment_id,
            CaseAttachment.incident_id == incident_id,
        )
    )
    attachment = result.scalar_one_or_none()

    if not attachment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attachment not found",
        )

    # Only uploader or admin can delete
    if attachment.uploaded_by != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this attachment",
        )

    # Delete file from disk
    if os.path.exists(attachment.file_path):
        os.remove(attachment.file_path)

    await db.delete(attachment)
    await db.commit()


# =============================================================================
# Timeline Endpoints
# =============================================================================


@router.get("/incidents/{incident_id}/timeline", response_model=list[TimelineResponse])
async def get_timeline(
    incident_id: str,
    db: DatabaseSession,
    current_user: CurrentUser,
    event_type: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
):
    """Get timeline events for an incident"""
    await get_incident_or_404(db, incident_id)

    query = (
        select(CaseTimeline)
        .options(selectinload(CaseTimeline.actor))
        .where(CaseTimeline.incident_id == incident_id)
    )

    if event_type:
        query = query.where(CaseTimeline.event_type == event_type)

    query = query.order_by(CaseTimeline.created_at.desc()).limit(limit)

    result = await db.execute(query)
    events = result.scalars().all()

    return [
        TimelineResponse(
            id=event.id,
            event_type=event.event_type,
            title=event.title,
            description=event.description,
            old_value=event.old_value,
            new_value=event.new_value,
            metadata=json.loads(event.metadata) if event.metadata else None,
            incident_id=event.incident_id,
            actor_id=event.actor_id,
            actor_name=event.actor.full_name if event.actor else None,
            created_at=event.created_at,
        )
        for event in events
    ]


@router.post(
    "/incidents/{incident_id}/timeline",
    response_model=TimelineResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_timeline_event(
    incident_id: str,
    data: TimelineCreate,
    db: DatabaseSession,
    current_user: CurrentUser,
):
    """Create a custom timeline event"""
    await get_incident_or_404(db, incident_id)

    event = await add_timeline_event(
        db=db,
        incident_id=incident_id,
        event_type=data.event_type,
        title=data.title,
        description=data.description,
        actor_id=current_user.id,
    )

    await db.commit()
    await db.refresh(event)

    return TimelineResponse(
        id=event.id,
        event_type=event.event_type,
        title=event.title,
        description=event.description,
        old_value=event.old_value,
        new_value=event.new_value,
        metadata=json.loads(event.metadata) if event.metadata else None,
        incident_id=event.incident_id,
        actor_id=event.actor_id,
        actor_name=current_user.full_name,
        created_at=event.created_at,
    )
