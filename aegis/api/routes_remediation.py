"""Remediation task and evidence API."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_db, get_settings, require_permission
from aegis.api.responses import ok, page_meta
from aegis.api.schemas import (
    RemediationCreateRequest,
    RemediationFromRiskRequest,
    RemediationTransitionRequest,
    RemediationUpdateRequest,
)
from aegis.config import Settings
from aegis.serializers import evidence_public, remediation_task_public
from aegis.services.auth import AuthContext
from aegis.services.remediation import EvidenceService, RemediationService
from aegis.storage.cas import EvidenceStore

router = APIRouter(prefix="/api", tags=["remediation"])


def _remediation(db: Session, settings: Settings) -> RemediationService:
    return RemediationService(db, EvidenceStore(settings.evidence_path))


def _evidence(db: Session, settings: Settings) -> EvidenceService:
    return EvidenceService(db, EvidenceStore(settings.evidence_path))


@router.get("/engagements/{engagement_id}/remediation-tasks")
def list_tasks(
    engagement_id: str,
    status: str = Query(default="", max_length=20),
    priority: str = Query(default="", max_length=20),
    overdue: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("remediation:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    rows, total, page, page_size = _remediation(db, settings).list(
        ctx,
        engagement_id,
        status=status,
        priority=priority,
        overdue=overdue,
        page=page,
        page_size=page_size,
    )
    counts = EvidenceService(db, EvidenceStore(settings.evidence_path)).counts_for_tasks(
        [row.id for row in rows]
    )
    return ok(
        [
            remediation_task_public(row, evidence_count=counts.get(row.id, 0))
            for row in rows
        ],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.post("/engagements/{engagement_id}/remediation-tasks", status_code=201)
def create_task(
    engagement_id: str,
    payload: RemediationCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("remediation:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    task = _remediation(db, settings).create(
        ctx,
        engagement_id,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        owner=payload.owner,
        owner_user_id=payload.owner_user_id,
        control_id=payload.control_id,
        due_date=payload.due_date,
        notes=payload.notes,
        risk_item_id=payload.risk_item_id,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(remediation_task_public(task, evidence_count=0))


@router.get("/engagements/{engagement_id}/remediation/summary")
def remediation_summary(
    engagement_id: str,
    ctx: AuthContext = Depends(require_permission("remediation:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    return ok(_remediation(db, settings).summary(ctx, engagement_id))


@router.get("/remediation-tasks/{task_id}")
def get_task(
    task_id: str,
    ctx: AuthContext = Depends(require_permission("remediation:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    service = _remediation(db, settings)
    task = service.get_for(ctx, task_id)
    evidence = EvidenceService(db, EvidenceStore(settings.evidence_path)).list(
        ctx, task.id
    )
    payload = remediation_task_public(task, evidence_count=len(evidence))
    payload["evidence"] = [evidence_public(row) for row in evidence]
    return ok(payload)


@router.patch("/remediation-tasks/{task_id}")
def update_task(
    task_id: str,
    payload: RemediationUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("remediation:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    task = _remediation(db, settings).update(
        ctx,
        task_id,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        owner=payload.owner,
        owner_user_id=payload.owner_user_id,
        control_id=payload.control_id,
        due_date=payload.due_date,
        notes=payload.notes,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(remediation_task_public(task))


@router.post("/remediation-tasks/{task_id}/transition")
def transition_task(
    task_id: str,
    payload: RemediationTransitionRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("remediation:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    task = _remediation(db, settings).transition(
        ctx,
        task_id,
        payload.status,
        note=payload.note,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(remediation_task_public(task))


@router.delete("/remediation-tasks/{task_id}")
def delete_task(
    task_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("remediation:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    _remediation(db, settings).delete(
        ctx, task_id, ip=ip, user_agent=user_agent
    )
    return ok({"deleted": True})


@router.post("/risks/{risk_id}/remediation", status_code=201)
def create_from_risk(
    risk_id: str,
    payload: RemediationFromRiskRequest | None = None,
    request: Request = None,
    ctx: AuthContext = Depends(require_permission("remediation:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    task = _remediation(db, settings).create_from_risk(
        ctx,
        risk_id,
        title=payload.title if payload else None,
        description=payload.description if payload else "",
        priority=payload.priority if payload else "medium",
        owner=payload.owner if payload else "",
        owner_user_id=payload.owner_user_id if payload else None,
        control_id=payload.control_id if payload else None,
        due_date=payload.due_date if payload else None,
        notes=payload.notes if payload else "",
        ip=ip,
        user_agent=user_agent,
    )
    return ok(remediation_task_public(task, evidence_count=0))


@router.get("/remediation-tasks/{task_id}/evidence")
def list_evidence(
    task_id: str,
    ctx: AuthContext = Depends(require_permission("evidence:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    rows = _evidence(db, settings).list(ctx, task_id)
    return ok([evidence_public(row) for row in rows], {"total": len(rows)})


@router.post("/remediation-tasks/{task_id}/evidence", status_code=201)
async def attach_evidence(
    task_id: str,
    request: Request,
    file: UploadFile = File(...),
    ctx: AuthContext = Depends(require_permission("evidence:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    data = await file.read()
    row, created = _evidence(db, settings).attach(
        ctx,
        task_id,
        filename=file.filename or "",
        data=data,
        content_type=file.content_type or "",
        ip=ip,
        user_agent=user_agent,
    )
    payload = evidence_public(row)
    payload["created"] = created
    return ok(payload)


@router.get("/evidence/{evidence_id}/download")
def download_evidence(
    evidence_id: str,
    ctx: AuthContext = Depends(require_permission("evidence:read")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    row, data = _evidence(db, settings).download(ctx, evidence_id)
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(row.filename)}"
    }
    return Response(
        content=data,
        media_type=row.content_type or "application/octet-stream",
        headers=headers,
    )


@router.delete("/evidence/{evidence_id}")
def delete_evidence(
    evidence_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("evidence:write")),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    _evidence(db, settings).delete(
        ctx, evidence_id, ip=ip, user_agent=user_agent
    )
    return ok({"deleted": True})
