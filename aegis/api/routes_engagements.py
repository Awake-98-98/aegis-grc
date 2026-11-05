"""Engagement and stakeholder API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_db, require_permission
from aegis.api.responses import ok, page_meta
from aegis.api.schemas import (
    EngagementCreateRequest,
    EngagementUpdateRequest,
    StakeholderCreateRequest,
    StakeholderUpdateRequest,
    TransitionRequest,
)
from aegis.serializers import engagement_public, stakeholder_public
from aegis.services.auth import AuthContext
from aegis.services.engagements import EngagementService
from aegis.services.stakeholders import StakeholderService

router = APIRouter(prefix="/api", tags=["engagements"])


@router.get("/engagements")
def list_engagements(
    q: str = Query(default="", max_length=100),
    status: str = Query(default="", max_length=20),
    client_id: str = Query(default="", max_length=32),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("engagement:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows, total, page, page_size = EngagementService(db).list(
        ctx, q=q, status=status, client_id=client_id, page=page, page_size=page_size
    )
    return ok(
        [engagement_public(row) for row in rows],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.post("/engagements", status_code=201)
def create_engagement(
    payload: EngagementCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("engagement:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    engagement = EngagementService(db).create(
        ctx,
        client_id=payload.client_id,
        name=payload.name,
        code=payload.code,
        engagement_type=payload.engagement_type,
        start_date=payload.start_date,
        end_date=payload.end_date,
        lead_user_id=payload.lead_user_id,
        scope_summary=payload.scope_summary,
        objectives=payload.objectives,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(engagement_public(engagement))


@router.get("/engagements/{engagement_id}")
def get_engagement(
    engagement_id: str,
    ctx: AuthContext = Depends(require_permission("engagement:read")),
    db: Session = Depends(get_db),
) -> dict:
    engagement = EngagementService(db).get_for(ctx, engagement_id)
    return ok(engagement_public(engagement))


@router.patch("/engagements/{engagement_id}")
def update_engagement(
    engagement_id: str,
    payload: EngagementUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("engagement:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    fields = payload.model_dump(exclude_unset=True)
    engagement = EngagementService(db).update(
        ctx, engagement_id, ip=ip, user_agent=user_agent, **fields
    )
    return ok(engagement_public(engagement))


@router.post("/engagements/{engagement_id}/transition")
def transition_engagement(
    engagement_id: str,
    payload: TransitionRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("engagement:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    engagement = EngagementService(db).transition(
        ctx,
        engagement_id,
        payload.status,
        note=payload.note,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(engagement_public(engagement))


@router.get("/engagements/{engagement_id}/stakeholders")
def list_stakeholders(
    engagement_id: str,
    ctx: AuthContext = Depends(require_permission("engagement:read")),
    db: Session = Depends(get_db),
) -> dict:
    EngagementService(db).get_for(ctx, engagement_id)
    rows = StakeholderService(db).list_for(engagement_id)
    return ok([stakeholder_public(row) for row in rows])


@router.post("/engagements/{engagement_id}/stakeholders", status_code=201)
def create_stakeholder(
    engagement_id: str,
    payload: StakeholderCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("stakeholder:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    row = StakeholderService(db).create(
        ctx,
        engagement_id,
        name=payload.name,
        role_title=payload.role_title,
        organization=payload.organization,
        email=payload.email,
        influence=payload.influence,
        interest=payload.interest,
        notes=payload.notes,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(stakeholder_public(row))


@router.patch("/stakeholders/{stakeholder_id}")
def update_stakeholder(
    stakeholder_id: str,
    payload: StakeholderUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("stakeholder:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    fields = payload.model_dump(exclude_unset=True)
    row = StakeholderService(db).update(
        ctx, stakeholder_id, ip=ip, user_agent=user_agent, **fields
    )
    return ok(stakeholder_public(row))


@router.delete("/stakeholders/{stakeholder_id}")
def delete_stakeholder(
    stakeholder_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("stakeholder:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    StakeholderService(db).delete(ctx, stakeholder_id, ip=ip, user_agent=user_agent)
    return ok({"deleted": True})
