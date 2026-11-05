"""Audit trail and dashboard API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from aegis.api.deps import get_db, require_permission
from aegis.api.responses import ok, page_meta
from aegis.serializers import audit_public, engagement_public
from aegis.services.audit import AuditService
from aegis.services.auth import AuthContext
from aegis.services.dashboard import DashboardService

router = APIRouter(prefix="/api", tags=["insight"])


@router.get("/audit")
def list_audit(
    entity_type: str = Query(default="", max_length=32),
    entity_id: str = Query(default="", max_length=32),
    actor_email: str = Query(default="", max_length=254),
    action: str = Query(default="", max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> dict:
    offset = (page - 1) * page_size
    rows, total = AuditService(db).list_events(
        entity_type=entity_type or None,
        entity_id=entity_id or None,
        actor_email=actor_email or None,
        action=action or None,
        limit=page_size,
        offset=offset,
    )
    return ok(
        [audit_public(row) for row in rows],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.get("/dashboard/summary")
def dashboard_summary(
    ctx: AuthContext = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> dict:
    summary = DashboardService(db).summary(ctx)
    return ok(
        {
            "clients": summary["clients"],
            "engagements": summary["engagements"],
            "upcoming": [engagement_public(row) for row in summary["upcoming"]],
            "recent_events": [audit_public(row) for row in summary["recent_events"]],
        }
    )
