"""Control catalog, statement of applicability and coverage API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_db, require_permission
from aegis.api.responses import ok, page_meta
from aegis.api.schemas import (
    RiskControlLinkRequest,
    SoAGenerateRequest,
    SoAUpdateRequest,
)
from aegis.serializers import (
    control_framework_public,
    control_public,
    risk_assessment_public,
    risk_control_link_public,
    risk_item_public,
    soa_entry_public,
)
from aegis.services.auth import AuthContext
from aegis.services.controls import ControlService, RiskControlService, SoAService

router = APIRouter(prefix="/api", tags=["controls"])


@router.get("/frameworks")
def list_frameworks(
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = ControlService(db)
    rows = service.frameworks(ctx)
    counts = service.framework_counts([row.id for row in rows])
    return ok(
        [
            control_framework_public(row, control_count=counts.get(row.id, 0))
            for row in rows
        ]
    )


@router.get("/frameworks/{framework_id}")
def get_framework(
    framework_id: str,
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = ControlService(db)
    framework = service.framework(ctx, framework_id)
    control_count = service.framework_counts([framework.id]).get(framework.id, 0)
    payload = control_framework_public(framework, control_count=control_count)
    payload["domains"] = service.domains(ctx, framework.id)
    return ok(payload)


@router.get("/frameworks/{framework_id}/controls")
def list_controls(
    framework_id: str,
    q: str = Query(default="", max_length=120),
    domain: str = Query(default="", max_length=32),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows, total, page, page_size = ControlService(db).controls(
        ctx,
        framework_id,
        q=q,
        domain=domain,
        page=page,
        page_size=page_size,
    )
    return ok(
        [control_public(row) for row in rows],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.get("/controls/{control_id}")
def get_control(
    control_id: str,
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    return ok(control_public(ControlService(db).control(ctx, control_id)))


@router.get("/engagements/{engagement_id}/soa")
def list_soa(
    engagement_id: str,
    framework_id: str = Query(min_length=1, max_length=32),
    q: str = Query(default="", max_length=120),
    domain: str = Query(default="", max_length=32),
    status: str = Query(default="", max_length=20),
    applicable: bool | None = Query(default=None),
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = SoAService(db).entries(
        ctx,
        engagement_id,
        framework_id,
        q=q,
        domain=domain,
        status=status,
        applicable=applicable,
    )
    return ok(
        [soa_entry_public(entry, control=control) for entry, control in rows],
        {"total": len(rows)},
    )


@router.post("/engagements/{engagement_id}/soa/generate")
def generate_soa(
    engagement_id: str,
    payload: SoAGenerateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("control:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    result = SoAService(db).generate(
        ctx,
        engagement_id,
        payload.framework_id,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(result)


@router.get("/engagements/{engagement_id}/soa/summary")
def soa_summary(
    engagement_id: str,
    framework_id: str = Query(min_length=1, max_length=32),
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    return ok(SoAService(db).summary(ctx, engagement_id, framework_id))


@router.patch("/soa/{entry_id}")
def update_soa_entry(
    entry_id: str,
    payload: SoAUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("control:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    entry = SoAService(db).update(
        ctx,
        entry_id,
        applicable=payload.applicable,
        implementation_status=payload.implementation_status,
        justification=payload.justification,
        owner=payload.owner,
        notes=payload.notes,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(soa_entry_public(entry))


@router.get("/assessments/{assessment_id}/coverage")
def assessment_coverage(
    assessment_id: str,
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    result = RiskControlService(db).coverage(ctx, assessment_id)
    return ok(
        {
            "assessment": risk_assessment_public(
                result["assessment"], item_count=len(result["rows"])
            ),
            "summary": result["summary"],
            "rows": [
                {
                    "risk": risk_item_public(row["item"]),
                    "covered": row["covered"],
                    "frameworks": row["frameworks"],
                    "links": [
                        risk_control_link_public(link) for link in row["links"]
                    ],
                }
                for row in result["rows"]
            ],
        }
    )


@router.get("/risks/{risk_id}/controls")
def list_risk_controls(
    risk_id: str,
    ctx: AuthContext = Depends(require_permission("control:read")),
    db: Session = Depends(get_db),
) -> dict:
    rows = RiskControlService(db).links_for_risk(ctx, risk_id)
    return ok([risk_control_link_public(link) for link in rows])


@router.post("/risks/{risk_id}/controls", status_code=201)
def link_risk_control(
    risk_id: str,
    payload: RiskControlLinkRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("control:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    link = RiskControlService(db).link(
        ctx,
        risk_id,
        control_id=payload.control_id,
        coverage=payload.coverage,
        notes=payload.notes,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(risk_control_link_public(link))


@router.delete("/risk-controls/{link_id}")
def unlink_risk_control(
    link_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("control:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    RiskControlService(db).unlink(ctx, link_id, ip=ip, user_agent=user_agent)
    return ok({"deleted": True})
