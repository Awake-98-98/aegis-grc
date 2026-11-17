"""Risk assessment, risk item and appetite API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_db, require_permission
from aegis.api.responses import ok, page_meta
from aegis.api.schemas import (
    AssessmentCreateRequest,
    AssessmentUpdateRequest,
    RiskAppetiteRequest,
    RiskCreateRequest,
    RiskUpdateRequest,
)
from aegis.serializers import (
    risk_appetite_public,
    risk_assessment_public,
    risk_item_public,
)
from aegis.services.auth import AuthContext
from aegis.services.risks import DEFAULT_APPETITE, RiskAssessmentService, RiskService

router = APIRouter(prefix="/api", tags=["risks"])


@router.get("/engagements/{engagement_id}/assessments")
def list_assessments(
    engagement_id: str,
    status: str = Query(default="", max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("risk:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = RiskAssessmentService(db)
    rows, total, page, page_size = service.list(
        ctx, engagement_id, status=status, page=page, page_size=page_size
    )
    counts = service.item_counts([row.id for row in rows])
    return ok(
        [
            risk_assessment_public(row, item_count=counts.get(row.id, 0))
            for row in rows
        ],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.post("/engagements/{engagement_id}/assessments", status_code=201)
def create_assessment(
    engagement_id: str,
    payload: AssessmentCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    assessment = RiskAssessmentService(db).create(
        ctx,
        engagement_id,
        title=payload.title,
        assessor=payload.assessor,
        summary=payload.summary,
        code=payload.code,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(risk_assessment_public(assessment, item_count=0))


@router.get("/engagements/{engagement_id}/risk-appetite")
def get_appetite(
    engagement_id: str,
    ctx: AuthContext = Depends(require_permission("risk:read")),
    db: Session = Depends(get_db),
) -> dict:
    row = RiskAssessmentService(db).appetite(ctx, engagement_id)
    return ok(risk_appetite_public(row))


@router.put("/engagements/{engagement_id}/risk-appetite")
def set_appetite(
    engagement_id: str,
    payload: RiskAppetiteRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    row = RiskAssessmentService(db).set_appetite(
        ctx,
        engagement_id,
        max_acceptable_score=payload.max_acceptable_score,
        statement=payload.statement,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(risk_appetite_public(row))


@router.get("/assessments/{assessment_id}")
def get_assessment(
    assessment_id: str,
    ctx: AuthContext = Depends(require_permission("risk:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = RiskAssessmentService(db)
    assessment = service.get_for(ctx, assessment_id)
    items = service.items_for(assessment.id)
    appetite = service.appetite(ctx, assessment.engagement_id)
    threshold = appetite.max_acceptable_score if appetite else DEFAULT_APPETITE
    payload = risk_assessment_public(
        assessment,
        item_count=len(items),
        summary=service.summary(ctx, assessment_id),
    )
    payload["appetite"] = risk_appetite_public(appetite)
    payload["items"] = [
        risk_item_public(item, appetite_threshold=threshold) for item in items
    ]
    return ok(payload)


@router.patch("/assessments/{assessment_id}")
def update_assessment(
    assessment_id: str,
    payload: AssessmentUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    assessment = RiskAssessmentService(db).update(
        ctx,
        assessment_id,
        title=payload.title,
        assessor=payload.assessor,
        summary=payload.summary,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(risk_assessment_public(assessment))


@router.post("/assessments/{assessment_id}/issue")
def issue_assessment(
    assessment_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    assessment = RiskAssessmentService(db).issue(
        ctx, assessment_id, ip=ip, user_agent=user_agent
    )
    return ok(risk_assessment_public(assessment))


@router.delete("/assessments/{assessment_id}")
def delete_assessment(
    assessment_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    RiskAssessmentService(db).delete(
        ctx, assessment_id, ip=ip, user_agent=user_agent
    )
    return ok({"deleted": True})


@router.get("/assessments/{assessment_id}/summary")
def assessment_summary(
    assessment_id: str,
    ctx: AuthContext = Depends(require_permission("risk:read")),
    db: Session = Depends(get_db),
) -> dict:
    return ok(RiskAssessmentService(db).summary(ctx, assessment_id))


@router.get("/assessments/{assessment_id}/risks")
def list_risks(
    assessment_id: str,
    ctx: AuthContext = Depends(require_permission("risk:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = RiskAssessmentService(db)
    assessment = service.get_for(ctx, assessment_id)
    appetite = service.appetite(ctx, assessment.engagement_id)
    threshold = appetite.max_acceptable_score if appetite else DEFAULT_APPETITE
    items = service.items_for(assessment.id)
    return ok(
        [risk_item_public(item, appetite_threshold=threshold) for item in items],
        {"total": len(items)},
    )


@router.post("/assessments/{assessment_id}/risks", status_code=201)
def create_risk(
    assessment_id: str,
    payload: RiskCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    item = RiskService(db).add(
        ctx,
        assessment_id,
        asset_threat_id=payload.asset_threat_id,
        likelihood=payload.likelihood,
        impact=payload.impact,
        residual_likelihood=payload.residual_likelihood,
        residual_impact=payload.residual_impact,
        treatment=payload.treatment,
        rationale=payload.rationale,
        ip=ip,
        user_agent=user_agent,
    )
    assessments = RiskAssessmentService(db)
    assessment = assessments.get_for(ctx, item.assessment_id)
    appetite = assessments.appetite(ctx, assessment.engagement_id)
    threshold = appetite.max_acceptable_score if appetite else DEFAULT_APPETITE
    return ok(risk_item_public(item, appetite_threshold=threshold))


@router.get("/risks/{risk_id}")
def get_risk(
    risk_id: str,
    ctx: AuthContext = Depends(require_permission("risk:read")),
    db: Session = Depends(get_db),
) -> dict:
    return ok(risk_item_public(RiskService(db).get_for(ctx, risk_id)))


@router.patch("/risks/{risk_id}")
def update_risk(
    risk_id: str,
    payload: RiskUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    item = RiskService(db).update(
        ctx,
        risk_id,
        likelihood=payload.likelihood,
        impact=payload.impact,
        residual_likelihood=payload.residual_likelihood,
        residual_impact=payload.residual_impact,
        treatment=payload.treatment,
        rationale=payload.rationale,
        ip=ip,
        user_agent=user_agent,
    )
    assessments = RiskAssessmentService(db)
    assessment = assessments.get_for(ctx, item.assessment_id)
    appetite = assessments.appetite(ctx, assessment.engagement_id)
    threshold = appetite.max_acceptable_score if appetite else DEFAULT_APPETITE
    return ok(risk_item_public(item, appetite_threshold=threshold))


@router.delete("/risks/{risk_id}")
def delete_risk(
    risk_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("risk:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    RiskService(db).delete(ctx, risk_id, ip=ip, user_agent=user_agent)
    return ok({"deleted": True})


@router.get("/assessments/{assessment_id}/compare/{baseline_id}")
def compare_assessments(
    assessment_id: str,
    baseline_id: str,
    ctx: AuthContext = Depends(require_permission("risk:read")),
    db: Session = Depends(get_db),
) -> dict:
    result = RiskAssessmentService(db).compare(ctx, assessment_id, baseline_id)
    return ok(
        {
            "baseline": risk_assessment_public(
                result["baseline"],
                item_count=sum(
                    1 for row in result["rows"] if row["before"] is not None
                ),
            ),
            "current": risk_assessment_public(
                result["current"],
                item_count=sum(
                    1 for row in result["rows"] if row["after"] is not None
                ),
            ),
            "summary": result["summary"],
            "rows": result["rows"],
        }
    )
