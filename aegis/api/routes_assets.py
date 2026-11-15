"""Asset, threat and asset-threat link API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_db, require_permission
from aegis.api.responses import ok, page_meta
from aegis.api.schemas import (
    AssetCreateRequest,
    AssetThreatLinkRequest,
    AssetThreatUpdateRequest,
    AssetUpdateRequest,
    ThreatCreateRequest,
    ThreatUpdateRequest,
)
from aegis.errors import ValidationFailure
from aegis.serializers import asset_public, asset_threat_public, threat_public
from aegis.services.asset_import import AssetImportService, csv_template
from aegis.services.assets import AssetService
from aegis.services.auth import AuthContext
from aegis.services.threats import ThreatService

router = APIRouter(prefix="/api", tags=["assets"])

MAX_UPLOAD_BYTES = 2 * 1024 * 1024


@router.get("/engagements/{engagement_id}/assets")
def list_assets(
    engagement_id: str,
    q: str = Query(default="", max_length=100),
    category: str = Query(default="", max_length=32),
    asset_type: str = Query(default="", max_length=20),
    criticality: str = Query(default="", max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("asset:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = AssetService(db)
    rows, total, page, page_size = service.list(
        ctx,
        engagement_id,
        q=q,
        category=category,
        asset_type=asset_type,
        criticality=criticality,
        page=page,
        page_size=page_size,
    )
    counts = service.threat_counts([row.id for row in rows])
    return ok(
        [asset_public(row, threat_count=counts.get(row.id, 0)) for row in rows],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.post("/engagements/{engagement_id}/assets", status_code=201)
def create_asset(
    engagement_id: str,
    payload: AssetCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    asset = AssetService(db).create(
        ctx,
        engagement_id,
        name=payload.name,
        code=payload.code,
        asset_type=payload.asset_type,
        category=payload.category,
        owner=payload.owner,
        department=payload.department,
        location=payload.location,
        description=payload.description,
        confidentiality=payload.confidentiality,
        integrity=payload.integrity,
        availability=payload.availability,
        lifecycle_status=payload.lifecycle_status,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(asset_public(asset, threat_count=0))


@router.get("/engagements/{engagement_id}/assets/summary")
def asset_summary(
    engagement_id: str,
    ctx: AuthContext = Depends(require_permission("asset:read")),
    db: Session = Depends(get_db),
) -> dict:
    return ok(AssetService(db).summary(ctx, engagement_id))


@router.post("/engagements/{engagement_id}/assets/import")
async def import_assets(
    engagement_id: str,
    request: Request,
    file: UploadFile = File(...),
    ctx: AuthContext = Depends(require_permission("asset:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    payload = await file.read()
    if len(payload) > MAX_UPLOAD_BYTES:
        raise ValidationFailure(
            "file is larger than 2 MB",
            details={"limit": MAX_UPLOAD_BYTES, "received": len(payload)},
        )
    result = AssetImportService(db).import_bytes(
        ctx,
        engagement_id,
        payload,
        filename=file.filename or "",
        ip=ip,
        user_agent=user_agent,
    )
    return ok(result)


@router.get("/assets/template.csv", response_class=PlainTextResponse)
def download_template(
    ctx: AuthContext = Depends(require_permission("asset:read")),
) -> PlainTextResponse:
    return PlainTextResponse(
        csv_template(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="asset-template.csv"'},
    )


@router.get("/assets/{asset_id}")
def get_asset(
    asset_id: str,
    ctx: AuthContext = Depends(require_permission("asset:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = AssetService(db)
    asset = service.get_for(ctx, asset_id)
    counts = service.threat_counts([asset.id])
    return ok(asset_public(asset, threat_count=counts.get(asset.id, 0)))


@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: str,
    payload: AssetUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    asset = AssetService(db).update(
        ctx,
        asset_id,
        name=payload.name,
        asset_type=payload.asset_type,
        category=payload.category,
        owner=payload.owner,
        department=payload.department,
        location=payload.location,
        description=payload.description,
        confidentiality=payload.confidentiality,
        integrity=payload.integrity,
        availability=payload.availability,
        lifecycle_status=payload.lifecycle_status,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(asset_public(asset))


@router.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    AssetService(db).delete(ctx, asset_id, ip=ip, user_agent=user_agent)
    return ok({"id": asset_id, "deleted": True})


@router.get("/assets/{asset_id}/threats")
def list_asset_threats(
    asset_id: str,
    ctx: AuthContext = Depends(require_permission("asset:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = AssetService(db)
    service.get_for(ctx, asset_id)
    links = service.links_for(asset_id)
    return ok([asset_threat_public(link) for link in links])


@router.post("/assets/{asset_id}/threats", status_code=201)
def link_asset_threat(
    asset_id: str,
    payload: AssetThreatLinkRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    link = AssetService(db).link_threat(
        ctx,
        asset_id,
        threat_id=payload.threat_id,
        vulnerability=payload.vulnerability,
        exposure=payload.exposure,
        notes=payload.notes,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(asset_threat_public(link))


@router.patch("/asset-threats/{link_id}")
def update_asset_threat(
    link_id: str,
    payload: AssetThreatUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    link = AssetService(db).update_link(
        ctx,
        link_id,
        vulnerability=payload.vulnerability,
        exposure=payload.exposure,
        notes=payload.notes,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(asset_threat_public(link))


@router.delete("/asset-threats/{link_id}")
def unlink_asset_threat(
    link_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    AssetService(db).unlink_threat(ctx, link_id, ip=ip, user_agent=user_agent)
    return ok({"id": link_id, "deleted": True})


@router.get("/engagements/{engagement_id}/threats")
def list_threats(
    engagement_id: str,
    q: str = Query(default="", max_length=100),
    category: str = Query(default="", max_length=32),
    actor: str = Query(default="", max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("threat:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = ThreatService(db)
    rows, total, page, page_size = service.list(
        ctx,
        engagement_id,
        q=q,
        category=category,
        actor=actor,
        page=page,
        page_size=page_size,
    )
    counts = service.asset_counts([row.id for row in rows])
    return ok(
        [threat_public(row, asset_count=counts.get(row.id, 0)) for row in rows],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.post("/engagements/{engagement_id}/threats", status_code=201)
def create_threat(
    engagement_id: str,
    payload: ThreatCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("threat:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    threat = ThreatService(db).create(
        ctx,
        engagement_id,
        name=payload.name,
        code=payload.code,
        category=payload.category,
        actor=payload.actor,
        description=payload.description,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(threat_public(threat, asset_count=0))


@router.get("/threats/{threat_id}")
def get_threat(
    threat_id: str,
    ctx: AuthContext = Depends(require_permission("threat:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = ThreatService(db)
    threat = service.get_for(ctx, threat_id)
    counts = service.asset_counts([threat.id])
    return ok(threat_public(threat, asset_count=counts.get(threat.id, 0)))


@router.patch("/threats/{threat_id}")
def update_threat(
    threat_id: str,
    payload: ThreatUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("threat:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    threat = ThreatService(db).update(
        ctx,
        threat_id,
        name=payload.name,
        category=payload.category,
        actor=payload.actor,
        description=payload.description,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(threat_public(threat))


@router.delete("/threats/{threat_id}")
def delete_threat(
    threat_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("threat:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    ThreatService(db).delete(ctx, threat_id, ip=ip, user_agent=user_agent)
    return ok({"id": threat_id, "deleted": True})
