"""Client ledger API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_auth, get_db, require_permission
from aegis.api.responses import ok, page_meta
from aegis.api.schemas import ClientCreateRequest, ClientUpdateRequest
from aegis.serializers import client_public
from aegis.services.auth import AuthContext
from aegis.services.clients import ClientService

router = APIRouter(prefix="/api/clients", tags=["clients"])


@router.get("")
def list_clients(
    q: str = Query(default="", max_length=100),
    status: str = Query(default="", max_length=20),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    ctx: AuthContext = Depends(require_permission("client:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = ClientService(db)
    rows, total, page, page_size = service.list(
        ctx, q=q, status=status, page=page, page_size=page_size
    )
    counts = service.engagement_counts([row.id for row in rows])
    return ok(
        [client_public(row, engagement_count=counts.get(row.id, 0)) for row in rows],
        page_meta(page=page, page_size=page_size, total=total),
    )


@router.post("", status_code=201)
def create_client(
    payload: ClientCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("client:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    client = ClientService(db).create(
        ctx,
        name=payload.name,
        code=payload.code,
        industry=payload.industry,
        contact_name=payload.contact_name,
        contact_email=payload.contact_email,
        contact_phone=payload.contact_phone,
        status=payload.status,
        notes=payload.notes,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(client_public(client, engagement_count=0))


@router.get("/{client_id}")
def get_client(
    client_id: str,
    ctx: AuthContext = Depends(require_permission("client:read")),
    db: Session = Depends(get_db),
) -> dict:
    service = ClientService(db)
    client = service.get_for(ctx, client_id)
    count = service.engagement_counts([client.id]).get(client.id, 0)
    return ok(client_public(client, engagement_count=count))


@router.patch("/{client_id}")
def update_client(
    client_id: str,
    payload: ClientUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("client:write")),
    db: Session = Depends(get_db),
) -> dict:
    ip, user_agent = client_meta(request)
    fields = payload.model_dump(exclude_unset=True)
    client = ClientService(db).update(ctx, client_id, ip=ip, user_agent=user_agent, **fields)
    count = ClientService(db).engagement_counts([client.id]).get(client.id, 0)
    return ok(client_public(client, engagement_count=count))
