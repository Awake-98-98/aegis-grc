"""Server-rendered web console.

Forms post to HTML routes; every state-changing form carries the session's
CSRF token in a hidden field and is checked before the service call. The web
layer never re-implements business rules: it validates CSRF, calls the same
service as the API, and renders the result.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.api.responses import clear_session_cookie, set_session_cookie
from aegis.config import Settings
from aegis.errors import CsrfFailure, Unauthorized, ValidationFailure
from aegis.models import AssetThreat, User
from aegis.security.tokens import csrf_matches
from aegis.security.validation import (
    ASSET_CATEGORIES,
    ASSET_LIFECYCLE,
    ASSET_TYPES,
    CLIENT_STATUSES,
    ENGAGEMENT_STATUSES,
    ENGAGEMENT_TYPES,
    LEVELS,
    RISK_ASSESSMENT_STATUSES,
    RISK_TREATMENTS,
)
from aegis.risk.matrix import (
    IMPACT_LABELS,
    LIKELIHOOD_LABELS,
    MATRIX_MAX,
    MATRIX_MIN,
    SEVERITY_LABELS,
    severity_for,
)
from aegis.serializers import audit_public
from aegis.services.asset_import import AssetImportService
from aegis.services.assets import CRITICALITY_LABELS, AssetService
from aegis.services.auth import AuthContext, AuthService
from aegis.services.clients import ClientService
from aegis.services.dashboard import DashboardService
from aegis.services.engagements import ALLOWED_TRANSITIONS, EngagementService
from aegis.services.risks import (
    ASSESSMENT_STATUS_LABELS,
    DEFAULT_APPETITE,
    TREATMENT_LABELS,
    RiskAssessmentService,
    RiskService,
)
from aegis.services.stakeholders import StakeholderService
from aegis.services.threats import ThreatService

router = APIRouter(tags=["web"])


# ----------------------------------------------------------------- dependencies
def get_web_db(request: Request) -> Iterator[Session]:
    db: Session = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def get_web_settings(request: Request) -> Settings:
    return request.app.state.settings


def _ip(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "")
    return ip[:64], request.headers.get("user-agent", "")[:255]


def _optional_ctx(request: Request, db: Session, settings: Settings) -> AuthContext | None:
    token = request.cookies.get(settings.cookie_name)
    if not token:
        return None
    return AuthService(db, settings).resolve(token, "cookie")


def _require_ctx(request: Request, db: Session, settings: Settings) -> AuthContext:
    ctx = _optional_ctx(request, db, settings)
    if ctx is None:
        raise Unauthorized("login required")
    return ctx


def _render(request: Request, template: str, ctx: AuthContext | None, *, nav: str = "", **context):
    templates = request.app.state.templates
    base = {
        "current_user": ctx.user if ctx else None,
        "csrf_token": ctx.session.csrf_token if ctx else "",
        "nav": nav,
    }
    base.update(context)
    return templates.TemplateResponse(request, template, base)


async def _form(request: Request) -> dict[str, str]:
    form = await request.form()
    return {key: str(value) for key, value in form.items()}


def _check_csrf(ctx: AuthContext, form: dict[str, str]) -> None:
    if not csrf_matches(ctx.session.csrf_token, form.get("csrf_token")):
        raise CsrfFailure("invalid or missing CSRF token")


def _active_users(db: Session) -> list[User]:
    return list(
        db.execute(select(User).where(User.is_active.is_(True)).order_by(User.display_name)).scalars()
    )


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=303)


# ----------------------------------------------------------------------- public
@router.get("/setup", response_class=HTMLResponse)
def setup_page(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _optional_ctx(request, db, settings)
    if ctx is not None:
        return _redirect("/")
    if AuthService(db, settings).has_users():
        return _redirect("/login")
    return _render(request, "setup.html", None, nav="setup")


@router.post("/setup", response_class=HTMLResponse)
async def setup_submit(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _optional_ctx(request, db, settings)
    if AuthService(db, settings).has_users():
        return _redirect("/login")
    form = await _form(request)
    ip, user_agent = _ip(request)
    _, result = AuthService(db, settings).bootstrap(
        email=form.get("email", ""),
        display_name=form.get("display_name", ""),
        password=form.get("password", ""),
        ip=ip,
        user_agent=user_agent,
    )
    redirect = _redirect("/")
    set_session_cookie(redirect, settings, result.token)
    return redirect


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _optional_ctx(request, db, settings)
    if ctx is not None:
        return _redirect("/")
    if not AuthService(db, settings).has_users():
        return _redirect("/setup")
    return _render(request, "login.html", None, nav="login")


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    form = await _form(request)
    ip, user_agent = _ip(request)
    result = AuthService(db, settings).login(
        email=form.get("email", ""),
        password=form.get("password", ""),
        ip=ip,
        user_agent=user_agent,
    )
    redirect = _redirect("/")
    set_session_cookie(redirect, settings, result.token)
    return redirect


@router.post("/logout")
async def logout_submit(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _optional_ctx(request, db, settings)
    if ctx:
        form = await _form(request)
        _check_csrf(ctx, form)
        ip, user_agent = _ip(request)
        AuthService(db, settings).logout(ctx, ip=ip, user_agent=user_agent)
    redirect = _redirect("/login")
    clear_session_cookie(redirect, settings)
    return redirect


# -------------------------------------------------------------------- dashboard
@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    summary = DashboardService(db).summary(ctx)
    return _render(
        request,
        "dashboard.html",
        ctx,
        nav="dashboard",
        summary=summary,
        client_labels=summary["clients"]["by_status"],
        engagement_labels=summary["engagements"]["by_status"],
    )


# ----------------------------------------------------------------------- clients
@router.get("/clients", response_class=HTMLResponse)
def clients_page(
    request: Request,
    q: str = "",
    status: str = "",
    page: int = 1,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    rows, total, page, page_size = ClientService(db).list(
        ctx, q=q, status=status, page=page, page_size=20
    )
    counts = ClientService(db).engagement_counts([row.id for row in rows])
    return _render(
        request,
        "clients/list.html",
        ctx,
        nav="clients",
        clients=rows,
        counts=counts,
        total=total,
        page=page,
        pages=(total + page_size - 1) // page_size,
        q=q,
        status=status,
        statuses=CLIENT_STATUSES,
    )


@router.get("/clients/new", response_class=HTMLResponse)
def client_new_page(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    return _render(
        request,
        "clients/form.html",
        ctx,
        nav="clients",
        mode="create",
        client=None,
        statuses=CLIENT_STATUSES,
        form_action="/clients",
    )


@router.post("/clients", response_class=HTMLResponse)
async def client_create_submit(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    client = ClientService(db).create(
        ctx,
        name=form.get("name", ""),
        code=form.get("code") or None,
        industry=form.get("industry", ""),
        contact_name=form.get("contact_name", ""),
        contact_email=form.get("contact_email", ""),
        contact_phone=form.get("contact_phone", ""),
        status=form.get("status", "prospect"),
        notes=form.get("notes", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/clients/{client.id}")


@router.get("/clients/{client_id}", response_class=HTMLResponse)
def client_detail_page(
    client_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    service = ClientService(db)
    client = service.get_for(ctx, client_id)
    engagements = EngagementService(db).list_for_client(ctx, client_id)
    timeline = [audit_public(row) for row in _entity_timeline(db, "client", client_id)]
    return _render(
        request,
        "clients/detail.html",
        ctx,
        nav="clients",
        client=client,
        engagements=engagements,
        timeline=timeline,
    )


@router.get("/clients/{client_id}/edit", response_class=HTMLResponse)
def client_edit_page(
    client_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    client = ClientService(db).get_for(ctx, client_id)
    return _render(
        request,
        "clients/form.html",
        ctx,
        nav="clients",
        mode="edit",
        client=client,
        statuses=CLIENT_STATUSES,
        form_action=f"/clients/{client.id}/edit",
    )


@router.post("/clients/{client_id}/edit", response_class=HTMLResponse)
async def client_edit_submit(
    client_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    ClientService(db).update(
        ctx,
        client_id,
        name=form.get("name", ""),
        industry=form.get("industry", ""),
        contact_name=form.get("contact_name", ""),
        contact_email=form.get("contact_email", ""),
        contact_phone=form.get("contact_phone", ""),
        status=form.get("status", "prospect"),
        notes=form.get("notes", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/clients/{client_id}")


# --------------------------------------------------------------------- engagements
@router.get("/engagements", response_class=HTMLResponse)
def engagements_page(
    request: Request,
    q: str = "",
    status: str = "",
    client_id: str = "",
    page: int = 1,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    rows, total, page, page_size = EngagementService(db).list(
        ctx, q=q, status=status, client_id=client_id, page=page, page_size=20
    )
    return _render(
        request,
        "engagements/list.html",
        ctx,
        nav="engagements",
        engagements=rows,
        total=total,
        page=page,
        pages=(total + page_size - 1) // page_size,
        q=q,
        status=status,
        client_id=client_id,
        statuses=ENGAGEMENT_STATUSES,
    )


@router.get("/engagements/new", response_class=HTMLResponse)
def engagement_new_page(
    request: Request,
    client_id: str = "",
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    clients, _, _, _ = ClientService(db).list(ctx, page_size=200)
    return _render(
        request,
        "engagements/form.html",
        ctx,
        nav="engagements",
        mode="create",
        engagement=None,
        clients=clients,
        users=_active_users(db),
        types=ENGAGEMENT_TYPES,
        selected_client_id=client_id,
        form_action="/engagements",
    )


@router.post("/engagements", response_class=HTMLResponse)
async def engagement_create_submit(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    engagement = EngagementService(db).create(
        ctx,
        client_id=form.get("client_id", ""),
        name=form.get("name", ""),
        engagement_type=form.get("engagement_type", "risk_assessment"),
        start_date=form.get("start_date") or None,
        end_date=form.get("end_date") or None,
        lead_user_id=form.get("lead_user_id") or None,
        scope_summary=form.get("scope_summary", ""),
        objectives=form.get("objectives", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/engagements/{engagement.id}")


@router.get("/engagements/{engagement_id}", response_class=HTMLResponse)
def engagement_detail_page(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    service = EngagementService(db)
    engagement = service.get_for(ctx, engagement_id)
    stakeholders = service.stakeholders(engagement_id)
    lead = db.get(User, engagement.lead_user_id) if engagement.lead_user_id else None
    timeline = [audit_public(row) for row in _entity_timeline(db, "engagement", engagement_id)]
    return _render(
        request,
        "engagements/detail.html",
        ctx,
        nav="engagements",
        engagement=engagement,
        stakeholders=stakeholders,
        lead=lead,
        timeline=timeline,
        asset_summary=AssetService(db).summary(ctx, engagement_id),
        assessment_count=RiskAssessmentService(db).list(
            ctx, engagement_id, page_size=1
        )[1],
        next_statuses=sorted(ALLOWED_TRANSITIONS.get(engagement.status, set())),
        statuses=ENGAGEMENT_STATUSES,
        levels=LEVELS,
    )


@router.get("/engagements/{engagement_id}/edit", response_class=HTMLResponse)
def engagement_edit_page(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    engagement = EngagementService(db).get_for(ctx, engagement_id)
    clients, _, _, _ = ClientService(db).list(ctx, page_size=200)
    return _render(
        request,
        "engagements/form.html",
        ctx,
        nav="engagements",
        mode="edit",
        engagement=engagement,
        clients=clients,
        users=_active_users(db),
        types=ENGAGEMENT_TYPES,
        selected_client_id=engagement.client_id,
        form_action=f"/engagements/{engagement.id}/edit",
    )


@router.post("/engagements/{engagement_id}/edit", response_class=HTMLResponse)
async def engagement_edit_submit(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    EngagementService(db).update(
        ctx,
        engagement_id,
        name=form.get("name", ""),
        engagement_type=form.get("engagement_type", "risk_assessment"),
        start_date=form.get("start_date") or None,
        end_date=form.get("end_date") or None,
        lead_user_id=form.get("lead_user_id") or None,
        scope_summary=form.get("scope_summary", ""),
        objectives=form.get("objectives", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/engagements/{engagement_id}")


@router.post("/engagements/{engagement_id}/transition", response_class=HTMLResponse)
async def engagement_transition_submit(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    EngagementService(db).transition(
        ctx,
        engagement_id,
        form.get("status", ""),
        note=form.get("note", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/engagements/{engagement_id}")


# ------------------------------------------------------------------------ stakeholders
@router.post("/engagements/{engagement_id}/stakeholders", response_class=HTMLResponse)
async def stakeholder_create_submit(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    StakeholderService(db).create(
        ctx,
        engagement_id,
        name=form.get("name", ""),
        role_title=form.get("role_title", ""),
        organization=form.get("organization", ""),
        email=form.get("email", ""),
        influence=form.get("influence", "medium"),
        interest=form.get("interest", "medium"),
        notes=form.get("notes", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/engagements/{engagement_id}")


@router.post("/stakeholders/{stakeholder_id}/delete", response_class=HTMLResponse)
async def stakeholder_delete_submit(
    stakeholder_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    stakeholder = StakeholderService(db).get(stakeholder_id)
    engagement_id = stakeholder.engagement_id
    StakeholderService(db).delete(
        ctx, stakeholder_id, ip=ip, user_agent=user_agent
    )
    return _redirect(f"/engagements/{engagement_id}")


# ------------------------------------------------------------------- assets
@router.get("/engagements/{engagement_id}/assets", response_class=HTMLResponse)
def assets_page(
    engagement_id: str,
    request: Request,
    q: str = "",
    category: str = "",
    asset_type: str = "",
    criticality: str = "",
    page: int = 1,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    engagement = EngagementService(db).get_for(ctx, engagement_id)
    service = AssetService(db)
    rows, total, page, page_size = service.list(
        ctx,
        engagement_id,
        q=q,
        category=category,
        asset_type=asset_type,
        criticality=criticality,
        page=page,
        page_size=40,
    )
    counts = service.threat_counts([row.id for row in rows])
    pages = (total + page_size - 1) // page_size if total else 1
    return _render(
        request,
        "assets/list.html",
        ctx,
        nav="engagements",
        engagement=engagement,
        assets=rows,
        threat_counts=counts,
        summary=service.summary(ctx, engagement_id),
        total=total,
        page=page,
        pages=pages,
        q=q,
        category=category,
        asset_type=asset_type,
        criticality=criticality,
        categories=ASSET_CATEGORIES,
        types=ASSET_TYPES,
        criticalities=list(CRITICALITY_LABELS),
    )


@router.get("/engagements/{engagement_id}/assets/new", response_class=HTMLResponse)
def asset_new_page(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    engagement = EngagementService(db).get_for(ctx, engagement_id)
    return _render(
        request,
        "assets/form.html",
        ctx,
        nav="engagements",
        mode="create",
        engagement=engagement,
        asset=None,
        form_action=f"/engagements/{engagement.id}/assets",
        categories=ASSET_CATEGORIES,
        types=ASSET_TYPES,
        lifecycle=ASSET_LIFECYCLE,
    )


@router.post("/engagements/{engagement_id}/assets", response_class=HTMLResponse)
async def asset_create_submit(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    asset = AssetService(db).create(
        ctx,
        engagement_id,
        name=form.get("name", ""),
        asset_type=form.get("asset_type", "supporting"),
        category=form.get("category", "other"),
        owner=form.get("owner", ""),
        department=form.get("department", ""),
        location=form.get("location", ""),
        description=form.get("description", ""),
        confidentiality=form.get("confidentiality", "2"),
        integrity=form.get("integrity", "2"),
        availability=form.get("availability", "2"),
        lifecycle_status=form.get("lifecycle_status", "active"),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/assets/{asset.id}")


@router.post("/engagements/{engagement_id}/assets/import", response_class=HTMLResponse)
async def asset_import_submit(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await request.form()
    _check_csrf(ctx, {"csrf_token": str(form.get("csrf_token", ""))})
    upload = form.get("file")
    payload = await upload.read() if hasattr(upload, "read") else b""
    if not payload:
        raise ValidationFailure("please choose a CSV file")
    ip, user_agent = _ip(request)
    AssetImportService(db).import_bytes(
        ctx,
        engagement_id,
        payload,
        filename=getattr(upload, "filename", "") or "",
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/engagements/{engagement_id}/assets")


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail_page(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    service = AssetService(db)
    asset = service.get_for(ctx, asset_id)
    engagement = EngagementService(db).get_for(ctx, asset.engagement_id)
    links = service.links_for(asset.id)
    linked_ids = {link.threat_id for link in links}
    threats, _, _, _ = ThreatService(db).list(ctx, asset.engagement_id, page_size=200)
    return _render(
        request,
        "assets/detail.html",
        ctx,
        nav="engagements",
        asset=asset,
        engagement=engagement,
        links=links,
        available_threats=[row for row in threats if row.id not in linked_ids],
        levels=LEVELS,
    )


@router.get("/assets/{asset_id}/edit", response_class=HTMLResponse)
def asset_edit_page(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    asset = AssetService(db).get_for(ctx, asset_id)
    engagement = EngagementService(db).get_for(ctx, asset.engagement_id)
    return _render(
        request,
        "assets/form.html",
        ctx,
        nav="engagements",
        mode="edit",
        engagement=engagement,
        asset=asset,
        form_action=f"/assets/{asset.id}/edit",
        categories=ASSET_CATEGORIES,
        types=ASSET_TYPES,
        lifecycle=ASSET_LIFECYCLE,
    )


@router.post("/assets/{asset_id}/edit", response_class=HTMLResponse)
async def asset_edit_submit(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    AssetService(db).update(
        ctx,
        asset_id,
        name=form.get("name"),
        asset_type=form.get("asset_type"),
        category=form.get("category"),
        owner=form.get("owner"),
        department=form.get("department"),
        location=form.get("location"),
        description=form.get("description"),
        confidentiality=form.get("confidentiality"),
        integrity=form.get("integrity"),
        availability=form.get("availability"),
        lifecycle_status=form.get("lifecycle_status"),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/assets/{asset_id}")


@router.post("/assets/{asset_id}/delete", response_class=HTMLResponse)
async def asset_delete_submit(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    asset = AssetService(db).get_for(ctx, asset_id)
    engagement_id = asset.engagement_id
    AssetService(db).delete(ctx, asset_id, ip=ip, user_agent=user_agent)
    return _redirect(f"/engagements/{engagement_id}/assets")


@router.post("/assets/{asset_id}/threats", response_class=HTMLResponse)
async def asset_link_threat_submit(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    AssetService(db).link_threat(
        ctx,
        asset_id,
        threat_id=form.get("threat_id", ""),
        vulnerability=form.get("vulnerability", ""),
        exposure=form.get("exposure", "medium"),
        notes=form.get("notes", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/assets/{asset_id}")


@router.post("/asset-threats/{link_id}/delete", response_class=HTMLResponse)
async def asset_unlink_threat_submit(
    link_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    link = db.get(AssetThreat, link_id)
    asset_id = link.asset_id if link else ""
    AssetService(db).unlink_threat(ctx, link_id, ip=ip, user_agent=user_agent)
    return _redirect(f"/assets/{asset_id}")


# --------------------------------------------------------------------------- risk
@router.get("/engagements/{engagement_id}/assessments", response_class=HTMLResponse)
def assessments_page(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    engagement = EngagementService(db).get_for(ctx, engagement_id)
    service = RiskAssessmentService(db)
    rows, total, page, page_size = service.list(ctx, engagement_id, page_size=40)
    counts = service.item_counts([row.id for row in rows])
    appetite = service.appetite(ctx, engagement_id)
    return _render(
        request,
        "assessments/list.html",
        ctx,
        nav="engagements",
        engagement=engagement,
        assessments=rows,
        item_counts=counts,
        total=total,
        appetite=appetite,
        threshold=appetite.max_acceptable_score if appetite else DEFAULT_APPETITE,
        statuses=RISK_ASSESSMENT_STATUSES,
        status_labels_map=ASSESSMENT_STATUS_LABELS,
        severity_labels=SEVERITY_LABELS,
        appetite_severities={
            score: severity_for(score) for score in range(1, 26)
        },
    )


@router.post("/engagements/{engagement_id}/assessments", response_class=HTMLResponse)
async def assessment_create_submit(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    assessment = RiskAssessmentService(db).create(
        ctx,
        engagement_id,
        title=form.get("title", ""),
        assessor=form.get("assessor", ""),
        summary=form.get("summary", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/assessments/{assessment.id}")


@router.post("/engagements/{engagement_id}/risk-appetite", response_class=HTMLResponse)
async def risk_appetite_submit(
    engagement_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    RiskAssessmentService(db).set_appetite(
        ctx,
        engagement_id,
        max_acceptable_score=form.get("max_acceptable_score", str(DEFAULT_APPETITE)),
        statement=form.get("statement", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/engagements/{engagement_id}/assessments")


@router.get("/assessments/{assessment_id}", response_class=HTMLResponse)
def assessment_detail_page(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    service = RiskAssessmentService(db)
    assessment = service.get_for(ctx, assessment_id)
    engagement = EngagementService(db).get_for(ctx, assessment.engagement_id)
    items = service.items_for(assessment.id)
    appetite = service.appetite(ctx, assessment.engagement_id)
    threshold = appetite.max_acceptable_score if appetite else 9
    scored = {(item.asset_id, item.threat_id) for item in items}
    pairs = [
        link
        for link in AssetService(db).links_for_engagement(ctx, assessment.engagement_id)
        if (link.asset_id, link.threat_id) not in scored
    ]
    matrix_cells: dict[tuple[int, int], dict] = {}
    for item in items:
        key = (item.likelihood, item.impact)
        cell = matrix_cells.setdefault(key, {"count": 0, "severity": item.inherent_severity})
        cell["count"] += 1
    return _render(
        request,
        "assessments/detail.html",
        ctx,
        nav="engagements",
        assessment=assessment,
        engagement=engagement,
        items=items,
        summary=service.summary(ctx, assessment.id),
        appetite=appetite,
        threshold=threshold,
        pairs=pairs,
        matrix_cells=matrix_cells,
        matrix_severities={
            (level, impact): severity_for(level * impact)
            for level in range(MATRIX_MIN, MATRIX_MAX + 1)
            for impact in range(MATRIX_MIN, MATRIX_MAX + 1)
        },
        matrix_range=range(MATRIX_MAX, MATRIX_MIN - 1, -1),
        likelihood_labels=LIKELIHOOD_LABELS,
        impact_labels=IMPACT_LABELS,
        severity_labels=SEVERITY_LABELS,
        treatment_labels=TREATMENT_LABELS,
        status_labels_map=ASSESSMENT_STATUS_LABELS,
    )


@router.post("/assessments/{assessment_id}/issue", response_class=HTMLResponse)
async def assessment_issue_submit(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    RiskAssessmentService(db).issue(
        ctx, assessment_id, ip=ip, user_agent=user_agent
    )
    return _redirect(f"/assessments/{assessment_id}")


@router.post("/assessments/{assessment_id}/delete", response_class=HTMLResponse)
async def assessment_delete_submit(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    assessment = RiskAssessmentService(db).get_for(ctx, assessment_id)
    engagement_id = assessment.engagement_id
    RiskAssessmentService(db).delete(
        ctx, assessment_id, ip=ip, user_agent=user_agent
    )
    return _redirect(f"/engagements/{engagement_id}/assessments")


@router.get("/assessments/{assessment_id}/risks/new", response_class=HTMLResponse)
def risk_new_page(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    service = RiskAssessmentService(db)
    assessment = service.get_for(ctx, assessment_id)
    engagement = EngagementService(db).get_for(ctx, assessment.engagement_id)
    items = service.items_for(assessment.id)
    scored = {(item.asset_id, item.threat_id) for item in items}
    pairs = [
        link
        for link in AssetService(db).links_for_engagement(ctx, assessment.engagement_id)
        if (link.asset_id, link.threat_id) not in scored
    ]
    return _render(
        request,
        "assessments/form.html",
        ctx,
        nav="engagements",
        mode="create",
        assessment=assessment,
        engagement=engagement,
        item=None,
        pairs=pairs,
        form_action=f"/assessments/{assessment.id}/risks",
        treatments=RISK_TREATMENTS,
        treatment_labels=TREATMENT_LABELS,
        grades=range(MATRIX_MIN, MATRIX_MAX + 1),
        likelihood_labels=LIKELIHOOD_LABELS,
        impact_labels=IMPACT_LABELS,
    )


@router.post("/assessments/{assessment_id}/risks", response_class=HTMLResponse)
async def risk_create_submit(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    RiskService(db).add(
        ctx,
        assessment_id,
        asset_threat_id=form.get("asset_threat_id", ""),
        likelihood=form.get("likelihood", "3"),
        impact=form.get("impact", "3"),
        residual_likelihood=form.get("residual_likelihood") or None,
        residual_impact=form.get("residual_impact") or None,
        treatment=form.get("treatment", "mitigate"),
        rationale=form.get("rationale", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/assessments/{assessment_id}")


@router.get("/risks/{risk_id}/edit", response_class=HTMLResponse)
def risk_edit_page(
    risk_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    item = RiskService(db).get_for(ctx, risk_id)
    assessment = RiskAssessmentService(db).get_for(ctx, item.assessment_id)
    engagement = EngagementService(db).get_for(ctx, assessment.engagement_id)
    return _render(
        request,
        "assessments/form.html",
        ctx,
        nav="engagements",
        mode="edit",
        assessment=assessment,
        engagement=engagement,
        item=item,
        pairs=[],
        form_action=f"/risks/{item.id}/edit",
        treatments=RISK_TREATMENTS,
        treatment_labels=TREATMENT_LABELS,
        grades=range(MATRIX_MIN, MATRIX_MAX + 1),
        likelihood_labels=LIKELIHOOD_LABELS,
        impact_labels=IMPACT_LABELS,
    )


@router.post("/risks/{risk_id}/edit", response_class=HTMLResponse)
async def risk_edit_submit(
    risk_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    item = RiskService(db).update(
        ctx,
        risk_id,
        likelihood=form.get("likelihood"),
        impact=form.get("impact"),
        residual_likelihood=form.get("residual_likelihood"),
        residual_impact=form.get("residual_impact"),
        treatment=form.get("treatment"),
        rationale=form.get("rationale"),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect(f"/assessments/{item.assessment_id}")


@router.post("/risks/{risk_id}/delete", response_class=HTMLResponse)
async def risk_delete_submit(
    risk_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    item = RiskService(db).get_for(ctx, risk_id)
    assessment_id = item.assessment_id
    RiskService(db).delete(ctx, risk_id, ip=ip, user_agent=user_agent)
    return _redirect(f"/assessments/{assessment_id}")


@router.get("/assessments/{assessment_id}/compare", response_class=HTMLResponse)
def assessment_compare_page(
    assessment_id: str,
    request: Request,
    against: str = "",
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    service = RiskAssessmentService(db)
    assessment = service.get_for(ctx, assessment_id)
    engagement = EngagementService(db).get_for(ctx, assessment.engagement_id)
    candidates, _, _, _ = service.list(ctx, assessment.engagement_id, page_size=200)
    candidates = [row for row in candidates if row.id != assessment.id]
    result = service.compare(ctx, assessment.id, against) if against else None
    return _render(
        request,
        "assessments/compare.html",
        ctx,
        nav="engagements",
        assessment=assessment,
        engagement=engagement,
        candidates=candidates,
        against=against,
        result=result,
        severity_labels=SEVERITY_LABELS,
        treatment_labels=TREATMENT_LABELS,
    )


# ---------------------------------------------------------------------------- audit
@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    entity_type: str = "",
    action: str = "",
    page: int = 1,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    from aegis.services.audit import AuditService

    page_size = 30
    rows, total = AuditService(db).list_events(
        entity_type=entity_type or None,
        action=action or None,
        limit=page_size,
        offset=(page - 1) * page_size,
    )
    return _render(
        request,
        "audit.html",
        ctx,
        nav="audit",
        events=[audit_public(row) for row in rows],
        total=total,
        page=page,
        pages=(total + page_size - 1) // page_size,
        entity_type=entity_type,
        action=action,
    )


# ----------------------------------------------------------------------------- users
@router.get("/users", response_class=HTMLResponse)
def users_page(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    service = AuthService(db, settings)
    if ctx.user.role != "admin":
        from aegis.errors import Forbidden

        raise Forbidden("administrator role required")
    users = service.list_users()
    return _render(request, "users.html", ctx, nav="users", users=users)


@router.post("/users", response_class=HTMLResponse)
async def user_create_submit(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    if ctx.user.role != "admin":
        from aegis.errors import Forbidden

        raise Forbidden("administrator role required")
    AuthService(db, settings).create_user(
        ctx,
        email=form.get("email", ""),
        display_name=form.get("display_name", ""),
        password=form.get("password", ""),
        role=form.get("role", "consultant"),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect("/users")


@router.post("/users/{user_id}/update", response_class=HTMLResponse)
async def user_update_submit(
    user_id: str,
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    if ctx.user.role != "admin":
        from aegis.errors import Forbidden

        raise Forbidden("administrator role required")
    AuthService(db, settings).update_user(
        ctx,
        user_id,
        display_name=form.get("display_name"),
        role=form.get("role"),
        is_active=form.get("is_active") == "1" if "is_active" in form else None,
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect("/users")


# --------------------------------------------------------------------------- account
@router.get("/account", response_class=HTMLResponse)
def account_page(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    return _render(request, "account.html", ctx, nav="account")


@router.post("/account/password", response_class=HTMLResponse)
async def account_password_submit(
    request: Request,
    db: Session = Depends(get_web_db),
    settings: Settings = Depends(get_web_settings),
):
    ctx = _require_ctx(request, db, settings)
    form = await _form(request)
    _check_csrf(ctx, form)
    ip, user_agent = _ip(request)
    AuthService(db, settings).change_password(
        ctx,
        current_password=form.get("current_password", ""),
        new_password=form.get("new_password", ""),
        ip=ip,
        user_agent=user_agent,
    )
    return _redirect("/account")


def _entity_timeline(db: Session, entity_type: str, entity_id: str):
    from aegis.services.audit import AuditService

    return AuditService(db).entity_timeline(entity_type, entity_id)
