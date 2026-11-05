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
from aegis.errors import CsrfFailure, Unauthorized
from aegis.models import User
from aegis.security.tokens import csrf_matches
from aegis.security.validation import (
    CLIENT_STATUSES,
    ENGAGEMENT_STATUSES,
    ENGAGEMENT_TYPES,
    LEVELS,
)
from aegis.serializers import audit_public
from aegis.services.auth import AuthContext, AuthService
from aegis.services.clients import ClientService
from aegis.services.dashboard import DashboardService
from aegis.services.engagements import ALLOWED_TRANSITIONS, EngagementService
from aegis.services.stakeholders import StakeholderService

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
