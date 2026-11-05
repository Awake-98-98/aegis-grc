"""FastAPI dependencies: database session, authentication, CSRF and RBAC."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from aegis.config import Settings
from aegis.errors import CsrfFailure, Forbidden, Unauthorized
from aegis.security.rbac import can
from aegis.security.tokens import csrf_matches
from aegis.services.auth import AuthContext, AuthService

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    factory = request.app.state.session_factory
    db: Session = factory()
    try:
        yield db
    finally:
        db.close()


def client_meta(request: Request) -> tuple[str, str]:
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "")
    return ip[:64], request.headers.get("user-agent", "")[:255]


def _extract_token(request: Request, settings: Settings) -> tuple[str | None, str]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip(), "bearer"
    cookie_token = request.cookies.get(settings.cookie_name)
    if cookie_token:
        return cookie_token, "cookie"
    return None, "none"


def get_auth(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthContext:
    token, via = _extract_token(request, settings)
    ctx = AuthService(db, settings).resolve(token, via)
    if ctx is None:
        raise Unauthorized("authentication required")
    if via == "cookie" and request.method.upper() in STATE_CHANGING:
        provided = request.headers.get("x-csrf-token")
        if not csrf_matches(ctx.session.csrf_token, provided):
            raise CsrfFailure("invalid or missing X-CSRF-Token header")
    return ctx


def require_permission(permission: str):
    def dependency(ctx: AuthContext = Depends(get_auth)) -> AuthContext:
        if not can(ctx.user.role, permission):
            raise Forbidden(f"missing permission: {permission}")
        return ctx

    return dependency


def require_admin(ctx: AuthContext = Depends(get_auth)) -> AuthContext:
    if ctx.user.role != "admin":
        raise Forbidden("administrator role required")
    return ctx
