"""Authentication and session API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_auth, get_db, get_settings
from aegis.api.responses import clear_session_cookie, ok, set_session_cookie
from aegis.api.schemas import BootstrapRequest, ChangePasswordRequest, LoginRequest
from aegis.config import Settings
from aegis.serializers import session_public, user_public
from aegis.services.auth import AuthContext, AuthService

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/bootstrap", status_code=201)
def bootstrap(
    payload: BootstrapRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    service = AuthService(db, settings)
    user, result = service.bootstrap(
        email=payload.email,
        display_name=payload.display_name,
        password=payload.password,
        ip=ip,
        user_agent=user_agent,
    )
    set_session_cookie(response, settings, result.token)
    return ok(
        {
            "user": user_public(user),
            "session": {
                "id": result.session_id,
                "expires_at": result.expires_at.isoformat() + "Z",
            },
            "csrf_token": result.csrf_token,
            "token": result.token,
        }
    )


@router.post("/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    service = AuthService(db, settings)
    result = service.login(
        email=payload.email, password=payload.password, ip=ip, user_agent=user_agent
    )
    set_session_cookie(response, settings, result.token)
    return ok(
        {
            "user": user_public(result.user),
            "csrf_token": result.csrf_token,
            "token": result.token,
            "expires_at": result.expires_at.isoformat() + "Z",
        }
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    AuthService(db, settings).logout(ctx, ip=ip, user_agent=user_agent)
    clear_session_cookie(response, settings)
    return ok({"logged_out": True})


@router.get("/me")
def me(ctx: AuthContext = Depends(get_auth)) -> dict:
    return ok(
        {
            "user": user_public(ctx.user),
            "session": session_public(ctx.session),
            "csrf_token": ctx.session.csrf_token,
            "via": ctx.via,
        }
    )


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    ctx: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    AuthService(db, settings).change_password(
        ctx,
        current_password=payload.current_password,
        new_password=payload.new_password,
        ip=ip,
        user_agent=user_agent,
    )
    return ok({"changed": True})
