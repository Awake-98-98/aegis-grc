"""User administration API (administrator only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from aegis.api.deps import client_meta, get_db, get_settings, require_admin
from aegis.api.responses import ok
from aegis.api.schemas import UserCreateRequest, UserUpdateRequest
from aegis.config import Settings
from aegis.serializers import user_public
from aegis.services.auth import AuthContext, AuthService

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("")
def list_users(
    ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    users = AuthService(db, settings).list_users()
    return ok([user_public(user) for user in users])


@router.post("", status_code=201)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    user = AuthService(db, settings).create_user(
        ctx,
        email=payload.email,
        display_name=payload.display_name,
        password=payload.password,
        role=payload.role,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(user_public(user))


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    request: Request,
    ctx: AuthContext = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip, user_agent = client_meta(request)
    user = AuthService(db, settings).update_user(
        ctx,
        user_id,
        display_name=payload.display_name,
        role=payload.role,
        is_active=payload.is_active,
        ip=ip,
        user_agent=user_agent,
    )
    return ok(user_public(user))
