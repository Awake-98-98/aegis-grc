"""Service layer tests that do not need an HTTP client."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from aegis.models import Session as LoginSession
from aegis.models import User
from aegis.services.auth import AuthContext, AuthService
from aegis.services.clients import ClientService
from aegis.services.engagements import ALLOWED_TRANSITIONS, STATUS_LABELS, EngagementService
from aegis.util.time import utcnow


def _bootstrap(service: AuthService) -> AuthContext:
    user, result = service.bootstrap(
        email="owner@aegis.test", display_name="Owner", password="OwnerPass123"
    )
    session = service.db.execute(
        select(LoginSession).where(LoginSession.token_hash != "")
    ).scalar_one()
    return AuthContext(user=user, session=session, via="cli")


def test_bootstrap_creates_admin(auth_service: AuthService) -> None:
    user, result = auth_service.bootstrap(
        email="owner@aegis.test", display_name="Owner", password="OwnerPass123"
    )
    assert user.role == "admin"
    assert auth_service.has_users() is True
    assert auth_service.resolve(result.token) is not None


def test_client_codes_are_sequential(auth_service: AuthService) -> None:
    ctx = _bootstrap(auth_service)
    service = ClientService(auth_service.db)
    first = service.create(ctx, name="甲客户")
    second = service.create(ctx, name="乙客户")
    assert first.code == "CL-0001"
    assert second.code == "CL-0002"


def test_engagement_codes_are_sequential(auth_service: AuthService) -> None:
    ctx = _bootstrap(auth_service)
    client = ClientService(auth_service.db).create(ctx, name="客户")
    service = EngagementService(auth_service.db)
    first = service.create(ctx, client_id=client.id, name="项目一")
    second = service.create(ctx, client_id=client.id, name="项目二")
    assert first.code.startswith("ENG-2026-")
    assert first.code != second.code


def test_transition_matrix_is_complete() -> None:
    for status in STATUS_LABELS:
        assert status in ALLOWED_TRANSITIONS
        for target in ALLOWED_TRANSITIONS[status]:
            assert target in STATUS_LABELS
    assert ALLOWED_TRANSITIONS["archived"] == set()


def test_expired_session_is_not_resolved(auth_service: AuthService) -> None:
    _, result = auth_service.bootstrap(
        email="owner@aegis.test", display_name="Owner", password="OwnerPass123"
    )
    session = auth_service.db.execute(
        select(LoginSession).where(LoginSession.token_hash != "")
    ).scalar_one()
    session.expires_at = utcnow() - timedelta(seconds=1)
    auth_service.db.commit()
    assert auth_service.resolve(result.token) is None


def test_revoked_session_is_not_resolved(auth_service: AuthService) -> None:
    _, result = auth_service.bootstrap(
        email="owner@aegis.test", display_name="Owner", password="OwnerPass123"
    )
    session = auth_service.db.execute(
        select(LoginSession).where(LoginSession.token_hash != "")
    ).scalar_one()
    session.revoked_at = utcnow()
    auth_service.db.commit()
    assert auth_service.resolve(result.token) is None


def test_unknown_token_is_not_resolved(auth_service: AuthService) -> None:
    assert auth_service.resolve("token-that-does-not-exist") is None


def test_cleanup_removes_expired_sessions(auth_service: AuthService) -> None:
    _, result = auth_service.bootstrap(
        email="owner@aegis.test", display_name="Owner", password="OwnerPass123"
    )
    row = auth_service.db.execute(
        select(LoginSession).where(LoginSession.token_hash != "")
    ).scalar_one()
    row.expires_at = utcnow() - timedelta(hours=1)
    auth_service.db.commit()
    removed = auth_service.cleanup_expired()
    assert removed >= 1
    assert auth_service.resolve(result.token) is None


def test_user_update_protects_last_admin(auth_service: AuthService) -> None:
    from aegis.errors import Conflict

    ctx = _bootstrap(auth_service)
    with pytest.raises(Conflict) as excinfo:
        auth_service.update_user(ctx, ctx.user.id, role="consultant")
    assert excinfo.value.code == "AEG-2002"
