"""Shared pytest fixtures.

Each test gets an isolated data directory and an in-memory SQLite database so
tests never touch the developer's working data.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from aegis.app import create_app
from aegis.config import Settings
from aegis.db import create_db_engine, create_session_factory, run_migrations
from aegis.services.auth import LOGIN_LIMITER, AuthService


@pytest.fixture(autouse=True)
def _reset_limiter() -> Iterator[None]:
    LOGIN_LIMITER.reset()
    yield
    LOGIN_LIMITER.reset()


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings.load(
        home=tmp_path,
        env={
            "AEGIS_ENV": "test",
            "AEGIS_DATABASE_URL": "sqlite+pysqlite:///:memory:",
            "AEGIS_SECRET_KEY": "x" * 40,
            "AEGIS_SESSION_TTL_HOURS": "8",
        },
    )


@pytest.fixture()
def engine(settings: Settings) -> Iterator[Engine]:
    engine = create_db_engine(settings)
    run_migrations(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings, run_migration=True)
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client
    app.state.engine.dispose()


@pytest.fixture()
def bootstrap_admin(client: TestClient) -> dict:
    response = client.post(
        "/api/auth/bootstrap",
        json={
            "email": "admin@aegis.test",
            "display_name": "平台管理员",
            "password": "AdminPass123",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


@pytest.fixture()
def admin_headers(client: TestClient, bootstrap_admin: dict) -> dict:
    return {"X-CSRF-Token": bootstrap_admin["csrf_token"]}


@pytest.fixture()
def db_session(engine: Engine, settings: Settings):
    factory = create_session_factory(engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def auth_service(db_session, settings: Settings) -> AuthService:
    return AuthService(db_session, settings)
