"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.config import ConfigError, Settings


def test_defaults_create_home_and_database(tmp_path: Path) -> None:
    settings = Settings.load(home=tmp_path, env={})
    assert settings.home == tmp_path.resolve()
    assert settings.database_url.startswith("sqlite+pysqlite:///")
    assert settings.database_path is not None
    assert settings.database_path.exists() is False  # engine creates the file
    assert (tmp_path / "secret.key").exists()


def test_secret_is_stable_across_reloads(tmp_path: Path) -> None:
    first = Settings.load(home=tmp_path, env={})
    second = Settings.load(home=tmp_path, env={})
    assert first.secret_key == second.secret_key
    assert len(first.secret_key) >= 32


def test_production_requires_long_secret(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Settings.load(home=tmp_path, env={"AEGIS_ENV": "production", "AEGIS_SECRET_KEY": "short"})


def test_invalid_port_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Settings.load(home=tmp_path, env={"AEGIS_PORT": "70000"})


def test_session_ttl_bounds(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        Settings.load(home=tmp_path, env={"AEGIS_SESSION_TTL_HOURS": "0"})


def test_cookie_secure_defaults_to_production(tmp_path: Path) -> None:
    dev = Settings.load(home=tmp_path, env={})
    prod = Settings.load(
        home=tmp_path, env={"AEGIS_ENV": "production", "AEGIS_SECRET_KEY": "y" * 48}
    )
    assert dev.cookie_secure is False
    assert prod.cookie_secure is True
