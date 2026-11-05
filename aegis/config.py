"""Application configuration.

Configuration comes from environment variables with an ``AEGIS_`` prefix.
The data directory also holds an auto-generated secret used to sign nothing
by itself today (session tokens are opaque random values hashed at rest),
but the file is kept so later milestones can add signed exports without
changing the deployment contract.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SESSION_TTL_HOURS = 8
DEFAULT_PORT = 8080


class ConfigError(ValueError):
    """Raised when the environment cannot produce a usable configuration."""


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int, name: str) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from exc


def _load_or_create_secret(home: Path) -> str:
    path = home / "secret.key"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value
    value = secrets.token_urlsafe(48)
    home.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows may ignore POSIX modes
        pass
    return value


def _environment(env: dict[str, str]) -> str:
    return (env.get("AEGIS_ENV") or "development").strip().lower()


@dataclass(frozen=True, slots=True)
class Settings:
    home: Path
    database_url: str
    secret_key: str
    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    session_ttl_hours: int = DEFAULT_SESSION_TTL_HOURS
    cookie_name: str = "aegis_session"
    cookie_secure: bool = False
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    _source: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def database_path(self) -> Path | None:
        prefix = "sqlite+pysqlite:///"
        if self.database_url.startswith(prefix):
            return Path(self.database_url[len(prefix) :])
        return None

    @classmethod
    def load(cls, home: str | Path | None = None, env: dict[str, str] | None = None) -> "Settings":
        values = dict(os.environ if env is None else env)
        raw_home = str(home) if home is not None else values.get("AEGIS_HOME", "aegis-data")
        home_path = Path(raw_home).expanduser().resolve()
        home_path.mkdir(parents=True, exist_ok=True)

        database_url = values.get("AEGIS_DATABASE_URL") or (
            f"sqlite+pysqlite:///{(home_path / 'aegis.sqlite3').as_posix()}"
        )
        environment = _environment(values)
        secret = values.get("AEGIS_SECRET_KEY") or _load_or_create_secret(home_path)
        if environment == "production" and len(secret) < 32:
            raise ConfigError("AEGIS_SECRET_KEY must be at least 32 characters in production")

        cookie_secure = _as_bool(values.get("AEGIS_COOKIE_SECURE"), environment == "production")
        port = _as_int(values.get("AEGIS_PORT"), DEFAULT_PORT, "AEGIS_PORT")
        if not 1 <= port <= 65535:
            raise ConfigError(f"AEGIS_PORT out of range: {port}")

        ttl = _as_int(
            values.get("AEGIS_SESSION_TTL_HOURS"),
            DEFAULT_SESSION_TTL_HOURS,
            "AEGIS_SESSION_TTL_HOURS",
        )
        if not 1 <= ttl <= 24 * 30:
            raise ConfigError("AEGIS_SESSION_TTL_HOURS must be between 1 and 720")

        return cls(
            home=home_path,
            database_url=database_url,
            secret_key=secret,
            environment=environment,
            host=values.get("AEGIS_HOST", "127.0.0.1"),
            port=port,
            session_ttl_hours=ttl,
            cookie_name=values.get("AEGIS_COOKIE_NAME", "aegis_session"),
            cookie_secure=cookie_secure,
            login_max_attempts=_as_int(
                values.get("AEGIS_LOGIN_MAX_ATTEMPTS"), 5, "AEGIS_LOGIN_MAX_ATTEMPTS"
            ),
            login_window_seconds=_as_int(
                values.get("AEGIS_LOGIN_WINDOW_SECONDS"), 300, "AEGIS_LOGIN_WINDOW_SECONDS"
            ),
            _source=values,
        )
