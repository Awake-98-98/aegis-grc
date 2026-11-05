"""Versioned schema migrations.

Each migration is a Python module exposing ``VERSION``, ``NAME`` and
``apply(connection)``. The runner applies pending migrations in one transaction
per version and records the version in ``schema_migrations``. Keeping the
runner in-project (instead of Alembic) is a deliberate trade-off documented
in ``docs/design/m1-foundation.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from sqlalchemy import Engine, text
from sqlalchemy.engine import Connection

from aegis.db import migrations as migration_package
from aegis.errors import DatabaseFailure
from aegis.util.time import utcnow


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Connection], None]


def load_migrations() -> list[Migration]:
    items: list[Migration] = []
    for module_name in migration_package.MIGRATION_MODULES:
        module = __import__(
            f"{migration_package.__name__}.{module_name}", fromlist=["apply"]
        )
        items.append(Migration(version=module.VERSION, name=module.NAME, apply=module.apply))
    items.sort(key=lambda item: item.version)
    versions = [item.version for item in items]
    if versions != list(range(1, len(items) + 1)):
        raise DatabaseFailure(f"migration versions are not contiguous: {versions}")
    return items


def current_version(connection: Connection) -> int:
    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, "
            "name TEXT NOT NULL, "
            "applied_at TEXT NOT NULL)"
        )
    )
    row = connection.execute(text("SELECT MAX(version) FROM schema_migrations")).scalar()
    return int(row or 0)


def run_migrations(engine: Engine) -> list[Migration]:
    applied: list[Migration] = []
    with engine.begin() as connection:
        version = current_version(connection)
        for migration in load_migrations():
            if migration.version <= version:
                continue
            migration.apply(connection)
            connection.execute(
                text(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (:v, :n, :t)"
                ),
                {"v": migration.version, "n": migration.name, "t": utcnow().isoformat()},
            )
            applied.append(migration)
    return applied


def schema_status(engine: Engine) -> dict[str, int]:
    with engine.connect() as connection:
        version = current_version(connection)
    latest = load_migrations()[-1].version if load_migrations() else 0
    return {"current": version, "latest": latest}
