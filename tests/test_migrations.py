"""Migration runner behaviour."""

from __future__ import annotations

from sqlalchemy import text

from aegis.db import load_migrations, run_migrations, schema_status


def test_migrations_are_contiguous_and_versioned() -> None:
    migrations = load_migrations()
    assert [item.version for item in migrations] == list(range(1, len(migrations) + 1))
    assert migrations[0].name


def test_migrations_are_idempotent(settings) -> None:
    from aegis.db import create_db_engine

    engine = create_db_engine(settings)
    applied_first = run_migrations(engine)
    applied_second = run_migrations(engine)
    assert applied_first
    assert applied_second == []
    status = schema_status(engine)
    assert status["current"] == status["latest"]
    engine.dispose()


def test_expected_tables_exist(engine) -> None:
    with engine.connect() as connection:
        names = {
            row[0]
            for row in connection.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
        }
    assert {
        "users",
        "sessions",
        "clients",
        "engagements",
        "stakeholders",
        "audit_events",
        "schema_migrations",
        "control_frameworks",
        "controls",
        "soa_entries",
        "risk_control_links",
    } <= names


def test_foreign_keys_enforced(engine) -> None:
    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1
