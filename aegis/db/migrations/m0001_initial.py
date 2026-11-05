"""Schema v1: users, sessions, clients, engagements, stakeholders, audit.

The DDL is written explicitly instead of ``Base.metadata.create_all`` so the
migration is reviewable and future versions can alter it. Column types mirror
the SQLAlchemy models in ``aegis/models``.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

VERSION = 1
NAME = "initial platform and consulting ledger"

DDL = (
    """
    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'consultant',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        last_login_at DATETIME
    )
    """,
    """
    CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        csrf_token TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        last_seen_at DATETIME NOT NULL,
        revoked_at DATETIME,
        ip TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE clients (
        id TEXT PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        industry TEXT NOT NULL DEFAULT '',
        contact_name TEXT NOT NULL DEFAULT '',
        contact_email TEXT NOT NULL DEFAULT '',
        contact_phone TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'prospect',
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL
    )
    """,
    """
    CREATE TABLE engagements (
        id TEXT PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
        name TEXT NOT NULL,
        engagement_type TEXT NOT NULL DEFAULT 'risk_assessment',
        status TEXT NOT NULL DEFAULT 'draft',
        start_date DATE,
        end_date DATE,
        lead_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        scope_summary TEXT NOT NULL DEFAULT '',
        objectives TEXT NOT NULL DEFAULT '',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL
    )
    """,
    """
    CREATE TABLE stakeholders (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        role_title TEXT NOT NULL DEFAULT '',
        organization TEXT NOT NULL DEFAULT '',
        email TEXT NOT NULL DEFAULT '',
        influence TEXT NOT NULL DEFAULT 'medium',
        interest TEXT NOT NULL DEFAULT 'medium',
        notes TEXT NOT NULL DEFAULT '',
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL
    )
    """,
    """
    CREATE TABLE audit_events (
        id TEXT PRIMARY KEY,
        actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        actor_email TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL,
        detail_json TEXT NOT NULL DEFAULT '{}',
        ip TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT '',
        created_at DATETIME NOT NULL
    )
    """,
)

INDEXES = (
    "CREATE INDEX idx_sessions_user ON sessions(user_id)",
    "CREATE INDEX idx_sessions_expires ON sessions(expires_at)",
    "CREATE INDEX idx_clients_status ON clients(status)",
    "CREATE INDEX idx_engagements_client ON engagements(client_id)",
    "CREATE INDEX idx_engagements_status ON engagements(status)",
    "CREATE INDEX idx_stakeholders_engagement ON stakeholders(engagement_id)",
    "CREATE INDEX idx_audit_created ON audit_events(created_at)",
    "CREATE INDEX idx_audit_entity ON audit_events(entity_type, entity_id)",
)


def apply(connection: Connection) -> None:
    for statement in DDL:
        connection.execute(text(statement))
    for statement in INDEXES:
        connection.execute(text(statement))
