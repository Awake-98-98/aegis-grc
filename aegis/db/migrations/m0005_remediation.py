"""Schema v5: remediation tasks and content addressed evidence files.

A remediation task is the unit a consultant plans, assigns and closes. It may
point at the scored risk item that motivated it, but the identifying labels are
copied into ``risk_snapshot`` so the task survives a later assessment version
that drops the item. Evidence rows store metadata only; the bytes live in the
content addressed store outside the database, keyed by their SHA-256 digest.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

VERSION = 5
NAME = "remediation plan and evidence files"

DDL = (
    """
    CREATE TABLE remediation_tasks (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        risk_item_id TEXT REFERENCES risk_items(id) ON DELETE SET NULL,
        code TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        control_id TEXT REFERENCES controls(id) ON DELETE SET NULL,
        owner TEXT NOT NULL DEFAULT '',
        owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        priority TEXT NOT NULL DEFAULT 'medium',
        status TEXT NOT NULL DEFAULT 'open',
        due_date DATE,
        completed_at DATETIME,
        notes TEXT NOT NULL DEFAULT '',
        risk_snapshot TEXT NOT NULL DEFAULT '',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (engagement_id, code),
        CHECK (priority IN ('low', 'medium', 'high', 'critical')),
        CHECK (status IN ('open', 'in_progress', 'blocked', 'done', 'cancelled'))
    )
    """,
    """
    CREATE TABLE evidence_files (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        remediation_task_id TEXT NOT NULL REFERENCES remediation_tasks(id) ON DELETE CASCADE,
        sha256 TEXT NOT NULL,
        filename TEXT NOT NULL,
        content_type TEXT NOT NULL DEFAULT '',
        size_bytes INTEGER NOT NULL,
        uploaded_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (remediation_task_id, sha256)
    )
    """,
)

INDEXES = (
    "CREATE INDEX idx_remediation_tasks_engagement ON remediation_tasks(engagement_id)",
    "CREATE INDEX idx_remediation_tasks_risk ON remediation_tasks(risk_item_id)",
    "CREATE INDEX idx_remediation_tasks_status ON remediation_tasks(engagement_id, status)",
    "CREATE INDEX idx_remediation_tasks_due ON remediation_tasks(due_date)",
    "CREATE INDEX idx_evidence_files_task ON evidence_files(remediation_task_id)",
    "CREATE INDEX idx_evidence_files_sha ON evidence_files(sha256)",
)


def apply(connection: Connection) -> None:
    for statement in DDL:
        connection.execute(text(statement))
    for statement in INDEXES:
        connection.execute(text(statement))
