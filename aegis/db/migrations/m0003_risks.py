"""Schema v3: risk assessments, scored items and risk appetite.

The assessment batch is the version unit. Items copy the asset and threat
labels so an issued register survives later renames or deletions, which is
why the identifier columns are nullable with ``ON DELETE SET NULL``.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

VERSION = 3
NAME = "risk assessment register"

DDL = (
    """
    CREATE TABLE risk_assessments (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        assessor TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        issued_at DATETIME,
        issued_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (engagement_id, code),
        CHECK (status IN ('draft', 'issued'))
    )
    """,
    """
    CREATE TABLE risk_items (
        id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL REFERENCES risk_assessments(id) ON DELETE CASCADE,
        asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
        threat_id TEXT REFERENCES threats(id) ON DELETE SET NULL,
        asset_threat_id TEXT REFERENCES asset_threats(id) ON DELETE SET NULL,
        asset_code TEXT NOT NULL DEFAULT '',
        asset_name TEXT NOT NULL DEFAULT '',
        threat_code TEXT NOT NULL DEFAULT '',
        threat_name TEXT NOT NULL DEFAULT '',
        likelihood INTEGER NOT NULL,
        impact INTEGER NOT NULL,
        residual_likelihood INTEGER NOT NULL,
        residual_impact INTEGER NOT NULL,
        treatment TEXT NOT NULL DEFAULT 'mitigate',
        rationale TEXT NOT NULL DEFAULT '',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (assessment_id, asset_id, threat_id),
        CHECK (likelihood BETWEEN 1 AND 5),
        CHECK (impact BETWEEN 1 AND 5),
        CHECK (residual_likelihood BETWEEN 1 AND 5),
        CHECK (residual_impact BETWEEN 1 AND 5),
        CHECK (treatment IN ('mitigate', 'accept', 'transfer', 'avoid'))
    )
    """,
    """
    CREATE TABLE risk_appetite (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL UNIQUE REFERENCES engagements(id) ON DELETE CASCADE,
        max_acceptable_score INTEGER NOT NULL DEFAULT 9,
        statement TEXT NOT NULL DEFAULT '',
        updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        CHECK (max_acceptable_score BETWEEN 1 AND 25)
    )
    """,
)

INDEXES = (
    "CREATE INDEX idx_risk_assessments_engagement ON risk_assessments(engagement_id)",
    "CREATE INDEX idx_risk_items_assessment ON risk_items(assessment_id)",
    "CREATE INDEX idx_risk_items_pair ON risk_items(assessment_id, asset_id, threat_id)",
)


def apply(connection: Connection) -> None:
    for statement in DDL:
        connection.execute(text(statement))
    for statement in INDEXES:
        connection.execute(text(statement))
