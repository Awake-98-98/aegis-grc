"""Schema v2: asset inventory, threat catalog and their links.

Assets belong to one engagement and carry a CIA grade. Threats are catalogued
per engagement too, since threat wording differs between projects. The link
table stores the vulnerability that makes an asset-threat pair concrete;
milestone 3 scores those pairs.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

VERSION = 2
NAME = "asset inventory and threat surface"

DDL = (
    """
    CREATE TABLE assets (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        name TEXT NOT NULL,
        asset_type TEXT NOT NULL DEFAULT 'supporting',
        category TEXT NOT NULL DEFAULT 'other',
        owner TEXT NOT NULL DEFAULT '',
        department TEXT NOT NULL DEFAULT '',
        location TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        confidentiality INTEGER NOT NULL DEFAULT 2,
        integrity INTEGER NOT NULL DEFAULT 2,
        availability INTEGER NOT NULL DEFAULT 2,
        lifecycle_status TEXT NOT NULL DEFAULT 'active',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (engagement_id, code),
        UNIQUE (engagement_id, name),
        CHECK (confidentiality BETWEEN 1 AND 4),
        CHECK (integrity BETWEEN 1 AND 4),
        CHECK (availability BETWEEN 1 AND 4)
    )
    """,
    """
    CREATE TABLE threats (
        id TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        code TEXT NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'other',
        actor TEXT NOT NULL DEFAULT 'external',
        description TEXT NOT NULL DEFAULT '',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (engagement_id, code),
        UNIQUE (engagement_id, name)
    )
    """,
    """
    CREATE TABLE asset_threats (
        id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
        threat_id TEXT NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
        vulnerability TEXT NOT NULL DEFAULT '',
        exposure TEXT NOT NULL DEFAULT 'medium',
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        UNIQUE (asset_id, threat_id)
    )
    """,
)

INDEXES = (
    "CREATE INDEX idx_assets_engagement ON assets(engagement_id)",
    "CREATE INDEX idx_assets_category ON assets(engagement_id, category)",
    "CREATE INDEX idx_threats_engagement ON threats(engagement_id)",
    "CREATE INDEX idx_asset_threats_asset ON asset_threats(asset_id)",
    "CREATE INDEX idx_asset_threats_threat ON asset_threats(threat_id)",
)


def apply(connection: Connection) -> None:
    for statement in DDL:
        connection.execute(text(statement))
    for statement in INDEXES:
        connection.execute(text(statement))
