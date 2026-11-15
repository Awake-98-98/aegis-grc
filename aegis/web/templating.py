"""Jinja2 environment wiring.

Templates receive a small set of globals so a page can ask the same RBAC
question the API asks, and can render labels consistently.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from aegis.config import Settings
from aegis.security.rbac import can
from aegis.services.assets import (
    ASSET_CATEGORY_LABELS,
    ASSET_LIFECYCLE_LABELS,
    ASSET_TYPE_LABELS,
    CRITICALITY_LABELS,
)
from aegis.services.engagements import STATUS_LABELS, TYPE_LABELS
from aegis.services.threats import THREAT_ACTOR_LABELS, THREAT_CATEGORY_LABELS
from aegis.util.time import as_date_iso, as_iso

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

CLIENT_STATUS_LABELS = {
    "prospect": "潜在客户",
    "active": "在服务",
    "dormant": "暂停",
    "archived": "已归档",
}

LEVEL_LABELS = {"low": "低", "medium": "中", "high": "高"}


def _humanize_action(action: str) -> str:
    return action.replace(".", " · ")


def _short_time(value) -> str:
    iso = as_iso(value)
    if not iso:
        return "-"
    return iso[:16].replace("T", " ")


def build_templates(settings: Settings) -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    env = templates.env
    env.globals.update(
        app_name="AegisGRC",
        can=can,
        status_labels=STATUS_LABELS,
        type_labels=TYPE_LABELS,
        client_status_labels=CLIENT_STATUS_LABELS,
        level_labels=LEVEL_LABELS,
        asset_type_labels=ASSET_TYPE_LABELS,
        asset_category_labels=ASSET_CATEGORY_LABELS,
        asset_lifecycle_labels=ASSET_LIFECYCLE_LABELS,
        criticality_labels=CRITICALITY_LABELS,
        threat_category_labels=THREAT_CATEGORY_LABELS,
        threat_actor_labels=THREAT_ACTOR_LABELS,
        humanize_action=_humanize_action,
        settings=settings,
    )
    env.filters.update(
        iso=as_iso,
        short_time=_short_time,
        date_iso=as_date_iso,
    )
    return templates
