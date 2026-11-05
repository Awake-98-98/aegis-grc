"""Small time helpers.

All timestamps are stored as naive UTC values. SQLite has no timezone type,
so keeping one convention (UTC, no tzinfo) avoids aware/naive comparison bugs.
The API layer renders them as ISO-8601 strings with a trailing ``Z``.
"""

from __future__ import annotations

from datetime import date, datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def as_date_iso(value: date | None) -> str | None:
    return value.isoformat() if value else None


def parse_date(value: str | date | None, field: str = "date") -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO date (YYYY-MM-DD)") from exc
