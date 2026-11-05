"""Input validation shared by the API and the web forms."""

from __future__ import annotations

import re

from aegis.errors import ValidationFailure

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

CLIENT_STATUSES = ("prospect", "active", "dormant", "archived")
ENGAGEMENT_TYPES = (
    "risk_assessment",
    "compliance_audit",
    "penetration_test",
    "incident_response",
    "security_planning",
    "other",
)
ENGAGEMENT_STATUSES = ("draft", "scoping", "fieldwork", "reporting", "closed", "archived")
LEVELS = ("low", "medium", "high")


def require_text(
    value: str | None,
    field: str,
    *,
    min_length: int = 1,
    max_length: int = 200,
    allow_empty: bool = False,
) -> str:
    text = (value or "").strip()
    if not text:
        if allow_empty:
            return ""
        raise ValidationFailure(f"{field} is required", details={"field": field})
    if len(text) < min_length:
        raise ValidationFailure(
            f"{field} must be at least {min_length} characters",
            details={"field": field, "min_length": min_length},
        )
    if len(text) > max_length:
        raise ValidationFailure(
            f"{field} must be at most {max_length} characters",
            details={"field": field, "max_length": max_length},
        )
    return text


def normalize_email(value: str | None, field: str = "email") -> str:
    email = (value or "").strip().lower()
    if not email:
        raise ValidationFailure(f"{field} is required", details={"field": field})
    if len(email) > 254 or not _EMAIL_RE.match(email):
        raise ValidationFailure(f"{field} is not a valid address", details={"field": field})
    return email


def optional_email(value: str | None, field: str = "email") -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    if len(text) > 254 or not _EMAIL_RE.match(text):
        raise ValidationFailure(f"{field} is not a valid address", details={"field": field})
    return text


def choice(value: str | None, allowed: tuple[str, ...], field: str, default: str | None = None) -> str:
    candidate = (value or default or "").strip().lower()
    if candidate not in allowed:
        raise ValidationFailure(
            f"{field} must be one of: {', '.join(allowed)}",
            details={"field": field, "allowed": list(allowed)},
        )
    return candidate


def optional_choice(value: str | None, allowed: tuple[str, ...], field: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    if text not in allowed:
        raise ValidationFailure(
            f"{field} must be one of: {', '.join(allowed)}",
            details={"field": field, "allowed": list(allowed)},
        )
    return text


def page_params(page: int | None, page_size: int | None) -> tuple[int, int]:
    current = max(1, int(page or 1))
    size = int(page_size or 20)
    if size < 1:
        size = 20
    if size > 200:
        size = 200
    return current, size
