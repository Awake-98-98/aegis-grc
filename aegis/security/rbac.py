"""Role based access control.

Permissions are explicit strings rather than a numeric hierarchy. The web UI
and the API both ask the same ``can`` function, so a hidden button and a
rejected request can never disagree.
"""

from __future__ import annotations

from typing import Iterable

ROLES = ("admin", "consultant", "viewer")

PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"*"}),
    "consultant": frozenset(
        {
            "dashboard:read",
            "client:read",
            "client:write",
            "engagement:read",
            "engagement:write",
            "asset:read",
            "asset:write",
            "threat:read",
            "threat:write",
            "risk:read",
            "risk:write",
            "stakeholder:write",
            "audit:read",
        }
    ),
    "viewer": frozenset(
        {
            "dashboard:read",
            "client:read",
            "engagement:read",
            "asset:read",
            "threat:read",
            "risk:read",
            "audit:read",
        }
    ),
}


def is_known_role(role: str) -> bool:
    return role in PERMISSIONS


def permissions_for(role: str) -> frozenset[str]:
    return PERMISSIONS.get(role, frozenset())


def can(role: str, permission: str) -> bool:
    granted = permissions_for(role)
    return "*" in granted or permission in granted


def missing_permissions(role: str, required: Iterable[str]) -> list[str]:
    return [permission for permission in required if not can(role, permission)]
