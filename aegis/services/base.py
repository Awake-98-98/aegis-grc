"""Shared service plumbing: permission checks and audit actors."""

from __future__ import annotations

from sqlalchemy.orm import Session

from aegis.errors import Forbidden
from aegis.security.rbac import missing_permissions
from aegis.services.audit import Actor, AuditService, actor_from_user
from aegis.services.auth import AuthContext


class ServiceBase:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.audit = AuditService(db)

    def require(self, ctx: AuthContext, permission: str) -> None:
        missing = missing_permissions(ctx.user.role, (permission,))
        if missing:
            raise Forbidden(f"missing permission: {permission}")

    def actor(self, ctx: AuthContext, ip: str = "", user_agent: str = "") -> Actor:
        return actor_from_user(ctx.user, ip, user_agent)
