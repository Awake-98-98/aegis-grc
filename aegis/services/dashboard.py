"""Dashboard aggregation queries."""

from __future__ import annotations

from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.models import AuditEvent, Client, Engagement
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase

ACTIVE_STATUSES = ("scoping", "fieldwork", "reporting")


class DashboardService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def summary(self, ctx: AuthContext, *, recent_limit: int = 8) -> dict:
        self.require(ctx, "dashboard:read")
        client_rows = self.db.execute(
            select(Client.status, func.count(Client.id)).group_by(Client.status)
        ).all()
        client_by_status = {status: int(count) for status, count in client_rows}
        engagement_rows = self.db.execute(
            select(Engagement.status, func.count(Engagement.id)).group_by(Engagement.status)
        ).all()
        engagement_by_status = {status: int(count) for status, count in engagement_rows}

        upcoming = list(
            self.db.execute(
                select(Engagement)
                .where(
                    Engagement.end_date.is_not(None),
                    Engagement.end_date >= date.today(),
                    Engagement.status.in_(ACTIVE_STATUSES),
                )
                .order_by(Engagement.end_date.asc())
                .limit(5)
            ).scalars()
        )
        recent_events = list(
            self.db.execute(
                select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(recent_limit)
            ).scalars()
        )
        total_clients = sum(client_by_status.values())
        total_engagements = sum(engagement_by_status.values())
        return {
            "clients": {
                "total": total_clients,
                "by_status": client_by_status,
                "active": client_by_status.get("active", 0),
            },
            "engagements": {
                "total": total_engagements,
                "by_status": engagement_by_status,
                "active": sum(engagement_by_status.get(s, 0) for s in ACTIVE_STATUSES),
            },
            "upcoming": upcoming,
            "recent_events": recent_events,
        }
