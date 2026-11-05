"""Audit trail service.

Every business write in this project goes through a service that appends an
audit event in the same transaction. The trail is append-only: there is no
update or delete method, and the web/API layers expose read endpoints only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.models import AuditEvent, User
from aegis.util.time import utcnow


@dataclass(frozen=True, slots=True)
class Actor:
    user_id: str | None
    email: str
    ip: str = ""
    user_agent: str = ""


def actor_from_user(user: User | None, ip: str = "", user_agent: str = "") -> Actor:
    return Actor(
        user_id=user.id if user else None,
        email=user.email if user else "",
        ip=ip[:64],
        user_agent=user_agent[:255],
    )


class AuditService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def record(
        self,
        *,
        action: str,
        entity_type: str,
        summary: str,
        entity_id: str = "",
        detail: dict[str, Any] | None = None,
        actor: Actor | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            actor_user_id=actor.user_id if actor else None,
            actor_email=actor.email if actor else "",
            action=action,
            entity_type=entity_type,
            entity_id=entity_id or "",
            summary=summary[:255],
            detail_json=json.dumps(detail or {}, ensure_ascii=False, default=str),
            ip=actor.ip if actor else "",
            user_agent=actor.user_agent if actor else "",
            created_at=utcnow(),
        )
        self.db.add(event)
        return event

    def list_events(
        self,
        *,
        entity_type: str | None = None,
        entity_id: str | None = None,
        actor_email: str | None = None,
        action: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEvent], int]:
        conditions = []
        if entity_type:
            conditions.append(AuditEvent.entity_type == entity_type)
        if entity_id:
            conditions.append(AuditEvent.entity_id == entity_id)
        if actor_email:
            conditions.append(AuditEvent.actor_email == actor_email.strip().lower())
        if action:
            conditions.append(AuditEvent.action == action)

        base = select(AuditEvent)
        count_stmt = select(func.count(AuditEvent.id))
        if conditions:
            base = base.where(*conditions)
            count_stmt = count_stmt.where(*conditions)
        total = int(self.db.execute(count_stmt).scalar() or 0)
        rows = list(
            self.db.execute(
                base.order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)
            ).scalars()
        )
        return rows, total

    def entity_timeline(self, entity_type: str, entity_id: str, limit: int = 20) -> list[AuditEvent]:
        rows = list(
            self.db.execute(
                select(AuditEvent)
                .where(AuditEvent.entity_type == entity_type, AuditEvent.entity_id == entity_id)
                .order_by(AuditEvent.created_at.desc())
                .limit(limit)
            ).scalars()
        )
        return rows
