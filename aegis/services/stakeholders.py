"""Stakeholder service scoped to one engagement."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.errors import NotFound
from aegis.models import Engagement, Stakeholder
from aegis.security.validation import LEVELS, choice, optional_email, require_text
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import utcnow


class StakeholderService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def create(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        name: str,
        role_title: str = "",
        organization: str = "",
        email: str = "",
        influence: str = "medium",
        interest: str = "medium",
        notes: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> Stakeholder:
        self.require(ctx, "stakeholder:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")
        row = Stakeholder(
            engagement_id=engagement.id,
            name=require_text(name, "name", max_length=120),
            role_title=require_text(role_title, "role_title", max_length=120, allow_empty=True),
            organization=require_text(
                organization, "organization", max_length=200, allow_empty=True
            ),
            email=optional_email(email, "email"),
            influence=choice(influence, LEVELS, "influence", default="medium"),
            interest=choice(interest, LEVELS, "interest", default="medium"),
            notes=require_text(notes, "notes", max_length=2000, allow_empty=True),
        )
        self.db.add(row)
        self.db.flush()
        self.audit.record(
            action="stakeholder.create",
            entity_type="stakeholder",
            entity_id=row.id,
            summary=f"新增干系人 {row.name}（{engagement.code}）",
            detail={"engagement_id": engagement.id, "name": row.name, "influence": row.influence},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return row

    def update(
        self,
        ctx: AuthContext,
        stakeholder_id: str,
        *,
        name: str | None = None,
        role_title: str | None = None,
        organization: str | None = None,
        email: str | None = None,
        influence: str | None = None,
        interest: str | None = None,
        notes: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Stakeholder:
        self.require(ctx, "stakeholder:write")
        row = self.get(stakeholder_id)
        before = _snapshot(row)
        if name is not None:
            row.name = require_text(name, "name", max_length=120)
        if role_title is not None:
            row.role_title = require_text(role_title, "role_title", max_length=120, allow_empty=True)
        if organization is not None:
            row.organization = require_text(
                organization, "organization", max_length=200, allow_empty=True
            )
        if email is not None:
            row.email = optional_email(email, "email")
        if influence is not None:
            row.influence = choice(influence, LEVELS, "influence")
        if interest is not None:
            row.interest = choice(interest, LEVELS, "interest")
        if notes is not None:
            row.notes = require_text(notes, "notes", max_length=2000, allow_empty=True)
        row.updated_at = utcnow()
        self.audit.record(
            action="stakeholder.update",
            entity_type="stakeholder",
            entity_id=row.id,
            summary=f"更新干系人 {row.name}",
            detail={"before": before, "after": _snapshot(row)},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return row

    def delete(
        self,
        ctx: AuthContext,
        stakeholder_id: str,
        *,
        ip: str = "",
        user_agent: str = "",
    ) -> None:
        self.require(ctx, "stakeholder:write")
        row = self.get(stakeholder_id)
        self.db.delete(row)
        self.audit.record(
            action="stakeholder.delete",
            entity_type="stakeholder",
            entity_id=row.id,
            summary=f"删除干系人 {row.name}",
            detail={"engagement_id": row.engagement_id, "name": row.name},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    def list_for(self, engagement_id: str) -> list[Stakeholder]:
        return list(
            self.db.execute(
                select(Stakeholder)
                .where(Stakeholder.engagement_id == engagement_id)
                .order_by(Stakeholder.created_at.asc())
            ).scalars()
        )

    def get(self, stakeholder_id: str) -> Stakeholder:
        row = self.db.get(Stakeholder, stakeholder_id)
        if row is None:
            raise NotFound("stakeholder not found")
        return row


def _snapshot(row: Stakeholder) -> dict:
    return {
        "name": row.name,
        "role_title": row.role_title,
        "organization": row.organization,
        "email": row.email,
        "influence": row.influence,
        "interest": row.interest,
        "notes": row.notes,
    }
