"""Engagement lifecycle service with an explicit state machine."""

from __future__ import annotations

from datetime import date

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from aegis.errors import Conflict, NotFound, StateTransition, ValidationFailure
from aegis.models import Client, Engagement, User
from aegis.security.validation import (
    ENGAGEMENT_STATUSES,
    ENGAGEMENT_TYPES,
    choice,
    page_params,
    require_text,
)
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import parse_date, utcnow

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"scoping", "archived"},
    "scoping": {"draft", "fieldwork", "archived"},
    "fieldwork": {"scoping", "reporting", "archived"},
    "reporting": {"fieldwork", "closed", "archived"},
    "closed": {"archived"},
    "archived": set(),
}

STATUS_LABELS = {
    "draft": "草稿",
    "scoping": "范围界定",
    "fieldwork": "现场工作",
    "reporting": "报告编制",
    "closed": "已结项",
    "archived": "已归档",
}

TYPE_LABELS = {
    "risk_assessment": "风险评估",
    "compliance_audit": "合规审计",
    "penetration_test": "渗透测试",
    "incident_response": "应急响应",
    "security_planning": "安全规划",
    "other": "其他",
}

MAX_TEXT = 4000


class EngagementService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------- create
    def create(
        self,
        ctx: AuthContext,
        *,
        client_id: str,
        name: str,
        engagement_type: str = "risk_assessment",
        start_date: str | date | None = None,
        end_date: str | date | None = None,
        lead_user_id: str | None = None,
        scope_summary: str = "",
        objectives: str = "",
        code: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Engagement:
        self.require(ctx, "engagement:write")
        client = self.db.get(Client, client_id)
        if client is None:
            raise NotFound("client not found")

        clean_type = choice(engagement_type, ENGAGEMENT_TYPES, "engagement_type")
        clean_name = require_text(name, "name", max_length=200)
        start = parse_date(start_date, "start_date")
        end = parse_date(end_date, "end_date")
        _check_dates(start, end)
        lead = self._lead_user(lead_user_id)
        final_code = require_text(code, "code", max_length=32) if code else self._next_code()
        if self.db.execute(select(Engagement).where(Engagement.code == final_code)).scalar_one_or_none():
            raise Conflict(f"engagement code already exists: {final_code}")

        engagement = Engagement(
            code=final_code,
            client_id=client.id,
            name=clean_name,
            engagement_type=clean_type,
            status="draft",
            start_date=start,
            end_date=end,
            lead_user_id=lead.id if lead else None,
            scope_summary=require_text(
                scope_summary, "scope_summary", max_length=MAX_TEXT, allow_empty=True
            ),
            objectives=require_text(
                objectives, "objectives", max_length=MAX_TEXT, allow_empty=True
            ),
            created_by=ctx.user.id,
        )
        self.db.add(engagement)
        self.db.flush()
        self.audit.record(
            action="engagement.create",
            entity_type="engagement",
            entity_id=engagement.id,
            summary=f"新建项目 {engagement.code} {engagement.name}",
            detail={
                "code": engagement.code,
                "name": engagement.name,
                "client_id": client.id,
                "client_name": client.name,
                "type": clean_type,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return engagement

    # ------------------------------------------------------------------- update
    def update(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        name: str | None = None,
        engagement_type: str | None = None,
        start_date: str | date | None = None,
        end_date: str | date | None = None,
        lead_user_id: str | None = None,
        scope_summary: str | None = None,
        objectives: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Engagement:
        self.require(ctx, "engagement:write")
        engagement = self.get(engagement_id)
        before = _engagement_snapshot(engagement)

        if name is not None:
            engagement.name = require_text(name, "name", max_length=200)
        if engagement_type is not None:
            engagement.engagement_type = choice(
                engagement_type, ENGAGEMENT_TYPES, "engagement_type"
            )
        if start_date is not None:
            engagement.start_date = parse_date(start_date, "start_date")
        if end_date is not None:
            engagement.end_date = parse_date(end_date, "end_date")
        _check_dates(engagement.start_date, engagement.end_date)
        if lead_user_id is not None:
            lead = self._lead_user(lead_user_id or None)
            engagement.lead_user_id = lead.id if lead else None
        if scope_summary is not None:
            engagement.scope_summary = require_text(
                scope_summary, "scope_summary", max_length=MAX_TEXT, allow_empty=True
            )
        if objectives is not None:
            engagement.objectives = require_text(
                objectives, "objectives", max_length=MAX_TEXT, allow_empty=True
            )
        engagement.updated_at = utcnow()

        after = _engagement_snapshot(engagement)
        self.audit.record(
            action="engagement.update",
            entity_type="engagement",
            entity_id=engagement.id,
            summary=f"更新项目 {engagement.code} {engagement.name}",
            detail={"before": before, "after": after},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return engagement

    def transition(
        self,
        ctx: AuthContext,
        engagement_id: str,
        target: str,
        *,
        note: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> Engagement:
        self.require(ctx, "engagement:write")
        engagement = self.get(engagement_id)
        clean_target = choice(target, ENGAGEMENT_STATUSES, "status")
        allowed = ALLOWED_TRANSITIONS.get(engagement.status, set())
        if clean_target not in allowed:
            raise StateTransition(
                f"cannot move engagement from {engagement.status} to {clean_target}",
                details={"from": engagement.status, "to": clean_target, "allowed": sorted(allowed)},
            )
        previous = engagement.status
        engagement.status = clean_target
        engagement.updated_at = utcnow()
        self.audit.record(
            action="engagement.transition",
            entity_type="engagement",
            entity_id=engagement.id,
            summary=f"项目状态 {previous} → {clean_target}：{engagement.code}",
            detail={"from": previous, "to": clean_target, "note": note[:500]},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return engagement

    # --------------------------------------------------------------------- read
    def get(self, engagement_id: str) -> Engagement:
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")
        return engagement

    def get_for(self, ctx: AuthContext, engagement_id: str) -> Engagement:
        self.require(ctx, "engagement:read")
        return self.get(engagement_id)

    def list(
        self,
        ctx: AuthContext,
        *,
        q: str = "",
        status: str = "",
        client_id: str = "",
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Engagement], int, int, int]:
        self.require(ctx, "engagement:read")
        page, page_size = page_params(page, page_size)
        conditions = []
        if q.strip():
            needle = f"%{q.strip()}%"
            conditions.append(
                or_(
                    Engagement.name.ilike(needle),
                    Engagement.code.ilike(needle),
                    Engagement.scope_summary.ilike(needle),
                )
            )
        if status:
            if status not in ENGAGEMENT_STATUSES:
                raise ValidationFailure(f"unknown engagement status: {status}")
            conditions.append(Engagement.status == status)
        if client_id:
            conditions.append(Engagement.client_id == client_id)

        base = select(Engagement)
        count_stmt = select(func.count(Engagement.id))
        if conditions:
            base = base.where(*conditions)
            count_stmt = count_stmt.where(*conditions)
        total = int(self.db.execute(count_stmt).scalar() or 0)
        rows = list(
            self.db.execute(
                base.order_by(Engagement.updated_at.desc())
                .limit(page_size)
                .offset((page - 1) * page_size)
            ).scalars()
        )
        return rows, total, page, page_size

    def list_for_client(self, ctx: AuthContext, client_id: str) -> list[Engagement]:
        self.require(ctx, "engagement:read")
        return list(
            self.db.execute(
                select(Engagement)
                .where(Engagement.client_id == client_id)
                .order_by(Engagement.updated_at.desc())
            ).scalars()
        )

    def stakeholders(self, engagement_id: str) -> list:
        from aegis.models import Stakeholder

        return list(
            self.db.execute(
                select(Stakeholder)
                .where(Stakeholder.engagement_id == engagement_id)
                .order_by(Stakeholder.created_at.asc())
            ).scalars()
        )

    # ------------------------------------------------------------------ private
    def _lead_user(self, user_id: str | None) -> User | None:
        if not user_id:
            return None
        user = self.db.get(User, user_id)
        if user is None or not user.is_active:
            raise ValidationFailure("lead_user_id does not reference an active user")
        return user

    def _next_code(self) -> str:
        year = date.today().year
        prefix = f"ENG-{year}-"
        total = int(
            self.db.execute(
                select(func.count(Engagement.id)).where(Engagement.code.like(f"{prefix}%"))
            ).scalar()
            or 0
        )
        candidate = total + 1
        while True:
            code = f"{prefix}{candidate:04d}"
            exists = self.db.execute(select(Engagement.id).where(Engagement.code == code)).scalar_one_or_none()
            if exists is None:
                return code
            candidate += 1


def _check_dates(start: date | None, end: date | None) -> None:
    if start and end and end < start:
        raise ValidationFailure(
            "end_date cannot be earlier than start_date",
            details={"field": "end_date"},
        )


def _engagement_snapshot(engagement: Engagement) -> dict:
    return {
        "name": engagement.name,
        "engagement_type": engagement.engagement_type,
        "start_date": engagement.start_date.isoformat() if engagement.start_date else None,
        "end_date": engagement.end_date.isoformat() if engagement.end_date else None,
        "lead_user_id": engagement.lead_user_id,
        "scope_summary": engagement.scope_summary,
        "objectives": engagement.objectives,
    }
