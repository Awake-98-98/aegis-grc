"""Threat catalog service.

Threats live per engagement so each project keeps its own vocabulary. Names
are unique inside an engagement to keep the register readable; the same
threat may appear in two projects with different wording.
"""

from __future__ import annotations

from sqlalchemy import func, or_, select

from aegis.errors import Conflict, NotFound
from aegis.models import AssetThreat, Engagement, Threat
from aegis.security.validation import (
    THREAT_ACTORS,
    THREAT_CATEGORIES,
    choice,
    page_params,
    require_text,
)
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import utcnow

THREAT_CATEGORY_LABELS = {
    "malicious": "恶意攻击",
    "insider": "内部人员",
    "environmental": "环境灾害",
    "technical": "技术故障",
    "supply_chain": "供应链",
    "process": "流程缺陷",
    "other": "其他",
}

THREAT_ACTOR_LABELS = {
    "external": "外部攻击者",
    "insider": "内部人员",
    "third_party": "第三方",
    "nature": "自然因素",
    "accidental": "无意失误",
}


class ThreatService(ServiceBase):
    def create(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        name: str,
        category: str = "other",
        actor: str = "external",
        description: str = "",
        code: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Threat:
        self.require(ctx, "threat:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")

        clean_name = require_text(name, "name", max_length=200)
        existing = self.db.execute(
            select(Threat).where(
                Threat.engagement_id == engagement.id, Threat.name == clean_name
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise Conflict(f"threat name already used in this engagement: {clean_name}")

        final_code = require_text(code, "code", max_length=32) if code else self._next_code(
            engagement.id
        )
        if self._code_taken(engagement.id, final_code):
            raise Conflict(f"threat code already exists: {final_code}")

        threat = Threat(
            engagement_id=engagement.id,
            code=final_code,
            name=clean_name,
            category=choice(category, THREAT_CATEGORIES, "category", default="other"),
            actor=choice(actor, THREAT_ACTORS, "actor", default="external"),
            description=require_text(description, "description", max_length=2000, allow_empty=True),
            created_by=ctx.user.id,
        )
        self.db.add(threat)
        self.db.flush()
        self.audit.record(
            action="threat.create",
            entity_type="threat",
            entity_id=threat.id,
            summary=f"登记威胁 {threat.code} {threat.name}（{engagement.code}）",
            detail={
                "engagement_id": engagement.id,
                "code": threat.code,
                "name": threat.name,
                "category": threat.category,
                "actor": threat.actor,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return threat

    def update(
        self,
        ctx: AuthContext,
        threat_id: str,
        *,
        name: str | None = None,
        category: str | None = None,
        actor: str | None = None,
        description: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Threat:
        self.require(ctx, "threat:write")
        threat = self.get(threat_id)
        before = {
            "name": threat.name,
            "category": threat.category,
            "actor": threat.actor,
            "description": threat.description,
        }
        if name is not None:
            clean_name = require_text(name, "name", max_length=200)
            if clean_name != threat.name:
                duplicate = self.db.execute(
                    select(Threat.id).where(
                        Threat.engagement_id == threat.engagement_id,
                        Threat.name == clean_name,
                        Threat.id != threat.id,
                    )
                ).scalar_one_or_none()
                if duplicate is not None:
                    raise Conflict(f"threat name already used in this engagement: {clean_name}")
            threat.name = clean_name
        if category is not None:
            threat.category = choice(category, THREAT_CATEGORIES, "category")
        if actor is not None:
            threat.actor = choice(actor, THREAT_ACTORS, "actor")
        if description is not None:
            threat.description = require_text(
                description, "description", max_length=2000, allow_empty=True
            )
        threat.updated_at = utcnow()
        self.audit.record(
            action="threat.update",
            entity_type="threat",
            entity_id=threat.id,
            summary=f"更新威胁 {threat.code} {threat.name}",
            detail={
                "before": before,
                "after": {
                    "name": threat.name,
                    "category": threat.category,
                    "actor": threat.actor,
                    "description": threat.description,
                },
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return threat

    def delete(
        self, ctx: AuthContext, threat_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "threat:write")
        threat = self.get(threat_id)
        code, name, engagement_id = threat.code, threat.name, threat.engagement_id
        self.db.delete(threat)
        self.audit.record(
            action="threat.delete",
            entity_type="threat",
            entity_id=threat_id,
            summary=f"删除威胁 {code} {name}",
            detail={"code": code, "name": name, "engagement_id": engagement_id},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    def get(self, threat_id: str) -> Threat:
        threat = self.db.get(Threat, threat_id)
        if threat is None:
            raise NotFound("threat not found")
        return threat

    def get_for(self, ctx: AuthContext, threat_id: str) -> Threat:
        self.require(ctx, "threat:read")
        return self.get(threat_id)

    def list(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        q: str = "",
        category: str = "",
        actor: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Threat], int, int, int]:
        self.require(ctx, "threat:read")
        page, page_size = page_params(page, page_size)
        conditions = [Threat.engagement_id == engagement_id]
        if q.strip():
            needle = f"%{q.strip()}%"
            conditions.append(
                or_(
                    Threat.name.ilike(needle),
                    Threat.code.ilike(needle),
                    Threat.description.ilike(needle),
                )
            )
        if category:
            conditions.append(Threat.category == choice(category, THREAT_CATEGORIES, "category"))
        if actor:
            conditions.append(Threat.actor == choice(actor, THREAT_ACTORS, "actor"))

        total = int(
            self.db.execute(
                select(func.count(Threat.id)).where(*conditions)
            ).scalar()
            or 0
        )
        rows = list(
            self.db.execute(
                select(Threat)
                .where(*conditions)
                .order_by(Threat.code.asc())
                .limit(page_size)
                .offset((page - 1) * page_size)
            ).scalars()
        )
        return rows, total, page, page_size

    def asset_counts(self, threat_ids: list[str]) -> dict[str, int]:
        if not threat_ids:
            return {}
        rows = self.db.execute(
            select(AssetThreat.threat_id, func.count(AssetThreat.id))
            .where(AssetThreat.threat_id.in_(threat_ids))
            .group_by(AssetThreat.threat_id)
        ).all()
        return {threat_id: int(count) for threat_id, count in rows}

    def _code_taken(self, engagement_id: str, code: str) -> bool:
        return (
            self.db.execute(
                select(Threat.id).where(
                    Threat.engagement_id == engagement_id, Threat.code == code
                )
            ).scalar_one_or_none()
            is not None
        )

    def _next_code(self, engagement_id: str) -> str:
        total = int(
            self.db.execute(
                select(func.count(Threat.id)).where(Threat.engagement_id == engagement_id)
            ).scalar()
            or 0
        )
        candidate = total + 1
        while True:
            code = f"THR-{candidate:04d}"
            if not self._code_taken(engagement_id, code):
                return code
            candidate += 1
