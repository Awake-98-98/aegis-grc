"""Control catalog, statement of applicability and risk-control mapping.

The catalog is read-only reference data. Everything a consultant writes lives
in ``soa_entries`` (one row per engagement and control) or in
``risk_control_links`` (one row per scored risk item and control). Coverage is
computed on read: the framework percentage uses applicable SoA rows as the
denominator, the risk percentage uses the scored items of one assessment.
"""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from aegis.errors import Conflict, NotFound, ValidationFailure
from aegis.models import (
    Control,
    ControlFramework,
    Engagement,
    RiskAssessment,
    RiskControlLink,
    RiskItem,
    SoAEntry,
)
from aegis.security.validation import choice, page_params, require_text
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import utcnow

IMPLEMENTATION_STATUSES = ("not_started", "in_progress", "implemented")
IMPLEMENTATION_LABELS = {
    "not_started": "未开始",
    "in_progress": "进行中",
    "implemented": "已实施",
}

COVERAGE_LEVELS = ("full", "partial", "planned")
COVERAGE_LABELS = {"full": "完全覆盖", "partial": "部分覆盖", "planned": "计划覆盖"}

FRAMEWORK_KIND_LABELS = {
    "standard": "国际标准",
    "framework": "参考框架",
    "regulation": "法规要求",
}

MAX_JUSTIFICATION = 2000
MAX_NOTES = 2000
MAX_OWNER = 120


class ControlService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def frameworks(self, ctx: AuthContext) -> list[ControlFramework]:
        self.require(ctx, "control:read")
        return list(
            self.db.execute(
                select(ControlFramework).order_by(ControlFramework.code.asc())
            ).scalars()
        )

    def framework_counts(self, framework_ids: list[str]) -> dict[str, int]:
        if not framework_ids:
            return {}
        rows = self.db.execute(
            select(Control.framework_id, func.count(Control.id))
            .where(Control.framework_id.in_(framework_ids))
            .group_by(Control.framework_id)
        ).all()
        return {framework_id: int(count) for framework_id, count in rows}

    def framework(self, ctx: AuthContext, framework_id: str) -> ControlFramework:
        self.require(ctx, "control:read")
        return self._framework(framework_id)

    def framework_by_code(self, ctx: AuthContext, code: str) -> ControlFramework:
        self.require(ctx, "control:read")
        framework = self.db.execute(
            select(ControlFramework).where(ControlFramework.code == code)
        ).scalar_one_or_none()
        if framework is None:
            raise NotFound(f"control framework not found: {code}")
        return framework

    def controls(
        self,
        ctx: AuthContext,
        framework_id: str,
        *,
        q: str = "",
        domain: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Control], int, int, int]:
        self.require(ctx, "control:read")
        self._framework(framework_id)
        page, page_size = page_params(page, page_size)
        conditions = [Control.framework_id == framework_id]
        keyword = (q or "").strip()
        if keyword:
            pattern = f"%{keyword}%"
            conditions.append(
                or_(
                    Control.code.ilike(pattern),
                    Control.title.ilike(pattern),
                    Control.title_en.ilike(pattern),
                )
            )
        if domain:
            conditions.append(Control.domain == domain)
        total = int(
            self.db.execute(select(func.count(Control.id)).where(*conditions)).scalar()
            or 0
        )
        rows = list(
            self.db.execute(
                select(Control)
                .where(*conditions)
                .order_by(Control.sort_order.asc(), Control.code.asc())
                .limit(page_size)
                .offset((page - 1) * page_size)
            ).scalars()
        )
        return rows, total, page, page_size

    def all_controls(self, ctx: AuthContext, framework_id: str) -> list[Control]:
        self.require(ctx, "control:read")
        return list(
            self.db.execute(
                select(Control)
                .where(Control.framework_id == framework_id)
                .order_by(Control.sort_order.asc(), Control.code.asc())
            ).scalars()
        )

    def control(self, ctx: AuthContext, control_id: str) -> Control:
        self.require(ctx, "control:read")
        control = self.db.get(Control, control_id)
        if control is None:
            raise NotFound("control not found")
        return control

    def domains(self, ctx: AuthContext, framework_id: str) -> list[dict]:
        self.require(ctx, "control:read")
        rows = self.db.execute(
            select(
                Control.domain,
                Control.domain_label,
                func.count(Control.id),
                func.min(Control.sort_order),
            )
            .where(Control.framework_id == framework_id)
            .group_by(Control.domain, Control.domain_label)
            .order_by(func.min(Control.sort_order).asc())
        ).all()
        return [
            {
                "domain": domain,
                "domain_label": label,
                "control_count": int(count),
            }
            for domain, label, count, _ in rows
        ]

    def _framework(self, framework_id: str) -> ControlFramework:
        framework = self.db.get(ControlFramework, framework_id)
        if framework is None:
            raise NotFound("control framework not found")
        return framework


class SoAService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def generate(
        self,
        ctx: AuthContext,
        engagement_id: str,
        framework_id: str,
        *,
        ip: str = "",
        user_agent: str = "",
    ) -> dict:
        self.require(ctx, "control:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")
        framework = self.db.get(ControlFramework, framework_id)
        if framework is None:
            raise NotFound("control framework not found")

        existing = set(
            self.db.execute(
                select(SoAEntry.control_id)
                .join(Control, SoAEntry.control_id == Control.id)
                .where(
                    SoAEntry.engagement_id == engagement.id,
                    Control.framework_id == framework.id,
                )
            ).scalars()
        )
        created = 0
        total = 0
        for control in self.db.execute(
            select(Control)
            .where(Control.framework_id == framework.id)
            .order_by(Control.sort_order.asc(), Control.code.asc())
        ).scalars():
            total += 1
            if control.id in existing:
                continue
            self.db.add(SoAEntry(engagement_id=engagement.id, control_id=control.id))
            created += 1
        self.audit.record(
            action="soa.generate",
            entity_type="engagement",
            entity_id=engagement.id,
            summary=f"为 {engagement.code} 生成 {framework.name} 适用性声明，新增 {created} 项",
            detail={
                "framework_id": framework.id,
                "framework_code": framework.code,
                "created": created,
                "skipped": total - created,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return {"created": created, "skipped": total - created, "total": total}

    def entries(
        self,
        ctx: AuthContext,
        engagement_id: str,
        framework_id: str,
        *,
        q: str = "",
        domain: str = "",
        status: str = "",
        applicable: bool | None = None,
    ) -> list[tuple[SoAEntry, Control]]:
        self.require(ctx, "control:read")
        conditions = [Control.framework_id == framework_id]
        keyword = (q or "").strip()
        if keyword:
            pattern = f"%{keyword}%"
            conditions.append(
                or_(
                    Control.code.ilike(pattern),
                    Control.title.ilike(pattern),
                    Control.title_en.ilike(pattern),
                )
            )
        if domain:
            conditions.append(Control.domain == domain)
        if status:
            conditions.append(
                SoAEntry.implementation_status
                == choice(status, IMPLEMENTATION_STATUSES, "status")
            )
        if applicable is not None:
            conditions.append(SoAEntry.applicable.is_(applicable))
        rows = self.db.execute(
            select(SoAEntry, Control)
            .join(Control, SoAEntry.control_id == Control.id)
            .where(SoAEntry.engagement_id == engagement_id, *conditions)
            .order_by(Control.sort_order.asc(), Control.code.asc())
        ).all()
        return [(entry, control) for entry, control in rows]

    def summary(
        self, ctx: AuthContext, engagement_id: str, framework_id: str
    ) -> dict:
        self.require(ctx, "control:read")
        framework = self.db.get(ControlFramework, framework_id)
        if framework is None:
            raise NotFound("control framework not found")
        total = int(
            self.db.execute(
                select(func.count(Control.id)).where(
                    Control.framework_id == framework.id
                )
            ).scalar()
            or 0
        )
        rows = self.entries(ctx, engagement_id, framework.id)
        applicable = 0
        excluded = 0
        implemented = 0
        in_progress = 0
        not_started = 0
        unjustified = 0
        for entry, _control in rows:
            if entry.applicable:
                applicable += 1
                if entry.implementation_status == "implemented":
                    implemented += 1
                elif entry.implementation_status == "in_progress":
                    in_progress += 1
                else:
                    not_started += 1
            else:
                excluded += 1
                if not entry.justification.strip():
                    unjustified += 1
        coverage_pct = round(implemented / applicable * 100, 1) if applicable else 0.0
        return {
            "framework_id": framework.id,
            "framework_code": framework.code,
            "total_controls": total,
            "generated": len(rows),
            "applicable": applicable,
            "excluded": excluded,
            "implemented": implemented,
            "in_progress": in_progress,
            "not_started": not_started,
            "coverage_pct": coverage_pct,
            "excluded_without_justification": unjustified,
        }

    def entry(self, ctx: AuthContext, entry_id: str) -> SoAEntry:
        self.require(ctx, "control:read")
        entry = self.db.get(SoAEntry, entry_id)
        if entry is None:
            raise NotFound("statement of applicability entry not found")
        return entry

    def update(
        self,
        ctx: AuthContext,
        entry_id: str,
        *,
        applicable: bool | None = None,
        implementation_status: str | None = None,
        justification: str | None = None,
        owner: str | None = None,
        notes: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> SoAEntry:
        self.require(ctx, "control:write")
        entry = self.db.get(SoAEntry, entry_id)
        if entry is None:
            raise NotFound("statement of applicability entry not found")
        before = {
            "applicable": entry.applicable,
            "implementation_status": entry.implementation_status,
            "justification": entry.justification,
            "owner": entry.owner,
        }
        final_applicable = entry.applicable if applicable is None else bool(applicable)
        final_status = (
            entry.implementation_status
            if implementation_status is None
            else choice(implementation_status, IMPLEMENTATION_STATUSES, "implementation_status")
        )
        final_justification = (
            entry.justification
            if justification is None
            else require_text(
                justification,
                "justification",
                max_length=MAX_JUSTIFICATION,
                allow_empty=True,
            )
        )
        if not final_applicable:
            if not final_justification:
                raise ValidationFailure(
                    "excluded controls need a justification",
                    details={"field": "justification"},
                )
            if final_status != "not_started":
                raise ValidationFailure(
                    "excluded controls cannot be marked as in progress or implemented",
                    details={"field": "implementation_status"},
                )

        entry.applicable = final_applicable
        entry.implementation_status = final_status
        entry.justification = final_justification
        if owner is not None:
            entry.owner = require_text(
                owner, "owner", max_length=MAX_OWNER, allow_empty=True
            )
        if notes is not None:
            entry.notes = require_text(
                notes, "notes", max_length=MAX_NOTES, allow_empty=True
            )
        entry.updated_by = ctx.user.id
        entry.updated_at = utcnow()
        control = self.db.get(Control, entry.control_id)
        self.audit.record(
            action="soa.update",
            entity_type="engagement",
            entity_id=entry.engagement_id,
            summary=f"更新适用性声明 {control.code if control else entry.control_id}",
            detail={
                "entry_id": entry.id,
                "before": before,
                "after": {
                    "applicable": entry.applicable,
                    "implementation_status": entry.implementation_status,
                    "justification": entry.justification,
                    "owner": entry.owner,
                },
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return entry

    def export_rows(
        self, ctx: AuthContext, engagement_id: str, framework_id: str
    ) -> list[dict]:
        rows = []
        for entry, control in self.entries(ctx, engagement_id, framework_id):
            rows.append(
                {
                    "control_code": control.code,
                    "control_title": control.title,
                    "domain": control.domain,
                    "domain_label": control.domain_label,
                    "applicable": "是" if entry.applicable else "否",
                    "implementation_status": IMPLEMENTATION_LABELS.get(
                        entry.implementation_status, entry.implementation_status
                    ),
                    "owner": entry.owner,
                    "justification": entry.justification,
                    "notes": entry.notes,
                }
            )
        return rows


class RiskControlService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def link(
        self,
        ctx: AuthContext,
        risk_item_id: str,
        *,
        control_id: str,
        coverage: str = "partial",
        notes: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> RiskControlLink:
        self.require(ctx, "control:write")
        risk_item = self.db.get(RiskItem, risk_item_id)
        if risk_item is None:
            raise NotFound("risk item not found")
        control = self.db.get(Control, control_id)
        if control is None:
            raise NotFound("control not found")
        existing = self.db.execute(
            select(RiskControlLink).where(
                RiskControlLink.risk_item_id == risk_item.id,
                RiskControlLink.control_id == control.id,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise Conflict("this control is already linked to the risk item")

        link = RiskControlLink(
            risk_item_id=risk_item.id,
            control_id=control.id,
            coverage=choice(coverage, COVERAGE_LEVELS, "coverage"),
            notes=require_text(notes, "notes", max_length=MAX_NOTES, allow_empty=True),
            created_by=ctx.user.id,
        )
        self.db.add(link)
        self.db.flush()
        self.audit.record(
            action="risk_control.link",
            entity_type="risk_item",
            entity_id=risk_item.id,
            summary=f"将控制 {control.code} 关联到风险项 {risk_item.asset_code}/{risk_item.threat_code}",
            detail={
                "link_id": link.id,
                "control_id": control.id,
                "control_code": control.code,
                "coverage": link.coverage,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return link

    def unlink(
        self, ctx: AuthContext, link_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "control:write")
        link = self.db.get(RiskControlLink, link_id)
        if link is None:
            raise NotFound("risk control link not found")
        control = self.db.get(Control, link.control_id)
        self.db.delete(link)
        self.audit.record(
            action="risk_control.unlink",
            entity_type="risk_item",
            entity_id=link.risk_item_id,
            summary=f"解除控制 {control.code if control else link.control_id} 与风险项的关联",
            detail={
                "link_id": link_id,
                "control_id": link.control_id,
                "coverage": link.coverage,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    def links_for_risk(
        self, ctx: AuthContext, risk_item_id: str
    ) -> list[RiskControlLink]:
        self.require(ctx, "control:read")
        return list(
            self.db.execute(
                select(RiskControlLink)
                .options(
                    joinedload(RiskControlLink.control).joinedload(Control.framework)
                )
                .where(RiskControlLink.risk_item_id == risk_item_id)
                .order_by(RiskControlLink.created_at.asc())
            ).scalars()
        )

    def links_for_assessment(
        self, assessment_id: str
    ) -> dict[str, list[RiskControlLink]]:
        rows = self.db.execute(
            select(RiskControlLink)
            .options(joinedload(RiskControlLink.control).joinedload(Control.framework))
            .join(RiskItem, RiskControlLink.risk_item_id == RiskItem.id)
            .where(RiskItem.assessment_id == assessment_id)
            .order_by(RiskControlLink.created_at.asc())
        ).scalars()
        grouped: dict[str, list[RiskControlLink]] = {}
        for link in rows:
            grouped.setdefault(link.risk_item_id, []).append(link)
        return grouped

    def coverage(self, ctx: AuthContext, assessment_id: str) -> dict:
        self.require(ctx, "control:read")
        assessment = self.db.get(RiskAssessment, assessment_id)
        if assessment is None:
            raise NotFound("risk assessment not found")
        items = list(
            self.db.execute(
                select(RiskItem)
                .where(RiskItem.assessment_id == assessment.id)
                .order_by(
                    (RiskItem.likelihood * RiskItem.impact).desc(),
                    RiskItem.asset_code.asc(),
                    RiskItem.threat_code.asc(),
                )
            ).scalars()
        )
        grouped = self.links_for_assessment(assessment.id)
        by_framework: dict[str, int] = {}
        by_coverage = {level: 0 for level in COVERAGE_LEVELS}
        covered_ids: set[str] = set()
        rows = []
        for item in items:
            links = grouped.get(item.id, [])
            frameworks = set()
            for link in links:
                by_coverage[link.coverage] = by_coverage.get(link.coverage, 0) + 1
                if link.control and link.control.framework:
                    frameworks.add(link.control.framework.code)
            if links:
                covered_ids.add(item.id)
                for code in frameworks:
                    by_framework[code] = by_framework.get(code, 0) + 1
            rows.append(
                {
                    "item": item,
                    "links": links,
                    "covered": bool(links),
                    "frameworks": sorted(frameworks),
                }
            )
        total = len(items)
        covered = len(covered_ids)
        return {
            "assessment": assessment,
            "rows": rows,
            "summary": {
                "total": total,
                "covered": covered,
                "uncovered": total - covered,
                "links": sum(len(entry["links"]) for entry in rows),
                "coverage_pct": round(covered / total * 100, 1) if total else 0.0,
                "by_framework": by_framework,
                "by_coverage": by_coverage,
            },
        }

    def default_assessment(
        self, ctx: AuthContext, engagement_id: str
    ) -> RiskAssessment | None:
        self.require(ctx, "control:read")
        issued = self.db.execute(
            select(RiskAssessment)
            .where(
                RiskAssessment.engagement_id == engagement_id,
                RiskAssessment.status == "issued",
            )
            .order_by(RiskAssessment.issued_at.desc())
        ).scalars().first()
        if issued is not None:
            return issued
        return (
            self.db.execute(
                select(RiskAssessment)
                .where(RiskAssessment.engagement_id == engagement_id)
                .order_by(RiskAssessment.created_at.desc())
            ).scalars().first()
        )
