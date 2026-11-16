"""Risk assessment batches, scored items and appetite.

The batch is the version unit: drafts are editable, issuing freezes them, and
a later batch can be compared against an earlier one by asset and threat
codes. Scores come from the 5x5 matrix in :mod:`aegis.risk.matrix` and are
derived, never stored.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.errors import Conflict, NotFound, StateTransition, ValidationFailure
from aegis.models import (
    AssetThreat,
    Engagement,
    RiskAppetite,
    RiskAssessment,
    RiskItem,
)
from aegis.risk.matrix import DEFAULT_APPETITE, SEVERITY_ORDER
from aegis.security.validation import (
    RISK_ASSESSMENT_STATUSES,
    RISK_TREATMENTS,
    appetite_score,
    choice,
    matrix_grade,
    page_params,
    require_text,
)
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import utcnow

TREATMENT_LABELS = {
    "mitigate": "缓解",
    "accept": "接受",
    "transfer": "转移",
    "avoid": "规避",
}

ASSESSMENT_STATUS_LABELS = {"draft": "草稿", "issued": "已签发"}

MAX_TEXT = 4000
MAX_SUMMARY = 2000


class RiskAssessmentService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------- create
    def create(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        title: str,
        assessor: str = "",
        summary: str = "",
        code: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> RiskAssessment:
        self.require(ctx, "risk:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")

        clean_title = require_text(title, "title", max_length=200)
        final_code = (
            require_text(code, "code", max_length=32) if code else self._next_code(engagement.id)
        )
        if self._code_taken(engagement.id, final_code):
            raise Conflict(f"assessment code already exists: {final_code}")

        assessment = RiskAssessment(
            engagement_id=engagement.id,
            code=final_code,
            title=clean_title,
            assessor=require_text(assessor, "assessor", max_length=120, allow_empty=True),
            summary=require_text(
                summary, "summary", max_length=MAX_SUMMARY, allow_empty=True
            ),
            created_by=ctx.user.id,
        )
        self.db.add(assessment)
        self.db.flush()
        self.audit.record(
            action="risk_assessment.create",
            entity_type="risk_assessment",
            entity_id=assessment.id,
            summary=f"创建评估批次 {assessment.code} {assessment.title}（{engagement.code}）",
            detail={"engagement_id": engagement.id, "code": assessment.code, "title": title},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return assessment

    def update(
        self,
        ctx: AuthContext,
        assessment_id: str,
        *,
        title: str | None = None,
        assessor: str | None = None,
        summary: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> RiskAssessment:
        self.require(ctx, "risk:write")
        assessment = self.get(assessment_id)
        self._require_draft(assessment, "assessment is issued and cannot be edited")
        before = {
            "title": assessment.title,
            "assessor": assessment.assessor,
            "summary": assessment.summary,
        }
        if title is not None:
            assessment.title = require_text(title, "title", max_length=200)
        if assessor is not None:
            assessment.assessor = require_text(
                assessor, "assessor", max_length=120, allow_empty=True
            )
        if summary is not None:
            assessment.summary = require_text(
                summary, "summary", max_length=MAX_SUMMARY, allow_empty=True
            )
        assessment.updated_at = utcnow()
        self.audit.record(
            action="risk_assessment.update",
            entity_type="risk_assessment",
            entity_id=assessment.id,
            summary=f"更新评估批次 {assessment.code}",
            detail={
                "before": before,
                "after": {
                    "title": assessment.title,
                    "assessor": assessment.assessor,
                    "summary": assessment.summary,
                },
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return assessment

    def issue(
        self, ctx: AuthContext, assessment_id: str, *, ip: str = "", user_agent: str = ""
    ) -> RiskAssessment:
        self.require(ctx, "risk:write")
        assessment = self.get(assessment_id)
        if assessment.status == "issued":
            raise StateTransition("assessment is already issued")
        total = int(
            self.db.execute(
                select(func.count(RiskItem.id)).where(
                    RiskItem.assessment_id == assessment.id
                )
            ).scalar()
            or 0
        )
        if total == 0:
            raise ValidationFailure(
                "an assessment needs at least one risk item before it can be issued",
                details={"assessment_id": assessment.id},
            )

        assessment.status = "issued"
        assessment.issued_at = utcnow()
        assessment.issued_by = ctx.user.id
        assessment.updated_at = utcnow()
        self.audit.record(
            action="risk_assessment.issue",
            entity_type="risk_assessment",
            entity_id=assessment.id,
            summary=f"签发评估批次 {assessment.code}（{total} 项风险）",
            detail={"code": assessment.code, "items": total},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return assessment

    def delete(
        self, ctx: AuthContext, assessment_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "risk:write")
        assessment = self.get(assessment_id)
        self._require_draft(assessment, "issued assessments cannot be deleted")
        code, title = assessment.code, assessment.title
        self.db.delete(assessment)
        self.audit.record(
            action="risk_assessment.delete",
            entity_type="risk_assessment",
            entity_id=assessment_id,
            summary=f"删除评估批次 {code} {title}",
            detail={"code": code, "title": title},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    # --------------------------------------------------------------------- read
    def get(self, assessment_id: str) -> RiskAssessment:
        assessment = self.db.get(RiskAssessment, assessment_id)
        if assessment is None:
            raise NotFound("risk assessment not found")
        return assessment

    def get_for(self, ctx: AuthContext, assessment_id: str) -> RiskAssessment:
        self.require(ctx, "risk:read")
        return self.get(assessment_id)

    def list(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        status: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[RiskAssessment], int, int, int]:
        self.require(ctx, "risk:read")
        page, page_size = page_params(page, page_size)
        conditions = [RiskAssessment.engagement_id == engagement_id]
        if status:
            conditions.append(
                RiskAssessment.status
                == choice(status, RISK_ASSESSMENT_STATUSES, "status")
            )
        total = int(
            self.db.execute(
                select(func.count(RiskAssessment.id)).where(*conditions)
            ).scalar()
            or 0
        )
        rows = list(
            self.db.execute(
                select(RiskAssessment)
                .where(*conditions)
                .order_by(RiskAssessment.created_at.desc())
                .limit(page_size)
                .offset((page - 1) * page_size)
            ).scalars()
        )
        return rows, total, page, page_size

    def item_counts(self, assessment_ids: list[str]) -> dict[str, int]:
        if not assessment_ids:
            return {}
        rows = self.db.execute(
            select(RiskItem.assessment_id, func.count(RiskItem.id))
            .where(RiskItem.assessment_id.in_(assessment_ids))
            .group_by(RiskItem.assessment_id)
        ).all()
        return {assessment_id: int(count) for assessment_id, count in rows}

    def items_for(self, assessment_id: str) -> list[RiskItem]:
        return list(
            self.db.execute(
                select(RiskItem)
                .where(RiskItem.assessment_id == assessment_id)
                .order_by(
                    (RiskItem.likelihood * RiskItem.impact).desc(),
                    RiskItem.asset_code.asc(),
                    RiskItem.threat_code.asc(),
                )
            ).scalars()
        )

    def summary(self, ctx: AuthContext, assessment_id: str) -> dict:
        self.require(ctx, "risk:read")
        assessment = self.get(assessment_id)
        items = self.items_for(assessment.id)
        threshold = self._appetite_threshold(assessment.engagement_id)
        by_severity = {key: 0 for key in SEVERITY_ORDER}
        by_treatment = {key: 0 for key in RISK_TREATMENTS}
        above_appetite = 0
        inherent_total = 0
        residual_total = 0
        for item in items:
            by_severity[item.residual_severity] = by_severity.get(item.residual_severity, 0) + 1
            by_treatment[item.treatment] = by_treatment.get(item.treatment, 0) + 1
            inherent_total += item.inherent_score
            residual_total += item.residual_score
            if item.residual_score > threshold:
                above_appetite += 1
        count = len(items)
        return {
            "total": count,
            "by_severity": by_severity,
            "by_treatment": by_treatment,
            "average_inherent": round(inherent_total / count, 1) if count else 0,
            "average_residual": round(residual_total / count, 1) if count else 0,
            "above_appetite": above_appetite,
            "appetite_threshold": threshold,
        }

    # ------------------------------------------------------------------ appetite
    def appetite(self, ctx: AuthContext, engagement_id: str) -> RiskAppetite | None:
        self.require(ctx, "risk:read")
        return self.db.execute(
            select(RiskAppetite).where(RiskAppetite.engagement_id == engagement_id)
        ).scalar_one_or_none()

    def set_appetite(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        max_acceptable_score: int | str,
        statement: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> RiskAppetite:
        self.require(ctx, "risk:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")
        score = appetite_score(max_acceptable_score)
        clean_statement = require_text(
            statement, "statement", max_length=MAX_SUMMARY, allow_empty=True
        )

        row = self.db.execute(
            select(RiskAppetite).where(RiskAppetite.engagement_id == engagement.id)
        ).scalar_one_or_none()
        before = None
        if row is None:
            row = RiskAppetite(engagement_id=engagement.id)
            self.db.add(row)
        else:
            before = {
                "max_acceptable_score": row.max_acceptable_score,
                "statement": row.statement,
            }
        row.max_acceptable_score = score
        row.statement = clean_statement
        row.updated_by = ctx.user.id
        row.updated_at = utcnow()
        self.db.flush()
        self.audit.record(
            action="risk_appetite.update",
            entity_type="engagement",
            entity_id=engagement.id,
            summary=f"更新风险偏好：可接受残余分值 ≤ {score}",
            detail={
                "before": before,
                "after": {
                    "max_acceptable_score": score,
                    "statement": clean_statement,
                },
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return row

    # ------------------------------------------------------------------ compare
    def compare(self, ctx: AuthContext, assessment_id: str, baseline_id: str) -> dict:
        self.require(ctx, "risk:read")
        current = self.get(assessment_id)
        baseline = self.get(baseline_id)
        if current.engagement_id != baseline.engagement_id:
            raise ValidationFailure(
                "assessments belong to different engagements",
                details={"current": current.id, "baseline": baseline.id},
            )
        if current.id == baseline.id:
            raise ValidationFailure(
                "choose a different assessment to compare against",
                details={"assessment_id": current.id},
            )

        baseline_rows = {_key(item): item for item in self.items_for(baseline.id)}
        current_rows = {_key(item): item for item in self.items_for(current.id)}
        rows: list[dict] = []
        counts = {"added": 0, "removed": 0, "changed": 0, "unchanged": 0}
        increased = decreased = 0

        for key in sorted(set(baseline_rows) | set(current_rows)):
            before = baseline_rows.get(key)
            after = current_rows.get(key)
            if before is None:
                change = "added"
            elif after is None:
                change = "removed"
            elif _scores(before) == _scores(after) and before.treatment == after.treatment:
                change = "unchanged"
            else:
                change = "changed"
            counts[change] += 1
            if before is not None and after is not None:
                delta = after.residual_score - before.residual_score
                if delta > 0:
                    increased += 1
                elif delta < 0:
                    decreased += 1
            else:
                delta = None
            anchor = after or before
            rows.append(
                {
                    "key": "|".join(key),
                    "asset_code": anchor.asset_code,
                    "asset_name": anchor.asset_name,
                    "threat_code": anchor.threat_code,
                    "threat_name": anchor.threat_name,
                    "change": change,
                    "before": _compare_snapshot(before),
                    "after": _compare_snapshot(after),
                    "delta_residual": delta,
                }
            )

        return {
            "baseline": baseline,
            "current": current,
            "summary": {
                **counts,
                "increased": increased,
                "decreased": decreased,
                "total": len(rows),
            },
            "rows": rows,
        }

    # ------------------------------------------------------------------ private
    def _require_draft(self, assessment: RiskAssessment, message: str) -> None:
        if assessment.status != "draft":
            raise StateTransition(message)

    def _appetite_threshold(self, engagement_id: str) -> int:
        row = self.db.execute(
            select(RiskAppetite).where(RiskAppetite.engagement_id == engagement_id)
        ).scalar_one_or_none()
        return row.max_acceptable_score if row else DEFAULT_APPETITE

    def _code_taken(self, engagement_id: str, code: str) -> bool:
        return (
            self.db.execute(
                select(RiskAssessment.id).where(
                    RiskAssessment.engagement_id == engagement_id,
                    RiskAssessment.code == code,
                )
            ).scalar_one_or_none()
            is not None
        )

    def _next_code(self, engagement_id: str) -> str:
        total = int(
            self.db.execute(
                select(func.count(RiskAssessment.id)).where(
                    RiskAssessment.engagement_id == engagement_id
                )
            ).scalar()
            or 0
        )
        candidate = total + 1
        while True:
            code = f"RA-{candidate:04d}"
            if not self._code_taken(engagement_id, code):
                return code
            candidate += 1


class RiskService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def add(
        self,
        ctx: AuthContext,
        assessment_id: str,
        *,
        asset_threat_id: str,
        likelihood: int | str = 3,
        impact: int | str = 3,
        residual_likelihood: int | str | None = None,
        residual_impact: int | str | None = None,
        treatment: str = "mitigate",
        rationale: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> RiskItem:
        self.require(ctx, "risk:write")
        assessment = self._draft_assessment(assessment_id)
        link = self.db.get(AssetThreat, asset_threat_id)
        if link is None:
            raise NotFound("asset threat link not found")
        if link.asset.engagement_id != assessment.engagement_id:
            raise ValidationFailure(
                "asset threat link belongs to another engagement",
                details={"asset_threat_id": link.id},
            )
        duplicate = self.db.execute(
            select(RiskItem.id).where(
                RiskItem.assessment_id == assessment.id,
                RiskItem.asset_id == link.asset_id,
                RiskItem.threat_id == link.threat_id,
            )
        ).scalar_one_or_none()
        if duplicate is not None:
            raise Conflict("this pair is already scored in the assessment")

        inherent_l = matrix_grade(likelihood, "likelihood")
        inherent_i = matrix_grade(impact, "impact")
        item = RiskItem(
            assessment_id=assessment.id,
            asset_id=link.asset_id,
            threat_id=link.threat_id,
            asset_threat_id=link.id,
            asset_code=link.asset.code,
            asset_name=link.asset.name,
            threat_code=link.threat.code,
            threat_name=link.threat.name,
            likelihood=inherent_l,
            impact=inherent_i,
            residual_likelihood=matrix_grade(
                residual_likelihood, "residual_likelihood", default=inherent_l
            ),
            residual_impact=matrix_grade(
                residual_impact, "residual_impact", default=inherent_i
            ),
            treatment=choice(treatment, RISK_TREATMENTS, "treatment", default="mitigate"),
            rationale=require_text(rationale, "rationale", max_length=MAX_TEXT, allow_empty=True),
            created_by=ctx.user.id,
        )
        self.db.add(item)
        self.db.flush()
        self.audit.record(
            action="risk.create",
            entity_type="risk_item",
            entity_id=item.id,
            summary=(
                f"评分 {item.asset_code} × {item.threat_code}："
                f"{item.inherent_score} → {item.residual_score}"
            ),
            detail={
                "assessment_id": assessment.id,
                "asset_code": item.asset_code,
                "threat_code": item.threat_code,
                "likelihood": item.likelihood,
                "impact": item.impact,
                "residual_likelihood": item.residual_likelihood,
                "residual_impact": item.residual_impact,
                "treatment": item.treatment,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return item

    def update(
        self,
        ctx: AuthContext,
        item_id: str,
        *,
        likelihood: int | str | None = None,
        impact: int | str | None = None,
        residual_likelihood: int | str | None = None,
        residual_impact: int | str | None = None,
        treatment: str | None = None,
        rationale: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> RiskItem:
        self.require(ctx, "risk:write")
        item = self.get(item_id)
        self._draft_assessment(item.assessment_id)
        before = _item_snapshot(item)

        if likelihood is not None:
            item.likelihood = matrix_grade(likelihood, "likelihood")
        if impact is not None:
            item.impact = matrix_grade(impact, "impact")
        if residual_likelihood is not None:
            item.residual_likelihood = matrix_grade(
                residual_likelihood, "residual_likelihood"
            )
        if residual_impact is not None:
            item.residual_impact = matrix_grade(residual_impact, "residual_impact")
        if treatment is not None:
            item.treatment = choice(treatment, RISK_TREATMENTS, "treatment")
        if rationale is not None:
            item.rationale = require_text(
                rationale, "rationale", max_length=MAX_TEXT, allow_empty=True
            )
        item.updated_at = utcnow()
        self.audit.record(
            action="risk.update",
            entity_type="risk_item",
            entity_id=item.id,
            summary=f"更新评分 {item.asset_code} × {item.threat_code}",
            detail={"before": before, "after": _item_snapshot(item)},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return item

    def delete(
        self, ctx: AuthContext, item_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "risk:write")
        item = self.get(item_id)
        self._draft_assessment(item.assessment_id)
        self.db.delete(item)
        self.audit.record(
            action="risk.delete",
            entity_type="risk_item",
            entity_id=item_id,
            summary=f"删除评分 {item.asset_code} × {item.threat_code}",
            detail={
                "assessment_id": item.assessment_id,
                "asset_code": item.asset_code,
                "threat_code": item.threat_code,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    def get(self, item_id: str) -> RiskItem:
        item = self.db.get(RiskItem, item_id)
        if item is None:
            raise NotFound("risk item not found")
        return item

    def get_for(self, ctx: AuthContext, item_id: str) -> RiskItem:
        self.require(ctx, "risk:read")
        return self.get(item_id)

    def _draft_assessment(self, assessment_id: str) -> RiskAssessment:
        assessment = self.db.get(RiskAssessment, assessment_id)
        if assessment is None:
            raise NotFound("risk assessment not found")
        if assessment.status != "draft":
            raise StateTransition("assessment is issued and cannot be edited")
        return assessment


def _key(item: RiskItem) -> tuple[str, str]:
    return item.asset_code, item.threat_code


def _scores(item: RiskItem) -> tuple[int, int, int, int]:
    return item.likelihood, item.impact, item.residual_likelihood, item.residual_impact


def _item_snapshot(item: RiskItem) -> dict:
    return {
        "likelihood": item.likelihood,
        "impact": item.impact,
        "residual_likelihood": item.residual_likelihood,
        "residual_impact": item.residual_impact,
        "treatment": item.treatment,
        "rationale": item.rationale,
    }


def _compare_snapshot(item: RiskItem | None) -> dict | None:
    if item is None:
        return None
    return {
        "inherent_score": item.inherent_score,
        "residual_score": item.residual_score,
        "inherent_severity": item.inherent_severity,
        "residual_severity": item.residual_severity,
        "treatment": item.treatment,
    }
