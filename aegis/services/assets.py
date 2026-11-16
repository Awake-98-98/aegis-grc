"""Asset inventory service.

Audit events are written in the same transaction as the asset change, as in
the client and engagement services.
"""

from __future__ import annotations

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from aegis.errors import Conflict, NotFound, ValidationFailure
from aegis.models import Asset, AssetThreat, Engagement, Threat
from aegis.security.validation import (
    ASSET_CATEGORIES,
    ASSET_LIFECYCLE,
    ASSET_TYPES,
    LEVELS,
    choice,
    cia_grade,
    page_params,
    require_text,
)
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import utcnow

ASSET_TYPE_LABELS = {"business": "业务资产", "supporting": "支撑资产"}

ASSET_CATEGORY_LABELS = {
    "application": "应用系统",
    "database": "数据库",
    "server": "服务器",
    "network": "网络设备",
    "endpoint": "终端",
    "data": "数据",
    "people": "人员",
    "facility": "场所",
    "process": "业务流程",
    "cloud": "云服务",
    "third_party": "第三方",
    "other": "其他",
}

ASSET_LIFECYCLE_LABELS = {"planned": "规划中", "active": "在用", "retired": "已退役"}

CRITICALITY_LABELS = {"low": "低", "medium": "中", "high": "高", "critical": "关键"}

MAX_TEXT = 4000
MAX_DESCRIPTION = 2000


class AssetService(ServiceBase):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------- create
    def create(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        name: str,
        asset_type: str = "supporting",
        category: str = "other",
        owner: str = "",
        department: str = "",
        location: str = "",
        description: str = "",
        confidentiality: int = 2,
        integrity: int = 2,
        availability: int = 2,
        lifecycle_status: str = "active",
        code: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Asset:
        self.require(ctx, "asset:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")

        clean_name = require_text(name, "name", max_length=200)
        existing = self.db.execute(
            select(Asset).where(
                Asset.engagement_id == engagement.id, Asset.name == clean_name
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise Conflict(f"asset name already used in this engagement: {clean_name}")

        final_code = (
            require_text(code, "code", max_length=32) if code else self._next_code(engagement.id)
        )
        if self._code_taken(engagement.id, final_code):
            raise Conflict(f"asset code already exists: {final_code}")

        asset = Asset(
            engagement_id=engagement.id,
            code=final_code,
            name=clean_name,
            asset_type=choice(asset_type, ASSET_TYPES, "asset_type", default="supporting"),
            category=choice(category, ASSET_CATEGORIES, "category", default="other"),
            owner=require_text(owner, "owner", max_length=120, allow_empty=True),
            department=require_text(department, "department", max_length=120, allow_empty=True),
            location=require_text(location, "location", max_length=200, allow_empty=True),
            description=require_text(
                description, "description", max_length=MAX_DESCRIPTION, allow_empty=True
            ),
            confidentiality=cia_grade(confidentiality, "confidentiality"),
            integrity=cia_grade(integrity, "integrity"),
            availability=cia_grade(availability, "availability"),
            lifecycle_status=choice(
                lifecycle_status, ASSET_LIFECYCLE, "lifecycle_status", default="active"
            ),
            created_by=ctx.user.id,
        )
        self.db.add(asset)
        self.db.flush()
        self.audit.record(
            action="asset.create",
            entity_type="asset",
            entity_id=asset.id,
            summary=f"登记资产 {asset.code} {asset.name}（{engagement.code}）",
            detail={
                "engagement_id": engagement.id,
                "code": asset.code,
                "name": asset.name,
                "category": asset.category,
                "confidentiality": asset.confidentiality,
                "integrity": asset.integrity,
                "availability": asset.availability,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return asset

    # ------------------------------------------------------------------- update
    def update(
        self,
        ctx: AuthContext,
        asset_id: str,
        *,
        name: str | None = None,
        asset_type: str | None = None,
        category: str | None = None,
        owner: str | None = None,
        department: str | None = None,
        location: str | None = None,
        description: str | None = None,
        confidentiality: int | None = None,
        integrity: int | None = None,
        availability: int | None = None,
        lifecycle_status: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> Asset:
        self.require(ctx, "asset:write")
        asset = self.get(asset_id)
        before = _snapshot(asset)

        if name is not None:
            clean_name = require_text(name, "name", max_length=200)
            if clean_name != asset.name:
                duplicate = self.db.execute(
                    select(Asset.id).where(
                        Asset.engagement_id == asset.engagement_id,
                        Asset.name == clean_name,
                        Asset.id != asset.id,
                    )
                ).scalar_one_or_none()
                if duplicate is not None:
                    raise Conflict(f"asset name already used in this engagement: {clean_name}")
            asset.name = clean_name
        if asset_type is not None:
            asset.asset_type = choice(asset_type, ASSET_TYPES, "asset_type")
        if category is not None:
            asset.category = choice(category, ASSET_CATEGORIES, "category")
        if owner is not None:
            asset.owner = require_text(owner, "owner", max_length=120, allow_empty=True)
        if department is not None:
            asset.department = require_text(
                department, "department", max_length=120, allow_empty=True
            )
        if location is not None:
            asset.location = require_text(location, "location", max_length=200, allow_empty=True)
        if description is not None:
            asset.description = require_text(
                description, "description", max_length=MAX_DESCRIPTION, allow_empty=True
            )
        if confidentiality is not None:
            asset.confidentiality = cia_grade(confidentiality, "confidentiality")
        if integrity is not None:
            asset.integrity = cia_grade(integrity, "integrity")
        if availability is not None:
            asset.availability = cia_grade(availability, "availability")
        if lifecycle_status is not None:
            asset.lifecycle_status = choice(lifecycle_status, ASSET_LIFECYCLE, "lifecycle_status")
        asset.updated_at = utcnow()

        self.audit.record(
            action="asset.update",
            entity_type="asset",
            entity_id=asset.id,
            summary=f"更新资产 {asset.code} {asset.name}",
            detail={"before": before, "after": _snapshot(asset)},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return asset

    def delete(
        self, ctx: AuthContext, asset_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "asset:write")
        asset = self.get(asset_id)
        code, name, engagement_id = asset.code, asset.name, asset.engagement_id
        self.db.delete(asset)
        self.audit.record(
            action="asset.delete",
            entity_type="asset",
            entity_id=asset_id,
            summary=f"删除资产 {code} {name}",
            detail={"code": code, "name": name, "engagement_id": engagement_id},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    # --------------------------------------------------------------------- read
    def get(self, asset_id: str) -> Asset:
        asset = self.db.get(Asset, asset_id)
        if asset is None:
            raise NotFound("asset not found")
        return asset

    def get_for(self, ctx: AuthContext, asset_id: str) -> Asset:
        self.require(ctx, "asset:read")
        return self.get(asset_id)

    def list(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        q: str = "",
        category: str = "",
        asset_type: str = "",
        criticality: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Asset], int, int, int]:
        self.require(ctx, "asset:read")
        page, page_size = page_params(page, page_size)
        conditions = [Asset.engagement_id == engagement_id]
        if q.strip():
            needle = f"%{q.strip()}%"
            conditions.append(
                or_(
                    Asset.name.ilike(needle),
                    Asset.code.ilike(needle),
                    Asset.owner.ilike(needle),
                    Asset.description.ilike(needle),
                )
            )
        if category:
            conditions.append(Asset.category == choice(category, ASSET_CATEGORIES, "category"))
        if asset_type:
            conditions.append(Asset.asset_type == choice(asset_type, ASSET_TYPES, "asset_type"))
        if criticality:
            conditions.append(_criticality_filter(criticality))

        total = int(
            self.db.execute(
                select(func.count(Asset.id)).where(*conditions)
            ).scalar()
            or 0
        )
        score = Asset.confidentiality * 3 + Asset.integrity * 2 + Asset.availability * 2
        rows = list(
            self.db.execute(
                select(Asset)
                .where(*conditions)
                .order_by(score.desc(), Asset.name.asc())
                .limit(page_size)
                .offset((page - 1) * page_size)
            ).scalars()
        )
        return rows, total, page, page_size

    def summary(self, ctx: AuthContext, engagement_id: str) -> dict:
        self.require(ctx, "asset:read")
        rows = list(
            self.db.execute(
                select(Asset).where(Asset.engagement_id == engagement_id)
            ).scalars()
        )
        by_category: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_criticality: dict[str, int] = {}
        for row in rows:
            by_category[row.category] = by_category.get(row.category, 0) + 1
            by_type[row.asset_type] = by_type.get(row.asset_type, 0) + 1
            by_criticality[row.criticality] = by_criticality.get(row.criticality, 0) + 1
        linked = int(
            self.db.execute(
                select(func.count(AssetThreat.id))
                .join(Asset, Asset.id == AssetThreat.asset_id)
                .where(Asset.engagement_id == engagement_id)
            ).scalar()
            or 0
        )
        linked_assets = set()
        if rows:
            linked_assets = set(
                self.db.execute(
                    select(AssetThreat.asset_id)
                    .where(AssetThreat.asset_id.in_([row.id for row in rows]))
                    .distinct()
                ).scalars()
            )
        return {
            "total": len(rows),
            "by_category": by_category,
            "by_type": by_type,
            "by_criticality": by_criticality,
            "threat_links": linked,
            "unlinked": len([row for row in rows if row.id not in linked_assets]),
        }

    # -------------------------------------------------------------- threat links
    def threat_counts(self, asset_ids: list[str]) -> dict[str, int]:
        if not asset_ids:
            return {}
        rows = self.db.execute(
            select(AssetThreat.asset_id, func.count(AssetThreat.id))
            .where(AssetThreat.asset_id.in_(asset_ids))
            .group_by(AssetThreat.asset_id)
        ).all()
        return {asset_id: int(count) for asset_id, count in rows}

    def links_for(self, asset_id: str) -> list[AssetThreat]:
        return list(
            self.db.execute(
                select(AssetThreat)
                .where(AssetThreat.asset_id == asset_id)
                .order_by(AssetThreat.created_at.asc())
            ).scalars()
        )

    def links_for_engagement(
        self, ctx: AuthContext, engagement_id: str
    ) -> list[AssetThreat]:
        self.require(ctx, "asset:read")
        return list(
            self.db.execute(
                select(AssetThreat)
                .join(Asset, AssetThreat.asset_id == Asset.id)
                .where(Asset.engagement_id == engagement_id)
                .order_by(Asset.code.asc(), AssetThreat.created_at.asc())
            ).scalars()
        )

    def link_threat(
        self,
        ctx: AuthContext,
        asset_id: str,
        *,
        threat_id: str,
        vulnerability: str = "",
        exposure: str = "medium",
        notes: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> AssetThreat:
        self.require(ctx, "asset:write")
        asset = self.get(asset_id)
        threat = self.db.get(Threat, threat_id)
        if threat is None:
            raise NotFound("threat not found")
        if threat.engagement_id != asset.engagement_id:
            raise ValidationFailure(
                "threat and asset belong to different engagements",
                details={"asset_id": asset.id, "threat_id": threat.id},
            )
        existing = self.db.execute(
            select(AssetThreat).where(
                AssetThreat.asset_id == asset.id, AssetThreat.threat_id == threat.id
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise Conflict("this threat is already linked to the asset")

        link = AssetThreat(
            asset_id=asset.id,
            threat_id=threat.id,
            vulnerability=require_text(
                vulnerability, "vulnerability", max_length=MAX_TEXT, allow_empty=True
            ),
            exposure=choice(exposure, LEVELS, "exposure", default="medium"),
            notes=require_text(notes, "notes", max_length=MAX_TEXT, allow_empty=True),
            created_by=ctx.user.id,
        )
        self.db.add(link)
        self.db.flush()
        self.audit.record(
            action="asset.link_threat",
            entity_type="asset",
            entity_id=asset.id,
            summary=f"资产 {asset.code} 关联威胁 {threat.code} {threat.name}",
            detail={
                "asset_id": asset.id,
                "threat_id": threat.id,
                "threat_name": threat.name,
                "exposure": link.exposure,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return link

    def update_link(
        self,
        ctx: AuthContext,
        link_id: str,
        *,
        vulnerability: str | None = None,
        exposure: str | None = None,
        notes: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> AssetThreat:
        self.require(ctx, "asset:write")
        link = self.db.get(AssetThreat, link_id)
        if link is None:
            raise NotFound("asset threat link not found")
        before = {
            "vulnerability": link.vulnerability,
            "exposure": link.exposure,
            "notes": link.notes,
        }
        if vulnerability is not None:
            link.vulnerability = require_text(
                vulnerability, "vulnerability", max_length=MAX_TEXT, allow_empty=True
            )
        if exposure is not None:
            link.exposure = choice(exposure, LEVELS, "exposure")
        if notes is not None:
            link.notes = require_text(notes, "notes", max_length=MAX_TEXT, allow_empty=True)
        link.updated_at = utcnow()
        self.audit.record(
            action="asset.update_link",
            entity_type="asset",
            entity_id=link.asset_id,
            summary="更新资产威胁关联",
            detail={
                "before": before,
                "after": {
                    "vulnerability": link.vulnerability,
                    "exposure": link.exposure,
                    "notes": link.notes,
                },
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return link

    def unlink_threat(
        self, ctx: AuthContext, link_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "asset:write")
        link = self.db.get(AssetThreat, link_id)
        if link is None:
            raise NotFound("asset threat link not found")
        asset_id = link.asset_id
        threat_id = link.threat_id
        self.db.delete(link)
        self.audit.record(
            action="asset.unlink_threat",
            entity_type="asset",
            entity_id=asset_id,
            summary="解除资产与威胁的关联",
            detail={"asset_id": asset_id, "threat_id": threat_id},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    # ------------------------------------------------------------------ private
    def _code_taken(self, engagement_id: str, code: str) -> bool:
        return (
            self.db.execute(
                select(Asset.id).where(
                    Asset.engagement_id == engagement_id, Asset.code == code
                )
            ).scalar_one_or_none()
            is not None
        )

    def _next_code(self, engagement_id: str) -> str:
        total = int(
            self.db.execute(
                select(func.count(Asset.id)).where(Asset.engagement_id == engagement_id)
            ).scalar()
            or 0
        )
        candidate = total + 1
        while True:
            code = f"AST-{candidate:04d}"
            if not self._code_taken(engagement_id, code):
                return code
            candidate += 1


def _criticality_filter(level: str) -> object:
    """Translate a derived criticality label into SQL conditions."""
    top = or_(
        Asset.confidentiality == 4, Asset.integrity == 4, Asset.availability == 4
    )
    if level == "critical":
        return top
    if level == "high":
        return and_(
            or_(
                Asset.confidentiality == 3, Asset.integrity == 3, Asset.availability == 3
            ),
            ~top,
        )
    if level == "medium":
        return and_(
            or_(
                Asset.confidentiality == 2, Asset.integrity == 2, Asset.availability == 2
            ),
            Asset.confidentiality < 3,
            Asset.integrity < 3,
            Asset.availability < 3,
            ~top,
        )
    if level == "low":
        return and_(Asset.confidentiality < 2, Asset.integrity < 2, Asset.availability < 2)
    raise ValidationFailure(
        f"criticality must be one of: {', '.join(CRITICALITY_LABELS)}",
        details={"field": "criticality"},
    )


def _snapshot(asset: Asset) -> dict:
    return {
        "name": asset.name,
        "asset_type": asset.asset_type,
        "category": asset.category,
        "owner": asset.owner,
        "department": asset.department,
        "location": asset.location,
        "description": asset.description,
        "confidentiality": asset.confidentiality,
        "integrity": asset.integrity,
        "availability": asset.availability,
        "lifecycle_status": asset.lifecycle_status,
    }
