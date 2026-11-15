"""CSV import for asset inventory.

The importer is deliberately strict about shape and lenient about content:
missing or malformed cells fail the row and are reported, valid rows are kept.
Duplicate names inside the same engagement are skipped rather than failing the
whole file, because re-running an import is a normal operation.
"""

from __future__ import annotations

import csv
import io

from sqlalchemy import func, select

from aegis.errors import ValidationFailure
from aegis.models import Asset, Engagement
from aegis.security.validation import (
    ASSET_CATEGORIES,
    ASSET_LIFECYCLE,
    ASSET_TYPES,
    cia_grade,
    choice,
    require_text,
)
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.util.time import utcnow

MAX_ROWS = 1000

# Canonical column -> accepted headers. Matching ignores case, spaces and
# underscores, so "Asset Type", "asset_type" and "类型" resolve to one column.
COLUMNS = {
    "name": ("name", "资产名称", "名称"),
    "asset_type": ("asset_type", "type", "类型", "资产类型"),
    "category": ("category", "类别", "资产类别"),
    "owner": ("owner", "责任人", "负责人"),
    "department": ("department", "部门"),
    "location": ("location", "位置", "部署位置"),
    "confidentiality": ("confidentiality", "c", "机密性"),
    "integrity": ("integrity", "i", "完整性"),
    "availability": ("availability", "a", "可用性"),
    "lifecycle_status": ("lifecycle_status", "lifecycle", "状态", "生命周期"),
    "description": ("description", "描述", "备注"),
}

REQUIRED = ("name",)

# Chinese input is common; accept the labels people actually type in a sheet.
VALUE_ALIASES = {
    "asset_type": {
        "业务资产": "business",
        "业务": "business",
        "business": "business",
        "支撑资产": "supporting",
        "支撑": "supporting",
        "supporting": "supporting",
    },
    "category": {
        "应用系统": "application",
        "应用": "application",
        "数据库": "database",
        "服务器": "server",
        "网络设备": "network",
        "网络": "network",
        "终端": "endpoint",
        "数据": "data",
        "人员": "people",
        "场所": "facility",
        "业务流程": "process",
        "流程": "process",
        "云服务": "cloud",
        "云": "cloud",
        "第三方": "third_party",
        "其他": "other",
    },
    "lifecycle_status": {
        "规划中": "planned",
        "规划": "planned",
        "在用": "active",
        "运行中": "active",
        "active": "active",
        "已退役": "retired",
        "退役": "retired",
        "retired": "retired",
    },
}


class AssetImportService(ServiceBase):
    def import_bytes(
        self,
        ctx: AuthContext,
        engagement_id: str,
        payload: bytes,
        *,
        filename: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> dict:
        self.require(ctx, "asset:write")
        text = _decode(payload)
        return self.import_text(
            ctx,
            engagement_id,
            text,
            filename=filename,
            ip=ip,
            user_agent=user_agent,
        )

    def import_text(
        self,
        ctx: AuthContext,
        engagement_id: str,
        text: str,
        *,
        filename: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> dict:
        self.require(ctx, "asset:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise ValidationFailure("engagement not found")

        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValidationFailure("CSV has no header row")

        mapping = _map_headers(reader.fieldnames)
        missing = [column for column in REQUIRED if column not in mapping]
        if missing:
            raise ValidationFailure(
                "CSV is missing required columns: " + ", ".join(missing),
                details={"missing": missing, "headers": list(reader.fieldnames)},
            )

        known_names = set(
            self.db.execute(
                select(Asset.name).where(Asset.engagement_id == engagement.id)
            ).scalars()
        )
        next_index = int(
            self.db.execute(
                select(func.count(Asset.id)).where(Asset.engagement_id == engagement.id)
            ).scalar()
            or 0
        ) + 1

        imported: list[str] = []
        skipped: list[dict] = []
        errors: list[dict] = []
        created = 0

        for offset, raw in enumerate(reader, start=2):
            if created + len(skipped) >= MAX_ROWS:
                errors.append(
                    {
                        "row": offset,
                        "field": "",
                        "message": f"row limit reached, only {MAX_ROWS} rows are processed",
                    }
                )
                break
            values = {column: (raw.get(header) or "").strip() for column, header in mapping.items()}
            name = values.get("name", "")
            if not name:
                errors.append({"row": offset, "field": "name", "message": "name is required"})
                continue
            if name in known_names:
                skipped.append({"row": offset, "name": name, "reason": "name already exists"})
                continue
            try:
                asset = Asset(
                    engagement_id=engagement.id,
                    code=f"AST-{next_index:04d}",
                    name=require_text(name, "name", max_length=200),
                    asset_type=choice(
                        _alias("asset_type", values.get("asset_type", "")),
                        ASSET_TYPES,
                        "asset_type",
                        default="supporting",
                    ),
                    category=choice(
                        _alias("category", values.get("category", "")),
                        ASSET_CATEGORIES,
                        "category",
                        default="other",
                    ),
                    owner=values.get("owner", "")[:120],
                    department=values.get("department", "")[:120],
                    location=values.get("location", "")[:200],
                    description=values.get("description", "")[:2000],
                    confidentiality=cia_grade(values.get("confidentiality"), "confidentiality"),
                    integrity=cia_grade(values.get("integrity"), "integrity"),
                    availability=cia_grade(values.get("availability"), "availability"),
                    lifecycle_status=choice(
                        _alias("lifecycle_status", values.get("lifecycle_status", "")),
                        ASSET_LIFECYCLE,
                        "lifecycle_status",
                        default="active",
                    ),
                    created_by=ctx.user.id,
                )
            except ValidationFailure as exc:
                errors.append(
                    {"row": offset, "field": exc.details.get("field", ""), "message": exc.message}
                )
                continue

            self.db.add(asset)
            known_names.add(name)
            imported.append(asset.code)
            next_index += 1
            created += 1

        if created:
            self.db.flush()
        self.audit.record(
            action="asset.import",
            entity_type="engagement",
            entity_id=engagement.id,
            summary=(
                f"导入资产表 {filename or '(未命名)'}：新增 {created} 条，"
                f"跳过 {len(skipped)} 条，失败 {len(errors)} 条"
            ),
            detail={
                "filename": filename,
                "imported": created,
                "skipped": len(skipped),
                "failed": len(errors),
                "codes": imported[:50],
                "errors": errors[:20],
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return {
            "filename": filename,
            "imported": created,
            "skipped": len(skipped),
            "failed": len(errors),
            "codes": imported,
            "skipped_rows": skipped[:50],
            "errors": errors,
            "imported_at": utcnow().isoformat() + "Z",
        }


def _decode(payload: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValidationFailure("cannot decode CSV file; expected UTF-8 or GB18030")


def _normalize(header: str) -> str:
    return header.strip().lower().replace(" ", "").replace("_", "").replace("-", "")


def _map_headers(fieldnames: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    normalized = {_normalize(name): name for name in fieldnames if name}
    for column, aliases in COLUMNS.items():
        for alias in aliases:
            key = _normalize(alias)
            if key in normalized:
                mapping[column] = normalized[key]
                break
    return mapping


def _alias(column: str, value: str) -> str:
    if not value:
        return ""
    table = VALUE_ALIASES.get(column, {})
    key = value.strip().lower()
    return table.get(value.strip(), table.get(key, value.strip()))


def csv_template() -> str:
    """Header row plus one example, written with a BOM so Excel reads UTF-8."""
    header = (
        "name,asset_type,category,owner,department,location,"
        "confidentiality,integrity,availability,lifecycle_status,description"
    )
    sample = (
        "订单服务,业务资产,应用系统,王工,信息中心,核心机房,3,3,4,在用,"
        "承载线上交易，停机影响直接收入"
    )
    return f"\ufeff{header}\n{sample}\n"
