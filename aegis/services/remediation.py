"""Remediation tasks and their evidence.

A task is the operational unit a consultant assigns and closes. It can be
created from a scored risk item, in which case the asset code, threat code and
residual score are copied into ``risk_snapshot``. Transitions are a small state
machine; evidence rows reference a content addressed blob store so the same
file uploaded twice is stored once.
"""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from aegis.errors import Conflict, NotFound, StateTransition, ValidationFailure
from aegis.models import (
    Control,
    Engagement,
    EvidenceFile,
    RemediationTask,
    RiskAssessment,
    RiskItem,
    User,
)
from aegis.security.validation import choice, page_params, require_text
from aegis.services.auth import AuthContext
from aegis.services.base import ServiceBase
from aegis.storage.cas import EvidenceStore
from aegis.util.time import parse_date, utcnow

REMEDIATION_PRIORITIES = ("low", "medium", "high", "critical")
REMEDIATION_STATUSES = ("open", "in_progress", "blocked", "done", "cancelled")

PRIORITY_LABELS = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "紧急",
}
STATUS_LABELS = {
    "open": "待开始",
    "in_progress": "进行中",
    "blocked": "受阻",
    "done": "已完成",
    "cancelled": "已取消",
}

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "open": {"in_progress", "blocked", "cancelled"},
    "in_progress": {"blocked", "done", "cancelled"},
    "blocked": {"in_progress", "cancelled"},
    "done": set(),
    "cancelled": set(),
}

TERMINAL_STATUSES = frozenset({"done", "cancelled"})
MAX_FILE_BYTES = 10 * 1024 * 1024
DUE_SOON_DAYS = 7


def is_overdue(task: RemediationTask, today: date | None = None) -> bool:
    if task.due_date is None or task.status in TERMINAL_STATUSES:
        return False
    return task.due_date < (today or date.today())


class RemediationService(ServiceBase):
    def __init__(self, db: Session, store: EvidenceStore) -> None:
        super().__init__(db)
        self.store = store

    # ------------------------------------------------------------------- create
    def create(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        title: str,
        description: str = "",
        priority: str = "medium",
        owner: str = "",
        owner_user_id: str | None = None,
        control_id: str | None = None,
        due_date: str | date | None = None,
        notes: str = "",
        risk_item_id: str | None = None,
        code: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> RemediationTask:
        self.require(ctx, "remediation:write")
        engagement = self.db.get(Engagement, engagement_id)
        if engagement is None:
            raise NotFound("engagement not found")

        clean_title = require_text(title, "title", max_length=200)
        final_code = (
            require_text(code, "code", max_length=32) if code else self._next_code(engagement.id)
        )
        if self._code_taken(engagement.id, final_code):
            raise Conflict(f"remediation code already exists: {final_code}")

        item, snapshot = self._risk_link(engagement.id, risk_item_id)
        task = RemediationTask(
            engagement_id=engagement.id,
            risk_item_id=item.id if item else None,
            code=final_code,
            title=clean_title,
            description=require_text(
                description, "description", max_length=4000, allow_empty=True
            ),
            control_id=self._control_id(control_id),
            owner=require_text(owner, "owner", max_length=120, allow_empty=True),
            owner_user_id=self._user_id(owner_user_id),
            priority=choice(priority, REMEDIATION_PRIORITIES, "priority"),
            due_date=parse_date(due_date, "due_date"),
            notes=require_text(notes, "notes", max_length=4000, allow_empty=True),
            risk_snapshot=snapshot,
            created_by=ctx.user.id,
        )
        self.db.add(task)
        self.db.flush()
        self.audit.record(
            action="remediation.create",
            entity_type="remediation_task",
            entity_id=task.id,
            summary=f"创建整改任务 {task.code} {task.title}（{engagement.code}）",
            detail={
                "engagement_id": engagement.id,
                "code": task.code,
                "title": task.title,
                "priority": task.priority,
                "risk_snapshot": task.risk_snapshot,
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return task

    def create_from_risk(
        self,
        ctx: AuthContext,
        risk_id: str,
        *,
        title: str | None = None,
        description: str = "",
        priority: str = "medium",
        owner: str = "",
        owner_user_id: str | None = None,
        control_id: str | None = None,
        due_date: str | date | None = None,
        notes: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> RemediationTask:
        self.require(ctx, "remediation:write")
        item = self.db.get(RiskItem, risk_id)
        if item is None:
            raise NotFound("risk item not found")
        assessment = self.db.get(RiskAssessment, item.assessment_id)
        if assessment is None:
            raise NotFound("risk assessment not found")
        default_title = f"整改 {item.asset_name} / {item.threat_name}"
        return self.create(
            ctx,
            assessment.engagement_id,
            title=title or default_title,
            description=description,
            priority=priority,
            owner=owner,
            owner_user_id=owner_user_id,
            control_id=control_id,
            due_date=due_date,
            notes=notes,
            risk_item_id=item.id,
            ip=ip,
            user_agent=user_agent,
        )

    def update(
        self,
        ctx: AuthContext,
        task_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        priority: str | None = None,
        owner: str | None = None,
        owner_user_id: str | None = None,
        control_id: str | None = None,
        due_date: str | date | None = None,
        notes: str | None = None,
        ip: str = "",
        user_agent: str = "",
    ) -> RemediationTask:
        self.require(ctx, "remediation:write")
        task = self.get(task_id)
        before = {
            "title": task.title,
            "priority": task.priority,
            "owner": task.owner,
            "owner_user_id": task.owner_user_id,
            "control_id": task.control_id,
            "due_date": task.due_date.isoformat() if task.due_date else None,
        }
        if title is not None:
            task.title = require_text(title, "title", max_length=200)
        if description is not None:
            task.description = require_text(
                description, "description", max_length=4000, allow_empty=True
            )
        if priority is not None:
            task.priority = choice(priority, REMEDIATION_PRIORITIES, "priority")
        if owner is not None:
            task.owner = require_text(owner, "owner", max_length=120, allow_empty=True)
        if owner_user_id is not None:
            task.owner_user_id = self._user_id(owner_user_id)
        if control_id is not None:
            task.control_id = self._control_id(control_id)
        if due_date is not None:
            task.due_date = parse_date(due_date, "due_date")
        if notes is not None:
            task.notes = require_text(notes, "notes", max_length=4000, allow_empty=True)
        task.updated_at = utcnow()
        self.audit.record(
            action="remediation.update",
            entity_type="remediation_task",
            entity_id=task.id,
            summary=f"更新整改任务 {task.code}",
            detail={
                "before": before,
                "after": {
                    "title": task.title,
                    "priority": task.priority,
                    "owner": task.owner,
                    "owner_user_id": task.owner_user_id,
                    "control_id": task.control_id,
                    "due_date": task.due_date.isoformat() if task.due_date else None,
                },
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return task

    def transition(
        self,
        ctx: AuthContext,
        task_id: str,
        status: str,
        *,
        note: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> RemediationTask:
        self.require(ctx, "remediation:write")
        task = self.get(task_id)
        target = choice(status, REMEDIATION_STATUSES, "status")
        if target not in ALLOWED_TRANSITIONS.get(task.status, set()):
            raise StateTransition(
                f"cannot move remediation task from {task.status} to {target}",
                details={"from": task.status, "to": target},
            )
        previous = task.status
        task.status = target
        if target == "done":
            task.completed_at = utcnow()
        task.updated_at = utcnow()
        self.audit.record(
            action="remediation.transition",
            entity_type="remediation_task",
            entity_id=task.id,
            summary=f"整改任务 {task.code}：{STATUS_LABELS[previous]} → {STATUS_LABELS[target]}",
            detail={
                "from": previous,
                "to": target,
                "note": require_text(note, "note", max_length=500, allow_empty=True),
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return task

    def delete(
        self, ctx: AuthContext, task_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "remediation:write")
        task = self.get(task_id)
        if task.status not in {"open", "cancelled"}:
            raise StateTransition("only open or cancelled tasks can be deleted")
        code, title = task.code, task.title
        digests = {
            row.sha256
            for row in self.db.execute(
                select(EvidenceFile).where(EvidenceFile.remediation_task_id == task.id)
            ).scalars()
        }
        self.db.delete(task)
        self.db.flush()
        for digest in digests:
            remaining = int(
                self.db.execute(
                    select(func.count(EvidenceFile.id)).where(
                        EvidenceFile.sha256 == digest
                    )
                ).scalar()
                or 0
            )
            if remaining == 0:
                self.store.unlink(digest)
        self.audit.record(
            action="remediation.delete",
            entity_type="remediation_task",
            entity_id=task_id,
            summary=f"删除整改任务 {code} {title}",
            detail={"code": code, "title": title, "evidence_removed": len(digests)},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    # --------------------------------------------------------------------- read
    def get(self, task_id: str) -> RemediationTask:
        task = self.db.get(RemediationTask, task_id)
        if task is None:
            raise NotFound("remediation task not found")
        return task

    def get_for(self, ctx: AuthContext, task_id: str) -> RemediationTask:
        self.require(ctx, "remediation:read")
        return self.get(task_id)

    def list(
        self,
        ctx: AuthContext,
        engagement_id: str,
        *,
        status: str = "",
        priority: str = "",
        overdue: bool = False,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[RemediationTask], int, int, int]:
        self.require(ctx, "remediation:read")
        if self.db.get(Engagement, engagement_id) is None:
            raise NotFound("engagement not found")
        page, page_size = page_params(page, page_size)
        conditions = [RemediationTask.engagement_id == engagement_id]
        conditions.extend(self._filters(status, priority, overdue))
        return self._page(conditions, page, page_size)

    def list_all(
        self,
        ctx: AuthContext,
        *,
        status: str = "",
        priority: str = "",
        overdue: bool = False,
        q: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[RemediationTask], int, int, int]:
        self.require(ctx, "remediation:read")
        page, page_size = page_params(page, page_size)
        conditions = self._filters(status, priority, overdue)
        keyword = (q or "").strip()
        if keyword:
            pattern = f"%{keyword}%"
            conditions.append(
                or_(
                    RemediationTask.code.ilike(pattern),
                    RemediationTask.title.ilike(pattern),
                    RemediationTask.owner.ilike(pattern),
                )
            )
        return self._page(conditions, page, page_size)

    def summary(self, ctx: AuthContext, engagement_id: str = "") -> dict:
        self.require(ctx, "remediation:read")
        conditions = []
        if engagement_id:
            if self.db.get(Engagement, engagement_id) is None:
                raise NotFound("engagement not found")
            conditions.append(RemediationTask.engagement_id == engagement_id)
        rows = list(
            self.db.execute(select(RemediationTask).where(*conditions)).scalars()
        )
        by_status = {key: 0 for key in REMEDIATION_STATUSES}
        by_priority = {key: 0 for key in REMEDIATION_PRIORITIES}
        overdue = 0
        due_soon = 0
        horizon = date.today() + timedelta(days=DUE_SOON_DAYS)
        for task in rows:
            by_status[task.status] = by_status.get(task.status, 0) + 1
            by_priority[task.priority] = by_priority.get(task.priority, 0) + 1
            if is_overdue(task):
                overdue += 1
            elif (
                task.due_date is not None
                and task.status not in TERMINAL_STATUSES
                and task.due_date <= horizon
            ):
                due_soon += 1
        total = len(rows)
        return {
            "total": total,
            "by_status": by_status,
            "by_priority": by_priority,
            "overdue": overdue,
            "due_soon": due_soon,
            "completion_pct": round(by_status["done"] * 100 / total) if total else 0,
        }

    def tasks_for_risk(self, ctx: AuthContext, risk_id: str) -> list[RemediationTask]:
        self.require(ctx, "remediation:read")
        return list(
            self.db.execute(
                select(RemediationTask)
                .where(RemediationTask.risk_item_id == risk_id)
                .order_by(RemediationTask.created_at.desc())
            ).scalars()
        )

    def counts_for_engagements(self, engagement_ids: list[str]) -> dict[str, int]:
        if not engagement_ids:
            return {}
        rows = self.db.execute(
            select(RemediationTask.engagement_id, func.count(RemediationTask.id))
            .where(RemediationTask.engagement_id.in_(engagement_ids))
            .group_by(RemediationTask.engagement_id)
        ).all()
        return {engagement_id: int(count) for engagement_id, count in rows}

    # ------------------------------------------------------------------ helpers
    def _filters(self, status: str, priority: str, overdue: bool) -> list:
        conditions = []
        if status:
            conditions.append(
                RemediationTask.status == choice(status, REMEDIATION_STATUSES, "status")
            )
        if priority:
            conditions.append(
                RemediationTask.priority
                == choice(priority, REMEDIATION_PRIORITIES, "priority")
            )
        if overdue:
            conditions.append(RemediationTask.due_date.is_not(None))
            conditions.append(RemediationTask.due_date < date.today())
            conditions.append(RemediationTask.status.not_in(TERMINAL_STATUSES))
        return conditions

    def _page(
        self, conditions: list, page: int, page_size: int
    ) -> tuple[list[RemediationTask], int, int, int]:
        total = int(
            self.db.execute(
                select(func.count(RemediationTask.id)).where(*conditions)
            ).scalar()
            or 0
        )
        rows = list(
            self.db.execute(
                select(RemediationTask)
                .where(*conditions)
                .order_by(
                    RemediationTask.due_date.is_(None),
                    RemediationTask.due_date.asc(),
                    RemediationTask.created_at.desc(),
                )
                .limit(page_size)
                .offset((page - 1) * page_size)
            ).scalars()
        )
        return rows, total, page, page_size

    def _risk_link(
        self, engagement_id: str, risk_item_id: str | None
    ) -> tuple[RiskItem | None, str]:
        if not risk_item_id:
            return None, ""
        item = self.db.get(RiskItem, risk_item_id)
        if item is None:
            raise NotFound("risk item not found")
        assessment = self.db.get(RiskAssessment, item.assessment_id)
        if assessment is None or assessment.engagement_id != engagement_id:
            raise ValidationFailure("risk item belongs to another engagement")
        asset = item.asset_code or item.asset_name
        threat = item.threat_code or item.threat_name
        return item, f"{asset} × {threat} 残余 {item.residual_score}"

    def _user_id(self, value: str | None) -> str | None:
        if not value:
            return None
        user = self.db.get(User, value)
        if user is None:
            raise ValidationFailure("owner user not found", details={"field": "owner_user_id"})
        return user.id

    def _control_id(self, value: str | None) -> str | None:
        if not value:
            return None
        control = self.db.get(Control, value)
        if control is None:
            raise ValidationFailure("control not found", details={"field": "control_id"})
        return control.id

    def _code_taken(self, engagement_id: str, code: str) -> bool:
        return (
            self.db.execute(
                select(RemediationTask.id).where(
                    RemediationTask.engagement_id == engagement_id,
                    RemediationTask.code == code,
                )
            ).scalar_one_or_none()
            is not None
        )

    def _next_code(self, engagement_id: str) -> str:
        total = int(
            self.db.execute(
                select(func.count(RemediationTask.id)).where(
                    RemediationTask.engagement_id == engagement_id
                )
            ).scalar()
            or 0
        )
        candidate = total + 1
        while True:
            code = f"RT-{candidate:04d}"
            if not self._code_taken(engagement_id, code):
                return code
            candidate += 1


class EvidenceService(ServiceBase):
    def __init__(self, db: Session, store: EvidenceStore) -> None:
        super().__init__(db)
        self.store = store

    def attach(
        self,
        ctx: AuthContext,
        task_id: str,
        *,
        filename: str,
        data: bytes,
        content_type: str = "",
        ip: str = "",
        user_agent: str = "",
    ) -> tuple[EvidenceFile, bool]:
        self.require(ctx, "evidence:write")
        task = self.db.get(RemediationTask, task_id)
        if task is None:
            raise NotFound("remediation task not found")
        if not data:
            raise ValidationFailure("evidence file is empty")
        if len(data) > MAX_FILE_BYTES:
            raise ValidationFailure(
                "evidence file must be at most 10 MiB",
                details={"max_bytes": MAX_FILE_BYTES},
            )
        digest = self.store.digest(data)
        existing = self.db.execute(
            select(EvidenceFile).where(
                EvidenceFile.remediation_task_id == task.id,
                EvidenceFile.sha256 == digest,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False

        self.store.put(data)
        row = EvidenceFile(
            engagement_id=task.engagement_id,
            remediation_task_id=task.id,
            sha256=digest,
            filename=self._filename(filename),
            content_type=(content_type or "")[:120],
            size_bytes=len(data),
            uploaded_by=ctx.user.id,
        )
        self.db.add(row)
        self.db.flush()
        self.audit.record(
            action="evidence.attach",
            entity_type="evidence_file",
            entity_id=row.id,
            summary=f"上传证据 {row.filename}（{task.code}）",
            detail={
                "remediation_task_id": task.id,
                "sha256": digest,
                "size_bytes": len(data),
            },
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()
        return row, True

    def list(self, ctx: AuthContext, task_id: str) -> list[EvidenceFile]:
        self.require(ctx, "evidence:read")
        if self.db.get(RemediationTask, task_id) is None:
            raise NotFound("remediation task not found")
        return list(
            self.db.execute(
                select(EvidenceFile)
                .where(EvidenceFile.remediation_task_id == task_id)
                .order_by(EvidenceFile.created_at.desc())
            ).scalars()
        )

    def get(self, ctx: AuthContext, evidence_id: str) -> EvidenceFile:
        self.require(ctx, "evidence:read")
        return self._get(evidence_id)

    def download(self, ctx: AuthContext, evidence_id: str) -> tuple[EvidenceFile, bytes]:
        row = self.get(ctx, evidence_id)
        try:
            return row, self.store.read(row.sha256)
        except FileNotFoundError:
            raise NotFound("evidence file is missing from the store") from None

    def delete(
        self, ctx: AuthContext, evidence_id: str, *, ip: str = "", user_agent: str = ""
    ) -> None:
        self.require(ctx, "evidence:write")
        row = self._get(evidence_id)
        digest, filename = row.sha256, row.filename
        self.db.delete(row)
        self.db.flush()
        remaining = int(
            self.db.execute(
                select(func.count(EvidenceFile.id)).where(EvidenceFile.sha256 == digest)
            ).scalar()
            or 0
        )
        if remaining == 0:
            self.store.unlink(digest)
        self.audit.record(
            action="evidence.delete",
            entity_type="evidence_file",
            entity_id=evidence_id,
            summary=f"删除证据 {filename}",
            detail={"sha256": digest},
            actor=self.actor(ctx, ip, user_agent),
        )
        self.db.commit()

    def counts_for_tasks(self, task_ids: list[str]) -> dict[str, int]:
        if not task_ids:
            return {}
        rows = self.db.execute(
            select(EvidenceFile.remediation_task_id, func.count(EvidenceFile.id))
            .where(EvidenceFile.remediation_task_id.in_(task_ids))
            .group_by(EvidenceFile.remediation_task_id)
        ).all()
        return {task_id: int(count) for task_id, count in rows}

    def _get(self, evidence_id: str) -> EvidenceFile:
        row = self.db.get(EvidenceFile, evidence_id)
        if row is None:
            raise NotFound("evidence file not found")
        return row

    @staticmethod
    def _filename(value: str) -> str:
        name = (value or "").replace("\\", "/").split("/")[-1].strip()
        return name[:255] or "evidence.bin"
