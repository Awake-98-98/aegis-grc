"""Remediation task: the unit a consultant plans, assigns and closes.

The task points at the scored risk item that motivated it, but the labels and
score are copied into ``risk_snapshot`` at creation time. A later assessment
version may drop the item; the task still reads correctly for a reader who has
no access to the old register.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class RemediationTask(TimestampMixin, Base):
    __tablename__ = "remediation_tasks"
    __table_args__ = (
        UniqueConstraint("engagement_id", "code", name="uq_remediation_tasks_code"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    risk_item_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("risk_items.id", ondelete="SET NULL"), nullable=True
    )
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    control_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("controls.id", ondelete="SET NULL"), nullable=True
    )
    owner: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    owner_user_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    risk_snapshot: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    evidence: Mapped[list["EvidenceFile"]] = relationship(  # noqa: F821
        back_populates="task", cascade="all, delete-orphan"
    )

    @property
    def is_overdue(self) -> bool:
        if self.due_date is None or self.status in {"done", "cancelled"}:
            return False
        return self.due_date < date.today()
