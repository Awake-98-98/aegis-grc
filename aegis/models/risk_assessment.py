"""Risk assessment batch.

An assessment is one pass over an engagement's asset-threat pairs. Drafts can
be edited; issuing freezes the batch so a later pass can be compared against
it. Snapshot text lives on the items, not here.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class RiskAssessment(TimestampMixin, Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        UniqueConstraint("engagement_id", "code", name="uq_risk_assessments_code"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    assessor: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    issued_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    issued_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    items: Mapped[list["RiskItem"]] = relationship(  # noqa: F821
        back_populates="assessment", cascade="all, delete-orphan"
    )
