"""Consulting engagement (project) model.

An engagement is the unit every later milestone hangs off: assets, risk
assessments, control gap analyses, remediation plans and reports all belong
to exactly one engagement. Deleting a client with engagements is refused by
the database (``ON DELETE RESTRICT``).
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import Date, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class Engagement(TimestampMixin, Base):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("clients.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    engagement_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="risk_assessment"
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    lead_user_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    scope_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    objectives: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    client: Mapped["Client"] = relationship(back_populates="engagements")  # noqa: F821
    stakeholders: Mapped[list["Stakeholder"]] = relationship(  # noqa: F821
        back_populates="engagement", cascade="all, delete-orphan"
    )
