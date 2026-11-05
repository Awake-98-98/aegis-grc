"""Stakeholder of an engagement."""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class Stakeholder(TimestampMixin, Base):
    __tablename__ = "stakeholders"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    role_title: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    organization: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    email: Mapped[str] = mapped_column(String(254), nullable=False, default="")
    influence: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    interest: Mapped[str] = mapped_column(String(10), nullable=False, default="medium")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    engagement: Mapped["Engagement"] = relationship(  # noqa: F821
        back_populates="stakeholders"
    )
