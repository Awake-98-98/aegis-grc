"""Threat catalog entries scoped to one engagement."""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class Threat(TimestampMixin, Base):
    __tablename__ = "threats"
    __table_args__ = (
        UniqueConstraint("engagement_id", "code", name="uq_threats_engagement_code"),
        UniqueConstraint("engagement_id", "name", name="uq_threats_engagement_name"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    actor: Mapped[str] = mapped_column(String(20), nullable=False, default="external")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    links: Mapped[list["AssetThreat"]] = relationship(  # noqa: F821
        back_populates="threat", cascade="all, delete-orphan"
    )
