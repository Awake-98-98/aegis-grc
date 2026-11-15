"""Asset inventory entries.

An asset is scoped to one engagement. The confidentiality, integrity and
availability grades are stored as integers 1-4; the derived criticality and
priority score are computed on read so they cannot drift from the stored
grades.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("engagement_id", "code", name="uq_assets_engagement_code"),
        UniqueConstraint("engagement_id", "name", name="uq_assets_engagement_name"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False, default="supporting")
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="other")
    owner: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    department: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    location: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidentiality: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    integrity: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    availability: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    lifecycle_status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    links: Mapped[list["AssetThreat"]] = relationship(  # noqa: F821
        back_populates="asset", cascade="all, delete-orphan"
    )

    @property
    def priority_score(self) -> int:
        return self.confidentiality * 3 + self.integrity * 2 + self.availability * 2

    @property
    def criticality(self) -> str:
        top = max(self.confidentiality, self.integrity, self.availability)
        if top >= 4:
            return "critical"
        if top == 3:
            return "high"
        if top == 2:
            return "medium"
        return "low"
