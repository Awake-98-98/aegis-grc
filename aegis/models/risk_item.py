"""Scored asset-threat pair inside one assessment.

The pair is copied from ``asset_threats`` together with the asset and threat
labels. Identifiers are kept for navigation but nullable with ``SET NULL``:
deleting an asset must not erase a register that was already issued. Scores
are derived from the four grades, never stored.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id
from aegis.risk.matrix import severity_for


class RiskItem(TimestampMixin, Base):
    __tablename__ = "risk_items"
    __table_args__ = (
        UniqueConstraint(
            "assessment_id", "asset_id", "threat_id", name="uq_risk_items_pair"
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    assessment_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("risk_assessments.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    threat_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("threats.id", ondelete="SET NULL"), nullable=True
    )
    asset_threat_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("asset_threats.id", ondelete="SET NULL"), nullable=True
    )
    asset_code: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    asset_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    threat_code: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    threat_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    residual_likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    residual_impact: Mapped[int] = mapped_column(Integer, nullable=False)
    treatment: Mapped[str] = mapped_column(String(20), nullable=False, default="mitigate")
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    assessment: Mapped["RiskAssessment"] = relationship(  # noqa: F821
        back_populates="items"
    )

    @property
    def inherent_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual_score(self) -> int:
        return self.residual_likelihood * self.residual_impact

    @property
    def inherent_severity(self) -> str:
        return severity_for(self.inherent_score)

    @property
    def residual_severity(self) -> str:
        return severity_for(self.residual_score)

    @property
    def reduction(self) -> int:
        return self.inherent_score - self.residual_score
