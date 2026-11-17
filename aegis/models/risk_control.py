"""Link between a scored risk item and a catalog control.

Links belong to the assessment version that owns the risk item, so a new
version does not silently inherit coverage from an older one.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class RiskControlLink(TimestampMixin, Base):
    __tablename__ = "risk_control_links"
    __table_args__ = (
        UniqueConstraint("risk_item_id", "control_id", name="uq_risk_control_pair"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    risk_item_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("risk_items.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    coverage: Mapped[str] = mapped_column(String(20), nullable=False, default="partial")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    control: Mapped["Control"] = relationship()  # noqa: F821
    risk_item: Mapped["RiskItem"] = relationship()  # noqa: F821
