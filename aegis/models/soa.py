"""Statement of applicability entry for one engagement and control.

The entry is created by the generate step and then edited in place. Excluding
a control is allowed only with a written justification, which is the whole
point of a statement of applicability.
"""

from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class SoAEntry(TimestampMixin, Base):
    __tablename__ = "soa_entries"
    __table_args__ = (
        UniqueConstraint("engagement_id", "control_id", name="uq_soa_entries_pair"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    applicable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    implementation_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="not_started"
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    control: Mapped["Control"] = relationship()  # noqa: F821
