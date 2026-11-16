"""Risk appetite for one engagement.

A single score threshold keeps the model honest: a consultant states the
highest residual score the client is willing to carry, and the register marks
anything above it. Per-category appetites can wait until a milestone needs
them.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegis.db.base import Base, TimestampMixin, new_id


class RiskAppetite(TimestampMixin, Base):
    __tablename__ = "risk_appetite"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("engagements.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    max_acceptable_score: Mapped[int] = mapped_column(Integer, nullable=False, default=9)
    statement: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
