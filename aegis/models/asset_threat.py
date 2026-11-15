"""Concrete asset-threat pair with the vulnerability that exposes it.

The pair is the unit milestone 3 scores. ``exposure`` records how reachable
the weakness is from the threat actor's position.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class AssetThreat(TimestampMixin, Base):
    __tablename__ = "asset_threats"
    __table_args__ = (
        UniqueConstraint("asset_id", "threat_id", name="uq_asset_threats_pair"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    threat_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("threats.id", ondelete="CASCADE"), nullable=False
    )
    vulnerability: Mapped[str] = mapped_column(Text, nullable=False, default="")
    exposure: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="links")  # noqa: F821
    threat: Mapped["Threat"] = relationship(back_populates="links")  # noqa: F821
