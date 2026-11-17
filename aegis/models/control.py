"""Framework metadata and catalog entries.

The catalog is reference data seeded by schema v4. A framework groups controls
by the document that publishes them; a control carries a code that is unique
inside its framework and keeps the original title next to the Chinese one.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class ControlFramework(TimestampMixin, Base):
    __tablename__ = "control_frameworks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    code: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    publisher: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="standard")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    controls: Mapped[list["Control"]] = relationship(
        back_populates="framework",
        order_by="Control.sort_order",
    )


class Control(TimestampMixin, Base):
    __tablename__ = "controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "code", name="uq_controls_code"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    framework_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("control_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    title_en: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    domain: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    domain_label: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    guidance: Mapped[str] = mapped_column(Text, nullable=False, default="")
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    framework: Mapped[ControlFramework] = relationship(back_populates="controls")
