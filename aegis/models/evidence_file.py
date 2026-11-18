"""Metadata for one evidence file attached to a remediation task.

Only the digest and descriptive fields live in the database. The bytes are
written to ``<home>/evidence/<sha[:2]>/<sha>`` by :class:`EvidenceStore`, so the
same document uploaded to two tasks is stored once and rows stay comparable by
digest.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.db.base import Base, TimestampMixin, new_id


class EvidenceFile(TimestampMixin, Base):
    __tablename__ = "evidence_files"
    __table_args__ = (
        UniqueConstraint(
            "remediation_task_id", "sha256", name="uq_evidence_files_digest"
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    engagement_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    remediation_task_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("remediation_tasks.id", ondelete="CASCADE"),
        nullable=False,
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    uploaded_by: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    task: Mapped["RemediationTask"] = relationship(  # noqa: F821
        back_populates="evidence"
    )
