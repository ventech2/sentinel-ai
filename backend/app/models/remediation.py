"""Human-supervised remediation proposal for a security finding."""

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.user import User


class Remediation(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "remediations"
    __table_args__ = (
        CheckConstraint("tier IN (1, 2, 3)", name="valid_tier"),
        CheckConstraint(
            "status IN ('proposed', 'pending_approval', 'approved', 'verifying', 'pr_opened', 'rejected', 'failed')",
            name="valid_status",
        ),
    )

    finding_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    tier: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="proposed")
    diff: Mapped[str | None] = mapped_column(Text)
    verification_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    pr_url: Mapped[str | None] = mapped_column(Text)
    approved_by: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id"),
    )

    finding: Mapped["Finding"] = relationship(back_populates="remediations")
    approved_by_user: Mapped["User | None"] = relationship(
        back_populates="approved_remediations",
        foreign_keys=[approved_by],
    )
