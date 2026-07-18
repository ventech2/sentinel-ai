"""Merged scan report model."""

from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Numeric, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


class Report(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(
            "overall_risk_score >= 0 AND overall_risk_score <= 100",
            name="risk_score_range",
        ),
    )

    scan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    overall_risk_score: Mapped[Decimal] = mapped_column(Numeric(4, 1), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    finding_counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    export_url: Mapped[str | None] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="report")
