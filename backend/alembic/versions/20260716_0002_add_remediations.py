"""Add remediation proposals for human-supervised security fixes.

Revision ID: 20260716_0002
Revises: 20260714_0001
Create Date: 2026-07-16 00:00:00
"""

from collections.abc import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "20260716_0002"
down_revision: Union[str, Sequence[str], None] = "20260714_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "remediations",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'proposed'"), nullable=False),
        sa.Column("diff", sa.Text(), nullable=True),
        sa.Column("verification_result", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("pr_url", sa.Text(), nullable=True),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("tier IN (1, 2, 3)", name="ck_remediations_valid_tier"),
        sa.CheckConstraint(
            "status IN ('proposed', 'pending_approval', 'approved', 'verifying', 'pr_opened', 'rejected', 'failed')",
            name="ck_remediations_valid_status",
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], name="fk_remediations_finding_id_findings", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], name="fk_remediations_approved_by_users"),
        sa.PrimaryKeyConstraint("id", name="pk_remediations"),
    )


def downgrade() -> None:
    op.drop_table("remediations")
