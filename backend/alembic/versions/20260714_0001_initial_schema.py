"""Create the Sentinel AI architecture's PostgreSQL system-of-record tables.

Revision ID: 20260714_0001
Revises:
Create Date: 2026-07-14 00:00:00
"""

from collections.abc import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "20260714_0001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("github_id", sa.BigInteger(), nullable=False),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("github_id", name="uq_users_github_id"),
    )
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("repo_url", sa.Text(), nullable=False),
        sa.Column("repo_owner", sa.Text(), nullable=False),
        sa.Column("repo_name", sa.Text(), nullable=False),
        sa.Column("default_branch", sa.Text(), server_default=sa.text("'main'"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_projects_user_id_users", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
    )
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'queued'"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("files_scanned", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "status IN ('queued', 'cloning', 'static_scan', 'ai_review', 'merging', 'complete', 'failed')",
            name="ck_scans_valid_status",
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], name="fk_scans_project_id_projects", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("idx_scans_project", "scans", ["project_id"])
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("detector", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=3, scale=2), server_default=sa.text("1.0"), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("ai_explanation", sa.Text(), nullable=True),
        sa.Column("fix_suggestion", sa.Text(), nullable=True),
        sa.Column("is_false_positive", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_findings_confidence_range"),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_findings_valid_severity",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], name="fk_findings_scan_id_scans", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("idx_findings_scan", "findings", ["scan_id"])
    op.create_index("idx_findings_severity", "findings", ["severity"])
    op.create_index("idx_findings_category", "findings", ["category"])
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("overall_risk_score", sa.Numeric(precision=4, scale=1), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("finding_counts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("export_url", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("overall_risk_score >= 0 AND overall_risk_score <= 100", name="ck_reports_risk_score_range"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], name="fk_reports_scan_id_scans", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_reports"),
        sa.UniqueConstraint("scan_id", name="uq_reports_scan_id"),
    )


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_index("idx_findings_category", table_name="findings")
    op.drop_index("idx_findings_severity", table_name="findings")
    op.drop_index("idx_findings_scan", table_name="findings")
    op.drop_table("findings")
    op.drop_index("idx_scans_project", table_name="scans")
    op.drop_table("scans")
    op.drop_table("projects")
    op.drop_table("users")
