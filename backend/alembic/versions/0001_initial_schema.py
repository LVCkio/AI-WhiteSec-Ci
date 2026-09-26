"""initial schema — scan_runs and findings tables.

Revision ID: 0001
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project", sa.String(200), nullable=False, index=True),
        sa.Column("repository", sa.String(300), nullable=False),
        sa.Column("commit_sha", sa.String(64), nullable=False, index=True),
        sa.Column("branch", sa.String(200), nullable=True),
        sa.Column("trigger", sa.String(40), nullable=False, server_default="manual"),
        sa.Column("status", sa.String(30), nullable=False, server_default="running", index=True),
        sa.Column("model_version", sa.String(200), nullable=True),
        sa.Column("checkmarx_config", sa.String(200), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float, nullable=True),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "run_id",
            sa.String(36),
            sa.ForeignKey("scan_runs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("source", sa.String(30), nullable=False, index=True),
        sa.Column("file_path", sa.String(500), nullable=False, index=True),
        sa.Column("function_name", sa.String(300), nullable=True),
        sa.Column("start_line", sa.Integer, nullable=True),
        sa.Column("end_line", sa.Integer, nullable=True),
        sa.Column("cwe", sa.String(30), nullable=True, index=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium", index=True),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("evidence", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("fingerprint", sa.String(64), nullable=False, index=True),
        sa.Column("combination_status", sa.String(40), nullable=True, index=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("scan_runs")
