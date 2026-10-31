"""Immutable exact-function analyst overlays."""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "function_review_revision",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("version_id", sa.String(32), sa.ForeignKey("sample_version.id"), nullable=False),
        sa.Column(
            "invocation_id", sa.String(32), sa.ForeignKey("tool_invocation.id"), nullable=False
        ),
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("document_sha256", sa.String(64), nullable=False),
        sa.UniqueConstraint("scope_sha256", "revision"),
    )
    for column in ("version_id", "invocation_id", "scope_sha256"):
        op.create_index(
            "ix_function_review_revision_" + column, "function_review_revision", [column]
        )


def downgrade() -> None:
    if op.get_bind().execute(sa.text("SELECT count(*) FROM function_review_revision")).scalar():
        raise RuntimeError("Cannot downgrade while function review revisions exist")
    op.drop_table("function_review_revision")
