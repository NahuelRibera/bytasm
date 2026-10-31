"""Add immutable reviews without changing historical reports."""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "review_snapshot",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("version_id", sa.String(32), sa.ForeignKey("sample_version.id"), nullable=False),
        sa.Column("supersedes_id", sa.String(32), sa.ForeignKey("review_snapshot.id")),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("canonical", sa.Text(), nullable=False),
    )
    op.create_index("ix_review_snapshot_version_id", "review_snapshot", ["version_id"])


def downgrade() -> None:
    if op.get_bind().execute(sa.text("SELECT count(*) FROM review_snapshot")).scalar():
        raise RuntimeError("Cannot downgrade while pinned reviews exist")
    op.drop_table("review_snapshot")
