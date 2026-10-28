"""v0.2 strings step and multi-step runs: string_occurrence, per-step times

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-27

Adds the strings extractor's rows, the start and finish time and a summary
for each analysis step, and when a cancel was requested. Existing rows stay
valid: the new columns are nullable, and runs recorded by 0002 (one YARA-X
step) keep their single invocation.
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analysis_run", schema=None) as batch_op:
        batch_op.add_column(sa.Column("cancel_requested_at", sa.String(length=32), nullable=True))

    with op.batch_alter_table("tool_invocation", schema=None) as batch_op:
        batch_op.add_column(sa.Column("started_at", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("finished_at", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("summary", sa.JSON(), nullable=True))

    op.create_table(
        "string_occurrence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("invocation_id", sa.String(length=32), nullable=False),
        sa.Column("file_offset", sa.Integer(), nullable=False),
        sa.Column("encoding", sa.String(length=16), nullable=False),
        sa.Column("length_chars", sa.Integer(), nullable=False),
        sa.Column("byte_length", sa.Integer(), nullable=False),
        sa.Column("value", sa.String(length=256), nullable=False),
        sa.Column("value_truncated", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["invocation_id"], ["tool_invocation.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invocation_id", "file_offset", "encoding"),
    )
    with op.batch_alter_table("string_occurrence", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_string_occurrence_invocation_id"), ["invocation_id"], unique=False
        )


def downgrade() -> None:
    # 0002 reads a run's single YARA-X step from steps[0]. Runs recorded with
    # the multi-step profile (version 2) cannot be shown by it, so they are
    # removed with everything they produced; v0.1 imports and 0002 runs stay.
    op.drop_table("string_occurrence")
    multi_step = (
        "SELECT id FROM analysis_run WHERE kind = 'analysis' "
        "AND json_extract(profile_snapshot, '$.version') = 2"
    )
    op.execute(
        f"DELETE FROM evidence WHERE finding_id IN (SELECT id FROM finding WHERE run_id IN ({multi_step}))"  # noqa: E501, S608
    )
    op.execute(f"DELETE FROM finding WHERE run_id IN ({multi_step})")  # noqa: S608
    op.execute(f"DELETE FROM tool_invocation WHERE run_id IN ({multi_step})")  # noqa: S608
    op.execute(f"DELETE FROM analysis_run WHERE id IN ({multi_step})")  # noqa: S608
    with op.batch_alter_table("tool_invocation", schema=None) as batch_op:
        batch_op.drop_column("summary")
        batch_op.drop_column("finished_at")
        batch_op.drop_column("started_at")
    with op.batch_alter_table("analysis_run", schema=None) as batch_op:
        batch_op.drop_column("cancel_requested_at")
