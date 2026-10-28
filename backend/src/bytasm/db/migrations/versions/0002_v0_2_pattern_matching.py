"""v0.2 pattern matching: run lifecycle, rule sets, findings, evidence

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-27

Existing v0.1 rows stay valid: every existing analysis_run becomes
kind = 'import' (its status is already 'succeeded'), and every existing
tool_invocation keeps its LIEF-specific values.
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_set",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tool", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("snapshot_path", sa.String(length=128), nullable=False),
        sa.Column("rule_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sha256"),
    )

    with op.batch_alter_table("analysis_run", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "kind", sa.String(length=16), server_default=sa.text("'import'"), nullable=False
            )
        )
        batch_op.add_column(sa.Column("queued_at", sa.String(length=32), nullable=True))
        batch_op.add_column(
            sa.Column("cancel_requested", sa.Boolean(), server_default=sa.false(), nullable=False)
        )
        batch_op.alter_column("started_at", existing_type=sa.String(length=32), nullable=True)
        batch_op.alter_column("finished_at", existing_type=sa.String(length=32), nullable=True)

    with op.batch_alter_table("tool_invocation", schema=None) as batch_op:
        batch_op.add_column(sa.Column("failure_reason", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("rule_set_id", sa.String(length=32), nullable=True))
        batch_op.alter_column("exit_code", existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column("raw_output_path", existing_type=sa.String(length=128), nullable=True)
        batch_op.alter_column(
            "raw_output_sha256", existing_type=sa.String(length=64), nullable=True
        )
        batch_op.alter_column("entropy_method", existing_type=sa.String(length=32), nullable=True)
        batch_op.alter_column("header", existing_type=sa.JSON(), nullable=True)
        batch_op.create_index(
            batch_op.f("ix_tool_invocation_rule_set_id"), ["rule_set_id"], unique=False
        )
        batch_op.create_foreign_key(
            "fk_tool_invocation_rule_set_id_rule_set", "rule_set", ["rule_set_id"], ["id"]
        )

    op.create_table(
        "finding",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("run_id", sa.String(length=32), nullable=False),
        sa.Column("invocation_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("rule_namespace", sa.String(length=128), nullable=False),
        sa.Column("rule_set_id", sa.String(length=32), nullable=False),
        sa.Column("tool_reported_attributes", sa.JSON(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("match_count", sa.Integer(), nullable=False),
        sa.Column("evidence_truncated", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["invocation_id"], ["tool_invocation.id"]),
        sa.ForeignKeyConstraint(["rule_set_id"], ["rule_set.id"]),
        sa.ForeignKeyConstraint(["run_id"], ["analysis_run.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invocation_id", "rule_namespace", "rule_id"),
    )
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_finding_invocation_id"), ["invocation_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_finding_rule_set_id"), ["rule_set_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_finding_run_id"), ["run_id"], unique=False)

    op.create_table(
        "evidence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("pattern_id", sa.String(length=128), nullable=False),
        sa.Column("file_offset", sa.Integer(), nullable=False),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("xor_key", sa.Integer(), nullable=True),
        sa.Column("excerpt_hex", sa.String(length=64), nullable=False),
        sa.Column("raw_json_pointer", sa.String(length=256), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_evidence_finding_id"), ["finding_id"], unique=False)


def downgrade() -> None:
    # v0.1 has no place for analysis runs: drop them with their findings.
    op.drop_table("evidence")
    op.drop_table("finding")
    op.execute(
        "DELETE FROM tool_invocation WHERE run_id IN "
        "(SELECT id FROM analysis_run WHERE kind = 'analysis')"
    )
    op.execute("DELETE FROM analysis_run WHERE kind = 'analysis'")
    with op.batch_alter_table("tool_invocation", schema=None) as batch_op:
        batch_op.drop_constraint("fk_tool_invocation_rule_set_id_rule_set", type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_tool_invocation_rule_set_id"))
        batch_op.alter_column("header", existing_type=sa.JSON(), nullable=False)
        batch_op.alter_column("entropy_method", existing_type=sa.String(length=32), nullable=False)
        batch_op.alter_column(
            "raw_output_sha256", existing_type=sa.String(length=64), nullable=False
        )
        batch_op.alter_column(
            "raw_output_path", existing_type=sa.String(length=128), nullable=False
        )
        batch_op.alter_column("exit_code", existing_type=sa.Integer(), nullable=False)
        batch_op.drop_column("rule_set_id")
        batch_op.drop_column("failure_reason")
    with op.batch_alter_table("analysis_run", schema=None) as batch_op:
        batch_op.alter_column("finished_at", existing_type=sa.String(length=32), nullable=False)
        batch_op.alter_column("started_at", existing_type=sa.String(length=32), nullable=False)
        batch_op.drop_column("cancel_requested")
        batch_op.drop_column("queued_at")
        batch_op.drop_column("kind")
    op.drop_table("rule_set")
