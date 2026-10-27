"""v0.1 schema

Revision ID: 0001
Revises:
Create Date: 2026-10-26
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "project",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.Column("updated_at", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "sample",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("project_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["project.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name"),
    )
    with op.batch_alter_table("sample", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_sample_project_id"), ["project_id"], unique=False)

    op.create_table(
        "sample_version",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("sample_id", sa.String(length=32), nullable=False),
        sa.Column("version_label", sa.String(length=100), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("declared_filename", sa.String(length=255), nullable=True),
        sa.Column("detected_format", sa.String(length=8), nullable=False),
        sa.Column("blob_path", sa.String(length=128), nullable=False),
        sa.Column("admitted_under", sa.String(length=32), nullable=False),
        sa.Column("manifest_entry", sa.String(length=255), nullable=True),
        sa.Column("imported_at", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["sample_id"],
            ["sample.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sample_id", "sha256"),
    )
    with op.batch_alter_table("sample_version", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_sample_version_sample_id"), ["sample_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_sample_version_sha256"), ["sha256"], unique=False)

    op.create_table(
        "analysis_run",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("sample_version_id", sa.String(length=32), nullable=False),
        sa.Column("profile_snapshot", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("failure_reason", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.String(length=32), nullable=False),
        sa.Column("finished_at", sa.String(length=32), nullable=False),
        sa.Column("bytasm_version", sa.String(length=32), nullable=False),
        sa.Column("image_digest", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(
            ["sample_version_id"],
            ["sample_version.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("analysis_run", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_analysis_run_sample_version_id"), ["sample_version_id"], unique=False
        )

    op.create_table(
        "authorization_record",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("sample_version_id", sa.String(length=32), nullable=False),
        sa.Column("basis", sa.String(length=32), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("terms_reference", sa.Text(), nullable=True),
        sa.Column("recorded_at", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(
            ["sample_version_id"],
            ["sample_version.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sample_version_id"),
    )
    op.create_table(
        "report",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("sample_version_id", sa.String(length=32), nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("generated_at", sa.String(length=32), nullable=False),
        sa.Column("generator_version", sa.String(length=32), nullable=False),
        sa.Column("path", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(
            ["sample_version_id"],
            ["sample_version.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("report", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_report_sample_version_id"), ["sample_version_id"], unique=False
        )

    op.create_table(
        "tool_invocation",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("run_id", sa.String(length=32), nullable=False),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("tool_name", sa.String(length=32), nullable=False),
        sa.Column("tool_version", sa.String(length=32), nullable=False),
        sa.Column("adapter_name", sa.String(length=32), nullable=False),
        sa.Column("adapter_version", sa.String(length=32), nullable=False),
        sa.Column("args", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("raw_output_path", sa.String(length=128), nullable=False),
        sa.Column("raw_output_sha256", sa.String(length=64), nullable=False),
        sa.Column("entropy_method", sa.String(length=32), nullable=False),
        sa.Column("header", sa.JSON(), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["analysis_run.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("tool_invocation", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_tool_invocation_run_id"), ["run_id"], unique=False)

    op.create_table(
        "section",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("invocation_id", sa.String(length=32), nullable=False),
        sa.Column("index", sa.Integer(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("section_type", sa.String(length=64), nullable=True),
        sa.Column("file_offset", sa.Integer(), nullable=False),
        sa.Column("raw_size", sa.Integer(), nullable=False),
        sa.Column("virtual_address", sa.Integer(), nullable=False),
        sa.Column("virtual_size", sa.Integer(), nullable=False),
        sa.Column("flags", sa.JSON(), nullable=False),
        sa.Column("entropy", sa.Double(), nullable=True),
        sa.Column("entropy_note", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["invocation_id"],
            ["tool_invocation.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invocation_id", "index"),
    )
    with op.batch_alter_table("section", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_section_invocation_id"), ["invocation_id"], unique=False
        )

    op.create_table(
        "symbol",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("invocation_id", sa.String(length=32), nullable=False),
        sa.Column("direction", sa.String(length=8), nullable=False),
        sa.Column("library", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=True),
        sa.Column("address", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["invocation_id"],
            ["tool_invocation.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("symbol", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_symbol_invocation_id"), ["invocation_id"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("symbol", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_symbol_invocation_id"))

    op.drop_table("symbol")
    with op.batch_alter_table("section", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_section_invocation_id"))

    op.drop_table("section")
    with op.batch_alter_table("tool_invocation", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_tool_invocation_run_id"))

    op.drop_table("tool_invocation")
    with op.batch_alter_table("report", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_report_sample_version_id"))

    op.drop_table("report")
    op.drop_table("authorization_record")
    with op.batch_alter_table("analysis_run", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_analysis_run_sample_version_id"))

    op.drop_table("analysis_run")
    with op.batch_alter_table("sample_version", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sample_version_sha256"))
        batch_op.drop_index(batch_op.f("ix_sample_version_sample_id"))

    op.drop_table("sample_version")
    with op.batch_alter_table("sample", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sample_project_id"))

    op.drop_table("sample")
    op.drop_table("project")
