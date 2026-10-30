"""Immutable human annotations and their citations."""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("report", sa.Column("scope", sa.JSON(), nullable=True))
    op.create_table(
        "analyst",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
    )
    op.create_table(
        "annotation",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("root_id", sa.String(32), sa.ForeignKey("annotation.id"), nullable=False),
        sa.Column("supersedes_id", sa.String(32), sa.ForeignKey("annotation.id"), unique=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("version_id", sa.String(32), sa.ForeignKey("sample_version.id"), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(32), nullable=False),
        sa.Column("finding_id", sa.String(32), sa.ForeignKey("finding.id")),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id")),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(16)),
        sa.Column("author_id", sa.String(32), sa.ForeignKey("analyst.id"), nullable=False),
        sa.Column("created_at", sa.String(32), nullable=False),
        sa.UniqueConstraint("root_id", "revision"),
    )
    op.create_index("ix_annotation_root_id", "annotation", ["root_id"])
    op.create_index("ix_annotation_version_id", "annotation", ["version_id"])
    op.create_table(
        "annotation_citation",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("annotation_id", sa.String(32), sa.ForeignKey("annotation.id"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(32), nullable=False),
        sa.Column("finding_id", sa.String(32), sa.ForeignKey("finding.id")),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id")),
        sa.UniqueConstraint("annotation_id", "target_type", "target_id"),
    )
    op.create_index(
        "ix_annotation_citation_annotation_id", "annotation_citation", ["annotation_id"]
    )
    op.execute(
        "INSERT INTO analyst (id, display_name, created_at) "
        "VALUES ('local', 'Local analyst', strftime('%Y-%m-%dT%H:%M:%SZ','now'))"
    )
    for table in ("annotation", "annotation_citation"):
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'annotations are append-only'); END"
            )
    op.execute("""
        CREATE TRIGGER annotation_valid BEFORE INSERT ON annotation
        WHEN NEW.kind NOT IN ('note','interpretation','conclusion')
        OR NEW.target_type NOT IN ('sample_version','finding','evidence')
        OR (NEW.target_type = 'sample_version' AND (NEW.target_id != NEW.version_id
            OR NEW.finding_id IS NOT NULL OR NEW.evidence_id IS NOT NULL))
        OR (NEW.target_type = 'finding' AND (NEW.finding_id IS NULL
            OR NEW.target_id != NEW.finding_id OR NEW.evidence_id IS NOT NULL))
        OR (NEW.target_type = 'evidence' AND (NEW.evidence_id IS NULL
            OR NEW.target_id != CAST(NEW.evidence_id AS TEXT) OR NEW.finding_id IS NOT NULL))
        OR length(trim(NEW.body)) NOT BETWEEN 1 AND 4000 OR NEW.revision < 1
        OR (NEW.kind = 'conclusion' AND (NEW.confidence IS NULL
            OR NEW.confidence NOT IN ('tentative','likely','well-supported')))
        OR (NEW.kind != 'conclusion' AND NEW.confidence IS NOT NULL)
        OR (NEW.revision = 1 AND (NEW.root_id != NEW.id OR NEW.supersedes_id IS NOT NULL))
        OR (NEW.revision > 1 AND NOT EXISTS (
            SELECT 1 FROM annotation p WHERE p.id = NEW.supersedes_id
            AND p.root_id = NEW.root_id AND p.revision = NEW.revision - 1
            AND p.target_type = NEW.target_type AND p.target_id = NEW.target_id
            AND p.version_id = NEW.version_id))
        BEGIN SELECT RAISE(ABORT, 'invalid annotation'); END
    """)
    op.execute("""
        CREATE TRIGGER annotation_citation_valid BEFORE INSERT ON annotation_citation
        WHEN NEW.position NOT BETWEEN 0 AND 19
        OR NEW.target_type NOT IN ('finding','evidence')
        OR (NEW.target_type = 'finding' AND (NEW.finding_id IS NULL
            OR NEW.target_id != NEW.finding_id OR NEW.evidence_id IS NOT NULL))
        OR (NEW.target_type = 'evidence' AND (NEW.evidence_id IS NULL
            OR NEW.target_id != CAST(NEW.evidence_id AS TEXT) OR NEW.finding_id IS NOT NULL))
        BEGIN SELECT RAISE(ABORT, 'invalid citation'); END
    """)


def downgrade() -> None:
    op.drop_column("report", "scope")
    for table in ("annotation_citation", "annotation", "analyst"):
        op.drop_table(table)
