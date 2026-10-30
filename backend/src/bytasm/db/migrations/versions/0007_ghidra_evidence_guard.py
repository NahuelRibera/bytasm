"""Mark Ghidra-aware storage; reject downgrades that hide retained evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing invocation output and profile JSON columns preserve the strict
    # versioned document without rewriting historical rows or report bytes.
    pass


def downgrade() -> None:
    bind = op.get_bind()
    if (
        bind.execute(
            sa.text("SELECT count(*) FROM tool_invocation WHERE tool_name = 'ghidra'")
        ).scalar()
        or bind.execute(
            sa.text(
                "SELECT count(*) FROM analysis_run "
                "WHERE json_extract(profile_snapshot, '$.id') = 'ghidra-static'"
            )
        ).scalar()
    ):
        raise RuntimeError(
            "Cannot downgrade while Ghidra runs exist; use a separate data directory"
        )
