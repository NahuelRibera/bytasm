"""Preserve v0.3 evidence and add truthful capa virtual addresses."""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("evidence") as batch:
        batch.alter_column("file_offset", existing_type=sa.Integer(), nullable=True)
        batch.alter_column("length", existing_type=sa.Integer(), nullable=True)
        batch.add_column(sa.Column("virtual_address", sa.Integer(), nullable=True))


def downgrade() -> None:
    # A lossy downgrade would break immutable annotation/citation provenance.
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT count(*) FROM evidence WHERE kind != 'byte_range'")).scalar():
        raise RuntimeError(
            "Cannot downgrade while capa evidence exists; use a separate data directory"
        )
    with op.batch_alter_table("evidence") as batch:
        batch.drop_column("virtual_address")
        batch.alter_column("length", existing_type=sa.Integer(), nullable=False)
        batch.alter_column("file_offset", existing_type=sa.Integer(), nullable=False)
