"""Add capsule_id and original_filename column

Revision ID: e044c831c919
Revises: 9b9ed230d239
Create Date: 2025-07-04 21:54:48.362107
"""

from alembic import op
import sqlalchemy as sa
import uuid
from sqlalchemy.sql import table, column
from sqlalchemy import String, Integer

# Revision identifiers, used by Alembic.
revision = 'e044c831c919'
down_revision = '9b9ed230d239'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add both columns as nullable
    with op.batch_alter_table('time_capsules', schema=None) as batch_op:
        batch_op.add_column(sa.Column('capsule_id', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('original_filename', sa.String(length=255), nullable=True))

    # Step 2: Backfill capsule_id and original_filename
    conn = op.get_bind()
    results = conn.execute(sa.text("SELECT id FROM time_capsules WHERE capsule_id IS NULL")).fetchall()

    for row in results:
        cid = str(uuid.uuid4())[:8]
        conn.execute(
            sa.text("UPDATE time_capsules SET capsule_id = :cid, original_filename = 'unknown.txt' WHERE id = :id"),
            {"cid": cid, "id": row.id}
        )

    # Step 3: Make both columns NOT NULL
    with op.batch_alter_table('time_capsules', schema=None) as batch_op:
        batch_op.alter_column('capsule_id', existing_type=sa.String(length=20), nullable=False)
        batch_op.alter_column('original_filename', existing_type=sa.String(length=255), nullable=False)


def downgrade():
    with op.batch_alter_table('time_capsules', schema=None) as batch_op:
        batch_op.drop_column('original_filename')
        batch_op.drop_column('capsule_id')
