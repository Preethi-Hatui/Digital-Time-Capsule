"""Add capsule_id and action to OTPAttempt

Revision ID: 9752f282a605
Revises: 7ec955ebe6a3
Create Date: 2025-07-05 22:42:25.243370
"""

from alembic import op
import sqlalchemy as sa


# Revision identifiers, used by Alembic.
revision = '9752f282a605'
down_revision = '7ec955ebe6a3'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add new columns (action is temporarily nullable)
    with op.batch_alter_table('otp_attempts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('capsule_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('action', sa.String(length=50), nullable=True))  # Add nullable first
        batch_op.create_foreign_key(
            constraint_name='fk_otp_attempts_capsule_id',
            referent_table='time_capsules',
            local_cols=['capsule_id'],
            remote_cols=['id'],
            ondelete='CASCADE'
        )

    # Step 2: Fill default action as 'login' for existing records
    op.execute("UPDATE otp_attempts SET action = 'login' WHERE action IS NULL")

    # Step 3: Enforce NOT NULL constraint after population
    with op.batch_alter_table('otp_attempts', schema=None) as batch_op:
        batch_op.alter_column('action', existing_type=sa.String(length=50), nullable=False)


def downgrade():
    # Reverse the changes
    with op.batch_alter_table('otp_attempts', schema=None) as batch_op:
        batch_op.drop_constraint('fk_otp_attempts_capsule_id', type_='foreignkey')
        batch_op.drop_column('action')
        batch_op.drop_column('capsule_id')
