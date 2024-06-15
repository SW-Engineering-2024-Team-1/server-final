"""add

Revision ID: 1c89efe1d288
Revises: 09d37b03f672
Create Date: 2024-06-04 22:32:15.874952

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "1c89efe1d288"
down_revision = "09d37b03f672"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("message", schema=None) as batch_op:
        batch_op.add_column(sa.Column("reply_to_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(None, "message", ["reply_to_id"], ["id"])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("message", schema=None) as batch_op:
        batch_op.drop_constraint(None, type_="foreignkey")
        batch_op.drop_column("reply_to_id")

    # ### end Alembic commands ###