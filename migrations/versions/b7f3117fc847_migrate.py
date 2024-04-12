"""migrate

Revision ID: b7f3117fc847
Revises: ff0ced4a7a43
Create Date: 2023-11-25 20:45:05.009239

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b7f3117fc847'
down_revision = 'ff0ced4a7a43'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.create_unique_constraint(None, ['Id'])

    with op.batch_alter_table('page', schema=None) as batch_op:
        batch_op.create_unique_constraint(None, ['Id'])

    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.create_unique_constraint(None, ['Id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')

    with op.batch_alter_table('page', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')

    with op.batch_alter_table('comment', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')

    # ### end Alembic commands ###
