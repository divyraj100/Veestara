"""kdwd

Revision ID: ff0ced4a7a43
Revises: 2df8bc45681e
Create Date: 2023-11-24 01:31:42.725323

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'ff0ced4a7a43'
down_revision = '2df8bc45681e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    # op.drop_table('article')
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.alter_column('ImageData',
               existing_type=mysql.LONGBLOB(),
               type_=sa.LargeBinary(),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.alter_column('ImageData',
               existing_type=sa.LargeBinary(),
               type_=mysql.LONGBLOB(),
               existing_nullable=True)

    op.create_table('article',
    sa.Column('id', mysql.INTEGER(display_width=3), autoincrement=False, nullable=False),
    sa.Column('post', mysql.VARCHAR(length=50), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_general_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    # ### end Alembic commands ###
