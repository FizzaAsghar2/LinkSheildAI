from alembic import op
import sqlalchemy as sa
revision="0001_initial"; down_revision=None; branch_labels=None; depends_on=None
def upgrade():
 op.create_table("scans",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("url",sa.String(2048),nullable=False),sa.Column("status",sa.String(20),nullable=False),sa.Column("risk_score",sa.Integer()),sa.Column("classification",sa.String(20)),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.Column("scanned_at",sa.DateTime(timezone=True)),sa.Column("result",sa.JSON(),nullable=False))
 op.create_index("ix_scans_id","scans",["id"]); op.create_index("ix_scans_url","scans",["url"])
def downgrade():
 op.drop_index("ix_scans_url",table_name="scans");op.drop_index("ix_scans_id",table_name="scans");op.drop_table("scans")
