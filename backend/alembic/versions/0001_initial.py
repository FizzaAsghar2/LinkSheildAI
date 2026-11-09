from alembic import op
import sqlalchemy as sa
revision="0001_initial"; down_revision=None; branch_labels=None; depends_on=None
def upgrade():
 op.create_table("scans",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("url",sa.String(2048),nullable=False),sa.Column("status",sa.String(20),nullable=False),sa.Column("risk_score",sa.Integer()),sa.Column("classification",sa.String(20)),sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.Column("scanned_at",sa.DateTime(timezone=True)),sa.Column("result",sa.JSON(),nullable=False))
 op.create_index("ix_scans_id","scans",["id"]); op.create_index("ix_scans_url","scans",["url"])
 for table,columns in [("scan_findings",[sa.Column("finding_key",sa.String(80)),sa.Column("severity",sa.String(20)),sa.Column("title",sa.String(300)),sa.Column("details",sa.JSON(),nullable=False)]),("scan_evidence",[sa.Column("detail",sa.Text(),nullable=False)]),("ai_explanations",[sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),sa.Column("explanation",sa.Text(),nullable=False),sa.Column("provider",sa.String(40),nullable=False)]),("scan_metadata",[sa.Column("key",sa.String(80),nullable=False),sa.Column("value",sa.JSON(),nullable=False)])]:
  op.create_table(table,sa.Column("id",sa.Integer(),primary_key=True),sa.Column("scan_id",sa.Integer(),sa.ForeignKey("scans.id",ondelete="CASCADE"),nullable=False),*columns)
  op.create_index(f"ix_{table}_scan_id",table,["scan_id"])
def downgrade():
 for table in ["scan_metadata","ai_explanations","scan_evidence","scan_findings"]: op.drop_index(f"ix_{table}_scan_id",table_name=table);op.drop_table(table)
 op.drop_index("ix_scans_url",table_name="scans");op.drop_index("ix_scans_id",table_name="scans");op.drop_table("scans")
