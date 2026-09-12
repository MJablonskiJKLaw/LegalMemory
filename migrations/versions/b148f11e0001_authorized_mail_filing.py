"""Authenticated matter filing custody and immutable receipts.

Merge the existing schema heads without changing their behavior.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b148f11e0001"
down_revision = ("5b1f7c2e8a41", "9b1f4c7e6a02", "a71c4d9e2b60")
branch_labels = None
depends_on = None


def upgrade():
    payload = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table("mail_filings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("matter_id", sa.String(36), sa.ForeignKey("matters.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("actor_id", sa.String(512), nullable=False),
        sa.Column("replay_key", sa.String(100), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("manifest", payload, nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("sources.id")),
        sa.Column("receipt", payload),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("matter_id", "actor_id", "replay_key", name="uq_mail_filing_replay"))
    op.create_table("mail_filing_chunks",
        sa.Column("filing_id", sa.String(36), sa.ForeignKey("mail_filings.id"), primary_key=True),
        sa.Column("part", sa.Integer(), primary_key=True),
        sa.Column("offset", sa.BigInteger(), primary_key=True),
        sa.Column("data", sa.LargeBinary(), nullable=False))


def downgrade():
    op.drop_table("mail_filing_chunks")
    op.drop_table("mail_filings")
