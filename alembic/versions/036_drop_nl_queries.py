"""Wave 5 (W5-B follow-up): drop ``nl_queries``.

The natural-language query feature (``POST /ai/query``, the keyword
``NaturalLanguageQueryEngine`` and its Celery task) was graded FAKE in the
2026-10-08 audit and removed in wave 5. Nothing writes or reads the table
any more, and the AI dashboard no longer reports counters derived from it.

Idempotent like 027-035: the table is dropped only when it exists.
Downgrade recreates it in the shape the removed model declared (it was
created by ``init_db``'s ``create_all``; migration 002 declared an older,
narrower shape) so the pre-wave-5 code can run against it again.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "036"
down_revision: Union[str, None] = "035"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "nl_queries"


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table(TABLE):
        op.drop_table(TABLE)


def downgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table(TABLE):
        return
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("natural_language", sa.Text(), nullable=False),
        sa.Column("interpreted_intent", sa.String(100), nullable=False),
        sa.Column("generated_query", sa.Text(), nullable=False),
        sa.Column("query_parameters", sa.JSON(), nullable=False),
        sa.Column("results_summary", sa.Text(), nullable=True),
        sa.Column("result_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("execution_time_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("was_helpful", sa.Boolean(), nullable=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
