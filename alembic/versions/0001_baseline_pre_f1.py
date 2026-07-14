"""baseline — schema as it exists before F1 (created by Base.metadata.create_all)

Revision ID: 0001_baseline
Revises:
Create Date: 2026-07-14

This revision is deliberately EMPTY. It exists only to give Alembic a starting
point for a database whose schema predates Alembic entirely.

Context: this repo had alembic in requirements.txt but no alembic.ini, no env.py
and no versions/ — the dependency was unused. Schema is created by
Base.metadata.create_all() (app/database.py), which creates missing tables and
NEVER alters existing ones, so it cannot add a constraint to a live table.

Production is brought under Alembic control by STAMPING this revision, not by
running it:

    alembic stamp 0001_baseline    # records "baseline applied", changes nothing
    alembic upgrade head           # applies 0002_f1_chain_serialization

Do not put DDL here. A fresh database gets its tables from create_all() (which
already includes the F1 constraints, since they live on the model), and 0002 is
written to be idempotent so both paths converge on the same schema.
"""
from alembic import op  # noqa: F401
import sqlalchemy as sa  # noqa: F401

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
