"""add incidents and incident_iocs tables

Revision ID: 18bb73d59aaf
Revises: f73b69ff6d66
Create Date: 2026-08-14 04:28:21.077383

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '18bb73d59aaf'
down_revision: Union[str, None] = 'f73b69ff6d66'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
