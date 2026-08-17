"""Immutable forward-only projection migration registry."""

from __future__ import annotations

from .v0001_initial import MIGRATION as V1
from .v0002_cognitive import MIGRATION as V2
from .v0002_cognitive import V2_SCHEMA_SQL
from .v0003_evidence import MIGRATION as V3
from .v0003_evidence import V3_SCHEMA_SQL
from .v0004_knowledge import MIGRATION as V4
from .v0004_knowledge import V4_SCHEMA_SQL
from .v0005_learning import MIGRATION as V5
from .v0005_learning import V5_SCHEMA_SQL

MIGRATIONS = (V1, V2, V3, V4, V5)

__all__ = [
    "MIGRATIONS",
    "V2_SCHEMA_SQL",
    "V3_SCHEMA_SQL",
    "V4_SCHEMA_SQL",
    "V5_SCHEMA_SQL",
]

