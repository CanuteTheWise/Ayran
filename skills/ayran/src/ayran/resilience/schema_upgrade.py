"""Open historical projection schemas v0001-v0005 and confirm forward migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ayran.graph.migrations import (
    MIGRATIONS,
    V2_SCHEMA_SQL,
    V3_SCHEMA_SQL,
    V4_SCHEMA_SQL,
    V5_SCHEMA_SQL,
)
from ayran.graph.projection import MIGRATION_VERSION, SCHEMA_SQL, Projection, _json

_VERSION_SQL = {
    1: SCHEMA_SQL,
    2: V2_SCHEMA_SQL,
    3: V3_SCHEMA_SQL,
    4: V4_SCHEMA_SQL,
    5: V5_SCHEMA_SQL,
}


def historical_versions() -> tuple[int, ...]:
    return tuple(item.version for item in MIGRATIONS)


def seed_projection(path: Path, version: int, stream: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SCHEMA_SQL)
        for step in range(2, version + 1):
            connection.executescript(_VERSION_SQL[step])
        connection.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('projection_schema_version', ?)",
            ("1.0.0",),
        )
        connection.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('migration_version', ?)",
            (str(version),),
        )
        connection.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('stream', ?)",
            (_json(stream),),
        )
        connection.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('cursor', '0')")
        connection.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('event_hash', '')")
        connection.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('commit_hash', '')")
        connection.commit()
    finally:
        connection.close()
    return path


def upgrade_and_verify(path: Path, stream: dict[str, Any]) -> dict[str, Any]:
    projection = Projection(path, stream)
    try:
        stored = dict(projection.connection.execute("SELECT key,value FROM meta").fetchall())
        version = int(stored.get("migration_version") or "0")
        return {
            "path": str(path),
            "migration_version": version,
            "expected": MIGRATION_VERSION,
            "ok": version == MIGRATION_VERSION,
        }
    finally:
        projection.close()
