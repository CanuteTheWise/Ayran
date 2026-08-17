"""Load latest domain objects from the SQLite projection."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ayran.graph.recovery import GraphStore


def _latest(store: GraphStore, table: str, id_column: str, object_id: str) -> dict[str, Any] | None:
    sql = (
        f"SELECT object_json FROM {table} WHERE {id_column}=? "
        "ORDER BY revision DESC LIMIT 1"
    )
    with store.projection.snapshot() as connection:
        row = connection.execute(sql, (object_id,)).fetchone()
    if row is None:
        return None
    payload = json.loads(row["object_json"])
    return payload if isinstance(payload, dict) else None


def _all_latest(store: GraphStore, table: str, id_column: str) -> list[dict[str, Any]]:
    sql = (
        f"SELECT t.object_json FROM {table} t JOIN ("
        f"SELECT {id_column} AS id, MAX(revision) AS revision FROM {table} GROUP BY {id_column}"
        f") latest ON t.{id_column}=latest.id AND t.revision=latest.revision"
    )
    records: list[dict[str, Any]] = []
    with store.projection.snapshot() as connection:
        try:
            rows = connection.execute(sql).fetchall()
        except sqlite3.OperationalError:
            return []
        for row in rows:
            payload = json.loads(row["object_json"])
            if isinstance(payload, dict):
                records.append(payload)
    return records


def load_hypothesis(store: GraphStore, hypothesis_id: str) -> dict[str, Any] | None:
    return _latest(store, "hypotheses", "hypothesis_id", hypothesis_id)


def load_hypotheses(store: GraphStore) -> list[dict[str, Any]]:
    return _all_latest(store, "hypotheses", "hypothesis_id")


def load_verdict(store: GraphStore, verdict_id: str) -> dict[str, Any] | None:
    found = _latest(store, "gate_verdicts", "verdict_id", verdict_id)
    if found is not None:
        return found
    return _latest(store, "domain_objects", "object_id", verdict_id)


def load_finding(store: GraphStore, finding_id: str) -> dict[str, Any] | None:
    found = _latest(store, "findings", "finding_id", finding_id)
    if found is not None:
        return found
    return _latest(store, "domain_objects", "object_id", finding_id)


def load_evidence(store: GraphStore, evidence_id: str) -> dict[str, Any] | None:
    return _latest(store, "evidence", "evidence_id", evidence_id)


def load_tool_run(store: GraphStore, tool_run_id: str) -> dict[str, Any] | None:
    return _latest(store, "tool_runs", "tool_run_id", tool_run_id)


def load_poc(store: GraphStore, poc_id: str) -> dict[str, Any] | None:
    return _latest(store, "poc_runs", "poc_id", poc_id)


def load_verdicts_for(store: GraphStore, hypothesis_id: str) -> list[dict[str, Any]]:
    records = [
        item
        for item in _all_latest(store, "gate_verdicts", "verdict_id")
        if item.get("hypothesis_id") == hypothesis_id
    ]
    if records:
        return records
    return [
        item
        for item in _all_latest(store, "domain_objects", "object_id")
        if item.get("gate") in {"A", "B"} and item.get("hypothesis_id") == hypothesis_id
    ]


def load_nodes_by_type(store: GraphStore, node_type: str) -> list[dict[str, Any]]:
    sql = """
        SELECT r.object_json FROM nodes n
        JOIN node_revisions r ON r.node_id=n.node_id AND r.revision=n.current_revision
        WHERE n.node_type=? AND n.status != 'tombstoned'
        ORDER BY n.node_id
    """
    records: list[dict[str, Any]] = []
    with store.projection.snapshot() as connection:
        for row in connection.execute(sql, (node_type,)).fetchall():
            payload = json.loads(row["object_json"])
            if isinstance(payload, dict):
                records.append(payload)
    return records


def node_props(node: dict[str, Any]) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for item in node.get("properties") or []:
        if isinstance(item, dict) and "name" in item:
            mapped[str(item["name"])] = item.get("value")
    return mapped
