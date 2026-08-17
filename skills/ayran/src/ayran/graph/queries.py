"""Bounded, typed, provenance-preserving M1 graph queries."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import deque
from typing import Any, cast

from ayran.api.validators import validate_contract

from .canonical import canonical_bytes, canonical_hash, utc_now
from .ids import new_id
from .projection import MIGRATION_VERSION, PROJECTION_SCHEMA_VERSION, Projection


class GraphQueries:
    def __init__(self, projection: Projection) -> None:
        self.projection = projection

    def _snapshot(self) -> dict[str, Any]:
        cursor, event_hash, _ = self.projection.cursor()
        return {
            "as_of_seq": cursor,
            "event_hash": event_hash,
            "projection_schema_version": PROJECTION_SCHEMA_VERSION,
            "migration_version": MIGRATION_VERSION,
        }

    def _result(
        self,
        name: str,
        params: dict[str, Any],
        records: list[dict[str, Any]],
        *,
        truncated: bool = False,
        index_degraded: bool = False,
    ) -> dict[str, Any]:
        ordered = sorted(records, key=canonical_bytes)
        snapshot = self._snapshot()
        digest = canonical_hash(
            {
                "domain": "ayran.graph.query.v1",
                "query_api_version": "1.0.0",
                "canonical_params": params,
                "snapshot": snapshot,
                "records": ordered,
                "truncated": truncated,
                "index_degraded": index_degraded,
            }
        )
        value = {
            "schema_version": "1.0.0",
            "query_api_version": "1.0.0",
            "query_id": new_id("qry"),
            "created_at": utc_now(),
            "stream": self.projection.stream,
            "query_name": name,
            "canonical_params": params,
            "snapshot": snapshot,
            "records": ordered,
            "truncated": truncated,
            "index_degraded": index_degraded,
            "query_digest": digest,
        }
        validate_contract("graph-query-result", value)
        return value

    def _enrich(
        self,
        connection: sqlite3.Connection,
        object_id: str,
        revision: int,
        row: sqlite3.Row,
        object_json_column: str = "object_json",
    ) -> dict[str, Any]:
        value = cast(dict[str, Any], json.loads(row[object_json_column]))
        provenance = [
            cast(dict[str, Any], json.loads(item[0]))
            for item in connection.execute(
                "SELECT provenance_json FROM provenance WHERE object_id=? AND revision=? ORDER BY provenance_id",
                (object_id, revision),
            ).fetchall()
        ]
        references = [
            {"reference": item[0], "kind": item[1]}
            for item in connection.execute(
                "SELECT artifact_ref,ref_kind FROM artifact_refs WHERE object_id=? AND revision=? ORDER BY ref_kind,artifact_ref",
                (object_id, revision),
            ).fetchall()
        ]
        derived = {
            key: row[key]
            for key in row
            if key
            in {
                "valid_from_seq",
                "valid_to_seq",
                "origin_event_id",
                "origin_event_hash",
                "source_version",
                "content_hash",
            }
        }
        return {
            "object_id": object_id,
            "revision": revision,
            "namespace": self.projection.stream["namespace"],
            "run_or_corpus_identity": self.projection.stream,
            "value": value,
            "provenance": provenance,
            "evidence_and_artifact_refs": references,
            "derived_validity": derived,
        }

    def get_entity(self, object_id: str, revision: int | None = None) -> dict[str, Any]:
        with self.projection.snapshot() as connection:
            for table, id_column in (
                ("node_revisions", "node_id"),
                ("edge_revisions", "edge_id"),
                ("assertion_revisions", "assertion_id"),
            ):
                sql = f"SELECT * FROM {table} WHERE {id_column}=?"
                params: list[Any] = [object_id]
                if revision is not None:
                    sql += " AND revision=?"
                    params.append(revision)
                else:
                    sql += " ORDER BY revision DESC LIMIT 1"
                row = connection.execute(sql, params).fetchone()
                if row is not None:
                    record = self._enrich(connection, object_id, int(row["revision"]), row)
                    record["kind"] = table.removesuffix("_revisions")
                    return self._result(
                        "entity.get", {"object_id": object_id, "revision": revision}, [record]
                    )
            sql = "SELECT * FROM domain_objects WHERE object_id=?"
            params = [object_id]
            if revision is not None:
                sql += " AND revision=?"
                params.append(revision)
            else:
                sql += " ORDER BY revision DESC LIMIT 1"
            row = connection.execute(sql, params).fetchone()
            records = []
            if row is not None:
                record = self._enrich(connection, object_id, int(row["revision"]), row)
                record["kind"] = row["contract_id"]
                records.append(record)
        return self._result("entity.get", {"object_id": object_id, "revision": revision}, records)

    def resolve_node(self, node_type: str, canonical_key: str) -> dict[str, Any]:
        with self.projection.snapshot() as connection:
            row = connection.execute(
                """SELECT r.* FROM nodes n JOIN node_revisions r
                   ON r.node_id=n.node_id AND r.revision=n.current_revision
                   WHERE n.namespace=? AND n.node_type=? AND n.canonical_key=?""",
                (self.projection.stream["namespace"], node_type, canonical_key),
            ).fetchone()
            records = (
                [self._enrich(connection, row["node_id"], int(row["revision"]), row)]
                if row
                else []
            )
        return self._result(
            "node.resolve", {"node_type": node_type, "canonical_key": canonical_key}, records
        )

    def revisions(self, object_id: str, *, active_only: bool = False) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        with self.projection.snapshot() as connection:
            for table, id_column in (
                ("node_revisions", "node_id"),
                ("edge_revisions", "edge_id"),
                ("assertion_revisions", "assertion_id"),
            ):
                sql = f"SELECT * FROM {table} WHERE {id_column}=?"
                if active_only:
                    sql += " AND valid_to_seq IS NULL"
                for row in connection.execute(sql, (object_id,)).fetchall():
                    record = self._enrich(connection, object_id, int(row["revision"]), row)
                    record["kind"] = table.removesuffix("_revisions")
                    records.append(record)
        return self._result(
            "entity.revisions", {"object_id": object_id, "active_only": active_only}, records
        )

    def traverse(
        self,
        node_id: str,
        *,
        direction: str = "outgoing",
        edge_types: tuple[str, ...] = (),
        limit: int = 2000,
    ) -> dict[str, Any]:
        if direction not in {"outgoing", "incoming"}:
            raise ValueError("direction must be outgoing or incoming")
        field = "source_id" if direction == "outgoing" else "target_id"
        records: list[dict[str, Any]] = []
        params: list[Any] = [node_id]
        clause = ""
        if edge_types:
            clause = " AND e.edge_type IN (" + ",".join("?" for _ in edge_types) + ")"
            params.extend(edge_types)
        params.append(limit + 1)
        with self.projection.snapshot() as connection:
            rows = connection.execute(
                f"""SELECT r.* FROM edges e JOIN edge_revisions r
                    ON r.edge_id=e.edge_id AND r.revision=e.current_revision
                    WHERE e.{field}=? {clause} ORDER BY e.edge_id LIMIT ?""",
                params,
            ).fetchall()
            truncated = len(rows) > limit
            for row in rows[:limit]:
                records.append(self._enrich(connection, row["edge_id"], int(row["revision"]), row))
        return self._result(
            "edge.traverse",
            {"node_id": node_id, "direction": direction, "edge_types": list(edge_types), "limit": limit},
            records,
            truncated=truncated,
        )

    def neighborhood(
        self,
        node_id: str,
        *,
        hops: int = 2,
        edge_types: tuple[str, ...] = (),
        limit: int = 2000,
    ) -> dict[str, Any]:
        if not 1 <= hops <= 2:
            raise ValueError("M1 neighborhoods are bounded to one or two hops")
        records: list[dict[str, Any]] = []
        visited = {node_id}
        frontier = deque([(node_id, 0)])
        truncated = False
        with self.projection.snapshot() as connection:
            while frontier and len(records) < limit:
                current, depth = frontier.popleft()
                if depth >= hops:
                    continue
                params: list[Any] = [current, current]
                clause = ""
                if edge_types:
                    clause = " AND e.edge_type IN (" + ",".join("?" for _ in edge_types) + ")"
                    params.extend(edge_types)
                rows = connection.execute(
                    f"""SELECT r.* FROM edges e JOIN edge_revisions r
                        ON r.edge_id=e.edge_id AND r.revision=e.current_revision
                        WHERE (e.source_id=? OR e.target_id=?) {clause} ORDER BY e.edge_id""",
                    params,
                ).fetchall()
                for row in rows:
                    if len(records) >= limit:
                        truncated = True
                        break
                    records.append(
                        self._enrich(connection, row["edge_id"], int(row["revision"]), row)
                    )
                    other = row["target_id"] if row["source_id"] == current else row["source_id"]
                    if other not in visited:
                        visited.add(other)
                        frontier.append((other, depth + 1))
        return self._result(
            "graph.neighborhood",
            {"node_id": node_id, "hops": hops, "edge_types": list(edge_types), "limit": limit},
            records,
            truncated=truncated,
        )

    def assertions(
        self,
        *,
        subject_id: str | None = None,
        predicate: str | None = None,
        historical: bool = False,
        limit: int = 2000,
    ) -> dict[str, Any]:
        clauses = ["1=1"]
        params: list[Any] = []
        if subject_id:
            clauses.append("subject_id=?")
            params.append(subject_id)
        if predicate:
            clauses.append("predicate=?")
            params.append(predicate)
        if not historical:
            clauses.append("valid_to_seq IS NULL")
        params.append(limit + 1)
        with self.projection.snapshot() as connection:
            rows = connection.execute(
                "SELECT * FROM assertion_revisions WHERE "
                + " AND ".join(clauses)
                + " ORDER BY assertion_id,revision LIMIT ?",
                params,
            ).fetchall()
            records = [
                self._enrich(connection, row["assertion_id"], int(row["revision"]), row)
                for row in rows[:limit]
            ]
        return self._result(
            "assertion.query",
            {
                "subject_id": subject_id,
                "predicate": predicate,
                "historical": historical,
                "limit": limit,
            },
            records,
            truncated=len(rows) > limit,
        )

    def provenance(self, object_id: str, revision: int | None = None) -> dict[str, Any]:
        clauses = ["object_id=?"]
        params: list[Any] = [object_id]
        if revision is not None:
            clauses.append("revision=?")
            params.append(revision)
        with self.projection.snapshot() as connection:
            records = [
                {
                    "object_id": object_id,
                    "revision": row["revision"],
                    "provenance": json.loads(row["provenance_json"]),
                }
                for row in connection.execute(
                    "SELECT * FROM provenance WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY revision,provenance_id",
                    params,
                ).fetchall()
            ]
        return self._result(
            "provenance.get", {"object_id": object_id, "revision": revision}, records
        )

    def tombstones(self, object_id: str | None = None) -> dict[str, Any]:
        with self.projection.snapshot() as connection:
            if object_id:
                rows = connection.execute(
                    "SELECT * FROM tombstones WHERE object_id=? ORDER BY seq", (object_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM tombstones ORDER BY seq").fetchall()
            records = [dict(row) | {"value": json.loads(row["object_json"])} for row in rows]
            for record in records:
                record.pop("object_json", None)
        return self._result("tombstone.query", {"object_id": object_id}, records)

    def fts(self, text: str, *, limit: int = 100) -> dict[str, Any]:
        tokens = re.findall(r"[\w-]+", text, flags=re.UNICODE)[:32]
        query = " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens)
        with self.projection.snapshot() as connection:
            rows = (
                connection.execute(
                    "SELECT object_id,revision,title,summary,tags FROM fts_documents WHERE fts_documents MATCH ? ORDER BY object_id LIMIT ?",
                    (query, limit),
                ).fetchall()
                if query
                else []
            )
            records = [dict(row) for row in rows]
        return self._result("fts.lookup", {"text": text, "limit": limit}, records)

    def status(self) -> dict[str, Any]:
        cursor, event_hash, commit_hash = self.projection.cursor()
        ok, issues = self.projection.integrity_check()
        return self._result(
            "graph.status",
            {},
            [
                {
                    "journal_projection_cursor": cursor,
                    "event_hash": event_hash,
                    "commit_hash": commit_hash,
                    "projection_integrity": "ok" if ok else "corrupt",
                    "issues": issues,
                    "pragmas": self.projection.pragmas(),
                }
            ],
        )
