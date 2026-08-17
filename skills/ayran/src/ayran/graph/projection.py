"""Versioned, disposable SQLite projection for committed journal-v1 batches."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from .canonical import canonical_hash, canonical_line
from .errors import PROJECTION_CORRUPT, STORE_BUSY, GraphError
from .migrations.v0002_cognitive import V2_SCHEMA_SQL
from .migrations.v0003_evidence import V3_SCHEMA_SQL
from .migrations.v0004_knowledge import V4_SCHEMA_SQL
from .migrations.v0005_learning import V5_SCHEMA_SQL

PROJECTION_SCHEMA_VERSION = "1.0.0"
MIGRATION_VERSION = 5

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS migration_history (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS command_batches (
  batch_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  request_hash TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL,
  commit_hash TEXT NOT NULL UNIQUE,
  acknowledgement_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS applied_events (
  seq INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  event_hash TEXT NOT NULL UNIQUE,
  batch_id TEXT NOT NULL REFERENCES command_batches(batch_id),
  aggregate_id TEXT NOT NULL,
  aggregate_version INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  event_json TEXT NOT NULL,
  UNIQUE(aggregate_id, aggregate_version)
);
CREATE TABLE IF NOT EXISTS aggregate_heads (
  aggregate_id TEXT PRIMARY KEY,
  current_revision INTEGER NOT NULL,
  last_event_id TEXT NOT NULL,
  last_event_hash TEXT NOT NULL,
  last_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  node_type TEXT NOT NULL,
  canonical_key TEXT NOT NULL,
  current_revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS node_revisions (
  node_id TEXT NOT NULL REFERENCES nodes(node_id),
  revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  trust_class TEXT NOT NULL,
  confidence REAL NOT NULL,
  evidence_grade TEXT NOT NULL,
  source_locator TEXT NOT NULL,
  source_version TEXT NOT NULL,
  valid_from_seq INTEGER NOT NULL,
  valid_to_seq INTEGER,
  origin_event_id TEXT NOT NULL,
  origin_event_hash TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(node_id, revision)
);
CREATE TABLE IF NOT EXISTS edges (
  edge_id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  edge_type TEXT NOT NULL,
  source_id TEXT NOT NULL REFERENCES nodes(node_id),
  target_id TEXT NOT NULL REFERENCES nodes(node_id),
  current_revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS edge_revisions (
  edge_id TEXT NOT NULL REFERENCES edges(edge_id),
  revision INTEGER NOT NULL,
  source_id TEXT NOT NULL REFERENCES nodes(node_id),
  target_id TEXT NOT NULL REFERENCES nodes(node_id),
  status TEXT NOT NULL,
  trust_class TEXT NOT NULL,
  confidence REAL NOT NULL,
  evidence_grade TEXT NOT NULL,
  source_locator TEXT NOT NULL,
  source_version TEXT NOT NULL,
  valid_from_seq INTEGER NOT NULL,
  valid_to_seq INTEGER,
  origin_event_id TEXT NOT NULL,
  origin_event_hash TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(edge_id, revision)
);
CREATE TABLE IF NOT EXISTS assertions (
  assertion_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES nodes(node_id),
  predicate TEXT NOT NULL,
  current_revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS assertion_revisions (
  assertion_id TEXT NOT NULL REFERENCES assertions(assertion_id),
  revision INTEGER NOT NULL,
  subject_id TEXT NOT NULL REFERENCES nodes(node_id),
  predicate TEXT NOT NULL,
  object_kind TEXT NOT NULL,
  object_value_json TEXT NOT NULL,
  status TEXT NOT NULL,
  trust_class TEXT NOT NULL,
  confidence REAL NOT NULL,
  source_version TEXT NOT NULL,
  valid_from_seq INTEGER NOT NULL,
  valid_to_seq INTEGER,
  origin_event_id TEXT NOT NULL,
  origin_event_hash TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(assertion_id, revision)
);
CREATE TABLE IF NOT EXISTS provenance (
  object_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  provenance_id TEXT NOT NULL,
  source_uri TEXT NOT NULL,
  source_version TEXT NOT NULL,
  raw_hash TEXT NOT NULL,
  extraction_locator TEXT,
  parser_version TEXT,
  retrieved_at TEXT NOT NULL,
  license_or_terms TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  PRIMARY KEY(object_id, revision, provenance_id)
);
CREATE TABLE IF NOT EXISTS artifact_refs (
  object_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  artifact_ref TEXT NOT NULL,
  ref_kind TEXT NOT NULL,
  PRIMARY KEY(object_id, revision, artifact_ref, ref_kind)
);
CREATE TABLE IF NOT EXISTS hypotheses (
  hypothesis_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status TEXT,
  origin TEXT,
  object_json TEXT NOT NULL,
  PRIMARY KEY(hypothesis_id, revision)
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  artifact_hash TEXT,
  evidence_grade TEXT,
  object_json TEXT NOT NULL,
  PRIMARY KEY(evidence_id, revision)
);
CREATE TABLE IF NOT EXISTS coverage_cells (
  coverage_cell_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  coverage_dimension TEXT,
  status TEXT,
  risk_weight REAL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(coverage_cell_id, revision)
);
CREATE TABLE IF NOT EXISTS tool_runs (
  tool_run_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  tool_name TEXT,
  parse_status TEXT,
  object_json TEXT NOT NULL,
  PRIMARY KEY(tool_run_id, revision)
);
CREATE TABLE IF NOT EXISTS router_actions (
  router_action_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status TEXT,
  priority INTEGER,
  object_json TEXT NOT NULL,
  PRIMARY KEY(router_action_id, revision)
);
CREATE TABLE IF NOT EXISTS domain_objects (
  object_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  contract_id TEXT NOT NULL,
  status TEXT,
  object_json TEXT NOT NULL,
  PRIMARY KEY(object_id, revision)
);
CREATE TABLE IF NOT EXISTS outbox (
  event_id TEXT PRIMARY KEY REFERENCES applied_events(event_id),
  seq INTEGER NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  event_hash TEXT,
  checkpoint_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tombstones (
  object_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  event_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  reason TEXT NOT NULL,
  object_json TEXT NOT NULL,
  PRIMARY KEY(object_id, revision)
);
CREATE VIRTUAL TABLE IF NOT EXISTS fts_documents USING fts5(
  object_id UNINDEXED,
  revision UNINDEXED,
  title,
  summary,
  tags,
  tokenize='unicode61 remove_diacritics 2'
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_nodes_identity
  ON nodes(namespace, node_type, canonical_key);
CREATE INDEX IF NOT EXISTS ix_nodes_type_key
  ON nodes(namespace, node_type, canonical_key);
CREATE INDEX IF NOT EXISTS ix_edges_forward
  ON edges(source_id, edge_type, target_id);
CREATE INDEX IF NOT EXISTS ix_edges_reverse
  ON edges(target_id, edge_type, source_id);
CREATE INDEX IF NOT EXISTS ix_edge_revisions_validity
  ON edge_revisions(source_id, target_id, valid_from_seq, valid_to_seq);
CREATE INDEX IF NOT EXISTS ix_assertions_active
  ON assertion_revisions(subject_id, predicate, valid_to_seq, valid_from_seq);
CREATE INDEX IF NOT EXISTS ix_hypothesis_status
  ON hypotheses(hypothesis_id, status);
CREATE INDEX IF NOT EXISTS ix_artifact_hash
  ON artifact_refs(artifact_ref);
CREATE INDEX IF NOT EXISTS ix_coverage_status
  ON coverage_cells(coverage_dimension, status, risk_weight);
CREATE INDEX IF NOT EXISTS ix_event_sequence
  ON applied_events(seq);
CREATE INDEX IF NOT EXISTS ix_provenance_source_version
  ON provenance(source_version);
CREATE INDEX IF NOT EXISTS ix_router_status_priority
  ON router_actions(status, priority);
"""

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def _json(value: Any) -> str:
    # Projection bytes are disposable and logical digests parse these values;
    # RFC 8785 is mandatory for journal hashes, not for SQLite TEXT encoding.
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _properties(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in value.get("properties", []):
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            result[item["name"]] = item.get("value")
    return result


def _sanitize(value: object) -> str:
    if isinstance(value, list):
        value = " ".join(str(item) for item in value)
    if not isinstance(value, str):
        return ""
    return CONTROL_CHARS.sub(" ", value)[:8192]


class Projection:
    def __init__(
        self,
        path: Path,
        stream: dict[str, Any],
        *,
        synchronous: str = "FULL",
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if synchronous not in {"FULL", "NORMAL"}:
            raise ValueError("SQLite synchronous must be FULL or NORMAL")
        self.path = path
        self.stream = stream
        self.synchronous = synchronous
        self.fault_hook = fault_hook
        self._logical_digest_cache: str | None = None
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.connection = sqlite3.connect(
                path, timeout=5.0, isolation_level=None, check_same_thread=False
            )
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA busy_timeout=5000")
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute(f"PRAGMA synchronous={synchronous}")
            self.connection.executescript(SCHEMA_SQL)
            self.connection.executescript(V2_SCHEMA_SQL)
            self.connection.executescript(V3_SCHEMA_SQL)
            self.connection.executescript(V4_SCHEMA_SQL)
            self.connection.executescript(V5_SCHEMA_SQL)
            self._initialize_meta()
        except sqlite3.DatabaseError as error:
            raise GraphError(PROJECTION_CORRUPT, "SQLite projection cannot be opened.") from error

    def _initialize_meta(self) -> None:
        values = {
            "projection_schema_version": PROJECTION_SCHEMA_VERSION,
            "migration_version": str(MIGRATION_VERSION),
            "stream": _json(self.stream),
            "cursor": "0",
            "event_hash": "",
            "commit_hash": "",
        }
        for key, value in values.items():
            self.connection.execute("INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)", (key, value))
        stored = dict(self.connection.execute("SELECT key,value FROM meta").fetchall())
        if stored.get("projection_schema_version") != PROJECTION_SCHEMA_VERSION:
            raise GraphError(PROJECTION_CORRUPT, "Projection schema version is incompatible.")
        if stored.get("stream") != _json(self.stream):
            raise GraphError(PROJECTION_CORRUPT, "Projection stream identity does not match.")
        self.connection.execute(
            "INSERT OR IGNORE INTO migration_history(version,name,applied_at) VALUES(1,'initial_projection_v1','2026-08-12T00:00:00Z')"
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO migration_history(version,name,applied_at) VALUES(2,'cognitive_projection_v2','2026-08-13T00:00:00Z')"
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO migration_history(version,name,applied_at) VALUES(3,'evidence_projection_v3','2026-08-14T00:00:00Z')"
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO migration_history(version,name,applied_at) VALUES(4,'knowledge_projection_v4','2026-08-14T00:00:00Z')"
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO migration_history(version,name,applied_at) VALUES(5,'learning_projection_v5','2026-08-15T00:00:00Z')"
        )
        stored_version = int(stored.get("migration_version") or "1")
        if stored_version < 2:
            self.connection.executescript(V2_SCHEMA_SQL)
        if stored_version < 3:
            self.connection.executescript(V3_SCHEMA_SQL)
        if stored_version < 4:
            self.connection.executescript(V4_SCHEMA_SQL)
        if stored_version < 5:
            self.connection.executescript(V5_SCHEMA_SQL)
        if stored_version < MIGRATION_VERSION:
            self.connection.execute(
                "UPDATE meta SET value=? WHERE key='migration_version'", (str(MIGRATION_VERSION),)
            )

    def _fault(self, name: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(name)

    def cursor(self) -> tuple[int, str | None, str | None]:
        values = dict(
            self.connection.execute(
                "SELECT key,value FROM meta WHERE key IN ('cursor','event_hash','commit_hash')"
            ).fetchall()
        )
        return int(values["cursor"]), values["event_hash"] or None, values["commit_hash"] or None

    def aggregate_revision(self, aggregate_id: str) -> int:
        row = self.connection.execute(
            "SELECT current_revision FROM aggregate_heads WHERE aggregate_id=?", (aggregate_id,)
        ).fetchone()
        return int(row[0]) if row else 0

    def entity_exists(self, object_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM aggregate_heads WHERE aggregate_id=?", (object_id,)
        ).fetchone()
        return row is not None

    def receipt(self, idempotency_key: str) -> tuple[str, dict[str, Any]] | None:
        row = self.connection.execute(
            "SELECT request_hash,acknowledgement_json FROM command_batches WHERE idempotency_key=?",
            (idempotency_key,),
        ).fetchone()
        if row is None:
            return None
        return str(row[0]), cast(dict[str, Any], json.loads(row[1]))

    def apply_batch(
        self,
        begin: dict[str, Any],
        events: list[dict[str, Any]],
        commit: dict[str, Any],
        acknowledgement: dict[str, Any],
    ) -> dict[str, Any]:
        existing = self.connection.execute(
            "SELECT acknowledgement_json FROM command_batches WHERE batch_id=?", (begin["batch_id"],)
        ).fetchone()
        if existing is not None:
            return cast(dict[str, Any], json.loads(existing[0]))
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self._fault("after_sqlite_begin")
            cursor, _, _ = self.cursor()
            if begin["first_seq"] != cursor + 1:
                raise GraphError(PROJECTION_CORRUPT, "Projection batch sequence is not contiguous.")
            self.connection.execute(
                """INSERT INTO command_batches(
                     batch_id,idempotency_key,request_hash,operation_id,first_seq,last_seq,
                     commit_hash,acknowledgement_json) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    begin["batch_id"],
                    begin["idempotency_key"],
                    begin["request_hash"],
                    begin["operation_id"],
                    events[0]["seq"],
                    events[-1]["seq"],
                    commit["commit_hash"],
                    _json(acknowledgement),
                ),
            )
            for event in events:
                self._apply_event(event)
                self._fault("after_applied_event")
            self.connection.execute("UPDATE meta SET value=? WHERE key='cursor'", (str(events[-1]["seq"]),))
            self.connection.execute(
                "UPDATE meta SET value=? WHERE key='event_hash'", (events[-1]["event_hash"],)
            )
            self.connection.execute(
                "UPDATE meta SET value=? WHERE key='commit_hash'", (commit["commit_hash"],)
            )
            self.connection.commit()
            self._logical_digest_cache = None
            self._fault("after_sqlite_commit")
            return acknowledgement
        except GraphError:
            self.connection.rollback()
            raise
        except sqlite3.IntegrityError as error:
            self.connection.rollback()
            raise GraphError(PROJECTION_CORRUPT, "Projection invariant rejected a journal batch.") from error
        except sqlite3.OperationalError as error:
            self.connection.rollback()
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                raise GraphError(STORE_BUSY, "SQLite projection remained busy for five seconds.", True) from error
            raise GraphError(PROJECTION_CORRUPT, "SQLite projection update failed.") from error

    def _apply_event(self, event: dict[str, Any]) -> None:
        body = event["body"]
        value = cast(dict[str, Any], body["value"])
        contract_id = str(body["contract_id"])
        contract = contract_id.rsplit("@", 1)[0]
        object_id = str(body["object_id"])
        revision = int(event["aggregate_version"])
        seq = int(event["seq"])
        transition = body["transition"]
        self.connection.execute(
            """INSERT INTO applied_events(
                 seq,event_id,event_hash,batch_id,aggregate_id,aggregate_version,event_type,
                 contract_id,content_hash,event_json) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                seq,
                event["event_id"],
                event["event_hash"],
                event["batch_id"],
                event["aggregate_id"],
                revision,
                event["event_type"],
                contract_id,
                body["content_hash"],
                _json(event),
            ),
        )
        self.connection.execute(
            """INSERT INTO aggregate_heads(
                 aggregate_id,current_revision,last_event_id,last_event_hash,last_seq)
                 VALUES(?,?,?,?,?)
                 ON CONFLICT(aggregate_id) DO UPDATE SET
                   current_revision=excluded.current_revision,
                   last_event_id=excluded.last_event_id,
                   last_event_hash=excluded.last_event_hash,
                   last_seq=excluded.last_seq""",
            (object_id, revision, event["event_id"], event["event_hash"], seq),
        )
        if contract == "graph-node":
            self._project_node(event, value)
        elif contract == "graph-edge":
            self._project_edge(event, value)
        elif contract == "graph-assertion":
            self._project_assertion(event, value)
        else:
            self._project_domain(event, contract, value)
        self._project_provenance(object_id, revision, value)
        self._project_references(object_id, revision, value)
        if transition["kind"] == "tombstone":
            self.connection.execute(
                "INSERT INTO tombstones VALUES(?,?,?,?,?,?)",
                (object_id, revision, event["event_id"], seq, transition["reason"], _json(value)),
            )
        self.connection.execute(
            "INSERT INTO outbox(event_id,seq,event_type,created_at) VALUES(?,?,?,?)",
            (event["event_id"], seq, event["event_type"], event["created_at"]),
        )
        self._fault("after_outbox")

    def _project_node(self, event: dict[str, Any], value: dict[str, Any]) -> None:
        revision = int(event["aggregate_version"])
        seq = int(event["seq"])
        node_id = str(value["node_id"])
        props = _properties(value)
        canonical_key = str(props.get("canonical_key") or node_id)
        if revision == 1:
            self.connection.execute(
                "INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?)",
                (
                    node_id,
                    value["namespace"],
                    value["node_type"],
                    canonical_key,
                    revision,
                    value["status"],
                    seq,
                    seq,
                ),
            )
        else:
            self.connection.execute(
                "UPDATE node_revisions SET valid_to_seq=? WHERE node_id=? AND valid_to_seq IS NULL",
                (seq, node_id),
            )
            self.connection.execute(
                "UPDATE nodes SET current_revision=?,status=?,last_seq=? WHERE node_id=?",
                (revision, value["status"], seq, node_id),
            )
        self.connection.execute(
            """INSERT INTO node_revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                node_id,
                revision,
                value["status"],
                value["trust_class"],
                value["confidence"],
                value["evidence_grade"],
                value["source_locator"],
                event["source_version"],
                seq,
                None,
                event["event_id"],
                event["event_hash"],
                event["body"]["content_hash"],
                _json(value),
            ),
        )
        self.connection.execute("DELETE FROM fts_documents WHERE object_id=?", (node_id,))
        self.connection.execute(
            "INSERT INTO fts_documents(object_id,revision,title,summary,tags) VALUES(?,?,?,?,?)",
            (
                node_id,
                revision,
                _sanitize(props.get("title")),
                _sanitize(props.get("summary")),
                _sanitize(props.get("tags")),
            ),
        )
        self._project_cognitive_node(value, revision)

    def _project_cognitive_node(self, value: dict[str, Any], revision: int) -> None:
        node_type = str(value.get("node_type") or "")
        props = _properties(value)
        node_id = str(value["node_id"])
        if node_type.endswith("Map"):
            self.connection.execute(
                "INSERT OR REPLACE INTO cognitive_maps VALUES(?,?,?,?,?)",
                (
                    node_id,
                    revision,
                    node_type,
                    str(props.get("cluster_id") or ""),
                    _json(value),
                ),
            )
        if node_type in {"DriverState", "RouterBudget", "RouterControl", "PayloadStrike", "Quarantine", "TargetFirstSnapshot"}:
            self.connection.execute(
                "INSERT OR REPLACE INTO router_runtime VALUES(?,?,?,?)",
                (node_id, revision, node_type, _json(value)),
            )
        if node_type == "PocRun":
            self.connection.execute(
                "INSERT OR REPLACE INTO poc_runs VALUES(?,?,?,?,?)",
                (
                    node_id,
                    revision,
                    str(props.get("hypothesis_id") or ""),
                    str(props.get("status") or "pending"),
                    _json(value),
                ),
            )
        if node_type == "DedupCluster":
            self.connection.execute(
                "INSERT OR REPLACE INTO dedup_clusters VALUES(?,?,?,?)",
                (
                    node_id,
                    revision,
                    str(props.get("status") or "unique"),
                    _json(value),
                ),
            )
        knowledge_types = {
            "MechanismCard",
            "IncidentCard",
            "ToolCard",
            "MethodCard",
            "FalsePositiveTrap",
            "FixCard",
            "EvaluationResult",
            "VulnerabilityPattern",
            "SpecialistSkill",
            "ReasoningLens",
            "GlobalRecord",
        }
        if node_type in knowledge_types:
            record_id = str(props.get("record_id") or node_id)
            self.connection.execute(
                "INSERT OR REPLACE INTO knowledge_records VALUES(?,?,?,?,?,?,?)",
                (
                    record_id,
                    revision,
                    str(props.get("record_type") or node_type),
                    str(props.get("source_id") or ""),
                    node_id,
                    1 if str(props.get("safe_for_retrieval") or "true").lower() not in {"false", "0"} else 0,
                    _json(value),
                ),
            )
        if node_type == "Contradiction":
            group_id = str(props.get("canonical_key") or node_id)
            self.connection.execute(
                "INSERT OR REPLACE INTO conflict_groups VALUES(?,?,?,?)",
                (
                    group_id,
                    revision,
                    str(props.get("kind") or "other"),
                    _json(value),
                ),
            )
        if node_type == "CorpusRelease":
            release_id = str(props.get("release_id") or node_id)
            self.connection.execute(
                "INSERT OR REPLACE INTO corpus_releases VALUES(?,?,?,?)",
                (
                    release_id,
                    revision,
                    str(props.get("content_hash") or ""),
                    _json(value),
                ),
            )
        self._project_learning_node(node_id, node_type, revision, props, value)

    def _project_learning_node(
        self,
        node_id: str,
        node_type: str,
        revision: int,
        props: Mapping[str, Any],
        value: dict[str, Any],
    ) -> None:
        payload = _json(value)
        raw_record = props.get("record_json")
        if isinstance(raw_record, str) and raw_record.startswith("{"):
            payload = raw_record
        if node_type == "LearningOutcome":
            self.connection.execute(
                "INSERT OR REPLACE INTO learning_outcomes VALUES(?,?,?,?,?,?)",
                (
                    str(props.get("outcome_id") or node_id),
                    revision,
                    str(props.get("run_id") or ""),
                    str(props.get("outcome_type") or ""),
                    str(props.get("hypothesis_id") or ""),
                    payload,
                ),
            )
        if node_type == "LearningCandidate":
            self.connection.execute(
                "INSERT OR REPLACE INTO learning_candidates VALUES(?,?,?,?,?)",
                (
                    str(props.get("candidate_id") or node_id),
                    revision,
                    str(props.get("outcome_ref") or ""),
                    str(props.get("promotion_stage") or "quarantined"),
                    payload,
                ),
            )
        if node_type == "LearningReview":
            self.connection.execute(
                "INSERT OR REPLACE INTO learning_reviews VALUES(?,?,?,?,?,?)",
                (
                    str(props.get("review_id") or node_id),
                    revision,
                    str(props.get("candidate_id") or ""),
                    str(props.get("reviewer_id") or ""),
                    str(props.get("verdict") or ""),
                    payload,
                ),
            )
        if node_type == "LearningPromotion":
            self.connection.execute(
                "INSERT OR REPLACE INTO learning_promotions VALUES(?,?,?)",
                (
                    str(props.get("release_id") or node_id),
                    revision,
                    payload,
                ),
            )
        if node_type == "QuarantineRecord":
            self.connection.execute(
                "INSERT OR REPLACE INTO quarantine_records VALUES(?,?,?,?,?)",
                (
                    str(props.get("quarantine_id") or node_id),
                    revision,
                    str(props.get("subject_id") or ""),
                    str(props.get("reason") or ""),
                    payload,
                ),
            )
        if node_type == "RoutingPolicy":
            self.connection.execute(
                "INSERT OR REPLACE INTO routing_policies VALUES(?,?,?,?)",
                (
                    str(props.get("policy_id") or node_id),
                    revision,
                    str(props.get("status") or "active"),
                    payload,
                ),
            )

    def _project_edge(self, event: dict[str, Any], value: dict[str, Any]) -> None:
        revision = int(event["aggregate_version"])
        seq = int(event["seq"])
        edge_id = str(value["edge_id"])
        if revision == 1:
            self.connection.execute(
                "INSERT INTO edges VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    edge_id,
                    value["namespace"],
                    value["edge_type"],
                    value["source_id"],
                    value["target_id"],
                    revision,
                    value["status"],
                    seq,
                    seq,
                ),
            )
        else:
            self.connection.execute(
                "UPDATE edge_revisions SET valid_to_seq=? WHERE edge_id=? AND valid_to_seq IS NULL",
                (seq, edge_id),
            )
            self.connection.execute(
                """UPDATE edges SET edge_type=?,source_id=?,target_id=?,current_revision=?,
                   status=?,last_seq=? WHERE edge_id=?""",
                (
                    value["edge_type"],
                    value["source_id"],
                    value["target_id"],
                    revision,
                    value["status"],
                    seq,
                    edge_id,
                ),
            )
        self.connection.execute(
            "INSERT INTO edge_revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                edge_id,
                revision,
                value["source_id"],
                value["target_id"],
                value["status"],
                value["trust_class"],
                value["confidence"],
                value["evidence_grade"],
                value["source_locator"],
                event["source_version"],
                seq,
                None,
                event["event_id"],
                event["event_hash"],
                event["body"]["content_hash"],
                _json(value),
            ),
        )

    def _project_assertion(self, event: dict[str, Any], value: dict[str, Any]) -> None:
        revision = int(event["aggregate_version"])
        seq = int(event["seq"])
        assertion_id = str(value["assertion_id"])
        status = "retracted" if event["body"]["transition"]["kind"] == "retraction" else "active"
        if revision == 1:
            self.connection.execute(
                "INSERT INTO assertions VALUES(?,?,?,?,?,?,?)",
                (assertion_id, value["subject_id"], value["predicate"], revision, status, seq, seq),
            )
        else:
            self.connection.execute(
                "UPDATE assertion_revisions SET valid_to_seq=? WHERE assertion_id=? AND valid_to_seq IS NULL",
                (seq, assertion_id),
            )
            self.connection.execute(
                "UPDATE assertions SET current_revision=?,status=?,last_seq=? WHERE assertion_id=?",
                (revision, status, seq, assertion_id),
            )
        self.connection.execute(
            "INSERT INTO assertion_revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                assertion_id,
                revision,
                value["subject_id"],
                value["predicate"],
                value["object_kind"],
                _json(value["object_value"]),
                status,
                value["trust_class"],
                value["confidence"],
                value["source_version"],
                seq,
                None,
                event["event_id"],
                event["event_hash"],
                event["body"]["content_hash"],
                _json(value),
            ),
        )

    def _project_domain(self, event: dict[str, Any], contract: str, value: dict[str, Any]) -> None:
        object_id = str(event["aggregate_id"])
        revision = int(event["aggregate_version"])
        status = value.get("status")
        self.connection.execute(
            "INSERT INTO domain_objects VALUES(?,?,?,?,?)",
            (object_id, revision, event["body"]["contract_id"], status, _json(value)),
        )
        mapping = {
            "hypothesis": ("hypotheses", "hypothesis_id", [status, value.get("origin")]),
            "evidence-artifact": (
                "evidence",
                "evidence_id",
                [value.get("artifact_hash"), value.get("evidence_grade")],
            ),
            "coverage-cell": (
                "coverage_cells",
                "coverage_cell_id",
                [value.get("dimension"), status, value.get("risk_weight")],
            ),
            "tool-run": ("tool_runs", "tool_run_id", [value.get("tool_name"), value.get("parse_status")]),
            "router-action": (
                "router_actions",
                "router_action_id",
                [status, value.get("priority")],
            ),
        }
        selected = mapping.get(contract)
        if selected:
            table, _, fields = selected
            placeholders = ",".join("?" for _ in range(3 + len(fields)))
            self.connection.execute(
                f"INSERT INTO {table} VALUES({placeholders})",
                (object_id, revision, *fields, _json(value)),
            )
        if contract == "da-verdict":
            self.connection.execute(
                "INSERT OR REPLACE INTO gate_verdicts VALUES(?,?,?,?,?,?)",
                (
                    object_id,
                    revision,
                    str(value.get("gate") or ""),
                    str(value.get("decision") or ""),
                    str(value.get("hypothesis_id") or ""),
                    _json(value),
                ),
            )
        if contract == "finding":
            self.connection.execute(
                "INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?)",
                (
                    object_id,
                    revision,
                    str(value.get("status") or ""),
                    None,
                    _json(value),
                ),
            )
        if contract == "coverage-cell":
            examined = str(value.get("examined_result") or "")
            state = "unexamined"
            risk = 0
            if examined.startswith("[") and "]" in examined:
                meta = examined[1 : examined.index("]")]
                parts = meta.split("|")
                state = parts[0]
                for part in parts[1:]:
                    if part.startswith("risk="):
                        try:
                            risk = int(part.split("=", 1)[1])
                        except ValueError:
                            risk = 0
            self.connection.execute(
                "INSERT OR REPLACE INTO coverage_grid VALUES(?,?,?,?,?,?,?,?)",
                (
                    object_id,
                    revision,
                    str((value.get("target_refs") or [""])[0] if value.get("target_refs") else ""),
                    str(value.get("dimension") or ""),
                    state,
                    risk,
                    str(value.get("updated_at") or ""),
                    _json(value),
                ),
            )

    def _project_provenance(self, object_id: str, revision: int, value: Mapping[str, Any]) -> None:
        for provenance in value.get("provenance", []):
            self.connection.execute(
                "INSERT INTO provenance VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    object_id,
                    revision,
                    provenance["provenance_id"],
                    provenance["source_uri"],
                    provenance["source_version"],
                    provenance["raw_hash"],
                    provenance.get("extraction_locator"),
                    provenance.get("parser_version"),
                    provenance["retrieved_at"],
                    provenance["license_or_terms"],
                    _json(provenance),
                ),
            )

    def _project_references(self, object_id: str, revision: int, value: Mapping[str, Any]) -> None:
        for field, kind in (("artifact_refs", "artifact_hash"), ("evidence_refs", "evidence_id")):
            for reference in value.get(field, []):
                self.connection.execute(
                    "INSERT OR IGNORE INTO artifact_refs VALUES(?,?,?,?)",
                    (object_id, revision, reference, kind),
                )
        artifact_hash = value.get("artifact_hash")
        if isinstance(artifact_hash, str):
            self.connection.execute(
                "INSERT OR IGNORE INTO artifact_refs VALUES(?,?,?,?)",
                (object_id, revision, artifact_hash, "artifact_hash"),
            )

    @contextmanager
    def snapshot(self) -> Iterator[sqlite3.Connection]:
        uri = f"file:{self.path.as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("BEGIN")
        try:
            yield connection
        finally:
            connection.rollback()
            connection.close()

    def integrity_check(self) -> tuple[bool, list[str]]:
        issues = [
            str(row[0])
            for row in self.connection.execute("PRAGMA integrity_check").fetchall()
            if row[0] != "ok"
        ]
        issues.extend(
            "foreign-key violation: " + repr(tuple(row))
            for row in self.connection.execute("PRAGMA foreign_key_check").fetchall()
        )
        cursor, event_hash, _ = self.cursor()
        row = self.connection.execute("SELECT COALESCE(MAX(seq),0) FROM applied_events").fetchone()
        if cursor != int(row[0]):
            issues.append("projection cursor differs from applied event maximum")
        if cursor:
            tail = self.connection.execute(
                "SELECT event_hash FROM applied_events WHERE seq=?", (cursor,)
            ).fetchone()
            if tail is None or tail[0] != event_hash:
                issues.append("projection tail hash differs from applied event tail")
        return not issues, issues

    def logical_digest(self) -> str:
        if self._logical_digest_cache is not None:
            return self._logical_digest_cache
        tables = (
            "applied_events",
            "command_batches",
            "aggregate_heads",
            "nodes",
            "node_revisions",
            "edges",
            "edge_revisions",
            "assertions",
            "assertion_revisions",
            "provenance",
            "artifact_refs",
            "hypotheses",
            "evidence",
            "coverage_cells",
            "tool_runs",
            "router_actions",
            "domain_objects",
            "outbox",
            "checkpoints",
            "tombstones",
            "coverage_grid",
            "cognitive_maps",
            "router_runtime",
            "gate_verdicts",
            "findings",
            "poc_runs",
            "dedup_clusters",
            "knowledge_records",
            "conflict_groups",
            "corpus_releases",
            "learning_outcomes",
            "learning_candidates",
            "learning_reviews",
            "learning_promotions",
            "quarantine_records",
            "routing_policies",
        )
        content: list[dict[str, Any]] = []
        for table in tables:
            columns = self.connection.execute(f"PRAGMA table_info({table})").fetchall()
            column_names = [str(row[1]) for row in columns]
            # Large JSON bodies are already bound by content/event/commit hashes
            # stored in the same logical projection. Digest the semantic columns
            # and those cryptographic commitments, not representation-dependent
            # duplicate TEXT blobs.
            selected = [
                (index, column)
                for index, column in enumerate(column_names)
                if not column.endswith("_json")
            ]
            primary = [
                str(row[1])
                for row in sorted(columns, key=lambda row: int(row[5]))
                if int(row[5]) > 0
            ]
            order = primary or [str(row[1]) for row in columns]
            quoted = ",".join('"' + column.replace('"', '""') + '"' for column in order)
            selected_sql = ",".join(
                '"' + column.replace('"', '""') + '"' for _, column in selected
            )
            digest = hashlib.sha256()
            count = 0
            for row in self.connection.execute(
                f"SELECT {selected_sql} FROM {table} ORDER BY {quoted}"
            ):
                digest.update(canonical_line(list(row)))
                count += 1
            content.append(
                {
                    "table": table,
                    "row_count": count,
                    "rows_hash": "sha256:" + digest.hexdigest(),
                }
            )
        self._logical_digest_cache = canonical_hash(
            {
                "domain": "ayran.projection.logical.v1",
                "stream": self.stream,
                "projection_schema_version": PROJECTION_SCHEMA_VERSION,
                "migration_version": MIGRATION_VERSION,
                "tables": content,
            }
        )
        return self._logical_digest_cache

    def projection_counts(self) -> dict[str, int]:
        tables = (
            "applied_events",
            "command_batches",
            "nodes",
            "node_revisions",
            "edges",
            "edge_revisions",
            "assertions",
            "assertion_revisions",
            "tombstones",
            "outbox",
        )
        return {
            table: int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        }

    def pragmas(self) -> dict[str, Any]:
        return {
            name: self.connection.execute(f"PRAGMA {name}").fetchone()[0]
            for name in ("foreign_keys", "journal_mode", "synchronous", "busy_timeout")
        }

    def checkpoint_wal(self) -> None:
        self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def close(self) -> None:
        self.connection.close()
