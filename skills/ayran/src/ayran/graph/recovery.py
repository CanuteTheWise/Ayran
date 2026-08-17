"""Integrated append, replay, verification, rebuild, rollback, and graph doctor."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from ayran.api.validators import validate_contract

from .canonical import atomic_write, canonical_line, object_hash, utc_now
from .checkpoints import create_checkpoint
from .errors import (
    IDEMPOTENCY_COLLISION,
    JOURNAL_CORRUPT,
    PROJECTION_CORRUPT,
    GraphError,
)
from .events import acknowledgement_for_replay, build_batch, command_request_hash
from .ids import new_id
from .journal import DEFAULT_MAX_SEGMENT_BYTES, DEFAULT_MAX_SEGMENT_EVENTS, Journal
from .leases import WriterLease
from .namespaces import require_ext4
from .projection import MIGRATION_VERSION, PROJECTION_SCHEMA_VERSION, Projection
from .queries import GraphQueries
from .types import AppendCommand


class GraphStore:
    def __init__(
        self,
        root: Path,
        stream: dict[str, Any],
        *,
        allow_unsafe_filesystem: bool = False,
        synchronous: str = "FULL",
        max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES,
        max_segment_events: int = DEFAULT_MAX_SEGMENT_EVENTS,
        fault_hook: Callable[[str], None] | None = None,
        fault_split_write: bool = False,
    ) -> None:
        require_ext4(root, allow_unsafe_filesystem=allow_unsafe_filesystem)
        self.root = root
        self.stream = copy.deepcopy(stream)
        self.synchronous = synchronous
        self.fault_hook = fault_hook
        root.mkdir(parents=True, exist_ok=True)
        self.lease = WriterLease(root, stream["stream_id"], fault_hook=fault_hook).acquire()
        self.journal = Journal(
            root,
            self.stream,
            max_segment_bytes=max_segment_bytes,
            max_segment_events=max_segment_events,
            fault_hook=fault_hook,
            fault_split_write=fault_split_write,
        )
        try:
            self.journal.verify(recover_tail=True)
            self.projection = self._open_projection()
            self.replay()
            self.queries = GraphQueries(self.projection)
        except BaseException as error:
            if isinstance(error, GraphError):
                self._diagnose_error(error, "open")
            self.lease.release()
            raise

    def _fault(self, name: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(name)

    def _diagnose_error(self, error: GraphError, operation: str) -> Path:
        diagnostic_id = new_id("dia")
        value = {
            "schema_version": "1.0.0",
            "diagnostic_id": diagnostic_id,
            "created_at": utc_now(),
            "operation": operation,
            "stream": self.stream,
            "error": error.as_dict(),
        }
        path = self.root / "diagnostics" / f"{diagnostic_id}.failure.json"
        atomic_write(path, canonical_line(value))
        return path

    @property
    def pointer_path(self) -> Path:
        return self.root / "projection.current.json"

    @property
    def projections_dir(self) -> Path:
        return self.root / "projections"

    def _pointer(self) -> dict[str, Any] | None:
        if not self.pointer_path.is_file():
            return None
        try:
            value = cast(dict[str, Any], json.loads(self.pointer_path.read_text(encoding="utf-8")))
            filename = value["filename"]
            path = (self.projections_dir / filename).resolve(strict=False)
            if path.parent != self.projections_dir.resolve(strict=False) or Path(filename).name != filename:
                raise ValueError("unsafe projection pointer")
            return value
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as error:
            raise GraphError(PROJECTION_CORRUPT, "Projection pointer is invalid.") from error

    def _write_pointer(self, filename: str, previous: str | None) -> dict[str, Any]:
        value = {
            "schema_version": "1.0.0",
            "pointer_id": new_id("ptr"),
            "filename": filename,
            "previous_filename": previous,
            "projection_schema_version": PROJECTION_SCHEMA_VERSION,
            "migration_version": MIGRATION_VERSION,
            "switched_at": utc_now(),
        }
        atomic_write(
            self.pointer_path,
            canonical_line(value),
            fault_hook=self.fault_hook,
            fault_prefix="projection_pointer",
        )
        return value

    def _open_projection(self) -> Projection:
        self.projections_dir.mkdir(parents=True, exist_ok=True)
        pointer = self._pointer()
        if pointer is None:
            filename = "projection-000001.sqlite3"
            projection = Projection(
                self.projections_dir / filename,
                self.stream,
                synchronous=self.synchronous,
                fault_hook=self.fault_hook,
            )
            self._write_pointer(filename, None)
            return projection
        try:
            return Projection(
                self.projections_dir / pointer["filename"],
                self.stream,
                synchronous=self.synchronous,
                fault_hook=self.fault_hook,
            )
        except GraphError:
            return self._rebuild_without_current()

    def _rebuild_without_current(self) -> Projection:
        pointer = self._pointer()
        old = pointer["filename"] if pointer else None
        filename = self._next_projection_name()
        projection = Projection(
            self.projections_dir / filename,
            self.stream,
            synchronous=self.synchronous,
            fault_hook=self.fault_hook,
        )
        assert self.journal.state is not None
        for begin, events, commit in self.journal.state.committed_batches:
            projection.apply_batch(begin, events, commit, acknowledgement_for_replay(begin, events, commit))
        ok, issues = projection.integrity_check()
        if not ok:
            projection.close()
            raise GraphError(PROJECTION_CORRUPT, "Rebuilt projection failed validation.", details={"issues": issues})
        projection.checkpoint_wal()
        self._write_pointer(filename, old)
        return projection

    def _next_projection_name(self) -> str:
        ordinals = []
        for path in self.projections_dir.glob("projection-*.sqlite3"):
            try:
                ordinals.append(int(path.stem.split("-")[-1]))
            except ValueError:
                continue
        return f"projection-{max(ordinals, default=0) + 1:06d}.sqlite3"

    def replay(self) -> dict[str, Any]:
        if self.journal.state is None:
            self.journal.verify(recover_tail=True)
        assert self.journal.state is not None
        projection_cursor, _, _ = self.projection.cursor()
        if projection_cursor > self.journal.state.cursor:
            raise GraphError(PROJECTION_CORRUPT, "Projection cursor is ahead of canonical history.")
        applied = 0
        for begin, events, commit in self.journal.state.committed_batches:
            if events[-1]["seq"] <= projection_cursor:
                continue
            if events[0]["seq"] <= projection_cursor:
                raise GraphError(PROJECTION_CORRUPT, "Projection cursor splits an atomic journal batch.")
            acknowledgement = acknowledgement_for_replay(begin, events, commit)
            self.projection.apply_batch(begin, events, commit, acknowledgement)
            applied += len(events)
        cursor, event_hash, commit_hash = self.projection.cursor()
        if cursor != self.journal.state.cursor or event_hash != self.journal.state.last_event_hash:
            raise GraphError(PROJECTION_CORRUPT, "Projection replay did not reach the journal cursor.")
        return {
            "applied_events": applied,
            "projection_cursor": cursor,
            "event_hash": event_hash,
            "commit_hash": commit_hash,
        }

    def _check_references(self, events: list[dict[str, Any]]) -> None:
        batch_ids = {event["body"]["object_id"] for event in events}
        for event in events:
            value = event["body"]["value"]
            contract = event["body"]["contract_id"].rsplit("@", 1)[0]
            references: list[str] = []
            if contract == "graph-edge":
                references = [value["source_id"], value["target_id"]]
            elif contract == "graph-assertion":
                references = [value["subject_id"]]
            for reference in references:
                if reference not in batch_ids and not self.projection.entity_exists(reference):
                    from .errors import CONTRACT_INVALID

                    raise GraphError(
                        CONTRACT_INVALID,
                        "Graph event references an entity absent from history and its command batch.",
                    )

    def append(self, command: AppendCommand) -> dict[str, Any]:
        if self.journal.state is None:
            self.journal.verify(recover_tail=True)
        assert self.journal.state is not None
        projection_cursor, _, _ = self.projection.cursor()
        if projection_cursor < self.journal.state.cursor:
            self.replay()
        request_hash = command_request_hash(command, self.stream)
        prior = self.projection.receipt(command.idempotency_key)
        if prior is not None:
            prior_hash, acknowledgement = prior
            if prior_hash != request_hash:
                raise GraphError(
                    IDEMPOTENCY_COLLISION,
                    "Idempotency key was already committed with a different canonical command.",
                )
            acknowledgement["idempotent_replay"] = True
            validate_contract("graph-acknowledgement", acknowledgement)
            return acknowledgement
        aggregate_ids = []
        from .journal import contract_name, object_id_for

        for item in command.items:
            name = contract_name(item.contract_id)
            aggregate_ids.append(object_id_for(name, item.value))
        revisions = {item: self.projection.aggregate_revision(item) for item in aggregate_ids}
        begin, events, commit, acknowledgement = build_batch(
            command,
            self.stream,
            cursor=self.journal.state.cursor,
            last_event_hash=self.journal.state.last_event_hash,
            last_commit_hash=self.journal.state.last_commit_hash,
            current_revisions=revisions,
        )
        self._check_references(events)
        try:
            self.journal.append_batch(begin, events, commit)
        except BaseException:
            self.journal.state = None
            raise
        self.projection.apply_batch(begin, events, commit, acknowledgement)
        self._fault("after_acknowledgement")
        return acknowledgement

    def verify(self, *, operation: str = "verify") -> dict[str, Any]:
        # Keep committed batches in the verified state. Rebuild/replay may be the
        # very next operation and the journal, not SQLite, remains authoritative.
        try:
            journal_state = self.journal.verify(recover_tail=False, include_batches=True)
        except GraphError as error:
            self._diagnose_error(error, operation)
            raise
        ok, projection_issues = self.projection.integrity_check()
        projection_cursor, projection_hash, _ = self.projection.cursor()
        issues = list(journal_state.issues)
        issues.extend(
            {
                "code": "PROJECTION_CORRUPT",
                "message": issue,
                "segment": None,
                "line": None,
                "retryable": False,
            }
            for issue in projection_issues
        )
        if projection_cursor != journal_state.cursor or projection_hash != journal_state.last_event_hash:
            issues.append(
                {
                    "code": "PROJECTION_CURSOR_MISMATCH",
                    "message": "Projection and journal cursors do not agree.",
                    "segment": None,
                    "line": None,
                    "retryable": False,
                }
            )
        value: dict[str, Any] = {
            "schema_version": "1.0.0",
            "report_id": new_id("rpt"),
            "created_at": utc_now(),
            "operation": operation,
            "stream": self.stream,
            "status": "ok" if ok and not issues else "corrupt",
            "journal_cursor": journal_state.cursor,
            "projection_cursor": projection_cursor,
            "last_event_hash": journal_state.last_event_hash,
            "last_commit_hash": journal_state.last_commit_hash,
            "verified_segments": journal_state.segment_count,
            "verified_batches": journal_state.batch_count,
            "verified_events": journal_state.event_count,
            "issues": issues,
            "recovered_suffix_hash": journal_state.recovered_suffix_hash,
            "query_digest": self.projection.logical_digest() if ok else None,
            "integrity": {
                "algorithm": "sha256",
                "canonicalization": "rfc8785",
                "content_hash": "sha256:" + "0" * 64,
                "excluded_fields": ["integrity.content_hash"],
            },
        }
        value["integrity"]["content_hash"] = object_hash(value)
        validate_contract("graph-integrity-report", value)
        if issues and any(issue["code"] == JOURNAL_CORRUPT for issue in issues):
            raise GraphError(JOURNAL_CORRUPT, "Canonical journal verification failed.")
        return value

    def rebuild(
        self,
        *,
        from_checkpoint: Path | None = None,
        verify_journal: bool = True,
    ) -> dict[str, Any]:
        if from_checkpoint is not None:
            from .checkpoints import read_checkpoint

            read_checkpoint(from_checkpoint, self.stream)
        if verify_journal:
            self.journal.verify(recover_tail=False)
        elif self.journal.state is None:
            raise RuntimeError("a verified in-memory journal state is required")
        old_pointer = self._pointer()
        old_filename = old_pointer["filename"] if old_pointer else None
        old_digest: str | None = None
        old_ok, _ = self.projection.integrity_check()
        if old_ok:
            old_digest = self.projection.logical_digest()
        filename = self._next_projection_name()
        candidate = Projection(
            self.projections_dir / filename,
            self.stream,
            synchronous=self.synchronous,
            fault_hook=self.fault_hook,
        )
        assert self.journal.state is not None
        self._fault("during_projection_rebuild")
        for begin, events, commit in self.journal.state.committed_batches:
            candidate.apply_batch(begin, events, commit, acknowledgement_for_replay(begin, events, commit))
        ok, issues = candidate.integrity_check()
        candidate_digest = candidate.logical_digest() if ok else None
        if not ok or (old_digest is not None and candidate_digest != old_digest):
            candidate.close()
            raise GraphError(
                PROJECTION_CORRUPT,
                "Candidate projection failed integrity or logical-digest validation.",
                details={"issues": issues},
            )
        candidate.checkpoint_wal()
        self._write_pointer(filename, old_filename)
        self.projection.close()
        self.projection = candidate
        self.queries = GraphQueries(candidate)
        return {
            "projection": filename,
            "previous_projection": old_filename,
            "cursor": candidate.cursor()[0],
            "logical_digest": candidate_digest,
            "from_checkpoint": from_checkpoint is not None,
        }

    def rollback_projection(self) -> dict[str, Any]:
        pointer = self._pointer()
        if pointer is None or not pointer.get("previous_filename"):
            raise GraphError(PROJECTION_CORRUPT, "No prior projection is recorded for rollback.")
        previous = str(pointer["previous_filename"])
        candidate = Projection(
            self.projections_dir / previous,
            self.stream,
            synchronous=self.synchronous,
            fault_hook=self.fault_hook,
        )
        ok, issues = candidate.integrity_check()
        if not ok:
            candidate.close()
            raise GraphError(PROJECTION_CORRUPT, "Prior projection failed rollback validation.", details={"issues": issues})
        self._write_pointer(previous, pointer["filename"])
        self.projection.close()
        self.projection = candidate
        self.queries = GraphQueries(candidate)
        return {"projection": previous, "cursor": candidate.cursor()[0]}

    def checkpoint(self, **hashes: str | None) -> dict[str, Any]:
        cursor, event_hash, commit_hash = self.projection.cursor()
        outbox = self.projection.connection.execute(
            "SELECT event_id,seq,status,attempts FROM outbox ORDER BY seq"
        ).fetchall()
        from .canonical import canonical_hash

        return create_checkpoint(
            self.root,
            self.stream,
            journal_cursor=cursor,
            journal_event_hash=event_hash,
            journal_commit_hash=commit_hash,
            projection_schema_version=PROJECTION_SCHEMA_VERSION,
            migration_version=MIGRATION_VERSION,
            projection_digest=self.projection.logical_digest(),
            outbox_digest=canonical_hash([list(row) for row in outbox]),
            target_hash=hashes.get("target_hash"),
            config_hash=hashes.get("config_hash"),
            source_hash=hashes.get("source_hash"),
            tool_hash=hashes.get("tool_hash"),
            artifact_manifest_hash=hashes.get("artifact_manifest_hash"),
            fault_hook=self.fault_hook,
        )

    def doctor(self) -> dict[str, Any]:
        return self.verify(operation="doctor")

    def close(self) -> None:
        try:
            self.projection.close()
        finally:
            self.lease.release()

    def __enter__(self) -> GraphStore:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
