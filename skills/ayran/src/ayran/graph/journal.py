"""Frozen journal-v1 framing, append, verification, rotation, backup, and tail recovery."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from ayran.api.validators import CONTRACTS, ContractValidationError, validate_contract

from .canonical import (
    atomic_write,
    canonical_hash,
    canonical_line,
    commit_hash,
    file_hash,
    fsync_directory,
    members_hash,
    merkle_root,
    object_hash,
    sha256_bytes,
    strict_canonical_load,
    utc_now,
    write_all,
)
from .errors import (
    CONTRACT_INVALID,
    JOURNAL_CORRUPT,
    NAMESPACE_MISMATCH,
    UNSUPPORTED_SCHEMA_VERSION,
    GraphError,
)
from .ids import new_id
from .types import VerificationState

JOURNAL_FORMAT_VERSION = 1
SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_SEGMENT_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_SEGMENT_EVENTS = 100_000
MAX_FRAME_BYTES = 32 * 1024 * 1024
SEGMENT_PATTERN = re.compile(r"^[0-9]{6}\.jsonl$")

OBJECT_ID_FIELDS = {
    "graph-node": "node_id",
    "graph-edge": "edge_id",
    "graph-assertion": "assertion_id",
    "hypothesis": "hypothesis_id",
    "evidence-artifact": "evidence_id",
    "coverage-cell": "coverage_cell_id",
    "tool-run": "tool_run_id",
    "router-action": "router_action_id",
    "learning-outcome": "learning_outcome_id",
    "finding": "finding_id",
    "context-pack": "context_pack_id",
    "da-verdict": "verdict_id",
}


def contract_name(contract_id: str) -> str:
    try:
        name, version = contract_id.rsplit("@", 1)
    except ValueError as error:
        raise GraphError(CONTRACT_INVALID, "Body contract ID is not versioned.") from error
    if version != SCHEMA_VERSION or name not in CONTRACTS:
        raise GraphError(
            UNSUPPORTED_SCHEMA_VERSION,
            "The journal body contract version is not supported.",
            details={"contract_id": contract_id},
        )
    return name


def object_id_for(name: str, value: Mapping[str, Any]) -> str:
    field = OBJECT_ID_FIELDS.get(name)
    if field is None or not isinstance(value.get(field), str):
        raise GraphError(
            CONTRACT_INVALID,
            "The journal body contract has no registered durable object identity.",
            details={"contract": name},
        )
    return cast(str, value[field])


def _validate_typed_values(name: str, value: Mapping[str, Any]) -> None:
    properties = value.get("properties")
    if isinstance(properties, list):
        seen: set[str] = set()
        expected_types: dict[str, tuple[type[object], ...]] = {
            "string": (str,),
            "integer": (int,),
            "number": (int, float),
            "boolean": (bool,),
            "identifier": (str,),
            "hash": (str,),
        }
        for item in properties:
            if not isinstance(item, dict):
                continue
            key = item.get("name")
            if not isinstance(key, str) or key in seen:
                raise GraphError(CONTRACT_INVALID, "Typed property names must be unique.")
            seen.add(key)
            value_type = item.get("value_type")
            actual = item.get("value")
            if actual is not None and (
                value_type not in expected_types
                or not isinstance(actual, expected_types[cast(str, value_type)])
                or (value_type in {"integer", "number"} and isinstance(actual, bool))
            ):
                raise GraphError(CONTRACT_INVALID, "Typed property value does not match value_type.")
    if name == "graph-assertion":
        kind = value.get("object_kind")
        actual = value.get("object_value")
        expected: dict[str, tuple[type[object], ...]] = {
            "identifier": (str,),
            "string": (str,),
            "integer": (int,),
            "number": (int, float),
            "boolean": (bool,),
            "hash": (str,),
        }
        if kind not in expected or not isinstance(actual, expected[cast(str, kind)]):
            raise GraphError(CONTRACT_INVALID, "Assertion object value does not match object_kind.")


def validate_body(
    event: Mapping[str, Any],
    stream: Mapping[str, Any],
    *,
    same_batch_ids: set[str] | None = None,
    contract_schema_validated: bool = False,
    content_hash_validated: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Validate the embedded object, its digest, identity, namespace, and transition."""

    body = event.get("body")
    if not isinstance(body, dict) or not isinstance(body.get("value"), dict):
        raise GraphError(CONTRACT_INVALID, "Journal event body is missing its durable value.")
    value = cast(dict[str, Any], body["value"])
    name = contract_name(cast(str, body.get("contract_id")))
    context: dict[str, str] | None = None
    if stream.get("namespace") == "target":
        target = stream.get("target_identity")
        if not isinstance(target, dict):
            raise GraphError(NAMESPACE_MISMATCH, "Target stream identity is incomplete.")
        context = {"run_id": cast(str, stream["run_id"]), "target_id": cast(str, target["target_id"])}
    if not contract_schema_validated:
        try:
            validate_contract(name, value, context)
        except (ContractValidationError, KeyError) as error:
            raise GraphError(
                CONTRACT_INVALID, "Embedded graph object failed its canonical contract."
            ) from error
    elif context is not None:
        if value.get("run_id") != context["run_id"]:
            raise GraphError(NAMESPACE_MISMATCH, "Embedded object run identity differs from its stream.")
        target = value.get("target_identity")
        if isinstance(target, dict) and target.get("target_id") != context["target_id"]:
            raise GraphError(
                NAMESPACE_MISMATCH, "Embedded object target identity differs from its stream."
            )
    _validate_typed_values(name, value)
    actual_id = object_id_for(name, value)
    if actual_id != body.get("object_id") or actual_id != event.get("aggregate_id"):
        raise GraphError(CONTRACT_INVALID, "Event, aggregate, and body object identities disagree.")
    if content_hash_validated:
        integrity = value.get("integrity")
        if not isinstance(integrity, dict) or body.get("content_hash") != integrity.get(
            "content_hash"
        ):
            raise GraphError(CONTRACT_INVALID, "Embedded graph object content hash is invalid.")
    elif body.get("content_hash") != object_hash(value):
        raise GraphError(CONTRACT_INVALID, "Embedded graph object content hash is invalid.")
    if value.get("namespace") is not None and value.get("namespace") != stream.get("namespace"):
        raise GraphError(NAMESPACE_MISMATCH, "Embedded object namespace differs from its stream.")
    if name in {"graph-node", "graph-edge"} and value.get("revision") != event.get(
        "aggregate_version"
    ):
        raise GraphError(CONTRACT_INVALID, "Object revision differs from aggregate version.")
    if name in {"graph-node", "graph-edge", "graph-assertion"} and value.get(
        "valid_from_event"
    ) != event.get("event_id"):
        raise GraphError(CONTRACT_INVALID, "Object validity must begin at its journal event.")
    transition = body.get("transition")
    if not isinstance(transition, dict):
        raise GraphError(CONTRACT_INVALID, "Journal transition is missing.")
    expected_event: set[str]
    if name == "graph-node":
        expected_event = {"node.created" if event.get("aggregate_version") == 1 else "node.revised"}
    elif name == "graph-edge":
        expected_event = {"edge.created" if event.get("aggregate_version") == 1 else "edge.revised"}
    elif name == "graph-assertion":
        expected_event = {"assertion.retracted" if transition.get("kind") == "retraction" else "assertion.added"}
    else:
        stem = name.replace("-", "_")
        expected_event = {f"{stem}.recorded", f"{stem}.revised"}
    if transition.get("kind") == "tombstone":
        expected_event = {"entity.tombstoned"}
    if event.get("event_type") not in expected_event:
        raise GraphError(
            CONTRACT_INVALID,
            "Event type is incompatible with its durable body and transition.",
            details={"contract": name, "event_type": event.get("event_type")},
        )
    if transition.get("kind") in {"retraction", "tombstone"} and not transition.get("reason"):
        raise GraphError(CONTRACT_INVALID, "Retractions and tombstones require a reason.")
    if name == "graph-edge":
        allowed = same_batch_ids or set()
        for field in ("source_id", "target_id"):
            ref = value.get(field)
            if not isinstance(ref, str):
                raise GraphError(CONTRACT_INVALID, "Graph edge reference is invalid.")
            if same_batch_ids is not None and ref not in allowed:
                # Historical existence is checked by the verifier/projection caller.
                continue
    return name, value


def _issue(code: str, message: str, segment: str | None, line: int | None) -> dict[str, Any]:
    return {"code": code, "message": message, "segment": segment, "line": line, "retryable": False}


class Journal:
    def __init__(
        self,
        root: Path,
        stream: dict[str, Any],
        *,
        max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES,
        max_segment_events: int = DEFAULT_MAX_SEGMENT_EVENTS,
        fault_hook: Callable[[str], None] | None = None,
        fault_split_write: bool = False,
    ) -> None:
        self.root = root
        self.stream = copy.deepcopy(stream)
        self.events_dir = root / "events"
        self.manifests_dir = root / "manifests"
        self.diagnostics_dir = root / "diagnostics"
        self.backups_dir = root / "backups"
        self.max_segment_bytes = max_segment_bytes
        self.max_segment_events = max_segment_events
        self.fault_hook = fault_hook
        self.fault_split_write = fault_split_write
        for path in (self.events_dir, self.manifests_dir, self.diagnostics_dir, self.backups_dir):
            path.mkdir(parents=True, exist_ok=True)
        self.state: VerificationState | None = None

    def _fault(self, name: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(name)

    def segments(self) -> list[Path]:
        return sorted(
            path for path in self.events_dir.glob("*.jsonl") if SEGMENT_PATTERN.fullmatch(path.name)
        )

    def _active_segment(self) -> Path:
        segments = self.segments()
        if not segments:
            path = self.events_dir / "000001.jsonl"
            fd = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600
            )
            os.fsync(fd)
            os.close(fd)
            fsync_directory(self.events_dir)
            self._fault("after_segment_create")
            return path
        highest = segments[-1]
        manifest = self.manifests_dir / f"{highest.stem}.manifest.json"
        if manifest.exists():
            ordinal = int(highest.stem) + 1
            path = self.events_dir / f"{ordinal:06d}.jsonl"
            fd = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600
            )
            os.fsync(fd)
            os.close(fd)
            fsync_directory(self.events_dir)
            self._fault("after_segment_create")
            return path
        return highest

    def _preserve_suffix(self, segment: Path, suffix: bytes, offset: int) -> str:
        receipt_id = new_id("rcp")
        payload_path = self.diagnostics_dir / f"{receipt_id}.suffix.bin"
        atomic_write(payload_path, suffix)
        digest = sha256_bytes(suffix)
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "kind": "uncommitted-journal-suffix",
            "segment": segment.name,
            "offset": offset,
            "byte_size": len(suffix),
            "content_hash": digest,
            "created_at": utc_now(),
        }
        atomic_write(self.diagnostics_dir / f"{receipt_id}.json", canonical_line(receipt))
        return digest

    def _recover_suffix(self, segment: Path, raw: bytes, offset: int) -> str | None:
        suffix = raw[offset:]
        if not suffix:
            return None
        digest = self._preserve_suffix(segment, suffix, offset)
        with segment.open("r+b") as stream:
            stream.truncate(offset)
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(segment.parent)
        return digest

    def verify(self, *, recover_tail: bool = False, include_batches: bool = True) -> VerificationState:
        state = VerificationState()
        expected_seq = 1
        last_event_hash: str | None = None
        last_commit_hash: str | None = None
        aggregate_heads: dict[str, int] = {}
        seen_events: set[str] = set()
        seen_batches: set[str] = set()
        known_objects: set[str] = set()
        segments = self.segments()
        for segment_index, segment in enumerate(segments):
            raw = segment.read_bytes()
            is_last = segment_index == len(segments) - 1
            manifest_path = self.manifests_dir / f"{segment.stem}.manifest.json"
            if not is_last and not manifest_path.is_file():
                raise GraphError(JOURNAL_CORRUPT, "A non-active journal segment has no manifest.")
            line_start = 0
            last_commit_offset = 0
            begin: dict[str, Any] | None = None
            events: list[dict[str, Any]] = []
            begin_offset = 0
            lines = raw.splitlines(keepends=True)
            for line_number, framed in enumerate(lines, 1):
                has_newline = framed.endswith(b"\n")
                frame = framed[:-1] if has_newline else framed
                if not has_newline:
                    if not (is_last and recover_tail):
                        raise GraphError(JOURNAL_CORRUPT, "Journal has a trailing partial frame.")
                    offset = begin_offset if begin is not None else line_start
                    state.recovered_suffix_hash = self._recover_suffix(segment, raw, offset)
                    raw = raw[:offset]
                    begin = None
                    events = []
                    break
                if not frame or len(frame) > MAX_FRAME_BYTES:
                    raise GraphError(JOURNAL_CORRUPT, "Journal frame length is invalid.")
                try:
                    record = strict_canonical_load(frame)
                    if not isinstance(record, dict):
                        raise ValueError("record is not an object")
                    validate_contract("journal-record", record)
                except (ValueError, ContractValidationError, UnicodeError) as error:
                    raise GraphError(
                        JOURNAL_CORRUPT,
                        "A complete journal frame is invalid.",
                        details={"segment": segment.name, "line": line_number},
                    ) from error
                if record.get("journal_format_version") != JOURNAL_FORMAT_VERSION:
                    raise GraphError(UNSUPPORTED_SCHEMA_VERSION, "Unsupported journal format version.")
                record_type = record["record_type"]
                if record_type == "batch.begin":
                    if begin is not None:
                        raise GraphError(JOURNAL_CORRUPT, "Nested journal batch begin record.")
                    if record["stream"] != self.stream:
                        raise GraphError(NAMESPACE_MISMATCH, "Journal record stream identity changed.")
                    if record["first_seq"] != expected_seq:
                        raise GraphError(JOURNAL_CORRUPT, "Journal batch begins at a noncontiguous sequence.")
                    if record["previous_event_hash"] != last_event_hash or record[
                        "previous_commit_hash"
                    ] != last_commit_hash:
                        raise GraphError(JOURNAL_CORRUPT, "Journal batch predecessor hash is invalid.")
                    revisions = record["expected_revisions"]
                    if revisions != sorted(revisions, key=lambda item: item["aggregate_id"]):
                        raise GraphError(JOURNAL_CORRUPT, "Expected revisions are not canonically sorted.")
                    if len({item["aggregate_id"] for item in revisions}) != len(revisions):
                        raise GraphError(JOURNAL_CORRUPT, "Expected revisions contain duplicates.")
                    begin = record
                    events = []
                    begin_offset = line_start
                elif record_type == "batch.event":
                    if begin is None:
                        raise GraphError(JOURNAL_CORRUPT, "Journal event is outside a batch.")
                    event = cast(dict[str, Any], record["event"])
                    if event["stream"] != self.stream or event["batch_id"] != begin["batch_id"]:
                        raise GraphError(JOURNAL_CORRUPT, "Journal event has the wrong stream or batch.")
                    ordinal = len(events) + 1
                    if event["ordinal"] != ordinal or event["seq"] != expected_seq + len(events):
                        raise GraphError(JOURNAL_CORRUPT, "Journal event ordinal or sequence is invalid.")
                    predecessor = last_event_hash if not events else events[-1]["event_hash"]
                    if event["previous_event_hash"] != predecessor:
                        raise GraphError(JOURNAL_CORRUPT, "Journal event hash chain is broken.")
                    if event["event_id"] in seen_events or event["event_hash"] in seen_events:
                        raise GraphError(JOURNAL_CORRUPT, "Duplicate event identity or hash.")
                    same_batch_ids = {
                        cast(str, item["event"]["body"]["object_id"])
                        for item in [record]
                    } | {cast(str, item["body"]["object_id"]) for item in events}
                    name, body_value = validate_body(
                        event,
                        self.stream,
                        same_batch_ids=same_batch_ids,
                        content_hash_validated=True,
                    )
                    expected_version = aggregate_heads.get(event["aggregate_id"], 0) + 1
                    if event["aggregate_version"] != expected_version:
                        raise GraphError(JOURNAL_CORRUPT, "Aggregate revision history is not contiguous.")
                    if name == "graph-edge":
                        refs = {body_value["source_id"], body_value["target_id"]}
                        batch_objects = {item["body"]["object_id"] for item in events} | {
                            event["body"]["object_id"]
                        }
                        if not refs <= known_objects | batch_objects:
                            raise GraphError(JOURNAL_CORRUPT, "Graph edge references an unknown node.")
                    if name == "graph-assertion" and body_value["subject_id"] not in known_objects | {
                        item["body"]["object_id"] for item in events
                    }:
                        raise GraphError(JOURNAL_CORRUPT, "Graph assertion references an unknown subject.")
                    events.append(event)
                elif record_type == "batch.commit":
                    if begin is None or not events:
                        raise GraphError(JOURNAL_CORRUPT, "Journal commit has no open batch.")
                    hashes = [cast(str, event["event_hash"]) for event in events]
                    expected = {
                        "stream": self.stream,
                        "batch_id": begin["batch_id"],
                        "event_count": len(events),
                        "first_seq": events[0]["seq"],
                        "last_seq": events[-1]["seq"],
                        "first_event_hash": hashes[0],
                        "last_event_hash": hashes[-1],
                        "begin_hash": canonical_hash(begin),
                        "members_hash": members_hash(hashes),
                        "previous_commit_hash": last_commit_hash,
                    }
                    if any(record[key] != value for key, value in expected.items()):
                        raise GraphError(JOURNAL_CORRUPT, "Journal commit does not bind its batch.")
                    if begin["event_count"] != len(events) or record["commit_hash"] != commit_hash(record):
                        raise GraphError(JOURNAL_CORRUPT, "Journal commit count or hash is invalid.")
                    if begin["batch_id"] in seen_batches:
                        raise GraphError(JOURNAL_CORRUPT, "Duplicate journal batch ID.")
                    seen_batches.add(begin["batch_id"])
                    for event in events:
                        seen_events.add(event["event_id"])
                        seen_events.add(event["event_hash"])
                        aggregate_heads[event["aggregate_id"]] = event["aggregate_version"]
                        known_objects.add(event["body"]["object_id"])
                    expected_seq = events[-1]["seq"] + 1
                    last_event_hash = events[-1]["event_hash"]
                    last_commit_hash = record["commit_hash"]
                    state.batch_count += 1
                    state.event_count += len(events)
                    state.cursor = events[-1]["seq"]
                    state.last_event_hash = last_event_hash
                    state.last_commit_hash = last_commit_hash
                    if include_batches:
                        state.committed_batches.append((begin, list(events), record))
                    begin = None
                    events = []
                    last_commit_offset = line_start + len(framed)
                line_start += len(framed)
            if begin is not None:
                if not (is_last and recover_tail):
                    raise GraphError(JOURNAL_CORRUPT, "Journal ends with an uncommitted batch.")
                state.recovered_suffix_hash = self._recover_suffix(segment, raw, begin_offset)
            if manifest_path.exists():
                self._verify_manifest(segment, manifest_path)
            elif not is_last:
                raise GraphError(JOURNAL_CORRUPT, "Closed segment manifest is missing.")
            if is_last and manifest_path.exists() and last_commit_offset != len(raw):
                raise GraphError(JOURNAL_CORRUPT, "Closed segment contains bytes after its last commit.")
            state.segment_count += 1
        self.state = state
        return state

    def append_batch(
        self, begin: dict[str, Any], events: list[dict[str, Any]], commit: dict[str, Any]
    ) -> Path:
        if self.state is None:
            raise RuntimeError("journal must be verified before append")
        records = [begin, *({"schema_version": SCHEMA_VERSION, "journal_format_version": 1, "record_type": "batch.event", "event": event} for event in events), commit]
        # build_batch validated each event and both boundary records before I/O.
        # Replay remains an independent full-schema verifier for on-disk bytes.
        payload = b"".join(canonical_line(record) for record in records)
        segment = self._active_segment()
        fd = os.open(segment, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
        try:
            self._fault("before_append")
            if self.fault_split_write and len(payload) > 1:
                split = min(4096, len(payload) - 1)
                write_all(fd, payload[:split])
                self._fault("during_partial_write")
                write_all(fd, payload[split:])
            else:
                write_all(fd, payload)
            self._fault("after_complete_write")
            os.fsync(fd)
            self._fault("after_journal_fsync")
        finally:
            os.close(fd)
        self.state.cursor = events[-1]["seq"]
        self.state.last_event_hash = events[-1]["event_hash"]
        self.state.last_commit_hash = commit["commit_hash"]
        self.state.batch_count += 1
        self.state.event_count += len(events)
        self.state.committed_batches.append((begin, list(events), commit))
        segment_event_count = self._segment_events(segment)
        if segment.stat().st_size >= self.max_segment_bytes or segment_event_count >= self.max_segment_events:
            self.close_segment(segment)
        return segment

    def _segment_records(self, segment: Path) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for framed in segment.read_bytes().splitlines(keepends=True):
            if not framed.endswith(b"\n"):
                raise GraphError(JOURNAL_CORRUPT, "Cannot summarize a partial segment.")
            value = strict_canonical_load(framed[:-1])
            if not isinstance(value, dict):
                raise GraphError(JOURNAL_CORRUPT, "Segment record is not an object.")
            records.append(value)
        return records

    def _segment_events(self, segment: Path) -> int:
        return sum(1 for record in self._segment_records(segment) if record["record_type"] == "batch.event")

    def close_segment(self, segment: Path) -> dict[str, Any]:
        manifest_path = self.manifests_dir / f"{segment.stem}.manifest.json"
        if manifest_path.exists():
            return cast(dict[str, Any], json.loads(manifest_path.read_text(encoding="utf-8")))
        records = self._segment_records(segment)
        events = [record["event"] for record in records if record["record_type"] == "batch.event"]
        commits = [record for record in records if record["record_type"] == "batch.commit"]
        begins = [record for record in records if record["record_type"] == "batch.begin"]
        if not events or len(begins) != len(commits):
            raise GraphError(JOURNAL_CORRUPT, "Only complete nonempty segments can be closed.")
        previous_paths = sorted(self.manifests_dir.glob("*.manifest.json"))
        previous_hash = None
        if previous_paths:
            previous = json.loads(previous_paths[-1].read_text(encoding="utf-8"))
            previous_hash = previous["integrity"]["content_hash"]
        created_at = begins[0]["created_at"]
        value: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "journal_format_version": JOURNAL_FORMAT_VERSION,
            "segment_id": new_id("seg"),
            "segment_name": segment.name,
            "stream": self.stream,
            "first_seq": events[0]["seq"],
            "last_seq": events[-1]["seq"],
            "first_event_hash": events[0]["event_hash"],
            "last_event_hash": events[-1]["event_hash"],
            "first_commit_hash": commits[0]["commit_hash"],
            "last_commit_hash": commits[-1]["commit_hash"],
            "previous_manifest_hash": previous_hash,
            "event_count": len(events),
            "batch_count": len(commits),
            "byte_size": segment.stat().st_size,
            "file_hash": file_hash(segment),
            "merkle_root": merkle_root([event["event_hash"] for event in events]),
            "backup_state": "pending",
            "created_at": created_at,
            "closed_at": utc_now(),
            "integrity": {
                "algorithm": "sha256",
                "canonicalization": "rfc8785",
                "content_hash": "sha256:" + "0" * 64,
                "excluded_fields": ["integrity.content_hash"],
            },
        }
        value["integrity"]["content_hash"] = object_hash(value)
        validate_contract("segment-manifest", value)
        atomic_write(
            manifest_path,
            canonical_line(value),
            fault_hook=self.fault_hook,
            fault_prefix="manifest",
        )
        self._verify_manifest(segment, manifest_path)
        return value

    def _verify_manifest(self, segment: Path, manifest_path: Path) -> None:
        try:
            raw = manifest_path.read_bytes()
            value = strict_canonical_load(raw[:-1] if raw.endswith(b"\n") else raw)
            validate_contract("segment-manifest", value)
        except (OSError, ValueError, ContractValidationError) as error:
            raise GraphError(JOURNAL_CORRUPT, "Closed segment manifest is invalid.") from error
        if value["segment_name"] != segment.name:
            raise GraphError(JOURNAL_CORRUPT, "Segment manifest names another segment.")
        records = self._segment_records(segment)
        events = [record["event"] for record in records if record["record_type"] == "batch.event"]
        commits = [record for record in records if record["record_type"] == "batch.commit"]
        checks = {
            "byte_size": segment.stat().st_size,
            "file_hash": file_hash(segment),
            "event_count": len(events),
            "batch_count": len(commits),
            "first_seq": events[0]["seq"],
            "last_seq": events[-1]["seq"],
            "first_event_hash": events[0]["event_hash"],
            "last_event_hash": events[-1]["event_hash"],
            "first_commit_hash": commits[0]["commit_hash"],
            "last_commit_hash": commits[-1]["commit_hash"],
            "merkle_root": merkle_root([event["event_hash"] for event in events]),
        }
        if any(value[key] != expected for key, expected in checks.items()):
            raise GraphError(JOURNAL_CORRUPT, "Closed segment manifest does not match segment bytes.")

    def backup_closed(self) -> list[dict[str, Any]]:
        receipts: list[dict[str, Any]] = []
        for manifest_path in sorted(self.manifests_dir.glob("*.manifest.json")):
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            segment = self.events_dir / value["segment_name"]
            target_segment = self.backups_dir / segment.name
            target_manifest = self.backups_dir / manifest_path.name
            for source, target in ((segment, target_segment), (manifest_path, target_manifest)):
                temporary = target.with_suffix(target.suffix + ".tmp")
                shutil.copyfile(source, temporary)
                # Windows rejects FlushFileBuffers through a read-only handle;
                # an update handle preserves the bytes and is portable to ext4.
                with temporary.open("r+b") as stream:
                    os.fsync(stream.fileno())
                os.replace(temporary, target)
                fsync_directory(target.parent)
                if file_hash(source) != file_hash(target):
                    raise GraphError(JOURNAL_CORRUPT, "Closed-segment backup verification failed.")
            receipt = {
                "schema_version": SCHEMA_VERSION,
                "segment_name": segment.name,
                "segment_hash": file_hash(segment),
                "manifest_hash": file_hash(manifest_path),
                "verified_at": utc_now(),
            }
            atomic_write(
                self.backups_dir / f"{segment.stem}.backup-receipt.json",
                canonical_line(receipt),
            )
            receipts.append(receipt)
        return receipts
