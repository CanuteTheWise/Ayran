"""Pure command fingerprinting and journal-v1 batch construction."""

from __future__ import annotations

import copy
from typing import Any, cast

from ayran.api.validators import ContractValidationError, validate_contract

from .canonical import (
    canonical_hash,
    commit_hash,
    members_hash,
    object_hash,
    require_canonical_timestamps,
    utc_now,
)
from .errors import CONFLICT_REVISION, CONTRACT_INVALID, GraphError
from .ids import new_id
from .journal import SCHEMA_VERSION, contract_name, object_id_for, validate_body
from .types import AppendCommand

ZERO_HASH = "sha256:" + "0" * 64


def _integrity(*, event: bool = False) -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": ZERO_HASH,
        "excluded_fields": ["integrity.content_hash", "event_hash"]
        if event
        else ["integrity.content_hash"],
    }


def command_request_hash(command: AppendCommand, stream: dict[str, Any]) -> str:
    if not command.items:
        raise GraphError(CONTRACT_INVALID, "A graph command must contain at least one event.")
    semantic = {
        "domain": "ayran.graph.command.v1",
        "stream": stream,
        "operation_id": command.operation_id,
        "causation_id": command.causation_id,
        "idempotency_key": command.idempotency_key,
        "expected_revisions": [
            {"aggregate_id": key, "revision": command.expected_revisions[key]}
            for key in sorted(command.expected_revisions)
        ],
        "actor": command.actor,
        "config_hash": command.config_hash,
        "source_version": command.source_version,
        "created_at": command.created_at,
        "items": [
            {
                "contract_id": item.contract_id,
                "event_type": item.event_type,
                "aggregate_id": item.aggregate_id,
                "value": item.value,
                "transition": item.transition,
                "reason": item.reason,
                "supersedes": list(item.supersedes),
            }
            for item in command.items
        ],
    }
    require_canonical_timestamps(semantic)
    return canonical_hash(semantic)


def _prepare_value(
    contract: str,
    source: dict[str, Any],
    stream: dict[str, Any],
    event_id: str,
    aggregate_version: int,
) -> dict[str, Any]:
    value = copy.deepcopy(source)
    supplied_integrity = value.get("integrity")
    if isinstance(supplied_integrity, dict):
        supplied_hash = supplied_integrity.get("content_hash")
        if supplied_hash not in {None, ZERO_HASH} and supplied_hash != object_hash(value):
            raise GraphError(CONTRACT_INVALID, "Caller-supplied graph object hash is invalid.")
    value["integrity"] = _integrity()
    if contract in {"graph-node", "graph-edge", "graph-assertion"}:
        value["valid_from_event"] = event_id
        value["namespace"] = stream["namespace"]
        value["run_id"] = stream.get("run_id")
    if contract in {"graph-node", "graph-edge"}:
        value["revision"] = aggregate_version
    value["integrity"]["content_hash"] = object_hash(value)
    require_canonical_timestamps(value)
    return value


def build_batch(
    command: AppendCommand,
    stream: dict[str, Any],
    *,
    cursor: int,
    last_event_hash: str | None,
    last_commit_hash: str | None,
    current_revisions: dict[str, int],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Build and validate a complete batch without performing I/O."""

    request_hash = command_request_hash(command, stream)
    created_at = command.created_at or utc_now()
    operation_id = command.operation_id or new_id("op")
    batch_id = new_id("bat")
    aggregate_ids: list[str] = []
    contract_names: list[str] = []
    for item in command.items:
        name = contract_name(item.contract_id)
        object_id = object_id_for(name, item.value)
        if item.aggregate_id is not None and item.aggregate_id != object_id:
            raise GraphError(CONTRACT_INVALID, "Command aggregate ID differs from object ID.")
        aggregate_ids.append(object_id)
        contract_names.append(name)
    if len(set(aggregate_ids)) != len(aggregate_ids):
        raise GraphError(CONTRACT_INVALID, "A v1 command batch may revise each aggregate only once.")
    if set(command.expected_revisions) != set(aggregate_ids):
        raise GraphError(CONTRACT_INVALID, "Expected revisions must name every batch aggregate exactly once.")
    for aggregate_id in aggregate_ids:
        current = current_revisions.get(aggregate_id, 0)
        expected = command.expected_revisions[aggregate_id]
        if expected != current:
            raise GraphError(
                CONFLICT_REVISION,
                "Aggregate revision precondition failed.",
                details={"aggregate_id": aggregate_id, "expected_revision": expected, "current_revision": current},
            )
    event_ids = [new_id("evt") for _ in command.items]
    events: list[dict[str, Any]] = []
    predecessor = last_event_hash
    for index, (item, name, aggregate_id, event_id) in enumerate(
        zip(command.items, contract_names, aggregate_ids, event_ids, strict=True), 1
    ):
        aggregate_version = current_revisions.get(aggregate_id, 0) + 1
        value = _prepare_value(name, item.value, stream, event_id, aggregate_version)
        body = {
            "contract_id": item.contract_id,
            "object_id": aggregate_id,
            "content_hash": value["integrity"]["content_hash"],
            "value": value,
            "transition": {
                "kind": item.transition,
                "reason": item.reason,
                "supersedes": list(item.supersedes),
            },
        }
        event: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "journal_format_version": 1,
            "event_id": event_id,
            "seq": cursor + index,
            "stream": copy.deepcopy(stream),
            "batch_id": batch_id,
            "ordinal": index,
            "aggregate_id": aggregate_id,
            "aggregate_version": aggregate_version,
            "event_type": item.event_type,
            "actor": copy.deepcopy(command.actor),
            "operation_id": operation_id,
            "causation_id": command.causation_id,
            "created_at": created_at,
            "provenance": copy.deepcopy(value["provenance"]),
            "integrity": _integrity(event=True),
            "config_hash": command.config_hash,
            "source_version": command.source_version,
            "idempotency_key": command.idempotency_key,
            "body": body,
            "previous_event_hash": predecessor,
            "event_hash": ZERO_HASH,
        }
        event["integrity"]["content_hash"] = object_hash(event)
        event["event_hash"] = object_hash(event)
        try:
            validate_contract("journal-event", event)
        except ContractValidationError as error:
            raise GraphError(CONTRACT_INVALID, "Constructed journal event is invalid.") from error
        # journal-event validation recursively validates the embedded durable
        # object. The semantic pass must not repeat the same JSON-Schema walk.
        validate_body(
            event,
            stream,
            same_batch_ids=set(aggregate_ids),
            content_hash_validated=True,
        )
        events.append(event)
        predecessor = event["event_hash"]
    expected_revisions = [
        {"aggregate_id": key, "revision": command.expected_revisions[key]}
        for key in sorted(command.expected_revisions)
    ]
    begin: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "journal_format_version": 1,
        "hash_domain": "ayran.journal.begin.v1",
        "record_type": "batch.begin",
        "stream": copy.deepcopy(stream),
        "batch_id": batch_id,
        "operation_id": operation_id,
        "causation_id": command.causation_id,
        "idempotency_key": command.idempotency_key,
        "request_hash": request_hash,
        "expected_revisions": expected_revisions,
        "first_seq": events[0]["seq"],
        "event_count": len(events),
        "previous_event_hash": last_event_hash,
        "previous_commit_hash": last_commit_hash,
        "created_at": created_at,
    }
    hashes = [cast(str, event["event_hash"]) for event in events]
    commit: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "journal_format_version": 1,
        "hash_domain": "ayran.journal.commit.v1",
        "record_type": "batch.commit",
        "stream": copy.deepcopy(stream),
        "batch_id": batch_id,
        "event_count": len(events),
        "first_seq": events[0]["seq"],
        "last_seq": events[-1]["seq"],
        "first_event_hash": hashes[0],
        "last_event_hash": hashes[-1],
        "begin_hash": canonical_hash(begin),
        "members_hash": members_hash(hashes),
        "previous_commit_hash": last_commit_hash,
        "committed_at": created_at,
        "commit_hash": ZERO_HASH,
    }
    commit["commit_hash"] = commit_hash(commit)
    acknowledgement = {
        "schema_version": SCHEMA_VERSION,
        "journal_format_version": 1,
        "stream": copy.deepcopy(stream),
        "batch_id": batch_id,
        "operation_id": operation_id,
        "idempotency_key": command.idempotency_key,
        "request_hash": request_hash,
        "first_seq": events[0]["seq"],
        "last_seq": events[-1]["seq"],
        "event_ids": event_ids,
        "event_hashes": hashes,
        "commit_hash": commit["commit_hash"],
        "projection_cursor": events[-1]["seq"],
        "projection_event_hash": hashes[-1],
        "idempotent_replay": False,
    }
    validate_contract("journal-record", begin)
    validate_contract("journal-record", commit)
    validate_contract("graph-acknowledgement", acknowledgement)
    return begin, events, commit, acknowledgement


def acknowledgement_for_replay(
    begin: dict[str, Any], events: list[dict[str, Any]], commit: dict[str, Any]
) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSION,
        "journal_format_version": 1,
        "stream": copy.deepcopy(begin["stream"]),
        "batch_id": begin["batch_id"],
        "operation_id": begin["operation_id"],
        "idempotency_key": begin["idempotency_key"],
        "request_hash": begin["request_hash"],
        "first_seq": events[0]["seq"],
        "last_seq": events[-1]["seq"],
        "event_ids": [event["event_id"] for event in events],
        "event_hashes": [event["event_hash"] for event in events],
        "commit_hash": commit["commit_hash"],
        "projection_cursor": events[-1]["seq"],
        "projection_event_hash": events[-1]["event_hash"],
        "idempotent_replay": False,
    }
    validate_contract("graph-acknowledgement", value)
    return value
