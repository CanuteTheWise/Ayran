"""Append lifecycle and RLM child records to the Target journal via GraphStore."""

from __future__ import annotations

import json
import re
from typing import Any

from ayran.graph.canonical import canonical_hash, utc_now
from ayran.graph.ids import new_id
from ayran.graph.recovery import GraphStore
from ayran.graph.types import AppendCommand, AppendItem

ACTOR = {"kind": "service", "id": "ayran.bridge", "version": "1.0.0"}
SOURCE_VERSION = "1.0.0"
CONFIG_HASH = "sha256:" + "e" * 64
_IDEMPOTENCY = re.compile(r"[^A-Za-z0-9_.:-]+")


def _idempotency_key(value: str) -> str:
    cleaned = _IDEMPOTENCY.sub("-", value).strip("-")
    if not cleaned:
        cleaned = "lifecycle.event"
    if not cleaned[0].isalnum():
        cleaned = f"k{cleaned}"
    return cleaned[:256]


def _string_props(values: dict[str, str]) -> list[dict[str, Any]]:
    properties: list[dict[str, Any]] = []
    for name, value in values.items():
        clipped = value[:2048]
        properties.append({"name": name, "value_type": "string", "value": clipped})
    return properties


def append_lifecycle_node(
    store: GraphStore,
    *,
    run_id: str,
    node_type: str,
    properties: dict[str, str],
    source_locator: str,
    idempotency_key: str,
) -> dict[str, Any]:
    """Write one graph-node snapshot for a Prime lifecycle or child event."""

    node_id = new_id("nod")
    created = utc_now()
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "node_id": node_id,
        "created_at": created,
        "run_id": run_id,
        "namespace": "target",
        "node_type": node_type,
        "revision": 1,
        "status": "active",
        "properties": _string_props(properties),
        "trust_class": "runtime_observation",
        "confidence": 1.0,
        "evidence_grade": "lead",
        "evidence_refs": [],
        "source_locator": source_locator[:512],
        "valid_from_event": new_id("evt"),
        "provenance": [
            {
                "provenance_id": new_id("prv"),
                "source_uri": "urn:ayran:prime-lifecycle",
                "source_version": SOURCE_VERSION,
                "raw_hash": canonical_hash(properties),
                "retrieved_at": created,
                "license_or_terms": "ayran-internal-lifecycle",
                "transformation_lineage": [],
            }
        ],
    }
    command = AppendCommand(
        _idempotency_key(idempotency_key),
        (AppendItem("graph-node@1.0.0", "node.created", value),),
        {node_id: 0},
        ACTOR,
        CONFIG_HASH,
        SOURCE_VERSION,
        created_at=created,
    )
    acknowledgement = store.append(command)
    return {
        "schema_version": "1.0.0",
        "node_id": node_id,
        "node_type": node_type,
        "acknowledgement": acknowledgement,
    }


def record_session_event(
    store: GraphStore,
    *,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    digest = canonical_hash(payload)
    node_type = "CompactionEvent" if "compact" in event_type else "SessionTransition"
    return append_lifecycle_node(
        store,
        run_id=run_id,
        node_type=node_type,
        properties={
            "event_type": event_type[:128],
            "payload_hash": digest,
            "payload_json": json.dumps(payload, separators=(",", ":"), ensure_ascii=True)[:2048],
        },
        source_locator=f"prime://lifecycle/{event_type}",
        idempotency_key=f"lifecycle:{event_type}:{digest}",
    )


def record_child(
    store: GraphStore,
    *,
    run_id: str,
    status: str,
    handle: dict[str, Any],
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    child_id = str(handle.get("rlm_child_id") or handle.get("child_id") or new_id("chd"))
    properties = {
        "status": status[:128],
        "rlm_child_id": child_id[:128],
        "name": str(handle.get("name") or "")[:128],
        "session_dir": str(handle.get("session_dir") or "")[:512],
        "model": str(handle.get("model") or "")[:128],
        "result_hash": canonical_hash(result or {}),
        "error": (error or "")[:512],
    }
    return append_lifecycle_node(
        store,
        run_id=run_id,
        node_type="ChildRunRecord",
        properties=properties,
        source_locator=f"prime://rlm/{child_id}",
        idempotency_key=f"child:{child_id}:{status}:{properties['result_hash']}",
    )
