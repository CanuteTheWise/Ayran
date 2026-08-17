"""Shared M0 envelope helpers for M5 cognitive objects."""

from __future__ import annotations

from typing import Any

from ayran.context.ids import ZERO_HASH, content_id
from ayran.graph.canonical import object_hash

ACTOR_ROUTER = {"kind": "router", "id": "ayran.router", "version": "1.0.0"}
ACTOR_SERVICE = {"kind": "service", "id": "ayran.context", "version": "1.0.0"}
ACTOR_MODEL = {"kind": "model", "id": "ayran.driver.model_native", "version": "1.0.0"}
SOURCE_URI = "urn:ayran:m5:cognitive"


def integrity_placeholder() -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "canonicalization": "rfc8785",
        "content_hash": ZERO_HASH,
        "excluded_fields": ["integrity.content_hash"],
    }


def provenance_record(
    *,
    created_at: str,
    raw_hash: str = ZERO_HASH,
    source_uri: str = SOURCE_URI,
    source_version: str = "1.0.0",
    material: str = "m5",
) -> dict[str, Any]:
    return {
        "provenance_id": content_id("prv", material, created_at, source_uri),
        "source_uri": source_uri,
        "source_version": source_version,
        "raw_hash": raw_hash if raw_hash.startswith("sha256:") else ZERO_HASH,
        "retrieved_at": created_at,
        "license_or_terms": "ayran-internal-projection",
        "transformation_lineage": [],
    }


def default_target_identity() -> dict[str, Any]:
    return {
        "target_id": "tgt_01J00000000000000000000001",
        "source_tree_hash": "sha256:" + "d" * 64,
        "scope_id": "scp_01J00000000000000000000001",
        "commit": "1" * 40,
    }


def seal(value: dict[str, Any]) -> dict[str, Any]:
    value["integrity"] = integrity_placeholder()
    value["integrity"]["content_hash"] = object_hash(value)
    return value


def typed_property(name: str, value: str | int | float | bool | None, value_type: str = "string") -> dict[str, Any]:
    return {"name": name, "value_type": value_type, "value": value}


def graph_node(
    *,
    node_id: str,
    node_type: str,
    run_id: str,
    created_at: str,
    source_locator: str,
    properties: list[dict[str, Any]],
    trust_class: str = "deterministic_tool",
    evidence_grade: str = "lead",
    namespace: str = "target",
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "1.0.0",
        "node_id": node_id,
        "created_at": created_at,
        "run_id": run_id,
        "namespace": namespace,
        "node_type": node_type,
        "revision": 1,
        "status": "active",
        "properties": properties,
        "trust_class": trust_class,
        "confidence": 1.0,
        "evidence_grade": evidence_grade,
        "evidence_refs": [],
        "source_locator": source_locator[:512],
        "valid_from_event": content_id("evt", node_id, "created"),
        "valid_to_event": None,
        "provenance": [provenance_record(created_at=created_at, material=node_id)],
        "integrity": integrity_placeholder(),
    }
    return value


def graph_edge(
    *,
    edge_id: str,
    edge_type: str,
    source_id: str,
    target_id: str,
    run_id: str,
    created_at: str,
    source_locator: str,
    properties: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "edge_id": edge_id,
        "created_at": created_at,
        "run_id": run_id,
        "namespace": "target",
        "edge_type": edge_type,
        "source_id": source_id,
        "target_id": target_id,
        "revision": 1,
        "status": "active",
        "properties": properties or [],
        "trust_class": "deterministic_tool",
        "confidence": 1.0,
        "evidence_grade": "lead",
        "evidence_refs": [],
        "source_locator": source_locator[:512],
        "valid_from_event": content_id("evt", edge_id, "created"),
        "valid_to_event": None,
        "provenance": [provenance_record(created_at=created_at, material=edge_id)],
        "integrity": integrity_placeholder(),
    }
