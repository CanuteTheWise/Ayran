"""Publish Global knowledge records through GraphStore.append only."""

from __future__ import annotations

from typing import Any

from ayran.api.validators import validate_contract
from ayran.context.contracts import graph_edge, graph_node, seal, typed_property
from ayran.context.ids import ZERO_HASH, content_id
from ayran.graph.recovery import GraphStore
from ayran.graph.types import AppendCommand, AppendItem
from ayran.knowledge.conflicts import ConflictGroup
from ayran.knowledge.models import NODE_TYPE_BY_RECORD, KnowledgeRecord
from ayran.knowledge.paths import PARSER_VERSION, PINNED_TIME

ACTOR_KNOWLEDGE = {"kind": "service", "id": "ayran.knowledge", "version": "1.0.0"}
CONFIG_HASH = ZERO_HASH
SOURCE_URI_PREFIX = "urn:ayran:knowledge"


def _prop(name: str, value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return typed_property(name, value, "boolean")
    if isinstance(value, int) and not isinstance(value, bool):
        return typed_property(name, value, "integer")
    if value is None:
        return typed_property(name, None, "string")
    if isinstance(value, list):
        return typed_property(name, ",".join(str(item) for item in value), "string")
    text = str(value)
    return typed_property(name, text[:512], "string")


def knowledge_node(record: KnowledgeRecord, *, run_id: str, created_at: str = PINNED_TIME) -> dict[str, Any]:
    node_type = NODE_TYPE_BY_RECORD.get(record.record_type, "GlobalRecord")
    node_id = content_id("nod", "global", record.record_id)
    properties = [
        _prop("title", record.title or record.record_id),
        _prop("summary", record.summary),
        _prop("canonical_key", record.canonical_key or record.record_id),
        _prop("record_id", record.record_id),
        _prop("record_type", record.record_type),
        _prop("mechanism", record.mechanism),
        _prop("language", record.language),
        _prop("protocol", record.protocol),
        _prop("component", record.component),
        _prop("trust_tier", record.trust_tier),
        _prop("source_id", record.source_ref.source_id),
        _prop("commit_or_version", record.commit_or_version),
        _prop("raw_hash", record.raw_hash),
        _prop("parser_version", record.parser_version or PARSER_VERSION),
        _prop("license", record.license_info.spdx_id),
        _prop("applicability_predicates", record.applicability_predicates),
        _prop("hard_negative", record.hard_negative),
        _prop("safe_for_retrieval", record.safe_for_retrieval),
        _prop("safe_for_execution", record.safe_for_execution),
        _prop("historical_reference", True),
        _prop("global_record", True),
        _prop("root_cause", record.root_cause),
        _prop("protocol_type", record.protocol),
        _prop("severity", None),
        _prop("payload", record.model_dump_json()),
    ]
    locator = record.source_ref.locator or f"knowledge:{record.source_ref.source_id}"
    node = graph_node(
        node_id=node_id,
        node_type=node_type,
        run_id=run_id,
        created_at=created_at,
        source_locator=locator[:512],
        properties=properties,
        trust_class="curated_external",
        evidence_grade="lead",
        namespace="target",
    )
    node["provenance"] = [
        {
            "provenance_id": content_id("prv", record.record_id, record.raw_hash),
            "source_uri": record.source_ref.origin or f"{SOURCE_URI_PREFIX}:{record.source_ref.source_id}",
            "source_version": record.commit_or_version or "curated-snapshot",
            "raw_hash": record.raw_hash if record.raw_hash.startswith("sha256:") else ZERO_HASH,
            "retrieved_at": created_at,
            "license_or_terms": record.license_info.spdx_id[:128],
            "extraction_locator": locator[:512],
            "parser_version": PARSER_VERSION,
            "transformation_lineage": [],
        }
    ]
    return node


def persist_record(store: GraphStore, record: KnowledgeRecord, *, created_at: str = PINNED_TIME) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    node = knowledge_node(record, run_id=run_id, created_at=created_at)
    sealed = seal(node)
    validate_contract("graph-node", sealed)
    identifier = str(sealed["node_id"])
    current = store.projection.aggregate_revision(identifier)
    event_type = "node.created" if current == 0 else "node.revised"
    command = AppendCommand(
        f"knowledge:{identifier}:{current + 1}",
        (AppendItem("graph-node@1.0.0", event_type, sealed),),
        {identifier: current},
        ACTOR_KNOWLEDGE,
        CONFIG_HASH,
        PARSER_VERSION,
        created_at=created_at,
    )
    return store.append(command)


def persist_conflict_group(
    store: GraphStore, group: ConflictGroup, *, created_at: str = PINNED_TIME
) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    node_id = content_id("nod", "conflict", group.group_id)
    node = graph_node(
        node_id=node_id,
        node_type="Contradiction",
        run_id=run_id,
        created_at=created_at,
        source_locator=f"conflict:{group.group_id}",
        properties=[
            typed_property("title", f"conflict:{group.kind}"),
            typed_property("kind", group.kind),
            typed_property("left", group.record_ids[0] if group.record_ids else ""),
            typed_property("right", group.record_ids[1] if len(group.record_ids) > 1 else ""),
            typed_property("reviewer_disposition", group.reviewer_disposition),
            typed_property("note", group.note),
        ],
        trust_class="curated_external",
        evidence_grade="lead",
    )
    sealed = seal(node)
    validate_contract("graph-node", sealed)
    current = store.projection.aggregate_revision(node_id)
    event_type = "node.created" if current == 0 else "node.revised"
    result = store.append(
        AppendCommand(
            f"conflict:{node_id}:{current + 1}",
            (AppendItem("graph-node@1.0.0", event_type, sealed),),
            {node_id: current},
            ACTOR_KNOWLEDGE,
            CONFIG_HASH,
            PARSER_VERSION,
            created_at=created_at,
        )
    )
    if len(group.record_ids) >= 2:
        left = content_id("nod", "global", group.record_ids[0])
        right = content_id("nod", "global", group.record_ids[1])
        edge_id = content_id("edg", "contradicts", left, right)
        if store.projection.aggregate_revision(edge_id) == 0:
            edge = graph_edge(
                edge_id=edge_id,
                edge_type="CONTRADICTS",
                source_id=left,
                target_id=right,
                run_id=run_id,
                created_at=created_at,
                source_locator=f"conflict:{group.group_id}",
            )
            sealed_edge = seal(edge)
            store.append(
                AppendCommand(
                    f"conflict-edge:{edge_id}",
                    (AppendItem("graph-edge@1.0.0", "edge.created", sealed_edge),),
                    {edge_id: 0},
                    ACTOR_KNOWLEDGE,
                    CONFIG_HASH,
                    PARSER_VERSION,
                    created_at=created_at,
                )
            )
    return result


def persist_variant_edge(
    store: GraphStore,
    *,
    source_record_id: str,
    target_record_id: str,
    edge_type: str,
    created_at: str = PINNED_TIME,
) -> dict[str, Any] | None:
    if edge_type not in {"VARIANT_OF", "LEARNED_FROM"}:
        return None
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    source_id = content_id("nod", "global", source_record_id)
    target_id = content_id("nod", "global", target_record_id)
    edge_id = content_id("edg", edge_type.lower(), source_id, target_id)
    if store.projection.aggregate_revision(source_id) == 0 or store.projection.aggregate_revision(target_id) == 0:
        return None
    if store.projection.aggregate_revision(edge_id):
        return None
    edge = graph_edge(
        edge_id=edge_id,
        edge_type=edge_type,
        source_id=source_id,
        target_id=target_id,
        run_id=run_id,
        created_at=created_at,
        source_locator=f"resolution:{source_record_id}",
    )
    sealed = seal(edge)
    return store.append(
        AppendCommand(
            f"knowledge-edge:{edge_id}",
            (AppendItem("graph-edge@1.0.0", "edge.created", sealed),),
            {edge_id: 0},
            ACTOR_KNOWLEDGE,
            CONFIG_HASH,
            PARSER_VERSION,
            created_at=created_at,
        )
    )


def persist_records(store: GraphStore, records: list[KnowledgeRecord]) -> dict[str, Any]:
    appended = 0
    for record in records:
        persist_record(store, record)
        appended += 1
        if record.variant_of:
            persist_variant_edge(
                store,
                source_record_id=record.record_id,
                target_record_id=record.variant_of,
                edge_type="VARIANT_OF",
            )
        if record.learned_from:
            persist_variant_edge(
                store,
                source_record_id=record.record_id,
                target_record_id=record.learned_from,
                edge_type="LEARNED_FROM",
            )
    return {"appended": appended}
