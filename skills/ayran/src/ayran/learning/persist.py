"""Publish Learning records through GraphStore.append only."""

from __future__ import annotations

import json
from typing import Any

from ayran.api.validators import validate_contract
from ayran.context.contracts import graph_node, seal, typed_property
from ayran.context.ids import ZERO_HASH, content_id
from ayran.graph.recovery import GraphStore
from ayran.graph.types import AppendCommand, AppendItem
from ayran.learning.models import (
    LearningCandidate,
    LearningOutcome,
    LearningReview,
    PromotionRelease,
    QuarantineRecord,
    RoutingPolicy,
)
from ayran.learning.paths import PARSER_VERSION, PINNED_TIME

ACTOR_LEARNING = {"kind": "service", "id": "ayran.learning", "version": "1.0.0"}
CONFIG_HASH = ZERO_HASH


def _prop(name: str, value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return typed_property(name, value, "boolean")
    if isinstance(value, int) and not isinstance(value, bool):
        return typed_property(name, value, "integer")
    if value is None:
        return typed_property(name, None, "string")
    if isinstance(value, list):
        return typed_property(name, ",".join(str(item) for item in value), "string")
    return typed_property(name, str(value), "string")


def _stream_namespace(store: GraphStore) -> str:
    namespace = str(store.stream.get("namespace") or "target")
    return namespace if namespace in {"target", "global", "learning"} else "target"


def _append_node(store: GraphStore, node: dict[str, Any], *, created_at: str) -> dict[str, Any]:
    identifier = str(node["node_id"])
    current = store.projection.aggregate_revision(identifier)
    if current:
        node["revision"] = current + 1
    sealed = seal(node)
    validate_contract("graph-node", sealed)
    event_type = "node.created" if current == 0 else "node.revised"
    command = AppendCommand(
        f"learning:{identifier}:{current + 1}",
        (AppendItem("graph-node@1.0.0", event_type, sealed),),
        {identifier: current},
        ACTOR_LEARNING,
        CONFIG_HASH,
        PARSER_VERSION,
        created_at=created_at,
    )
    return store.append(command)


def persist_outcome(
    store: GraphStore, outcome: LearningOutcome, *, created_at: str = PINNED_TIME
) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or outcome.run_id)
    record = outcome.model_dump(mode="json")
    node_id = content_id("nod", "learning", outcome.outcome_id)
    node = graph_node(
        node_id=node_id,
        node_type="LearningOutcome",
        run_id=run_id,
        created_at=created_at,
        source_locator=f"learning:outcome:{outcome.outcome_id}",
        properties=[
            _prop("outcome_id", outcome.outcome_id),
            _prop("run_id", outcome.run_id),
            _prop("outcome_type", outcome.outcome_type),
            _prop("hypothesis_id", outcome.hypothesis_id),
            _prop("promotion_stage", outcome.promotion_stage),
            _prop("content_hash", outcome.content_hash),
            _prop("record_json", json.dumps(record, separators=(",", ":"), ensure_ascii=True)),
        ],
        trust_class="adjudicated",
        evidence_grade="lead",
        namespace=_stream_namespace(store),
    )
    return _append_node(store, node, created_at=created_at)


def persist_candidate(
    store: GraphStore, candidate: LearningCandidate, *, created_at: str = PINNED_TIME
) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    record = candidate.model_dump(mode="json")
    node_id = content_id("nod", "learning", candidate.candidate_id)
    node = graph_node(
        node_id=node_id,
        node_type="LearningCandidate",
        run_id=run_id,
        created_at=created_at,
        source_locator=f"learning:candidate:{candidate.candidate_id}",
        properties=[
            _prop("candidate_id", candidate.candidate_id),
            _prop("outcome_ref", candidate.outcome_ref),
            _prop("promotion_stage", candidate.promotion_stage),
            _prop("trust_class", candidate.trust_class),
            _prop("record_json", json.dumps(record, separators=(",", ":"), ensure_ascii=True)),
        ],
        trust_class=candidate.trust_class
        if candidate.trust_class
        in {
            "deterministic_tool",
            "runtime_observation",
            "verified_source",
            "target_source_claim",
            "curated_external",
            "human_asserted",
            "adjudicated",
            "model_observation",
            "model_assumption",
        }
        else "model_observation",
        evidence_grade="lead",
        namespace=_stream_namespace(store),
    )
    return _append_node(store, node, created_at=created_at)


def persist_review(
    store: GraphStore, review: LearningReview, *, created_at: str = PINNED_TIME
) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    record = review.model_dump(mode="json")
    node_id = content_id("nod", "learning", review.review_id)
    node = graph_node(
        node_id=node_id,
        node_type="LearningReview",
        run_id=run_id,
        created_at=created_at,
        source_locator=f"learning:review:{review.review_id}",
        properties=[
            _prop("review_id", review.review_id),
            _prop("candidate_id", review.candidate_id),
            _prop("reviewer_id", review.reviewer_id),
            _prop("verdict", review.verdict),
            _prop("record_json", json.dumps(record, separators=(",", ":"), ensure_ascii=True)),
        ],
        trust_class="human_asserted",
        evidence_grade="lead",
        namespace=_stream_namespace(store),
    )
    return _append_node(store, node, created_at=created_at)


def persist_quarantine(
    store: GraphStore, record: QuarantineRecord, *, created_at: str = PINNED_TIME
) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    payload = record.model_dump(mode="json")
    node_id = content_id("nod", "learning", record.quarantine_id)
    node = graph_node(
        node_id=node_id,
        node_type="QuarantineRecord",
        run_id=run_id,
        created_at=created_at,
        source_locator=f"learning:quarantine:{record.quarantine_id}",
        properties=[
            _prop("quarantine_id", record.quarantine_id),
            _prop("subject_id", record.subject_id),
            _prop("reason", record.reason),
            _prop("record_json", json.dumps(payload, separators=(",", ":"), ensure_ascii=True)),
        ],
        trust_class="adjudicated",
        evidence_grade="lead",
        namespace=_stream_namespace(store),
    )
    return _append_node(store, node, created_at=created_at)


def persist_promotion(
    store: GraphStore, release: PromotionRelease, *, created_at: str = PINNED_TIME
) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    payload = release.model_dump(mode="json")
    node_id = content_id("nod", "learning", release.release_id)
    node = graph_node(
        node_id=node_id,
        node_type="LearningPromotion",
        run_id=run_id,
        created_at=created_at,
        source_locator=f"learning:release:{release.release_id}",
        properties=[
            _prop("release_id", release.release_id),
            _prop("prior_pointer", release.prior_pointer),
            _prop("rollback_pointer", release.rollback_pointer),
            _prop("record_json", json.dumps(payload, separators=(",", ":"), ensure_ascii=True)),
        ],
        trust_class="adjudicated",
        evidence_grade="lead",
        namespace=_stream_namespace(store),
    )
    return _append_node(store, node, created_at=created_at)


def persist_routing_policy(
    store: GraphStore, policy: RoutingPolicy, *, created_at: str = PINNED_TIME
) -> dict[str, Any]:
    run_id = str(store.stream.get("run_id") or "run_01J00000000000000000000001")
    payload = policy.model_dump(mode="json")
    node_id = content_id("nod", "learning", policy.policy_id)
    node = graph_node(
        node_id=node_id,
        node_type="RoutingPolicy",
        run_id=run_id,
        created_at=created_at,
        source_locator=f"learning:routing:{policy.policy_id}",
        properties=[
            _prop("policy_id", policy.policy_id),
            _prop("status", policy.status),
            _prop("record_json", json.dumps(payload, separators=(",", ":"), ensure_ascii=True)),
        ],
        trust_class="adjudicated",
        evidence_grade="lead",
        namespace=_stream_namespace(store),
    )
    return _append_node(store, node, created_at=created_at)
