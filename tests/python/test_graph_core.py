from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from ayran.graph import (
    AppendCommand,
    AppendItem,
    GraphError,
    GraphStore,
    LearningNamespace,
    TargetNamespace,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "fixtures" / "contracts"

RUN_ID = "run_01J00000000000000000000001"
TARGET_ID = "tgt_01J00000000000000000000001"
TARGET_KEY = "sha256:" + "a" * 64
TARGET_IDENTITY = {
    "target_id": TARGET_ID,
    "source_tree_hash": "sha256:" + "d" * 64,
    "scope_id": "scp_01J00000000000000000000001",
    "commit": "1" * 40,
}
STREAM_ID = "str_01J00000000000000000000001"
ACTOR = {"kind": "service", "id": "ayran.fixture", "version": "1.0.0"}
CONFIG_HASH = "sha256:" + "e" * 64
CREATED_AT = "2026-08-12T12:00:00Z"

NODE_A = "nod_01J00000000000000000000001"
NODE_B = "nod_01J00000000000000000000002"
EDGE_AB = "edg_01J00000000000000000000001"
ASSERTION_A = "ast_01J00000000000000000000001"

_ID_FIELDS = {
    "graph-node": "node_id",
    "graph-edge": "edge_id",
    "graph-assertion": "assertion_id",
}


def _fixture(relative: str) -> dict[str, Any]:
    value = json.loads((FIXTURE_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return copy.deepcopy(value)


def _node(node_id: str, canonical_key: str, title: str) -> dict[str, Any]:
    value = _fixture("graph-node/valid/full.json")
    value["node_id"] = node_id
    value["source_locator"] = f"target/src/{canonical_key}.sol:1"
    value["properties"] = [
        {"name": "canonical_key", "value_type": "string", "value": canonical_key},
        {"name": "title", "value_type": "string", "value": title},
        {"name": "summary", "value_type": "string", "value": f"{title} asset accounting"},
        {"name": "tags", "value_type": "string", "value": f"{canonical_key} accounting"},
    ]
    value.pop("integrity")
    return value


def _edge(source_id: str, target_id: str) -> dict[str, Any]:
    value = _fixture("graph-edge/valid/minimal.json")
    value["edge_id"] = EDGE_AB
    value["source_id"] = source_id
    value["target_id"] = target_id
    value.pop("integrity")
    return value


def _assertion(subject_id: str, object_id: str) -> dict[str, Any]:
    value = _fixture("graph-assertion/valid/minimal.json")
    value["assertion_id"] = ASSERTION_A
    value["subject_id"] = subject_id
    value["object_value"] = object_id
    value.pop("integrity")
    return value


def _object_id(item: AppendItem) -> str:
    contract = item.contract_id.rsplit("@", 1)[0]
    return str(item.value[_ID_FIELDS[contract]])


def _command(
    idempotency_key: str,
    items: tuple[AppendItem, ...],
    expected_revisions: dict[str, int] | None = None,
) -> AppendCommand:
    return AppendCommand(
        idempotency_key=idempotency_key,
        items=items,
        expected_revisions=expected_revisions
        if expected_revisions is not None
        else {_object_id(item): 0 for item in items},
        actor=ACTOR,
        config_hash=CONFIG_HASH,
        source_version="fixture-v1",
        operation_id="op_01J00000000000000000000001",
        created_at=CREATED_AT,
    )


@pytest.fixture
def target_store(tmp_path: Path) -> Iterator[GraphStore]:
    namespace = TargetNamespace(
        tmp_path,
        RUN_ID,
        TARGET_IDENTITY,
        TARGET_KEY,
        stream_id=STREAM_ID,
        # tmp_path is a Windows unit-test directory; durability tests must use WSL ext4.
        allow_unsafe_filesystem=True,
    )
    store = GraphStore(
        namespace.root,
        namespace.stream,
        allow_unsafe_filesystem=True,
    )
    try:
        yield store
    finally:
        store.close()


def test_append_projects_same_batch_references_provenance_and_query_apis(
    target_store: GraphStore,
) -> None:
    node_a = AppendItem("graph-node@1.0.0", "node.created", _node(NODE_A, "vault", "Vault"))
    node_b = AppendItem(
        "graph-node@1.0.0", "node.created", _node(NODE_B, "strategy", "Strategy")
    )
    edge = AppendItem("graph-edge@1.0.0", "edge.created", _edge(NODE_A, NODE_B))
    assertion = AppendItem(
        "graph-assertion@1.0.0", "assertion.added", _assertion(NODE_A, NODE_B)
    )

    acknowledgement = target_store.append(
        _command("core.batch.references", (node_a, node_b, edge, assertion))
    )

    assert acknowledgement["first_seq"] == 1
    assert acknowledgement["last_seq"] == 4
    assert len(acknowledgement["event_ids"]) == 4

    entity = target_store.queries.get_entity(NODE_A)
    assert entity["query_name"] == "entity.get"
    assert entity["records"][0]["value"]["namespace"] == "target"
    assert entity["records"][0]["value"]["run_id"] == RUN_ID
    assert entity["records"][0]["provenance"][0]["source_uri"] == "https://fixtures.ayran.dev/m0"

    resolved = target_store.queries.resolve_node("Contract", "vault")
    assert [record["object_id"] for record in resolved["records"]] == [NODE_A]

    revisions = target_store.queries.revisions(NODE_A, active_only=True)
    assert [record["revision"] for record in revisions["records"]] == [1]

    outgoing = target_store.queries.traverse(NODE_A, edge_types=("CALLS",))
    assert [record["object_id"] for record in outgoing["records"]] == [EDGE_AB]

    neighborhood = target_store.queries.neighborhood(NODE_A, hops=2)
    assert {record["object_id"] for record in neighborhood["records"]} == {EDGE_AB}

    assertions = target_store.queries.assertions(subject_id=NODE_A, predicate="has.asset.flow")
    assert [record["object_id"] for record in assertions["records"]] == [ASSERTION_A]

    provenance = target_store.queries.provenance(NODE_A)
    assert provenance["records"][0]["provenance"]["raw_hash"] == "sha256:" + "b" * 64

    search = target_store.queries.fts("vault")
    assert [record["object_id"] for record in search["records"]] == [NODE_A]

    status = target_store.queries.status()
    assert status["records"][0]["journal_projection_cursor"] == 4
    assert status["records"][0]["projection_integrity"] == "ok"
    assert target_store.verify()["status"] == "ok"


def test_expected_revision_conflict_preserves_state_and_accepts_the_current_revision(
    target_store: GraphStore,
) -> None:
    initial = AppendItem("graph-node@1.0.0", "node.created", _node(NODE_A, "vault", "Vault"))
    target_store.append(_command("core.revision.initial", (initial,)))

    revised_value = _node(NODE_A, "vault", "Vault revised")
    stale = AppendItem("graph-node@1.0.0", "node.revised", revised_value)
    with pytest.raises(GraphError) as error:
        target_store.append(_command("core.revision.stale", (stale,), {NODE_A: 0}))
    assert error.value.code == "CONFLICT_REVISION"
    assert target_store.queries.status()["records"][0]["journal_projection_cursor"] == 1

    acknowledgement = target_store.append(
        _command("core.revision.current", (stale,), {NODE_A: 1})
    )
    assert acknowledgement["last_seq"] == 2
    revisions = target_store.queries.revisions(NODE_A)
    assert {record["revision"] for record in revisions["records"]} == {1, 2}
    active = target_store.queries.revisions(NODE_A, active_only=True)
    assert [record["revision"] for record in active["records"]] == [2]


def test_idempotency_returns_the_original_acknowledgement_and_rejects_collisions(
    target_store: GraphStore,
) -> None:
    item = AppendItem("graph-node@1.0.0", "node.created", _node(NODE_A, "vault", "Vault"))
    command = _command("core.idempotency", (item,))

    first = target_store.append(command)
    replay = target_store.append(command)
    assert replay["idempotent_replay"] is True
    assert replay["event_ids"] == first["event_ids"]
    assert replay["event_hashes"] == first["event_hashes"]
    assert target_store.queries.status()["records"][0]["journal_projection_cursor"] == 1

    changed = AppendItem(
        "graph-node@1.0.0", "node.created", _node(NODE_A, "vault", "Different vault")
    )
    with pytest.raises(GraphError) as error:
        target_store.append(_command("core.idempotency", (changed,)))
    assert error.value.code == "IDEMPOTENCY_COLLISION"
    assert target_store.queries.status()["records"][0]["journal_projection_cursor"] == 1


def test_retraction_and_tombstone_preserve_history_and_expose_their_current_state(
    target_store: GraphStore,
) -> None:
    node = AppendItem("graph-node@1.0.0", "node.created", _node(NODE_A, "vault", "Vault"))
    assertion = AppendItem(
        "graph-assertion@1.0.0", "assertion.added", _assertion(NODE_A, NODE_B)
    )
    target_store.append(_command("core.history.initial", (node, assertion)))

    retracted = AppendItem(
        "graph-assertion@1.0.0",
        "assertion.retracted",
        _assertion(NODE_A, NODE_B),
        transition="retraction",
        reason="fixture contradiction",
        supersedes=(ASSERTION_A,),
    )
    target_store.append(_command("core.history.retract", (retracted,), {ASSERTION_A: 1}))

    tombstoned_value = _node(NODE_A, "vault", "Vault")
    tombstoned_value["status"] = "tombstoned"
    tombstoned = AppendItem(
        "graph-node@1.0.0",
        "entity.tombstoned",
        tombstoned_value,
        transition="tombstone",
        reason="fixture removal",
    )
    target_store.append(_command("core.history.tombstone", (tombstoned,), {NODE_A: 1}))

    assertion_history = target_store.queries.assertions(
        subject_id=NODE_A, predicate="has.asset.flow", historical=True
    )
    assert {record["revision"] for record in assertion_history["records"]} == {1, 2}
    current_assertion = target_store.queries.assertions(
        subject_id=NODE_A, predicate="has.asset.flow"
    )
    assert [record["revision"] for record in current_assertion["records"]] == [2]

    node_history = target_store.queries.revisions(NODE_A)
    assert {record["revision"] for record in node_history["records"]} == {1, 2}
    tombstones = target_store.queries.tombstones(NODE_A)
    assert tombstones["records"][0]["reason"] == "fixture removal"
    assert tombstones["records"][0]["revision"] == 2
    assert target_store.verify()["verified_events"] == 4


def test_target_store_binds_values_to_its_namespace_and_learning_cannot_promote(
    target_store: GraphStore, tmp_path: Path
) -> None:
    crafted = _node(NODE_A, "vault", "Vault")
    crafted["namespace"] = "global"
    crafted["run_id"] = None

    acknowledgement = target_store.append(
        _command("core.namespace.binding", (AppendItem("graph-node@1.0.0", "node.created", crafted),))
    )
    assert acknowledgement["stream"]["namespace"] == "target"
    stored = target_store.queries.get_entity(NODE_A)["records"][0]["value"]
    assert stored["namespace"] == "target"
    assert stored["run_id"] == RUN_ID

    learning = LearningNamespace(
        tmp_path,
        "lrn_01J00000000000000000000001",
        origin_run_id=RUN_ID,
        origin_target_key=TARGET_KEY,
        stream_id="str_01J00000000000000000000002",
        allow_unsafe_filesystem=True,
    )
    with pytest.raises(GraphError) as error:
        learning.promote()
    assert error.value.code == "NAMESPACE_MISMATCH"


def test_rebuild_preserves_logical_and_query_digests(target_store: GraphStore) -> None:
    node_a = AppendItem("graph-node@1.0.0", "node.created", _node(NODE_A, "vault", "Vault"))
    node_b = AppendItem(
        "graph-node@1.0.0", "node.created", _node(NODE_B, "strategy", "Strategy")
    )
    edge = AppendItem("graph-edge@1.0.0", "edge.created", _edge(NODE_A, NODE_B))
    target_store.append(_command("core.rebuild.seed", (node_a, node_b, edge)))

    before_report = target_store.verify()
    before_query = target_store.queries.neighborhood(NODE_A, hops=2)
    rebuilt = target_store.rebuild()
    after_report = target_store.verify()
    after_query = target_store.queries.neighborhood(NODE_A, hops=2)

    assert rebuilt["previous_projection"] == "projection-000001.sqlite3"
    assert rebuilt["projection"] == "projection-000002.sqlite3"
    assert rebuilt["logical_digest"] == before_report["query_digest"]
    assert after_report["query_digest"] == before_report["query_digest"]
    assert after_query["query_digest"] == before_query["query_digest"]
    assert after_report["status"] == "ok"
