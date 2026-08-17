"""M7 corpus release determinism, pointer swap, tombstone, and queries."""

from __future__ import annotations

from pathlib import Path

from ayran.context.compiler import compile_from_view
from ayran.context.queries import OntologyQueries, snapshot_view
from ayran.knowledge.corpus import build_release, corpus_status, query_corpus
from ayran.knowledge.ingestion import ingest_source
from ayran.knowledge.persist import persist_records
from ayran.knowledge.service import ingest_runtime_sources, query_records, tombstone_source
from m5_fixtures import CLUSTER
from m7_fixtures import copy_knowledge, open_store


def test_release_manifest_is_deterministic(tmp_path: Path) -> None:
    first = copy_knowledge(tmp_path, "one")
    second = copy_knowledge(tmp_path, "two")
    ingest_runtime_sources(first)
    ingest_runtime_sources(second)
    a = build_release(first, version="v0.1.0")
    b = build_release(second, version="v0.1.0")
    assert a["content_hash"] == b["content_hash"]
    assert a["content_hash"].startswith("sha256:")
    assert a["record_counts"]
    assert a["sources"]
    again = build_release(first, version="v0.1.0")
    assert again["content_hash"] == a["content_hash"]
    status = corpus_status(first)
    assert status["current"]["release_id"] == a["release_id"]
    mechanisms = query_corpus(first, record_type="mechanism", filters={"language": "solidity"})
    assert mechanisms
    for record in mechanisms:
        assert record["source_ref"]["locator"]
        assert record["trust_tier"]
        assert record["license_info"]["spdx_id"]
        assert record["safe_for_execution"] is False


def test_tombstone_publishes_new_release_without_rewriting(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    ingest_runtime_sources(root)
    original = build_release(root, version="v0.1.0")
    result = tombstone_source(root, "krait", "quality removal", republish_version="v0.1.1")
    updated = result["release"]
    assert updated["content_hash"] != original["content_hash"]
    assert (root / "releases" / original["release_id"] / "manifest.json").is_file()
    leftover = query_corpus(root, record_type="method")
    assert all(item["source_ref"]["source_id"] != "krait" for item in leftover)
    status = query_records(root, record_type="reasoning_lens")
    assert status["count"] >= 1


def test_graph_queries_and_blind_aware_differ(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    ingest_source(root, "zeroskills")
    ingest_source(root, "solodit")
    ingest_source(root, "0xsimao")
    manifest = build_release(root, version="v0.1.0")
    store = open_store(tmp_path)
    try:
        from ayran.knowledge.corpus import load_release_records

        records = load_release_records(root, str(manifest["release_id"]))
        persist_records(store, records)
        queries = OntologyQueries(store=store)
        import asyncio

        mechanisms = asyncio.run(queries.search_mechanisms("storage", budget=5))
        assert mechanisms
        assert mechanisms[0]["historical_reference"] is True
        incidents = asyncio.run(queries.search_incidents(protocol_type="dao"))
        _ = incidents
        patterns = asyncio.run(queries.search_vulnerability_patterns(["vault"]))
        assert isinstance(patterns, list)
        tools = asyncio.run(queries.get_tool_capabilities())
        assert tools
        view = snapshot_view(queries, cluster_id=CLUSTER)
        assert view.global_mechanisms
        view.knowledge_policy = "knowledge_blind"
        blind = compile_from_view(view)
        view.knowledge_policy = "graph_aware"
        aware = compile_from_view(view)
        blind_labels = {section["classification"] for section in blind["sections"]}
        aware_labels = {section["classification"] for section in aware["sections"]}
        assert "HISTORICAL_REFERENCE" not in blind_labels
        assert "HISTORICAL_REFERENCE" in aware_labels
    finally:
        store.close()
