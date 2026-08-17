"""Sidecar/CLI facade for the Global Graph corpus. Journal writes go through GraphStore."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ayran.knowledge.conflicts import ConflictGroup
from ayran.knowledge.corpus import (
    RUNTIME_SOURCES,
    build_release,
    corpus_status,
    load_release_records,
    query_corpus,
)
from ayran.knowledge.errors import KnowledgeError
from ayran.knowledge.ingestion import ingest_source as run_ingest
from ayran.knowledge.models import KnowledgeRecord
from ayran.knowledge.paths import default_knowledge_root
from ayran.knowledge.persist import persist_conflict_group, persist_records
from ayran.knowledge.source_registry import get_source
from ayran.knowledge.source_registry import list_sources as registry_list
from ayran.knowledge.source_registry import tombstone_source as registry_tombstone


def _root(knowledge_root: Path | str | None) -> Path:
    if knowledge_root is None:
        return default_knowledge_root()
    return Path(knowledge_root)


def list_sources(knowledge_root: Path | str | None = None, phase: str | None = None) -> dict[str, Any]:
    root = _root(knowledge_root)
    entries = [item.model_dump(mode="json") for item in registry_list(root, phase=phase)]
    return {"schema_version": "1.0.0", "sources": entries, "count": len(entries)}


def ingest_source(
    knowledge_root: Path | str | None,
    source_id: str,
    *,
    store: Any | None = None,
    artifact_store: Any | None = None,
) -> dict[str, Any]:
    root = _root(knowledge_root)
    existing = []
    try:
        existing = load_release_records(root)
    except KnowledgeError:
        existing = []
    result = run_ingest(root, source_id, artifact_store=artifact_store, existing=existing)
    if store is not None:
        from ayran.knowledge.ingestion import load_staged_records

        records = load_staged_records(root, source_id)
        persist_records(store, records)
        result["graph_appended"] = len(records)
    return result


def release_corpus(
    knowledge_root: Path | str | None,
    version: str,
    *,
    store: Any | None = None,
    exclude: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    root = _root(knowledge_root)
    manifest = build_release(root, version=version, exclude=exclude)
    if store is not None:
        records = load_release_records(root, str(manifest.get("release_id")))
        persist_records(store, records)
        for item in manifest.get("conflicts") or []:
            persist_conflict_group(store, ConflictGroup.model_validate(item))
        manifest = {**manifest, "graph_appended": len(records)}
    return manifest


def knowledge_status(knowledge_root: Path | str | None = None) -> dict[str, Any]:
    return corpus_status(_root(knowledge_root))


def query_records(
    knowledge_root: Path | str | None,
    *,
    record_type: str | None = None,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    records = query_corpus(_root(knowledge_root), record_type=record_type, filters=filters)
    return {"schema_version": "1.0.0", "count": len(records), "records": records}


def tombstone_source(
    knowledge_root: Path | str | None,
    source_id: str,
    reason: str,
    *,
    store: Any | None = None,
    republish_version: str | None = None,
) -> dict[str, Any]:
    root = _root(knowledge_root)
    record = registry_tombstone(root, source_id, reason)
    payload: dict[str, Any] = {"schema_version": "1.0.0", "tombstone": record.model_dump(mode="json")}
    if republish_version:
        payload["release"] = release_corpus(
            root, republish_version, store=store, exclude=frozenset({source_id})
        )
    elif store is not None:
        _ = store
    return payload


def ingest_runtime_sources(
    knowledge_root: Path | str | None = None,
    *,
    store: Any | None = None,
    artifact_store: Any | None = None,
) -> dict[str, Any]:
    root = _root(knowledge_root)
    results = []
    for source_id in sorted(RUNTIME_SOURCES):
        entry = get_source(root, source_id)
        if entry.phase in {"deferred", "catalogued", "tombstoned"}:
            continue
        results.append(
            ingest_source(root, source_id, store=store, artifact_store=artifact_store)
        )
    return {"schema_version": "1.0.0", "ingested": results}


def records_as_cards(records: list[KnowledgeRecord]) -> list[dict[str, Any]]:
    cards = []
    for record in records:
        if not record.safe_for_retrieval:
            continue
        cards.append(
            {
                "id": record.record_id,
                "title": record.title or record.record_id,
                "record_type": record.record_type,
                "mechanism": record.mechanism,
                "language": record.language,
                "protocol": record.protocol,
                "applicability_predicates": list(record.applicability_predicates),
                "trust_tier": record.trust_tier,
                "provenance": [
                    {
                        "source_id": record.source_ref.source_id,
                        "locator": record.source_ref.locator,
                        "commit": record.commit_or_version,
                        "raw_hash": record.raw_hash,
                        "license": record.license_info.spdx_id,
                    }
                ],
                "hard_negative": record.hard_negative,
                "historical_reference": True,
            }
        )
    return cards
