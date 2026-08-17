"""Immutable, versioned Global corpus releases. Refresh never rewrites history."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from ayran.graph.canonical import atomic_write, canonical_hash, canonical_line, sha256_bytes
from ayran.knowledge.errors import CORPUS_UNAVAILABLE, KnowledgeError
from ayran.knowledge.ingestion import ingest_source, load_staged_records
from ayran.knowledge.models import KnowledgeRecord, record_from_mapping
from ayran.knowledge.paths import (
    PARSER_VERSION,
    PINNED_TIME,
    TAXONOMY_VERSION,
    current_pointer,
    quarantine_dir,
    releases_dir,
    staging_dir,
)
from ayran.knowledge.source_registry import get_source, list_sources, save_source

RUNTIME_SOURCES = frozenset({"zeroskills", "solodit", "0xsimao", "krait"})


def _cas_path(release_root: Path, digest: str) -> Path:
    hexpart = digest[7:] if digest.startswith("sha256:") else digest
    return release_root / "cas" / hexpart[:2] / hexpart[2:4] / hexpart


def load_current(root: Path) -> dict[str, Any] | None:
    pointer = current_pointer(root)
    if not pointer.is_file():
        return None
    payload = json.loads(pointer.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def load_release(root: Path, release_id: str | None = None) -> dict[str, Any]:
    pointer = load_current(root)
    identifier = release_id or (str(pointer.get("release_id")) if pointer else "")
    if not identifier:
        raise KnowledgeError(CORPUS_UNAVAILABLE, "no corpus release is current")
    manifest_path = releases_dir(root) / identifier / "manifest.json"
    if not manifest_path.is_file():
        raise KnowledgeError(CORPUS_UNAVAILABLE, f"release {identifier} has no manifest")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise KnowledgeError(CORPUS_UNAVAILABLE, "manifest is not an object")
    return payload


def load_release_records(root: Path, release_id: str | None = None) -> list[KnowledgeRecord]:
    manifest = load_release(root, release_id)
    release_root = releases_dir(root) / str(manifest["release_id"])
    records: list[KnowledgeRecord] = []
    for block in manifest.get("blocks") or []:
        if not isinstance(block, dict):
            continue
        digest = str(block.get("content_hash") or "")
        path = _cas_path(release_root, digest)
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            records.append(record_from_mapping(payload))
    return sorted(records, key=lambda item: item.record_id)


def _eligible_sources(root: Path, *, exclude: frozenset[str] = frozenset()) -> list[str]:
    eligible: list[str] = []
    for entry in list_sources(root):
        if entry.source_id in exclude:
            continue
        if entry.phase == "tombstoned":
            continue
        if entry.phase in {"deferred", "catalogued", "quarantined"}:
            continue
        if entry.source_id not in RUNTIME_SOURCES:
            continue
        staging = staging_dir(root, entry.source_id) / "records.json"
        if entry.phase in {"ingested", "active"} or staging.is_file():
            eligible.append(entry.source_id)
    return sorted(eligible)


def gather_records(root: Path, *, exclude: frozenset[str] = frozenset()) -> tuple[list[KnowledgeRecord], list[dict[str, Any]]]:
    records: list[KnowledgeRecord] = []
    sources: list[dict[str, Any]] = []
    for source_id in _eligible_sources(root, exclude=exclude):
        entry = get_source(root, source_id)
        staged = load_staged_records(root, source_id)
        if not staged:
            ingest_source(root, source_id, existing=records)
            entry = get_source(root, source_id)
            staged = load_staged_records(root, source_id)
        records.extend(staged)
        sources.append(
            {
                "source_id": entry.source_id,
                "origin": entry.origin,
                "pin": entry.pin.model_dump(mode="json"),
                "license": entry.license.spdx_id,
                "trust_tier": entry.trust_tier,
                "phase": entry.phase,
            }
        )
    records.sort(key=lambda item: item.record_id)
    sources.sort(key=lambda item: str(item["source_id"]))
    return records, sources


def _unsigned_manifest(
    *,
    version: str,
    records: list[KnowledgeRecord],
    sources: list[dict[str, Any]],
    blocks: list[dict[str, str]],
    quarantine_count: int,
) -> dict[str, Any]:
    counts = Counter(item.record_type for item in records)
    corpus_id = f"ayran-global-{version}"
    body = {
        "schema_version": "1.0.0",
        "corpus_id": corpus_id,
        "release_id": corpus_id,
        "version": version,
        "created_at": PINNED_TIME,
        "taxonomy_version": TAXONOMY_VERSION,
        "parser_version": PARSER_VERSION,
        "sources": sources,
        "record_counts": {key: counts[key] for key in sorted(counts)},
        "record_ids": [item.record_id for item in records],
        "blocks": blocks,
        "quarantine_count": quarantine_count,
    }
    return body


def build_release(
    root: Path,
    *,
    version: str,
    exclude: frozenset[str] = frozenset(),
    switch_pointer: bool = True,
) -> dict[str, Any]:
    records, sources = gather_records(root, exclude=exclude)
    release_id = f"ayran-global-{version}"
    destination = releases_dir(root) / release_id
    if destination.exists():
        existing = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        if switch_pointer:
            _switch_pointer(root, release_id, str(existing.get("content_hash") or ""))
        return existing if isinstance(existing, dict) else {"release_id": release_id}
    destination.mkdir(parents=True, exist_ok=True)
    blocks: list[dict[str, str]] = []
    for record in records:
        payload = record.canonical_dict()
        encoded = canonical_line(payload)
        digest = sha256_bytes(encoded)
        path = _cas_path(destination, digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(encoded)
        blocks.append({"record_id": record.record_id, "content_hash": digest})
    blocks.sort(key=lambda item: item["record_id"])
    quarantined = 0
    qroot = quarantine_dir(root)
    if qroot.is_dir():
        quarantined = sum(1 for path in qroot.glob("*/*.json") if path.is_file())
    unsigned = _unsigned_manifest(
        version=version,
        records=records,
        sources=sources,
        blocks=blocks,
        quarantine_count=quarantined,
    )
    content_hash = canonical_hash(unsigned)
    manifest = {**unsigned, "content_hash": content_hash, "signature": content_hash}
    atomic_write(destination / "manifest.json", canonical_line(manifest))
    if switch_pointer:
        _switch_pointer(root, release_id, content_hash)
    for source in sources:
        entry = get_source(root, str(source["source_id"]))
        if entry.phase == "ingested":
            save_source(root, entry.model_copy(update={"phase": "active"}))
    return manifest


def _switch_pointer(root: Path, release_id: str, manifest_hash: str) -> dict[str, Any]:
    previous = None
    current = load_current(root)
    if current:
        previous = current.get("release_id")
    pointer = {
        "schema_version": "1.0.0",
        "release_id": release_id,
        "manifest_hash": manifest_hash,
        "previous_release_id": previous,
        "switched_at": PINNED_TIME,
    }
    atomic_write(current_pointer(root), canonical_line(pointer))
    return pointer


def corpus_status(root: Path) -> dict[str, Any]:
    pointer = load_current(root)
    quarantined = 0
    qroot = quarantine_dir(root)
    if qroot.is_dir():
        quarantined = sum(1 for path in qroot.glob("*/*.json") if path.is_file())
    if pointer is None:
        return {
            "schema_version": "1.0.0",
            "current": None,
            "record_counts": {},
            "quarantine_count": quarantined,
            "sources": [item.model_dump(mode="json") for item in list_sources(root)],
        }
    try:
        manifest = load_release(root)
    except KnowledgeError:
        manifest = {}
    return {
        "schema_version": "1.0.0",
        "current": pointer,
        "corpus_id": manifest.get("corpus_id"),
        "content_hash": manifest.get("content_hash"),
        "record_counts": manifest.get("record_counts") or {},
        "quarantine_count": manifest.get("quarantine_count", quarantined),
        "sources": manifest.get("sources") or [],
        "taxonomy_version": manifest.get("taxonomy_version"),
    }


def query_corpus(
    root: Path,
    *,
    record_type: str | None = None,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    records = load_release_records(root)
    filters = filters or {}
    hits: list[dict[str, Any]] = []
    for record in records:
        if record_type and record.record_type != record_type:
            continue
        if not record.safe_for_retrieval:
            continue
        payload = record.canonical_dict()
        skipped = False
        for key, expected in filters.items():
            if key == "hard_negative":
                if bool(payload.get("hard_negative")) != bool(expected):
                    skipped = True
                    break
                continue
            actual = payload.get(key)
            if actual != expected:
                skipped = True
                break
        if skipped:
            continue
        hits.append(payload)
    return hits
