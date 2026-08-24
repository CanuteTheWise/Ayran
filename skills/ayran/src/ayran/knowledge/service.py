"""Sidecar/CLI facade for the Global Graph corpus. Journal writes go through GraphStore."""

from __future__ import annotations

import shutil
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
from ayran.knowledge.defihacklabs import DEFIHACKLABS_ORIGIN, iter_exploit_files
from ayran.knowledge.errors import (
    INGESTION_QUARANTINED,
    SOURCE_NOT_FOUND,
    KnowledgeError,
)
from ayran.knowledge.ingestion import (
    IngestionContext,
    load_staged_records,
    persist_staging,
    run_pipeline,
)
from ayran.knowledge.ingestion import (
    ingest_source as run_ingest,
)
from ayran.knowledge.krait_deep import (
    KRAIT_JSON_MAX_BYTES,
    supersede_micro_summaries,
)
from ayran.knowledge.models import (
    KnowledgeRecord,
    LicenseInfo,
    SourcePin,
    SourceRegistryEntry,
)
from ayran.knowledge.parse import snapshot_tree
from ayran.knowledge.paths import MAX_RECORD_BYTES, default_knowledge_root, raw_dir, staging_dir
from ayran.knowledge.persist import persist_conflict_group, persist_records
from ayran.knowledge.source_registry import (
    get_source,
    register_source,
    save_source,
)
from ayran.knowledge.source_registry import list_sources as registry_list
from ayran.knowledge.source_registry import tombstone_source as registry_tombstone

DEFIHACKLABS_SOURCE_ID = "defihacklabs"


def _root(knowledge_root: Path | str | None) -> Path:
    if knowledge_root is None:
        return default_knowledge_root()
    return Path(knowledge_root)


def _check_archive_pin(supplied: str | None, computed: str) -> None:
    expected = (supplied or "").strip()
    if expected and expected != computed:
        raise KnowledgeError(
            INGESTION_QUARANTINED,
            f"archive pin mismatch: supplied {expected} but the materialized snapshot hashes to "
            f"{computed}; re-run with --archive-sha256 {computed} to pin these bytes",
        )


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


def ingest_defihacklabs(
    knowledge_root: Path | str | None,
    source_root: Path | str,
    *,
    commit: str,
    archive_sha256: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Offline ingest of a caller-supplied pinned DeFiHackLabs checkout.

    Materializes the selected ``src/test/**/*_exp.sol`` bytes verbatim under
    ``raw/defihacklabs``, pins the snapshot by its canonical tree hash (a
    supplied ``--archive-sha256`` must equal it), then runs the full
    ingestion pipeline. Nothing is compiled or executed.
    """

    root = _root(knowledge_root)
    checkout = Path(source_root)
    if not checkout.is_dir():
        raise KnowledgeError(SOURCE_NOT_FOUND, f"DeFiHackLabs root {checkout} is not a directory")
    entries = list(iter_exploit_files(checkout))
    regular = [entry for entry in entries if entry.card is not None]
    irregular = [
        {"relpath": entry.relpath, "reason": entry.reason or "irregular layout"}
        for entry in entries
        if entry.card is None
    ]
    if limit is not None:
        regular = regular[: max(0, int(limit))]
    if not regular:
        raise KnowledgeError(
            INGESTION_QUARANTINED,
            "no src/test/**/*_exp.sol files found under the supplied root",
        )
    raw_dest = raw_dir(root, DEFIHACKLABS_SOURCE_ID)
    if raw_dest.exists():
        shutil.rmtree(raw_dest)
    for entry in regular:
        target = raw_dest / entry.relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(entry.path, target)
    snapshot = snapshot_tree(raw_dest)
    _check_archive_pin(archive_sha256, snapshot.tree_hash)
    register_source(
        root,
        SourceRegistryEntry(
            source_id=DEFIHACKLABS_SOURCE_ID,
            display_name="DeFiHackLabs exploit PoCs",
            source_type="repository",
            origin=DEFIHACKLABS_ORIGIN,
            pin=SourcePin(commit=commit, archive_sha256=snapshot.tree_hash),
            license=LicenseInfo(
                spdx_id="Apache-2.0",
                attribution_required=True,
                local_use=True,
                redistribution=True,
            ),
            phase="proposed",
            authors=["SunWeb3Sec"],
            notes=(
                "Offline ingest of a caller-supplied pinned checkout; exploit files only; "
                "source text is data and is never compiled or executed."
            ),
        ),
    )
    result = run_ingest(root, DEFIHACKLABS_SOURCE_ID)
    result["irregular_count"] = len(irregular)
    result["irregular_files"] = irregular
    return result


def ingest_krait_deep(
    knowledge_root: Path | str | None,
    deep_root: Path | str,
    *,
    commit: str,
    archive_sha256: str | None = None,
) -> dict[str, Any]:
    """Deep-ingest a pinned Krait check corpus, superseding the micro summaries.

    The check files are materialized under ``raw/krait/deep/``; the legacy
    micro-summary YAML bytes stay untouched. Legacy records remain in
    staging (provenance law) but flip to ``safe_for_retrieval=False`` so the
    default corpus query excludes them.
    """

    root = _root(knowledge_root)
    corpus = Path(deep_root)
    if not corpus.is_dir():
        raise KnowledgeError(SOURCE_NOT_FOUND, f"krait deep corpus root {corpus} is not a directory")
    entry = get_source(root, "krait")
    if not (staging_dir(root, "krait") / "records.json").is_file():
        # Bootstrap the legacy micro-summary ingest BEFORE materializing the
        # deep corpus: the generic parser is single-document and must never
        # see the multi-block deep files.
        run_ingest(root, "krait")
    deep_dest = raw_dir(root, "krait") / "deep"
    if deep_dest.exists():
        shutil.rmtree(deep_dest)
    deep_dest.mkdir(parents=True)
    deep_files: list[tuple[str, str]] = []
    for path in sorted(corpus.rglob("*")):
        if not path.is_file() or any(part.startswith(".") for part in path.parts):
            continue
        relative = path.relative_to(corpus)
        target = deep_dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        raw_bytes = path.read_bytes()
        if path.suffix.lower() == ".json":
            # The frameworks aggregate is one large JSON document; the
            # per-record text cap would truncate it into invalid JSON.
            if len(raw_bytes) > KRAIT_JSON_MAX_BYTES:
                continue
            text = raw_bytes.decode("utf-8", errors="strict")
        else:
            text = raw_bytes[:MAX_RECORD_BYTES].decode("utf-8", errors="strict")
        deep_files.append((f"deep/{relative.as_posix()}", text))
    if not deep_files:
        raise KnowledgeError(
            INGESTION_QUARANTINED,
            "krait deep corpus root contains no readable check files",
        )
    snapshot = snapshot_tree(raw_dir(root, "krait"))
    _check_archive_pin(archive_sha256, snapshot.tree_hash)
    save_source(
        root,
        entry.model_copy(
            update={
                "pin": SourcePin(commit=commit or entry.pin.commit, archive_sha256=snapshot.tree_hash),
                "phase": "proposed",
            }
        ),
    )
    ctx = IngestionContext(
        source=get_source(root, "krait"),
        knowledge_root=root,
        existing_records=load_staged_records(root, "krait"),
    )
    ctx.working["static_parse_preset"] = "krait_deep"
    ctx.working["krait_deep_files"] = deep_files
    outcome = run_pipeline(ctx)
    if not outcome.ok:
        raise KnowledgeError(
            INGESTION_QUARANTINED,
            outcome.quarantine.reason if outcome.quarantine else "krait deep ingest quarantined",
            details=outcome.quarantine.model_dump(mode="json") if outcome.quarantine else {},
        )
    stats = supersede_micro_summaries(ctx)
    persist_staging(ctx)
    save_source(root, ctx.source.model_copy(update={"phase": "ingested"}))
    return {
        "schema_version": "1.0.0",
        "source_id": "krait",
        "phase": "ingested",
        "tree_hash": ctx.working.get("tree_hash"),
        "deep_records": stats["deep_records"],
        "superseded": stats["superseded"],
        "empty_predicates": stats["empty_predicates"],
    }


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
