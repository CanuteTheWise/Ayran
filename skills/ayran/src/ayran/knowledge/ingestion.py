"""Deterministic Global Graph ingestion pipeline (blueprint §7.1). No network, no exec."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ayran.context.ids import content_id
from ayran.graph.canonical import canonical_line, sha256_bytes
from ayran.knowledge.conflicts import attach_conflicts, detect_conflicts
from ayran.knowledge.defihacklabs import incident_payload, iter_exploit_files
from ayran.knowledge.entity_resolution import apply_resolution, resolve_against
from ayran.knowledge.errors import (
    INGESTION_QUARANTINED,
    LICENSE_INCOMPLETE,
    NETWORK_FORBIDDEN,
    SOURCE_DEFERRED,
    SOURCE_TOMBSTONED,
    KnowledgeError,
)
from ayran.knowledge.hard_negatives import ensure_hard_negatives
from ayran.knowledge.krait_deep import parse_krait_check_block, parse_krait_framework_checks
from ayran.knowledge.models import (
    KnowledgeRecord,
    LicenseInfo,
    QuarantineRecord,
    SourceRef,
    SourceRegistryEntry,
    record_from_mapping,
)
from ayran.knowledge.parse import ParsedRecord, parse_tree, snapshot_tree
from ayran.knowledge.paths import (
    MAX_RECORD_BYTES,
    PARSER_VERSION,
    PINNED_TIME,
    quarantine_dir,
    raw_dir,
    staging_dir,
)
from ayran.knowledge.safety import scan_mapping, scan_text
from ayran.knowledge.sanitizers import (
    check_hostile_hash,
    load_hostile_hashes,
    sanitize_darknavy_curl_strip,
    sanitize_shuvon_amp_rewrite,
    scan_execution_artifacts,
)
from ayran.knowledge.source_registry import get_source, save_source
from ayran.knowledge.taxonomy import assign_taxonomy, load_taxonomy

INGESTION_STAGES = (
    "registry_proposal",
    "acquire_pin",
    "immutable_quarantine",
    "blacklist_hook",
    "execution_artifact_scan",
    "hostile_hash_check",
    "static_parse",
    "injection_safety_scan",
    "sanitize_transforms",
    "normalize",
    "provenance_rights",
    "taxonomy_map",
    "entity_resolution",
    "conflict_retention",
    "applicability_review",
    "retrieval_test",
    "contamination_scan",
    "corpus_release",
)


@dataclass(slots=True)
class StageOutcome:
    ok: bool
    quarantine: QuarantineRecord | None = None


@dataclass(slots=True)
class IngestionContext:
    source: SourceRegistryEntry
    knowledge_root: Path
    working: dict[str, Any] = field(default_factory=dict)
    max_record_bytes: int = MAX_RECORD_BYTES
    existing_records: list[KnowledgeRecord] = field(default_factory=list)
    artifact_store: Any | None = None
    include_release: bool = False

    def quarantine(self, stage: str, reason: str, *, locator: str = "", raw_hash: str = "") -> StageOutcome:
        record = QuarantineRecord(
            source_id=self.source.source_id,
            stage=stage,
            reason=reason,
            raw_hash=raw_hash,
            locator=locator,
            created_at=PINNED_TIME,
        )
        bucket = quarantine_dir(self.knowledge_root) / self.source.source_id
        bucket.mkdir(parents=True, exist_ok=True)
        path = bucket / f"{stage}.json"
        path.write_bytes(canonical_line(record.model_dump(mode="json")))
        self.working.setdefault("quarantines", []).append(record.model_dump(mode="json"))
        return StageOutcome(ok=False, quarantine=record)


def _records(ctx: IngestionContext) -> list[KnowledgeRecord]:
    stored = ctx.working.get("records")
    if isinstance(stored, list):
        return [item if isinstance(item, KnowledgeRecord) else record_from_mapping(item) for item in stored]
    return []


def _set_records(ctx: IngestionContext, records: list[KnowledgeRecord]) -> None:
    ctx.working["records"] = records


def stage_registry_proposal(ctx: IngestionContext) -> StageOutcome:
    if ctx.source.phase == "tombstoned":
        raise KnowledgeError(SOURCE_TOMBSTONED, f"{ctx.source.source_id} is tombstoned")
    if ctx.source.phase in {"deferred", "catalogued"}:
        raise KnowledgeError(SOURCE_DEFERRED, f"{ctx.source.source_id} is {ctx.source.phase} and has no M7 runtime route")
    ctx.working["phase"] = "proposed"
    return StageOutcome(ok=True)


def stage_acquire_pin(ctx: IngestionContext) -> StageOutcome:
    raw_root = raw_dir(ctx.knowledge_root, ctx.source.source_id)
    snapshot = snapshot_tree(raw_root)
    if not snapshot.files:
        return ctx.quarantine("acquire_pin", "approved snapshot is missing locally; network fetch is forbidden")
    expected = ctx.source.pin.archive_sha256
    if expected and expected != snapshot.tree_hash:
        return ctx.quarantine(
            "acquire_pin",
            "source drift: working-tree hash does not match the registered pin",
            raw_hash=snapshot.tree_hash,
        )
    ctx.working["files"] = snapshot.files
    ctx.working["tree_hash"] = snapshot.tree_hash
    ctx.working["artifacts"] = {
        str(item["path"]): (raw_root / str(item["path"])).read_bytes()
        for item in snapshot.files
    }
    if ctx.artifact_store is not None:
        for item in snapshot.files:
            payload = (raw_root / item["path"]).read_bytes()
            ctx.artifact_store.store(payload, media_type="application/octet-stream", source="knowledge-raw")
    return StageOutcome(ok=True)


def stage_immutable_quarantine(ctx: IngestionContext) -> StageOutcome:
    raw_root = raw_dir(ctx.knowledge_root, ctx.source.source_id)
    dest = quarantine_dir(ctx.knowledge_root) / "raw" / ctx.source.source_id / str(ctx.working.get("tree_hash") or "unknown")[7:23]
    dest.mkdir(parents=True, exist_ok=True)
    for item in ctx.working.get("files") or []:
        source = raw_root / item["path"]
        target = dest / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    ctx.working["immutable_raw"] = str(dest)
    return StageOutcome(ok=True)


def stage_blacklist_hook(ctx: IngestionContext) -> StageOutcome:
    """Spec 11.3 item 2: blacklisted sources hard-fail before any parsing."""

    blacklisted = sorted(flag for flag in ctx.source.contamination_flags if flag.startswith("blacklisted"))
    if ctx.source.source_id == "olaradial" or blacklisted:
        detail = f"SOURCE_BLACKLISTED: flags {blacklisted}" if blacklisted else "SOURCE_BLACKLISTED"
        return ctx.quarantine(
            "blacklist_hook",
            f"{detail}; {ctx.source.source_id} is on the permanent blacklist "
            "(spec 11.3 item 2) and can never be ingested",
        )
    return StageOutcome(ok=True)


def stage_execution_artifact_scan(ctx: IngestionContext) -> StageOutcome:
    """Spec 11.3: archives/binaries/installers/auto-fetch bait never enter staging."""

    artifacts = ctx.working.get("artifacts")
    if not isinstance(artifacts, dict):
        return StageOutcome(ok=True)
    for name in sorted(artifacts):
        data = artifacts.get(name)
        if not isinstance(data, bytes):
            continue
        reasons = scan_execution_artifacts(str(name), data)
        if reasons:
            digest = sha256_bytes(data)
            return ctx.quarantine(
                "execution_artifact_scan",
                f"artifact {name}: " + "; ".join(reasons),
                locator=str(name),
                raw_hash=digest,
            )
    return StageOutcome(ok=True)


def stage_hostile_hash_check(ctx: IngestionContext) -> StageOutcome:
    """Spec 6.1: SHA256 hostile-artifact blocklist (Olaradial lineage)."""

    artifacts = ctx.working.get("artifacts")
    if not isinstance(artifacts, dict):
        return StageOutcome(ok=True)
    table = load_hostile_hashes(ctx.knowledge_root)
    for name in sorted(artifacts):
        data = artifacts.get(name)
        if not isinstance(data, bytes):
            continue
        digest = sha256_bytes(data)
        reason = check_hostile_hash(digest.split(":", 1)[-1], table)
        if reason is not None:
            return ctx.quarantine(
                "hostile_hash_check",
                f"artifact {name}: {reason}",
                locator=str(name),
                raw_hash=digest,
            )
    return StageOutcome(ok=True)


def _defihacklabs_parsed(ctx: IngestionContext, raw_root: Path) -> list[ParsedRecord] | None:
    if not (raw_root / "src" / "test").is_dir():
        return None
    parsed: list[ParsedRecord] = []
    irregular: list[dict[str, str]] = []
    commit = ctx.source.pin.commit
    for entry in iter_exploit_files(raw_root, max_bytes=ctx.max_record_bytes):
        if entry.card is None:
            irregular.append({"relpath": entry.relpath, "reason": entry.reason or "irregular layout"})
            continue
        payload = incident_payload(entry.card, commit=commit)
        parsed.append(
            ParsedRecord(
                locator=entry.relpath,
                payload=payload,
                raw_hash=sha256_bytes(entry.path.read_bytes()),
                kind="code",
            )
        )
    ctx.working["defihacklabs_irregular"] = irregular
    ctx.working["defihacklabs_cards"] = len(parsed)
    return parsed


def _krait_deep_parsed(ctx: IngestionContext) -> list[ParsedRecord]:
    files = ctx.working.get("krait_deep_files") or []
    parsed: list[ParsedRecord] = []
    source_code_suffixes = {"ts", "tsx", "js", "mjs", "cjs", "sh", "py", "toml"}
    for relpath, text in files:
        if not isinstance(text, str):
            continue
        suffix = relpath.rsplit(".", 1)[-1].lower() if "." in relpath else ""
        if suffix in source_code_suffixes:
            # Executable/source text is not check-block material; the
            # execution-artifact scan already bounds what may materialize.
            continue
        digest = sha256_bytes(text.encode("utf-8"))
        if suffix == "json":
            records = parse_krait_framework_checks(text)
        elif suffix in {"yaml", "yml"}:
            records = parse_krait_check_block(text, yaml_strict=True)
        else:
            records = parse_krait_check_block(text)
        for key, values in records.items():
            parsed.append(
                ParsedRecord(
                    locator=f"{relpath}#{key}",
                    payload=values,
                    raw_hash=digest,
                    kind="yaml",
                )
            )
    return parsed


def stage_static_parse(ctx: IngestionContext) -> StageOutcome:
    raw_root = raw_dir(ctx.knowledge_root, ctx.source.source_id)
    if ctx.working.get("static_parse_preset") == "krait_deep":
        parsed: list[ParsedRecord] | None = _krait_deep_parsed(ctx)
    else:
        parsed = _defihacklabs_parsed(ctx, raw_root)
        if parsed is None:
            parsed = parse_tree(raw_root, max_bytes=ctx.max_record_bytes)
    if not parsed:
        return ctx.quarantine("static_parse", "static parse produced no records")
    ctx.working["parsed"] = parsed
    return StageOutcome(ok=True)


def stage_injection_safety_scan(ctx: IngestionContext) -> StageOutcome:
    accepted: list[ParsedRecord] = []
    parsed = ctx.working.get("parsed") or []
    for item in parsed:
        if not isinstance(item, ParsedRecord):
            continue
        result = scan_mapping(item.payload)
        if not result.accepted:
            return ctx.quarantine(
                "injection_safety_scan",
                result.reason,
                locator=item.locator,
                raw_hash=item.raw_hash,
            )
        body = item.payload.get("body")
        if isinstance(body, str):
            body_scan = scan_text(body)
            if not body_scan.accepted:
                return ctx.quarantine(
                    "injection_safety_scan",
                    body_scan.reason,
                    locator=item.locator,
                    raw_hash=item.raw_hash,
                )
            item.payload["body"] = body_scan.text
            item.payload["non_executable_metadata"] = body_scan.metadata
        accepted.append(item)
    ctx.working["parsed"] = accepted
    return StageOutcome(ok=True)


def _sanitize_text(text: str) -> tuple[str, list[str]]:
    applied: list[str] = []
    for transform, label in (
        (sanitize_darknavy_curl_strip, "darknavy_curl_strip"),
        (sanitize_shuvon_amp_rewrite, "shuvon_amp_rewrite"),
    ):
        cleaned, changed = transform(text)
        if changed:
            text = cleaned
            applied.append(label)
    return text, applied


def stage_sanitize_transforms(ctx: IngestionContext) -> StageOutcome:
    """Spec 6.5/11.3: apply recorded sanitizer transforms; keep before/after hashes."""

    log: list[dict[str, Any]] = []
    applied_by_locator: dict[str, list[str]] = {}
    source_applied: list[str] = []
    artifacts = ctx.working.get("artifacts")
    if isinstance(artifacts, dict):
        for name in sorted(artifacts):
            data = artifacts.get(name)
            if not isinstance(data, bytes):
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            cleaned, applied = _sanitize_text(text)
            if not applied:
                continue
            encoded = cleaned.encode("utf-8")
            artifacts[str(name)] = encoded
            source_applied.extend(applied)
            log.append(
                {
                    "artifact": str(name),
                    "before": sha256_bytes(data),
                    "after": sha256_bytes(encoded),
                    "sanitizers": applied,
                }
            )
    for item in ctx.working.get("parsed") or []:
        if not isinstance(item, ParsedRecord):
            continue
        body = item.payload.get("body")
        if not isinstance(body, str):
            continue
        cleaned, applied = _sanitize_text(body)
        if not applied:
            continue
        item.payload["body"] = cleaned
        applied_by_locator[item.locator] = applied
        source_applied.extend(applied)
        log.append(
            {
                "artifact": item.locator,
                "before": sha256_bytes(body.encode("utf-8")),
                "after": sha256_bytes(cleaned.encode("utf-8")),
                "sanitizers": applied,
            }
        )
    ctx.working["sanitize_log"] = log
    ctx.working["applied_sanitizers"] = sorted(set(source_applied))
    ctx.working["sanitizers_by_locator"] = applied_by_locator
    return StageOutcome(ok=True)


def _license(entry: SourceRegistryEntry) -> LicenseInfo:
    if not entry.license.spdx_id:
        raise KnowledgeError(LICENSE_INCOMPLETE, f"{entry.source_id} is missing SPDX license metadata")
    return entry.license


def _normalize_one(ctx: IngestionContext, parsed: ParsedRecord) -> KnowledgeRecord:
    payload = dict(parsed.payload)
    slug = str(payload.get("canonical_key") or payload.get("record_id") or Path(parsed.locator).stem)
    record_id = content_id("krec", ctx.source.source_id, slug, parsed.raw_hash)
    source_ref = SourceRef(
        source_id=ctx.source.source_id,
        origin=ctx.source.origin,
        commit_or_version=ctx.source.pin.commit or ctx.source.pin.tag or "curated-snapshot",
        pin=ctx.source.pin,
        locator=parsed.locator,
        retrieved_at=PINNED_TIME,
    )
    payload.setdefault("record_id", record_id)
    payload.setdefault("source_ref", source_ref.model_dump(mode="json"))
    payload.setdefault("authors", list(ctx.source.authors))
    payload.setdefault("commit_or_version", source_ref.commit_or_version)
    payload.setdefault("date", PINNED_TIME)
    payload.setdefault("raw_hash", parsed.raw_hash)
    payload.setdefault("parser_version", PARSER_VERSION)
    payload.setdefault("license_info", _license(ctx.source).model_dump(mode="json"))
    payload.setdefault("trust_tier", ctx.source.trust_tier)
    payload.setdefault("reproduction_status", ctx.source.reproduction_status)
    payload.setdefault("safe_for_execution", False)
    payload.setdefault("title", slug.replace("-", " "))
    record_sanitizers = sorted(
        set(
            list(ctx.working.get("applied_sanitizers") or [])
            + list((ctx.working.get("sanitizers_by_locator") or {}).get(parsed.locator) or [])
        )
    )
    payload.setdefault("sanitizers", record_sanitizers)
    if "record_type" not in payload:
        payload["record_type"] = "method"
    if payload.get("hard_negative") in {True, "true"}:
        payload["record_type"] = "false_positive_trap"
        payload["hard_negative"] = True
    return record_from_mapping(payload)


def stage_normalize(ctx: IngestionContext) -> StageOutcome:
    records = [_normalize_one(ctx, item) for item in ctx.working.get("parsed") or [] if isinstance(item, ParsedRecord)]
    _set_records(ctx, records)
    ctx.working["trust_class"] = "curated_external"
    return StageOutcome(ok=True)


def stage_provenance_rights(ctx: IngestionContext) -> StageOutcome:
    records = []
    for record in _records(ctx):
        if not record.source_ref.locator or not record.raw_hash or not record.license_info.spdx_id:
            return ctx.quarantine("provenance_rights", "required provenance or license fields are missing")
        records.append(record)
    _set_records(ctx, records)
    return StageOutcome(ok=True)


def stage_taxonomy_map(ctx: IngestionContext) -> StageOutcome:
    taxonomy = load_taxonomy(ctx.knowledge_root)
    mapped = []
    for record in _records(ctx):
        tags = assign_taxonomy(record, taxonomy)
        mapped.append(record.model_copy(update={"taxonomy": sorted(set(record.taxonomy + tags))}))
    _set_records(ctx, mapped)
    ctx.working["taxonomy_version"] = taxonomy.get("mechanisms", {}).get("version") or "1.0.0"
    return StageOutcome(ok=True)


def stage_entity_resolution(ctx: IngestionContext) -> StageOutcome:
    resolved: list[KnowledgeRecord] = []
    pool = list(ctx.existing_records)
    for record in _records(ctx):
        decision = resolve_against(record, pool)
        updated = apply_resolution(record, decision)
        resolved.append(updated)
        pool.append(updated)
    _set_records(ctx, resolved)
    return StageOutcome(ok=True)


def stage_conflict_retention(ctx: IngestionContext) -> StageOutcome:
    records = _records(ctx)
    groups = detect_conflicts(records + list(ctx.existing_records))
    updated = attach_conflicts(records, groups)
    _set_records(ctx, updated)
    ctx.working["conflicts"] = [group.model_dump(mode="json") for group in groups]
    return StageOutcome(ok=True)


def stage_applicability_review(ctx: IngestionContext) -> StageOutcome:
    reviewed: list[KnowledgeRecord] = []
    for record in _records(ctx):
        needs = record.record_type in {"mechanism", "reasoning_lens", "specialist_skill", "finding_pattern"}
        completeness = record.completeness
        if needs and not record.applicability_predicates:
            completeness = min(completeness, 0.4)
        reviewed.append(record.model_copy(update={"completeness": completeness}))
    _set_records(ctx, ensure_hard_negatives(reviewed))
    return StageOutcome(ok=True)


def stage_retrieval_test(ctx: IngestionContext) -> StageOutcome:
    for record in _records(ctx):
        if not record.safe_for_retrieval:
            continue
        if not record.source_ref.locator or not record.commit_or_version or not record.trust_tier:
            return ctx.quarantine("retrieval_test", f"{record.record_id} lacks retrieval provenance")
        if record.safe_for_execution:
            return ctx.quarantine("retrieval_test", "execution flag must default false for curated imports")
    return StageOutcome(ok=True)


def stage_contamination_scan(ctx: IngestionContext) -> StageOutcome:
    if ctx.source.contamination_registry == "sealed_holdout":
        return ctx.quarantine("contamination_scan", "sealed holdout records cannot enter production")
    for record in _records(ctx):
        if "sealed_holdout" in record.benchmark_exposure and ctx.source.contamination_registry == "production":
            return ctx.quarantine(
                "contamination_scan",
                "near-duplicate sealed-set labels cannot cross into production",
                locator=record.source_ref.locator,
                raw_hash=record.raw_hash,
            )
    return StageOutcome(ok=True)


def stage_corpus_release(ctx: IngestionContext) -> StageOutcome:
    if not ctx.include_release:
        return StageOutcome(ok=True)
    from ayran.knowledge.corpus import build_release

    release = build_release(ctx.knowledge_root, version=str(ctx.working.get("release_version") or "v0.1.0"))
    ctx.working["release"] = release
    return StageOutcome(ok=True)


STAGE_FUNCTIONS: dict[str, Callable[[IngestionContext], StageOutcome]] = {
    "registry_proposal": stage_registry_proposal,
    "acquire_pin": stage_acquire_pin,
    "immutable_quarantine": stage_immutable_quarantine,
    "blacklist_hook": stage_blacklist_hook,
    "execution_artifact_scan": stage_execution_artifact_scan,
    "hostile_hash_check": stage_hostile_hash_check,
    "static_parse": stage_static_parse,
    "injection_safety_scan": stage_injection_safety_scan,
    "sanitize_transforms": stage_sanitize_transforms,
    "normalize": stage_normalize,
    "provenance_rights": stage_provenance_rights,
    "taxonomy_map": stage_taxonomy_map,
    "entity_resolution": stage_entity_resolution,
    "conflict_retention": stage_conflict_retention,
    "applicability_review": stage_applicability_review,
    "retrieval_test": stage_retrieval_test,
    "contamination_scan": stage_contamination_scan,
    "corpus_release": stage_corpus_release,
}


def run_pipeline(ctx: IngestionContext, *, until: str | None = None) -> StageOutcome:
    for name in INGESTION_STAGES:
        outcome = STAGE_FUNCTIONS[name](ctx)
        ctx.working["last_stage"] = name
        if not outcome.ok:
            ctx.source = ctx.source.model_copy(update={"phase": "quarantined"})
            save_source(ctx.knowledge_root, ctx.source)
            return outcome
        if until == name:
            return outcome
    return StageOutcome(ok=True)


def persist_staging(ctx: IngestionContext) -> Path:
    destination = staging_dir(ctx.knowledge_root, ctx.source.source_id)
    destination.mkdir(parents=True, exist_ok=True)
    payload = {
        "source_id": ctx.source.source_id,
        "tree_hash": ctx.working.get("tree_hash"),
        "taxonomy_version": ctx.working.get("taxonomy_version"),
        "conflicts": ctx.working.get("conflicts") or [],
        "records": [item.canonical_dict() for item in _records(ctx)],
        "created_at": PINNED_TIME,
    }
    path = destination / "records.json"
    path.write_bytes(canonical_line(payload))
    return path


def ingest_source(root: Path, source_id: str, *, artifact_store: Any | None = None, existing: list[KnowledgeRecord] | None = None) -> dict[str, Any]:
    if artifact_store is not None and getattr(artifact_store, "fetch_url", None):
        raise KnowledgeError(NETWORK_FORBIDDEN, "ingestion must not perform network fetches")
    source = get_source(root, source_id)
    ctx = IngestionContext(
        source=source,
        knowledge_root=root,
        artifact_store=artifact_store,
        existing_records=list(existing or []),
    )
    outcome = run_pipeline(ctx)
    if not outcome.ok:
        quarantine = outcome.quarantine.model_dump(mode="json") if outcome.quarantine else {}
        raise KnowledgeError(
            INGESTION_QUARANTINED,
            outcome.quarantine.reason if outcome.quarantine else "ingestion quarantined",
            details=quarantine,
        )
    persist_staging(ctx)
    updated = ctx.source.model_copy(update={"phase": "ingested"})
    save_source(root, updated)
    records = [item.canonical_dict() for item in _records(ctx)]
    return {
        "schema_version": "1.0.0",
        "source_id": source_id,
        "phase": "ingested",
        "accepted": len(records),
        "quarantined": 0,
        "tree_hash": ctx.working.get("tree_hash"),
        "record_ids": [item["record_id"] for item in records],
        "conflicts": ctx.working.get("conflicts") or [],
    }


def load_staged_records(root: Path, source_id: str) -> list[KnowledgeRecord]:
    path = staging_dir(root, source_id) / "records.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return []
    return [record_from_mapping(item) for item in items if isinstance(item, dict)]
