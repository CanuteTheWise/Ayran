"""Deep Krait check ingestion (spec 12-R4 D). Text processing only.

Replaces the twelve micro-summary YAML records with predicate-keyed
mechanism records once the owner's pinned check corpus is supplied. The
upstream job runner is never ported and never executed (spec 6.2/6.4); this
module only reads check blocks as data. Legacy records are superseded at
the record level - bytes on disk are retained per provenance law - and are
excluded from default retrieval through the existing corpus-release
semantics (``safe_for_retrieval`` gates ``query_corpus``).
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from ayran.knowledge.defihacklabs import normalize_name
from ayran.knowledge.models import KnowledgeRecord, record_from_mapping
from ayran.tools.yaml_lite import YamlLiteError, load_yaml

if TYPE_CHECKING:
    from ayran.knowledge.ingestion import IngestionContext

KRAIT_DEEP_PARSER_VERSION = "krait-deep-1.1.0"
SUPERSEDED_BY_KEY = "superseded-by:krait-deep"
# The frameworks aggregate is one JSON document well beyond the per-record
# text cap; it gets a dedicated bound so the strict JSON parse sees all bytes.
KRAIT_JSON_MAX_BYTES = 2_000_000

_CHECK_SPLIT = re.compile(r"^---+\s*$", re.MULTILINE)
_LABELED_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9 _-]{0,30})\s*[:=]\s*(.*)$")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]


def _parse_block(block: str, *, yaml_strict: bool = False) -> dict[str, Any]:
    try:
        loaded = load_yaml(block)
    except YamlLiteError:
        loaded = None
        if yaml_strict:
            return {}
    if isinstance(loaded, dict):
        return {str(key): value for key, value in loaded.items()}
    mapping: dict[str, Any] = {}
    for line in block.splitlines():
        match = _LABELED_LINE.match(line.strip())
        if match is None:
            continue
        key = match.group(1).strip().lower().replace(" ", "_")
        value = match.group(2).strip()
        if value:
            mapping[key] = value
    return mapping


def _solc_predicate(mapping: dict[str, Any]) -> str | None:
    raw = mapping.get("solc") or mapping.get("solc_range") or mapping.get("compiler")
    text = str(raw or "").strip()
    if not text:
        return None
    compact = re.sub(r"[^0-9.<>=^~,x-]", "", text)
    return f"solc-range:{compact}" if compact else None


def _pattern_predicates(mapping: dict[str, Any]) -> list[str]:
    predicates: list[str] = []
    for raw in _as_list(mapping.get("patterns") or mapping.get("pattern") or mapping.get("signatures")):
        text = str(raw)
        lowered = text.lower()
        if lowered.startswith("selector:"):
            selector = text.split(":", 1)[1].strip().lower()
            predicates.append(f"pattern:selector-{normalize_name(selector)}")
            continue
        slug = normalize_name(text)
        if slug:
            predicates.append(f"pattern:{slug[:64]}")
    return predicates


def _standard_predicates(mapping: dict[str, Any]) -> list[str]:
    tokens = [
        *(_as_list(mapping.get("standards") or mapping.get("standard") or mapping.get("tokens"))),
        *(_as_list(mapping.get("token_standards"))),
    ]
    predicates = [f"standard:{normalize_name(token)}" for token in tokens if normalize_name(token)]
    return predicates


def check_record_values(mapping: dict[str, Any]) -> dict[str, Any] | None:
    """Build one mechanism-record payload from a parsed check mapping."""

    check_id = str(mapping.get("check_id") or mapping.get("id") or "").strip()
    name = str(mapping.get("name") or mapping.get("title") or "").strip()
    if not check_id and not name:
        return None
    key = check_id or name
    predicates = [
        predicate
        for predicate in (
            _solc_predicate(mapping),
            *_pattern_predicates(mapping),
            *_standard_predicates(mapping),
        )
        if predicate
    ]
    severity = str(mapping.get("severity") or "").strip().lower()
    summary = str(mapping.get("summary") or mapping.get("description") or "").strip()
    if severity:
        summary = f"[{severity}] {summary}" if summary else f"[{severity}]"
    return {
        "record_type": "mechanism",
        "canonical_key": f"krait-deep-{normalize_name(key)}",
        "title": name or f"Krait check {check_id}",
        "summary": summary or f"Krait check {key}; no upstream summary text.",
        "language": "solidity",
        "mechanism": name or check_id,
        "applicability_predicates": sorted(set(predicates)),
        "parser_version": KRAIT_DEEP_PARSER_VERSION,
        "safe_for_execution": False,
        "safe_for_retrieval": True,
    }


def parse_krait_check_block(
    text: str,
    *,
    yaml_strict: bool = False,
) -> dict[str, dict[str, Any]]:
    """Parse one or more ``---``-separated check blocks into record payloads.

    Records with no derivable predicates are returned too; callers count
    them separately (empty predicates are allowed, never fabricated).
    With ``yaml_strict`` set, blocks whose YAML sits outside the supported
    subset are dropped instead of falling back to labeled-line scraping -
    the multi-document pattern library must not become junk records.
    """

    records: dict[str, dict[str, Any]] = {}
    for block in _CHECK_SPLIT.split(text):
        stripped = block.strip()
        if not stripped:
            continue
        values = check_record_values(_parse_block(stripped, yaml_strict=yaml_strict))
        if values is None:
            continue
        key = str(values["canonical_key"])
        records[key] = values
    return records


def parse_krait_framework_checks(text: str) -> dict[str, dict[str, Any]]:
    """Parse framework-check JSON blobs (``checklist/frameworks/index.json``).

    Each entry of a framework's ``checks`` array becomes one predicate-keyed
    mechanism record keyed ``krait-deep-<framework>-<check id>``; the upstream
    question text stays verbatim as the title with the severity prefixed in
    the summary. Tags, category, and the framework id become applicability
    predicates. Non-JSON input returns an empty mapping so callers can fall
    through to the block parser.
    """

    stripped = text.strip()
    if not stripped.startswith("{"):
        return {}
    try:
        data = json.loads(stripped)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    records: dict[str, dict[str, Any]] = {}
    for framework_id, framework in data.items():
        if not isinstance(framework, dict) or not isinstance(framework.get("checks"), list):
            continue
        prefix = normalize_name(str(framework_id)) or "framework"
        for check in framework["checks"]:
            if not isinstance(check, dict):
                continue
            check_id = str(check.get("id") or "").strip()
            question = str(check.get("q") or check.get("name") or "").strip()
            if not check_id and not question:
                continue
            severity = str(check.get("sev") or "").strip().lower()
            summary = question or f"Krait check {check_id}"
            if severity:
                summary = f"[{severity}] {summary}"
            category = str(check.get("cat") or "").strip()
            predicates = {f"framework:{prefix}"}
            tag_pool = [*_as_list(check.get("tags"))]
            if category:
                tag_pool.append(category)
            for tag in tag_pool:
                slug = normalize_name(str(tag))
                if slug:
                    predicates.add(f"pattern:{slug}")
            key = f"krait-deep-{prefix}-{normalize_name(check_id or question)}"
            records[key] = {
                "record_type": "mechanism",
                "canonical_key": key,
                "title": question or f"Krait check {check_id}",
                "summary": summary,
                "mechanism": category or str(framework.get("label") or prefix),
                "applicability_predicates": sorted(predicates),
                "parser_version": KRAIT_DEEP_PARSER_VERSION,
                "safe_for_execution": False,
                "safe_for_retrieval": True,
            }
    return records


def _ctx_records(ctx: IngestionContext) -> list[KnowledgeRecord]:
    stored = ctx.working.get("records")
    if not isinstance(stored, list):
        return []
    return [item if isinstance(item, KnowledgeRecord) else record_from_mapping(item) for item in stored]


def supersede_micro_summaries(ctx: IngestionContext) -> dict[str, Any]:
    """Mark legacy micro-summary records superseded by deep mechanism records.

    Legacy records stay in the staging output (provenance law: bytes are
    never deleted) but flip ``safe_for_retrieval`` to False so the default
    corpus query excludes them, and carry a lineage stamp pointing at the
    deep generation.
    """

    deep = [item for item in _ctx_records(ctx) if item.record_type == "mechanism"]
    legacy = [
        item
        for item in ctx.existing_records
        if item.source_ref.source_id == ctx.source.source_id and item.record_type != "mechanism"
    ]
    marked: list[KnowledgeRecord] = []
    for record in legacy:
        if record.safe_for_retrieval is False and any(
            stamp.startswith("superseded-by:") for stamp in record.near_duplicate_lineage
        ):
            marked.append(record)
            continue
        marked.append(
            record.model_copy(
                update={
                    "safe_for_retrieval": False,
                    "near_duplicate_lineage": sorted(
                        {*record.near_duplicate_lineage, SUPERSEDED_BY_KEY}
                    ),
                }
            )
        )
    ctx.working["records"] = [*deep, *marked]
    ctx.working["superseded_record_ids"] = [record.record_id for record in marked]
    return {
        "deep_records": len(deep),
        "superseded": len(marked),
        "empty_predicates": sum(1 for item in deep if not item.applicability_predicates),
    }
