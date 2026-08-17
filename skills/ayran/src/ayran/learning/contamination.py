"""Sealed-holdout contamination wall for Learning candidates."""

from __future__ import annotations

from typing import Any

from ayran.context.ids import content_id
from ayran.graph.canonical import canonical_hash
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import CONTAMINATION_BLOCKED, LEARNING_NOT_FOUND, LearningError
from ayran.learning.load import load_candidate
from ayran.learning.models import LearningCandidate, QuarantineRecord
from ayran.learning.paths import PINNED_TIME
from ayran.learning.persist import persist_candidate, persist_quarantine

SEALED_MARKERS = frozenset(
    {
        "sealed-holdout",
        "sealed_holdout",
        "benchmark_exposure",
        "near_duplicate_lineage",
    }
)


def _tokens(text: str) -> set[str]:
    return {part for part in text.lower().replace(":", " ").replace("-", " ").split() if len(part) > 3}


def sealed_records(knowledge_root: Any | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        from ayran.knowledge.corpus import load_release_records
        from ayran.knowledge.paths import default_knowledge_root
        from ayran.knowledge.source_registry import get_source

        root = knowledge_root if knowledge_root is not None else default_knowledge_root()
        for record in load_release_records(root):
            registry = "production"
            try:
                entry = get_source(root, record.source_ref.source_id)
                registry = str(entry.contamination_registry)
            except Exception:
                registry = "production"
            exposure = [str(item) for item in record.benchmark_exposure]
            lineage = [str(item) for item in record.near_duplicate_lineage]
            sealed = registry == "sealed_holdout" or any("sealed" in item.lower() for item in exposure + lineage)
            if not sealed:
                continue
            records.append(
                {
                    "record_id": record.record_id,
                    "root_cause": record.root_cause or record.mechanism or "",
                    "project_family": record.protocol or "",
                    "fork_lineage": record.source_ref.origin,
                    "report_lineage": record.source_ref.locator,
                    "code_ancestry": record.raw_hash,
                    "benchmark_exposure": ",".join(exposure),
                    "near_duplicate_lineage": ",".join(lineage),
                }
            )
    except Exception:
        records = []
    return records


def overlaps_holdout(candidate: LearningCandidate, holdouts: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidate_tokens = _tokens(
        " ".join(
            [
                candidate.normalized_pattern,
                candidate.generalized_mechanism,
                candidate.root_cause,
                *candidate.project_families,
                *candidate.applicability_predicates,
            ]
        )
    )
    for item in holdouts:
        haystack = _tokens(
            " ".join(
                str(item.get(key) or "")
                for key in (
                    "root_cause",
                    "project_family",
                    "fork_lineage",
                    "report_lineage",
                    "code_ancestry",
                    "benchmark_exposure",
                    "near_duplicate_lineage",
                    "record_id",
                )
            )
        )
        if item.get("forced_overlap"):
            return item
        shared = candidate_tokens & haystack
        significant = {token for token in shared if token not in {"solidity", "language", "family", "generic"}}
        if significant and (
            str(item.get("root_cause") or "").lower() in candidate.root_cause.lower()
            or str(item.get("project_family") or "") in candidate.project_families
            or "sealed" in haystack
        ):
            return item
        if candidate.normalized_pattern and candidate.normalized_pattern in str(item.get("root_cause") or ""):
            return item
        lineage = str(item.get("near_duplicate_lineage") or item.get("benchmark_exposure") or "")
        if lineage and lineage in candidate.normalized_pattern:
            return item
    return None


def contamination_check(
    candidate: LearningCandidate,
    *,
    store: GraphStore | None = None,
    holdouts: list[dict[str, Any]] | None = None,
    knowledge_root: Any | None = None,
    created_at: str = PINNED_TIME,
) -> dict[str, Any]:
    sealed = list(holdouts) if holdouts is not None else sealed_records(knowledge_root)
    overlap = overlaps_holdout(candidate, sealed)
    if overlap is not None:
        candidate.contamination_check_status = "overlap"
        candidate.promotion_stage = "rejected"
        if store is not None:
            persist_candidate(store, candidate, created_at=created_at)
            persist_quarantine(
                store,
                QuarantineRecord(
                    quarantine_id=content_id("qrn", candidate.candidate_id, "contamination"),
                    subject_id=candidate.candidate_id,
                    subject_kind="candidate",
                    reason="sealed_holdout_overlap",
                    created_at=created_at,
                    review_deadline=created_at,
                    status="rejected",
                    inspectable=True,
                    production_retrievable=False,
                ),
                created_at=created_at,
            )
        raise LearningError(
            CONTAMINATION_BLOCKED,
            "candidate overlaps a sealed holdout and cannot be promoted",
            details={"record_id": str(overlap.get("record_id") or "")},
        )
    candidate.contamination_check_status = "clean"
    candidate.promotion_stage = "contamination_checked"
    payload = candidate.model_dump(mode="json")
    payload.pop("content_hash", None)
    candidate.content_hash = canonical_hash(payload)
    if store is not None:
        persist_candidate(store, candidate, created_at=created_at)
    return {
        "schema_version": "1.0.0",
        "candidate_id": candidate.candidate_id,
        "status": "clean",
        "result_hash": canonical_hash({"candidate": candidate.candidate_id, "status": "clean"}),
    }


def check_candidate(
    candidate_id: str,
    *,
    store: GraphStore,
    holdouts: list[dict[str, Any]] | None = None,
    created_at: str = PINNED_TIME,
) -> dict[str, Any]:
    candidate = load_candidate(store, candidate_id)
    if candidate is None:
        raise LearningError(LEARNING_NOT_FOUND, f"candidate {candidate_id} is not in the Learning Graph")
    return contamination_check(candidate, store=store, holdouts=holdouts, created_at=created_at)
