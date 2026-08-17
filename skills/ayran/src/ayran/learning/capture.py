"""Capture adjudicated run outcomes into the quarantined Learning Graph."""

from __future__ import annotations

import re
from typing import Any

from ayran.context.ids import ZERO_HASH, content_id
from ayran.graph.canonical import canonical_hash, utc_now
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import DIRECT_MUTATION_DENIED, LearningError
from ayran.learning.models import (
    LearningOutcome,
    OutcomeType,
    PhaseMetrics,
    RetrievalUsefulness,
    RightsRecord,
    ToolRunSummary,
)
from ayran.learning.paths import PINNED_TIME
from ayran.learning.persist import persist_outcome

SECRET_KEY_MARKERS = (
    "private_key",
    "privatekey",
    "mnemonic",
    "secret",
    "password",
    "api_key",
    "token",
    "exploit",
    "payload",
    "source_text",
    "raw_source",
    "bytecode",
)
PRIVATE_KEY_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{64}")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
STATUS_TO_OUTCOME: dict[str, OutcomeType] = {
    "reported": "accepted",
    "validated": "validated",
    "falsified": "falsified",
    "duplicate_known_issue": "duplicate",
    "parked": "rejected",
}


def redact_secrets(value: Any) -> Any:
    """Drop raw target material, private keys, and secret-bearing fields."""

    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_KEY_MARKERS):
                continue
            if lowered in {"source", "code", "exploit_payload"}:
                continue
            cleaned[str(key)] = redact_secrets(item)
        return cleaned
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        if PRIVATE_KEY_RE.fullmatch(value.strip()):
            return ZERO_HASH
        return PRIVATE_KEY_RE.sub(ZERO_HASH, value)
    return value


def _as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _hash_identity(target_identity: dict[str, Any] | None) -> str:
    if not target_identity:
        return ZERO_HASH
    return canonical_hash(
        {
            "target_id": target_identity.get("target_id"),
            "source_tree_hash": target_identity.get("source_tree_hash"),
            "scope_id": target_identity.get("scope_id"),
            "commit": target_identity.get("commit"),
        }
    )


def _summarize_tool_runs(tool_runs: list[Any]) -> list[ToolRunSummary]:
    summaries: list[ToolRunSummary] = []
    for item in tool_runs:
        if not isinstance(item, dict):
            continue
        started = str(item.get("started_at") or "")
        ended = str(item.get("ended_at") or "")
        duration = 0
        extra = item.get("environment") or []
        experimental = False
        if isinstance(extra, list):
            experimental = any(
                isinstance(entry, dict) and str(entry.get("name") or "") == "AYRAN_EXPERIMENTAL"
                for entry in extra
            )
        summaries.append(
            ToolRunSummary(
                capability=str(item.get("capability_id") or item.get("tool_name") or ""),
                duration_ms=duration,
                resource_usage={
                    "cpu": int(_as_mapping(item.get("limits")).get("cpu") or 0),
                    "memory_mib": int(_as_mapping(item.get("limits")).get("memory_mib") or 0),
                },
                output_hash=str(item.get("stdout_hash") or item.get("stderr_hash") or ZERO_HASH),
                experimental=experimental,
            )
        )
        _ = started, ended
    return summaries[:64]


def _retrieval(hypothesis: dict[str, Any], artifacts: list[Any]) -> RetrievalUsefulness:
    record_ids: list[str] = []
    for key in ("retrieved_record_ids", "global_record_ids", "historical_matches"):
        value = hypothesis.get(key) or []
        if isinstance(value, list):
            record_ids.extend(str(item) for item in value if item)
    for item in artifacts:
        if isinstance(item, dict) and item.get("record_id"):
            record_ids.append(str(item["record_id"]))
    unique = sorted({item for item in record_ids if item})
    return RetrievalUsefulness(
        record_ids=unique[:64],
        influenced=bool(unique),
        notes="retrieval hashes only; no target source",
    )


def capture_outcome(
    run_id: str,
    outcome_type: OutcomeType | str,
    hypothesis_id: str,
    gate_verdicts: list[dict[str, Any]] | None = None,
    tool_runs: list[dict[str, Any]] | None = None,
    artifacts: list[Any] | None = None,
    *,
    store: GraphStore | None = None,
    hypothesis: dict[str, Any] | None = None,
    created_at: str | None = None,
    corpus_pin: str = "",
    routing_pin: str = "",
    metrics: list[dict[str, Any]] | None = None,
    false_positive_reason: str = "",
    false_negative_reason: str = "",
) -> LearningOutcome:
    """Record one adjudicated outcome. Never writes Global production."""

    if store is not None and str(store.stream.get("namespace") or "") == "global":
        raise LearningError(
            DIRECT_MUTATION_DENIED,
            "a run cannot capture learning outcomes into Global production",
        )
    stamped = created_at or PINNED_TIME
    hypo = redact_secrets(_as_mapping(hypothesis))
    verdicts = [redact_secrets(item) for item in (gate_verdicts or []) if isinstance(item, dict)]
    runs = [redact_secrets(item) for item in (tool_runs or []) if isinstance(item, dict)]
    arts = [redact_secrets(item) for item in (artifacts or [])]
    claim = str(hypo.get("claim") or hypo.get("adjudication") or outcome_type)
    origin = str(hypo.get("origin") or "")
    identity = _as_mapping(hypo.get("target_identity"))
    mapped_type: OutcomeType
    if outcome_type in {
        "accepted",
        "rejected",
        "duplicate",
        "adjudicated",
        "falsified",
        "validated",
        "inconclusive",
        "unsafe",
    }:
        mapped_type = outcome_type
    else:
        mapped_type = "adjudicated"
    unsigned = {
        "run_id": run_id,
        "outcome_type": mapped_type,
        "hypothesis_id": hypothesis_id,
        "gate_verdicts": verdicts,
        "tool_run_hashes": [item.get("stdout_hash") for item in runs if isinstance(item, dict)],
        "artifact_hashes": [
            item if isinstance(item, str) else str(_as_mapping(item).get("content_hash") or "")
            for item in arts
        ],
        "claim_digest": canonical_hash({"claim": claim, "origin": origin}),
        "created_at": stamped,
    }
    outcome_id = content_id("out", run_id, hypothesis_id, mapped_type, stamped)
    novelty = 0.5
    if str(hypo.get("novelty") or "") in {"novel", "high"}:
        novelty = 0.9
    elif origin == "model_novel":
        novelty = 0.8
    severity = 0.5
    impact = str(hypo.get("impact_kind") or "")
    if "critical" in impact or "fund" in impact:
        severity = 0.9
    elif "integrity" in impact:
        severity = 0.7
    phase_metrics = [
        PhaseMetrics(
            phase=str(item.get("phase") or "unknown"),
            runtime_ms=int(item.get("runtime_ms") or 0),
            tokens=int(item.get("tokens") or 0),
            cost_micros=int(item.get("cost_micros") or 0),
        )
        for item in (metrics or [])
        if isinstance(item, dict)
    ]
    outcome = LearningOutcome(
        outcome_id=outcome_id,
        created_at=stamped,
        run_id=run_id,
        outcome_type=mapped_type,
        hypothesis_id=hypothesis_id,
        promotion_stage="quarantined",
        gate_verdicts=verdicts,
        tool_runs=_summarize_tool_runs(runs),
        artifacts=[
            item if isinstance(item, str) else str(_as_mapping(item).get("content_hash") or "")
            for item in arts
            if item
        ][:64],
        retrieval=_retrieval(hypo, arts if isinstance(arts, list) else []),
        false_positive_reason=str(false_positive_reason or hypo.get("false_positive_reason") or "")[:2048],
        false_negative_reason=str(false_negative_reason or hypo.get("false_negative_reason") or "")[:2048],
        metrics=phase_metrics,
        model_versions={
            key: str(value)
            for key, value in _as_mapping(hypo.get("model_versions")).items()
            if isinstance(value, str)
        },
        tool_versions={
            str(item.get("tool_name") or item.get("capability_id") or "tool"): str(
                item.get("tool_version") or "unknown"
            )
            for item in runs
            if isinstance(item, dict)
        },
        knowledge_versions={"corpus_pin": corpus_pin} if corpus_pin else {},
        corpus_pin=corpus_pin,
        routing_pin=routing_pin,
        content_hash="",
        rights=RightsRecord(),
        contamination_class="development",
        target_identity_hash=_hash_identity(identity),
        claim_digest=canonical_hash({"claim": claim, "origin": origin}),
        origin=origin,
        novelty_score=novelty,
        severity_score=severity,
        cost_to_validate=1.0,
        adjudication=claim[:4096],
    )
    payload = outcome.model_dump(mode="json")
    payload.pop("content_hash", None)
    outcome.content_hash = canonical_hash({**unsigned, "body": payload})
    if store is not None:
        persist_outcome(store, outcome, created_at=stamped)
    return outcome


def capture_run_outcomes(
    store: GraphStore,
    *,
    run_id: str | None = None,
    created_at: str | None = None,
    corpus_pin: str = "",
    routing_pin: str = "",
) -> dict[str, Any]:
    """Capture terminal M6 hypothesis states for one run into quarantine."""

    from ayran.evidence.load import load_hypotheses, load_tool_run, load_verdicts_for
    from ayran.learning.quarantine import submit_for_review

    stamped = created_at or utc_now()
    effective_run = run_id or str(store.stream.get("run_id") or "")
    captured: list[str] = []
    for hypothesis in load_hypotheses(store):
        status = str(hypothesis.get("status") or "")
        if status not in STATUS_TO_OUTCOME and status not in {"validated", "reported"}:
            continue
        outcome_type = STATUS_TO_OUTCOME.get(status, "adjudicated")
        hid = str(hypothesis.get("hypothesis_id") or "")
        verdicts = load_verdicts_for(store, hid)
        tool_ids = list(hypothesis.get("tool_run_ids") or [])
        runs: list[dict[str, Any]] = []
        for tool_id in tool_ids:
            loaded = load_tool_run(store, str(tool_id))
            if loaded:
                runs.append(loaded)
        outcome = capture_outcome(
            effective_run,
            outcome_type,
            hid,
            verdicts,
            runs,
            list(hypothesis.get("evidence_ids") or []),
            store=store,
            hypothesis=hypothesis,
            created_at=stamped,
            corpus_pin=corpus_pin,
            routing_pin=routing_pin,
        )
        submit_for_review(outcome.outcome_id, store=store, outcome=outcome, created_at=stamped)
        captured.append(outcome.outcome_id)
    return {
        "schema_version": "1.0.0",
        "run_id": effective_run,
        "captured": captured,
        "count": len(captured),
        "created_at": stamped,
    }
