"""Multi-level deduplication. Nothing is deleted."""

from __future__ import annotations

import re
from typing import Any

from ayran.context.ids import content_id
from ayran.evidence.types import as_mapping
from ayran.hypotheses.builders import canonical_triple

LEVELS = ("exact", "root_cause", "attack_graph", "impact_deployment", "semantic")


def _tokens(text: str) -> frozenset[str]:
    return frozenset(re.findall(r"[a-z0-9]+", text.lower()))


def jaccard(left: str, right: str) -> float:
    a, b = _tokens(left), _tokens(right)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _span_key(item: dict[str, Any]) -> str:
    spans = item.get("source_spans") or item.get("affected_code") or item.get("attack_path") or []
    if isinstance(spans, list):
        return "|".join(str(part).strip().lower() for part in spans)
    return str(item.get("claim") or "").strip().lower()


def _known_issue(item: dict[str, Any]) -> str:
    return str(item.get("known_issue_id") or item.get("duplicate_of") or "").strip()


def _root_key(item: dict[str, Any]) -> str:
    cause = str(item.get("root_cause") or item.get("_triple") or item.get("claim") or "")
    state = str((item.get("target_entities") or ["state"])[0])
    attacker = "unprivileged"
    return canonical_triple(cause, state, attacker)


def _graph_key(item: dict[str, Any]) -> str:
    path = tuple(str(step).strip().lower() for step in (item.get("attack_path") or []))
    pres = tuple(
        str(p.get("description") if isinstance(p, dict) else p).strip().lower()
        for p in (item.get("preconditions") or [])
    )
    return "|".join(path + pres)


def _impact_key(item: dict[str, Any]) -> str:
    premise = as_mapping(item.get("impact_premise"))
    kind = str(premise.get("kind") or item.get("impact_kind") or "")
    deploy = str(item.get("deployment_id") or as_mapping(item.get("target_identity")).get("commit") or "")
    return f"{kind}|{deploy}"


def classify_pair(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Compare two hypotheses. Variants are preserved; nothing is merged away."""

    exact_span = _span_key(left) == _span_key(right) and bool(_span_key(left))
    exact_issue = bool(_known_issue(left)) and _known_issue(left) == _known_issue(right)
    root = _root_key(left) == _root_key(right)
    graph = _graph_key(left) == _graph_key(right) and bool(_graph_key(left))
    impact = _impact_key(left) == _impact_key(right)
    semantic = jaccard(str(left.get("claim") or ""), str(right.get("claim") or ""))
    level = "none"
    disposition = "unique"
    if exact_span or exact_issue:
        level = "exact"
        disposition = "duplicate_known_issue"
    elif root and graph and impact:
        level = "root_cause"
        disposition = "duplicate_known_issue"
    elif root and not graph:
        level = "root_cause"
        disposition = "variant"
    elif graph:
        level = "attack_graph"
        disposition = "variant"
    elif impact and root:
        level = "impact_deployment"
        disposition = "variant"
    elif semantic >= 0.92:
        level = "semantic"
        disposition = "unique"
    return {
        "level": level,
        "disposition": disposition,
        "semantic_similarity": round(semantic, 4),
        "same_span": exact_span,
        "same_known_issue": exact_issue,
        "same_root_cause": root,
        "same_attack_graph": graph,
        "same_impact_deployment": impact,
        "left_id": str(left.get("hypothesis_id") or ""),
        "right_id": str(right.get("hypothesis_id") or ""),
        "comparison": (
            f"level={level} span={exact_span} root={root} graph={graph} "
            f"impact={impact} semantic={semantic:.4f}"
        ),
        "deleted": False,
    }


def check_duplicates(candidate: dict[str, Any], others: list[dict[str, Any]]) -> dict[str, Any]:
    comparisons: list[dict[str, Any]] = []
    duplicate_of = None
    variants: list[str] = []
    for other in others:
        if str(other.get("hypothesis_id")) == str(candidate.get("hypothesis_id")):
            continue
        pair = classify_pair(candidate, other)
        comparisons.append(pair)
        if pair["disposition"] == "duplicate_known_issue" and duplicate_of is None:
            duplicate_of = pair["right_id"]
        if pair["disposition"] == "variant":
            variants.append(pair["right_id"])
    cluster_id = content_id(
        "clu",
        "dedup",
        str(candidate.get("hypothesis_id") or ""),
        duplicate_of or "none",
    )
    status = "duplicate_known_issue" if duplicate_of else "unique"
    if status == "unique" and variants:
        status = "variant"
    return {
        "schema_version": "1.0.0",
        "cluster_id": cluster_id,
        "status": status,
        "duplicate_of": duplicate_of,
        "variants": variants,
        "comparisons": comparisons,
        "deleted": False,
        "reviewer": {"kind": "service", "id": "ayran.dedup", "version": "1.0.0"},
        "confidence": 1.0 if duplicate_of else 0.6,
        "trust_class": "deterministic_tool",
    }
