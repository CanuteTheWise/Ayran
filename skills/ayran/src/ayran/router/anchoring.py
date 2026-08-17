"""Anchoring and novelty protections from blueprint §4.3."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ayran.context.view import GraphView
from ayran.graph.canonical import canonical_hash


@dataclass(slots=True)
class AnchoringState:
    freeze_hashes: dict[str, str] = field(default_factory=dict)
    pre_retrieval_ids: dict[str, tuple[str, ...]] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)

    def freeze_target_first(self, view: GraphView) -> str:
        if view.cluster_id in self.freeze_hashes:
            return self.freeze_hashes[view.cluster_id]
        digest = view.snapshot_hash()
        self.freeze_hashes[view.cluster_id] = digest
        ids = tuple(
            sorted(
                str(item.get("hypothesis_id"))
                for item in view.hypotheses
                if item.get("origin") == "model_novel"
            )
        )
        self.pre_retrieval_ids[view.cluster_id] = ids
        return digest

    def record_post_retrieval(self, view: GraphView) -> dict[str, Any]:
        pre = set(self.pre_retrieval_ids.get(view.cluster_id, ()))
        post = {
            str(item.get("hypothesis_id"))
            for item in view.hypotheses
            if item.get("origin") == "model_novel"
        }
        historical = [
            item for item in view.hypotheses if item.get("origin") == "global_graph"
        ]
        dropped = sorted(pre - post)
        metrics = {
            "cluster_id": view.cluster_id,
            "pre_retrieval_count": len(pre),
            "post_retrieval_count": len(post),
            "novel_dropped": dropped,
            "forced_historical_matches": len(historical),
            "freeze_hash": self.freeze_hashes.get(view.cluster_id),
        }
        self.metrics = metrics
        return metrics

    def diversify(self, cards: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for card in sorted(cards, key=lambda row: str(row.get("id") or row.get("title") or "")):
            key = canonical_hash(
                {
                    "title": card.get("title") or card.get("name"),
                    "mechanism": card.get("mechanism"),
                    "source": card.get("source") or card.get("id"),
                }
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(card)
            if len(unique) >= limit:
                break
        return unique

    def dual_review_required(self, view: GraphView) -> bool:
        if view.value_at_risk < 40:
            return False
        flags = [
            bool(view.global_mechanisms or view.global_incidents),
            "novel" in str(view.maps),
            bool(view.contradictions),
            "integration" in view.maps,
            view.dual_review,
        ]
        return any(flags)
