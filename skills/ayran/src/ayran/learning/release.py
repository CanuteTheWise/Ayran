"""Immutable Learning promotion releases and atomic pointer switches."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.graph.canonical import atomic_write, canonical_hash, canonical_line
from ayran.learning.errors import RELEASE_UNAVAILABLE, LearningError
from ayran.learning.models import PromotionRelease, RoutingPolicy
from ayran.learning.paths import (
    BASELINE_ROUTING_POLICY,
    PINNED_TIME,
    current_pointer,
    default_learning_root,
    releases_dir,
    routing_current,
    routing_dir,
    staging_dir,
)


def _root(learning_root: Path | str | None) -> Path:
    if learning_root is None:
        return default_learning_root()
    return Path(learning_root)


def load_current(root: Path) -> dict[str, Any] | None:
    pointer = current_pointer(root)
    if not pointer.is_file():
        return None
    payload = json.loads(pointer.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def load_release_manifest(root: Path, release_id: str) -> dict[str, Any]:
    path = releases_dir(root) / release_id / "manifest.json"
    if not path.is_file():
        raise LearningError(RELEASE_UNAVAILABLE, f"learning release {release_id} has no manifest")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise LearningError(RELEASE_UNAVAILABLE, "learning release manifest is not an object")
    return payload


def baseline_routing_policy(*, created_at: str = PINNED_TIME) -> RoutingPolicy:
    policy = RoutingPolicy(
        policy_id=BASELINE_ROUTING_POLICY,
        created_at=created_at,
        status="baseline",
        driver_weights={
            "model_novel": 25,
            "global_graph": 15,
            "contradiction": 15,
            "tool": 10,
            "coverage": 15,
            "specialist": 20,
        },
        adapter_weights={"solc.compile": 1.0, "foundry.test": 1.0, "slither.analyze": 1.0},
        knowledge_records=[],
        prior_pointer="",
        rollback_pointer="",
    )
    payload = policy.model_dump(mode="json")
    payload.pop("content_hash", None)
    policy.content_hash = canonical_hash(payload)
    return policy


def load_routing_policy(root: Path, policy_id: str | None = None) -> RoutingPolicy:
    pointer = routing_current(root)
    if pointer.is_file():
        payload = json.loads(pointer.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and (policy_id is None or payload.get("policy_id") == policy_id):
            return RoutingPolicy.model_validate(payload)
    if policy_id in {None, BASELINE_ROUTING_POLICY}:
        return baseline_routing_policy()
    raise LearningError(RELEASE_UNAVAILABLE, f"routing policy {policy_id} is not current")


def write_routing_policy(root: Path, policy: RoutingPolicy) -> None:
    routing_dir(root).mkdir(parents=True, exist_ok=True)
    atomic_write(routing_current(root), canonical_line(policy.model_dump(mode="json")))


def publish_release(
    root: Path,
    release: PromotionRelease,
    *,
    candidates: list[dict[str, Any]],
    switch_pointer: bool = True,
) -> PromotionRelease:
    """Write an immutable content-addressed learning release and switch current."""

    destination = releases_dir(root)
    destination.mkdir(parents=True, exist_ok=True)
    staging = staging_dir(root) / release.release_id
    staging.mkdir(parents=True, exist_ok=True)
    blocks: list[dict[str, str]] = []
    for item in candidates:
        digest = canonical_hash(item)
        hexpart = digest[7:] if digest.startswith("sha256:") else digest
        cas = staging / "cas" / hexpart[:2] / hexpart[2:4]
        cas.mkdir(parents=True, exist_ok=True)
        atomic_write(cas / hexpart, canonical_line(item))
        blocks.append({"record_id": str(item.get("candidate_id") or ""), "content_hash": digest})
    unsigned = release.model_dump(mode="json")
    unsigned.pop("content_hash", None)
    unsigned.pop("signature", None)
    unsigned["blocks"] = blocks
    digest = canonical_hash(unsigned)
    release.content_hash = digest
    release.signature = digest
    manifest = release.model_dump(mode="json")
    atomic_write(staging / "manifest.json", canonical_line(manifest))
    published = destination / release.release_id
    if published.exists():
        raise LearningError(RELEASE_UNAVAILABLE, "published learning releases are immutable")
    staging.replace(published)
    if switch_pointer:
        previous = load_current(root)
        pointer = {
            "schema_version": "1.0.0",
            "release_id": release.release_id,
            "content_hash": release.content_hash,
            "previous_release_id": previous.get("release_id") if previous else "",
            "switched_at": release.signed_at or release.created_at,
            "action": release.action,
        }
        atomic_write(current_pointer(root), canonical_line(pointer))
    return release


def switch_pointer(root: Path, release_id: str, *, action: str, signed_at: str) -> dict[str, Any]:
    manifest = load_release_manifest(root, release_id)
    previous = load_current(root)
    pointer = {
        "schema_version": "1.0.0",
        "release_id": release_id,
        "content_hash": manifest.get("content_hash"),
        "previous_release_id": previous.get("release_id") if previous else "",
        "switched_at": signed_at,
        "action": action,
    }
    atomic_write(current_pointer(root), canonical_line(pointer))
    return pointer
