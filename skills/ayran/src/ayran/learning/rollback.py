"""Atomic rollback of a Learning promotion pointer. Historical pins are retained."""

from __future__ import annotations

from pathlib import Path

from ayran.context.ids import content_id
from ayran.graph.recovery import GraphStore
from ayran.learning.errors import RELEASE_UNAVAILABLE, LearningError
from ayran.learning.models import PromotionRelease, RollbackResult
from ayran.learning.paths import PINNED_TIME, default_learning_root
from ayran.learning.persist import persist_promotion
from ayran.learning.release import (
    load_current,
    load_release_manifest,
    publish_release,
    switch_pointer,
)


def rollback(
    release_id: str,
    *,
    store: GraphStore | None = None,
    learning_root: Path | str | None = None,
    created_at: str = PINNED_TIME,
) -> RollbackResult:
    """Restore the previous learning pointer. Rollback of a rollback is valid."""

    root = Path(learning_root) if learning_root else default_learning_root()
    try:
        manifest = load_release_manifest(root, release_id)
    except LearningError:
        raise
    restore_id = str(manifest.get("rollback_pointer") or manifest.get("prior_pointer") or "")
    if not restore_id:
        current = load_current(root)
        if current and current.get("previous_release_id"):
            restore_id = str(current["previous_release_id"])
    if not restore_id:
        raise LearningError(RELEASE_UNAVAILABLE, "release has no rollback pointer")
    pointer = switch_pointer(root, restore_id, action="rollback", signed_at=created_at)
    rollback_id = content_id("rel", "rollback", release_id, restore_id, created_at)
    record = PromotionRelease(
        release_id=rollback_id,
        created_at=created_at,
        candidates=list(manifest.get("candidates") or []),
        prior_pointer=release_id,
        rollback_pointer=restore_id,
        signed_at=created_at,
        action="rollback",
        routing_policy_id=str(manifest.get("routing_policy_id") or ""),
        corpus_pin=str(manifest.get("corpus_pin") or ""),
    )
    published = publish_release(root, record, candidates=[], switch_pointer=False)
    if store is not None:
        persist_promotion(store, published, created_at=created_at)
    return RollbackResult(
        release_id=release_id,
        restored_pointer=str(pointer["release_id"]),
        rollback_release_id=published.release_id,
        signed_at=created_at,
        content_hash=published.content_hash,
        historical_pins_retained=True,
    )
