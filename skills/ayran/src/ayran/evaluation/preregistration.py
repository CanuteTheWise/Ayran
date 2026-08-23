"""Owner-signed preregistration for live evaluation. Hash binds content; journal binds order."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ayran.evaluation.errors import (
    PREREGISTRATION_MISMATCH,
    PREREGISTRATION_REQUIRED,
    EvaluationError,
)
from ayran.evaluation.models import ArmId
from ayran.graph.canonical import canonical_hash, utc_now

JOURNAL_NAME = "eval-journal.jsonl"
EVENT_PREREGISTERED = "eval_preregistered"


class PricingRates(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_rate: float
    output_rate: float


class EvalCaps(BaseModel):
    model_config = ConfigDict(extra="forbid")
    per_arm_usd: float = 50.0
    session_usd: float = 150.0


class Preregistration(BaseModel):
    """Canonical grading sheet. Any post-signature edit changes the hash."""

    model_config = ConfigDict(extra="forbid")
    arms: list[ArmId]
    targets: list[str]
    model_id: str
    model_version: str
    thinking_level: str
    pricing_table: dict[str, PricingRates]
    epsilon_non_inferiority: float = 0.0
    lift_required_on: list[str] = Field(default_factory=lambda: ["severity_weighted_recall"])
    caps: EvalCaps = Field(default_factory=EvalCaps)
    created_at: str

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def content_hash(self) -> str:
        return canonical_hash(self.canonical_payload())


def load_preregistration(path: Path | str) -> Preregistration:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvaluationError(PREREGISTRATION_REQUIRED, "preregistration manifest is not an object")
    return Preregistration.model_validate(payload)


def journal_path(results_root: Path | str) -> Path:
    return Path(results_root) / JOURNAL_NAME


def _read_journal(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if isinstance(item, dict):
            events.append(item)
    return events


def preregister(
    manifest: Preregistration | Path | str,
    *,
    results_root: Path | str,
    confirmed_by: str = "operator",
    recorded_at: str | None = None,
) -> dict[str, Any]:
    """Record ``eval_preregistered`` {manifest_hash, confirmed_by} in the eval journal."""

    sheet = manifest if isinstance(manifest, Preregistration) else load_preregistration(manifest)
    stamp = recorded_at or utc_now()
    digest = sheet.content_hash()
    event = {
        "event": EVENT_PREREGISTERED,
        "manifest_hash": digest,
        "confirmed_by": confirmed_by,
        "recorded_at": stamp,
        "arms": list(sheet.arms),
        "targets": list(sheet.targets),
    }
    path = journal_path(results_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
    return event


def matching_preregistration(
    sheet: Preregistration,
    *,
    results_root: Path | str,
) -> dict[str, Any] | None:
    digest = sheet.content_hash()
    for event in _read_journal(journal_path(results_root)):
        if event.get("event") == EVENT_PREREGISTERED and event.get("manifest_hash") == digest:
            return event
    return None


def require_preregistration(
    sheet: Preregistration,
    *,
    results_root: Path | str,
    launch_at: str,
) -> dict[str, Any]:
    """Refuse unless a matching-hash record exists with recorded_at <= first launch."""

    existing = _read_journal(journal_path(results_root))
    if not any(item.get("event") == EVENT_PREREGISTERED for item in existing):
        raise EvaluationError(
            PREREGISTRATION_REQUIRED,
            "live evaluation requires a journaled eval_preregistered record",
        )
    match = matching_preregistration(sheet, results_root=results_root)
    if match is None:
        raise EvaluationError(
            PREREGISTRATION_MISMATCH,
            "preregistration hash does not match the journaled signature; post-signature edits are refused",
        )
    recorded = str(match.get("recorded_at") or "")
    if recorded > launch_at:
        raise EvaluationError(
            PREREGISTRATION_REQUIRED,
            "preregistration recorded_at is after the first arm launch timestamp",
        )
    return match
