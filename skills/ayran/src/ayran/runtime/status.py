"""Reconstruct deterministic run status from durable state."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.runtime.paths import process_root, run_root


def reconstruct_status(config: Any, run_id: str, state_root: Path | None) -> dict[str, Any]:
    root = run_root((state_root or Path(config.state_root)), run_id)
    if not root.is_dir():
        return {
            "schema_version": "1.0.0",
            "run_id": run_id,
            "present": False,
            "phase": "unknown",
            "graph_cursor": None,
            "budgets": {},
            "active_processes": [],
            "queued_hypotheses": [],
            "pending_approvals": [],
            "last_concrete_progress": None,
            "blockers": [],
        }
    receipt_path = root / "run.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8")) if receipt_path.is_file() else {}

    proc_root = process_root((state_root or Path(config.state_root)), run_id)
    active: list[dict[str, Any]] = []
    records_root = proc_root / "records"
    if records_root.is_dir():
        for path in sorted(records_root.glob("*.jsonl")):
            last: dict[str, Any] | None = None
            with path.open("rb") as stream:
                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    last = json.loads(line.decode("utf-8"))
            if last and last.get("state") == "running":
                active.append(
                    {
                        "process_uid": last.get("process_uid"),
                        "pid": last.get("pid"),
                        "pgid": last.get("pgid"),
                    }
                )
    run_state = receipt.get("run_state", "unknown")
    # Additive derived flag (§7.2 row 3): conservative heuristic for "this run
    # never shut down cleanly and still carries unreconciled process records"
    # — the shape /ayran:status uses to surface the recovery hint. The
    # authoritative stale/alive decision belongs to run.recover, which probes
    # OS liveness; this projection reads durable state only.
    interruptible = run_state not in {"stopped", "completed"} and bool(active)
    return {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "present": True,
        "phase": receipt.get("phase", "unknown"),
        "graph_cursor": receipt.get("graph_cursor"),
        "budgets": receipt.get("budgets", {}),
        "active_processes": active,
        "queued_hypotheses": receipt.get("queued_hypotheses", []),
        "pending_approvals": receipt.get("pending_approvals", []),
        "last_concrete_progress": receipt.get("last_concrete_progress"),
        "blockers": receipt.get("blockers", []),
        "run_state": run_state,
        "interruptible": interruptible,
    }
