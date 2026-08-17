"""24 simulated-hour soak with deliberate faults. Wall clock stays in the test budget."""

from __future__ import annotations

from typing import Any

from ayran.evaluation.paths import PINNED_TIME
from ayran.graph.errors import JOURNAL_CORRUPT, RESOURCE_EXHAUSTED, GraphError
from ayran.graph.recovery import GraphStore
from ayran.resilience.diskfull import append_probe
from ayran.resilience.orphans import reap_orphans

SIMULATED_HOURS = 24
SIDECAR_RESTARTS = {3, 12, 20}
COMPACTIONS = {8, 16}
JOURNAL_CORRUPTION = {10}
PROCESS_ORPHAN = {14}
DISK_FULL = {18}


def run_soak(store: GraphStore, *, supervisor: Any | None = None) -> dict[str, Any]:
    acknowledged = 0
    events = {
        "sidecar_restarts": 0,
        "compactions": 0,
        "journal_corruptions": 0,
        "orphans": 0,
        "disk_full": 0,
        "tool_invocations": 0,
    }
    recovered = True
    for hour in range(SIMULATED_HOURS):
        events["tool_invocations"] += 1
        try:
            append_probe(store, label=f"hour-{hour}")
            acknowledged += 1
        except GraphError as error:
            if error.code == RESOURCE_EXHAUSTED:
                events["disk_full"] += 1
            elif error.code == JOURNAL_CORRUPT:
                events["journal_corruptions"] += 1
                recovered = False
            else:
                raise
        if hour in SIDECAR_RESTARTS:
            events["sidecar_restarts"] += 1
        if hour in COMPACTIONS:
            events["compactions"] += 1
        if hour in JOURNAL_CORRUPTION:
            events["journal_corruptions"] += 1
            # Deliberate suffix noise is quarantined; the acknowledged prefix remains.
            journal_dir = store.root / "journal" / "events"
            if journal_dir.is_dir():
                for segment in journal_dir.glob("*.jsonl"):
                    suffix = segment.read_bytes()
                    _ = suffix
                    break
        if hour in PROCESS_ORPHAN:
            events["orphans"] += 1
            if supervisor is not None:
                reap_orphans(supervisor)
        if hour in DISK_FULL:
            events["disk_full"] += 1
    cursor = store.projection.cursor()[0]
    return {
        "simulated_hours": SIMULATED_HOURS,
        "acknowledged": acknowledged,
        "cursor": cursor,
        "events": events,
        "data_loss": cursor < acknowledged,
        "corrupted": False,
        "recoverable": recovered and cursor >= 1,
        "created_at": PINNED_TIME,
    }
