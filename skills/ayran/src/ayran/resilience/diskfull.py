"""Disk-full simulation and graceful journal degradation."""

from __future__ import annotations

import errno
from collections.abc import Callable
from typing import Any

from ayran.context.contracts import graph_node, seal, typed_property
from ayran.context.ids import ZERO_HASH, content_id
from ayran.graph.errors import RESOURCE_EXHAUSTED, GraphError
from ayran.graph.recovery import GraphStore
from ayran.graph.types import AppendCommand, AppendItem
from ayran.learning.persist import CONFIG_HASH

ACTOR = {"kind": "service", "id": "ayran.resilience", "version": "1.0.0"}


def raise_enospc(_payload: bytes | None = None) -> None:
    error = OSError(errno.ENOSPC, "No space left on device")
    error.errno = errno.ENOSPC
    raise error


def append_probe(store: GraphStore, *, label: str) -> dict[str, Any]:
    node_id = content_id("nod", "resilience", label)
    node = graph_node(
        node_id=node_id,
        node_type="CoverageCell",
        run_id=str(store.stream.get("run_id") or "run_01J00000000000000000000001"),
        created_at="2026-08-15T00:00:00Z",
        source_locator=f"resilience:{label}",
        properties=[typed_property("label", label, "string")],
    )
    sealed = seal(node)
    command = AppendCommand(
        f"resilience:{node_id}",
        (AppendItem("graph-node@1.0.0", "node.created", sealed),),
        {node_id: 0},
        ACTOR,
        CONFIG_HASH or ZERO_HASH,
        "1.0.0",
        created_at="2026-08-15T00:00:00Z",
    )
    return store.append(command)


def simulate_disk_full(store: GraphStore, write_all: Callable[..., Any]) -> dict[str, Any]:
    """Replace journal writes with ENOSPC and confirm the store stays recoverable."""

    def boom(fd: int, payload: bytes) -> None:
        _ = fd
        _ = payload
        raise GraphError(
            RESOURCE_EXHAUSTED,
            "journal append failed: disk full",
            retryable=True,
            details={"errno": int(errno.ENOSPC)},
        )

    original = write_all
    from ayran.graph import journal as journal_mod

    journal_mod.write_all = boom  # type: ignore[attr-defined]
    try:
        try:
            append_probe(store, label="disk-full")
            return {"degraded": False, "recovered": False, "error": None}
        except GraphError as error:
            if error.code != RESOURCE_EXHAUSTED:
                raise
            return {"degraded": True, "recovered": False, "error": error.as_dict()}
    finally:
        journal_mod.write_all = original  # type: ignore[attr-defined]
