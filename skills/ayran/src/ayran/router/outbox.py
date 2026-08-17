"""Outbox helpers: pending graph events become router inputs without mutating SQLite."""

from __future__ import annotations

from typing import Any

from ayran.context.ids import ROUTER_SEED_EVENT, content_id

_ID_PREFIX = "evt_"


def pending_event_ids(view_actions: list[dict[str, Any]], cursor: int) -> list[str]:
    """Deterministic stand-in for outbox drain: valid Identifier event ids only."""

    seen: list[str] = []
    for action in sorted(view_actions, key=lambda row: str(row.get("router_action_id") or "")):
        for event_id in action.get("triggering_event_ids") or []:
            token = str(event_id)
            if token.startswith(_ID_PREFIX) and token not in seen:
                seen.append(token)
    if not seen:
        seen.append(content_id("evt", "cursor", str(cursor)) if cursor else ROUTER_SEED_EVENT)
    return seen
