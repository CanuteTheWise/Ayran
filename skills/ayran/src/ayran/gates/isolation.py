"""Challenger/rlm() isolation verification (spec §11.2). Fail-closed.

Each deployment mode ships a probe asserting: (i) process boundary facts are
recorded; (ii) the challenger context has NO write access to the state root —
its only writable surface is the sidecar-owned spool directory OUTSIDE the
state root and outside included_roots; (iii) no direct sidecar socket access
beyond the declared client credential (exactly one ``gate_a_submission``
grant). The probe runs at startup AND before the first cognitive call; failure
is fail-closed: cognitive methods refuse with ``ISOLATION_UNVERIFIED`` until a
passing probe exists. Degraded fallback (§11.2 + §5.5): the challenger runs as
a separate short-lived headless session whose verbs reduce to read-only target
access via an operator-provided path copy; its verdict lands in the spool
directory mode 0600 and the spool file's transcript hash is bound into the
sealed record.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

ISOLATION_GRANT = "gate_a_submission"
ISOLATION_CHANNELS = frozenset({"subprocess", "headless_session"})


def verify_isolation(
    *,
    state_root: Path | str,
    spool_root: Path | str,
    included_roots: list[str] | None = None,
    transport_facts: dict[str, Any] | None = None,
    credential_grants: list[str] | None = None,
    tampered: bool = False,
) -> dict[str, Any]:
    """Run the fail-closed isolation probe and return its report."""

    refusals: list[str] = []
    transport = dict(transport_facts or {})
    facts: dict[str, Any] = {
        "state_root": str(state_root),
        "spool_root": str(spool_root),
        "included_roots": [str(item) for item in (included_roots or [])],
        "transport": transport,
        "credential_grants": [str(item) for item in (credential_grants or [])],
    }
    if tampered:
        refusals.append("isolation tamper flag set: process boundary cannot be trusted")

    # (i) Process boundary facts recorded, and the challenger really runs in a
    # separate short-lived process (subprocess or headless session).
    if not transport.get("channel"):
        refusals.append("process boundary facts missing: no transport channel recorded")
    elif str(transport["channel"]) not in ISOLATION_CHANNELS:
        refusals.append(
            f"challenger channel {transport['channel']!r} is not an isolated process boundary"
        )

    # (ii) NO write access to the state root from the challenger context: its
    # only writable surface (the spool root) must live outside the state root
    # and outside every included root.
    try:
        spool = Path(spool_root).resolve()
        state = Path(state_root).resolve()
    except OSError:
        refusals.append("state or spool root is unresolvable")
    else:
        if state == spool or state in spool.parents or spool in state.parents:
            refusals.append("spool root must live OUTSIDE the state root")
        for raw in included_roots or []:
            try:
                included = Path(str(raw)).resolve()
            except OSError:
                continue
            if included == spool or included in spool.parents:
                refusals.append("spool root must live outside included_roots")
    if transport.get("state_root_writable") is True:
        refusals.append("challenger context must not hold write access to the state root")

    # (iii) No direct sidecar socket access beyond the declared client
    # credential: exactly the single-submission grant, nothing broader.
    grants = {str(item) for item in (credential_grants or [])}
    if ISOLATION_GRANT not in grants:
        refusals.append(
            f"challenger credential must declare the {ISOLATION_GRANT!r} grant"
        )
    if grants - {ISOLATION_GRANT}:
        refusals.append(
            f"challenger credential grants exceed the declared client scope: {sorted(grants - {ISOLATION_GRANT})}"
        )
    if transport.get("has_sidecar_socket") is True:
        refusals.append("challenger context must not hold direct sidecar socket access")

    verified = not refusals
    mode = (
        "degraded_headless"
        if transport.get("channel") == "headless_session"
        else "verified_subprocess"
    )
    return {
        "schema_version": "1.0.0",
        "verified": verified,
        "mode": mode,
        "facts": facts,
        "refusals": refusals,
    }


def degraded_headless_facts(
    *, target_copy_root: Path | str, has_sidecar_socket: bool = False
) -> dict[str, Any]:
    """Transport facts for the degraded mode: a separate short-lived headless
    session whose verbs reduce to read-only target access via an
    operator-provided path copy."""

    return {
        "channel": "headless_session",
        "verbs": ["read_target_copy"],
        "target_copy_root": str(target_copy_root),
        "writable_roots": [],
        "has_sidecar_socket": has_sidecar_socket,
    }
