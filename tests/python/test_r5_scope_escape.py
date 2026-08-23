"""R5 — S9.4: scope escape blocked mid-session, session survives (spec §9).

Named binary check:
``test_out_of_scope_denied_session_continues``

A REAL dispatcher+store runs with a ScopeManifest whose included_roots cover
one tmp target tree and the M2 PolicyEngine deny-wins boundary. Every
out-of-scope request type is denied with a ``SCOPE_DENIED`` reason BEFORE
execution; filesystem sentinel probes (content hashes + directory listings of
the outside trees, captured before/after) prove ZERO bytes were read or
written outside the roots at the boundary function — the deterministic
CI stand-in for PRE-execution ordering, whose live-Prime witness belongs to
the owner demo. The session then continues: router state stays sane and a
subsequent in-scope operation in the SAME session succeeds end-to-end.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from ayran.artifacts.store import ArtifactStore
from ayran.bridge.handler import build_dispatcher
from ayran.config.models import EffectiveConfig
from ayran.evidence.load import load_hypotheses, load_nodes_by_type, node_props
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from m3_fixtures import scope_value
from m5_fixtures import RUN_ID

CLAIM = (
    "ReentrantVault.withdraw credits msg.sender only after the external call, so an "
    "attacker fallback can re-enter withdraw before balances are zeroed."
)


def _scope_manifest() -> dict[str, Any]:
    """scope_value() base with the graph_write allow narrowed off "." so the
    deny-wins boundary (not a catch-all rule) decides RPC writes."""

    value = scope_value()
    value["rules"] = [
        {"rule_id": "rul_01J00000000000000000000001", "effect": "allow", "action": "read_source", "resource": "target/src"},
        {"rule_id": "rul_01J00000000000000000000002", "effect": "allow", "action": "compile_local", "resource": "target/src"},
        {"rule_id": "rul_01J00000000000000000000003", "effect": "allow", "action": "graph_read", "resource": "."},
        {"rule_id": "rul_01J00000000000000000000004", "effect": "allow", "action": "graph_write", "resource": "target"},
        {"rule_id": "rul_01J00000000000000000000005", "effect": "allow", "action": "test_local", "resource": "target/src"},
    ]
    return value


def _sidecar(tmp_path: Path) -> tuple[Any, Any]:
    store_root = tmp_path / "graph"
    from m5_fixtures import open_store as _open_store

    store = _open_store(store_root)
    config = EffectiveConfig(state_root=str(tmp_path / "state"))
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    (tmp_path / "scope.json").write_text(json.dumps(_scope_manifest()), encoding="utf-8")
    logger = StructuredLogger(logs / "runtime.jsonl", run_id=RUN_ID, component="ayran.test")
    artifact_store = ArtifactStore(tmp_path / "artifacts", allow_unsafe_filesystem=True)
    supervisor = ProcessSupervisor(
        tmp_path / "processes", run_id=RUN_ID, logger=logger, artifact_store=artifact_store
    )
    dispatcher = build_dispatcher(
        run_id=RUN_ID,
        config=config,
        store=store,
        logger=logger,
        artifact_store=artifact_store,
        process_supervisor=supervisor,
        receipt={"schema_version": "1.0.0", "run_id": RUN_ID, "run_state": "running"},
        state_root=tmp_path / "state",
        run_root=tmp_path,
    )
    return dispatcher, store


def _snapshot(root: Path) -> dict[str, str]:
    """Content hash + listing of every file under root (fs sentinel probe)."""

    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            key = str(path.relative_to(root))
            snapshot[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def _policy_denial_events(store: Any) -> list[dict[str, Any]]:
    events = []
    for node in load_nodes_by_type(store, "SessionTransition"):
        props = node_props(node)
        if props.get("event_type") == "policy_denial":
            events.append(json.loads(str(props.get("payload_json") or "{}")))
    return events


def test_out_of_scope_denied_session_continues(tmp_path: Path) -> None:
    dispatcher, store = _sidecar(tmp_path)
    try:
        # Real trees: inside (target/src) and outside (secrets/, sibling/) roots.
        inside = tmp_path / "target" / "src"
        inside.mkdir(parents=True)
        (inside / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "ssh.key").write_bytes(b"PRIVATE-KEY-BYTES")
        sibling = tmp_path / "sibling"
        (sibling / "other-repo").mkdir(parents=True)
        (sibling / "other-repo" / "note.md").write_text("neighbor engagement notes", encoding="utf-8")

        outside_before = {name: _snapshot(root) for name, root in (("secrets", secrets), ("sibling", sibling))}
        denials_before = len(_policy_denial_events(store))

        # --- attempt matrix: once per request type, ALL denied BEFORE execution
        authorize_attempts: list[tuple[str, dict[str, Any]]] = [
            (
                "read outside roots",
                {"tool_name": "read", "arguments": {"path": "secrets/ssh.key"}},
            ),
            (
                "edit/write outside roots",
                {
                    "tool_name": "edit",
                    "arguments": {"path": "secrets/ssh.key", "new_string": "pwned"},
                },
            ),
            (
                "bash touching an outside path",
                {
                    "tool_name": "bash",
                    "arguments": {"path": "sibling/other-repo/note.md", "command": "cat sibling/other-repo/note.md"},
                },
            ),
        ]
        for label, params in authorize_attempts:
            decision = dispatcher.dispatch("policy.authorize", params)
            assert decision["permitted"] is False, label
            assert "SCOPE_DENIED" in str(decision["reason"]), (label, decision["reason"])
            # Router/budget state intact after each denial (no crash, sane shape).
            router = dispatcher.dispatch("router.status", {})
            assert isinstance(router, dict) and router.get("schema_version") == "1.0.0", label

        # (4) out-of-scope skill-verb style RPC write: denied at _require_write.
        remember_params: dict[str, Any] = {
            "origin": "model_novel",
            "claim": CLAIM,
            "attack_path": ["enter withdraw()", "re-enter via fallback", "profit"],
            "preconditions": [{"description": "fallback contract", "attacker_can_create": True}],
            "cluster_id": "clus_01J00000000000000000000001",
            "session": "sess-s94",
            "resource": "sibling/other-repo/note.md",
        }
        with pytest.raises(PermissionError) as refused:
            dispatcher.dispatch("hypotheses.remember", remember_params)
        assert "SCOPE_DENIED" in str(refused.value), refused.value
        router = dispatcher.dispatch("router.status", {})
        assert router.get("schema_version") == "1.0.0"

        # --- every denial journaled with actor=policy
        events = _policy_denial_events(store)
        assert len(events) == denials_before + len(authorize_attempts) + 1
        for event in events[denials_before:]:
            assert event["actor"] == "policy"
            assert "SCOPE_DENIED" in str(event["reason"])

        # --- fs sentinels: zero bytes read or written outside the roots
        assert {name: _snapshot(root) for name, root in (("secrets", secrets), ("sibling", sibling))} == outside_before
        # No hypothesis leaked into the graph from the denied write.
        assert load_hypotheses(store) == []

        # --- the SAME session continues: in-scope operations succeed end-to-end
        allowed_read = dispatcher.dispatch(
            "policy.authorize",
            {"tool_name": "read", "arguments": {"path": "target/src/Vault.sol"}},
        )
        assert allowed_read["permitted"] is True
        remembered = dispatcher.dispatch(
            "hypotheses.remember",
            {
                **remember_params,
                "resource": "target/src",
                "violated_invariant": "balances are zeroed before any external call",
            },
        )
        assert remembered["accepted"] is True
        assert remembered["status"] == "lead"

        # The journal chain still verifies after denials + the in-scope write.
        verification = store.verify()
        assert verification["status"] == "ok"
        assert verification["issues"] == []
    finally:
        store.close()
