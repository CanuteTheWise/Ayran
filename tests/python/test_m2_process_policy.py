"""M2 supervisor, artifact store, scope, and reconcile tests."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skills" / "ayran" / "src"))

import pytest
from ayran.artifacts.store import ArtifactStore
from ayran.graph.errors import GraphError
from ayran.policy.permissions import Authority, PolicyEngine
from ayran.policy.scope import ScopeManifest

_HASH_ZERO = "sha256:" + "0" * 64


def _actor() -> dict[str, Any]:
    return {"kind": "test", "id": "operator-m2"}


# ---------- artifact store ----------


def test_artifact_store_two_roundtrip_idempotent(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts", allow_unsafe_filesystem=True)
    payload = b"hello artifacts"
    first = store.store(payload)
    second = store.store(payload)
    assert first["content_hash"] == second["content_hash"]
    assert second["deduplicated"] is True


def test_artifact_store_secret_scan_blocks_write(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts", allow_unsafe_filesystem=True)
    with pytest.raises(GraphError) as raised:
        store.store(b"-----BEGIN RSA PRIVATE KEY-----\nsome-bytes\n")
    assert raised.value.code == "ARTIFACT_MISSING"


# ---------- scope ----------


def _manifest_value() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "scope_id": "id_2GG3Z4HQ1MB6AJTAR0JSCR3AGZ",
        "created_at": "2026-08-13T00:00:00Z",
        "run_id": "run_2GG3Z4HQ1MB6AJTAR0JSCR3AGZ",
        "revision": 1,
        "target_identity": {
            "target_id": "tgt_2GG3Z4HQ1MB6AJTAR0JSCR3AGZ",
            "source_tree_hash": "sha256:" + "9" * 64,
            "scope_id": "id_2GG3Z4HQ1MB6AJTAR0JSCR3AGZ",
        },
        "included_roots": ["src", "test"],
        "excluded_roots": ["src/internal/private"],
        "deployments": [],
        "chains": [],
        "fork_blocks": [],
        "rules": [
            {"rule_id": "id_2GG3Z4HQ1MB6AJTAR0JSCR3AGZ", "effect": "allow", "action": "read_source", "resource": "src"},
            {"rule_id": "id_2GG3Z4HQ1MB6AJTAR0JSCR3AH0", "effect": "deny", "action": "read_source", "resource": "src/internal/private"},
        ],
        "deny_overrides": True,
        "allowed_hosts": [],
        "allowed_endpoints": [],
        "allowed_tools": [],
        "write_roots": ["."],
        "secret_aliases": [],
        "budgets": {"wall_minutes": 60, "token_units": 1000, "tool_seconds": 600, "disk_mib": 1024},
        "approval_rules": [
            {"action_class": "install_tool", "approval": "explicit-human"},
            {"action_class": "add_endpoint", "approval": "explicit-human"},
            {"action_class": "expand_scope", "approval": "explicit-human"},
            {"action_class": "external_upload", "approval": "explicit-human"},
            {"action_class": "submission", "approval": "explicit-human"},
            {"action_class": "signing", "approval": "explicit-human"},
            {"action_class": "spending", "approval": "explicit-human"},
            {"action_class": "transaction_broadcast", "approval": "explicit-human"},
        ],
        "authorization": {
            "approved_by": {"kind": "human", "id": "operator", "version": "1.0.0"},
            "approved_scope_hash": "sha256:" + "1" * 64,
            "approved_at": "2026-08-13T00:00:00Z",
        },
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
        "provenance": [
            {
                "provenance_id": "id_2GG3Z4HQ1MB6AJTAR0JSCR3AGZ",
                "source_uri": "git+https://example.com/a.git",
                "source_version": "1.0.0",
                "raw_hash": "sha256:" + "8" * 64,
                "retrieved_at": "2026-08-13T00:00:00Z",
                "license_or_terms": "MIT",
                "transformation_lineage": ["sha256:" + "7" * 64],
            }
        ],
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": "sha256:" + "0" * 64,
            "excluded_fields": ["integrity.content_hash"],
        },
    }


def test_scope_manifest_deny_wins_over_allow() -> None:
    scope = ScopeManifest(_manifest_value())
    allowed = scope.evaluate("read_source", "src/app.py")
    denied = scope.evaluate("read_source", "src/internal/private/secret.py")
    assert allowed.allowed is True
    assert denied.allowed is False


def test_scope_manifest_hash_is_canonical_and_revision_bound() -> None:
    scope = ScopeManifest(_manifest_value())
    value = dict(_manifest_value())
    value["revision"] = 2
    other = ScopeManifest(value)
    assert scope.hash != other.hash


def test_policy_engine_unknown_action_is_forbidden() -> None:
    engine = PolicyEngine(None, config=type("C", (), {"offline": False})())
    decision = engine.authorize("burn_the_world")
    assert decision.authority == Authority.FORBIDDEN


def test_policy_engine_no_scope_fail_closed() -> None:
    engine = PolicyEngine(None, config=type("C", (), {"offline": False})())
    decision = engine.authorize("read_source")
    assert decision.permitted is False
