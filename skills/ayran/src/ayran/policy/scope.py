"""Scope manifest loading, canonical hashing, and deterministic action checks.

Deny rules always override allows.  Unknown or ambiguous paths are denied.
This module enforces the compiled, immutable scope at the M2 boundary; a later
milestone adds signed scope revisions and approval binding.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ayran.api.validators import ContractValidationError, validate_contract
from ayran.graph.canonical import canonical_hash, strict_json_loads, utc_now
from ayran.graph.errors import CONTRACT_INVALID, GraphError

SCOPE_DENIED = "SCOPE_DENIED"

_ACTION_ENUM = {
    "read_source",
    "read_spec",
    "graph_read",
    "graph_write",
    "compile_local",
    "test_local",
    "fuzz_local",
    "read_only_rpc",
    "approved_api_query",
    "render_local_report",
}


class ScopeError(GraphError):
    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(SCOPE_DENIED, message, retryable=False, details=details)


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    action: str
    resource: str
    allowed: bool
    reason: str
    scope_hash: str
    scope_revision: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "resource": self.resource,
            "allowed": self.allowed,
            "reason": self.reason,
            "scope_hash": self.scope_hash,
            "scope_revision": self.scope_revision,
        }


def _normalize_rel(root: str) -> str:
    value = root.replace("\\", "/").strip()
    if value.startswith("/"):
        raise ScopeError(
            "scope roots must be relative to the target root, not absolute.",
            details={"root": root},
        )
    normalized = os.path.normpath(value).replace("\\", "/")
    if normalized == ".":
        return ""
    if normalized.startswith("..") or "\x00" in normalized:
        raise ScopeError(
            "scope roots may not contain traversal, NUL, or ambiguous characters.",
            details={"root": root, "normalized": normalized},
        )
    return normalized


class ScopeManifest:
    """A validated, canonical-hash-pinned scope manifest with deny-wins checks."""

    def __init__(self, value: dict[str, Any]) -> None:
        value = dict(value)
        placeholder = value.get("integrity", {}).get("content_hash")
        if placeholder == "sha256:" + "0" * 64:
            # Manifests are hashed canonically after applying excluded fields.
            integrity = dict(value.get("integrity", {}))
            excluded = tuple(str(path) for path in integrity.get("excluded_fields", ()))
            value["integrity"] = integrity
            value["integrity"]["content_hash"] = canonical_hash(value, exclude=excluded)
        try:
            validate_contract("scope-manifest", value)
        except ContractValidationError as error:
            raise GraphError(CONTRACT_INVALID, "scope manifest failed contract validation.") from error
        if value.get("deny_overrides") is not True:
            raise GraphError(
                CONTRACT_INVALID,
                "scope manifest must declare deny_overrides=true.",
            )
        self.value = value
        self.scope_id = str(value["scope_id"])
        self.revision = int(value["revision"])
        self.run_id = str(value["run_id"])
        self.hash = canonical_hash(value)
        self.included_roots = sorted({_normalize_rel(root) for root in value["included_roots"]})
        self.excluded_roots = sorted({_normalize_rel(root) for root in value.get("excluded_roots", [])})
        self.write_roots = sorted({_normalize_rel(root) for root in value["write_roots"]})
        self.allowed_hosts = frozenset(value.get("allowed_hosts", []))
        self.allowed_endpoints = frozenset(value.get("allowed_endpoints", []))
        self.allowed_tools = frozenset(value.get("allowed_tools", []))
        self.secret_aliases = frozenset(value.get("secret_aliases", []))
        self.rules = tuple(value["rules"])
        self.valid_from = str(value["valid_from"])
        self.valid_until = str(value["valid_until"])

    def _temporally_valid(self, now: str) -> bool:
        return self.valid_from <= now <= self.valid_until

    def _resource_under_roots(self, resource: str, roots: list[str]) -> bool:
        normalized = _normalize_rel(resource)
        for root in roots:
            if not root:
                return True
            if normalized == root or normalized.startswith(root + "/"):
                return True
        return False

    def evaluate(self, action: str, resource: str, *, now: str | None = None) -> ScopeDecision:
        """Return a deterministic allow/deny decision for one action+resource.

        Deny always wins.  Unknown actions are denied.  Path-bearing actions
        additionally check included/excluded roots.
        """

        now = now or utc_now()
        if action not in _ACTION_ENUM:
            return ScopeDecision(action, resource, False, "unknown action class", self.hash, self.revision)
        if not self._temporally_valid(now):
            return ScopeDecision(action, resource, False, "scope validity interval elapsed", self.hash, self.revision)

        denied = False
        allowed = False
        matched_rule: str | None = None
        for rule in self.rules:
            if rule["action"] != action:
                continue
            pattern = _normalize_rel(str(rule["resource"]))
            if pattern and not (resource == pattern or resource.startswith(pattern + "/")):
                continue
            matched_rule = str(rule["rule_id"])
            if rule["effect"] == "deny":
                denied = True
                allowed = False
                break
            if rule["effect"] == "allow":
                allowed = True

        if denied:
            return ScopeDecision(action, resource, False, f"denied by rule {matched_rule}", self.hash, self.revision)
        if not allowed:
            return ScopeDecision(action, resource, False, "no allow rule matched", self.hash, self.revision)

        if action in {"read_source", "read_spec", "compile_local", "test_local", "fuzz_local", "render_local_report"}:
            if not self._resource_under_roots(resource, self.included_roots):
                return ScopeDecision(action, resource, False, "resource outside included_roots", self.hash, self.revision)
            if self._resource_under_roots(resource, self.excluded_roots):
                return ScopeDecision(action, resource, False, "resource under excluded_roots", self.hash, self.revision)

        return ScopeDecision(action, resource, True, "allowed", self.hash, self.revision)


def load_scope(path: Path) -> ScopeManifest:
    """Read and validate one scope manifest from JSON."""

    raw = path.read_bytes()
    value = strict_json_loads(raw)
    if not isinstance(value, dict):
        raise GraphError(CONTRACT_INVALID, "scope manifest file must be a single JSON object.")
    return ScopeManifest(value)
