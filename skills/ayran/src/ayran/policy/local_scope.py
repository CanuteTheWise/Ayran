"""Build a valid scope envelope from in-scope relative roots.

The JSON schema stays strict. Operators do not have to author approval_rules,
integrity, or identifier fields. Those exist for the sidecar, not the model.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ayran.graph.canonical import canonical_hash
from ayran.graph.ids import new_id
from ayran.policy.scope import _ACTION_ENUM, _normalize_rel, ScopeError

_HUMAN_CLASSES = (
    "install_tool",
    "add_endpoint",
    "expand_scope",
    "external_upload",
    "submission",
    "signing",
    "spending",
    "transaction_broadcast",
)

_ZERO_HASH = "sha256:" + ("0" * 64)
_PLACEHOLDER_COMMIT = "1111111111111111111111111111111111111111"


def parse_roots(raw: str) -> list[str]:
    parts = [item.strip().replace("\\", "/") for item in raw.split(",") if item.strip()]
    if not parts:
        raise ScopeError("at least one in-scope relative root is required.")
    seen: list[str] = []
    for part in parts:
        normalized = _normalize_rel(part) or "."
        if normalized not in seen:
            seen.append(normalized)
    return seen


_LAYOUT_DIRS = ("src", "contracts", "target/src", "target/contracts")
_SKIP_DIR_NAMES = {
    ".git",
    ".github",
    ".prime",
    ".ayran",
    ".venv",
    "node_modules",
    "out",
    "cache",
    "lib",
    "broadcast",
    "artifacts",
    "typechain-types",
    "coverage",
    "snapshots",
    "reports",
    "dist",
    "build",
    "output",
    "__pycache__",
    "foundry-cache",
}


def detect_excluded_roots(cwd: Path) -> list[str]:
    """Junk / tool-output dirs that exist beside the target. Foundry/Slither live on PATH, not here."""

    root = cwd.expanduser().resolve(strict=False)
    found: list[str] = []
    for name in sorted(_SKIP_DIR_NAMES):
        if (root / name).exists():
            found.append(name.replace("\\", "/"))
    return found


def detect_local_roots(cwd: Path) -> list[str]:
    """Infer in-scope folders from a Solidity/Foundry layout. Never asks the model.

    Prefers ``src`` / ``contracts``. Ignores notes, reports, and compiler output.
    Falls back to ``.`` only when Solidity sits at the workspace root; excluded
    dirs still keep ``out/``, ``lib/``, and similar out of mapped reads.
    """

    root = cwd.expanduser().resolve(strict=False)
    found: list[str] = []
    for rel in _LAYOUT_DIRS:
        if (root / rel).is_dir():
            found.append(rel.replace("\\", "/"))
    if found:
        return found
    nearby: list[str] = []
    for pattern in ("*.sol", "*/*.sol"):
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            parent = path.parent
            if parent == root:
                rel_dir = "."
            else:
                rel_dir = parent.relative_to(root).as_posix()
            top = rel_dir.split("/", 1)[0]
            if top in _SKIP_DIR_NAMES:
                continue
            if rel_dir not in nearby:
                nearby.append(rel_dir)
            if len(nearby) >= 8:
                break
        if len(nearby) >= 8:
            break
    return nearby or ["."]



def local_scope_manifest(
    roots: list[str],
    *,
    run_id: str | None = None,
    valid_days: int = 30,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Full schema document: local audit actions on ``roots``, human gate on spend/sign/broadcast."""

    included = parse_roots(",".join(str(item) for item in roots))
    excluded = [
        item
        for item in (detect_excluded_roots(cwd) if cwd is not None else [])
        if item not in included and item != "."
    ]
    now = datetime.now(UTC)
    created = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
    until = (now + timedelta(days=max(1, valid_days))).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    scope_id = new_id("scp")
    target_id = new_id("tgt")
    run = run_id or new_id("run")
    rules: list[dict[str, str]] = []
    for root in included:
        for action in sorted(_ACTION_ENUM):
            rules.append(
                {
                    "rule_id": new_id("rul"),
                    "effect": "allow",
                    "action": action,
                    "resource": root,
                }
            )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "scope_id": scope_id,
        "created_at": created,
        "run_id": run,
        "revision": 1,
        "target_identity": {
            "commit": _PLACEHOLDER_COMMIT,
            "scope_id": scope_id,
            "source_tree_hash": canonical_hash({"roots": included}),
            "target_id": target_id,
        },
        "included_roots": included,
        "excluded_roots": excluded,
        "deployments": [],
        "chains": [],
        "fork_blocks": [],
        "rules": rules,
        "deny_overrides": True,
        "allowed_hosts": [],
        "allowed_endpoints": [],
        "allowed_tools": [],
        "write_roots": ["run/work"],
        "secret_aliases": [],
        "budgets": {
            "disk_mib": 8192,
            "token_units": 100000,
            "tool_seconds": 7200,
            "wall_minutes": 240,
        },
        "approval_rules": [
            {"action_class": name, "approval": "explicit-human"} for name in _HUMAN_CLASSES
        ],
        "authorization": {
            "approved_at": created,
            "approved_by": {"id": "operator", "kind": "human", "version": "1.0.0"},
            "approved_scope_hash": _ZERO_HASH,
        },
        "valid_from": created,
        "valid_until": until,
        "provenance": [
            {
                "license_or_terms": "operator-local-roots",
                "provenance_id": new_id("prv"),
                "raw_hash": canonical_hash({"roots": included}),
                "retrieved_at": created,
                "source_uri": "https://ayran.local/scope/operator-roots",
                "source_version": "1.0.0",
                "transformation_lineage": [],
            }
        ],
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "rfc8785",
            "content_hash": _ZERO_HASH,
            "excluded_fields": ["integrity.content_hash"],
        },
    }
    return payload
