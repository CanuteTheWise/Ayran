"""Per-project engagement pin: one Target Graph per protocol folder.

The pin (``.ayran/engagement.json``) lives in the project. Authoritative
journals stay on ext4: either ``<cwd>/.ayran/state`` when the project itself
is ext4, or ``~/.local/state/ayran`` when the clone is on DrvFS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ayran.graph.canonical import utc_now
from ayran.graph.errors import GraphError
from ayran.graph.namespaces import require_ext4
from ayran.runtime.paths import default_state_root, run_root

PIN_RELATIVE = Path(".ayran") / "engagement.json"


def pin_path(cwd: Path) -> Path:
    return cwd.expanduser().resolve(strict=False) / PIN_RELATIVE


def is_ext4(path: Path, *, allow_unsafe_filesystem: bool = False) -> bool:
    try:
        require_ext4(path, allow_unsafe_filesystem=allow_unsafe_filesystem)
    except GraphError:
        return False
    return True


def project_holds_graph(cwd: Path, *, allow_unsafe_filesystem: bool = False) -> bool:
    """True when journals may live under ``<cwd>/.ayran/state``."""

    if allow_unsafe_filesystem:
        return True
    return is_ext4(cwd, allow_unsafe_filesystem=False)


def resolve_state_root(
    cwd: Path,
    *,
    explicit: Path | None = None,
    fallback: Path | None = None,
    allow_unsafe_filesystem: bool = False,
) -> Path:
    if explicit is not None:
        return explicit.expanduser().resolve(strict=False)
    resolved_cwd = cwd.expanduser().resolve(strict=False)
    if project_holds_graph(resolved_cwd, allow_unsafe_filesystem=allow_unsafe_filesystem):
        return (resolved_cwd / ".ayran" / "state").resolve(strict=False)
    return (fallback or default_state_root()).expanduser().resolve(strict=False)


def load_pin(cwd: Path) -> dict[str, Any] | None:
    path = pin_path(cwd)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    run_id = str(payload.get("run_id") or "")
    state = str(payload.get("state_root") or "")
    if not run_id.startswith("run_") or not state:
        return None
    return payload


def write_pin(cwd: Path, *, run_id: str, state_root: Path, run_root_path: Path) -> Path:
    dest = pin_path(cwd)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "state_root": str(state_root),
        "run_root": str(run_root_path),
        "graph_root": str(run_root_path / "graph"),
        "updated_at": utc_now(),
    }
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return dest


def existing_run_root(pin: dict[str, Any]) -> Path | None:
    state = Path(str(pin["state_root"]))
    run_id = str(pin["run_id"])
    base = run_root(state, run_id)
    if (base / "stream.json").is_file() and (base / "graph").is_dir():
        return base
    return None
