"""Doctor / compatibility check against prime-lock and platform-lock facts.

Startup compares facts, not display strings: Prime version/commit, kernel
class, Python version, filesystem type for the state root, free disk, memory
headroom, and the allowlisted capability probes.  The output reports which
specific invariant failed; incompatibility fails closed.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

from ayran.graph.namespaces import require_ext4

_ROOT_LOCK = Path(__file__).resolve().parents[4] / "compatibility"


def _load_lock(name: str) -> dict[str, Any]:
    path = _ROOT_LOCK / f"{name}.json"
    if not path.is_file():
        return {"passed": False, "error": f"compatibility lock {name}.json is missing"}
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _probe(command: list[str], timeout: int = 10) -> dict[str, Any]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout.strip()[:512],
        }
    except (OSError, subprocess.TimeoutExpired):
        return {"ok": False, "returncode": None, "stdout": ""}


def check_compatibility(config) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    prime = _load_lock("prime-lock")
    platform_lock = _load_lock("platform-lock")

    checks: dict[str, Any] = {
        "prime_lock_present": prime.get("passed") is not False,
        "platform_lock_present": platform_lock.get("passed") is not False,
        "state_root_ext4": False,
        "kernel_wsl2": False,
        "python_version_in_range": False,
        "memory_headroom_ok": False,
        "free_disk_ok": False,
        "uv_present": False,
        "findmnt_present": False,
        "bubblewrap_present": False,
        "docker_present": False,
        "sock_dir_0o700": False,
        "prime_version_or_commit": False,
        "non_blocking_warnings": [],
    }

    try:
        require_ext4(Path(config.state_root))
        checks["state_root_ext4"] = True
    except Exception:
        checks["non_blocking_warnings"].append("state_root_ext4 did not resolve to ext4")

    # Kernel class.
    if "microsoft-standard-WSL2" in platform.release():
        checks["kernel_wsl2"] = True

    python_version = platform.python_version_tuple()
    checks["python_version_in_range"] = (3, 11) <= tuple(map(int, python_version[:2])) < (3, 15)

    try:
        meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
        total_kib = next(
            int(line.split()[1]) for line in meminfo.splitlines() if line.startswith("MemTotal:")
        )
        checks["memory_headroom_ok"] = total_kib >= 4_096_000
    except (OSError, StopIteration, ValueError):
        checks["non_blocking_warnings"].append("/proc/meminfo could not be read")

    try:
        volume = shutil.disk_usage(Path(config.state_root))
        checks["free_disk_ok"] = volume.free >= int(config.min_free_disk_mib) * 1024 * 1024
    except OSError:
        checks["non_blocking_warnings"].append("disk usage could not be probed")

    checks["uv_present"] = _probe(["uv", "--version"])["ok"]
    checks["findmnt_present"] = _probe(["findmnt", "--version"])["ok"]
    checks["bubblewrap_present"] = _probe(["bwrap", "--version"])["ok"]
    checks["docker_present"] = _probe(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"], timeout=8
    )["ok"]

    sock_dir = Path(config.state_root) / "runtime"
    try:
        sock_dir.mkdir(parents=True, exist_ok=True)
        sock_dir.chmod(0o700)
        checks["sock_dir_0o700"] = (sock_dir.stat().st_mode & 0o777) == 0o700
    except OSError:
        checks["non_blocking_warnings"].append("could not inspect socket runtime dir mode")

    required_version = str(prime.get("package", {}).get("version", ""))
    required_commit = str(prime.get("upstream", {}).get("release_commit", ""))
    observed = config.tools.get("prime", "")
    checks["prime_version_or_commit"] = observed in {required_version, required_commit}

    all_passed = all(
        value is True for key, value in checks.items() if key not in {"non_blocking_warnings"}
    )
    checks["all_passed"] = all_passed
    return checks
