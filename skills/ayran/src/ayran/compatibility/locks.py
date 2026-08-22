"""Doctor / compatibility check against prime-lock and platform-lock facts.

Startup compares facts, not display strings: Prime version/commit, kernel
class, Python version, filesystem type for the state root, free disk, memory
headroom, and the allowlisted capability probes.  The output reports which
specific invariant failed; incompatibility fails closed.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any, cast

from ayran.graph.namespaces import require_ext4
from ayran.release.paths import RELEASE_VERSION


def find_compatibility_dir(start: Path) -> Path | None:
    """Nearest ancestor of ``start`` holding ``compatibility/prime-lock.json``.

    Works in both the authored tree (repo-root ``compatibility/``) and installed
    payload layouts (``<prefix>/versions/<version>/ayran/compatibility/``) without
    hardcoding a parents[] index. Returns None when no ancestor matches.
    """
    resolved = Path(start).resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / "compatibility" / "prime-lock.json").is_file():
            return candidate / "compatibility"
    return None


_ROOT_LOCK = find_compatibility_dir(Path(__file__))


def versions_align(package_json: Path, pyproject_toml: Path, expected: str) -> bool:
    """package.json and pyproject.toml project versions both equal ``expected``.

    Missing or unparsable manifests fail closed (False). Takes explicit paths so
    tests can exercise mismatches against synthetic trees.
    """
    try:
        package = json.loads(package_json.read_text(encoding="utf-8"))
        project = tomllib.loads(pyproject_toml.read_text(encoding="utf-8"))["project"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return bool(package.get("version") == expected and project.get("version") == expected)


_PRIME_LOCK_PINS: dict[str, Any] = {
    "release_commit": "83a0f9f9566219551fcb6ffaf7f519a815749a58",
    "sha256": "bc5471f2a626d727b88a45eb745fff93b10c554a3c4fc5912f25d8c64b987f5e",
    "size_bytes": 9387295,
    "package_version": "0.7.2",
}


def prime_lock_provenance(lock: dict[str, Any], archive: Path | None = None) -> bool:
    """The loaded prime-lock pins the exact Prime 0.7.2 release; anything else fails closed.

    When ``archive`` is given and exists, its sha256 must also match the pin;
    archive absence changes nothing.
    """
    if lock.get("passed") is False:
        return False
    if lock.get("upstream", {}).get("release_commit") != _PRIME_LOCK_PINS["release_commit"]:
        return False
    artifact = lock.get("release_artifact", {})
    if artifact.get("sha256") != _PRIME_LOCK_PINS["sha256"]:
        return False
    if artifact.get("size_bytes") != _PRIME_LOCK_PINS["size_bytes"]:
        return False
    if lock.get("package", {}).get("version") != _PRIME_LOCK_PINS["package_version"]:
        return False
    if archive is not None and archive.is_file():
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != _PRIME_LOCK_PINS["sha256"]:
            return False
    return True


def _load_lock(name: str) -> dict[str, Any]:
    if _ROOT_LOCK is None:
        return {"passed": False, "error": f"compatibility lock {name}.json is missing"}
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
        "version_alignment": False,
        "prime_lock_provenance": False,
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

    compat_dir = find_compatibility_dir(Path(__file__))
    if compat_dir is not None:
        manifest_root = compat_dir.parent
        checks["version_alignment"] = versions_align(
            manifest_root / "package.json", manifest_root / "pyproject.toml", RELEASE_VERSION
        )
        cached_archive = manifest_root / "vendor" / "cache" / "prime-agent-0.7.2.tgz"
        archive = cached_archive if cached_archive.is_file() else None
    else:
        archive = None
    checks["prime_lock_provenance"] = prime_lock_provenance(prime, archive)

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
