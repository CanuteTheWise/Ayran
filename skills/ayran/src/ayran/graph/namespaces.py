"""Target, immutable Global release, and quarantined Learning namespace layouts."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from .canonical import (
    atomic_write,
    canonical_hash,
    canonical_line,
    fsync_directory,
    utc_now,
    write_all,
)
from .errors import NAMESPACE_MISMATCH, GraphError
from .ids import new_id


def require_ext4(path: Path, *, allow_unsafe_filesystem: bool = False) -> None:
    """Fail closed unless authoritative state resolves to Linux/WSL ext4."""

    if allow_unsafe_filesystem:
        return
    if os.name == "nt":
        raise GraphError(
            NAMESPACE_MISMATCH,
            "Authoritative Graph Fabric state must be created inside WSL ext4.",
        )
    probe = path.resolve(strict=False)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    result = subprocess.run(
        ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(probe)],
        check=False,
        capture_output=True,
        text=True,
    )
    filesystem = result.stdout.strip()
    if result.returncode != 0 or filesystem != "ext4":
        raise GraphError(
            NAMESPACE_MISMATCH,
            "Authoritative Graph Fabric state requires ext4.",
            details={"filesystem": filesystem or "unknown"},
        )


def target_stream(
    run_id: str, target_identity: dict[str, Any], target_key: str, stream_id: str | None = None
) -> dict[str, Any]:
    return {
        "namespace": "target",
        "stream_id": stream_id or new_id("str"),
        "run_id": run_id,
        "target_identity": target_identity,
        "target_key": target_key,
    }


def global_stream(
    corpus_id: str,
    release_id: str,
    ontology_version: str,
    manifest_hash: str,
    stream_id: str | None = None,
) -> dict[str, Any]:
    return {
        "namespace": "global",
        "stream_id": stream_id or new_id("str"),
        "corpus_id": corpus_id,
        "release_id": release_id,
        "ontology_version": ontology_version,
        "manifest_hash": manifest_hash,
    }


def learning_stream(
    learning_id: str,
    *,
    origin_run_id: str | None = None,
    origin_target_key: str | None = None,
    stream_id: str | None = None,
) -> dict[str, Any]:
    return {
        "namespace": "learning",
        "stream_id": stream_id or new_id("str"),
        "learning_id": learning_id,
        "origin_run_id": origin_run_id,
        "origin_target_key": origin_target_key,
    }


class TargetNamespace:
    def __init__(
        self,
        run_root: Path,
        run_id: str,
        target_identity: dict[str, Any],
        target_key: str,
        *,
        stream_id: str | None = None,
        allow_unsafe_filesystem: bool = False,
    ) -> None:
        self.root = run_root / "target"
        require_ext4(self.root, allow_unsafe_filesystem=allow_unsafe_filesystem)
        self.root.mkdir(parents=True, exist_ok=True)
        self.stream = target_stream(run_id, target_identity, target_key, stream_id)


class LearningNamespace:
    def __init__(
        self,
        state_root: Path,
        learning_id: str,
        *,
        origin_run_id: str | None = None,
        origin_target_key: str | None = None,
        stream_id: str | None = None,
        allow_unsafe_filesystem: bool = False,
    ) -> None:
        self.root = state_root / "learning" / "quarantine"
        require_ext4(self.root, allow_unsafe_filesystem=allow_unsafe_filesystem)
        self.root.mkdir(parents=True, exist_ok=True)
        self.stream = learning_stream(
            learning_id,
            origin_run_id=origin_run_id,
            origin_target_key=origin_target_key,
            stream_id=stream_id,
        )

    @staticmethod
    def promote(*_: object, **__: object) -> None:
        raise GraphError(
            NAMESPACE_MISMATCH,
            "Learning data remains quarantined in M1; Global promotion belongs to M8.",
        )


class GlobalReleaseManager:
    """Build, verify, publish, and roll back immutable Global releases."""

    def __init__(
        self,
        global_root: Path,
        *,
        allow_unsafe_filesystem: bool = False,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.root = global_root
        require_ext4(self.root, allow_unsafe_filesystem=allow_unsafe_filesystem)
        self.releases = self.root / "releases"
        self.staging = self.root / "staging"
        self.current = self.root / "current.json"
        self.pointer_journal = self.root / "pointer-history.jsonl"
        self.fault_hook = fault_hook
        self.releases.mkdir(parents=True, exist_ok=True)
        self.staging.mkdir(parents=True, exist_ok=True)

    def create_staging(self, release_id: str) -> Path:
        path = self.staging / release_id
        if path.exists():
            raise GraphError(NAMESPACE_MISMATCH, "Global release staging root already exists.")
        path.mkdir(mode=0o700)
        fsync_directory(self.staging)
        return path

    def publish(
        self,
        staging_root: Path,
        release_id: str,
        manifest_hash: str,
        verify: Callable[[Path], bool],
    ) -> dict[str, Any]:
        resolved_staging = staging_root.resolve(strict=True)
        if resolved_staging.parent != self.staging.resolve(strict=True):
            raise GraphError(NAMESPACE_MISMATCH, "Global staging root is outside the manager.")
        if resolved_staging.name != release_id or not verify(resolved_staging):
            raise GraphError(NAMESPACE_MISMATCH, "Global release verification failed.")
        release = self.releases / release_id
        if release.exists():
            raise GraphError(NAMESPACE_MISMATCH, "Published Global releases are immutable.")
        os.replace(resolved_staging, release)
        fsync_directory(self.releases)
        pointer = self._switch(release_id, manifest_hash, "publish")
        if os.name != "nt":
            for path in sorted(release.rglob("*"), reverse=True):
                path.chmod(0o500 if path.is_dir() else 0o400)
            release.chmod(0o500)
        return pointer

    def rollback(self, release_id: str) -> dict[str, Any]:
        release = (self.releases / release_id).resolve(strict=True)
        if release.parent != self.releases.resolve(strict=True):
            raise GraphError(NAMESPACE_MISMATCH, "Rollback release is outside the release root.")
        manifest = release / "release.json"
        if manifest.is_file():
            value = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_hash = value.get("manifest_hash") or canonical_hash(value)
        else:
            manifest_hash = canonical_hash({"release_id": release_id})
        return self._switch(release_id, manifest_hash, "rollback")

    def _switch(self, release_id: str, manifest_hash: str, action: str) -> dict[str, Any]:
        previous: str | None = None
        if self.current.is_file():
            previous = json.loads(self.current.read_text(encoding="utf-8")).get("release_id")
        pointer = {
            "schema_version": "1.0.0",
            "pointer_id": new_id("ptr"),
            "action": action,
            "release_id": release_id,
            "manifest_hash": manifest_hash,
            "previous_release_id": previous,
            "switched_at": utc_now(),
        }
        atomic_write(
            self.current,
            canonical_line(pointer),
            fault_hook=self.fault_hook,
            fault_prefix="global_pointer",
        )
        fd = os.open(
            self.pointer_journal,
            os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            write_all(fd, canonical_line(pointer))
            os.fsync(fd)
        finally:
            os.close(fd)
        fsync_directory(self.root)
        return pointer

    def current_release(self) -> Mapping[str, Any] | None:
        if not self.current.is_file():
            return None
        return cast(Mapping[str, Any], json.loads(self.current.read_text(encoding="utf-8")))
