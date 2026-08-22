"""R0 Truth Repair: lock-path resolution, registry truth, version alignment, pin provenance."""
from __future__ import annotations

import json
import shutil
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from ayran.compatibility import locks
from ayran.knowledge import source_registry
from ayran.release.paths import RELEASE_VERSION

ROOT = Path(__file__).resolve().parents[2]

PINNED_PRIME_COMMIT = "83a0f9f9566219551fcb6ffaf7f519a815749a58"
PINNED_PRIME_SHA256 = "bc5471f2a626d727b88a45eb745fff93b10c554a3c4fc5912f25d8c64b987f5e"
PINNED_PRIME_SIZE_BYTES = 9387295
PINNED_PRIME_VERSION = "0.7.2"


def test_find_compatibility_dir_resolves_authored_tree() -> None:
    compat = locks.find_compatibility_dir(Path(locks.__file__))
    assert compat == ROOT / "compatibility"
    prime = locks._load_lock("prime-lock")
    assert prime["upstream"]["release_commit"] == PINNED_PRIME_COMMIT


def test_find_compatibility_dir_resolves_installed_layout(tmp_path: Path) -> None:
    payload = tmp_path / "versions" / "0.1.6" / "ayran"
    payload_compat = payload / "compatibility"
    payload_compat.mkdir(parents=True)
    shutil.copyfile(ROOT / "compatibility" / "prime-lock.json", payload_compat / "prime-lock.json")
    shutil.copyfile(
        ROOT / "compatibility" / "platform-lock.json", payload_compat / "platform-lock.json"
    )
    deep_start = payload / "skills" / "ayran" / "src" / "ayran" / "compatibility"
    deep_start.mkdir(parents=True)
    assert locks.find_compatibility_dir(deep_start) == payload_compat


def test_find_compatibility_dir_missing_tree_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    start = tmp_path / "a" / "b" / "c"
    start.mkdir(parents=True)
    assert locks.find_compatibility_dir(start) is None
    monkeypatch.setattr(locks, "_ROOT_LOCK", None)
    unresolved = locks._load_lock("prime-lock")
    assert unresolved["passed"] is False
    assert "error" in unresolved
    monkeypatch.setattr(locks, "_ROOT_LOCK", tmp_path)
    missing = locks._load_lock("prime-lock")
    assert missing["passed"] is False
    assert "error" in missing


def test_fabricated_registry_entries_are_gone() -> None:
    registry = ROOT / "knowledge" / "registry"
    assert not (registry / "foundryvtt.yaml").exists()
    assert not (registry / "htsx.yaml").exists()
    olaradial = registry / "olaradial.yaml"
    assert olaradial.is_file()
    assert olaradial.stat().st_size > 0
    sources = source_registry.list_sources(ROOT / "knowledge")
    source_ids = {entry.source_id for entry in sources}
    assert "olaradial" in source_ids
    assert "foundryvtt" not in source_ids
    assert "htsx" not in source_ids


def test_version_alignment_authored_tree() -> None:
    compat = locks.find_compatibility_dir(Path(locks.__file__))
    assert compat is not None
    manifest_root = compat.parent
    package = json.loads((manifest_root / "package.json").read_text(encoding="utf-8"))
    project = tomllib.loads((manifest_root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert RELEASE_VERSION == "0.1.6"
    assert package["version"] == RELEASE_VERSION
    assert project["version"] == RELEASE_VERSION
    assert locks.versions_align(
        manifest_root / "package.json", manifest_root / "pyproject.toml", RELEASE_VERSION
    )


def test_version_alignment_synthetic_mismatch(tmp_path: Path) -> None:
    package_json = tmp_path / "package.json"
    pyproject_toml = tmp_path / "pyproject.toml"
    package_json.write_text(json.dumps({"version": "9.9.9"}), encoding="utf-8")
    pyproject_toml.write_text(
        '[project]\nname = "synthetic"\nversion = "0.1.6"\n', encoding="utf-8"
    )
    assert locks.versions_align(package_json, pyproject_toml, "0.1.6") is False
    package_json.write_text(json.dumps({"version": "0.1.6"}), encoding="utf-8")
    assert locks.versions_align(package_json, pyproject_toml, "0.1.6") is True
    assert locks.versions_align(tmp_path / "absent.json", pyproject_toml, "0.1.6") is False


def test_doctor_reports_lock_and_version_checks(tmp_path: Path) -> None:
    config = SimpleNamespace(state_root=tmp_path, min_free_disk_mib=1, tools={"prime": ""})
    checks = locks.check_compatibility(config)
    assert checks["prime_lock_present"] is True
    assert checks["platform_lock_present"] is True
    assert checks["version_alignment"] is True
    assert checks["prime_lock_provenance"] is True


def test_prime_lock_provenance_pins() -> None:
    lock = json.loads((ROOT / "compatibility" / "prime-lock.json").read_text(encoding="utf-8"))
    assert lock["upstream"]["release_commit"] == PINNED_PRIME_COMMIT
    assert lock["release_artifact"]["sha256"] == PINNED_PRIME_SHA256
    assert lock["release_artifact"]["size_bytes"] == PINNED_PRIME_SIZE_BYTES
    assert lock["package"]["version"] == PINNED_PRIME_VERSION
    assert locks.prime_lock_provenance(lock) is True
    tampered_commit = json.loads(json.dumps(lock))
    tampered_commit["upstream"]["release_commit"] = "0" * 40
    assert locks.prime_lock_provenance(tampered_commit) is False
    tampered_size = json.loads(json.dumps(lock))
    tampered_size["release_artifact"]["size_bytes"] = 1
    assert locks.prime_lock_provenance(tampered_size) is False
    tampered_version = json.loads(json.dumps(lock))
    tampered_version["package"]["version"] = "0.7.3"
    assert locks.prime_lock_provenance(tampered_version) is False
    assert locks.prime_lock_provenance({"passed": False, "error": "missing"}) is False


def test_prime_lock_provenance_archive_is_conditional(tmp_path: Path) -> None:
    lock = json.loads((ROOT / "compatibility" / "prime-lock.json").read_text(encoding="utf-8"))
    absent = tmp_path / "prime-agent-0.7.2.tgz"
    assert locks.prime_lock_provenance(lock, absent) is True
    wrong_bytes = tmp_path / "wrong.tgz"
    wrong_bytes.write_bytes(b"not the pinned archive")
    assert locks.prime_lock_provenance(lock, wrong_bytes) is False
    cached = ROOT / "vendor" / "cache" / "prime-agent-0.7.2.tgz"
    if cached.is_file():
        assert locks.prime_lock_provenance(lock, cached) is True
