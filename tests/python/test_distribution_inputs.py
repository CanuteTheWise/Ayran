from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((ROOT / relative).read_text(encoding="utf-8")))


def test_prime_identity_and_verified_artifact() -> None:
    lock = read("compatibility/prime-lock.json")
    vendor = read("vendor/manifests/prime-v0.7.2.json")
    assert lock["upstream"]["release_commit"] == "83a0f9f9566219551fcb6ffaf7f519a815749a58"
    assert lock["package"] == {
        "ecosystem": "npm",
        "name": "prime-agent",
        "version": "0.7.2",
        "artifact_type": "npm-package-tarball",
    }
    assert vendor["artifact"]["sha256"] == lock["release_artifact"]["sha256"]
    cached = ROOT / vendor["artifact"]["cache_path"]
    if cached.exists():
        assert hashlib.sha256(cached.read_bytes()).hexdigest() == vendor["artifact"]["sha256"]
    assert vendor["source_state"] == {"modified": False, "patches": [], "repacked": False}


def test_prime_license_notice_is_exactly_pinned() -> None:
    vendor = read("vendor/manifests/prime-v0.7.2.json")
    notice = ROOT / vendor["license"]["required_license_file"]
    assert hashlib.sha256(notice.read_bytes()).hexdigest() == vendor["license"]["sha256"]
    assert notice.read_text(encoding="utf-8").startswith("MIT License")


def test_layer_and_complete_share_identical_ayran_payload_but_different_prime_ownership() -> None:
    layer = read("packaging/manifests/layer.json")
    complete = read("packaging/manifests/complete.json")
    assert layer["ayran_payload"] == complete["ayran_payload"]
    assert layer["prime"]["mode"] == "external-compatible-peer"
    assert complete["prime"]["mode"] == "bundled-unmodified"
    assert layer["rollback_uninstall"]["remove_prime"] is False
    assert complete["rollback_uninstall"]["remove_external_prime"] is False
    assert complete["prime"]["required_license_file"] == "LICENSES/Prime-Agent-MIT.txt"


def test_platform_lock_never_binds_installables_to_user_or_distro() -> None:
    lock = read("compatibility/platform-lock.json")
    text = json.dumps(lock)
    assert re.search(r"[A-Za-z]:\\\\Users\\\\", text, re.IGNORECASE) is None
    assert re.search(r"/home/[^/]+/", text) is None
    assert lock["runtime"]["hardcoded_distribution"] is None
    assert lock["runtime"]["hardcoded_user_home"] is None
    assert lock["filesystem"]["staging_and_active_state_required"] == "wsl-ext4"


def test_external_tools_have_no_mutating_action() -> None:
    support = read("compatibility/tool-support.json")
    for tool in support["tools"]:
        assert tool["ownership"] == "external"
        assert set(tool["m0_actions"]) <= {"detect", "version-check"}
        assert {"copy", "install", "upgrade", "overwrite", "remove"} <= set(
            tool["forbidden_actions"]
        )
