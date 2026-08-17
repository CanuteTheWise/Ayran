from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import stage_wsl

ROOT = Path(__file__).resolve().parents[2]


def test_layer_and_complete_enumeration_share_payload_and_only_complete_adds_prime() -> None:
    layer, _ = stage_wsl.enumerate_payload(ROOT, "layer")
    if not (ROOT / "vendor/cache/prime-agent-0.7.2.tgz").exists():
        pytest.skip("Complete-only Prime archive is intentionally absent from a Layer stage")
    complete, _ = stage_wsl.enumerate_payload(ROOT, "complete")
    layer_paths = {item["path"] for item in layer}
    complete_paths = {item["path"] for item in complete}
    assert complete_paths - layer_paths == {"vendor/cache/prime-agent-0.7.2.tgz"}
    assert not layer_paths - complete_paths
    assert "vendor/cache/prime-agent-0.7.2.tgz" not in layer_paths


@pytest.mark.parametrize("value", ["/absolute", "../parent", "path/../escape", "./relative"])
def test_manifest_path_guard_rejects_unsafe_paths(value: str) -> None:
    with pytest.raises(stage_wsl.StageError):
        stage_wsl.safe_relative(value)


def test_cleanup_refuses_unreceipted_stage_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(stage_wsl, "ext4_mount", lambda _: {"filesystem": "ext4"})
    base = tmp_path / "base"
    root = base / "ayran-m1-layer-0123456789abcdef"
    root.mkdir(parents=True)
    with pytest.raises(stage_wsl.StageError, match="receipt and marker"):
        stage_wsl.cleanup(root, base)
    assert root.is_dir()


def test_cleanup_removes_only_authenticated_exact_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(stage_wsl, "ext4_mount", lambda _: {"filesystem": "ext4"})
    base = tmp_path / "base"
    root = base / "ayran-m1-layer-0123456789abcdef"
    root.mkdir(parents=True)
    receipt = {
        "schema_version": "1.0.0",
        "receipt_type": "ayran-m1-stage",
        "distribution": "layer",
        "stage_name": root.name,
        "ownership": "entire-stage-root-created-by-this-receipt",
    }
    receipt_bytes = stage_wsl.json_bytes(receipt)
    (root / stage_wsl.ROOT_RECEIPT).write_bytes(receipt_bytes)
    (root / stage_wsl.ROOT_MARKER).write_text(
        hashlib.sha256(receipt_bytes).hexdigest() + "\n", encoding="ascii"
    )
    result = stage_wsl.cleanup(root, base)
    assert result["removed"] is True
    assert not root.exists()
    assert base.is_dir()


def test_plan_identity_serialization_is_stable() -> None:
    value = {"z": [2, 1], "a": {"x": True}}
    assert stage_wsl.json_bytes(value) == b'{"a":{"x":true},"z":[2,1]}\n'
    assert json.loads(stage_wsl.json_bytes(value)) == value
