"""M9 distribution: URL-closure, signing, Layer/Complete bundles, install/rollback."""

from __future__ import annotations

from pathlib import Path

import pytest
from ayran.release.bundle import build_bundle, validate_bundle
from ayran.release.install import install, plan_install, rollback, uninstall
from ayran.release.signing import sign_payload, verify_signature, write_signature
from ayran.release.url_closure import build_complete_deps
from m7_fixtures import invoke, payload
from m9_fixtures import ROOT


def test_url_closure_pins_every_url_without_indirection() -> None:
    first = build_complete_deps(ROOT)
    second = build_complete_deps(ROOT)
    assert first["content_hash"] == second["content_hash"]
    assert first["url_indirection"] is False
    assert first["unresolved"] == []
    assert first["createAgentSession_unblocked"] is True
    assert first["prime"]["commit"] == "83a0f9f9566219551fcb6ffaf7f519a815749a58"
    urls = [item.get("original_url") or item.get("resolved") for item in first["prime_packages"]]
    assert any(isinstance(item, str) and item.startswith("https://") for item in urls)
    for item in first["prime_packages"]:
        assert item["url_indirection"] is False
        assert item["sha256"]
        assert item.get("install_fetches") in {False, None}


def test_rfc8785_signature_roundtrip(tmp_path: Path) -> None:
    value = {"kind": "ayran-layer", "version": "0.1.0"}
    path = tmp_path / "bundle.sig.json"
    signature = write_signature(path, value)
    assert signature["canonicalization"] == "rfc8785"
    assert signature["content_hash"].startswith("sha256:")
    assert verify_signature(path, value) is True
    assert sign_payload(value)["content_hash"] == signature["content_hash"]


def test_layer_and_complete_builds_are_bit_identical(tmp_path: Path) -> None:
    first_dir = tmp_path / "a"
    second_dir = tmp_path / "b"
    layer_a = build_bundle("layer", destination=first_dir, root=ROOT)
    layer_b = build_bundle("layer", destination=second_dir, root=ROOT)
    assert Path(layer_a["path"]).read_bytes() == Path(layer_b["path"]).read_bytes()
    assert layer_a["sha256"] == layer_b["sha256"]
    checked = validate_bundle(layer_a["path"])
    assert checked["ok"] is True
    assert "ayran/SBOM.json" in checked["members"]
    assert "ayran/THIRD-PARTY-NOTICES.md" in checked["members"]
    assert "install-ayran.sh" in checked["members"]
    complete_a = build_bundle("complete", destination=first_dir, root=ROOT)
    complete_b = build_bundle("complete", destination=second_dir, root=ROOT)
    assert Path(complete_a["path"]).read_bytes() == Path(complete_b["path"]).read_bytes()
    assert (first_dir / "manifests" / "complete-deps.json").is_file()


def test_layer_install_requires_prime_and_never_removes_it(tmp_path: Path) -> None:
    from ayran.release.errors import INSTALL_REFUSED, ReleaseError

    prefix = tmp_path / "prefix"
    source = tmp_path / "source"
    source.mkdir()
    (source / "README.md").write_text("ayran", encoding="utf-8")
    with pytest.raises(ReleaseError) as raised:
        install(kind="layer", prefix=prefix, source=source)
    assert raised.value.code == INSTALL_REFUSED
    prime = tmp_path / "external-prime"
    prime.mkdir()
    (prime / "keep.txt").write_text("owned", encoding="utf-8")
    dry = plan_install(kind="layer", prefix=prefix, prime=prime, dry_run=True)
    assert dry["mutates_external_prime"] is False
    assert dry["network"] is False
    receipt = install(kind="layer", prefix=prefix, source=source, prime=prime)
    assert receipt["applied"] is True
    assert (prime / "keep.txt").read_text(encoding="utf-8") == "owned"
    rolled = rollback(Path(receipt["receipt_path"]))
    assert rolled["external_prime_untouched"] is True
    receipt = install(kind="layer", prefix=prefix, source=source, prime=prime)
    removed = uninstall(Path(receipt["receipt_path"]))
    assert removed["external_prime_untouched"] is True
    assert (prime / "keep.txt").is_file()


def test_complete_install_owns_only_private_prefix(tmp_path: Path) -> None:
    prefix = tmp_path / "complete-prefix"
    source = tmp_path / "tree"
    (source / "vendor" / "cache").mkdir(parents=True)
    (source / "payload.txt").write_text("complete", encoding="utf-8")
    (source / "vendor" / "cache" / "prime-agent-0.7.2.tgz").write_bytes(b"prime-bytes")
    external = tmp_path / "live-prime"
    external.mkdir()
    (external / "stay.txt").write_text("live", encoding="utf-8")
    receipt = install(kind="complete", prefix=prefix, source=source)
    assert "prime" in Path(receipt["versioned"]).joinpath("prime").as_posix() or (
        Path(receipt["versioned"]) / "prime"
    ).is_dir()
    uninstall(Path(receipt["receipt_path"]))
    assert (external / "stay.txt").is_file()


def test_cli_release_validate_and_install_dry_run(tmp_path: Path) -> None:
    built = build_bundle("layer", destination=tmp_path / "dist", root=ROOT)
    code, output = invoke(["release", "validate", "--path", built["path"]])
    assert code == 0, output
    assert payload(output)["ok"] is True
    prefix = tmp_path / "prefix"
    prime = tmp_path / "prime"
    prime.mkdir()
    code, output = invoke(
        [
            "release",
            "install",
            "--layer",
            "--prime",
            str(prime),
            "--prefix",
            str(prefix),
            "--source",
            str(ROOT),
            "--dry-run",
        ]
    )
    assert code == 0, output
    body = payload(output)["result"]
    assert body["dry_run"] is True
    assert body["applied"] is False
