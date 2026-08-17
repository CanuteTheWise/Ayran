"""Session prepare creates an empty Target run for Prime --ayran."""

from __future__ import annotations

from pathlib import Path

from ayran.runtime.session import prepare_session, start_engagement
from m3_fixtures import scope_value
from m7_fixtures import invoke, payload


def test_session_prepare_writes_stream_token_and_socket(
    tmp_path: Path, short_state_root: Path
) -> None:
    cwd = tmp_path / "project"
    cwd.mkdir()
    prepared = prepare_session(
        cwd=cwd, state_root=short_state_root, allow_unsafe_filesystem=True
    )
    run_id = prepared["run_id"]
    assert run_id.startswith("run_")
    assert Path(prepared["token_file"]).is_file()
    assert (Path(prepared["run_root"]) / "stream.json").is_file()
    assert (Path(prepared["run_root"]) / "graph").is_dir()
    assert prepared["socket"].endswith("ayrand.sock")
    assert len(prepared["socket"]) <= 107


def test_cli_session_prepare(tmp_path: Path, short_state_root: Path) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    code, output = invoke(
        [
            "session",
            "prepare",
            "--cwd",
            str(cwd),
            "--state-root",
            str(short_state_root),
            "--allow-unsafe-filesystem",
        ]
    )
    assert code == 0, output
    body = payload(output)["result"]
    assert body["run_id"].startswith("run_")
    assert Path(body["token_file"]).is_file()
    assert Path(body["scope_file"]).is_file()
    assert body["included_roots"] == ["."]


def test_start_binds_scope_to_the_new_run(tmp_path: Path, short_state_root: Path) -> None:
    import json

    from ayran.config.loader import load_config
    from ayran.policy.permissions import PolicyEngine
    from ayran.policy.scope import load_scope

    cwd = tmp_path / "project"
    cwd.mkdir()
    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps(scope_value()), encoding="utf-8")
    started = start_engagement(
        cwd=cwd,
        manifest=manifest,
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )
    bound_path = Path(started["scope_file"])
    assert bound_path.is_file()
    loaded = load_scope(bound_path)
    assert loaded.run_id == started["run_id"]
    decision = PolicyEngine(loaded, config=load_config(env={})).authorize(
        "read_source", resource="target/src"
    )
    assert decision.permitted, decision.reason


def test_start_roots_generates_envelope(tmp_path: Path, short_state_root: Path) -> None:
    from ayran.config.loader import load_config
    from ayran.policy.permissions import PolicyEngine
    from ayran.policy.scope import load_scope

    cwd = tmp_path / "project"
    cwd.mkdir()
    started = start_engagement(
        cwd=cwd,
        roots=["target/src"],
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )
    loaded = load_scope(Path(started["scope_file"]))
    assert loaded.run_id == started["run_id"]
    assert "target/src" in loaded.included_roots
    allowed = PolicyEngine(loaded, config=load_config(env={})).authorize(
        "read_source", resource="target/src/Vault.sol"
    )
    denied = PolicyEngine(loaded, config=load_config(env={})).authorize(
        "read_source", resource="secrets/key.sol"
    )
    assert allowed.permitted, allowed.reason
    assert denied.permitted is False


def test_cli_start_manifest(tmp_path: Path, short_state_root: Path) -> None:
    import json

    cwd = tmp_path / "cwd"
    cwd.mkdir()
    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps(scope_value()), encoding="utf-8")
    code, output = invoke(
        [
            "start",
            "--manifest",
            str(manifest),
            "--cwd",
            str(cwd),
            "--state-root",
            str(short_state_root),
            "--allow-unsafe-filesystem",
        ]
    )
    assert code == 0, output
    body = payload(output)["result"]
    assert body["run_id"].startswith("run_")
    assert Path(body["scope_file"]).is_file()
    assert body["scope_hash"].startswith("sha256:")


def test_cli_start_roots(tmp_path: Path, short_state_root: Path) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    code, output = invoke(
        [
            "start",
            "--roots",
            "src",
            "--cwd",
            str(cwd),
            "--state-root",
            str(short_state_root),
            "--allow-unsafe-filesystem",
        ]
    )
    assert code == 0, output
    body = payload(output)["result"]
    assert Path(body["scope_file"]).is_file()
    assert "src" in body["included_roots"]


def test_detect_skips_notes_and_compiler_output(tmp_path: Path) -> None:
    from ayran.policy.local_scope import detect_excluded_roots, detect_local_roots

    cwd = tmp_path / "messy"
    (cwd / "src").mkdir(parents=True)
    (cwd / "out").mkdir()
    (cwd / "reports").mkdir()
    (cwd / "notes.md").write_text("bounty", encoding="utf-8")
    (cwd / "scope.txt").write_text("in scope: vault", encoding="utf-8")
    assert detect_local_roots(cwd) == ["src"]
    assert "out" in detect_excluded_roots(cwd)
    assert "reports" in detect_excluded_roots(cwd)


def test_start_auto_detects_contracts(tmp_path: Path, short_state_root: Path) -> None:
    cwd = tmp_path / "repo"
    (cwd / "contracts").mkdir(parents=True)
    started = start_engagement(
        cwd=cwd,
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )
    assert started["included_roots"] == ["contracts"]


def test_start_messy_repo_excludes_out(tmp_path: Path, short_state_root: Path) -> None:
    from ayran.policy.scope import load_scope

    cwd = tmp_path / "messy"
    (cwd / "src").mkdir(parents=True)
    (cwd / "out").mkdir()
    (cwd / "notes.md").write_text("bounty", encoding="utf-8")
    started = start_engagement(
        cwd=cwd,
        state_root=short_state_root,
        allow_unsafe_filesystem=True,
    )
    loaded = load_scope(Path(started["scope_file"]))
    assert loaded.included_roots == ["src"]
    assert "out" in loaded.excluded_roots
