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
