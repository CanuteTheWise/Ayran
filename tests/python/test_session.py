"""Session prepare creates an empty Target run for Prime --ayran."""

from __future__ import annotations

from pathlib import Path

from ayran.runtime.session import prepare_session
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
