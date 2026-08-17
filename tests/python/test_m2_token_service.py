"""M2 token, service, and config tests."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "skills" / "ayran" / "src"))

import pytest
from ayran.api.client import AyranClient, ClientError
from ayran.api.server import AyranServer
from ayran.api.token import create_token, open_inheritable, verify_token
from ayran.config.loader import ConfigError, load_config
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.paths import runtime_root

pytestmark = pytest.mark.wsl_ext4


def _actor() -> dict[str, Any]:
    return {"kind": "test", "id": "operator-m2"}


# ---------- token fd ----------


def test_token_roundtrip_and_fd_inheritance(tmp_path: Path) -> None:
    run_dir = runtime_root(tmp_path, "run_test")
    token_path = create_token(run_dir, run_id="run_test")
    assert token_path.is_file()
    assert (token_path.stat().st_mode & 0o777) == 0o600
    expected = token_path.read_bytes()
    fd, presented = open_inheritable(token_path)
    try:
        assert os.get_inheritable(fd)
        assert verify_token(fd, expected)
        assert verify_token(presented, expected)
        assert not verify_token(b"wrong", expected)
    finally:
        os.close(fd)


def test_token_non_0o600_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.token"
    path.write_bytes(b"token")
    os.chmod(path, 0o644)
    with pytest.raises(ValueError):
        open_inheritable(path)


# ---------- auth-bound UDS service ----------


def _write_stream(root: Path) -> dict[str, Any]:
    from ayran.graph.namespaces import target_stream

    stream = target_stream("run_test", {"name": "unit"}, "key")
    stream_root = root / "graph"
    stream_root.mkdir(parents=True, exist_ok=True)
    (stream_root / "stream.json").write_text(json.dumps(stream), encoding="utf-8")
    return stream


def _start_service(tmp_path: Path) -> tuple[AyranServer, Path, bytes, str]:
    run_id = "run_test"
    base = tmp_path / run_id
    base.mkdir(parents=True, exist_ok=True)
    stream = _write_stream(tmp_path)
    (base / "stream.json").write_text(json.dumps(stream), encoding="utf-8")
    token_bytes = b"expected-token"
    sock = tmp_path / f"{run_id}.sock"
    if sock.exists():
        sock.unlink()
    logger = StructuredLogger(base / "logs" / "runtime.jsonl", run_id=run_id, component="test")

    def handler(method: str, params: dict[str, Any], credentials: object) -> Any:
        if method == "ping":
            return {"pong": True}
        raise LookupError(method)

    server = AyranServer(sock, token=token_bytes, logger=logger, handler=handler, run_id=run_id)
    server.start_background()
    time.sleep(0.05)
    return server, sock, token_bytes, run_id


def test_service_roundtrip_and_signature(tmp_path: Path) -> None:
    server, sock, token, _run_id = _start_service(tmp_path)
    try:
        client = AyranClient(sock, token_bytes=token)
        assert client.call("ping") == {"pong": True}
        with pytest.raises(ClientError) as raised:
            client.call("missing")
        assert raised.value.error["details"]["code"] == "METHOD_NOT_FOUND"
    finally:
        server.stop()
        assert not sock.exists()


def test_service_rejects_non_owner_uid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server, sock, token, _ = _start_service(tmp_path)
    try:
        monkeypatch.setattr(server, "expected_uid", 12345)
        client = AyranClient(sock, token_bytes=token, timeout=2.0)
        with pytest.raises(ClientError) as raised:
            client.call("ping")
        assert raised.value.error["details"]["code"] == "PERMISSION_DENIED"
    finally:
        server.stop()


# ---------- config ----------


def test_config_unknown_key_is_fatal() -> None:
    with pytest.raises(ConfigError) as raised:
        load_config(env={}, cli_overrides={"not_a_real_key": "1"})
    assert raised.value.code == "CONFIG"


def test_config_monotonic_narrowing_blocks_weakening(tmp_path: Path) -> None:
    global_file = tmp_path / "global.toml"
    global_file.write_text("max_parallel_external_tools = 4\n")
    with pytest.raises(ConfigError) as raised:
        load_config(env={}, global_path=global_file)
    assert raised.value.code == "POLICY"


def test_config_cli_override_is_strongest_layer(tmp_path: Path) -> None:
    global_file = tmp_path / "global.toml"
    global_file.write_text('log_level = "WARN"\n')
    config = load_config(env={}, global_path=global_file, cli_overrides={"log_level": "DEBUG"})
    assert config.log_level == "DEBUG"


def test_config_env_layer_uses_allowlisted_keys_only() -> None:
    config = load_config(env={"AYRAN_STATE_ROOT": "/tmp/ayran-state"}, cli_overrides=None)
    assert config.state_root == "/tmp/ayran-state"
