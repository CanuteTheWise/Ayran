"""M4 capability registry, adapters, parsers, CLI, and ToolRun recording."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from ayran.api.validators import validate_contract
from ayran.artifacts.store import ArtifactStore
from ayran.cli import main as cli_main
from ayran.graph.namespaces import TargetNamespace
from ayran.graph.recovery import GraphStore
from ayran.tools.adapters.foundry import FoundryAdapter, parse_forge_json
from ayran.tools.adapters.slither import SlitherAdapter, classify_alert
from ayran.tools.adapters.solc import SolcAdapter
from ayran.tools.adapters.solodit import SoloditAdapter, privacy_issues
from ayran.tools.base import (
    HttpResponse,
    build_argv,
    bytes_hash,
    file_sha256,
    filter_env,
    hashed_environment,
    invoke_executable,
)
from ayran.tools.errors import PRIVACY_REJECTED, UNAVAILABLE, ToolError
from ayran.tools.recording import record_tool_run
from ayran.tools.registry import CapabilityRegistry
from ayran.tools.runner import RunContext, build_tool_run, policy_from_scope
from ayran.tools.types import (
    ALIAS_FOUNDRY,
    ALIAS_SLITHER,
    ALIAS_SOLC,
    ALIAS_SOLODIT,
    ZERO_HASH,
    Environment,
    ExecutionPolicy,
    RawRun,
    SoloditSearchRequest,
)
from ayran.tools.yaml_lite import dump_yaml, load_yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "tool-output"
RUN_ID = "run_01J00000000000000000000001"
TARGET_IDENTITY = {
    "target_id": "tgt_01J00000000000000000000001",
    "source_tree_hash": "sha256:" + "d" * 64,
    "scope_id": "scp_01J00000000000000000000001",
    "commit": "1" * 40,
}


def _registry(**kwargs: Any) -> CapabilityRegistry:
    env = Environment(
        path=os.environ.get("PATH"),
        allowed_binary_roots=(),
        probe_http=False,
    )
    return CapabilityRegistry(
        ROOT / "capabilities",
        environment=env,
        probe_on_load=kwargs.get("probe_on_load", True),
        http_transport=kwargs.get("http_transport"),
        health_ttl_seconds=kwargs.get("health_ttl_seconds", 60),
    )


def test_yaml_roundtrip_and_manifest_schema() -> None:
    for path in sorted((ROOT / "capabilities").glob("*.yaml")):
        loaded = load_yaml(path.read_text(encoding="utf-8"))
        assert isinstance(loaded, dict)
        again = load_yaml(dump_yaml(loaded))
        assert again == loaded
        validate_contract("capability-manifest", loaded)


def test_registry_loads_four_manifests() -> None:
    registry = _registry(probe_on_load=False)
    aliases = {item.alias for item in registry.list_capabilities()}
    assert aliases == {ALIAS_SOLC, ALIAS_FOUNDRY, ALIAS_SLITHER, ALIAS_SOLODIT}


def test_argv_templates() -> None:
    solc = build_argv(
        ["solc", "--optimize", "--output-dir", "{output_dir}", "{source_paths}"],
        {"output_dir": "out", "source_paths": ["a.sol", "b.sol"]},
    )
    assert solc == ["solc", "--optimize", "--output-dir", "out", "a.sol", "b.sol"]
    assert build_argv(["forge", "test", "--json"], {}) == ["forge", "test", "--json"]
    slither = build_argv(
        ["slither", "--json", "{output_file}", "{source_paths}"],
        {"output_file": "rep.json", "source_paths": ["ViewReentrancy.sol"]},
    )
    assert slither == ["slither", "--json", "rep.json", "ViewReentrancy.sol"]
    assert build_argv(["solodit", "search", "{query}"], {"query": "reentrancy"}) == [
        "solodit",
        "search",
        "reentrancy",
    ]
    with pytest.raises(ToolError):
        build_argv(["solc", "{missing}"], {})


def test_parse_solc_fixtures() -> None:
    registry = _registry(probe_on_load=False)
    adapter = registry.get_adapter(ALIAS_SOLC, require_available=False)
    assert isinstance(adapter, SolcAdapter)
    success = json.loads((FIXTURES / "solc-success.json").read_text(encoding="utf-8"))
    raw = RawRun(
        argv=["solc", "--combined-json", "abi,bin,hashes", "Hello.sol"],
        cwd=None,
        env_fingerprint=ZERO_HASH,
        started_at="2026-08-13T00:00:00Z",
        ended_at="2026-08-13T00:00:01Z",
        exit_code=0,
        signal=None,
        stdout=json.dumps(success).encode(),
        stderr=b"Version: 0.8.28+commit.7893614a.Linux.g++\n",
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_hash=ZERO_HASH,
        stderr_hash=ZERO_HASH,
        output_file_hashes={},
        input_hashes=[],
        executable_hash=None,
        timeout=False,
        failure_type=None,
        extra={"resolved_version": "0.8.28"},
    )
    parsed = adapter.parse(raw)
    assert parsed.contracts[0].name.endswith("Hello")
    assert parsed.contracts[0].bytecode_size and parsed.contracts[0].bytecode_size > 0
    assert parsed.evidence_ceiling == "observed"
    fail = replace(
        raw,
        exit_code=1,
        stdout=b"",
        stderr=(FIXTURES / "solc-compile-failure.json").read_bytes(),
        failure_type="compile",
    )
    failed = adapter.parse(fail)
    assert failed.errors
    with pytest.raises(ToolError):
        adapter.parse(replace(raw, stdout=b"", stderr=b"", output_file_hashes={}))


def test_parse_foundry_fixtures() -> None:
    passing = json.loads((FIXTURES / "foundry-test-pass.json").read_text(encoding="utf-8"))
    failing = json.loads((FIXTURES / "foundry-test-fail.json").read_text(encoding="utf-8"))
    suite = json.loads((FIXTURES / "foundry-test-suite-1.7.json").read_text(encoding="utf-8"))
    assert parse_forge_json(passing)[0].status == "pass"
    assert parse_forge_json(failing)[0].status == "fail"
    classified = {item.name: item.status for item in parse_forge_json(suite)}
    assert classified["testPass()"] == "pass"
    assert classified["testMismatch()"] == "fail"
    registry = _registry(probe_on_load=False)
    adapter = registry.get_adapter(ALIAS_FOUNDRY, require_available=False)
    assert isinstance(adapter, FoundryAdapter)
    raw = RawRun(
        argv=["forge", "test", "--json"],
        cwd="run/work",
        env_fingerprint=ZERO_HASH,
        started_at="2026-08-13T00:00:00Z",
        ended_at="2026-08-13T00:00:01Z",
        exit_code=0,
        signal=None,
        stdout=(FIXTURES / "foundry-test-pass.json").read_bytes(),
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_hash=ZERO_HASH,
        stderr_hash=ZERO_HASH,
        output_file_hashes={},
        input_hashes=[],
        executable_hash=None,
        timeout=False,
        failure_type=None,
        extra={},
    )
    parsed = adapter.parse(raw)
    assert parsed.passed == 1 and parsed.failed == 0
    assert parsed.compile_error is False
    with pytest.raises(ToolError):
        adapter.parse(replace(raw, stdout=b""))


def test_parse_slither_fixtures_classifies_false_positive() -> None:
    assert (
        classify_alert("reentrancy-benign", "Reentrancy in peek() view function")
        == "known_false_positive_pattern"
    )
    registry = _registry(probe_on_load=False)
    adapter = registry.get_adapter(ALIAS_SLITHER, require_available=False)
    assert isinstance(adapter, SlitherAdapter)
    raw = RawRun(
        argv=["slither", "--json", "out.json", "ViewReentrancy.sol"],
        cwd=None,
        env_fingerprint=ZERO_HASH,
        started_at="2026-08-13T00:00:00Z",
        ended_at="2026-08-13T00:00:01Z",
        exit_code=0,
        signal=None,
        stdout=(FIXTURES / "slither-findings.json").read_bytes(),
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_hash=ZERO_HASH,
        stderr_hash=ZERO_HASH,
        output_file_hashes={},
        input_hashes=[],
        executable_hash=None,
        timeout=False,
        failure_type=None,
        extra={},
    )
    parsed = adapter.parse(raw)
    assert parsed.evidence_ceiling == "lead"
    assert parsed.alerts[0].classification == "known_false_positive_pattern"
    assert parsed.alerts[0].spans[0].file.endswith("ViewReentrancy.sol")
    assert parsed.compilation_facts
    clean = adapter.parse(replace(raw, stdout=(FIXTURES / "slither-clean.json").read_bytes()))
    assert clean.alerts == []


def test_solodit_privacy_and_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    assert privacy_issues("reentrancy after external call") == []
    assert "contract-address" in privacy_issues("analyze 0x" + "a" * 40)
    # Protocol/project names are public information: allowed, audited.
    assert privacy_issues("Euler protocol reentrancy history") == []
    registry = _registry(probe_on_load=False)
    captured: dict[str, Any] = {}

    def transport(
        method: str, url: str, body: bytes | None, headers: dict[str, str], timeout: int
    ) -> HttpResponse:
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        captured["headers"] = headers
        return HttpResponse(200, (FIXTURES / "solodit-search-results.json").read_bytes())

    adapter = SoloditAdapter(
        registry.manifests[registry.resolve_id(ALIAS_SOLODIT)], transport=transport
    )
    with pytest.raises(ToolError) as raised:
        asyncio.run(
            adapter.run(
                SoloditSearchRequest(query="0x" + "b" * 40),
                ExecutionPolicy(network="approved-api", allowed_hosts=("solodit.cyfrin.io",)),
            )
        )
    assert raised.value.code == PRIVACY_REJECTED

    monkeypatch.setenv("AYRAN_SOLODIT_API_KEY", "test-key-material")
    raw = asyncio.run(
        adapter.run(
            SoloditSearchRequest(query="reentrancy after token transfer", protocol="Euler"),
            ExecutionPolicy(network="approved-api", allowed_hosts=("solodit.cyfrin.io",)),
        )
    )
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/api/v1/solodit/findings")
    request_body = json.loads(captured["body"])
    assert request_body["filters"]["keywords"] == "reentrancy after token transfer"
    assert request_body["filters"]["protocol"] == "Euler"
    assert captured["headers"]["X-Cyfrin-API-Key"] == "test-key-material"
    audit_reasons = [entry["reason"] for entry in adapter.privacy_audit if entry["rejected"] == "false"]
    assert any("protocol-name-query" in reason for reason in audit_reasons)

    parsed = adapter.parse(raw)
    assert parsed.records[0].source_url.startswith("https://solodit.cyfrin.io/")
    assert parsed.records[0].record_id == "FND-1001"
    assert parsed.records[0].protocol == "Euler"
    assert parsed.records[0].severity == "HIGH"
    assert parsed.evidence_ceiling == "lead"
    assert parsed.page == 1
    assert parsed.next_cursor is None


def test_environment_filtering_strips_secrets() -> None:
    filtered = filter_env(
        {
            "PATH": "/bin",
            "HOME": "/home/a",
            "AWS_SECRET_ACCESS_KEY": "nope",
            "TOKEN": "nope",
            "FOO": "bar",
        }
    )
    assert "PATH" in filtered
    assert "AWS_SECRET_ACCESS_KEY" not in filtered
    assert "TOKEN" not in filtered
    assert "FOO" not in filtered
    hashed = hashed_environment(filtered)
    assert all(item["value"].startswith("sha256:") for item in hashed)


def test_bounded_output_truncation(tmp_path: Path) -> None:
    script = tmp_path / "spew.py"
    script.write_text("import sys; sys.stdout.write('x' * 10000)", encoding="utf-8")
    raw = invoke_executable(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=filter_env(None),
        timeout_seconds=10,
        max_output_bytes=64,
    )
    assert raw.stdout_truncated is True
    assert b"AYRAN_OUTPUT_TRUNCATED" in raw.stdout


def test_timeout_kills_process_group(tmp_path: Path) -> None:
    script = tmp_path / "sleep.py"
    script.write_text("import time; time.sleep(30)", encoding="utf-8")
    raw = invoke_executable(
        [sys.executable, str(script)],
        cwd=tmp_path,
        env=filter_env(None),
        timeout_seconds=1,
        graceful_stop_seconds=0.2,
    )
    assert raw.timeout is True
    assert raw.failure_type == "timeout"


def test_tool_run_record_and_graph_storage(tmp_path: Path) -> None:
    registry = _registry(probe_on_load=False)
    adapter = registry.get_adapter(ALIAS_SOLC, require_available=False)
    raw = RawRun(
        argv=["solc", "--version"],
        cwd=None,
        env_fingerprint=ZERO_HASH,
        started_at="2026-08-13T00:00:00.000000Z",
        ended_at="2026-08-13T00:00:01.000000Z",
        exit_code=0,
        signal=None,
        stdout=(FIXTURES / "solc-success.json").read_bytes(),
        stderr=b"Version: 0.8.28+commit.7893614a\n",
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_hash="sha256:" + "2" * 64,
        stderr_hash="sha256:" + "3" * 64,
        output_file_hashes={},
        input_hashes=["sha256:" + "1" * 64],
        executable_hash="sha256:" + "4" * 64,
        timeout=False,
        failure_type=None,
        extra={"resolved_version": "0.8.28"},
    )
    parsed = adapter.parse(raw)
    artifacts = ArtifactStore(tmp_path / "artifacts", allow_unsafe_filesystem=True)
    context = RunContext(run_id=RUN_ID, target_identity=TARGET_IDENTITY, artifact_store=artifacts)
    policy = policy_from_scope(manifest=registry.manifests[registry.resolve_id(ALIAS_SOLC)])
    tool_run = build_tool_run(
        registry=registry,
        capability_id=ALIAS_SOLC,
        raw=raw,
        parsed=parsed,
        parse_error=None,
        context=context,
        policy=policy,
        env_map={"PATH": "/usr/bin"},
    )
    validate_contract("tool-run", tool_run)
    assert tool_run["parse_status"] == "parsed"
    assert tool_run["evidence_ceiling"] == "observed"
    namespace = TargetNamespace(
        tmp_path / "graph",
        RUN_ID,
        TARGET_IDENTITY,
        "sha256:" + "a" * 64,
        allow_unsafe_filesystem=True,
    )
    store = GraphStore(namespace.root, namespace.stream, allow_unsafe_filesystem=True)
    try:
        ack = record_tool_run(store, tool_run)
        assert "commit_hash" in ack
        fetched = store.queries.get_entity(tool_run["tool_run_id"])
        assert fetched["records"]
    finally:
        store.close()


def test_get_adapter_fails_closed_when_unavailable() -> None:
    registry = _registry(probe_on_load=True)
    status = {item.alias: item.status for item in registry.list_capabilities()}
    if status.get(ALIAS_SOLC) != "available":
        with pytest.raises(ToolError) as raised:
            registry.get_adapter(ALIAS_SOLC, require_available=True)
        assert raised.value.code == UNAVAILABLE


def test_cli_tools_list_detect_health_doctor(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["tools", "list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["ok"] is True
    names = {item["alias"] for item in listed["result"]["capabilities"]}
    assert names == {ALIAS_SOLC, ALIAS_FOUNDRY, ALIAS_SLITHER, ALIAS_SOLODIT}
    assert cli_main(["tools", "detect", ALIAS_SOLC]) == 0
    detect = json.loads(capsys.readouterr().out)
    assert detect["ok"] is True
    assert detect["result"]["alias"] == ALIAS_SOLC
    assert cli_main(["tools", "health", ALIAS_SOLC]) == 0
    health = json.loads(capsys.readouterr().out)
    assert health["ok"] is True
    assert cli_main(["tools", "doctor"]) == 0
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["ok"] is True
    assert doctor["result"]["doctor_status"] in {"healthy", "degraded"}
    assert "path_probes" in doctor["result"]


def test_hash_verification_on_inputs(tmp_path: Path) -> None:
    payload = b"pragma solidity ^0.8.28; contract A {}"
    source = tmp_path / "A.sol"
    source.write_bytes(payload)
    assert file_sha256(source) == bytes_hash(payload)
