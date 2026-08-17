"""M8 Fizz and experimental adapters: detect allowed, run refused when disabled."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from ayran.tools.adapters.experimental import ExperimentalAdapter
from ayran.tools.adapters.fizz import (
    FizzAdapter,
    FizzHarnessRequest,
    parse_fizz_version,
    parse_harness_payload,
)
from ayran.tools.errors import POLICY_DENIED, ToolError
from ayran.tools.registry import CapabilityRegistry
from ayran.tools.types import (
    ALIAS_ECHIDNA,
    ALIAS_FIZZ,
    ALIAS_FOUNDRY,
    ALIAS_HALMOS,
    ALIAS_ITYFUZZ,
    ALIAS_MEDUSA,
    ALIAS_SLITHER,
    ALIAS_SOLC,
    ALIAS_SOLODIT,
    Environment,
    ExecutionPolicy,
)

ROOT = Path(__file__).resolve().parents[2]


def _registry() -> CapabilityRegistry:
    env = Environment(path=None, allowed_binary_roots=(), probe_http=False)
    return CapabilityRegistry(ROOT / "capabilities", environment=env, probe_on_load=False)


def test_experimental_manifests_load_but_are_hidden_by_default() -> None:
    registry = _registry()
    aliases = {item.alias for item in registry.list_capabilities()}
    assert aliases == {ALIAS_SOLC, ALIAS_FOUNDRY, ALIAS_SLITHER, ALIAS_SOLODIT}
    experimental = {item.alias for item in registry.list_capabilities(include_experimental=True)}
    assert {ALIAS_FIZZ, ALIAS_ITYFUZZ, ALIAS_ECHIDNA, ALIAS_MEDUSA, ALIAS_HALMOS} <= experimental


def test_experimental_adapters_refuse_run_when_disabled() -> None:
    registry = _registry()
    policy = ExecutionPolicy()
    for alias in (ALIAS_FIZZ, ALIAS_ITYFUZZ, ALIAS_ECHIDNA, ALIAS_MEDUSA, ALIAS_HALMOS):
        adapter = registry.get_adapter(alias, require_available=False)
        with pytest.raises(ToolError) as raised:
            if isinstance(adapter, FizzAdapter):
                asyncio.run(
                    adapter.run(
                        FizzHarnessRequest(target_dir=".", output_dir="out", enable_experimental=False),
                        policy,
                    )
                )
            else:
                assert isinstance(adapter, ExperimentalAdapter)
                asyncio.run(adapter.run(adapter.request_type(), policy))
        assert raised.value.code == POLICY_DENIED
        assert "disabled" in raised.value.message.lower() or "experimental" in raised.value.message.lower()


def test_fizz_parser_and_version() -> None:
    assert parse_fizz_version("fizz 1.0.0") == "1.0.0"
    manifest = parse_harness_payload(
        {
            "actors": [{"name": "attacker", "permissions": ["call"], "balances": {"eth": "1"}, "actions": ["poke"]}],
            "properties": ["balance_conserved"],
            "handlers": ["handler_poke"],
            "engine": "medusa",
            "target_hash": "sha256:" + "a" * 64,
        },
        generator_version="1.0.0",
    )
    assert manifest.actors[0].name == "attacker"
    assert manifest.properties == ["balance_conserved"]
    assert manifest.engine == "medusa"


def test_fizz_adapter_detect_degrades_without_binary() -> None:
    registry = _registry()
    adapter = registry.get_adapter(ALIAS_FIZZ, require_available=False)
    assert isinstance(adapter, FizzAdapter)
    result = asyncio.run(adapter.detect(Environment(path="", allowed_binary_roots=(), probe_http=False)))
    assert result.status in {"unavailable_not_found", "unavailable_broken", "available"}
