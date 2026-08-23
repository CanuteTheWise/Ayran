"""Devil's Advocate Gate A/B engines. Structured validators, no model calls.

Package init is deliberately LAZY (PEP 562): eagerly importing gate_a here
triggers evidence.service, which imports back into this package - so any
cold ``import ayran.skill.verbs`` (or any gates.* submodule reached before
evidence) died in a circular import on the live path (found during R6 live
prep). Attribute access ``ayran.gates.run_gate_a`` still works.
"""

from __future__ import annotations

from typing import Any

__all__ = ["run_gate_a", "run_gate_b"]

_LAZY = {
    "run_gate_a": ("ayran.gates.gate_a", "run_gate_a"),
    "run_gate_b": ("ayran.gates.gate_b", "run_gate_b"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(list(globals()) + list(_LAZY))
