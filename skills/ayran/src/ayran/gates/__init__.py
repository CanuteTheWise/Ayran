"""Devil's Advocate Gate A/B engines. Structured validators, no model calls."""

from __future__ import annotations

from ayran.gates.gate_a import run_gate_a
from ayran.gates.gate_b import run_gate_b

__all__ = ["run_gate_a", "run_gate_b"]
