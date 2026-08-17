"""Driver protocol. Pure functions: GraphView + budget in, hypotheses out. No model calls."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ayran.context.view import GraphView
from ayran.hypotheses.builders import ORIGIN_BUDGET

DRIVER_NAMES = (
    "model_native",
    "global_graph",
    "contradiction",
    "tool_derived",
    "coverage_derived",
    "adversarial_specialist",
)

DRIVER_ORIGINS = {
    "model_native": "model_novel",
    "global_graph": "global_graph",
    "contradiction": "contradiction",
    "tool_derived": "tool",
    "coverage_derived": "coverage",
    "adversarial_specialist": "specialist",
}


@dataclass(slots=True)
class DriverResult:
    driver: str
    origin: str
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    coverage_deltas: list[dict[str, Any]] = field(default_factory=list)
    experiments: list[str] = field(default_factory=list)
    stop: bool = False
    stop_reason: str = ""
    material: bool = False
    units_spent: int = 0
    payload_only: bool = False
    source_id: str = ""

    def distinguishable_claims(self) -> list[str]:
        return sorted({str(item.get("claim") or "") for item in self.hypotheses})


class Driver(Protocol):
    name: str
    origin: str
    budget_units: int

    def propose(self, view: GraphView) -> DriverResult: ...


def budget_for(driver: str) -> int:
    origin = DRIVER_ORIGINS[driver]
    return ORIGIN_BUDGET[origin]
