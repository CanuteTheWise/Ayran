"""Tranche budget manager. Model-native 25-unit reserve is protected."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ayran.hypotheses.builders import ORIGIN_BUDGET
from ayran.hypotheses.drivers.base import DRIVER_NAMES, DRIVER_ORIGINS

TRANCHE = 100
FLOORS = {
    "model_native": 25,
    "global_graph": 15,
    "contradiction": 15,
    "tool_derived": 10,
    "coverage_derived": 15,
    "adversarial_specialist": 20,
}
CEILINGS = dict(FLOORS)


@dataclass(slots=True)
class BudgetManager:
    tranche: int = TRANCHE
    spent_total: int = 0
    spent: dict[str, int] = field(default_factory=dict)
    reserved_model_native: int = FLOORS["model_native"]
    reserve_released: bool = False
    exhaustion_mode: str = "manual_next"  # or halt

    def remaining(self) -> int:
        return max(0, self.tranche - self.spent_total)

    def remaining_for(self, driver: str) -> int:
        ceiling = CEILINGS[driver]
        used = self.spent.get(driver, 0)
        leftover = max(0, ceiling - used)
        if driver != "model_native" and not self.reserve_released:
            still_reserved = max(
                0, self.reserved_model_native - self.spent.get("model_native", 0)
            )
            unprotected = max(0, self.remaining() - still_reserved)
            return min(leftover, unprotected)
        return min(leftover, self.remaining())

    def can_spend(self, driver: str, units: int) -> bool:
        if units == 0:
            return True
        return units > 0 and units <= self.remaining_for(driver)

    def spend(self, driver: str, units: int) -> bool:
        if units < 0:
            return False
        if units == 0:
            return True
        if not self.can_spend(driver, units):
            return False
        self.spent[driver] = self.spent.get(driver, 0) + units
        self.spent_total += units
        return True

    def release_reserve(self, *, recorded: bool) -> None:
        if recorded:
            self.reserve_released = True
            self.reserved_model_native = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tranche": self.tranche,
            "spent_total": self.spent_total,
            "remaining": self.remaining(),
            "spent": {name: self.spent.get(name, 0) for name in DRIVER_NAMES},
            "floors": dict(FLOORS),
            "ceilings": dict(CEILINGS),
            "reserve_released": self.reserve_released,
            "origins": dict(DRIVER_ORIGINS),
            "origin_budgets": dict(ORIGIN_BUDGET),
        }

    @classmethod
    def from_view(cls, budget_state: dict[str, Any], driver_states: dict[str, dict[str, Any]]) -> BudgetManager:
        manager = cls()
        if budget_state:
            manager.spent_total = int(budget_state.get("spent") or 0)
            manager.tranche = int(budget_state.get("tranche") or TRANCHE)
            manager.reserve_released = bool(budget_state.get("reserve_released"))
        for name, state in driver_states.items():
            manager.spent[name] = int(state.get("spend") or 0)
        if manager.spent_total == 0:
            manager.spent_total = sum(manager.spent.values())
        return manager
