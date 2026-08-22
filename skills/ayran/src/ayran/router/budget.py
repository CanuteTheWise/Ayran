"""Tranche budget manager. First-principles 25-unit reserve is protected."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ayran.context.lenses import LENS_BUDGETS, LENS_NAMES, LENS_ORIGINS
from ayran.hypotheses.builders import ORIGIN_BUDGET

TRANCHE = 100
FLOORS = dict(LENS_BUDGETS)
CEILINGS = dict(LENS_BUDGETS)


@dataclass(slots=True)
class BudgetManager:
    tranche: int = TRANCHE
    spent_total: int = 0
    spent: dict[str, int] = field(default_factory=dict)
    # 25-unit first_principles protection inherits the model_novel reserve
    # semantics (release_reserve after target-first completion).
    reserved_first_principles: int = LENS_BUDGETS["first_principles"]
    reserve_released: bool = False
    exhaustion_mode: str = "manual_next"  # or halt

    def remaining(self) -> int:
        return max(0, self.tranche - self.spent_total)

    def remaining_for(self, lens: str) -> int:
        ceiling = CEILINGS[lens]
        used = self.spent.get(lens, 0)
        leftover = max(0, ceiling - used)
        if lens != "first_principles" and not self.reserve_released:
            still_reserved = max(
                0, self.reserved_first_principles - self.spent.get("first_principles", 0)
            )
            unprotected = max(0, self.remaining() - still_reserved)
            return min(leftover, unprotected)
        return min(leftover, self.remaining())

    def can_spend(self, lens: str, units: int) -> bool:
        if units == 0:
            return True
        return units > 0 and units <= self.remaining_for(lens)

    def spend(self, lens: str, units: int) -> bool:
        if units < 0:
            return False
        if units == 0:
            return True
        if not self.can_spend(lens, units):
            return False
        self.spent[lens] = self.spent.get(lens, 0) + units
        self.spent_total += units
        return True

    def release_reserve(self, *, recorded: bool) -> None:
        if recorded:
            self.reserve_released = True
            self.reserved_first_principles = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tranche": self.tranche,
            "spent_total": self.spent_total,
            "remaining": self.remaining(),
            "spent": {name: self.spent.get(name, 0) for name in LENS_NAMES},
            "floors": dict(FLOORS),
            "ceilings": dict(CEILINGS),
            "reserve_released": self.reserve_released,
            "origins": dict(LENS_ORIGINS),
            "origin_budgets": dict(ORIGIN_BUDGET),
        }

    @classmethod
    def from_view(cls, budget_state: dict[str, Any], driver_states: dict[str, dict[str, Any]]) -> BudgetManager:
        manager = cls()
        if budget_state:
            manager.spent_total = int(budget_state.get("spent") or 0)
            manager.tranche = int(budget_state.get("tranche") or TRANCHE)
            manager.reserve_released = bool(budget_state.get("reserve_released"))
            if manager.reserve_released:
                manager.reserved_first_principles = 0
        for name, state in driver_states.items():
            manager.spent[name] = int(state.get("spend") or 0)
        if manager.spent_total == 0:
            manager.spent_total = sum(manager.spent.values())
        return manager
