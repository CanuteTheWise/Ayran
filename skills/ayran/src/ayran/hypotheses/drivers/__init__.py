"""Hypothesis drivers. R1: the two templated drivers (model_native and
adversarial_specialist) are deleted outright (spec §5.1 DELETIONS); the four
survivors remain until the R3 lens conversion."""

from __future__ import annotations

from collections.abc import Callable

from ayran.context.view import GraphView
from ayran.hypotheses.drivers.base import DRIVER_NAMES, DriverResult
from ayran.hypotheses.drivers.contradiction import propose as propose_contradiction
from ayran.hypotheses.drivers.coverage_derived import propose as propose_coverage
from ayran.hypotheses.drivers.global_graph import propose as propose_global
from ayran.hypotheses.drivers.tool_derived import propose as propose_tool

PROPOSERS: dict[str, Callable[[GraphView], DriverResult]] = {
    "global_graph": propose_global,
    "contradiction": propose_contradiction,
    "tool_derived": propose_tool,
    "coverage_derived": propose_coverage,
}


def propose_all(view: GraphView) -> dict[str, DriverResult]:
    return {name: PROPOSERS[name](view) for name in DRIVER_NAMES}
