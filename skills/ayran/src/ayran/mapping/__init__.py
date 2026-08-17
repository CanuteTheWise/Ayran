"""Attack-surface, control/data/value/authority/temporal maps and coverage grid."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ayran.mapping.attack_surface import build_attack_surface
from ayran.mapping.authority import build_authority
from ayran.mapping.control_flow import build_control_flow
from ayran.mapping.coverage import CoverageGrid, CoverageTransitionError
from ayran.mapping.data_flow import build_data_flow
from ayran.mapping.temporal import build_temporal
from ayran.mapping.value_flow import build_value_flow

MAP_BUILDERS: dict[str, Callable[..., dict[str, Any]]] = {
    "attack_surface": build_attack_surface,
    "control_flow": build_control_flow,
    "data_flow": build_data_flow,
    "value_flow": build_value_flow,
    "authority": build_authority,
    "temporal": build_temporal,
}

__all__ = [
    "MAP_BUILDERS",
    "CoverageGrid",
    "CoverageTransitionError",
    "build_attack_surface",
    "build_authority",
    "build_control_flow",
    "build_data_flow",
    "build_temporal",
    "build_value_flow",
]
