"""Load-bearing context-pack classifications. The compiler never recasts labels."""

from __future__ import annotations

from typing import Literal

Classification = Literal[
    "POLICY",
    "DETERMINISTIC_FACT",
    "RUNTIME_OBSERVATION",
    "SOURCE_CLAIM",
    "ASSUMPTION",
    "HYPOTHESIS",
    "HISTORICAL_REFERENCE",
    "COUNTEREVIDENCE",
    "UNTRUSTED_DATA",
]

LABELS: tuple[Classification, ...] = (
    "POLICY",
    "DETERMINISTIC_FACT",
    "RUNTIME_OBSERVATION",
    "SOURCE_CLAIM",
    "ASSUMPTION",
    "HYPOTHESIS",
    "HISTORICAL_REFERENCE",
    "COUNTEREVIDENCE",
    "UNTRUSTED_DATA",
)

FACT_LABELS = {"DETERMINISTIC_FACT", "RUNTIME_OBSERVATION"}
NON_FACT_LABELS = {"ASSUMPTION", "HYPOTHESIS", "HISTORICAL_REFERENCE", "SOURCE_CLAIM"}
