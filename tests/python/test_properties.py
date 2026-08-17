from __future__ import annotations

import re

from ayran.api.validators import SCHEMAS
from hypothesis import given
from hypothesis import strategies as st

DEFS = SCHEMAS["common"]["$defs"]


@given(
    st.sampled_from(["run", "tgt", "evt", "hyp", "evd", "rta"]),
    st.integers(min_value=0, max_value=10**20),
)
def test_generated_prefixed_ulids_fit_identifier_contract(prefix: str, number: int) -> None:
    value = f"{prefix}_01J{number:023d}"[-(len(prefix) + 27) :]
    assert re.fullmatch(DEFS["Identifier"]["pattern"], value)


@given(st.text(alphabet="0123456789abcdef", min_size=64, max_size=64))
def test_lowercase_sha256_values_fit_hash_contract(hex_value: str) -> None:
    assert re.fullmatch(DEFS["Hash"]["pattern"], f"sha256:{hex_value}")


@given(st.integers(min_value=1, max_value=9007199254740991))
def test_event_sequence_bounds_are_javascript_safe(value: int) -> None:
    schema = SCHEMAS["graph-event"]["properties"]["seq"]
    assert schema["minimum"] <= value <= schema["maximum"]


@given(st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", fullmatch=True))
def test_idempotency_keys_match_event_contract(value: str) -> None:
    pattern = SCHEMAS["graph-event"]["properties"]["idempotency_key"]["pattern"]
    assert re.fullmatch(pattern, value)


@given(
    st.integers(min_value=0, max_value=999),
    st.integers(min_value=0, max_value=999),
    st.integers(min_value=0, max_value=999),
)
def test_semantic_versions_fit_contract(major: int, minor: int, patch: int) -> None:
    assert re.fullmatch(DEFS["SemVer"]["pattern"], f"{major}.{minor}.{patch}")
