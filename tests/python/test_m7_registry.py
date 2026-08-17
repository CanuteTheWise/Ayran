"""M7 source registry: register, get, list, tombstone."""

from __future__ import annotations

from pathlib import Path

import pytest
from ayran.knowledge.errors import SOURCE_DEFERRED, SOURCE_NOT_FOUND, KnowledgeError
from ayran.knowledge.ingestion import ingest_source
from ayran.knowledge.models import LicenseInfo, SourcePin, SourceRegistryEntry
from ayran.knowledge.source_registry import (
    get_source,
    list_sources,
    register_source,
    tombstone_source,
)
from m7_fixtures import copy_knowledge


def test_register_get_list_and_tombstone(tmp_path: Path) -> None:
    root = tmp_path / "knowledge"
    entry = SourceRegistryEntry(
        source_id="example",
        display_name="Example",
        origin="https://example.invalid/repo",
        pin=SourcePin(commit="a" * 40),
        license=LicenseInfo(spdx_id="MIT"),
        phase="proposed",
    )
    assert register_source(root, entry) == "example"
    loaded = get_source(root, "example")
    assert loaded.display_name == "Example"
    assert loaded.license.local_use is True
    assert [item.source_id for item in list_sources(root, phase="proposed")] == ["example"]
    tomb = tombstone_source(root, "example", "revoked", when="2026-08-14T00:00:00Z")
    assert tomb.reason == "revoked"
    assert get_source(root, "example").phase == "tombstoned"
    with pytest.raises(KnowledgeError) as error:
        get_source(root, "missing")
    assert error.value.code == SOURCE_NOT_FOUND


def test_authored_sources_are_complete(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    sources = list_sources(root)
    ids = {item.source_id for item in sources}
    assert {"zeroskills", "solodit", "0xsimao", "krait"} <= ids
    assert {"falcon", "hound", "olaradial", "ityfuzz"} <= ids
    assert get_source(root, "zeroskills").phase == "proposed"
    assert get_source(root, "olaradial").phase == "catalogued"
    assert get_source(root, "falcon").phase == "deferred"


def test_deferred_source_cannot_be_ingested(tmp_path: Path) -> None:
    root = copy_knowledge(tmp_path)
    with pytest.raises(KnowledgeError) as error:
        ingest_source(root, "falcon")
    assert error.value.code == SOURCE_DEFERRED
