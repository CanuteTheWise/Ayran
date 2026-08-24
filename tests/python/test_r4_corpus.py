"""R4 corpus-ingestion acceptance tests (spec sections 6.1, 6.3, 6.5, 11.3, 12-R4).

Every fixture byte under ``fixtures/knowledge/**`` is clearly-labeled
synthetic; the live pinned-commit ingest against upstream bytes is
owner-run after verification (kickoff C4).
"""

from __future__ import annotations

import hashlib
import io
import re
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ayran.evaluation.partitions import (
    ContaminationViolation,
    assert_targets_clean,
    contaminated_protocol_groups,
    enforce_at_harness_start,
)
from ayran.knowledge.defihacklabs import (
    contamination_group,
    iter_exploit_files,
    parse_header,
    to_incident_card,
)
from ayran.knowledge.errors import INGESTION_QUARANTINED, KnowledgeError
from ayran.knowledge.ingestion import ingest_source, load_staged_records
from ayran.knowledge.krait_deep import SUPERSEDED_BY_KEY
from ayran.knowledge.models import (
    IncidentCard,
    LicenseInfo,
    SourcePin,
    SourceRef,
    SourceRegistryEntry,
)
from ayran.knowledge.registry_audit import FABRICATED_SOURCE_IDS, audit_registry
from ayran.knowledge.sanitizers import (
    MAX_ARCHIVE_BYTES,
    check_hostile_hash,
    sanitize_darknavy_curl_strip,
    sanitize_shuvon_amp_rewrite,
    scan_execution_artifacts,
)
from ayran.knowledge.service import (
    ingest_defihacklabs,
    ingest_krait_deep,
    query_records,
    release_corpus,
)
from ayran.knowledge.source_registry import get_source, register_source
from m7_fixtures import copy_knowledge

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "knowledge"
SAMPLES = FIXTURES / "defihacklabs" / "samples"

EULER_TX = "0xc31bcc530831bf0682deb3ba24b1a6a485f5c8d1a1c3a2d2c6ef4f5a6b7c8d9e"
EULER_ATTACKER = "0x5fe274bb0c32f0e0eea1e77b30d5a2eb3e07b3bd"
EULER_VICTIM = "0xe9f1cdc006b7a9df8f5a1c8b3f5d2a7c4e9b1d3f"
EULER_HARNESS = "0x00000000000000000000000000000000dEaDbeef"
VERBATIM_ASSERTION = "assertApproxEqAbs(drained, 190_155_976393, 1e6);"


def _iter_cards(root: Path) -> dict[str, object]:
    cards: dict[str, object] = {}
    for entry in iter_exploit_files(root):
        if entry.card is not None:
            cards[entry.relpath] = entry.card
    return cards


def test_defihacklabs_header_parser_fixture_fidelity() -> None:
    """T01 (spec 12-R4 A, 11.3): every documented field parses from the six
    format-faithful header layouts, and the numeric assertion survives
    verbatim, never rounded or reformatted."""
    cards = _iter_cards(SAMPLES)
    assert len(cards) == 6

    euler = cards["src/test/2022-03/Euler_exp.sol"]
    assert euler.protocol == "Euler"
    assert euler.incident == "Euler"
    assert euler.month == "2022-03"
    assert euler.tx_hash == EULER_TX
    assert euler.exploit_block == 16687227
    assert euler.attacker_address == EULER_ATTACKER
    assert euler.victim_addresses == [EULER_VICTIM, EULER_HARNESS]
    assert euler.loss_amount == "197_000_000 USD"
    assert len(euler.root_cause_lines) == 3
    assert VERBATIM_ASSERTION in euler.assertions
    assert "require(drained > 180_000_000 ether, \"drain below expectation\");" in euler.assertions

    ateam = cards["src/test/2022-10/ATeam_exp.sol"]
    assert ateam.attacker_address == "0x9f51ab5a8a3c2e4d5f60718293a4b5c6d7e8f901"
    assert ateam.victim_addresses == [
        "0x1c2d3e4f5061728394a5b6c7d8e9f00111213140",
        "0x2d3e4f5061728394a5b6c7d8e9f0011121314150",
    ]
    assert ateam.loss_amount is None
    assert ateam.exploit_block == 15771113

    minimal = cards["src/test/2023-01/Minimal_exp.sol"]
    assert minimal.tx_hash == "0x7d2cbb1a6e94d7c8b5a4f3e2d1c0b9a8f7e6d5c4b3a291807f6e5d4c3b2a1908"
    assert minimal.exploit_block == 1640998200
    assert minimal.attacker_address is None and minimal.loss_amount is None

    nimbus = cards["src/test/2023-05/Nimbus_flashloan_exp.sol"]
    assert nimbus.protocol == "Nimbus"
    assert nimbus.incident == "Nimbus_flashloan"
    assert nimbus.tx_hash == "0x4b2f9e0d1a2b3c4d5e6f708192a3b4c5d6e7f8090a1b2c3d4e5f60718293a4b5"
    assert nimbus.loss_amount == "42_500"

    orion = cards["src/test/2023-08/Orion_reentrancy_exp.sol"]
    assert orion.attacker_address == "0x7a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d"
    assert orion.victim_addresses == ["0x8b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e"]
    assert orion.loss_amount == "3_000_000 DAI"

    sentiment = cards["src/test/2024-02/Sentiment_exp.sol"]
    assert sentiment.attacker_address == "0x4c1b2d3e4f5061728394a5b6c7d8e9f01a2b3c4d"
    assert sentiment.loss_amount == "1_000_000 USD"

    card = to_incident_card(
        euler,
        source_ref=SourceRef(source_id="defihacklabs", origin="https://github.com/SunWeb3Sec/DeFiHackLabs"),
        pin=SourcePin(commit="deadbeef"),
        raw_sha256="sha256:" + "0" * 64,
        provenance_uri=f"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/deadbeef/{euler.relpath}",
        sanitizers=["shuvon_amp_rewrite"],
    )
    assert isinstance(card, IncidentCard)
    assert card.record_type == "incident"
    assert card.contamination_group == "contamination:euler:euler"
    assert "contamination:euler:euler" in card.benchmark_exposure
    assert card.safe_for_execution is False
    assert card.sanitizers == ["shuvon_amp_rewrite"]
    assert VERBATIM_ASSERTION in card.assertions_verbatim
    assert any(url.endswith(euler.relpath) for url in card.urls)


def test_parser_reports_irregular_files_without_raising() -> None:
    """T02 (spec 12-R4 A): irregular layouts are reported with reasons, never
    raised; Academy directories are skipped entirely."""
    entries = list(iter_exploit_files(SAMPLES))
    irregular = {entry.relpath: entry.reason for entry in entries if entry.card is None}
    assert set(irregular) == {
        "src/test/2022-05/nounderscore.sol",
        "src/test/2022-13/BadMonth_exp.sol",
        "src/test/2022-06/Weird_exp.sol",
    }
    assert irregular["src/test/2022-05/nounderscore.sol"] == "filename lacks the documented _exp.sol suffix"
    assert "month" in irregular["src/test/2022-13/BadMonth_exp.sol"]
    assert "unreadable" in irregular["src/test/2022-06/Weird_exp.sol"]
    relpaths = {entry.relpath for entry in entries}
    assert not any("Academy" in relpath for relpath in relpaths)

    outside = parse_header("// x\n", "other/dir/File.sol")
    assert outside is not None and getattr(outside, "reason", "").startswith("not under")


def _synthetic_checkout(tmp_path: Path, count: int = 501) -> Path:
    checkout = tmp_path / "defihacklabs-checkout"
    for index in range(count):
        slot = index % 24
        month = f"20{19 + slot // 12:02d}-{slot % 12 + 1:02d}"
        directory = checkout / "src" / "test" / month
        directory.mkdir(parents=True, exist_ok=True)
        lines = [
            f"// Protocol: Proto{index:03d}",
            f"// Attack Tx: 0x{index:040x}",
            f"// EXPLOIT_BLOCK: {15_000_000 + index}",
            f"// Attacker EOA: 0x{index * 7 + 1:040x}",
            f"// Victim Contract: 0x{index * 13 + 5:040x}",
            f"// Loss: {index}_000 USD",
            f"// Root cause: mechanism {index} allowed inflated collateral accounting across transfers.",
        ]
        if index % 25 == 0:
            lines.append("// Build: forge install && forge build")
        lines.extend(
            [
                f"contract Proto{index:03d}_exp {{",
                f"    uint256 constant EXPLOIT_BLOCK = {15_000_000 + index};",
                "    function testExploit() public {",
                f"        uint256 drained = {index}_000;",
                f"        assertApproxEqAbs(drained, {index}_000_000, 1e6);",
                "    }",
                "}",
            ]
        )
        (directory / f"Proto{index:03d}_exp.sol").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return checkout


def test_ingestion_pipeline_500_plus_cards_labeled_synthetic(tmp_path: Path) -> None:
    """T03 (spec 12-R4 A/C, 11.3): SYNTHETIC SCALE PROOF - 501 format-faithful
    cards through the real pipeline; the live 847-PoC count proof against
    pinned upstream bytes is owner-run after verification."""
    root = copy_knowledge(tmp_path)
    checkout = _synthetic_checkout(tmp_path)
    started = time.monotonic()
    result = ingest_defihacklabs(root, checkout, commit="synthetic0000000000000000000000000000")
    elapsed = time.monotonic() - started
    assert elapsed < 120, f"pipeline took {elapsed:.1f}s"
    assert result["accepted"] >= 501
    assert result["irregular_count"] == 0

    records = load_staged_records(root, "defihacklabs")
    assert len(records) >= 501
    record_ids = [record.record_id for record in records]
    assert len(set(record_ids)) == len(record_ids)
    group_re = re.compile(r"^contamination:[a-z0-9]+:[a-z0-9]+$")
    for record in records:
        assert isinstance(record, IncidentCard)
        assert record.record_type == "incident"
        assert record.safe_for_execution is False
        assert record.exploit_block is not None and record.exploit_block >= 15_000_000
        assert group_re.match(record.contamination_group)
        assert record.contamination_group in record.benchmark_exposure
        assert record.sanitizers == ["shuvon_amp_rewrite"]
    assert get_source(root, "defihacklabs").phase == "ingested"


def test_sanitizer_darknavy_curl_strip_removes_fetch_instruction_only() -> None:
    """T04 (spec 11.3): the DarkNavy curl-home VERSION fetch instruction is
    stripped; every other byte survives untouched."""
    text = "\n".join(
        [
            "# DarkNavy setup",
            "curl -sSf https://raw.githubusercontent.com/darknavy/home/VERSION -o VERSION",
            "keep this line byte-for-byte",
            "wget -q https://example.invalid/some/VERSION.txt -O v",
            "# done",
        ]
    )
    cleaned, changed = sanitize_darknavy_curl_strip(text)
    assert changed is True
    assert "curl" not in cleaned
    assert "wget" not in cleaned
    assert "raw.githubusercontent.com" not in cleaned
    assert cleaned.splitlines() == [
        "# DarkNavy setup",
        "keep this line byte-for-byte",
        "# done",
    ]
    untouched, unchanged = sanitize_darknavy_curl_strip("pragma solidity ^0.8.20;\n")
    assert unchanged is False and untouched == "pragma solidity ^0.8.20;\n"


def test_sanitizer_shuvon_amp_rewrite_produces_single_purpose_lines() -> None:
    """T05 (spec 11.3): shuvon-style shell chains become numbered
    single-purpose lines; quoted separators and Solidity expressions are
    preserved."""
    text = "\n".join(
        [
            "npm install foo && npm run build",
            "echo 'a && b' && git status",
            'require(x > 0 && y > 0, "msg");',
        ]
    )
    cleaned, changed = sanitize_shuvon_amp_rewrite(text)
    assert changed is True
    lines = cleaned.splitlines()
    assert lines[0] == "1. npm install foo"
    assert lines[1] == "2. npm run build"
    assert lines[2] == "1. echo 'a && b'"
    assert lines[3] == "2. git status"
    assert lines[4] == 'require(x > 0 && y > 0, "msg");'
    assert "npm install foo && npm run build" not in cleaned
    assert "echo 'a && b' && git status" not in cleaned


def _register(root: Path, entry: SourceRegistryEntry) -> None:
    register_source(root, entry)


def test_blacklist_hook_hard_fails_source_blacklisted(tmp_path: Path) -> None:
    """T06 (spec 11.3 item 2, 6.1): an olaradial-shaped source (blacklisted
    flags) hard-fails at blacklist_hook with SOURCE_BLACKLISTED and produces
    zero staged records."""
    root = copy_knowledge(tmp_path)
    olaradial_raw = root / "raw" / "olaradial"
    olaradial_raw.mkdir(parents=True)
    (olaradial_raw / "README.md").write_text("# renamed dropper bundle\n", encoding="utf-8")
    _register(
        root,
        SourceRegistryEntry(
            source_id="olaradial",
            display_name="olaradial re-proposed",
            origin="https://github.com/Olaradiallysymmetrical491/web3-bug-bounty-hunting-ai-skills",
            pin=SourcePin(),
            license=LicenseInfo(spdx_id="NOASSERTION"),
            contamination_flags=["blacklisted-malware", "do-not-clone-do-not-ingest-do-not-execute"],
            phase="proposed",
        ),
    )
    with pytest.raises(KnowledgeError) as error:
        ingest_source(root, "olaradial")
    assert error.value.code == INGESTION_QUARANTINED
    assert error.value.details is not None
    assert error.value.details["stage"] == "blacklist_hook"
    assert "SOURCE_BLACKLISTED" in error.value.details["reason"]
    assert not (root / "staging" / "olaradial" / "records.json").exists()
    assert get_source(root, "olaradial").phase == "quarantined"

    reintroduced = root / "raw" / "reintroduced"
    reintroduced.mkdir(parents=True)
    (reintroduced / "skill.yaml").write_text("record_type: method\ntitle: renamed clone\n", encoding="utf-8")
    _register(
        root,
        SourceRegistryEntry(
            source_id="reintroduced",
            display_name="renamed clone",
            origin="https://example.invalid/clone",
            pin=SourcePin(),
            license=LicenseInfo(spdx_id="MIT"),
            contamination_flags=["blacklisted-malware"],
            phase="proposed",
        ),
    )
    with pytest.raises(KnowledgeError) as again:
        ingest_source(root, "reintroduced")
    assert "SOURCE_BLACKLISTED" in (again.value.details or {}).get("reason", "")


def test_execution_artifact_scan_rejects_installer_autofetch_and_caps(tmp_path: Path) -> None:
    """T07 (spec 11.3): installer bait, auto-fetch instructions, the 50 MB
    size cap, and zip expansion ratios are all rejected; a poisoned source
    is quarantined at the execution_artifact_scan stage."""
    reasons = scan_execution_artifacts("README.md", b"Unpack the bundle and run install.exe now")
    assert any("installer bait" in reason for reason in reasons)

    reasons = scan_execution_artifacts(
        "notes.txt", b"curl -sSf https://raw.githubusercontent.com/x/y/main/VERSION -o V"
    )
    assert any("auto-fetch" in reason for reason in reasons)

    oversized = scan_execution_artifacts("huge.bin", b"a" * (MAX_ARCHIVE_BYTES + 1))
    assert any("MAX_ARCHIVE_BYTES" in reason for reason in oversized)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros.bin", b"\x00" * (8 * 1024 * 1024))
    bomb_reasons = scan_execution_artifacts("pack.zip", buffer.getvalue())
    assert any("expansion ratio" in reason for reason in bomb_reasons)

    assert scan_execution_artifacts("vault.sol", b"pragma solidity ^0.8.20;\ncontract A {}\n") == []

    root = copy_knowledge(tmp_path)
    _register(
        root,
        SourceRegistryEntry(
            source_id="bait",
            display_name="installer bait",
            origin="https://example.invalid/bait",
            pin=SourcePin(),
            license=LicenseInfo(spdx_id="MIT"),
            phase="proposed",
        ),
    )
    bait_dir = root / "raw" / "bait"
    bait_dir.mkdir(parents=True)
    (bait_dir / "README.md").write_text("run install.exe to set up the toolkit\n", encoding="utf-8")
    with pytest.raises(KnowledgeError) as error:
        ingest_source(root, "bait")
    assert error.value.code == INGESTION_QUARANTINED
    assert error.value.details is not None
    assert error.value.details["stage"] == "execution_artifact_scan"


def test_hostile_hash_blocklist_blocks_matching_artifact(tmp_path: Path) -> None:
    """T08 (spec 6.1): the shipped placeholder line resolves, and an
    operator-appended hash blocks the matching artifact at
    hostile_hash_check."""
    reason = check_hostile_hash("0" * 64)
    assert reason is not None and "olaradial-dropper-placeholder" in reason
    assert check_hostile_hash("f" * 64) is None

    root = copy_knowledge(tmp_path)
    payload = b"plain-looking bytes whose digest the operator blocklisted"
    digest = hashlib.sha256(payload).hexdigest()
    blocklist = root / "registry" / "hostile-artifacts.sha256"
    blocklist.write_text(
        blocklist.read_text(encoding="utf-8") + f"{digest}  test-dropper\n",
        encoding="utf-8",
    )
    _register(
        root,
        SourceRegistryEntry(
            source_id="hostile",
            display_name="hostile artifact carrier",
            origin="https://example.invalid/hostile",
            pin=SourcePin(),
            license=LicenseInfo(spdx_id="MIT"),
            phase="proposed",
        ),
    )
    hostile_dir = root / "raw" / "hostile"
    hostile_dir.mkdir(parents=True)
    (hostile_dir / "dropper.bin").write_bytes(payload)
    with pytest.raises(KnowledgeError) as error:
        ingest_source(root, "hostile")
    assert error.value.code == INGESTION_QUARANTINED
    assert error.value.details is not None
    assert error.value.details["stage"] == "hostile_hash_check"
    assert "test-dropper" in error.value.details["reason"]


def test_registry_audit_zero_fabricated_entries_on_current_tree(tmp_path: Path) -> None:
    """T09 (spec 12-R4 F): the current registry audits clean; fabricated ids
    and incomplete ingested-phase provenance are caught."""
    assert {"foundryvtt", "htsx"} == FABRICATED_SOURCE_IDS
    root = copy_knowledge(tmp_path)
    report = audit_registry(root)
    assert report["ok"] is True
    assert report["violations"] == []
    assert report["checked"] >= 18

    _register(
        root,
        SourceRegistryEntry(
            source_id="foundryvtt",
            display_name="fabricated",
            origin="https://github.com/example/foundryvtt",
            pin=SourcePin(commit="a" * 40, archive_sha256="sha256:" + "b" * 64),
            license=LicenseInfo(spdx_id="MIT"),
            phase="ingested",
        ),
    )
    _register(
        root,
        SourceRegistryEntry(
            source_id="htsx",
            display_name="fabricated unpinned",
            origin="https://github.com/example/htsx",
            pin=SourcePin(),
            license=LicenseInfo(spdx_id="MIT"),
            phase="active",
        ),
    )
    poisoned = audit_registry(root)
    assert poisoned["ok"] is False
    rules = {(item["source_id"], item["rule"]) for item in poisoned["violations"]}
    assert ("foundryvtt", "fabricated") in rules
    assert ("htsx", "fabricated") in rules
    assert ("htsx", "pin.commit") in rules
    assert ("htsx", "pin.archive_sha256") in rules


def _incident(record_id: str, protocol: str, incident: str) -> IncidentCard:
    return IncidentCard(
        record_id=record_id,
        record_type="incident",
        source_ref=SourceRef(source_id="defihacklabs"),
        date=datetime(2026, 1, 1, tzinfo=UTC),
        raw_hash="sha256:" + "0" * 64,
        parser_version="defihacklabs-1.0.0",
        license_info=LicenseInfo(spdx_id="Apache-2.0"),
        contamination_group=contamination_group(protocol, incident),
    )


def test_partitions_exclude_contaminated_protocols_at_eval_start() -> None:
    """T10 (spec 6.3, 12-R4 E): ingested contamination groups collide with
    matching evaluation targets and raise ContaminationViolation; clean
    targets pass; enforce_at_harness_start is the R6 harness entry point."""
    cards = [_incident("r-euler-1", "Euler", "Euler"), _incident("r-euler-2", "Euler", "Euler_flash")]
    groups = contaminated_protocol_groups(cards)
    assert groups == {
        "contamination:euler:euler": ["r-euler-1"],
        "contamination:euler:eulerflash": ["r-euler-2"],
    }

    with pytest.raises(ContaminationViolation) as error:
        assert_targets_clean(["fixtures/contracts/EulerVault.sol"], cards)
    assert any("contamination:euler:euler" in collision for collision in error.value.collisions)
    with pytest.raises(ContaminationViolation):
        enforce_at_harness_start(cards, ["EulerVault.sol"])

    report = enforce_at_harness_start(cards, ["SafeVault.sol"])
    assert report["enforced"] is True
    assert report["groups"] == {"contamination:euler:euler": 1, "contamination:euler:eulerflash": 1}


def test_krait_deep_ingest_predicate_records_supersede_micro_summaries(tmp_path: Path) -> None:
    """T11 (spec 12-R4 D, 6.3): deep predicate-keyed mechanism records
    replace the twelve micro summaries in default retrieval while the
    legacy bytes and records are retained (provenance law)."""
    root = copy_knowledge(tmp_path)
    legacy_before = sorted(path.name for path in (root / "raw" / "krait").glob("*.yaml"))
    assert len(legacy_before) == 12

    result = ingest_krait_deep(
        root,
        FIXTURES / "krait" / "deep-sample",
        commit="76e5ac7b74ce5517409870c2974e6baaddc8f99e",
    )
    assert result["deep_records"] == 3
    assert result["empty_predicates"] == 1
    assert result["superseded"] == 12

    legacy_after = sorted(path.name for path in (root / "raw" / "krait").glob("*.yaml"))
    assert legacy_after == legacy_before

    records = load_staged_records(root, "krait")
    mechanisms = [record for record in records if record.record_type == "mechanism"]
    legacy = [record for record in records if record.record_type != "mechanism"]
    assert len(mechanisms) == 3
    assert len(legacy) == 12
    assert {record.record_type for record in legacy} == {"reasoning_lens", "method", "finding_pattern"}
    assert all(record.safe_for_retrieval is False for record in legacy)
    assert all(SUPERSEDED_BY_KEY in record.near_duplicate_lineage for record in legacy)

    deep = next(record for record in mechanisms if record.canonical_key == "krait-deep-krait0007")
    assert "standard:erc20" in deep.applicability_predicates
    assert "pattern:selector0x8129fc1c" in deep.applicability_predicates
    assert any(item.startswith("solc-range:") for item in deep.applicability_predicates)
    unpredicated = next(
        record for record in mechanisms if record.canonical_key == "krait-deep-krait0099"
    )
    assert unpredicated.applicability_predicates == []

    release_corpus(root, "v0.9.9-r4")
    lenses = query_records(root, record_type="reasoning_lens")["records"]
    assert lenses == []
    published = query_records(root, record_type="mechanism")["records"]
    assert any(record["canonical_key"] == "krait-deep-krait0007" for record in published)


def test_parser_reads_keyinfo_after_import_boilerplate(tmp_path: Path) -> None:
    """T12 (live-corpus repair, operator-sanctioned 2026-08-24): real
    DeFiHackLabs files place the @KeyInfo card AFTER the SPDX/pragma/import
    preamble; every structured field must still parse and the numeric
    assertions must survive verbatim."""
    directory = tmp_path / "src" / "test" / "2026-06"
    directory.mkdir(parents=True)
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.10;",
        "",
        'import "forge-std/Test.sol";',
        'import "../interface.sol";',
        "",
        "// @KeyInfo - Total Lost : ~$87,402 (146.60 WBNB drained from the pair)",
        "// Attacker EOA     : 0x047547A4fa4a67C1032d249B49EC1a79c0460BAD",
        "// Attacker Contract: 0xc08106a36BfA9CFad264F0d64fC45B93543485Ec",
        "// Vulnerable       : 0x6f50cffEcd4e00EcF7E442774C08c089450B62Ca (BY token)",
        "// Victim pair      : 0x1F358e18e0DB68FF33C2319C8DaD328eDF9B7059 (BY/WBNB)",
        "// Attack Tx        : 0xe31c681eee764fb94b1b6bda3bbb0e4f25acb129c19040b9f58ad30541980979",
        "// Attack date      : June 4, 2026  Chain: BSC  Block: 102329719",
        "//",
        "// Root cause: triggerAutoBurn() is permissionless.",
        "// Attacker corners BY supply via router, donates WBNB to hit trading threshold,",
        "// triggers burn to crash BY reserve, then drains WBNB via a flash loan.",
        "",
        "interface IBYToken is IERC20 {",
        "    function transfer(address to, uint256 amount) external returns (bool);",
        "}",
        "",
        "contract BYToken_exp is Test {",
        "    function testExploit() public {",
        '        assertGt(profit, 0, "no profit");',
        "    }",
        "}",
    ]
    path = directory / "BYToken_exp.sol"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    cards = _iter_cards(tmp_path)
    assert set(cards) == {"src/test/2026-06/BYToken_exp.sol"}
    by = cards["src/test/2026-06/BYToken_exp.sol"]
    assert by.tx_hash == "0xe31c681eee764fb94b1b6bda3bbb0e4f25acb129c19040b9f58ad30541980979"
    assert by.exploit_block == 102329719
    assert by.attacker_address == "0x047547A4fa4a67C1032d249B49EC1a79c0460BAD"
    assert by.victim_addresses == [
        "0x6f50cffEcd4e00EcF7E442774C08c089450B62Ca",
        "0x1F358e18e0DB68FF33C2319C8DaD328eDF9B7059",
    ]
    assert by.loss_amount == "87,402"
    assert by.root_cause_lines == [
        "triggerAutoBurn() is permissionless.",
        "Attacker corners BY supply via router, donates WBNB to hit trading threshold,",
        "triggers burn to crash BY reserve, then drains WBNB via a flash loan.",
    ]
    assert 'assertGt(profit, 0, "no profit");' in by.assertions

    record = to_incident_card(
        by,
        source_ref=SourceRef(source_id="defihacklabs", origin="https://github.com/SunWeb3Sec/DeFiHackLabs"),
        pin=SourcePin(commit="deadbeef"),
        raw_sha256="sha256:" + "1" * 64,
        provenance_uri=f"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/deadbeef/{by.relpath}",
        sanitizers=[],
    )
    assert record.attack_tx_hash == by.tx_hash
    assert record.exploit_block == 102329719
    assert record.loss_amount == "87,402"
    assert record.mechanism == "flash loan"
    assert record.contamination_group == "contamination:bytoken:bytoken"


def test_parser_analysis_section_and_fork_block_fallback(tmp_path: Path) -> None:
    """T13 (live-corpus repair, survey-driven): @Analysis prose parses as root
    cause while link lines stay out of it, and the exploited block comes from
    createSelectFork when no header block label exists."""
    directory = tmp_path / "src" / "test" / "2023-03"
    directory.mkdir(parents=True)
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.10;",
        "",
        'import "forge-std/Test.sol";',
        "",
        "// @KeyInfo - Total Lost : ~$197M",
        "// Attacker : 0x5fe274bb0c32f0e0eea1e77b30d5a2eb3e07b3bd",
        "// Attack Tx : https://etherscan.io/tx/0xc31bcc530831bf0682deb3ba24b1a6a485f5c8d1a1c3a2d2c6ef4f5a6b7c8d9e",
        "",
        "// @Analysis",
        "// The oracle price was manipulated with a flash loan,",
        "// then collateral accounting double-counted the inflated position.",
        "// Post-mortem : https://example.invalid/post-mortem",
        "",
        "contract Euler_exp is Test {",
        "    function setUp() public {",
        '        vm.createSelectFork("mainnet", 16687227);',
        "    }",
        "}",
    ]
    path = directory / "Euler_exp.sol"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    cards = _iter_cards(tmp_path)
    euler = cards["src/test/2023-03/Euler_exp.sol"]
    assert euler.tx_hash == "0xc31bcc530831bf0682deb3ba24b1a6a485f5c8d1a1c3a2d2c6ef4f5a6b7c8d9e"
    assert euler.exploit_block == 16687227
    assert euler.attacker_address == "0x5fe274bb0c32f0e0eea1e77b30d5a2eb3e07b3bd"
    assert euler.root_cause_lines == [
        "The oracle price was manipulated with a flash loan,",
        "then collateral accounting double-counted the inflated position.",
    ]

    record = to_incident_card(
        euler,
        source_ref=SourceRef(source_id="defihacklabs", origin="https://github.com/SunWeb3Sec/DeFiHackLabs"),
        pin=SourcePin(commit="deadbeef"),
        raw_sha256="sha256:" + "2" * 64,
        provenance_uri=f"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/deadbeef/{euler.relpath}",
        sanitizers=[],
    )
    assert record.mechanism == "oracle"
    assert record.attack_tx_hash == euler.tx_hash


def test_yaml_lite_rejects_deeper_inline_map_continuation() -> None:
    """T14a (live-corpus repair): inline mapping entries whose continuation
    lines are indented deeper than dash-indent+2 must raise YamlLiteError,
    never spin forever (found hanging on 26 real Krait pattern YAMLs)."""
    from ayran.tools.yaml_lite import YamlLiteError, load_yaml

    with pytest.raises(YamlLiteError):
        load_yaml("a:\n  - x: 1\n     y: 2\n")
    with pytest.raises(YamlLiteError):
        load_yaml("a:\n  - x: 1\n      y: 2\n        z: 3\n")
    # Well-formed documents keep parsing.
    assert load_yaml("a:\n  - x: 1\n    y: 2\n") == {"a": [{"x": 1, "y": 2}]}


def test_krait_framework_json_checks_parse(tmp_path: Path) -> None:
    """T14b (live-corpus repair): the checklist/frameworks JSON aggregate
    (845 checks at the pinned commit) becomes predicate-keyed mechanism
    records with verbatim questions and framework/tag applicability."""
    import json as _json

    from ayran.knowledge.krait_deep import parse_krait_framework_checks

    blob = _json.dumps(
        {
            "lending": {
                "label": "Lending / Borrowing",
                "totalChecks": 2,
                "version": "3.0.0",
                "checks": [
                    {
                        "id": "LN-01",
                        "q": "Is your collateral validation implemented securely?",
                        "sev": "high",
                        "cat": "Collateral Management",
                        "tags": ["collateral"],
                    },
                    {
                        "id": "LN-02",
                        "q": "Is your price manipulation implemented securely?",
                        "sev": "critical",
                        "cat": "Economic Attacks",
                        "tags": ["MEV", "flash-loan", "liquidation", "oracle"],
                    },
                    {"note": "no id and no q - skipped"},
                ],
            }
        }
    )
    records = parse_krait_framework_checks(blob)
    assert set(records) == {"krait-deep-lending-ln01", "krait-deep-lending-ln02"}
    first = records["krait-deep-lending-ln01"]
    assert first["record_type"] == "mechanism"
    assert first["title"] == "Is your collateral validation implemented securely?"
    assert first["summary"] == "[high] Is your collateral validation implemented securely?"
    assert first["applicability_predicates"] == [
        "framework:lending",
        "pattern:collateral",
        "pattern:collateralmanagement",
    ]
    second = records["krait-deep-lending-ln02"]
    assert "[critical]" in second["summary"]
    assert "pattern:flashloan" in second["applicability_predicates"]
    # Non-JSON and non-framework input fall through empty for the block parser.
    assert parse_krait_framework_checks("id: x\nname: y\n---\nid: z\nname: w\n") == {}
    assert parse_krait_framework_checks("[]") == {}
