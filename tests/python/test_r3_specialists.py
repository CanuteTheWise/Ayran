"""R3 specialists: INV-5.9 fourteen roles with methodology, goal.v1, ToB attribution."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPECIALISTS_ROOT = ROOT / "skills" / "specialists"

EXPECTED_ROLES = (
    "devils-advocate",
    "gate-b-skeptic",
    "econ-analyst",
    "state-coupling-auditor",
    "code-reviewer",
    "access-control-analyst",
    "boundary-provenance-auditor",
    "x-ray-invariant-synthesist",
    "formal-methods",
    "fuzz-harness-engineer",
    "attack-mapper",
    "bug-hunter",
    "precedent-analyst",
    "coverage-auditor",
)

TOB_ROLES = ("devils-advocate", "gate-b-skeptic", "formal-methods", "attack-mapper")

DONOR_KEYS = (
    "krait",
    "quillshield",
    "shuvon",
    "pashov",
    "plamen",
    "hound",
    "defihacklabs",
    "zeroskills",
    "0xsimao",
    "scv-scan",
    "trailofbits",
    "sanbir",
    "forefy",
    "falcon",
    "ityfuzz",
    "nemesis",
    "darknavy",
)

GOAL_MARKERS = (
    "end_state[]",
    "proof[]",
    "termination {max_turns | max_duration | stop_on}",
    "guardrails {invariants[], allowed_paths[]}",
)


def _frontmatter_name(text: str) -> str:
    assert text.startswith("---\n") or text.startswith("---\r\n"), "missing YAML frontmatter"
    closing = text.find("\n---", 3)
    assert closing != -1, "unclosed YAML frontmatter"
    block = text[3:closing]
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("name:"):
            return stripped.split(":", 1)[1].strip()
    raise AssertionError("frontmatter missing name")


def test_fourteen_specialists_present_with_methodology_and_goal_v1() -> None:
    dirs = sorted(path.name for path in SPECIALISTS_ROOT.iterdir() if path.is_dir())
    assert tuple(dirs) == tuple(sorted(EXPECTED_ROLES))
    assert len(dirs) == 14
    extras = set(dirs) - set(EXPECTED_ROLES)
    assert not extras
    for name in EXPECTED_ROLES:
        skill = SPECIALISTS_ROOT / name / "SKILL.md"
        assert skill.is_file(), skill
        text = skill.read_text(encoding="utf-8")
        assert _frontmatter_name(text) == name
        found = [key for key in DONOR_KEYS if key in text]
        assert len(found) >= 3, f"{name} donor keys {found}"
        assert "goal.v1" in text
        for marker in GOAL_MARKERS:
            assert marker in text, f"{name} missing {marker}"
        assert "ZERO sidecar-write verbs" in text
        assert "[lenses: 2+] LEAD->FINDING upgrade requires >=2 independent lenses converging" in text
        assert "raw.githubusercontent" not in text
        assert "&&" not in text
        assert "conservation equation" not in text
        assert "debit-credit table" not in text
        assert "cohort timeline" not in text


def test_tob_roles_carry_attribution_files() -> None:
    for name in TOB_ROLES:
        path = SPECIALISTS_ROOT / name / "ATTRIBUTION.md"
        assert path.is_file(), path
        text = path.read_text(encoding="utf-8")
        assert "CC BY-SA 4.0" in text or "Attribution-ShareAlike 4.0" in text
        assert "trailofbits" in text.lower() or "Trail of Bits" in text
