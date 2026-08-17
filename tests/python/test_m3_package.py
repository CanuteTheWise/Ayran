"""M3 package surface: Prime 0.7.2 pi manifest, skills, template, no Prime edits."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SPECIALISTS = (
    "bug-hunter",
    "econ-analyst",
    "attack-mapper",
    "code-reviewer",
    "formal-methods",
    "devils-advocate",
)


def test_pi_manifest_is_discoverable_by_stock_prime() -> None:
    pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    assert "pi-package" in pkg["keywords"]
    pi = pkg["pi"]
    assert pi["extensions"] == ["./prime/extension/index.ts"]
    assert (ROOT / "prime" / "extension" / "index.ts").is_file()
    assert pi["skills"] == ["./skills/ayran", "./skills/specialists"]
    assert pi["prompts"] == ["./prime/prompts"]
    assert pkg["peerDependencies"]["prime-agent"] == "0.7.2"
    assert "proper-lockfile" not in pkg.get("dependencies", {})


def test_core_skill_is_concise_operating_manual() -> None:
    skill = ROOT / "skills" / "ayran" / "SKILL.md"
    lines = skill.read_text(encoding="utf-8").splitlines()
    assert len(lines) < 200
    text = "\n".join(lines).lower()
    assert "authorized" in text
    assert "gate a" in text and "gate b" in text
    assert "context pack" in text
    assert "sandbox" in text


def test_specialist_shells_and_prompts_exist() -> None:
    for name in SPECIALISTS:
        path = ROOT / "skills" / "specialists" / name / "SKILL.md"
        assert path.is_file(), path
        assert "M5" in path.read_text(encoding="utf-8")
    assert (ROOT / "prime" / "prompts" / "audit-setup.md").is_file()
    assert (ROOT / "prime" / "prompts" / "context-pack-header.md").is_file()


def test_append_system_lives_only_in_trusted_template() -> None:
    template = ROOT / ".prime-template" / "agent" / "APPEND_SYSTEM.md"
    charter = template.read_text(encoding="utf-8")
    assert charter.startswith("# Ayran audit charter")
    assert "Never submit or disclose a finding" in charter
    target_copy = ROOT / "target" / ".prime" / "agent" / "APPEND_SYSTEM.md"
    assert not target_copy.exists()
    settings = json.loads(
        (ROOT / ".prime-template" / "agent" / "settings.json").read_text(encoding="utf-8")
    )
    assert settings["rlmMaxDepth"] == 1
    assert settings["ayran"]["contextPackTokenBudget"] == 4000
    assert settings["ayran"]["shutdownTimeoutMs"] == 5000


def test_extension_does_not_import_prime_agent() -> None:
    extension_root = ROOT / "prime" / "extension"
    for path in extension_root.rglob("*.ts"):
        if "generated" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                assert "prime-agent" not in stripped
                assert "@earendil-works" not in stripped
