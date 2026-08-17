"""Report linter: hard-fail unsupported claims, soft-warn completeness gaps."""

from __future__ import annotations

import re
from typing import Any

from ayran.evidence.types import as_mapping

SECRET_RE = re.compile(
    r"(?:[A-Za-z]:\\|/home/|/Users/|BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY|api[_-]?key\s*=|token=)",
    re.IGNORECASE,
)
DEFINITIVE_RE = re.compile(
    r"\b(?:this is exploitable|definitely vulnerable|proven safe|the area is clean|unquestionably)\b",
    re.IGNORECASE,
)
CLAIM_TAG_RE = re.compile(r"\[(evidence|assumption|uncertainty):([^\]]+)\]")
COMMAND_RE = re.compile(r"forge test|anvil |cast ")


def _sentences(markdown: str) -> list[str]:
    body = markdown.replace("\n", " ")
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+", body) if part.strip()]


def lint(
    finding: dict[str, Any],
    markdown: str,
    *,
    current_source: str | None = None,
) -> dict[str, Any]:
    hard: list[str] = []
    soft: list[str] = []
    status = str(finding.get("status") or "candidate")
    extras = as_mapping(finding.get("_extras"))
    severity = as_mapping(finding.get("severity"))

    if status != "validated":
        hard.append("status below validated")
    if not finding.get("reproduction_artifact_id") and not extras.get("one_command"):
        hard.append("missing proof")
    if status == "validated" and not finding.get("reproduction_artifact_id"):
        hard.append("missing proof")
    if status == "validated" and not severity.get("rule_citation"):
        hard.append("uncited policy")
    if status == "validated" and not severity.get("policy_id"):
        hard.append("uncited policy")

    if SECRET_RE.search(markdown):
        hard.append("secret/path leakage")

    for span in finding.get("affected_code") or []:
        text = str(span)
        if current_source is not None:
            line = None
            if ":" in text:
                try:
                    line = int(text.rsplit(":", 1)[-1])
                except ValueError:
                    line = None
            if line is not None:
                lines = current_source.splitlines()
                if line < 1 or line > len(lines) or not lines[line - 1].strip():
                    hard.append("stale source lines")
                    break

    command = extras.get("one_command") or ""
    if "Reproduction" in markdown and not COMMAND_RE.search(markdown) and not command:
        hard.append("non-reproducible commands")
    if command and "forge test" not in command and "--match-test" not in command:
        hard.append("non-reproducible commands")

    if DEFINITIVE_RE.search(markdown) and not finding.get("reproduction_artifact_id"):
        hard.append("unsupported definitive language")

    tagged = 0
    untagged_claims = 0
    for sentence in _sentences(markdown):
        if sentence.startswith("#") or sentence.startswith("Status:"):
            continue
        if "does not submit itself" in sentence.lower():
            continue
        if CLAIM_TAG_RE.search(sentence):
            tagged += 1
        elif re.search(r"\b(is|are|violates|steals|exploitable)\b", sentence, re.IGNORECASE):
            untagged_claims += 1
    if untagged_claims:
        hard.append("hidden assumptions")

    if (
        not finding.get("negative_control_ids")
        and status == "validated"
        and "negative control" not in markdown.lower()
    ):
        soft.append("missing negative controls")
    steps = extras.get("attack_steps") or finding.get("preconditions") or []
    if len(steps) < 2:
        soft.append("unclear attack steps")
    if not finding.get("uncertainty") and "[uncertainty:" not in markdown:
        soft.append("missing uncertainty labels")
    if "regression" not in markdown.lower():
        soft.append("missing regression test suggestions")

    return {
        "schema_version": "1.0.0",
        "passed": not hard,
        "hard": sorted(set(hard)),
        "soft": sorted(set(soft)),
        "tagged_claims": tagged,
        "untagged_claims": untagged_claims,
    }
