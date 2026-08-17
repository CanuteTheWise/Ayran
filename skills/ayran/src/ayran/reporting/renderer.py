"""Markdown and JSON report renderers. Never launch tools."""

from __future__ import annotations

import json
import re
from typing import Any

from ayran.evidence.types import as_mapping

CLAIM_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _tag(sentence: str, source: str, kind: str) -> str:
    text = sentence.strip()
    if not text:
        return ""
    if not text.endswith("."):
        text += "."
    return f"{text} [{kind}:{source}]"


def _claim_source(finding: dict[str, Any], extras: dict[str, Any]) -> str:
    evidence = finding.get("evidence_ids") or []
    if evidence:
        return str(evidence[0])
    if extras.get("result_hash"):
        return str(extras["result_hash"])
    return str(finding.get("finding_id") or "unknown")


def render_markdown(finding: dict[str, Any]) -> str:
    extras = as_mapping(finding.get("_extras"))
    evidence_ref = _claim_source(finding, extras)
    assumptions = list(as_mapping(finding.get("impact")).get("assumptions") or [])
    uncertainty = list(finding.get("uncertainty") or [])
    severity = as_mapping(finding.get("severity"))
    disposition = as_mapping(finding.get("duplicate_disposition"))
    steps = extras.get("attack_steps") or finding.get("preconditions") or []
    lines = [
        f"# {finding.get('title') or 'Finding'}",
        "",
        f"Status: `{finding.get('status')}`.",
        "",
        "## Root cause",
        _tag(str(finding.get("root_cause") or "unspecified"), evidence_ref, "evidence"),
        "",
        "## Violated invariant",
        _tag(str(finding.get("violated_invariant") or "unspecified"), evidence_ref, "evidence"),
        "",
        "## Affected code",
    ]
    for span in finding.get("affected_code") or []:
        lines.append(_tag(f"Affected locator {span}", evidence_ref, "evidence"))
    lines.extend(["", "## Attacker model"])
    lines.append(_tag(str(finding.get("attacker_model") or "unspecified"), evidence_ref, "evidence"))
    lines.extend(["", "## Attack steps"])
    for index, step in enumerate(steps, 1):
        lines.append(_tag(f"Step {index}: {step}", evidence_ref, "evidence"))
    lines.extend(["", "## Impact"])
    impact = finding.get("impact") or {}
    lines.append(
        _tag(
            f"Impact kind {impact.get('kind')} with equation {impact.get('equation')} "
            f"bounded [{impact.get('lower_bound')}, {impact.get('upper_bound')}]",
            evidence_ref,
            "evidence",
        )
    )
    lines.extend(["", "## Assumptions"])
    if assumptions:
        for item in assumptions:
            lines.append(_tag(str(item), "impact", "assumption"))
    else:
        lines.append(_tag("No additional numerical assumptions were recorded", "impact", "assumption"))
    if uncertainty:
        lines.extend(["", "## Uncertainty"])
        for item in uncertainty:
            lines.append(_tag(str(item), "severity", "uncertainty"))
    lines.extend(["", "## Evidence"])
    if finding.get("gate_a_verdict_id"):
        lines.append(_tag(f"Gate A verdict {finding['gate_a_verdict_id']}", finding["gate_a_verdict_id"], "evidence"))
    if finding.get("gate_b_verdict_id"):
        lines.append(_tag(f"Gate B verdict {finding['gate_b_verdict_id']}", finding["gate_b_verdict_id"], "evidence"))
    for item in finding.get("evidence_ids") or []:
        lines.append(_tag(f"Evidence artifact {item}", str(item), "evidence"))
    lines.extend(["", "## Reproduction"])
    command = str(extras.get("one_command") or "forge test --match-test test_exploit --json")
    result_hash = str(extras.get("result_hash") or evidence_ref)
    lines.append(_tag(f"One-command reproduction is `{command}`", result_hash, "evidence"))
    expected = extras.get("expected_output")
    if expected:
        lines.append(_tag(f"Expected output excerpt: {expected}", result_hash, "evidence"))
    lines.extend(["", "## Severity"])
    if severity:
        lines.append(
            _tag(
                f"Severity {severity.get('label')} under policy {severity.get('policy_id')} "
                f"({severity.get('rule_citation')})",
                str(severity.get("policy_id") or "policy"),
                "evidence",
            )
        )
    else:
        lines.append(_tag("Severity is not cited because this finding is not validated", "status", "uncertainty"))
    lines.extend(["", "## Duplicate disposition"])
    if disposition:
        lines.append(
            _tag(
                f"Disposition {disposition.get('status')}: {disposition.get('comparison')}",
                evidence_ref,
                "evidence",
            )
        )
    lines.extend(["", "## Mitigation"])
    for item in finding.get("mitigations") or ["Restore checks-effects-interactions and add a regression test"]:
        lines.append(_tag(str(item), evidence_ref, "evidence"))
    lines.extend(["", "This report does not submit itself."])
    return "\n".join(lines) + "\n"


def render_json(finding: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in finding.items() if not str(key).startswith("_")}


def render(finding: dict[str, Any], *, fmt: str = "markdown") -> dict[str, Any]:
    canonical = render_json(finding)
    if fmt == "json":
        body = json.dumps(canonical, indent=2, sort_keys=True)
        return {"format": "json", "body": body, "finding": canonical}
    return {"format": "markdown", "body": render_markdown(finding), "finding": canonical}
