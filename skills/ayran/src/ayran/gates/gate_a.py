"""Gate A — knowledge-blind pre-PoC challenge. No model calls."""

from __future__ import annotations

import re
from typing import Any

from ayran.context.contracts import provenance_record, seal
from ayran.context.ids import content_id
from ayran.evidence.actors import ACTOR_GATE_A
from ayran.evidence.errors import EVIDENCE_CEILING, GATE_PRECONDITION, EvidenceError
from ayran.evidence.types import (
    DECISION_TO_SCHEMA,
    GATE_A_DECISIONS,
    PRECONDITION_DIMENSIONS,
    RULE_VERSION,
    SOURCE_URI,
    as_mapping,
)
from ayran.mapping.source import parse_solidity

_CALL_RE = re.compile(r"\.call\s*\{|\.call\s*\(|\.transfer\s*\(|\.send\s*\(")
_BALANCE_MUT_RE = re.compile(r"balances\s*\[[^\]]+\]\s*(?:-=|=)")
_MSG_SENDER_PAY = re.compile(r"payable\s*\(\s*msg\.sender\s*\)|\bmsg\.sender\b")
_REQUIRE_RE = re.compile(r"\brequire\s*\(")
_ONLY_OWNER_RE = re.compile(r"\bonlyOwner\b|msg\.sender\s*==\s*owner")


def _source_from_view(view: dict[str, Any] | None, hypothesis: dict[str, Any]) -> tuple[str, str]:
    locator = "target/src/Contract.sol"
    units = []
    if isinstance(view, dict):
        units = list(view.get("source_units") or view.get("sources") or [])
    for unit in units:
        if not isinstance(unit, dict):
            continue
        text = str(unit.get("source") or unit.get("text") or "")
        loc = str(unit.get("locator") or unit.get("name") or locator)
        if text:
            return text, loc
    analysis = hypothesis.get("_source") if isinstance(hypothesis.get("_source"), str) else ""
    return str(analysis or ""), locator


def _function_body(source: str, name: str) -> str:
    match = re.search(rf"function\s+{re.escape(name)}\s*\(", source)
    if not match:
        return source
    start = source.find("{", match.start())
    if start < 0:
        return source[match.start() : match.start() + 800]
    depth = 0
    for index, char in enumerate(source[start:], start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    return source[start : start + 1200]


def _effects_before_interaction(body: str) -> bool:
    call = _CALL_RE.search(body)
    mutation = None
    for match in _BALANCE_MUT_RE.finditer(body):
        mutation = match
    if call is None:
        return True
    if mutation is None:
        return False
    return mutation.start() < call.start()


def _claim_lower(hypothesis: dict[str, Any]) -> str:
    return str(hypothesis.get("claim") or "").lower()


def extract_invariant(hypothesis: dict[str, Any], source: str) -> dict[str, Any]:
    claim = str(hypothesis.get("claim") or "")
    impact = as_mapping(hypothesis.get("impact_premise"))
    formula = str(impact.get("description") or claim)
    if "reentr" in claim.lower():
        formula = "balances[msg.sender] == 0 before external call; conservation of ETH"
    if "arbitrary" in claim.lower() and "send" in claim.lower():
        formula = "withdraw pays only the caller's own credited balance"
    return {
        "statement": formula[:2048],
        "formulas": [formula[:512]],
        "dimensions_units": ["wei", "ETH"],
        "balances": ["balances[msg.sender]", "address(this).balance"] if "balance" in source else [],
        "attacker_capital": "deposit of one unit plus gas",
        "fees_gas": "native gas for one call",
        "expected_profit_loss": str(impact.get("upper_bound") or "unspecified"),
    }


def analyze_preconditions(hypothesis: dict[str, Any], source: str, parsed: dict[str, Any]) -> list[dict[str, Any]]:
    claim = _claim_lower(hypothesis)
    items: list[dict[str, Any]] = []
    for dim in PRECONDITION_DIMENSIONS:
        items.append(
            {
                "dimension": dim,
                "present": False,
                "attacker_can_create": True,
                "detail": f"dimension {dim} not implicated by this claim",
            }
        )
    by_dim = {item["dimension"]: item for item in items}
    if _REQUIRE_RE.search(source):
        by_dim["require_guards"]["present"] = True
        by_dim["require_guards"]["detail"] = "require() guards are present in source"
    if parsed.get("modifiers") or _ONLY_OWNER_RE.search(source):
        by_dim["modifiers"]["present"] = True
        by_dim["access_boundaries"]["present"] = True
        by_dim["modifiers"]["detail"] = "owner/role modifiers present"
        if "setunlock" in claim or "owner" in claim:
            by_dim["modifiers"]["attacker_can_create"] = False
            by_dim["access_boundaries"]["attacker_can_create"] = False
            by_dim["access_boundaries"]["detail"] = "unprivileged attacker cannot satisfy onlyOwner"
    if parsed.get("has_time") or "unlock" in source:
        by_dim["finality_timing"]["present"] = True
        by_dim["slippage_deadline"]["present"] = True
        by_dim["finality_timing"]["detail"] = "timestamp/unlockTime compared in source"
    if parsed.get("has_value"):
        by_dim["solvency"]["present"] = True
        by_dim["solvency"]["detail"] = "value-flow functions exist"
    if "reentr" in claim:
        by_dim["integration_behavior"]["present"] = True
        by_dim["integration_behavior"]["detail"] = "external call during accounting"
        by_dim["integration_behavior"]["attacker_can_create"] = True
    for raw in hypothesis.get("preconditions") or []:
        if not isinstance(raw, dict):
            continue
        desc = str(raw.get("description") or "")
        can = raw.get("attacker_can_create")
        items.append(
            {
                "dimension": "hypothesis_precondition",
                "present": True,
                "attacker_can_create": can if isinstance(can, bool) else None,
                "detail": desc[:1024],
            }
        )
    return items


def strongest_benign(hypothesis: dict[str, Any], source: str, body: str) -> str:
    claim = _claim_lower(hypothesis)
    if (
        "arbitrary" in claim
        and ("send" in claim or "eth" in claim)
        and _MSG_SENDER_PAY.search(body)
        and _effects_before_interaction(body)
    ):
        return (
            "withdraw pays msg.sender after crediting/debiting that caller's own "
            "balance (CEI held); this is a user withdrawal, not an arbitrary send"
        )
    if ("unprotected" in claim or "upgrade" in claim) and _ONLY_OWNER_RE.search(source):
        return "the function is owner-gated; an unprivileged attacker cannot call it"
    if "reentr" in claim and _effects_before_interaction(body):
        return "external call occurs after the balance mutation; reentrancy cannot re-enter with credit"
    return "no stronger benign mechanism than the claimed path was extracted from source"


def missing_facts(hypothesis: dict[str, Any], analysis: dict[str, Any]) -> list[str]:
    named = analysis.get("missing_facts")
    if isinstance(named, list) and named:
        return [str(item)[:512] for item in named if str(item).strip()]
    facts: list[str] = []
    claim = _claim_lower(hypothesis)
    if "deploy" in claim or "proxy" in claim or "bytecode" in claim:
        facts.append("pinned-block deployed bytecode identity versus repo source")
    if hypothesis.get("impact_premise", {}).get("upper_bound") in {None, ""} and "deploy" in claim:
        facts.append("live total-value-at-risk at a pinned block")
    return facts


def cheapest_experiment(
    hypothesis: dict[str, Any],
    *,
    verdict_hint: str,
    analysis: dict[str, Any],
) -> dict[str, Any]:
    specified = analysis.get("experiment")
    if isinstance(specified, dict) and specified.get("inputs"):
        return {
            "inputs": specified.get("inputs") or ["unprivileged caller"],
            "expected_positive": str(specified.get("expected_positive") or "invariant broken"),
            "expected_negative": str(specified.get("expected_negative") or "invariant holds"),
            "capability": str(specified.get("capability") or "foundry.test"),
        }
    if "reentr" in _claim_lower(hypothesis):
        return {
            "inputs": ["attacker contract deposit", "withdraw callback"],
            "expected_positive": "attacker net ETH increases; vault balance decreases twice",
            "expected_negative": "single withdraw without callback preserves conservation",
            "capability": "foundry.test",
        }
    return {
        "inputs": ["unprivileged call along the claimed path"],
        "expected_positive": "claimed invariant breaks with numerical delta",
        "expected_negative": "benign call produces no attacker profit",
        "capability": "foundry.test" if verdict_hint == "poc_worthy" else "none",
    }


def _forced_verdict(analysis: dict[str, Any]) -> str | None:
    forced = analysis.get("verdict") or analysis.get("proposed_verdict")
    if isinstance(forced, str) and forced in GATE_A_DECISIONS:
        return forced
    return None


def decide_verdict(
    hypothesis: dict[str, Any],
    *,
    source: str,
    body: str,
    preconditions: list[dict[str, Any]],
    benign: str,
    facts: list[str],
    analysis: dict[str, Any],
) -> str:
    forced = _forced_verdict(analysis)
    if forced:
        return forced
    claim = _claim_lower(hypothesis)
    invariant = str(analysis.get("invariant") or hypothesis.get("claim") or "").strip()
    if len(invariant) < 12 or invariant.lower() in {"unspecified", "unknown"}:
        return "needs_reformulation"
    owner_blocked = any(
        item.get("dimension") in {"modifiers", "access_boundaries"}
        and item.get("attacker_can_create") is False
        and item.get("present")
        for item in preconditions
    )
    if owner_blocked and ("unprotected" in claim or "arbitrary" not in claim):
        return "falsified"
    if (
        "arbitrary" in claim
        and ("send" in claim or "eth" in claim)
        and _MSG_SENDER_PAY.search(body)
        and _effects_before_interaction(body)
    ):
        return "falsified"
    if "reentr" in claim and _CALL_RE.search(body):
        return "falsified" if _effects_before_interaction(body) else "poc_worthy"
    if facts and analysis.get("treat_missing_as_block") is True:
        return "needs_missing_fact"
    if facts and ("deploy" in claim or "bytecode" in claim):
        return "needs_missing_fact"
    unreachable = [
        item
        for item in preconditions
        if item.get("attacker_can_create") is False and item.get("dimension") == "hypothesis_precondition"
    ]
    if unreachable and not any(item.get("attacker_can_create") is True for item in preconditions):
        return "falsified"
    if "user withdrawal" in benign or "owner-gated" in benign:
        return "falsified"
    return "poc_worthy"


def _decision_status(verdict: str) -> tuple[str, str]:
    schema = DECISION_TO_SCHEMA[verdict]
    return schema, verdict


def build_verdict_record(
    *,
    hypothesis: dict[str, Any],
    verdict: str,
    invariant: dict[str, Any],
    preconditions: list[dict[str, Any]],
    benign: str,
    facts: list[str],
    experiment: dict[str, Any],
    killed: list[str],
    untried: list[str],
    created_at: str,
    independent_from: list[str],
) -> dict[str, Any]:
    hypothesis_id = str(hypothesis["hypothesis_id"])
    verdict_id = content_id("dav", "gate-a", hypothesis_id, verdict, invariant["statement"])
    schema_decision, status = _decision_status(verdict)
    attempts = [
        {
            "question": "Is the claimed invariant exact and attacker-reachable?",
            "result": invariant["statement"][:2048],
            "evidence_ids": [],
            "untried_dimensions": untried[:64],
        },
        {
            "question": "What is the strongest benign explanation?",
            "result": benign[:2048],
            "evidence_ids": [],
            "untried_dimensions": untried[:64],
        },
        {
            "question": "Can an unprivileged attacker create every precondition?",
            "result": "; ".join(
                f"{item['dimension']}={'yes' if item.get('attacker_can_create') else 'no'}"
                for item in preconditions[:16]
            )[:2048]
            or "no preconditions enumerated",
            "evidence_ids": [],
            "untried_dimensions": untried[:64],
        },
    ]
    if facts:
        attempts.append(
            {
                "question": "Which missing source or deployment fact would resolve ambiguity?",
                "result": "; ".join(facts)[:2048],
                "evidence_ids": [],
                "untried_dimensions": untried[:64],
            }
        )
    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "verdict_id": verdict_id,
        "created_at": created_at,
        "run_id": hypothesis["run_id"],
        "target_identity": dict(hypothesis["target_identity"]),
        "gate": "A",
        "decision": schema_decision,
        "resulting_hypothesis_status": status,
        "hypothesis_id": hypothesis_id,
        "evidence_ids": [],
        "falsification_attempts": attempts[:64],
        "causal_chain": [
            invariant["statement"][:1024],
            f"benign:{benign}"[:1024],
            f"experiment:{experiment.get('capability')}:{experiment.get('expected_positive')}"[:1024],
        ],
        "dissent": [f"killed:{item}"[:1024] for item in killed[:32]],
        "confidence": 1.0 if verdict == "falsified" else 0.7,
        "deterministic_rule_version": RULE_VERSION,
        "reviewer": dict(ACTOR_GATE_A),
        "independent_from": independent_from[:256] or [hypothesis_id],
        "provenance": [
            provenance_record(
                created_at=created_at,
                source_uri=SOURCE_URI,
                material=verdict_id,
            )
        ],
    }
    return seal(record)


def run_gate_a(
    hypothesis: dict[str, Any],
    *,
    view: dict[str, Any] | None = None,
    analysis: dict[str, Any] | None = None,
    created_at: str | None = None,
    reconcile: bool = False,
) -> dict[str, Any]:
    """Return a structured Gate A verdict. Never calls a model."""

    status = str(hypothesis.get("status") or "lead")
    grade = str(hypothesis.get("evidence_grade") or "lead")
    payload = dict(analysis or {})
    if payload.get("historical_matches") or payload.get("originator_narrative"):
        # Knowledge-blind: drop Global/originator material before scoring.
        payload = {
            key: value
            for key, value in payload.items()
            if key not in {"historical_matches", "originator_narrative", "global_graph"}
        }
    if status != "supported" and not payload.get("allow_non_supported"):
        raise EvidenceError(
            GATE_PRECONDITION,
            f"Gate A requires a supported hypothesis, not {status}",
            details={"status": status, "evidence_grade": grade},
        )
    if grade == "lead":
        raise EvidenceError(
            EVIDENCE_CEILING,
            "Gate A refuses a lead evidence grade; a poc_worthy verdict on a lead is rejected",
            details={"evidence_grade": grade},
        )
    source, locator = _source_from_view(view, hypothesis)
    if payload.get("source"):
        source = str(payload["source"])
    parsed = parse_solidity(source, locator=locator) if source else {
        "functions": [],
        "modifiers": [],
        "has_time": False,
        "has_value": False,
    }
    fn_name = "withdraw"
    for path in hypothesis.get("attack_path") or []:
        token = str(path).split("(")[0].split(".")[-1]
        if re.fullmatch(r"[A-Za-z_]\w*", token) and token in source:
            fn_name = token
            break
    claim = _claim_lower(hypothesis)
    if "setunlock" in claim:
        fn_name = "setUnlock"
    body = _function_body(source, fn_name) if source else ""
    invariant = extract_invariant(hypothesis, source)
    if payload.get("invariant"):
        invariant["statement"] = str(payload["invariant"])[:2048]
        invariant["formulas"] = [str(payload["invariant"])[:512]]
    preconditions = analyze_preconditions(hypothesis, source, parsed)
    benign = str(payload.get("benign_explanation") or strongest_benign(hypothesis, source, body))
    facts = missing_facts(hypothesis, payload)
    verdict = decide_verdict(
        hypothesis,
        source=source,
        body=body,
        preconditions=preconditions,
        benign=benign,
        facts=facts,
        analysis=payload,
    )
    experiment = cheapest_experiment(hypothesis, verdict_hint=verdict, analysis=payload)
    killed: list[str] = []
    untried = [dim for dim in PRECONDITION_DIMENSIONS]
    if verdict == "falsified":
        if "arbitrary" in claim:
            killed.append("arbitrary-send-eth")
        if "unprotected" in claim:
            killed.append("unprotected-upgrade")
        if "reentr" in claim:
            killed.append("reentrancy-on-claimed-path")
        killed.append(f"function:{fn_name}")
        untried = ["composed-callback-plus-oracle", "cross-function-reentrancy", "token-hook"]
    record = build_verdict_record(
        hypothesis=hypothesis,
        verdict=verdict,
        invariant=invariant,
        preconditions=preconditions,
        benign=benign,
        facts=facts,
        experiment=experiment,
        killed=killed,
        untried=untried,
        created_at=created_at or str(hypothesis.get("created_at") or ""),
        independent_from=[str(hypothesis["hypothesis_id"])],
    )
    result: dict[str, Any] = {
        "schema_version": "1.0.0",
        "verdict": verdict,
        "cannot_mark_surface_safe": True,
        "knowledge_blind": not reconcile,
        "invariant": invariant,
        "preconditions": preconditions,
        "benign_explanation": benign,
        "missing_facts": facts,
        "experiment": experiment,
        "killed_dimensions": killed,
        "untried_dimensions": untried,
        "record": record,
    }
    if reconcile:
        historical = (analysis or {}).get("historical_matches")
        result["reconciliation"] = {
            "considered_global": True,
            "historical_matches": historical or [],
            "blind_verdict_id": record["verdict_id"],
            "note": "reconciliation runs only after the blind verdict is committed",
        }
    return result
