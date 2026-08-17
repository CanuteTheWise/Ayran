"""Sidecar/CLI facade for the M6 evidence pipeline.

Engines are pure. This module is the only caller of GraphStore.append.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ayran.context.ids import content_id
from ayran.context.queries import OntologyQueries, snapshot_view
from ayran.evidence.actors import (
    ACTOR_DEDUP,
    ACTOR_EVIDENCE,
    ACTOR_FINDING,
    ACTOR_GATE_A,
    ACTOR_GATE_B,
    ACTOR_POC,
)
from ayran.evidence.dedup import check_duplicates
from ayran.evidence.errors import (
    FINDING_NOT_FOUND,
    HYPOTHESIS_NOT_FOUND,
    POC_NOT_FOUND,
    EvidenceError,
)
from ayran.evidence.finding import build_finding
from ayran.evidence.impact import assess_impact
from ayran.evidence.load import (
    load_finding,
    load_hypotheses,
    load_hypothesis,
    load_nodes_by_type,
    load_poc,
    load_verdicts_for,
    node_props,
)
from ayran.evidence.persist import (
    evidence_node,
    persist_contract,
    persist_duplicate_edge,
    persist_hypothesis_revision,
    persist_runtime_node,
)
from ayran.evidence.poc import (
    apply_recorded_result,
    execute_foundry,
    replay_recorded,
    request_from_hypothesis,
)
from ayran.evidence.severity import assess_severity
from ayran.evidence.state_machine import HypothesisStateMachine
from ayran.evidence.types import DEFAULT_SEVERITY_POLICY_ID
from ayran.gates.gate_a import run_gate_a
from ayran.gates.gate_b import run_gate_b
from ayran.graph.recovery import GraphStore
from ayran.reporting.linter import lint as lint_report
from ayran.reporting.renderer import render as render_report

MACHINE = HypothesisStateMachine()


def _view_dict(store: GraphStore, cluster_id: str | None = None) -> dict[str, Any]:
    view = snapshot_view(
        OntologyQueries(store=store),
        cluster_id=cluster_id,
        run_id=str(store.stream.get("run_id") or ""),
    )
    return {
        "source_units": list(view.source_units),
        "cluster_id": view.cluster_id,
        "run_id": view.run_id,
        "target_identity": view.target_identity,
    }


def _require_hypothesis(store: GraphStore, hypothesis_id: str) -> dict[str, Any]:
    found = load_hypothesis(store, hypothesis_id)
    if found is None:
        raise EvidenceError(HYPOTHESIS_NOT_FOUND, f"hypothesis {hypothesis_id} was not found")
    return found


def _apply_local(
    hypothesis: dict[str, Any],
    decision: Any,
    actor: dict[str, Any],
    evidence: dict[str, Any],
    created_at: str,
) -> tuple[dict[str, Any], str]:
    event_id = content_id(
        "evt",
        str(hypothesis.get("hypothesis_id") or ""),
        decision.current,
        decision.target,
        decision.reason,
    )
    history = list(hypothesis.get("transition_history") or [])
    refs = [str(item) for item in (evidence.get("evidence_ids") or []) if isinstance(item, str)]
    history.append(
        {
            "from": decision.current,
            "to": decision.target,
            "event_id": event_id,
            "actor": dict(actor),
            "at": created_at,
            "evidence_ids": refs[:256],
        }
    )
    updated = dict(hypothesis)
    updated["status"] = decision.target
    updated["evidence_grade"] = decision.next_grade
    updated["transition_history"] = history[:128]
    if decision.target == "supported":
        if evidence.get("invariant"):
            updated["invariant_ids"] = [content_id("inv", str(evidence["invariant"]))][:256]
        if evidence.get("path"):
            path = [str(evidence["path"])[:512]]
            updated["attack_path"] = (path + [str(item) for item in (updated.get("attack_path") or [])])[:64]
        if evidence.get("source_span"):
            entities = list(updated.get("target_entities") or [])
            span_id = content_id("nod", str(evidence["source_span"]))
            if span_id not in entities:
                entities.insert(0, span_id)
            updated["target_entities"] = entities[:256]
    if decision.target == "duplicate_known_issue":
        duplicate_of = str(evidence.get("duplicate_of") or "")
        ids = list(updated.get("duplicate_candidate_ids") or [])
        if duplicate_of and duplicate_of not in ids:
            ids.append(duplicate_of)
        updated["duplicate_candidate_ids"] = ids[:256]
    return updated, event_id


def transition(
    store: GraphStore,
    hypothesis_id: str,
    target: str,
    *,
    evidence: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
    cause: str | None = None,
) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    used_actor = actor or ACTOR_EVIDENCE
    payload = dict(evidence or {})
    decision = MACHINE.require(
        hypothesis, target, actor=used_actor, evidence=payload, cause=cause
    )
    stamp = str(hypothesis.get("created_at") or "")
    updated, event_id = _apply_local(hypothesis, decision, used_actor, payload, stamp)
    ack = persist_hypothesis_revision(
        store, updated, actor=used_actor, decision=decision, event_id=event_id, created_at=stamp
    )
    if decision.target == "duplicate_known_issue" and payload.get("duplicate_of"):
        persist_duplicate_edge(
            store,
            source_id=hypothesis_id,
            target_id=str(payload["duplicate_of"]),
            run_id=str(updated.get("run_id") or ""),
            created_at=stamp,
            comparison=str(payload.get("comparison") or "duplicate"),
        )
    return {
        "accepted": True,
        "hypothesis_id": hypothesis_id,
        "from": decision.current,
        "to": decision.target,
        "demotion": decision.demotion,
        "event_id": event_id,
        "acknowledgement": ack,
        "hypothesis": {key: value for key, value in updated.items() if not str(key).startswith("_")},
    }


def _auto_transition_from_gate(
    store: GraphStore,
    hypothesis: dict[str, Any],
    verdict: str,
    *,
    actor: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any] | None:
    current = str(hypothesis.get("status") or "")
    if current == verdict:
        return None
    try:
        return transition(
            store,
            str(hypothesis["hypothesis_id"]),
            verdict,
            evidence=evidence,
            actor=actor,
            cause=f"gate verdict {verdict}",
        )
    except EvidenceError as error:
        return error.as_result()


def gate_a(
    store: GraphStore,
    hypothesis_id: str,
    *,
    analysis: dict[str, Any] | None = None,
    reconcile: bool = False,
) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    view = _view_dict(store)
    result = run_gate_a(
        hypothesis,
        view=view,
        analysis=analysis,
        created_at=str(hypothesis.get("created_at") or ""),
        reconcile=reconcile,
    )
    record = result["record"]
    persist_contract(store, "da-verdict", record, actor=ACTOR_GATE_A, event_stem="da_verdict")
    evidence = {
        "gate_a_verdict_id": record["verdict_id"],
        "experiment": result.get("experiment") or {"inputs": ["n/a"]},
        "killed_dimension": (result.get("killed_dimensions") or ["dimension"])[0],
        "counterevidence": result.get("benign_explanation") or "benign explanation",
        "named_fact": (result.get("missing_facts") or ["unspecified fact"])[0],
        "why_decisive": "resolves benign versus malicious ambiguity",
        "failed_premise": result.get("benign_explanation") or "premise failed Gate A",
        "evidence_ids": [record["verdict_id"]],
    }
    moved = _auto_transition_from_gate(
        store, hypothesis, str(result["verdict"]), actor=ACTOR_GATE_A, evidence=evidence
    )
    result["transition"] = moved
    result["verdict_id"] = record["verdict_id"]
    return result


def gate_b(
    store: GraphStore,
    hypothesis_id: str,
    *,
    obligations: dict[str, Any] | None = None,
    poc_id: str | None = None,
    profile: str = "executable",
) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    poc = load_poc(store, poc_id) if poc_id else None
    if poc is None:
        for node in load_nodes_by_type(store, "PocRun"):
            props = node_props(node)
            if props.get("hypothesis_id") == hypothesis_id:
                poc = props
                poc["poc_id"] = node["node_id"]
                break
    result = run_gate_b(
        hypothesis,
        obligations=obligations,
        poc=poc,
        created_at=str(hypothesis.get("created_at") or ""),
        profile=profile,
    )
    record = result.get("record")
    if isinstance(record, dict):
        persist_contract(store, "da-verdict", record, actor=ACTOR_GATE_B, event_stem="da_verdict")
        result["verdict_id"] = record["verdict_id"]
        evidence = {
            "negative_control_ids": list((obligations or {}).get("negative_control_ids") or [record["verdict_id"]]),
            "fix_evidence_ids": list((obligations or {}).get("fix_evidence_ids") or [record["verdict_id"]]),
            "killed_dimension": "claimed-cause",
            "counterevidence": "Gate B obligation failure",
            "failed_premise": "Gate B rejected the proposed cause or obligations",
            "evidence_ids": [record["verdict_id"]],
        }
        moved = _auto_transition_from_gate(
            store, hypothesis, str(result["verdict"]), actor=ACTOR_GATE_B, evidence=evidence
        )
        result["transition"] = moved
    return result


def dedup_check(store: GraphStore, hypothesis_id: str, *, persist: bool = True) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    others = load_hypotheses(store)
    result = check_duplicates(hypothesis, others)
    if persist:
        stamp = str(hypothesis.get("created_at") or "")
        node = evidence_node(
            node_type="DedupCluster",
            node_id=str(result["cluster_id"]),
            run_id=str(hypothesis.get("run_id") or ""),
            created_at=stamp,
            source_locator=f"dedup:{hypothesis_id}",
            properties={
                "title": "dedup",
                "status": result["status"],
                "duplicate_of": result.get("duplicate_of") or "",
                "hypothesis_id": hypothesis_id,
                "comparison": result["status"],
            },
        )
        persist_runtime_node(store, node, actor=ACTOR_DEDUP)
        if result.get("duplicate_of"):
            persist_duplicate_edge(
                store,
                source_id=hypothesis_id,
                target_id=str(result["duplicate_of"]),
                run_id=str(hypothesis.get("run_id") or ""),
                created_at=stamp,
                comparison=str(result["status"]),
            )
            if str(hypothesis.get("status") or "") not in {"duplicate_known_issue", "reported"}:
                try:
                    result["transition"] = transition(
                        store,
                        hypothesis_id,
                        "duplicate_known_issue",
                        evidence={
                            "duplicate_of": result["duplicate_of"],
                            "comparison": f"linked to {result['duplicate_of']} without deletion",
                            "evidence_ids": [],
                        },
                        actor=ACTOR_DEDUP,
                        cause="exact or root-cause duplicate",
                    )
                except EvidenceError as error:
                    result["transition"] = error.as_result()
    result["deleted"] = False
    return result


def impact_assess(
    store: GraphStore,
    hypothesis_id: str,
    *,
    assumptions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    record = assess_impact(hypothesis, assumptions=assumptions)
    stamp = str(hypothesis.get("created_at") or "")
    node = evidence_node(
        node_type="ImpactRecord",
        node_id=str(record["impact_id"]),
        run_id=str(hypothesis.get("run_id") or ""),
        created_at=stamp,
        source_locator=f"impact:{hypothesis_id}",
        properties={
            "title": "impact",
            "hypothesis_id": hypothesis_id,
            "kind": record["kind"],
            "equation": record["profit_loss"]["equation"][:512],
            "lower_bound": record["profit_loss"]["lower_bound"],
            "upper_bound": record["profit_loss"]["upper_bound"],
        },
    )
    persist_runtime_node(store, node, actor=ACTOR_EVIDENCE)
    return record


def severity_assess(
    store: GraphStore,
    hypothesis_id: str,
    *,
    impact: dict[str, Any] | None = None,
    policy_id: str | None = None,
) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    used_impact = impact or assess_impact(hypothesis)
    unprivileged = True
    for item in hypothesis.get("preconditions") or []:
        if isinstance(item, dict) and item.get("attacker_can_create") is False:
            unprivileged = False
    record = assess_severity(
        used_impact, policy_id=policy_id, preconditions_unprivileged=unprivileged
    )
    stamp = str(hypothesis.get("created_at") or "")
    node = evidence_node(
        node_type="SeverityRecord",
        node_id=content_id("sev", hypothesis_id, record["label"], record["policy_id"]),
        run_id=str(hypothesis.get("run_id") or ""),
        created_at=stamp,
        source_locator=f"severity:{hypothesis_id}",
        properties={
            "title": "severity",
            "hypothesis_id": hypothesis_id,
            "label": record["label"],
            "policy_id": record["policy_id"],
            "rule_citation": record["rule_citation"],
        },
    )
    persist_runtime_node(store, node, actor=ACTOR_EVIDENCE)
    return record


def poc_run(
    store: GraphStore,
    hypothesis_id: str,
    *,
    experiment: dict[str, Any] | None = None,
    recorded: dict[str, Any] | None = None,
) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    request = request_from_hypothesis(hypothesis, experiment)
    request["run_id"] = hypothesis.get("run_id")
    execute = bool((experiment or {}).get("execute"))
    if recorded is not None:
        result = apply_recorded_result(request, recorded)
    elif execute:
        result = asyncio.run(execute_foundry(request, recorded=None))
    else:
        result = apply_recorded_result(request, {"status": "pending", "stdout": "not executed"})
        result["note"] = (
            "PoC not executed; pass recorded= or experiment.execute=true to dispatch Foundry"
        )
    stamp = str(hypothesis.get("created_at") or "")
    node = evidence_node(
        node_type="PocRun",
        node_id=str(result["poc_id"]),
        run_id=str(hypothesis.get("run_id") or ""),
        created_at=stamp,
        source_locator=f"poc:{hypothesis_id}",
        evidence_grade="observed" if result.get("status") == "succeeded" else "supported",
        properties={
            "title": "poc",
            "hypothesis_id": hypothesis_id,
            "status": str(result.get("status") or "pending"),
            "result_hash": str(result.get("result_hash") or ""),
            "replay_hash": str(result.get("replay_hash") or ""),
            "one_command": str(result.get("one_command") or ""),
            "tool_run_id": str(result.get("tool_run_id") or ""),
        },
    )
    persist_runtime_node(store, node, actor=ACTOR_POC)
    if result.get("status") == "succeeded" and str(hypothesis.get("status")) == "poc_worthy":
        try:
            result["transition"] = transition(
                store,
                hypothesis_id,
                "observed",
                evidence={
                    "reproduction_id": str(result.get("tool_run_id") or result["poc_id"]),
                    "evidence_ids": list(result.get("evidence_ids") or []),
                },
                actor=ACTOR_POC,
                cause="clean PoC reproduction",
            )
        except EvidenceError as error:
            result["transition"] = error.as_result()
    return result


def poc_replay(store: GraphStore, poc_id: str, *, recorded: dict[str, Any] | None = None) -> dict[str, Any]:
    original = load_poc(store, poc_id)
    props: dict[str, Any] = {}
    node_raw = None
    if original is None:
        for node in load_nodes_by_type(store, "PocRun"):
            if node.get("node_id") == poc_id:
                props = node_props(node)
                props["poc_id"] = poc_id
                node_raw = node
                original = props
                break
    if original is None:
        raise EvidenceError(POC_NOT_FOUND, f"poc {poc_id} was not found")
    result = replay_recorded(original, recorded)
    stamp = str((node_raw or {}).get("created_at") or "")
    node = evidence_node(
        node_type="PocRun",
        node_id=poc_id,
        run_id=str((node_raw or {}).get("run_id") or ""),
        created_at=stamp,
        source_locator=f"poc-replay:{poc_id}",
        evidence_grade="observed" if result.get("replay_matched") else "supported",
        properties={
            "title": "poc",
            "hypothesis_id": str(props.get("hypothesis_id") or original.get("hypothesis_id") or ""),
            "status": str(result.get("status") or "failed"),
            "result_hash": str(result.get("result_hash") or ""),
            "replay_hash": str(result.get("replay_hash") or ""),
            "one_command": str(result.get("one_command") or original.get("one_command") or ""),
            "tool_run_id": str(result.get("tool_run_id") or original.get("tool_run_id") or ""),
        },
    )
    persist_runtime_node(store, node, actor=ACTOR_POC)
    return result


def _related(store: GraphStore, hypothesis_id: str, node_type: str) -> dict[str, Any] | None:
    for node in load_nodes_by_type(store, node_type):
        props = node_props(node)
        if props.get("hypothesis_id") == hypothesis_id:
            return {"node": node, "props": props}
    return None


def finding_build(store: GraphStore, hypothesis_id: str) -> dict[str, Any]:
    hypothesis = _require_hypothesis(store, hypothesis_id)
    impact_node = _related(store, hypothesis_id, "ImpactRecord")
    severity_node = _related(store, hypothesis_id, "SeverityRecord")
    poc_node = _related(store, hypothesis_id, "PocRun")
    dedup_node = _related(store, hypothesis_id, "DedupCluster")
    impact = assess_impact(hypothesis)
    if impact_node:
        props = impact_node["props"]
        impact["finding_impact"]["equation"] = str(props.get("equation") or impact["finding_impact"]["equation"])
        impact["finding_impact"]["lower_bound"] = str(props.get("lower_bound") or "0")
        impact["finding_impact"]["upper_bound"] = str(props.get("upper_bound") or "0")
        impact["finding_impact"]["kind"] = str(props.get("kind") or "integrity")
    severity = assess_severity(impact) if str(hypothesis.get("status")) in {"validated", "reported", "defect_pinned"} else None
    if severity_node and severity is not None:
        severity["finding_severity"]["label"] = str(severity_node["props"].get("label") or "informational")
        severity["finding_severity"]["policy_id"] = str(
            severity_node["props"].get("policy_id") or DEFAULT_SEVERITY_POLICY_ID
        )
        severity["finding_severity"]["rule_citation"] = str(
            severity_node["props"].get("rule_citation") or "policy"
        )
    gate_a_id = None
    gate_b_id = None
    for record in load_verdicts_for(store, hypothesis_id):
        if record.get("gate") == "A":
            gate_a_id = str(record.get("verdict_id") or gate_a_id)
        if record.get("gate") == "B":
            gate_b_id = str(record.get("verdict_id") or gate_b_id)
    poc = poc_node["props"] if poc_node else {}
    if poc_node:
        poc["poc_id"] = poc_node["node"]["node_id"]
    dedup = {"status": str((dedup_node or {}).get("props", {}).get("status") or "unique")}
    validated = str(hypothesis.get("status") or "") in {"validated", "reported"}
    finding = build_finding(
        hypothesis,
        impact=impact,
        severity=severity,
        dedup=dedup,
        gate_a_id=gate_a_id,
        gate_b_id=gate_b_id,
        poc=poc,
        created_at=str(hypothesis.get("created_at") or ""),
        validated=validated,
    )
    persist_contract(
        store,
        "finding",
        {key: value for key, value in finding.items() if not str(key).startswith("_")},
        actor=ACTOR_FINDING,
        event_stem="finding",
    )
    return finding


def report_render(store: GraphStore, finding_id: str, *, fmt: str = "markdown") -> dict[str, Any]:
    finding = load_finding(store, finding_id)
    if finding is None:
        raise EvidenceError(FINDING_NOT_FOUND, f"finding {finding_id} was not found")
    extras: dict[str, Any] = {}
    for node in load_nodes_by_type(store, "PocRun"):
        extras["one_command"] = node_props(node).get("one_command") or extras.get("one_command")
        extras["result_hash"] = node_props(node).get("result_hash") or extras.get("result_hash")
    finding = dict(finding)
    finding["_extras"] = extras
    rendered = render_report(finding, fmt=fmt)
    return rendered


def report_lint(store: GraphStore, finding_id: str, *, current_source: str | None = None) -> dict[str, Any]:
    finding = load_finding(store, finding_id)
    if finding is None:
        raise EvidenceError(FINDING_NOT_FOUND, f"finding {finding_id} was not found")
    rendered = report_render(store, finding_id, fmt="markdown")
    view = _view_dict(store)
    source = current_source
    if source is None:
        units = view.get("source_units") or []
        if units and isinstance(units[0], dict):
            source = str(units[0].get("source") or "")
    result = lint_report(finding, str(rendered.get("body") or ""), current_source=source)
    result["finding_id"] = finding_id
    return result
