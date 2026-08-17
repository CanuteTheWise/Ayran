"""Deterministic six-origin router. No model calls. Same view+config → same actions."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from ayran.context.view import GraphView
from ayran.hypotheses.dedup import hypothesis_key, tool_key
from ayran.hypotheses.drivers import PROPOSERS
from ayran.hypotheses.drivers.base import DRIVER_NAMES, DriverResult
from ayran.router.actions import ActionRequest, semantic_checksum, to_router_action
from ayran.router.anchoring import AnchoringState
from ayran.router.budget import BudgetManager
from ayran.router.injection import StrikeBook, looks_like_injection
from ayran.router.outbox import pending_event_ids

KILL_STREAK = 2
NO_PROGRESS_CYCLES = 3
ALWAYS_ON = {"contradiction", "coverage_derived"}


@dataclass(slots=True)
class RouterConfig:
    created_at: str = "2026-08-12T12:00:00Z"
    kill_streak: int = KILL_STREAK
    no_progress_cycles: int = NO_PROGRESS_CYCLES
    exhaustion_mode: str = "manual_next"
    injection_patterns: tuple[str, ...] = ()
    phase: str = "map"


@dataclass(slots=True)
class StepResult:
    actions: list[dict[str, Any]]
    driver_results: dict[str, DriverResult]
    budget: dict[str, Any]
    checksum: str
    manual_next: bool
    halted: bool
    anchoring_metrics: dict[str, Any]
    reason: str = ""


@dataclass(slots=True)
class RouterEngine:
    config: RouterConfig = field(default_factory=RouterConfig)
    budget: BudgetManager = field(default_factory=BudgetManager)
    strikes: StrikeBook = field(default_factory=StrikeBook)
    anchoring: AnchoringState = field(default_factory=AnchoringState)
    kill_streaks: dict[str, int] = field(default_factory=dict)
    killed: set[str] = field(default_factory=set)
    seen_hypotheses: set[str] = field(default_factory=set)
    seen_tools: set[str] = field(default_factory=set)
    cycles_without_progress: int = 0
    manual_next: bool = False
    halted: bool = False
    history: list[dict[str, Any]] = field(default_factory=list)

    def restore(self, view: GraphView) -> None:
        self.budget = BudgetManager.from_view(view.budget_state, view.driver_states)
        self.strikes.counts = dict(view.payload_strikes)
        self.strikes.quarantined = set(view.quarantined_sources)
        self.anchoring.freeze_hashes = dict(view.freeze_snapshots)
        self.manual_next = view.manual_next
        self.cycles_without_progress = view.no_progress_cycles
        for name, state in view.driver_states.items():
            if state.get("killed"):
                self.killed.add(name)
            self.kill_streaks[name] = int(state.get("no_progress") or 0)
        for item in view.hypotheses:
            self.seen_hypotheses.add(hypothesis_key(item))
        for action in view.router_actions:
            handler = action.get("handler") or {}
            if handler.get("kind") == "adapter":
                self.seen_tools.add(str(action.get("deduplication_key") or ""))
        self.history = list(view.router_actions)

    def step(self, view: GraphView) -> StepResult:
        if not self.history:
            self.restore(view)
        if self.halted:
            return self._result([], {}, "halted")
        if self.manual_next:
            action = self._action(
                view,
                ActionRequest(
                    kind="EnterManualNext",
                    cluster_id=view.cluster_id,
                    dedup_suffix=f"cycle:{self.cycles_without_progress}",
                    reason="manual_next_mode",
                    run_id=view.run_id,
                    created_at=self.config.created_at,
                    target_identity=view.target_identity or None,
                    value_at_risk=view.value_at_risk,
                ),
            )
            return self._result([action], {}, "manual_next")

        high_value = view.high_value_clusters or [view.cluster_id]
        all_target_first = all(item in view.target_first_completed for item in high_value)
        if all_target_first:
            self.budget.release_reserve(recorded=True)
        else:
            self.anchoring.freeze_target_first(view)

        dual = self.anchoring.dual_review_required(view) or view.dual_review
        requests: list[ActionRequest] = []
        driver_results: dict[str, DriverResult] = {}

        order = list(DRIVER_NAMES)
        # Contradiction and coverage run throughout, not only after others.
        for name in ALWAYS_ON:
            if name in order:
                order.remove(name)
        order = ["contradiction", "coverage_derived"] + [
            name for name in DRIVER_NAMES if name not in ALWAYS_ON
        ]

        if not all_target_first:
            order = ["model_native"] + [name for name in order if name != "model_native"]

        progress = False
        for name in order:
            if name in self.killed and name not in ALWAYS_ON:
                continue
            if name in self.strikes.quarantined:
                continue
            if name == "global_graph" and not all_target_first:
                continue
            if name == "global_graph" and view.knowledge_policy in {"target_only", "knowledge_blind"}:
                continue
            if self.budget.remaining_for(name) <= 0:
                continue
            proposer = PROPOSERS[name]
            # Model-native must work without retrieved/tool anchors.
            isolated = view
            if name == "model_native":
                isolated = _without_anchors(view)
            result = proposer(isolated)
            flagged = any(
                looks_like_injection(str(item.get("claim") or ""), self.config.injection_patterns)
                for item in result.hypotheses
            )
            if flagged:
                result.payload_only = True
                quarantined = self.strikes.note(name, True)
                if quarantined:
                    self.killed.add(name)
            fresh: list[dict[str, Any]] = []
            for item in result.hypotheses:
                key = hypothesis_key(item)
                if key in self.seen_hypotheses:
                    continue
                self.seen_hypotheses.add(key)
                fresh.append(item)
            result.hypotheses = fresh
            result.material = bool(fresh) or bool(result.coverage_deltas)
            if not result.material:
                self.kill_streaks[name] = self.kill_streaks.get(name, 0) + 1
                if self.kill_streaks[name] >= self.config.kill_streak:
                    self.killed.add(name)
            else:
                self.kill_streaks[name] = 0
                progress = True
            spend = min(result.units_spent or 1, self.budget.remaining_for(name), FLOOR_CAP(name))
            if spend and not result.payload_only:
                self.budget.spend(name, spend)
                result.units_spent = spend
            driver_results[name] = result
            requests.append(
                ActionRequest(
                    kind="DispatchDriver",
                    cluster_id=view.cluster_id,
                    dedup_suffix=name,
                    budget_units=result.units_spent,
                    driver_name=name,
                    payload_only=result.payload_only,
                    reason=result.stop_reason or name,
                    run_id=view.run_id,
                    created_at=self.config.created_at,
                    target_identity=view.target_identity or None,
                    value_at_risk=view.value_at_risk,
                    urgency=3 if name in ALWAYS_ON or name == "model_native" else 2,
                    novelty=3 if name == "model_native" else 1,
                    extra=str(len(result.hypotheses)),
                )
            )
            if name == "adversarial_specialist" and dual:
                requests.append(
                    ActionRequest(
                        kind="RequestSpecialist",
                        cluster_id=view.cluster_id,
                        dedup_suffix="blind",
                        budget_units=min(10, self.budget.remaining_for(name)),
                        role_id="devils-advocate",
                        blind_mode=True,
                        run_id=view.run_id,
                        created_at=self.config.created_at,
                        target_identity=view.target_identity or None,
                        value_at_risk=view.value_at_risk,
                        reason="dual-review-blind",
                    )
                )
                if view.knowledge_policy == "graph_aware":
                    requests.append(
                        ActionRequest(
                            kind="RequestSpecialist",
                            cluster_id=view.cluster_id,
                            dedup_suffix="aware",
                            budget_units=min(10, self.budget.remaining_for(name)),
                            role_id="devils-advocate",
                            blind_mode=False,
                            run_id=view.run_id,
                            created_at=self.config.created_at,
                            target_identity=view.target_identity or None,
                            value_at_risk=view.value_at_risk,
                            reason="dual-review-aware",
                        )
                    )
            for delta in result.coverage_deltas:
                requests.append(
                    ActionRequest(
                        kind="RecordCoverageUpdate",
                        cluster_id=view.cluster_id,
                        dedup_suffix=str(delta.get("coverage_cell_id") or delta.get("dimension")),
                        cell_id=str(delta.get("coverage_cell_id") or ""),
                        new_state=str(delta.get("new_state") or "in_progress"),
                        run_id=view.run_id,
                        created_at=self.config.created_at,
                        target_identity=view.target_identity or None,
                        value_at_risk=view.value_at_risk,
                        reason="coverage-delta",
                    )
                )

        if view.tool_runs:
            for run in sorted(view.tool_runs, key=lambda row: str(row.get("tool_run_id") or ""))[:3]:
                capability = str(run.get("capability_id") or run.get("tool_name") or "tool")
                input_hash = str((run.get("input_hashes") or [run.get("stdout_hash") or "x"])[0])
                key = tool_key(capability, input_hash)
                if key in self.seen_tools:
                    continue
                self.seen_tools.add(key)
                requests.append(
                    ActionRequest(
                        kind="InvokeTool",
                        cluster_id=view.cluster_id,
                        dedup_suffix=key.replace(":", ".")[:80],
                        capability_id=capability,
                        budget_units=min(5, self.budget.remaining_for("tool_derived")),
                        run_id=view.run_id,
                        created_at=self.config.created_at,
                        target_identity=view.target_identity or None,
                        value_at_risk=view.value_at_risk,
                        reason="dedup-checked-tool",
                    )
                )

        requests.append(
            ActionRequest(
                kind="InjectContext",
                cluster_id=view.cluster_id,
                dedup_suffix=str(view.cursor),
                run_id=view.run_id,
                created_at=self.config.created_at,
                target_identity=view.target_identity or None,
                value_at_risk=view.value_at_risk,
                reason="bounded-context",
            )
        )

        if not progress:
            self.cycles_without_progress += 1
        else:
            self.cycles_without_progress = 0
        if self.cycles_without_progress >= self.config.no_progress_cycles:
            self.manual_next = True
            requests.append(
                ActionRequest(
                    kind="EnterManualNext",
                    cluster_id=view.cluster_id,
                    dedup_suffix="no-progress",
                    reason="no_progress",
                    run_id=view.run_id,
                    created_at=self.config.created_at,
                    target_identity=view.target_identity or None,
                    value_at_risk=view.value_at_risk,
                    urgency=5,
                )
            )
        if self.budget.remaining() == 0:
            kind = "HaltRun" if self.config.exhaustion_mode == "halt" else "EnterManualNext"
            if kind == "HaltRun":
                self.halted = True
            else:
                self.manual_next = True
            requests.append(
                ActionRequest(
                    kind=kind,  # type: ignore[arg-type]
                    cluster_id=view.cluster_id,
                    dedup_suffix="budget-exhausted",
                    reason="budget_exhausted",
                    run_id=view.run_id,
                    created_at=self.config.created_at,
                    target_identity=view.target_identity or None,
                    value_at_risk=view.value_at_risk,
                    urgency=5,
                )
            )

        triggers = pending_event_ids(view.router_actions, view.cursor)
        ranked = sorted(
            requests,
            key=lambda item: (
                -(item.priority or 0) - item.value_at_risk * item.urgency,
                item.created_at,
                item.kind,
                item.dedup_suffix,
            ),
        )
        actions: list[dict[str, Any]] = []
        seen_dedup: set[str] = set()
        for request in ranked:
            filled = replace(request, triggering_event_ids=tuple(triggers[:8]))
            if filled.priority == 0:
                from ayran.router.actions import priority_score

                filled = replace(filled, priority=priority_score(filled))
            contract = to_router_action(filled)
            key = str(contract["deduplication_key"])
            if key in seen_dedup:
                continue
            seen_dedup.add(key)
            if filled.driver_name in self.strikes.quarantined:
                contract["priority"] = 0
                contract["status"] = "denied"
            actions.append(contract)
        actions.sort(key=lambda row: (-int(row["priority"]), str(row["created_at"]), str(row["deduplication_key"])))
        metrics = {}
        if view.knowledge_policy == "graph_aware":
            metrics = self.anchoring.record_post_retrieval(view)
        self.history.extend(actions)
        return self._result(actions, driver_results, "ok", metrics)

    def _action(self, view: GraphView, request: ActionRequest) -> dict[str, Any]:
        filled = replace(
            request,
            triggering_event_ids=tuple(pending_event_ids(view.router_actions, view.cursor)[:8]),
        )
        return to_router_action(filled)

    def _result(
        self,
        actions: list[dict[str, Any]],
        driver_results: dict[str, DriverResult],
        reason: str,
        metrics: dict[str, Any] | None = None,
    ) -> StepResult:
        return StepResult(
            actions=actions,
            driver_results=driver_results,
            budget=self.budget.as_dict(),
            checksum=semantic_checksum(actions),
            manual_next=self.manual_next,
            halted=self.halted,
            anchoring_metrics=metrics or {},
            reason=reason,
        )


def FLOOR_CAP(name: str) -> int:
    from ayran.router.budget import CEILINGS

    return CEILINGS[name]


def _without_anchors(view: GraphView) -> GraphView:
    isolated = GraphView(
        run_id=view.run_id,
        target_identity=view.target_identity,
        cluster_id=view.cluster_id,
        phase=view.phase,
        cursor=view.cursor,
        event_hash=view.event_hash,
        token_budget=view.token_budget,
        knowledge_policy="target_only",
        hypotheses=view.hypotheses,
        coverage_cells=view.coverage_cells,
        evidence=view.evidence,
        tool_runs=[],
        dead_ends=view.dead_ends,
        open_questions=view.open_questions,
        nodes=view.nodes,
        edges=view.edges,
        maps=view.maps,
        contradictions=view.contradictions,
        source_units=view.source_units,
        global_mechanisms=[],
        global_incidents=[],
        global_patterns=[],
        router_actions=view.router_actions,
        driver_states=view.driver_states,
        budget_state=view.budget_state,
        created_at=view.created_at,
        policy_checksum=view.policy_checksum,
        config_checksum=view.config_checksum,
        scope_id=view.scope_id,
        high_value_clusters=view.high_value_clusters,
        target_first_completed=view.target_first_completed,
        value_at_risk=view.value_at_risk,
        dual_review=False,
    )
    return isolated
