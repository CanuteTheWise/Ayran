"""Deterministic six-lens router. No model calls. Same view+config → same LensUpdate actions.

R3: RouterEngine.step no longer fabricates hypotheses. It emits LensUpdate
actions. BudgetManager, StrikeBook, AnchoringState, kill-streaks, quarantine,
and semantic_checksum survive as advisory state feeding lens text.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from ayran.context.lenses import (
    ALWAYS_ON_LENSES,
    LENS_NAMES,
    LensBlock,
    compile_lens_blocks,
    precedent_suppressed,
)
from ayran.context.view import GraphView
from ayran.hypotheses.dedup import hypothesis_key, tool_key
from ayran.router.actions import ActionRequest, semantic_checksum, to_router_action
from ayran.router.anchoring import AnchoringState
from ayran.router.budget import CEILINGS, BudgetManager
from ayran.router.injection import StrikeBook
from ayran.router.outbox import pending_event_ids

KILL_STREAK = 2
NO_PROGRESS_CYCLES = 3
ALWAYS_ON = ALWAYS_ON_LENSES


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
    lens_updates: dict[str, dict[str, Any]]
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
    seen_lens_fingerprints: dict[str, str] = field(default_factory=dict)
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

        remaining = {name: self.budget.remaining_for(name) for name in LENS_NAMES}
        blocks = compile_lens_blocks(
            view,
            remaining=remaining,
            extra_patterns=self.config.injection_patterns,
        )

        order = ["contradiction", "coverage"] + [
            name for name in LENS_NAMES if name not in ALWAYS_ON
        ]

        requests: list[ActionRequest] = []
        lens_updates: dict[str, dict[str, Any]] = {}
        progress = False
        for name in order:
            if name in self.killed and name not in ALWAYS_ON:
                continue
            if name == "precedent" and precedent_suppressed(view):
                block = blocks[name]
                lens_updates[name] = block.as_dict()
                continue
            if self.budget.remaining_for(name) <= 0:
                continue
            block = blocks[name]
            if name in self.strikes.quarantined or block.quarantined:
                quarantined = self.strikes.note(name, True)
                if quarantined:
                    self.killed.add(name)
                block.payload_only = True
                block.quarantined = True
                block.material = False
                block.guidance = "[QUARANTINED: injection]"
            fingerprint = str(block.as_dict()["fingerprint"])
            prior = self.seen_lens_fingerprints.get(name)
            fresh = fingerprint != prior
            if fresh:
                self.seen_lens_fingerprints[name] = fingerprint
            material = bool(block.material and fresh) or bool(block.coverage_deltas and fresh)
            if block.payload_only:
                material = False
            if not material:
                self.kill_streaks[name] = self.kill_streaks.get(name, 0) + 1
                if self.kill_streaks[name] >= self.config.kill_streak:
                    self.killed.add(name)
            else:
                self.kill_streaks[name] = 0
                progress = True
            spend = min(1 if material else 0, self.budget.remaining_for(name), CEILINGS[name])
            if spend and not block.payload_only:
                self.budget.spend(name, spend)
                block.units_spent = spend
                block.budget_remaining = self.budget.remaining_for(name)
            lens_updates[name] = block.as_dict()
            requests.append(self._lens_request(view, name, block))
            if name == "specialist":
                for role in block.advised_roles:
                    requests.append(
                        ActionRequest(
                            kind="RequestSpecialist",
                            cluster_id=view.cluster_id,
                            dedup_suffix=role,
                            role_id=role,
                            budget_units=min(1, self.budget.remaining_for("specialist")),
                            run_id=view.run_id,
                            created_at=self.config.created_at,
                            target_identity=view.target_identity or None,
                            value_at_risk=view.value_at_risk,
                            reason=f"advise rlm spawn {role}",
                            urgency=2,
                            novelty=1,
                        )
                    )
            for delta in block.coverage_deltas:
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
                        budget_units=min(5, self.budget.remaining_for("tool_signal")),
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
        return self._result(actions, lens_updates, "ok", metrics)

    def _lens_request(self, view: GraphView, name: str, block: LensBlock) -> ActionRequest:
        return ActionRequest(
            kind="LensUpdate",
            cluster_id=view.cluster_id,
            dedup_suffix=name,
            budget_units=block.units_spent,
            driver_name=name,
            payload_only=block.payload_only,
            reason=block.stop_reason or name,
            run_id=view.run_id,
            created_at=self.config.created_at,
            target_identity=view.target_identity or None,
            value_at_risk=view.value_at_risk,
            urgency=3 if name in ALWAYS_ON else 2,
            novelty=1,
            extra=str(block.budget_remaining),
        )

    def _action(self, view: GraphView, request: ActionRequest) -> dict[str, Any]:
        filled = replace(
            request,
            triggering_event_ids=tuple(pending_event_ids(view.router_actions, view.cursor)[:8]),
        )
        return to_router_action(filled)

    def _result(
        self,
        actions: list[dict[str, Any]],
        lens_updates: dict[str, dict[str, Any]],
        reason: str,
        metrics: dict[str, Any] | None = None,
    ) -> StepResult:
        return StepResult(
            actions=actions,
            lens_updates=lens_updates,
            budget=self.budget.as_dict(),
            checksum=semantic_checksum(actions),
            manual_next=self.manual_next,
            halted=self.halted,
            anchoring_metrics=metrics or {},
            reason=reason,
        )
