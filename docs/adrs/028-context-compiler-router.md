---

status: accepted (2026-08-14)

---

# ADR 028 — Context compiler, ontology queries, and six-origin router

## Context

M5 is the cognitive engine of Ayran: it must compile bounded, labeled
ContextPacks for Prime, query Target/Global/Learning namespaces, project
attack-surface maps and a risk-weighted coverage grid, and sequence six
hypothesis origins without calling the model. M0 already defines
`context-pack`, `router-action`, `hypothesis`, and `coverage-cell`. M1
provides the hash-chained journal and SQLite projection. M2 is the only
authenticated mutator. M3 injects a context pack on `before_agent_start`.
M4 adapters supply tool facts. Zero new runtime dependencies are allowed.
Evidence ceilings remain: a `lead` must never be promoted to `observed`.

The M0 `RouterAction` contract is a single object with `handler.kind` /
`handler.id`, not a tagged union. Coverage-cell status is the closed set
`open | examined | blocked | accepted_residual_risk`. Finer cell states
from the blueprint must live in `examined_result` without new schemas.

## Decision

1. **Pure compute on a GraphView.** Compiler, drivers, maps, coverage, and
   the router consume an in-memory `GraphView`. They never open SQLite or
   the journal. Persistence is `GraphStore.append` invoked only from the
   sidecar RPC facade (`ayran.router.service`) and the operator CLI (the
   same pattern as the M1 graph CLI and M4 recording).

2. **Existing contracts, no hand-edited codegen.** Hypothesis, ContextPack,
   RouterAction, CoverageCell, GraphNode, and GraphEdge stay at schema
   1.0.0. RouterAction variants are encoded as `handler.id`
   (`driver.model_native`, `tool.invoke`, `router.manual_next`, …).
   Coverage finer states (`unexamined`, `in_progress`, `examined_no_issue`,
   `blocked`, `lead_found`, `hypothesis_active`, `validated`,
   `residual_risk`) are stored as
   `[state|risk=N] narrative` in `examined_result` and mapped onto schema
   `status` / `depth`. Identifiers are SHA-256 → 26 Crockford characters
   (`content_id`).

3. **Load-bearing labels.** Every injected section has exactly one of
   `DETERMINISTIC_FACT`, `RUNTIME_OBSERVATION`, `SOURCE_CLAIM`,
   `ASSUMPTION`, `HYPOTHESIS`, `HISTORICAL_REFERENCE`, `COUNTEREVIDENCE`,
   `POLICY`. The compiler never paraphrases an assumption into a fact.
   Historical cards appear only when `knowledge_policy=graph_aware`.
   Token estimate is `ceil(chars / 4)`. The injection block is
   `<!-- ayran-context-pack -->` + labeled markdown +
   `<!-- checksum: sha256:… -->`. Collapse reconstruction uses the M3
   titles (`Active hypothesis`, `Result so far`, `Next action`,
   `Dead approaches`, `Untried dimensions`) rebuilt from the graph.

4. **Additive projection only.** Migration `v0002_cognitive` adds
   `coverage_grid`, `cognitive_maps`, and `router_runtime`. `v0001` is
   untouched. `MIGRATION_VERSION` is 2. Query snapshots include the new
   empty tables in the logical digest.

5. **Six pure drivers.** Each `propose(view) -> DriverResult` is
   deterministic. Origins are `model_novel`, `global_graph`,
   `contradiction`, `tool`, `coverage`, `specialist`. Budgets per tranche
   are 25 / 15 / 15 / 10 / 15 / 20 against a 100-unit tranche. The
   model-native arm strips Global cards and tool runs. Global-graph stops
   on `target_only` / `knowledge_blind`. The tool driver never raises an
   evidence ceiling. Drivers never call the model.

6. **Router.** One cycle ranks typed `ActionRequest`s by
   value-at-risk × urgency × novelty × budget-efficiency, FIFO on ties.
   Contradiction and coverage are always-on. Global Graph is skipped until
   every high-value cluster has a recorded target-first pass. Kill after
   `kill_streak` (default 2) non-material invocations. No progress for
   `no_progress_cycles` (default 3) enters `manual_next`. Replay checksum
   is RFC 8785 over handler / dedup / priority / budget / status / stop
   (not ULIDs). Dedup: hypothesis canonical
   root-cause/state/attacker triple; tools capability + input hash.

7. **Anchoring and injection defense.** Target-first freeze stores a
   snapshot hash before Global retrieval. The 25-unit model-native reserve
   cannot be spent by other drivers until model-native has consumed it or
   a recorded `release_reserve` fires. Retrieval diversity suppresses
   near-duplicate mechanism cards. Dual-review clusters emit a knowledge-
   blind specialist request, then an aware one. Prompt-injection denylist
   (`<!-- SYSTEM -->`, `<<SYS>>`, …) marks `payload_only`; three
   consecutive flags quarantine the source and drop its priority to zero.

8. **Maps from tools and source, never from the model.** Attack-surface,
   control-flow, data-flow, value-flow, authority, and temporal maps are
   GraphNode / GraphEdge projections built from Solidity parse and M4
   Slither/solc JSON. Hypotheses may reference map nodes; they cannot
   rewrite maps.

9. **Sidecar RPC and extension.** New methods:
   `context.compile` (and `context.pack` as alias), `ontology.query`,
   `router.{status,step,history}`, `coverage.{summary,cell}`,
   `maps.{get,build}`. After `/ayran:activate`, the M3 `before_agent_start`
   hook calls `context.compile` and prefers `injection_text`. Until
   activate, that hook does not inject. The extension still does not write
   the journal.

10. **Learning Graph is a stub.** `get_promoted_lessons` returns `[]`.
    `get_routing_policy` returns `{policy: "m8-stub"}`.

## Consequences

* Windows can compile packs, run all six drivers, enforce budgets, replay
  routing, and build maps from fixtures without WSL tools present.
* Real sidecar injection and CLI against a fixture vault are `wsl_ext4`.
* M6 (Gate A/B, PoC, findings, reports), M7 (Global corpus), M8 (Learning
  promotion), and M9 (evaluation/release) remain unimplemented. A lead
  still cannot become a finding.
* Prime 0.7.2, the live Prime install, and the locked runtime dependency
  set are untouched. M9 Complete URL-closure remains open.
