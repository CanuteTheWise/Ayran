---

status: accepted (2026-08-14)

---

# ADR 029 — Evidence pipeline, Gate A/B, findings, and reports

## Context

M6 is the evidence plane of Ayran. It must encode legal hypothesis
transitions, run knowledge-blind Gate A and post-PoC Gate B as structured
validators (not model calls), quantify impact, apply versioned severity
policies, cluster duplicates without deletion, govern PoC execution
through the M4 Foundry adapter, emit schema-valid Findings, and render
linted Markdown/JSON reports that launch no tools.

M0 already defines `hypothesis`, `da-verdict`, `finding`, and
`evidence-artifact`. M1 provides the hash-chained journal and SQLite
projection. M2 is the only authenticated mutator. M4 adapters supply
tool evidence with ceilings (`lead` vs `observed`). M5 routing produces
hypotheses. Zero new runtime dependencies are allowed. A `lead` from
Slither or Solodit must never pass Gate A or Gate B.

The Finding schema is `additionalProperties: false`. Extra report fields
(one-command reproduction, numbered attack steps) live on graph nodes
and renderer extras, not as undeclared Finding properties.

## Decision

1. **State machine is the only status path.**
   `HypothesisStateMachine` enforces the §5.2 mermaid edges, required
   evidence per edge, and authorized actor kinds. Direct journal writes
   cannot change `status`. Persistence is `GraphStore.append` from
   `ayran.evidence.service` (sidecar RPC) and the operator CLI. The main
   ladder is monotonic (`lead` → `supported` → `poc_worthy` → `observed`
   → `defect_pinned` → `validated` → `reported`). Invalidation appends a
   `demotion` / `retraction` event with cause; history is never
   overwritten. `poc_worthy` maps to evidence grade `supported`;
   `reported` maps to `validated`. Evidence ceiling: a `lead` cannot
   become `poc_worthy` or later.

2. **Gate A is knowledge-blind structured analysis.**
   Input is a `supported` hypothesis plus Target view and source. The
   engine drops `historical_matches`, `originator_narrative`, and
   `global_graph` before scoring. It extracts the invariant, enumerates
   preconditions, names the strongest benign explanation, lists missing
   facts, and specifies the cheapest distinguishing experiment. Verdict
   is exactly one of `falsified`, `needs_missing_fact`,
   `needs_reformulation`, `poc_worthy`. A `falsified` verdict records
   killed dimensions and never marks a surface safe. Optional
   reconciliation against Global knowledge runs only after the blind
   verdict is committed. The engine does not call the model.

3. **Gate B is an obligation checklist.**
   Input is an `observed` hypothesis plus PoC artifacts. Obligations:
   clean replay, numerical assertions, negative controls, defect-removal
   mutation, fix efficacy (feature preserved), alternate paths,
   independent skeptic, deployment identity when claimed, and
   feasibility/scope/severity. Unspecified obligations yield
   `needs_reformulation`. A `governed_proof` profile waives executable
   replay for design/economic findings when contest policy allows it;
   the result is labeled `proof_based`. Weakening an assertion creates a
   new experiment revision.

4. **Dedup never deletes.**
   Levels in order: exact span or known-issue ID, canonical root cause +
   invariant, attack-graph isomorphism, impact/deployment identity,
   semantic Jaccard on normalized descriptions (tiebreaker only). Root
   cause and symptoms cluster separately. Distinct paths, deployments,
   severity, or impacts remain variants. Historical similarity does not
   prove duplication. `duplicate_known_issue` is terminal with a
   `duplicate_of` graph edge.

5. **Impact is not severity.**
   Impact records attacker model, profit/loss equations and bounds,
   asset exposure, recovery/blast radius, and deployment-identity claims
   with explicit assumptions (price, window, market). Severity is
   produced by a versioned engagement policy that cites the exact rule
   and records ambiguities. Historical severity is calibration only.

6. **PoC uses the M4 Foundry adapter.**
   Default Windows path records a result without launching tools.
   `experiment.execute=true` dispatches `forge test` through the M4
   adapter in a copied workspace. Status: `pending` → `executing` →
   `succeeded` | `failed` | `flaky` | `timeout`. Clean replay must match.
   One-command reproduction is stored with the PoC node.

7. **Finding builder and reports.**
   `build_finding` emits a sealed Finding matching
   `schemas/finding.schema.json`. Markdown renderer tags every claim
   sentence with `[evidence:…]` or `[assumption:…]` and preserves
   uncertainty. JSON renderer emits the canonical object. The linter
   hard-fails missing proof, stale source lines, non-reproducible
   commands, hidden assumptions, uncited policy, unsupported definitive
   language, secret/path leakage, and status below `validated`. Report
   generation never launches tools.

8. **Additive projection only.**
   Migration `v0003_evidence` adds `gate_verdicts`, `findings`,
   `poc_runs`, and `dedup_clusters`. `v0001` and `v0002` are untouched.
   `MIGRATION_VERSION` is 3.

9. **Sidecar RPC and CLI.**
   Methods: `evidence.transition`, `evidence.gate_a`, `evidence.gate_b`,
   `evidence.dedup_check`, `evidence.impact_assess`,
   `evidence.severity_assess`, `evidence.poc_run`, `evidence.poc_replay`,
   `finding.build`, `report.render`, `report.lint`. All bearer- and
   policy-checked. CLI: `ayran evidence transition`, `gate-a`, `gate-b`,
   `dedup check`, `poc run|replay`, `finding build`, `report render|lint`.

## Consequences

* Windows can exercise the full state machine, Gate A/B on fixtures,
  dedup/impact/severity, Finding build, and report lint without WSL
  tools. Foundry execution and sidecar UDS remain `wsl_ext4`.
* A Slither `arbitrary-send-eth` lead on CEI `withdraw` fails Gate A
  (`falsified`). A call-before-zero reentrancy hypothesis passes Gate A
  (`poc_worthy`) and, with recorded/executed PoC obligations, Gate B
  (`defect_pinned`).
* M7 (Global Graph corpus), M8 (Learning promotion), and M9
  (evaluation/release) remain unimplemented. The model's role in Gate
  A/B is out of scope: gates consume structured analysis; they do not
  call the model.
* Prime 0.7.2, the live Prime install, and the locked runtime dependency
  set are untouched. M9 Complete URL-closure remains open.
