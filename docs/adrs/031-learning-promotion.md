---

status: accepted (2026-08-15)

---

# ADR 031 — Learning Graph promotion, contamination, ablation, and experimental adapters

## Context

M8 implements blueprint §14 controlled improvement. M6 already records
adjudicated hypothesis outcomes. M7 already publishes an immutable Global
corpus. M5 Learning queries were stubs: `get_promoted_lessons()` returned
empty and `get_routing_policy()` returned `m8-stub`. A run must never
mutate Global production. Failed candidates must remain inspectable but
unretrievable by production routing. Target secrets and private keys must
never be captured or promoted. Zero new runtime dependencies are allowed.
Capability manifests remain `additionalProperties: false`, so feature
flags cannot live on YAML.

Fizz, Echidna, Medusa, Halmos, and ItyFuzz are not production tools in
M8. They belong behind the M4 adapter boundary as detect-and-refuse
unless an operator explicitly enables experimental execution.

## Decision

1. **Quarantine first, always.**
   Capture at `session_shutdown` and `ayran learning capture` writes
   `LearningOutcome` nodes into the connected graph through
   `GraphStore.append` only. Every outcome starts `quarantined`. Capture
   redacts private keys, mnemonics, 64-hex secrets, target source, and
   exploit payloads. The Learning file tree is
   `knowledge/learning/` (`current.json`, `releases/`, `routing/`),
   never `knowledge/current.json` (M7 Global).

2. **Additive projection v0005.**
   Tables `learning_outcomes`, `learning_candidates`, `learning_reviews`,
   `learning_promotions`, `quarantine_records`, and `routing_policies`
   are created with `CREATE TABLE IF NOT EXISTS`. `v0001`–`v0004` are
   untouched. `LearningNamespace.promote()` still raises
   `NAMESPACE_MISMATCH`; M8 promotion is a sidecar/CLI pipeline, not a
   namespace method.

3. **Two independent reviews before generalization.**
   Reviewers are `human` or `independent_agent`. Promotion requires two
   distinct reviewer IDs. A reject or TTL expiry (default 30 days)
   archives the record. Archived and rejected subjects stay in the
   journal and CLI queue (`include_archived`) but
   `production_retrievable` is false.

4. **Deterministic generalization with target-secret redaction.**
   The same outcome and seed produce the same candidate ID and pattern
   hash. Addresses, project denylist terms, and deployment identifiers
   are stripped. Trust class starts as `model_observation`. Incomplete
   redaction quarantines with `REDACTION_INCOMPLETE` and blocks
   promotion.

5. **Fixtures, contamination wall, held-out ablation.**
   Each candidate must have a positive Solidity fixture and a hard
   negative (safe CEI / nonReentrant variant with a distinction note).
   Contamination compares generalized pattern, families, and lineage
   against sealed-holdout `benchmark_exposure` / `near_duplicate_lineage`
   (M7 fields). Overlap quarantines (`CONTAMINATION_BLOCKED`). Ablation
   is an A0/A1 proxy until M9 owns the harness: baseline routing versus
   candidate-enabled routing. Pass requires measurable lift across more
   than one project family (or explicit safety value). No lift means
   historical record only.

6. **Versioned Learning releases with atomic rollback.**
   All eight promotion gates must pass. The release manifest is content-
   hashed with RFC 8785 (`canonical_hash`) until M9 signing. Pointer
   switch is atomic. Rollback writes a successor release that restores
   the prior pointer; rollback of a rollback is valid. Historical runs
   retain the pin they opened. Routing weights and tool defaults are
   the same class of artifact (`RoutingPolicy`). Baseline IDs
   `ayran-learning-baseline-v1` and `ayran-routing-baseline-v1` keep
   `get_routing_policy()` off `m8-stub` before the first promotion.

7. **Experimental adapters stay off the default list.**
   `capabilities/{fizz,ityfuzz,echidna,medusa,halmos}.yaml` validate as
   ordinary M4 manifests. `CapabilityRegistry.list_capabilities()`
   still returns the four production aliases by default.
   `ExperimentalAdapter` forces filtered env, tighter CPU/memory, and
   longer timeout. `ExecutionPolicy.allow_experimental` and per-alias
   enablement are required to run. Fizz is not bundled; missing Fizz
   degrades `unavailable_not_found`. Generated harnesses may request a
   clean Foundry replay; replay failure quarantines the harness.
   Failure taxonomy stays inside the closed M0 enum (`compile` /
   `test` stand in for harness-generation and engine failure).
   Experimental ToolRuns set env `AYRAN_EXPERIMENTAL=true` rather than
   adding a schema field.

## Consequences

- M5 `get_promoted_lessons()` returns released candidates from the
  graph. `get_routing_policy()` returns the active Learning routing
  policy, falling back to the baseline object.
- Sidecar methods `learning.*` are bearer-authenticated and
  write-policy gated, matching M7 `knowledge.*`.
- M9 evaluation, signing, and Complete URL-closure remain out of
  scope. Experimental fuzzers are never production defaults.
