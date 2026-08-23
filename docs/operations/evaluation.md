# Evaluation

Ayran's evaluation answers one question honestly: does each added mechanism improve
audit outcomes? Two modes exist.

## Sealed mode (offline, default)

The original sealed A0–A7 controller replays opaque fixture IDs with no model calls.
Knowledge releases are frozen for the session; a leakage scan runs before results are
accepted and invalidates the evaluation on failure.

```text
ayran eval run --arm A5 --seed 7      # one arm
ayran eval run                        # cumulative sequence, seeds 7/13/21
ayran eval adjudicate --session <id>
ayran eval results --session <id>
```

Sealed adjudication is synthetic by construction (two internal judges score the same
recorded metrics). Treat its numbers as regression checks, not as lift evidence.

## Live mode (real model runs)

Added by R6. The live harness replaces formula-derived metrics with measurements and
adds owner controls.

### Workflow

1. **Preregister the grading sheet** — this binds the manifest hash before any launch:

   ```text
   ayran eval preregister --manifest <sheet.json> --results-root <dir>
   ```

   The sheet declares arms, targets, model identity, pricing table (or token-unit
   fallback), caps (`per_arm_usd`, `session_usd`), and ε non-inferiority. The journal
   records `eval_preregistered {manifest_hash, confirmed_by}`. Any post-signature edit
   changes the hash and the runner refuses with `PREREGISTRATION_MISMATCH`.

2. **Run the session:**

   ```text
   ayran eval run --live --preregistration <sheet.json> \
                  --targets <dir-with-target.json-files> \
                  --results-root <dir> [--seed 7]
   ```

   Mandatory order inside the runner: contamination gate
   (`enforce_at_harness_start`) → preregistration check → launches. Between every
   launch it consults the kill switch and projects spend against the caps.

3. **Kill switch:**

   ```text
   ayran eval pause --results-root <dir>
   ```

   Honored between launches (`paused_operator`). An in-flight run finishes
   best-effort. Cap exhaustion pauses identically (`paused_cap`).

4. **Adjudicate:**

   ```text
   ayran eval adjudicate --session <id>
   ```

   Renders primaries, deltas vs A0, failures, null-metric disclosures, cost vs caps,
   and the preregistration hash the session ran under. Manifests are immutable;
   failures stay in.

### Ground-truth targets

Each target directory carries a `target.json`: `{target_id, workspace_path,
ground_truth: [{root_cause_family, severity, notes}], revision_or_commit,
held_out: true}`. Targets colliding with ingested Global/Learning incidents raise
`ContaminationViolation` before any launch — ingested incidents can never become exam
questions.

### Known limitation: transport-blind scoring

Under print-mode Prime the transport observes only the final stdout, so
runner-computed findings/recall/time-to-first are honestly `null` (never invented),
and the machine gate will report "no lift observable". Supplement with an operator
adjudication layer that grades reports against the answer key with a disclosed method
(keyword families over the report text plus PoC artifact listing) — see the committed
record under `docs/evaluation/r6-session-*`. Fixing the observation gap (structured
finding events from Prime sessions) is tracked work, not a solved problem.

## Metrics

Primary: severity-weighted recall of unique validated root causes, precision,
false-positive rate, executable-PoC rate, defect-pinning rate, time to first valid
finding, cost per validated finding, reproducibility.

Secondary: duplicate rate, coverage, tool-selection accuracy, retrieval usefulness,
anchoring resistance, Gate rejection accuracy, resume/recovery quality, operator
interventions, cost, scope violations, unsafe actions. Any successful unsafe action is
a release-blocking defect.

Metrics are computed from observations or left null. Nulls are listed as disclosures
in the manifest — a null beats an invented number.

## Interpreting results

Live gate: zero critical scope/provenance/journal/recovery failures, no unsafe
actions, non-inferiority to A0 at the declared ε, and improvement on at least one
preregistered primary metric without material safety/cost regression. Failed runs stay
in the manifest. Do not relabel a failed candidate as release-ready, and do not treat
a saturated fixture set (both arms at ceiling) as evidence of either lift or its
absence — it measures neither.
