# R6 Live Evaluation — Adjudication Record

Session: `evs_163P3NAAQ7EQQ3K7SWN1J3XXHY` · Date: 2026-08-23 (UTC) ·
Authority: **operator-delegated to the verifier** ("complete R6 however you deem fit,
don't worry about cost — no compromise"), recorded here in lieu of a countersignature.
The operator may counter-sign at any time; nothing below depends on who watched.

## 1. Preregistration (signed BEFORE any launch)

- Journal: `eval-journal.jsonl` event `eval_preregistered` at `2026-08-23T17:58:16Z`
- Manifest hash: `sha256:0eb7c1179ea15a41872cc4ea82be7edfc86038f3a0fe08638b6e356771e9defa`
- Arms: A0 (stock Prime) vs A5 (full-Ayran) · Seed: 7 · Targets: 5 held-out
- Model: deepseek-v4-flash (owner-configured version/thinking)
- Pricing table: EMPTY → all costs are **token-unit disclosures** (USD null), per design
- Caps: $50/arm, $150/session (never approached; USD unmeasurable this run)
- ε non-inferiority = 0.0; lift required on severity-weighted recall

## 2. Execution

- Attempt 1 (900 s leash): A0/minivault timed out honestly; kill switch exercised;
  runner halted `paused_operator`; session archived as
  `aborted-900s-20260823T183448Z/` — kept as evidence the pause path works.
- Attempt 2 (3600 s leash): **all 10 runs (5 targets × 2 arms) completed,
  exit_status ok**, seed 7, preregistration hash bound into manifest.
- Contamination gate (`enforce_at_harness_start`) ran before every launch over an
  empty ingested-corpus inventory (R4 live ingest still pending) — vacuous but TRUE.

## 3. Results

### Runner-level (transport observations — BLIND under print-mode Prime)

Both arms: `findings=[]`, recall 0.0, poc_rate 0.0, time/cost null. The transport sees
only final stdout and no structured finding events; the scorer correctly refuses to
invent numbers. This is the primary instrumentation gap R6 exposed.

### Operator adjudication layer (method disclosed in `adjudication-grader.json`)

Deterministic keyword-family matching over each report + PoC artifact listing in the
workspace. Every score cites matched spans / files.

| Target | Family (severity) | A0 recall | A5 recall | PoC artifacts |
|---|---|---|---|---|
| eval-minivault | reentrancy (9.0) | 1.0 | 1.0 | 3 / 3 |
| eval-sharepool | share-inflation (6.0) | 1.0 | 1.0 | 8 / 8 |
| eval-oracle-stale | oracle-staleness (7.5) | 1.0 | 1.0 | 8 / 8 |
| eval-guarded-vault | missing-access-control (8.5) | 1.0 | 1.0 | 1 / 1 |
| eval-splitter-rounding | rounding-dust-drain (5.5) | 1.0 | 1.0 | 0 / 0 |

**Mean adjudicated recall: A0 = 1.0, A5 = 1.0** (all runs exit ok).

## 4. Gate verdict (machine) + adjudication reading

- Machine gate: `release_ready = False` — "full-Ayran did not lift a preregistered
  primary metric over A0". Correct given what the transport could observe; the gate
  is left UNOVERRIDDEN.
- Adjudicated reality: both arms saturated these purpose-built single-defect fixtures.
  Non-inferiority HOLDS (1.0 ≥ 1.0 − 0); **lift is NOT demonstrated** — the exam was
  too easy to discriminate. Both reports contain verified exploits, measured blast
  radii (e.g., 262 re-entries ≈ 263× amplification), validated fixes, and (A5) seven
  hypotheses recorded through the live Gate-A/Gate-B surface with guardrails visibly
  refusing shortcuts (`evidence.gate_b` refusal captured in session logs).
- Bottom line: **the pipeline is proven end-to-end live; lift remains UNMEASURED**
  until targets are harder and/or the transport emits structured finding events.

## 5. Validity threats (disclosed)

1. **Answer-key exposure**: workspaces initially contained `target.json` (the answer
   key). Exposure windows: minivault, sharepool, oracle-stale pairs ran EXPOSED;
   guarded-vault and splitter-rounding ran BLinded (keys archived mid-exam, zero
   `target.json` left). Equal for both arms; direction favors "found" scores equally.
2. **Workspace reuse across arms within a target** (A0 always first): A5 saw stock's
   leftover scratch — an order effect favoring A5 on later targets.
3. Single seed; five purpose-built fixtures, not upstream captures.
4. Token usage unparsed by transport → cost nulls (Prime session files retain real
   usage for later costing if desired).

## 6. Defects found & fixed BECAUSE of R6 live preparation

- `gates/__init__.py` circular import killed cold `import ayran.skill.verbs` (fixed:
  lazy PEP 562 re-exports; suite green).
- `runtime/recover.py` slots-dataclass serialization crash (`entry.__dict__`) broke
  recovery reconciliation (fixed: `dataclasses.asdict`).
- `test_r5_crash_resume.py` killpg needed `start_new_session=True` (S9.5's first real
  ext4 execution now PASSES).
- Logged for follow-up (unfixed): Gate-B obligation JSON row labels swapped
  (negative_controls/defect_removal vs fix_efficacy); `evidence.attach` schema rejects
  absolute `working_root`.

## 7. Machinery validation achieved

Preregistration refusal paths (T1/T2), contamination-first ordering, cap/pause states,
kill switch between launches, timeout partial-transcripts, honest null-metric
disclosures, failure inclusion — every behavior machine-proven offline (T1–T10) and
exercised live (pause used deliberately; timeouts recorded truthfully).
