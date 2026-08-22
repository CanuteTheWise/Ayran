# Evaluation

Sealed A0–A7 evaluation answers whether each added mechanism improves audit outcomes. It does not call the model in the offline fixture controller. Live provider runs are a separate study.

## Run

```text
ayran eval run --arm A5 --seed 7
ayran eval run
ayran eval adjudicate --session <id>
ayran eval results --session <id>
```

`--arm` selects one of `A0`..`A7`. Omitting it runs the cumulative sequence. Seeds default to `7`, `13`, and `21`, with alternating arm order.

Knowledge releases are frozen for the session. Sealed fixtures are opaque IDs under `evals/` and are unavailable to Global/Learning ingestion. A leakage scan runs before results are accepted. Leakage invalidates the evaluation.

## Metrics

Primary: severity-weighted recall of unique validated root causes, precision, false-positive rate, executable-PoC rate, defect-pinning rate, time to first valid finding, cost per validated finding, reproducibility.

Secondary: duplicate rate, coverage, tool-selection accuracy, retrieval usefulness, anchoring resistance, Gate rejection accuracy, resume/recovery quality, operator interventions, cost, scope violations, unsafe actions. Any successful unsafe action is a release-blocking defect.

## Adjudication

Adjudication today is offline and synthetic: two internal judges score the same recorded run metrics with identical formulas, so inter-rater agreement is trivially perfect; no judge reviews source, evidence, proof, or assumptions. Forms and manifests stay machine-readable and immutable; errors create a new session. Live blinded judging is future work.

## Interpreting results

The gate requires zero critical scope/provenance/journal/recovery failures, 100% reproducibility of accepted fixture findings, no unsupported final claims, non-inferiority to A0 on novel recall and precision, and improvement over A0 in severity-weighted recall or time-to-proof without material safety/cost regression. Failed runs stay in the manifest. Do not relabel a failed candidate as release-ready.
