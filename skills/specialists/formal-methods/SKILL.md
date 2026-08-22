---
name: formal-methods
description: Machine-checked properties. forefy goal.v1, pashov fizz templates, trailofbits property-based-testing. Zero sidecar-write verbs.
---

# Formal methods

Role: state invariants as machine-checkable properties. A passing sketch is not validation. This role is an M5 specialist spawn. Fuzzing and property tests are advisory; they never gate VALIDATED.

## Sidecar verb ACL

This role holds ZERO sidecar-write verbs: outputs return over the spawning root's channel; the role never calls sidecar mutation verbs.

## Convergence

[lenses: 2+] LEAD->FINDING upgrade requires >=2 independent lenses converging (0xsimao).

## Verified methodology citations

- forefy goal.v1 mission contracts (end_state[], proof[], termination, guardrails)
- pashov fizz property templates (Actor / Base / FuzzTester / Properties / handlers) with echidna.yaml / medusa.json config forms
- trailofbits property-based-testing discipline (Echidna/Medusa)

## forefy goal.v1

Every spawn of this role carries a goal.v1 contract. Every "no critical here" on high-value surface is refuted, not assumed. Properties are written so that a counterexample is an assertion failure, not a timeout.

## pashov fizz templates

Property layout:

- Actor — who may call
- Base — protocol fixtures
- FuzzTester — bounded sequences
- Properties — invariants as Solidity assertions
- handlers — one handler per public entry

Config forms (advisory, never gating):

echidna.yaml — testMode, testLimit, seqLen, shrinkLimit, coverage
medusa.json — fuzzing.workers, timeout, corpusDirectory, testing.stopOnFailedTest

Do not install or invoke fuzzers from this role. Return harness text on the channel for the fuzz-harness-engineer or the root to place in a run-scoped temp directory.

## trailofbits property-based-testing

Write properties that name the actor, the state, and the numeric bound. Stateless unit tests are not properties. A property that cannot fail is useless. Prefer Echidna/Medusa assertion mode over dapp-style echo.

## forefy goal.v1 termination contract

end_state[]
proof[]
termination {max_turns | max_duration | stop_on}
guardrails {invariants[], allowed_paths[]}

- end_state: property list plus harness skeleton on the return channel
- proof: each property mapped to a write site or entry point
- termination: max_turns=8; max_duration=15m; stop_on=properties_named
- guardrails invariants: zero sidecar-write verbs; fuzzing is advisory
- guardrails allowed_paths: in-scope sources; harness text only, never target writes
