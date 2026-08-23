<p align="center">
  <img src="docs/logo.png" alt="Ayran" width="280">
</p>

# Ayran

Ayran is a private, local-first autonomous smart-contract security audit harness. It wraps the Prime-Agent CLI with a structured evidence pipeline that turns a configured AI model into a disciplined auditor — one that maps attack surfaces, proposes hypotheses, executes tools to prove or disprove them, enforces validation gates, retains what it learns between audits, and produces defensible reports where every claim resolves to recorded evidence.

The current release is **0.1.6**, now carrying the full Phase-B rebuild on `main`: milestones M0–M9, then R0 truth repair, R1 cognitive inversion, R2 mechanical Gate B, R3 specialists & lenses, R4 corpus ingestion, R5 seamless surface, C3 map enrichment, and R6's live comparative evaluation (not yet re-versioned or tagged). It targets Solidity/EVM contracts on WSL2, runs entirely offline by default, does not send your target code anywhere you did not explicitly allow, and cannot autonomously submit findings externally.

### How to understand Ayran

This README is the current product description. Use it first.

- **Run it:** [docs/operations](docs/operations/README.md) — install, [sessions / Target Graph](docs/operations/session.md), scope, upgrade, security, troubleshooting.
- **Why a decision looks like this:** [docs/adrs](docs/adrs) — accepted architecture records (journal, sidecar, Prime bridge, adapters, gates, corpus, learning, release).
- **Lead AI contract (local only):** `LEAD-OPERATIONS-MANUAL.md` is gitignored. It tells the engagement-lead model how to direct the executing model inside Prime. It is not on GitHub.
- **Do not start from the 2026-08-12 engineering blueprint.** That freeze (`docs/ayran-final-engineering-blueprint.md`) is local, gitignored, and predates `--ayran`, auto-scope, `/ayran:activate`, and per-folder Target Graph persistence. Rewriting it would fork the truth. Current behavior lives here and in operations/ADRs.

---

## What Ayran aims to solve

Using a plain AI agent for smart-contract auditing creates several structural problems that Ayran is designed to fix:

**No audit trail.** A plain agent has no durable record of what it checked, what it ruled out, or why it reached a conclusion. If the session ends, that knowledge is gone. Ayran records every hypothesis, tool run, gate verdict, and evidence artifact in a hash-chained journal with a rebuildable SQLite projection. You can replay any audit from the journal alone.

**Tool output without validation discipline.** An agent might run Slither and report every alert as a finding. Ayran enforces evidence ceilings — Slither alerts become `lead` (a starting point, not a conclusion), while only independently replayable Foundry observations earn `observed` status. A lead can never enter the validation gates. Every candidate finding must pass a knowledge-blind attacker review (Gate A) and a causal falsification review (Gate B) before it can appear in a report.

**Anchoring on known patterns.** Agents tend to find the bugs they've seen before, missing novel attack paths. Ayran protects against this with a mandatory target-first discovery phase, blind-vs-aware review separation, and six independently budgeted advisory lenses that prevent any single approach from monopolizing the search while the model authors hypotheses itself via `remember`.

**No organizational memory across protocols.** Ayran's three-namespace graph separates engagement-specific state (Target Graph, pinned to one protocol folder so mapping survives `/quit` and a new `--ayran` chat) from curated methodology knowledge (Global Graph) from lessons learned across engagements (Learning Graph). Learning promotions are human-reviewed, contamination-checked, and atomically reversible.

**Unsafe tool execution.** Agents that shell out to tools without policy gates can execute unintended actions. Ayran invokes every tool through typed adapters with argv-only invocation, environment variable allowlisting, resource limits, and deny-wins scope policies. Destructive actions always require explicit human approval.

---

## High-level architecture

Ayran is a package that layers onto a stock Prime-Agent installation without modifying it. It consists of three components working together:

**1. Prime extension (TypeScript)** — the bridge. Prime discovers Ayran as a package. After `/ayran:activate`, the extension injects a bounded, labeled context pack into the model's context. Native Prime tool calls flow through stock Prime; the extension enforces scope silently at the pre-execution hook (deny still wins, no routed JSON). It exposes four slash commands (`/ayran:activate`, `/ayran:status`, `/ayran:doctor`, `/ayran:stop`), a ten-verb skill catalog, and extension-side credential minting.

**2. Sidecar engine (Python)** — the brain. A per-run Unix-domain-socket JSON-RPC server that owns the journal, database projections, policy engine, tool adapters, context compiler, event router, evidence pipeline, knowledge corpus, and promotion pipeline. Only the sidecar writes to canonical state; the extension is a client.

**3. Graph Fabric** — the memory. Three isolated namespaces sharing one journal format: Target (one protocol folder, durable across Prime sessions), Global (curated methodology knowledge, immutable releases), and Learning (quarantined cross-engagement lessons, human-reviewed promotion). Journals live on WSL2 ext4.

### Skill verb catalog

The model's working interface is ten verbs in `ayran.skill.verbs`, 1:1 with sidecar RPC handlers. Discovery is env-paths-only (`AYRAN_SOCKET_PATH`, `AYRAN_TOKEN_FILE`). Authorization stays at the RPC boundary; these verbs add none.

| Verb | Signature | Purpose | RPC | Returns |
|------|-----------|---------|-----|---------|
| `map_target` | `map_target(force: bool = False, source_text: str \| None = None)` | Build/refresh attack-surface, value-flow, and data-flow maps and compile the enriched pack. Money-map and coupled-pair sections are deterministic heuristics over source text — leads with documented false-positive traps, not compiler-grade data flow. | `maps.build(attack_surface)` → `maps.build(value_flow)` → `maps.build(data_flow)` → `coverage.summary` → `context.compile` | `{schema_version, maps, coverage, pack}` or a denial |
| `scan` | `scan(adapter, input, timeout=None)` | Run one registered adapter supervised. Findings are leads. | `tools.run` | adapter result (ceiling `lead`) |
| `search_precedents` | `search_precedents(query, filters=None, limit=None)` | Ground hypotheses in **ingested** corpus only. Live Solodit POST remains operator-sanctioned-only. | `knowledge.query` | `{records, count, ...}` (limit trims records) |
| `remember` | `remember(*, origin, claim, attack_path, preconditions, cluster_id=None, **rest)` | Author a hypothesis. The only model→graph write path for reasoning content; writer identity is bound server-side. | `hypotheses.remember` | `{accepted, hypothesis_id, writer, ...}` |
| `attach_evidence` | `attach_evidence(hypothesis_id, artifact, kind="text")` | Bind one artifact to a hypothesis (grade stays `lead`). | `evidence.attach` | attach result |
| `spawn_challenger` | `spawn_challenger(hypothesis_id, *, child_id=None, transport=None, credentials=None, session=None)` | Gate A prep: blind bundle; extension mints; model never handles a challenger token. | `challenger.prepare` + `credentials.deliver` | `{credential_minter, bundle, verdict, ...}` or a denial |
| `request_gate_a` | `request_gate_a(hypothesis_id, *, submission, child_id, transcript_hash=None, reconcile=False)` | Submit the challenger verdict; sidecar consumes the vaulted token at seal. | `evidence.gate_a` | sealed verdict / record |
| `request_gate_b` | `request_gate_b(hypothesis_id, poc_id=None, **rest)` | Executed-artifact post-PoC falsification. Asserted booleans are forgery. | `evidence.gate_b` | Gate B verdict |
| `coverage` | `coverage(cluster_id=None)` | Coverage posture (grid summary + census). | `coverage.summary` (`coverage.cell` for detail) | summary census |
| `report` | `report(hypothesis_id, template=None)` | Render a submission draft. Nothing is sent anywhere. | `finding.build` → `report.render` → `report.lint` | `{schema_version, finding, report, lint}` |

---

## How it works: the audit lifecycle

Every audit engages the same pipeline. Here is the flow from start to finish:

### 1. Setup: `prime-agent --ayran`

In the protocol folder, start Prime with `--ayran`. That starts the sidecar and **reattaches** this folder's Target Graph (or creates one on first visit). Scope auto-binds from `src` / `contracts` / nearby Solidity. Chat stays normal until `/ayran:activate`. `/quit` stops the sidecar; the graph remains. The next `--ayran` in the same folder continues the audit. `AYRAN_FRESH=1` starts empty. Details: [sessions](docs/operations/session.md).

### 2. Mapping: build the model of the target

The mapping engine reads the target's Solidity source and builds six attack-surface maps:

- **Attack surface map** — every external/public function, its state dependencies, value flows, and privilege level. Extracted from Slither and solc output.
- **Control-flow map** — function-level CFG showing how the contract's computation is structured.
- **Data-flow map** — which state variables are written by which functions, showing taint paths from user input to state changes.
- **Authority map** — ownership, roles, access control patterns, unprotected state mutations.
- **Temporal map** — time-dependent state changes, epoch boundaries, deadline logic, cooldown patterns.
- **Value-flow map** — asset/value transfer edges across functions and contracts, complementing the data-flow view.

These maps populate the Target Graph. The model never sees them directly — it sees bounded, labeled summaries via the context pack. The maps are deterministic — they come from tool output, not model interpretation.

### 3. Coverage grid: track what's been examined

For each contract or cluster, a coverage grid tracks risk-weighted cells: entry points, state variables, invariants, external interactions, temporal behaviors, value flows, and integration boundaries. Each cell moves from `unexamined` through `in_progress` to `examined_no_issue`, `blocked`, `lead_found`, `hypothesis_active`, `validated`, or `residual_risk`. A cell can only move forward without explicit invalidation. This tells the router where attention is needed next.

### 4. Hypothesis generation: six advisory lenses, model-authored claims

The router no longer fabricates hypotheses. It emits `LensUpdate` actions over six advisory lenses (budgets still 25/15/15/10/15/20). The model authors claims itself via `remember`:

| # | Lens | Origin label | Budget | What it surfaces |
|---|------|--------------|--------|------------------|
| 1 | `first_principles` | `model_novel` | 25 (protected) | First-principles attack reasoning without external history. Mandatory target-first pass; budget cannot be reassigned until every high-value state cluster is covered. |
| 2 | `precedent` | `global_graph` | 15 | Applicable known mechanisms, incident precedents, and attack patterns, labeled historical reference (guidance, not proof). |
| 3 | `contradiction` | `contradiction` | 15 | Conflicting assertions, spec/code splits, inconsistent formulas/units, tool/model disagreements. |
| 4 | `tool_signal` | `tool` | 10 | Compiler, static, and test leads (ceiling `lead`). |
| 5 | `coverage` | `coverage` | 15 | Untried dimensions and sibling paths on the risk-weighted coverage grid. |
| 6 | `specialist` | `specialist` | 20 | Spawned role reviews (`rlm()`, depth default 1). |

The router enforces budget conservation. Hypothesis deduplication happens at the canonical level: same root cause + affected state + attacker path = duplicate. Nothing is silently merged or deleted.

### 5. Validation: Gate A and Gate B

Every hypothesis follows a state machine. A hypothesis must progress through: `lead` -> `supported` -> `poc_worthy` -> `observed` -> `defect_pinned` -> `validated` -> `reported`.

**Gate A (pre-PoC challenge)** is a knowledge-blind independent review. The challenger receives the claim and the Target view, but NOT any historical matches or the originator's rationale. It must produce: the exact invariant violated, every precondition and whether an unprivileged attacker can create it, the strongest benign explanation, the cheapest decisive experiment, and one verdict. Gate A never marks a surface safe — a falsified verdict records the killed dimension, not a clean bill of health.

**Gate B (post-PoC causal falsification)** is an obligation checklist. It requires: clean replay from a fresh workspace, explicit before-and-after assertions, negative controls (tests that do NOT trigger the attack), defect-removal validation (the fix kills the exploit without breaking the feature), and an independent skeptic. A test that "passes" for the wrong reason returns `needs_reformulation`, not `defect_pinned`.

### 6. Finding building and reporting

When a hypothesis reaches `defect_pinned`, the Finding builder assembles the canonical finding: title, root cause, violated invariant, source spans, attack steps, numerical impact, severity policy citation, PoC with one-command reproduction, negative controls, fix efficacy, assumptions/uncertainties, provenance chain, and mitigation suggestions.

The report renderer produces Markdown and JSON. Every claim sentence is tagged with its evidence source (journal event ID). Assumptions are explicitly labeled. The linter hard-rejects reports with missing proof, stale source lines, unsupported language, secret leakage, or status below `validated`. Report generation launches no tools — it reads from the graph.

### 7. Session management: crash recovery and resume

All state is persisted atomically. If the sidecar crashes, if Prime exits unexpectedly, if WSL reboots mid-audit:

- The journal's hash chain integrity is verified at startup
- The SQLite projection is rebuilt from the journal
- In-flight tool runs are reconciled against process identity
- Leases are reclaimed only when the owning process is confirmed absent
- The context pack recompiled from the graph tells the model exactly where it left off: active hypothesis, result so far, next action, dead ends, untried dimensions

Ayran does not lose work.

### 8. Learning: cross-engagement memory

When an audit completes, outcomes are captured into the Learning Graph (quarantine first, never production). A generalized lesson — a vulnerability pattern that transcends the specific target — follows the promotion pipeline: human review -> target-secret stripping -> fixture generation (positive + hard negative) -> contamination check against sealed evaluation fixtures -> held-out ablation -> versioned release with atomic rollback.

The next engagement that matches the pattern retrieves the lesson via M5's Global/Learning queries. The Learning Graph learns what mechanisms yield valid findings, which tools produce actionable evidence, and which retrieval patterns prevent anchoring — but only after evidence justifies the promotion. A single convincing model output cannot mutate production knowledge.

---

## The tool adapter plane

All tool execution happens through typed adapters registered in the capability registry. Each adapter has a manifest declaring its upstream tool version, detection command, invocation template (argv only — never shell), evidence ceiling, resource limits, and failure taxonomy.

### Production adapters (enabled)

| Adapter | Tool | Version | Evidence ceiling | What it does |
|---------|------|---------|-----------------|-------------|
| solc | Solidity compiler | 0.8.28 | `observed` | Compiles contracts, extracts ABIs, hashes inputs/outputs, records warnings/errors. |
| forge | Foundry test | 1.7.1 | `observed` | Runs unit/fuzz/fork tests. Copies target to temp dir (never mutates). Records fork state, seed, solc version, test pass/fail, traces, assertion failures. Distinguishes compile errors from test failures. |
| slither | Static analyzer | 0.11.5 | `lead` | Static vulnerability detection. Every alert is a lead — a hypothesis seed, not a conclusion. Source spans and evidence ceiling are preserved. |
| solodit | Findings database | api-v1 | `lead` | Searches known findings and incident reports. Rate-limited, privacy-filtered (never exposes target identity). Returns structured records with citations. |

Detection is lazy — the registry probes tools on demand, not at startup. Missing or wrong-version tools degrade capability explicitly without crashing. All adapters invoke with `shell: false`, build argv arrays from templates, run in isolated process groups, and record SHA-256 hashes of every input and output.

### Experimental adapters (registered, disabled by default)

These are discovered in the registry but invisible to `list_capabilities()` unless explicitly requested. They must be individually enabled: Fizz (stateful-fuzz harness generation), Echidna (stateful fuzzing), Medusa (stateful fuzzing), Halmos (symbolic execution), ItyFuzz (hybrid sequence exploration).

---

## What's in the knowledge corpus

The Global Graph is populated from curated snapshots. These are NOT live fetches — they are offline data transformed by the ingestion pipeline into structured knowledge records.

### Fully active in the runtime workflow

**Krait** — the richest knowledge source. Its attack angles, detector modules, kill-gate logic, candidate-proof-critic separation, impact/falsification methodology, and output schemas are ingested as machine-readable reasoning lenses and methodology records. Some design choices were informed by Krait's candidate/proof/critic/kill-gate pattern at the conceptual level only; there is no code lineage — the M1 journal, M5 router, and M6 gates are original implementations. All Krait records carry provenance (commit hash, trust tier) and its self-reported scores are NEVER treated as evidence. Its scheduler is never run.

**0xsimao** — all twelve accounting lenses (desynchronization, shares/exchange-rates, cohorts, liquidation/solvency, cross-chain state, rounding, ordering/MEV, DoS, access/trust, integration assumptions, edge states, flow completeness) ingested as first-class reasoning lenses in the Global Graph. The accounting specialist lens uses these as advisory context; the model still authors hypotheses via `remember`.

**ZeroSkills** — five specialist skill definitions (storage layout, Vyper, symmetry/path comparison, Uniswap v4 hooks, test-suite analysis) ingested as specialist role records. They feed the specialist advisory lens and spawned role reviews; they do not auto-author hypotheses.

**Solodit** — two contributions: (a) the M4 adapter calls the Solodit API to search known findings during an audit (rate-limited, privacy-filtered, ceiling: lead), and (b) historical incident records (beanstalk-2022, cream-2021, euler-2023, nomad-2022, harvest-2020, compound-empty) are ingested into the Global Graph with root cause separated from symptoms and full citation metadata. These incident cards supply the evaluation fixtures and serve as anchor-resistant historical references.

**Claudit** — its Solodit adapter pattern (structured search, pagination, rate limiting, citation tracking) formed the M4 Solodit adapter's design.

### Implemented as design patterns (no runtime adapters)

**Pashov Skills + Fizz** — Pashov's attacker-framed methodology shaped the specialist skill design and the mapper's x-ray approach. Fizz is registered as an experimental adapter for stateful-fuzz harness generation (disabled by default — it must be verified and enabled explicitly).

**ItyFuzz** — registered as an experimental adapter for hybrid EVM/Move sequence exploration (deep stateful fuzzing beyond Foundry's capability). Disabled by default.

**QuillShield Skills** — semantic guards, invariant catalogs, and defensive-review checklists for reentrancy, oracle/flash-liquidity, upgrades, arithmetic, weird-token, DoS. Catalogued as a design donor only: nothing from QuillShield is referenced by Gate A or any runtime code today. No wholesale prompt load.

**Plamen** — deterministic outer phases, append-only candidates, disk gates, checkpoints, retries, orphan recovery — these patterns shape the M1 crash-recovery design, M2 process supervision, and M5 checkpointing. Full Plamen runs only as an external baseline, never inlined.

**Nemesis** — first-principles explanation patterns, coupled-state relation discovery, and mutation matrix concepts. Used by the accounting/state-coupling specialist for invariant reasoning.

**SC Auditor** — typed wrapper patterns influenced adapter naming and path-safety checks for Slither, Foundry, Echidna/Medusa/Halmos scaffolds. Its Map/Hunt/Attack/Verify semantics informed the adapter plane boundaries.

**SCV-Scan** — classic Solidity vulnerability records with compiler/version predicates and hard negatives. Still-correct records are retrievable; obsolete records are tombstoned. No separate scanner.

**Forefy `.context`** — scope/goals/branching/stopping patterns and Foundry PoC hygiene principles. Shaped the M6 gate methodology and PoC validation workflow.

**DarkNavy Contract Auditor** — DFS/value-flow mapping, state-coupled work partition, and entry-point coverage denominator patterns. Used in the M5 mapper's security-relevant view design.

**Trail of Bits Skills** — audit context, multi-language entry points, false-positive review, property testing, differential/variant analysis patterns. Shaped the Gate A/B test design and M6 dedup rules.

**DeFiHackLabs** — the R4 ingestion pipeline converts pinned `src/test/<YYYY-MM>/<Protocol>_exp.sol` header cards into typed incident cards with verbatim numeric assertions and contamination groups; registry audit and sanitization stages (blacklist hook, artifact scan, hostile-hash blocklist) guard it. Ingestion runs offline against caller-supplied pinned directories (`knowledge ingest-defihacklabs`); no live upstream fetch has happened yet, so Global Graph cards from real upstream bytes remain pending work. Retrieved code is never executed.

**Shuvon Skills** — unique vulnerability triage and grep-location concepts ingested with dedup/version predicates. Grep is a locator, not semantic proof.

**Sanbir Move Auditor** — Move/Sui-specific (object/resource/capability, math, access, economic vectors). Catalogued only. Requires a Move mapper and Move tool adapters for activation.

**Olaradial** — duplicate source lineage record only. Excluded with exclusion tests.

### External baselines

**Hound** — catalogued as a potential external baseline; it is not run today and no isolated comparison has been executed. Whether a real Hound baseline happens is future evaluation work; Ayran never depends on it.

---

## How to install and use Ayran

### Prerequisites

- Windows 10/11 with WSL2 installed
- A WSL2 distribution (Ubuntu 22.04+ recommended) on ext4 (never `/mnt/c` or other DrvFS paths)
- Prime-Agent v0.7.2 (commit `83a0f9f9566219551fcb6ffaf7f519a815749a58`) — either installed already or bundled via Complete
- Foundry 1.7.1, Slither 0.11.5, solc 0.8.28 installed in the WSL distribution (detection is automatic; they are NOT bundled)
- Python 3.11+ in WSL (for Layer mode)
- Node.js 18+ in WSL (for extension compilation)
- At least 4 GB free disk space in WSL2 (10 GB recommended for full corpus)

### Option A: Install Layer (recommended for most users)

If you already have Prime-Agent 0.7.2 in WSL:

```powershell
# From the Ayran project root on Windows:
.\packaging\windows\install-ayran.ps1 -Layer -Prime /path/to/prime-agent

# Or use the CLI inside WSL:
ayran release install --layer --prime /path/to/prime-agent
```

Layer installs Ayran into `<prefix>/versions/<version>/` inside WSL (default prefix `~/.local/ayran`, e.g. `~/.local/ayran/versions/0.1.6`), creates a `current` pointer at `<prefix>/current`, and writes a machine-readable receipt to `<prefix>/receipts/<kind>-<version>.json`.

### Option B: Install Complete (clean-slate)

If you want a fully self-contained install (bundles Prime 0.7.2):

```powershell
# From the Ayran project root on Windows:
.\packaging\windows\install-ayran.ps1 -Complete

# Or use the CLI inside WSL:
ayran release install --complete
```

Complete installs everything into `~/.local/share/ayran/complete-<version>/` including its own Prime 0.7.2 in an isolated prefix. It never touches an existing Prime installation.

### Verify installation

```bash
# Inside WSL:
ayran doctor
```

This checks: Prime version compatibility, ext4 placement, Python environment, extension load, sidecar handshake, schema/migration versions, graph integrity, tool manifests and version probes (solc, forge, slither), resource headroom, and socket permissions.

### First audit

After a project-local `prime-agent package install <ayran-pkg> --local`:

```bash
# WSL, venv on PATH:
source "$HOME/.local/ayran-venv/bin/activate"
prime-agent --ayran
```

That one command starts the sidecar, **auto-binds scope** from the repo layout (`src`, `contracts`, or `.`), and **reattaches this folder's Target Graph** (or creates one). You do not write a scope JSON. The model does not write it either — expanding its own permissions would be a jailbreak. Chat stays normal until `/ayran:activate`. Plain `prime-agent` does not start Ayran. Coming back tomorrow in the same folder continues the same map.

Optional overrides: `--ayran-manifest path.json`, `AYRAN_SCOPE`, or `.ayran/scope.json`.

```bash
# Inside Prime: chat normally, then arm injection for the rest of the session
/ayran:activate
# optional: bind/load a scope manifest at the same time
/ayran:activate .ayran/scope.json
/ayran:status
/ayran:doctor
/ayran:stop
```

### Uninstall and rollback

```bash
# Rollback to previous version:
ayran release rollback --receipt <receipt_path>

# Uninstall completely:
ayran release uninstall --receipt <receipt_path>
```

Rollback and uninstall remove ONLY what Ayran installed. Your existing Prime, Foundry, Slither, solc, and WSL tools are never touched.

---

## CLI reference

```text
# Audit lifecycle
ayran start                             # reattach this folder's Target Graph, or create one
ayran start --fresh                     # new empty Target Graph for this folder
ayran start --roots src,contracts       # override detected folders
ayran start --manifest <scope>          # bind a custom scope-manifest JSON
ayran session prepare [--cwd <path>]    # same auto-bind as start, for --ayran
ayran service --run <id>                # run the local JSON-RPC sidecar
ayran status --run <id>                 # show run status, phase, budget
ayran doctor                            # full system health check
ayran diagnose --run <id> --bundle <path>  # export diagnostic bundle
ayran stop --run <id> [--graceful]      # stop a run
ayran recover --run <id>                # resume after crash

# Tools
ayran tools list                        # show available adapters
ayran tools detect <id>                 # probe a specific tool
ayran tools health <id>                 # health check a tool
ayran tools run <id> --input '<json>'   # invoke an adapter
ayran tools doctor                      # tool diagnostics

# Evidence and gates
ayran evidence transition <id> --to <state>  # state machine transition
ayran gate-a <hypothesis_id>            # run Gate A challenge
ayran gate-b <hypothesis_id>            # run Gate B falsification
ayran dedup check <hypothesis_id>       # check for duplicates
ayran poc run <hypothesis_id>           # execute PoC via Foundry
ayran poc replay <poc_id>               # clean replay

# Findings and reports
ayran finding build <hypothesis_id>     # build canonical finding
ayran report render <finding_id>        # render report (markdown|json)
ayran report lint <finding_id>          # lint report for unsupported claims

# Context and routing
ayran context compile --cluster <id>    # compile a context pack
ayran router status                     # show router state and budgets
ayran router step                       # advance one router cycle manually
ayran router history                    # recent routing decisions

# Knowledge management
ayran knowledge list-sources            # show curated knowledge sources
ayran knowledge status                  # current corpus release, record counts
ayran knowledge query --type <type>     # query knowledge records
ayran knowledge release --version <v>   # construct a corpus release
ayran knowledge tombstone <id> --reason # tombstone a source
ayran knowledge ingest-defihacklabs <dir> --archive-sha256 <h>  # pinned DeFiHackLabs ingest (R4)
ayran knowledge ingest-krait <dir>      # Krait deep-ingest (845-check snapshots)
ayran knowledge audit-registry          # registry integrity + fabrication audit

# Learning
ayran learning capture --run <id>       # capture outcome for learning
ayran learning queue                    # quarantine queue
ayran learning review <id> --verdict <v>  # submit review
ayran learning promote <candidate_id>   # run promotion pipeline
ayran learning rollback <release_id>    # rollback to previous release
ayran learning status                   # learning graph status

# Coverage and maps
ayran coverage summary                  # risk-weighted coverage grid
ayran coverage cell <cell_id>           # detailed cell state and evidence
ayran maps <type>                       # print a map (attack_surface, control_flow, etc.)

# Evaluation and release
ayran eval preregister --manifest <sheet.json> --results-root <dir>  # sign the grading sheet before live runs
ayran eval run --arm <A0..A7> --seed <n>   # run sealed evaluation
ayran eval run --live --preregistration <sheet> --targets <dir> --results-root <dir>  # live comparative session
ayran eval pause --results-root <dir>      # kill switch (honored between launches)
ayran eval adjudicate --session <id>       # adjudicate results
ayran eval results --session <id>          # show results manifest
ayran release build --layer             # build Layer bundle
ayran release build --complete          # build Complete bundle
ayran release validate --path <bundle>  # validate a release bundle
ayran release install --layer|--complete # install release
ayran release rollback --receipt <path> # rollback install
ayran release uninstall --receipt <path> # uninstall release

# Graph operations
ayran graph verify --root <path> --stream <s>  # verify hash chain
ayran graph rebuild --root <path>              # rebuild SQLite projection
ayran graph doctor --root <path>               # graph health
```

---

## Recommendations for improvement

The following are evidence-based recommendations to make Ayran more effective for autonomous smart-contract hunting. They are organized in rough priority order. Each is testable — run the relevant A0-A7 arm before committing resource.

### 1. Validate Fizz and promote A6 from experimental to production

**Why:** No evidence establishes value for stateful fuzzing: the offline sealed-fixture controller computes metrics by formula rather than by measurement, so the A6 arm demonstrates nothing about real-world lift. Without Fizz being available in production, A6 remains a concept rather than a tool.

**What to do:** Install Fizz as a controlled dependency, verify against the pinned Prime 0.7.2 compatibility surface, and run a live A6 evaluation. If the harness shows lift, promote it. If not, drop A6 from Phase 1 release planning and document why.

**Effort:** Medium (integration + evaluation). **Impact:** High (stateful coverage of invariants you cannot find with static analysis).

### 2. Raise Solodit's evidence ceiling for duplicate detection

**Why:** Currently Solodit results are capped at `lead` — historical reference only. But Solodit is the best duplicate detector available. When it returns a high-confidence match (same root cause + same affected state + citation), that should trigger the `duplicate_known_issue` state directly, not be treated as a mere hint.

**What to do:** Run a live evaluation arm measuring Solodit duplicate detection precision on known fixtures. If precision >95% for a given match type, add a special-case path: exact Solodit match -> `duplicate_known_issue` without requiring Gate A challenge.

**Risk:** False duplicates must be recoverable — the DUPLICATES edge must link but never delete. If you make this change, retain the original hypothesis record.

### 3. Evaluate whether Krait's attack-angle patterns should be runtime adapters

**Why:** Krait shaped the architecture but has no runtime adapter. Its attack angles, kill gates, and candidate/proof/critic patterns are available as knowledge records. The open question is whether a model actually uses Krait's methodology more effectively when it can *query* the attack angles at runtime rather than just having them summarized in a context pack.

**What to do:** Design an experiment: run an audit with Krait knowledge as-is, then run the same audit with a thin Krait query adapter (`tools/search_krait_patterns`). Compare coverage, duplicate rate, and time-to-first-valid-finding. If runtime query wins by >10% on your primary metric, promote a Krait adapter.

**Effort:** High (new adapter + evaluation). **Impact:** Unknown — evaluate first.

### 4. Add one complementary static analyzer

**Why:** Slither has false negatives and false positives. A second perspective would improve coverage, particularly for compiler-specific optimizations and proxy patterns.

**What to do:** Falcon (MetaTrustLabs) is catalogued as an experimental static analyzer. Promote it to experimental adapter status, run a detector-level ablation (Falcon findings vs. Slither findings on the same corpus), and only add it if it catches at least one bug class that Slither misses.

**Risk:** Adapters add version-maintenance burden. Each new adapter is a parser contract with an upstream project that may break. Budget for maintenance.

### 5. Decompose Krait's kill-gate logic into an explicit adversarial specialist

**Why:** Kill-gates force you to articulate what would falsify a hypothesis before investing in PoC work. Currently this is embedded in Gate A and Gate B, but it's not a separate driver.

**What to do:** Create a dedicated "kill-gate specialist" driver origin: for each `supported` hypothesis, this driver asks "what single experiment would kill this claim?" It runs before PoC work. If a kill-gate challenge fails cheaply, the hypothesis is ruled out early.

**Effort:** Medium. **Impact:** Medium-to-high — reduces false-positive and dead-end PoC work.

### 6. Wire the pre-PoC kill-gate checklist into the router's stop conditions

**Why:** Gate A is a structured challenge — but it fires BEFORE the PoC, not during. By the time a hypothesis is on Gate B, time and resources have been spent. A cheaper Kill-Gate challenge (using Krait's pattern: "state a falsifiable condition and the cheapest experiment to test it") can kill weak hypotheses before Gate A runs.

**What to do:** Add a pre-Gate-A step in the router: for each hypothesis, require one falsifiable condition statement. The router rejects any hypothesis that cannot state a falsifiable condition. This is cheap — one question per hypothesis.

**Effort:** Low. **Impact:** Medium (reduces Gate A workload).

### 7. Run live-model A0 through A7 against multiple project families

**Status: first live comparative session executed (R6, 2026-08-23)** — A0 vs full-Ayran on five held-out single-defect fixtures, preregistered sheet bound before launch, kill switch and caps active. Outcome: both arms adjudicated at recall 1.0 (ceiling — no lift measurable at that difficulty), transport-blind scoring disclosed, machine gate honestly kept at `release_ready: false`. Record: `docs/evaluation/r6-session-evs_163P3NAAQ7EQQ3K7SWN1J3XXHY/`. What remains for a *discriminative* result: harder multi-defect targets, a seeing-eye scorer (structured finding events or integrated post-hoc grading), multiple seeds/project families.

**Why:** Everything else was validated against offline fixtures. The entire point of the arm sequence is to answer whether each added mechanism improves real audit outcomes.

**Risk:** Expensive (API costs). Budget accordingly. Run smaller pilot first.

### 8. Increase the coverage grid's temporal and cross-chain awareness

**Why:** The temporal map catches deadline/epoch logic, but MEV, cross-chain timing, and multi-block state attacks are the hardest class to catch statically.

**What to do:** If you have access to MEV-relevant project families, add a `crosschain_temporal` coverage dimension. For MEV-sensitive contracts, add an evaluation arm that specifically measures temporal-vector coverage.

### 9. Build a replayable benchmark suite from your own audit history

**Why:** Your learning pipeline is designed to learn from outcomes, but you need a way to prove that learning actually helps. The best proof is cumulative: show that Finding N+1 validates faster or misses fewer dimensions because of what was learned from Finding N.

**What to do:** After every 10 audits, construct a benchmark: take a fresh target you haven't audited, run it with Learning active vs. Learning frozen, and compare precision, recall, and time-to-first-valid-finding. This may become A8 in the sequence — if the evidence justifies it.

---

## Runtime safety boundary

Ayran enforces policy; it does not sandbox execution. Critical truths about the trust model:

- Prime workers, agents, IPython, and the extension all run with your user permissions
- The UDS sidecar binds owner-only (0o600) with constant-time token comparison
- DiffFS and native Windows paths fail closed — ext4 only
- Destructive actions (file deletion, writes to protected paths) require explicit human approval
- Experimental adapters are disabled by default
- No network access is required for installation or offline evaluation
- Secrets and target source code are never persisted in journals or support bundles
- Ayran cannot autonomously submit findings to external platforms
- Every install step works offline

The real boundary is policy at the sidecar layer (deny-wins scope ACL, per-identity verb ACLs, single-writer state) plus external OS sandboxing (WSL/container isolation). There is no payload string-sniffing: enforcement is structural. Do not run untrusted Ayran targets outside an isolated VM.

---

## Documentation index

### ADRs

- [ADR 024: Journal Format v1](docs/adrs/024-journal-format-v1.md)
- [ADR 025: Local API and configuration](docs/adrs/025-local-api-configuration.md)
- [ADR 026: Prime lifecycle bridge](docs/adrs/026-prime-lifecycle-bridge.md)
- [ADR 027: Tool adapter plane](docs/adrs/027-tool-adapter-plane.md)
- [ADR 028: Context compiler and router](docs/adrs/028-context-compiler-router.md)
- [ADR 029: Evidence pipeline and gates](docs/adrs/029-evidence-pipeline-gates.md)
- [ADR 030: Global corpus ingestion](docs/adrs/030-global-corpus-ingestion.md)
- [ADR 031: Learning promotion](docs/adrs/031-learning-promotion.md)
- [ADR 032: Release and evaluation](docs/adrs/032-release-evaluation.md)

### Operations

- [Install guide](docs/operations/install.md)
- [Sessions and the Target Graph](docs/operations/session.md)
- [Scope](docs/operations/scope.md)
- [Security model](docs/operations/security.md)
- [Troubleshooting](docs/operations/troubleshooting.md)
- [Upgrade guide](docs/operations/upgrade.md)
- [Evaluation guide](docs/operations/evaluation.md)

---

## License and distribution

Ayran 0.1.6 is a **private release**. It is not licensed for public redistribution. The pinned Prime 0.7.2 archive includes its upstream MIT license; third-party notices live under `LICENSES/`.

This is version 0.1.6 carrying the Phase-B rebuild (R0–R6 + C3) on `main`. It is not a certified release and has no public license yet. A live comparative evaluation (A0 vs full-Ayran, five held-out targets, preregistered sheet) was executed on 2026-08-23 under operator-delegated authority: pipeline proven end-to-end, non-inferiority at ceiling, lift not demonstrated — see `docs/evaluation/r6-session-evs_163P3NAAQ7EQQ3K7SWN1J3XXHY/ADJUDICATION.md` for the full honest record.
