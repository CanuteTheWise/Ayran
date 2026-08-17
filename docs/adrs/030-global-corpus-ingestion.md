---

status: accepted (2026-08-14)

---

# ADR 030 — Global Graph curated corpus ingestion

## Context

M7 populates the Global namespace so M5 ontology queries and
blind/aware retrieval have real curated knowledge. M5 `search_mechanisms`
and `search_incidents` previously scanned empty MechanismCard and
IncidentCard node sets. Blueprint §7 requires a source registry, pinned
raw snapshots, injection-safe parse, provenance/rights, taxonomy, entity
resolution that never majority-votes, first-class hard negatives, and
immutable versioned corpus releases. Network fetch and source execution
are forbidden. Zero new runtime dependencies are allowed. Graph writes
remain GraphStore.append from the sidecar and operator CLI.

Approved runtime-usable sources for this seed are ZeroSkills, Solodit,
0xsimao, and Krait. Other §6 repositories stay deferred or catalogued
with no M7 runtime route.

## Decision

1. **Authored snapshots, not live clones.**
   Registry YAML lives under `knowledge/registry/`. Curated text lives
   under `knowledge/raw/<source_id>/`. `acquire_pin` hashes the local
   working tree and compares an optional `pin.archive_sha256`. Git clone,
   HTTP fetch, checkout hooks, package scripts, and `exec`/`eval` are
   out of scope. A missing snapshot quarantines; it is not downloaded.

2. **Fourteen-stage deterministic pipeline.**
   Stages match §7.1: registry proposal through contamination scan, with
   `corpus_release` as an explicit publish step. Each stage returns
   success or a `QuarantineRecord`. Quarantined bytes remain under
   `knowledge/quarantine/` and are never returned by production query.
   The same snapshots produce the same record IDs (content-derived) and
   the same manifest `content_hash`.

3. **Normalized knowledge model without new M0 schemas.**
   `KnowledgeRecord` and the MechanismCard / IncidentCard /
   SpecialistSkill specializations are Pydantic models in
   `ayran.knowledge.models`. Retrievable graph copies are existing
   `graph-node` / `graph-edge` contracts (`MechanismCard`,
   `IncidentCard`, `VulnerabilityPattern`, `ReasoningLens`,
   `CONTRADICTS`, `VARIANT_OF`, `LEARNED_FROM`). Extra fields serialize
   as typed properties. Evidence grade remains `lead`.

4. **Entity resolution links; it does not merge.**
   Order: exact hash, canonical source/commit/path, project/fork
   lineage, root-cause fingerprint, semantic candidate. Duplicates
   become `VARIANT_OF` or `LEARNED_FROM`. Conflicting loss, root cause,
   fix, or affected version become a `ConflictGroup` with
   `reviewer_disposition=unresolved`. The compiler surfaces those groups
   as COUNTEREVIDENCE. No majority vote.

5. **Hard negatives are first-class records.**
   `false_positive_trap` rows carry `hard_negative: true`, the safe
   variant, why it is safe, and the distinction from the defect. M5
   drivers can query them; they never become executable.

6. **Releases are immutable; tombstones publish a successor.**
   `knowledge/releases/<corpus_id>/` stores content-addressed record
   blocks plus `manifest.json`. `knowledge/current.json` is an atomic
   pointer. Refresh writes a new release. Active runs stay pinned to
   the release they opened. Removing a source tombstones the registry
   entry and publishes a new release; the previous release directory
   remains. The manifest `signature` is the RFC 8785 SHA-256 of the
   unsigned body (self-attestation until M9 signing).

7. **Contamination wall.**
   Each source has `contamination_registry` in
   `{production, development_evaluation, sealed_holdout}`. Sealed
   labels cannot enter a production release. Deferred sources cannot be
   ingested.

8. **Additive projection v0004.**
   `knowledge_records`, `conflict_groups`, and `corpus_releases` are
   new tables. `MIGRATION_VERSION` is 4. v0001–v0003 are unchanged.

## Consequences

M5 `search_mechanisms`, `search_incidents`, and
`search_vulnerability_patterns` return curated cards once a release is
published into the connected graph. Blind compiles still omit
HISTORICAL_REFERENCE. Model-assisted normalization, if added later,
remains `model_observation` until review. M8 Learning promotion and M9
evaluation/signing are not implemented. Prime 0.7.2 and external tools
are untouched.
