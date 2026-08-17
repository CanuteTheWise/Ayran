# ADR 024: canonical Graph Fabric journal format v1

- Status: accepted for M1
- Date: 2026-08-12
- Governing inputs: Final Engineering Blueprint §§3.1–3.8, 11, 15, 18, 19, 22 (M1), and ADRs 004–006

## Context

`GraphEvent@1.0.0` is a Target-oriented event contract whose payload contains only a contract ID, object ID, and content hash. It deliberately does not contain the referenced graph object. It also requires a Target run and Target identity even when its `graph` enum says `global` or `learning`. Writing bare GraphEvents to JSONL would therefore make a zero-projection rebuild depend on transient caller data and would force false Target identities into non-Target namespaces.

M1 preserves `GraphEvent@1.0.0` unchanged. It introduces a self-contained, namespace-aware `JournalEvent@1.0.0` and a three-record `JournalRecord@1.0.0` grammar. The event and projection adapters may accept a valid M0 GraphEvent at an ingress boundary where appropriate, but historical journal bytes use the M1 contracts below.

The M0 `tgt_<ULID>` remains an identity shell. M1 adds `target_key`, the SHA-256 canonical identity derived by the caller from origin, commit, scope ID, and source-tree hash. This resolves the blueprint's content-derived identity requirement without breaking M0 IDs.

## Decision

### Stream identity

Every record contains one closed discriminated identity:

- Target: namespace, stream ID, run ID, M0 TargetIdentity, and `target_key`.
- Global: namespace, stream ID, corpus ID, release ID, ontology version, and release-manifest hash.
- Learning: namespace, stream ID, learning-store ID, and optional origin run/Target key.

No journal batch crosses streams or namespaces. Cross-namespace causality uses `causation_id`; it is not an atomic transaction.

### Framing and canonical bytes

Journal format `1` is UTF-8, LF-delimited JSONL. Each line is exactly the RFC 8785 canonical serialization of one `JournalRecord`, followed by one byte `0x0a`. Readers reject BOM, CRLF, duplicate keys, invalid UTF-8, noncanonical encodings, non-finite numbers, and values outside the RFC 8785 domain.

A command batch is exactly:

1. `batch.begin`
2. one or more `batch.event` records
3. `batch.commit`

The commit record is the only visibility boundary. A batch never spans segments. Segment rotation occurs only after a committed batch.

`batch.begin` binds stream identity, batch/operation/causation IDs, idempotency key, canonical request hash, a sorted duplicate-free expected-revision set, first sequence, member count, previous event/commit hashes, and creation time.

Each `batch.event` embeds a complete `JournalEvent`. The event embeds the full validated durable object plus its versioned contract ID, object ID, content hash, and a closed transition descriptor (`snapshot`, `retraction`, or `tombstone`). This is sufficient to rebuild SQLite from journal bytes alone. Artifact file bodies may remain external content-addressed blobs, but their durable metadata and hashes are journaled and missing artifacts are reported.

`batch.commit` binds the begin hash, ordered member hash, sequence range, event-chain endpoints, and previous commit hash. Hash domains are literal fields:

- `ayran.journal.begin.v1`
- `ayran.journal.members.v1`
- `ayran.journal.commit.v1`
- `ayran.journal.merkle.v1`

All digests are `sha256:` plus lowercase SHA-256 of RFC 8785 canonical UTF-8 bytes. The begin hash hashes the complete begin record. The members hash hashes `{domain,event_hashes}` in ordinal order. The commit hash hashes the complete commit record with `commit_hash` omitted. A JournalEvent's event hash uses the M0 canonical rule: omit top-level `integrity.content_hash` and `event_hash`; hash every other field, including the embedded body. The embedded object's `content_hash` is independently verified with only its own `integrity.content_hash` omitted.

Genesis sequence is 1 with null previous event and commit hashes. Later batches/events are contiguous. Event IDs, hashes, sequences, batch IDs, aggregate versions, and idempotency keys are unique within a stream. Aggregate versions start at 1 and advance contiguously.

### Object and transition consistency

The contract registry resolves the body's explicit semver contract ID. The body value must pass that canonical schema and contextual validation. The object ID field selected by the registry must equal `body.object_id`; its canonical content hash must equal `body.content_hash`. Namespace, run, target/corpus/learning identity, aggregate ID/version, `valid_from_event`, event type, and transition kind are checked together.

Node/edge/assertion history is never rewritten. A revision, retraction, or tombstone is a new JournalEvent. SQLite derives `valid_to_seq` for an earlier revision from the later transition. Historical object bytes retain their original `valid_to_event` value.

### Idempotency and expected revisions

Idempotency scope is `(stream_id, idempotency_key)`. `request_hash` covers the canonical semantic command: stream identity, operation/causation IDs, idempotency key, sorted expected revisions, event types, aggregate IDs, versioned contract IDs, transition data, and full caller-supplied durable bodies. Writer-allocated sequence, event, batch, and commit IDs/hashes are not inputs.

- Same key and request hash returns the original acknowledgement with `idempotent_replay=true`.
- Same key and a different request hash fails with `IDEMPOTENCY_COLLISION` and no write.
- An expected-revision mismatch fails with `CONFLICT_REVISION`, reports the current revision, and writes nothing.
- Revision `0` means the aggregate must not yet exist.

All validation, identity, reference, idempotency, and revision preconditions are checked before journal bytes are written.

### Durability and acknowledgement order

Under the single-writer OS lease:

1. verify/recover the journal tail and reconcile projection lag;
2. validate the complete command and all preconditions;
3. allocate a batch ID, contiguous stream sequences, event IDs, and aggregate versions;
4. canonicalize and hash begin, members, and commit;
5. append every newline-terminated byte with a complete-write loop;
6. flush and `fsync` the segment once after the commit record;
7. apply the whole batch under SQLite `BEGIN IMMEDIATE`;
8. insert batch receipt, applied events, graph revisions, provenance/references, checkpoint/outbox state, and commit SQLite;
9. acknowledge only after the journal fsync and SQLite commit.

Target and Learning use foreign keys, WAL, `synchronous=FULL`, and a 5-second busy timeout. Global staging may use `NORMAL` only when explicitly marked disposable; publication verifies a FULL checkpointed database with no live WAL dependency.

If journal fsync returns an error, the stream freezes until a fresh verifier establishes the durable tail. If the journal commit is durable but SQLite is not, replay applies the whole batch. If SQLite committed but the caller lost the response, retry returns the stored receipt. No reader cursor advances inside a batch.

### Segments, manifests, and backups

Segments are named `000001.jsonl`, `000002.jsonl`, and so on. Default rotation is at 64 MiB or 100,000 committed events. A batch that crosses a threshold finishes in the current segment; the segment closes immediately afterward.

A closed immutable segment manifest records format/schema versions, stream identity, segment ID/name, exact byte size and file hash, event/batch counts, sequence and event/commit endpoints, previous-manifest hash, deterministic Merkle root over event hashes, backup state, and creation/closure time. Merkle leaves are RFC 8785 hashes of `{domain,index,event_hash}`; parents hash `{domain,left,right}`, duplicating an odd final node. Nondeterministic timestamps are not Merkle inputs.

The manifest is written to a sibling temporary file, flushed and fsynced, atomically replaced, and followed by a parent-directory fsync. Closed segment and manifest backup copies are byte-verified. SQLite is disposable and need not be backed up.

### Recovery and corruption

Verification processes segments numerically and independently checks JSON framing, duplicate keys, canonical bytes, all schemas/body hashes, begin/member/commit state, batch and event hash chains, sequences, identities, references provable from history, and closed manifests.

- A non-newline trailing partial frame or an EOF batch lacking a valid commit is an unacknowledged suffix. After the entire preceding prefix is verified, its exact bytes are copied to a receipt-owned diagnostics file, fsynced, and the active segment is truncated to the last verified commit boundary and fsynced.
- A complete invalid frame, an invalid committed batch, an interior framing error, sequence/hash/reference corruption, or a closed-manifest mismatch stops writes with `JOURNAL_CORRUPT`. It is never automatically rewritten.
- SQLite corruption or deletion never changes the journal. A new projection is rebuilt beside the old one.

### Checkpoints, rebuilds, and migrations

A checkpoint is a resume marker containing stream identity, journal sequence/event/commit hashes, projection/migration versions, currently available target/config/source/tool/artifact hashes, outbox digest, and logical projection digest. Null represents a value owned by a later milestone; a value is never fabricated. A checkpoint can accelerate replay only when accompanied by a verified projection snapshot; otherwise rebuild starts at zero.

Rebuild creates a sibling projection, replays committed batches, validates SQLite integrity/foreign keys/counts/references and canonical query digests, then switches a same-filesystem pointer through temp-file fsync, atomic replace, and directory fsync. The previous projection remains for rollback. The journal is never modified.

Migrations are numbered, forward-only Python modules with immutable checksums and `precheck`, deterministic event adaptation where required, fresh rebuild, and `validate`. Rollback restores the prior projection pointer. Released migrations and journal v1 bytes are never edited in place.

### Namespace publication

- Target lives below one run's `target` directory and enforces its immutable run/Target identity.
- Global builds in a new staging release, verifies fully, publishes the release immutably, and atomically changes `global/current.json`. Rollback changes that pointer to a prior immutable release.
- Learning lives in a physically separate quarantine root. M1 rejects promotion to Global.

Authoritative journal, SQLite, WAL/SHM, lease, rebuild, pointer, checkpoint, and diagnostic files must resolve to WSL ext4. Tests may opt into explicitly unsafe temporary filesystems only for unit semantics; acceptance and durability claims run on WSL ext4.

## Compatibility and rollback

Journal format v1 is permanent. Readers reject unknown format or incompatible schema versions with `UNSUPPORTED_SCHEMA_VERSION` or `MIGRATION_REQUIRED`. New object schema versions require a declared deterministic adapter. No released record, segment, manifest, or migration is rewritten.

Rollback installs prior code that still declares journal-v1 compatibility, or exports verified journal v1 through the prior adapter. Projection rollback only changes the active projection pointer. Global rollback only changes the current-release pointer.

## Verification

M1 verification must include real subprocess termination after journal fsync, during SQLite, after SQLite commit/before acknowledgement, during rotation/manifest publication, and during projection/global pointer switches; property tests for chain/idempotency/revision/batch invariants; corruption and lease contention tests; zero rebuild with equal canonical query digests; and the deterministic 100,000-event WSL ext4 fixture.

## Consequences

The journal is larger than a reference-only stream, but history is independently replayable and auditable. One fsync per command batch is the selected durability/throughput tradeoff. The format does not claim protection against a malicious party able to replace the journal, manifests, and all backup anchors; later release signing may add an external trust anchor without changing v1 bytes.
