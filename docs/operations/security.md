# Security

## Trust model

Prime's kernel and workers are not a sandbox. Ayran enforces policy at the extension and sidecar, and treats OS isolation (WSL/container) as the containment boundary. Target-repository instruction files are never trusted configuration.

## Scope policy

Deny wins. Scope manifests name allowed roots, actions, hosts, tools, and write paths. Later config layers may only narrow policy unless a private `security_override` is confirmed for that run.

## Sandboxing notes

Destructive actions, broadcasts, submissions, and installers stay human-gated.
Experimental adapters stay disabled unless an operator enables them. Tool invocation
is argv-only (`shell: false`) with environment allowlisting; the target is copied to
a scratch directory before any test run.

## Model credentials (R5)

Session keys are generated in the Prime extension (TypeScript — outside
model-reachable Python) and enrolled once into the sidecar via the
`credentials.enroll` RPC; until enrollment, credential-dependent methods fail closed.
Per-spawn challenger tokens are minted by the extension, vaulted server-side via
`credentials.deliver`, and consumed at the Gate A seal. The model never handles a
challenger token. Honest caveat: the key is symmetric HMAC, so post-enrollment the
sidecar *could* mint — challenger-token mint separation is procedural, while
single-use / TTL / child-binding enforcement stays cryptographic and server-side.

## String sniffing is gone

There is no substring gate on model payloads (the old "ipython payload blocking" was
removed in R5). Enforcement is structural: the single-writer sidecar boundary, scope
policy, and per-identity verb ACLs at the RPC boundary. Denied calls stay denied;
retrying a denial with a rewritten path is escape behavior, not debugging.

## UDS authentication

The sidecar binds an owner-only Unix-domain socket (`0o600`) and requires the per-run bearer token on every request. Peer credentials must match the service owner. The socket is removed on shutdown.

## Network

Default deny. Allowed classes are model provider, approved RPC, and approved source fetch. Install and sealed evaluation run offline. Complete URL-closure pins every transitive dependency so install does not fetch URLs.

## Secrets

Raw secrets are never persisted. Support bundles redact credentials, private target source, full prompts, and exploit payload bodies. Knowledge ingestion rejects credential-shaped text and inseparable malicious instructions.
