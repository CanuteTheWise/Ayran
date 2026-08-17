# Security

## Trust model

Prime's kernel and workers are not a sandbox. Ayran enforces policy at the extension and sidecar, and treats OS isolation (WSL/container) as the containment boundary. Target-repository instruction files are never trusted configuration.

## Scope policy

Deny wins. Scope manifests name allowed roots, actions, hosts, tools, and write paths. Later config layers may only narrow policy unless a private `security_override` is confirmed for that run.

## Sandboxing notes

IPython payload blocking is best-effort and is not OS sandboxing. Destructive actions, broadcasts, submissions, and installers stay human-gated. Experimental adapters stay disabled unless an operator enables them.

## UDS authentication

The sidecar binds an owner-only Unix-domain socket (`0o600`) and requires the per-run bearer token on every request. Peer credentials must match the service owner. The socket is removed on shutdown.

## Network

Default deny. Allowed classes are model provider, approved RPC, and approved source fetch. Install and sealed evaluation run offline. Complete URL-closure pins every transitive dependency so install does not fetch URLs.

## Secrets

Raw secrets are never persisted. Support bundles redact credentials, private target source, full prompts, and exploit payload bodies. Knowledge ingestion rejects credential-shaped text and inseparable malicious instructions.
