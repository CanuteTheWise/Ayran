# Scope manifests

A scope manifest is **not** the target contract or protocol. It is the signed
policy envelope for one engagement: which relative paths Ayran may read or
write, which actions are allowed, which hosts/endpoints are permitted, and
when the engagement expires.

The Solidity, specs, and bounty notes live in the target tree (or in files
you keep next to it). The manifest only **points at** those trees via
`included_roots` / `excluded_roots` and lists allow/deny **rules**.

## Bind a manifest

```text
ayran start --manifest .ayran/scope.json --cwd .
prime-agent --ayran --ayran-manifest .ayran/scope.json
# inside Prime, after chatting:
/ayran:activate
/ayran:activate .ayran/scope.json
```

`start` prepares a new run and rewrites `run_id` in a copy written to
`~/.local/state/ayran/runs/<run_id>/scope.json`. The operator template can
keep a placeholder `run_id`; the bound copy is what the sidecar loads.

Until a manifest is bound, mapped audit actions fail closed with
`no scope manifest is loaded`. Context packs stay off until `/ayran:activate`.

## Authoring from bounty markdown or text

Do not paste the bounty write-up into the JSON. Translate the **boundaries**:

| In the bounty notes | In the manifest |
|---|---|
| In-scope contracts / folders | `included_roots` (relative paths, e.g. `src`, `target/src`) |
| Out of scope (mocks, deps, other products) | `excluded_roots` plus deny rules |
| Read vs compile vs test | `rules` with `action` + `resource` + `effect` |
| Contest end date | `valid_from` / `valid_until` (UTC) |
| No broadcasting / no keys | already forbidden in policy; keep `approval_rules` |
| Allowed RPC / APIs | `allowed_hosts`, `allowed_endpoints` |

Start from `fixtures/contracts/scope-manifest/valid/minimal.json`. Stretch
the validity window into the present, set `included_roots` to the in-scope
directories of **this** clone, and keep `deny_overrides` true. Schema:
`schemas/scope-manifest.schema.json`.

Identifiers (`scope_id`, `rule_id`, …) use the form
`prefix_` + 26 Crockford characters (see `ayran.graph.ids`). `run_id` is
replaced when you `start` / `scope.load`.
