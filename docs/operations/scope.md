# Scope manifests

A scope manifest is **sidecar policy**, not the target protocol.

`--ayran` **auto-binds** it from the workspace layout. You do not fill JSON.
The **model does not author scope**.

The **Target Graph** is also pinned to this folder. See [session.md](session.md).
`.ayran/engagement.json` points at the durable run. A new blank
`prime-agent --ayran` in the same project **reopens that graph**. Journals
stay on ext4: `<cwd>/.ayran/state` when the project is ext4, otherwise
`~/.local/state/ayran/runs/<run_id>` with only the pin in the project
(DrvFS clones). Gitignore `.ayran/state/` and usually `engagement.json` in
the protocol repo.

Clean slate: `ayran start --fresh` or `AYRAN_FRESH=1`.

## One command

```text
prime-agent --ayran
# later, when you want audit packs:
/ayran:activate
```

Detection prefers `src`, `contracts`, or `target/src`. Notes, bounty `.md` /
`.txt`, compiler `out/`, `lib/`, reports, and `.prime` are not treated as
the protocol. If Solidity files sit at the repo root, scope is `.` with
those junk directories **excluded**.

Foundry, Slither, and solc are discovered on the WSL **PATH**. They should
stay in your normal WSL install (for example under `/usr/local` or
`~/.foundry`). They must not live inside the audit folder and are never
copied or upgraded by Ayran.

Human-gated: spend, sign, broadcast, submit, expand scope. No RPC unless
you add hosts.

## Overrides (optional)

```text
ayran start --roots src,contracts --cwd .
prime-agent --ayran --ayran-manifest .ayran/scope.json
```
