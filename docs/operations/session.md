# Sessions and the Target Graph

One protocol folder has one Target Graph. That is the living map of the
audit: contracts, hypotheses, evidence, coverage, and dead ends.

A Prime chat is disposable. The graph is not.

## Start

In the protocol folder, with the Ayran venv on PATH and the Prime package
attached (`prime-agent package install <ayran-pkg> --local`):

```text
prime-agent --ayran
```

That starts the sidecar and **reattaches** this folder's Target Graph, or
creates one on first visit. Scope auto-binds from the workspace layout.
See [scope.md](scope.md).

Chat stays normal until you arm audit packs:

```text
/ayran:activate
```

`/quit` stops the sidecar. The graph remains. The next `prime-agent --ayran`
in the **same folder** continues that graph, including after a blank new
Prime session.

## Where it lives

`.ayran/engagement.json` in the project is the pin (`run_id` plus where the
journal lives). Gitignore it in the protocol repo, along with `.ayran/state/`.

Journals and SQLite stay on **ext4**:

- Clone on ext4 (for example `~/src/vault`): graph under `<cwd>/.ayran/state`.
- Clone on DrvFS (`/mnt/f/...`): graph under `~/.local/state/ayran/runs/<run_id>`.
  Only the pin sits in the project. Do not put journals on DrvFS.

This is not the Global Graph (package `knowledge/`) and not the Learning
Graph (`knowledge/learning`). Those are Ayran's library and promoted
lessons, not per-folder chat memory.

## Clean slate

Use this for a new contest or a changed source tree, not for “new chat”:

```text
ayran start --fresh --cwd .
# or
AYRAN_FRESH=1 prime-agent --ayran
```

A stale pin (file present, `stream.json` gone) also starts a new run.

## Check

Same `run_id` in `.ayran/engagement.json` across sessions. After
`/ayran:activate`, `/ayran:status` should not look empty if the previous
session had written hypotheses.

If it does look empty, see [troubleshooting.md](troubleshooting.md).
