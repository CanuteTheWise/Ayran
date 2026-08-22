"""Gate B executed-artifact engine (spec §5.6, S9.3, INV-5.6/5.7/5.10).

Booleans are not artifacts. Every executable obligation is decided from an
EXECUTED run: a command that really ran, an exit code, a duration, and a
sha256 over the CANONICALIZED assertion summary (test names + pass/fail +
key numeric results parsed from forge JSON — never raw stdout bytes).

Three runs decide pinning (S9.3 c2), all against the sandbox copy, never the
target repo:

``replay``         vulnerable revision; the PoC test itself must pass.
``patched``        candidate fix applied; the PoC must fail via PARSED
                  assertion failures (a bare non-zero exit or a compile error
                  is not accepted) while the feature tests stay green.
``revert_mutation`` the fix reverted; the pinning assertions must fail again
                  via parsed assertions (defect-mutation pinning).

Mechanical-before-judgment (INV-5.10 analog): :func:`execute_runs` completes
and hashes EVERY run before :func:`classify_runs` sees anything; decisions
consume only frozen, hashed results.

The runner is an injected seam. ``ScriptedRunner`` replays recorded fixture
results verbatim through the same parse/hash/classify pipeline so Windows CI
exercises every rule with zero forge dependency; ``ForgeRunner`` routes the
same three runs through the FoundryAdapter public surface for the owner's
WSL demo-of-done. No model calls, no network, no wallets, no keys.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ayran.graph.canonical import canonical_hash
from ayran.tools.adapters.foundry import copy_project, parse_forge_json

KRAIT_PASS = "[POC-PASS]"
KRAIT_UNPINNED = "[POC-UNPINNED]"

EXECUTABLE_OBLIGATIONS = (
    "clean_replay",
    "numerical_assertions",
    "negative_controls",
    "defect_removal",
    "fix_efficacy",
)
JUDGMENT_OBLIGATIONS = (
    "alternate_paths",
    "independent_skeptic",
    "feasibility_scope_severity",
    "deployment_identity",
)

# INV-5.7: feature-suite green requires mutated-contract coverage >= 80% where
# measurable; where coverage cannot be measured the stamp fails CLOSED to
# [POC-UNPINNED].
MIN_FEATURE_COVERAGE = 0.80
DEFAULT_MATCH_TEST = "test_exploit"

# The three S9.3 c2 runs, in execution order.
RUN_SLOTS = ("replay", "patched", "revert_mutation")

# Which run slot backs which executable obligation (numerical_assertions
# shares the replay run; negative_controls and defect_removal share the
# patched run — the flip and the control are the same execution judged twice).
OBLIGATION_TO_SLOT: dict[str, str] = {
    "clean_replay": "replay",
    "numerical_assertions": "replay",
    "negative_controls": "patched",
    "defect_removal": "patched",
    "fix_efficacy": "revert_mutation",
}
SLOT_TO_OBLIGATIONS: dict[str, tuple[str, ...]] = {
    slot: tuple(name for name in OBLIGATION_TO_SLOT if OBLIGATION_TO_SLOT[name] == slot)
    for slot in RUN_SLOTS
}

# A candidate patch may touch target source only. Any diff reaching
# test/harness/config paths forces needs_reformulation BEFORE execution.
_PATCH_FORBIDDEN_PARTS = frozenset(
    {"test", "tests", "script", "scripts", "harness", "harnesses", "config", "configs", "ci", "mocks"}
)
_PATCH_FORBIDDEN_NAMES = frozenset(
    {"foundry.toml", "remappings.txt", "makefile", "gas-snapshot.json", "coverage.json"}
)
_PATCH_FORBIDDEN_SUFFIXES = (".t.sol", ".toml", ".json", ".sh", ".js", ".ts", ".py")


@dataclass(frozen=True, slots=True)
class MechanicalRunResult:
    """One hashed, completed execution. Classification consumes only these."""

    slot: str
    command: str
    argv: tuple[str, ...]
    cwd: str
    exit_code: int
    duration_ms: int
    stdout_sha256: str
    canonical_summary: str
    compiled_ok: bool
    coverage: float | None
    passed_tests: tuple[str, ...]
    assertion_failures: tuple[str, ...]
    numeric_results: tuple[int, ...]

    def executed_block(self, artifact_ids: tuple[str, ...]) -> dict[str, Any]:
        """The v2 record's per-obligation block (schema §5.6 additions)."""

        return {
            "command": self.command,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "stdout_sha256": self.stdout_sha256,
            "duration_ms": self.duration_ms,
            "artifact_ids": list(artifact_ids),
            "assertion_failures": list(self.assertion_failures),
            "compiled_ok": self.compiled_ok,
            "coverage": self.coverage,
            "canonical_summary": self.canonical_summary,
        }


def canonical_summary_of(tests: list[Mapping[str, Any]]) -> str:
    """Normalized assertion summary: test names + pass/fail + key numeric results."""

    entries = [
        {
            "contract": str(item.get("contract") or ""),
            "name": str(item.get("name") or ""),
            "status": str(item.get("status") or ""),
            "gas": int(item["gas"]) if isinstance(item.get("gas"), int) else None,
            "reason": str(item["reason"])[:512] if item.get("reason") else None,
        }
        for item in tests
    ]
    entries.sort(key=lambda entry: (entry["contract"], entry["name"]))
    return json.dumps(entries, sort_keys=True, separators=(",", ":"))


def summary_hash(summary: str) -> str:
    return "sha256:" + hashlib.sha256(summary.encode("utf-8")).hexdigest()


def _coerce_bool(value: Any) -> bool:
    return value is True


def _block_compile_error(block: Mapping[str, Any]) -> bool:
    if _coerce_bool(block.get("compile_error")):
        return True
    return str(block.get("failure_type") or "") == "compile"


class MechanicalRunner(Protocol):
    """Executor seam: one ``execute`` per run slot, results always hashed here."""

    channel: str

    def execute(self, slot: str, block: Mapping[str, Any]) -> MechanicalRunResult: ...


def result_from_parsed(
    *,
    slot: str,
    command: str,
    argv: tuple[str, ...],
    cwd: str,
    exit_code: int,
    duration_ms: int,
    forge_payload: Mapping[str, Any] | None,
    coverage: float | None,
    compiled_ok: bool,
) -> MechanicalRunResult:
    """Shared parse/hash pipeline: both runners funnel through this one core."""

    tests: list[Mapping[str, Any]] = (
        [case.model_dump() for case in parse_forge_json(dict(forge_payload))]
        if forge_payload is not None
        else []
    )
    summary = canonical_summary_of(tests)
    passed = tuple(str(item["name"]) for item in tests if item.get("status") == "pass")
    failed = tuple(str(item["name"]) for item in tests if item.get("status") == "fail")
    numeric = tuple(
        int(item["gas"]) for item in tests if isinstance(item.get("gas"), int)
    )
    return MechanicalRunResult(
        slot=slot,
        command=str(command),
        argv=tuple(str(item) for item in argv),
        cwd=str(cwd),
        exit_code=int(exit_code),
        duration_ms=int(duration_ms),
        stdout_sha256=summary_hash(summary),
        canonical_summary=summary,
        compiled_ok=compiled_ok,
        coverage=float(coverage) if coverage is not None else None,
        passed_tests=passed,
        assertion_failures=failed,
        numeric_results=numeric,
    )


class ScriptedRunner:
    """Replay recorded fixture results verbatim through the shared pipeline.

    The block IS the recorded run (command/argv/cwd/exit_code/duration plus the
    forge JSON payload). Hashing, parsing, classification, stamping, and every
    verdict rule run for real — only process invocation is scripted.
    """

    channel = "scripted"

    def __init__(self) -> None:
        self.executions: list[str] = []

    def execute(self, slot: str, block: Mapping[str, Any]) -> MechanicalRunResult:
        self.executions.append(str(slot))
        payload = block.get("stdout_json")
        if not isinstance(payload, Mapping):
            raw = block.get("stdout")
            try:
                decoded = json.loads(str(raw)) if raw else None
            except json.JSONDecodeError:
                decoded = None
            payload = decoded if isinstance(decoded, Mapping) else None
        raw_exit: Any = block.get("exit_code")
        return result_from_parsed(
            slot=slot,
            command=str(block.get("command") or "forge test --json"),
            argv=tuple(str(item) for item in (block.get("argv") or [])),
            cwd=str(block.get("cwd") or "sandbox/reentrant-vault"),
            exit_code=int(raw_exit) if isinstance(raw_exit, (int, float, str)) else 1,
            duration_ms=int(block.get("duration_ms") or 0),
            forge_payload=payload,
            coverage=(
                float(block["coverage"])
                if isinstance(block.get("coverage"), (int, float))
                else None
            ),
            compiled_ok=not _block_compile_error(block),
        )


class ForgeRunner:
    """Route the three runs through the FoundryAdapter public surface.

    Copy-before-run sandbox (``copy_project`` — the target repo is NEVER
    mutated), candidate patches applied to the sandbox copy only, solc/foundry
    versions pinned into the replay workspace config, outcomes parsed with
    ``parse_forge_json``. Real forge exists only inside the owner's WSL
    environment; Windows CI never constructs this runner.
    """

    channel = "foundry"

    def __init__(
        self,
        *,
        project_root: Path,
        match_test: str = DEFAULT_MATCH_TEST,
        patch_files: tuple[Mapping[str, Any], ...] = (),
        mutation_files: tuple[Mapping[str, Any], ...] = (),
        pinned_versions: Mapping[str, str] | None = None,
        fork_block: int | None = None,
        seed: int | None = None,
    ) -> None:
        self.project_root = Path(project_root)
        self.match_test = str(match_test)
        self.patch_files = tuple(patch_files)
        self.mutation_files = tuple(mutation_files)
        self.pinned_versions = dict(pinned_versions or {})
        self.fork_block = fork_block
        self.seed = seed
        self.executions: list[str] = []

    def _apply_files(self, sandbox: Path, files: tuple[Mapping[str, Any], ...]) -> None:
        for spec in files:
            relative = Path(str(spec.get("path") or ""))
            target = sandbox / relative
            content = spec.get("content")
            if content is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(content), encoding="utf-8")

    def _pin_versions(self, sandbox: Path) -> None:
        if not self.pinned_versions:
            return
        pins = "\n".join(
            f"# ayran-replay-pin: {name}={version}"
            for name, version in sorted(self.pinned_versions.items())
        )
        config = sandbox / "foundry.toml"
        existing = config.read_text(encoding="utf-8") if config.is_file() else ""
        solc = self.pinned_versions.get("solc")
        body = existing
        if solc and "solc-version" not in body and "\nsolc =" not in body:
            body += f'\nsolc = "{solc}"\n'
        config.write_text(body + pins + "\n", encoding="utf-8")

    def execute(self, slot: str, block: Mapping[str, Any]) -> MechanicalRunResult:
        import asyncio

        from ayran.tools.doctor import default_environment
        from ayran.tools.registry import CapabilityRegistry
        from ayran.tools.runner import RunContext, policy_from_scope, run_capability
        from ayran.tools.types import ALIAS_FOUNDRY

        self.executions.append(str(slot))
        sandbox = copy_project(self.project_root)
        if slot == "patched":
            self._apply_files(sandbox, self.patch_files)
        elif slot == "revert_mutation":
            self._apply_files(sandbox, self.mutation_files)
        self._pin_versions(sandbox)
        registry = CapabilityRegistry(environment=default_environment())
        payload: dict[str, Any] = {
            "project_root": str(sandbox),
            "match_test": self.match_test,
            "json_output": True,
            "fork_block": self.fork_block,
            "seed": self.seed,
        }
        identity = {
            "target_id": "tgt_01J00000000000000000000001",
            "source_tree_hash": canonical_hash({"slot": slot}),
            "scope_id": "scp_01J00000000000000000000001",
        }
        outcome = asyncio.run(
            run_capability(
                registry,
                ALIAS_FOUNDRY,
                payload,
                policy=policy_from_scope(
                    manifest=registry.manifests[registry.resolve_id(ALIAS_FOUNDRY)]
                ),
                context=RunContext(run_id="gate-b-mechanical", target_identity=identity),
                require_available=True,
            )
        )
        tool_run = outcome.get("tool_run") if isinstance(outcome, dict) else None
        tool_run = tool_run if isinstance(tool_run, Mapping) else {}
        stdout_text = str(tool_run.get("stdout") or "")
        try:
            decoded = json.loads(stdout_text) if stdout_text.strip() else None
        except json.JSONDecodeError:
            decoded = None
        forge_payload = decoded if isinstance(decoded, Mapping) else None
        argv = tuple(str(item) for item in (block.get("argv") or [])) or (
            "forge",
            "test",
            "--match-test",
            self.match_test,
            "--json",
        )
        raw_exit: Any = tool_run.get("exit_code")
        return result_from_parsed(
            slot=slot,
            command=" ".join(argv[:1]) or "forge",
            argv=argv,
            cwd=str(sandbox),
            exit_code=int(raw_exit) if isinstance(raw_exit, (int, float, str)) else 1,
            duration_ms=int(tool_run.get("duration_ms") or 0),
            forge_payload=forge_payload,
            coverage=None,
            compiled_ok=str(tool_run.get("failure_type") or "") != "compile",
        )


# --- parse-time strictness (S9.3 c1, INV-5.6) --------------------------------


def detect_forgery(payload: Mapping[str, Any]) -> list[str]:
    """Executable obligations claiming a bare pass with zero execution.

    Returns the offending obligation names: a block that asserts
    ``passed: true`` (the exact honor-system abuse of gate_b.py:26-47) while
    lacking the executed fields ``command`` + ``exit_code``.
    """

    forged: list[str] = []
    for name in EXECUTABLE_OBLIGATIONS:
        block = payload.get(name)
        if not isinstance(block, Mapping):
            continue
        if block.get("passed") is True and ("command" not in block or "exit_code" not in block):
            forged.append(name)
    return forged


def patch_scope_violations(payload: Mapping[str, Any]) -> list[str]:
    """Mechanical pre-check BEFORE any execution (§5.6 defect_removal row)."""

    pinning_requested = any(
        isinstance(payload.get(name), Mapping)
        for name in ("negative_controls", "defect_removal", "fix_efficacy")
    )
    patch = payload.get("patch")
    if not pinning_requested:
        return []
    if not isinstance(patch, Mapping):
        return ["pinning runs require the candidate patch (sandbox-copy only)"]
    files = patch.get("files")
    if not isinstance(files, list) or not files:
        return ["candidate patch must list at least one file"]
    violations: list[str] = []
    allowed = {
        str(item) for item in (payload.get("allowed_source_files") or []) if str(item)
    }
    for spec in files:
        if not isinstance(spec, Mapping):
            violations.append("patch file entries must be objects")
            continue
        raw_path = str(spec.get("path") or "")
        normalized = raw_path.replace("\\", "/").strip("/")
        lowered = normalized.lower()
        parts = [part for part in lowered.split("/") if part]
        name = parts[-1] if parts else ""
        if not lowered:
            violations.append("patch file path is empty")
            continue
        if any(part in _PATCH_FORBIDDEN_PARTS for part in parts[:-1]) or name in _PATCH_FORBIDDEN_NAMES:
            violations.append(f"patch touches test/harness/config path: {raw_path}")
            continue
        if lowered.endswith(_PATCH_FORBIDDEN_SUFFIXES):
            violations.append(f"patch touches a non-source file: {raw_path}")
            continue
        if allowed and normalized not in allowed and lowered not in {item.lower() for item in allowed}:
            violations.append(f"patch file outside the claim's source spans: {raw_path}")
    return violations


# --- mechanical-before-judgment (INV-5.10 analog) -----------------------------


@dataclass(frozen=True, slots=True)
class ExecutedRuns:
    """All runs completed and hashed BEFORE any classification runs."""

    results: dict[str, MechanicalRunResult]
    order: tuple[str, ...]


def execute_runs(
    payload: Mapping[str, Any],
    runner: MechanicalRunner,
) -> ExecutedRuns:
    """Execute every requested run slot in one pass; hash before returning."""

    def _has_executed_block(name: str) -> bool:
        block = payload.get(name)
        return isinstance(block, Mapping) and "command" in block and "exit_code" in block

    results: dict[str, MechanicalRunResult] = {}
    requested: list[str] = []
    for slot in RUN_SLOTS:
        names = [name for name in SLOT_TO_OBLIGATIONS[slot] if _has_executed_block(name)]
        if not names:
            continue
        requested.append(slot)
        first = payload.get(names[0])
        block = first if isinstance(first, Mapping) else {}
        results[slot] = runner.execute(slot, block)
    return ExecutedRuns(results=results, order=tuple(requested))


def _matched_test_status(run: MechanicalRunResult, match_test: str) -> str:
    """pass/fail/skip/missing for the matched PoC test, parsed from forge JSON."""

    if match_test in run.passed_tests:
        return "pass"
    if match_test in run.assertion_failures:
        return "fail"
    return "missing"


def _feature_tests_green(
    run: MechanicalRunResult, match_test: str
) -> tuple[bool, str]:
    """Feature-suite green: every non-matched test passed (forge exit 0 for the
    feature subset) AND mutated-contract coverage >= 80% where measurable
    (INV-5.7). Unmeasurable coverage fails CLOSED."""

    feature_failures = [name for name in run.assertion_failures if name != match_test]
    if feature_failures:
        return False, "feature tests failed: " + ",".join(feature_failures[:8])
    if run.coverage is None:
        return False, "coverage not measurable; feature green fails closed (INV-5.7)"
    if run.coverage < MIN_FEATURE_COVERAGE:
        return False, f"mutated-contract coverage {run.coverage:.2f} < {MIN_FEATURE_COVERAGE:.2f}"
    return True, "feature suite green"


@dataclass(frozen=True, slots=True)
class Classification:
    verdict: str
    krait_stamp: str | None
    pinned: bool
    replay_reproduced: bool
    obligations: dict[str, dict[str, Any]] = field(default_factory=dict)
    executed_blocks: dict[str, dict[str, Any]] = field(default_factory=dict)
    reasons: tuple[str, ...] = ()


def classify_runs(
    payload: Mapping[str, Any],
    runs: ExecutedRuns,
    *,
    match_test: str = DEFAULT_MATCH_TEST,
    expected_replay_hash: str | None = None,
) -> Classification:
    """Pure classification over hashed records only (never over caller claims)."""

    obligations: dict[str, dict[str, Any]] = {}
    executed_blocks: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []

    replay = runs.results.get("replay")
    patched = runs.results.get("patched")
    reverted = runs.results.get("revert_mutation")

    # --- clean_replay -----------------------------------------------------
    if replay is None:
        obligations["clean_replay"] = {
            "passed": False,
            "detail": "unspecified: no executed replay run supplied",
            "unspecified": True,
        }
    else:
        artifact_ids: tuple[str, ...] = ()
        replay_block = payload.get("clean_replay")
        if isinstance(replay_block, Mapping):
            artifact_ids = tuple(
                str(item) for item in (replay_block.get("artifact_ids") or []) if str(item)
            )
        executed_blocks["clean_replay"] = replay.executed_block(artifact_ids)
        status = _matched_test_status(replay, match_test)
        mismatch = bool(
            expected_replay_hash
            and replay.stdout_sha256 != expected_replay_hash
        )
        passed = replay.exit_code == 0 and status == "pass" and not mismatch
        obligations["clean_replay"] = {
            "passed": passed,
            "detail": (
                "replay hash mismatch versus original ToolRun"
                if mismatch
                else f"exit {replay.exit_code}, matched {match_test}: {status}, "
                f"canonical sha256 {replay.stdout_sha256}"
            ),
            "mismatch": mismatch,
            "stdout_sha256": replay.stdout_sha256,
        }
        if mismatch:
            reasons.append("clean_replay: replay hash mismatch")
        elif not passed:
            reasons.append("clean_replay: PoC did not reproduce on the vulnerable revision")

    # --- numerical_assertions (same replay run; numbers parsed from JSON) ---
    if replay is not None and isinstance(payload.get("numerical_assertions"), Mapping):
        numeric_ok = replay.exit_code == 0 and bool(replay.numeric_results)
        obligations["numerical_assertions"] = {
            "passed": numeric_ok,
            "detail": (
                f"{len(replay.numeric_results)} numeric results parsed from forge JSON"
                if numeric_ok
                else "no numeric assertion results parsed from the replay run"
            ),
            "stdout_sha256": replay.stdout_sha256,
        }
        executed_blocks["numerical_assertions"] = replay.executed_block(())
        if not numeric_ok:
            reasons.append("numerical_assertions: no parsed numeric results")
    else:
        obligations["numerical_assertions"] = {
            "passed": False,
            "detail": "unspecified: no executed run supplied",
            "unspecified": True,
        }

    # --- negative_controls (patched run must fail VIA PARSED ASSERTIONS) ---
    if patched is None:
        obligations["negative_controls"] = {
            "passed": False,
            "detail": "unspecified: no executed control run supplied",
            "unspecified": True,
        }
    else:
        executed_blocks["negative_controls"] = patched.executed_block(())
        control_failed_via_assertions = patched.compiled_ok and bool(patched.assertion_failures)
        wrong_reason = patched.exit_code != 0 and not patched.assertion_failures
        exploit_persists = patched.exit_code == 0
        obligations["negative_controls"] = {
            "passed": control_failed_via_assertions and not exploit_persists,
            "detail": (
                "control failed via parsed assertion failures: "
                + ",".join(patched.assertion_failures[:8])
                if control_failed_via_assertions
                else "exploit persists under the control revision"
                if exploit_persists
                else "control failed for the wrong reason (no parsed assertion failure)"
                if wrong_reason
                else "control run did not produce a parseable assertion outcome"
            ),
            "wrong_reason": wrong_reason or not patched.compiled_ok,
            "exploit_persists": exploit_persists,
            "stdout_sha256": patched.stdout_sha256,
        }
        if exploit_persists:
            reasons.append("negative_controls: exploit persists under the control revision")
        elif not control_failed_via_assertions:
            reasons.append("negative_controls: no parsed assertion failure (wrong reason)")

    # --- defect_removal (the flip must be an ASSERTION failure, never a
    #     compilation failure — INV-5.7) ------------------------------------
    if patched is None:
        obligations["defect_removal"] = {
            "passed": False,
            "detail": "unspecified: no executed patch run supplied",
            "unspecified": True,
        }
    else:
        executed_blocks["defect_removal"] = patched.executed_block(())
        flip = _matched_test_status(patched, match_test) == "fail"
        flip_via_assertion = flip and match_test in patched.assertion_failures
        obligations["defect_removal"] = {
            "passed": flip_via_assertion and patched.compiled_ok,
            "detail": (
                "exploit flipped via parsed assertion failure"
                if flip_via_assertion and patched.compiled_ok
                else "flip caused by compilation failure"
                if flip and not patched.compiled_ok
                else "exploit outcome did not flip under the candidate fix"
                if not flip
                else "flip not attributable to a parsed assertion failure"
            ),
            "compile_flip": flip and not patched.compiled_ok,
            "stdout_sha256": patched.stdout_sha256,
        }
        if not (flip_via_assertion and patched.compiled_ok):
            reasons.append("defect_removal: " + str(obligations["defect_removal"]["detail"]))

    # --- fix_efficacy (feature green on the patched run + pinning reproduced
    #     on the reverted run via parsed assertions) -------------------------
    if reverted is None:
        obligations["fix_efficacy"] = {
            "passed": False,
            "detail": "unspecified: no executed revert-mutation run supplied",
            "unspecified": True,
        }
    else:
        executed_blocks["fix_efficacy"] = reverted.executed_block(())
    feature_ok, feature_detail = (
        _feature_tests_green(patched, match_test) if patched is not None else (False, "no patched run")
    )
    pinning_ok = (
        reverted is not None
        and reverted.compiled_ok
        and bool(reverted.assertion_failures)
    )
    obligations["fix_efficacy"] = {
        "passed": bool(feature_ok and pinning_ok),
        "detail": (
            f"feature green ({feature_detail}); defect-mutation pinning reproduced via "
            "parsed assertions" if feature_ok and pinning_ok else f"{feature_detail}"
            if not feature_ok else "revert-mutation did not fail via parsed assertions"
        ),
        "feature_disabled": not feature_ok,
        "stdout_sha256": reverted.stdout_sha256 if reverted is not None else "",
    }
    if not pinning_ok:
        reasons.append("fix_efficacy: defect-mutation pinning not reproduced")

    replay_ok = bool(obligations.get("clean_replay", {}).get("passed"))
    mismatch = bool(obligations.get("clean_replay", {}).get("mismatch"))
    if mismatch:
        verdict = "falsified"
        return Classification("falsified", None, False, replay_ok, obligations, executed_blocks, ("replay hash mismatch",))
    blocking = [
        name
        for name in ("clean_replay", "numerical_assertions", "negative_controls", "defect_removal")
        if not obligations.get(name, {}).get("passed")
    ]
    if blocking or not obligations.get("fix_efficacy", {}).get("passed"):
        verdict = "needs_reformulation"
        stamp = KRAIT_UNPINNED if replay_ok else None
        return Classification(
            verdict,
            stamp,
            False,
            replay_ok,
            obligations,
            executed_blocks,
            tuple(reasons) or ("pinning incomplete",),
        )
    return Classification(
        "defect_pinned",
        KRAIT_PASS,
        True,
        True,
        obligations,
        executed_blocks,
        tuple(reasons),
    )


def artifact_hashes(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    """Recomputable sha256 list over PoC source, trace output, mutated source."""

    artifacts = payload.get("artifacts")
    entries: list[dict[str, str]] = []
    if isinstance(artifacts, Mapping):
        for kind in sorted(artifacts):
            raw = artifacts[kind]
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if not isinstance(raw, (bytes, bytearray)):
                continue
            entries.append(
                {
                    "kind": str(kind),
                    "sha256": "sha256:" + hashlib.sha256(bytes(raw)).hexdigest(),
                    "bytes": str(len(raw)),
                }
            )
    return entries
