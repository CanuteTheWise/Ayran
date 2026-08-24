"""Ayran operator CLI: doctor/status/diagnose/stop/recover/service/start.

These commands are deterministic and bound to one run.  ``start`` prepares a
session and binds a signed scope manifest; ``doctor`` checks compatibility
and resource facts; ``status`` reconstructs run state; ``diagnose`` exports a
redacted support bundle; ``stop`` applies process-tree termination;
``recover`` replays graph state; ``service`` starts the local JSON-RPC boundary.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _expand(value: str) -> Path:
    return Path(value).expanduser().resolve(strict=False)


def _load_for_args(arguments: argparse.Namespace) -> Any:
    from ayran.config.loader import load_config, parse_cli_override

    cli_overrides = parse_cli_override(getattr(arguments, "set", []) or [])
    env = {key: value for key, value in os.environ.items()}
    return load_config(
        global_path=_expand(getattr(arguments, "global_config", "") or "~/.config/ayran/config.toml"),
        project_path=_expand(getattr(arguments, "project_config", "") or "") if getattr(arguments, "project_config", "") else None,
        engagement_path=_expand(getattr(arguments, "engagement", "") or "") if getattr(arguments, "engagement", "") else None,
        env=env,
        cli_overrides=cli_overrides,
    )


def _add_run(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run", required=True, help="the run identifier to act on")
    parser.add_argument("--state-root", help="override the resolved state root")


def _add_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--global-config", default="~/.config/ayran/config.toml")
    parser.add_argument("--project-config")
    parser.add_argument("--engagement")
    parser.add_argument("--set", action="append", default=[])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ayran", description="Ayran operator tools")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check compatibility, locks, resources, graph integrity")
    _add_config(doctor)
    doctor.add_argument(
        "--observed-root",
        type=Path,
        default=Path("/"),
        help="the WSL ext4 root used to probe kernel/filesystem facts",
    )

    status = sub.add_parser("status", help="reconstruct run state")
    _add_config(status)
    _add_run(status)

    diagnose = sub.add_parser("diagnose", help="export a redacted support bundle")
    _add_config(diagnose)
    _add_run(diagnose)
    diagnose.add_argument("--bundle", type=Path, required=True)

    stop = sub.add_parser("stop", help="stop one run through the process supervisor")
    _add_config(stop)
    _add_run(stop)
    stop.add_argument("--graceful", action="store_true")
    stop.add_argument("--force-after", type=int, default=None)

    recover = sub.add_parser("recover", help="replay the journal and reconcile process state")
    _add_config(recover)
    _add_run(recover)

    service = sub.add_parser("service", help="run the local JSON-RPC ayrand service")
    _add_config(service)
    _add_run(service)
    service.add_argument("--socket", type=Path, default=None)
    service.add_argument("--token-file", type=Path, default=None)

    start = sub.add_parser("start", help="prepare a run and auto-bind scope")
    _add_config(start)
    start.add_argument("--manifest", type=Path, default=None, help="path to a full scope-manifest JSON")
    start.add_argument(
        "--roots",
        default=None,
        help="comma-separated relative in-scope paths; generates the policy envelope",
    )
    start.add_argument("--cwd", type=Path, default=None)
    start.add_argument("--state-root", type=Path, default=None)
    start.add_argument(
        "--fresh",
        action="store_true",
        help="ignore the project engagement pin and start a new Target Graph",
    )
    start.add_argument(
        "--allow-unsafe-filesystem", action="store_true", help=argparse.SUPPRESS
    )

    session = sub.add_parser("session", help="prepare a Prime-session sidecar run")
    session_sub = session.add_subparsers(dest="session_command", required=True)
    session_prepare = session_sub.add_parser(
        "prepare", help="create stream, token, and socket paths for one session"
    )
    _add_config(session_prepare)
    session_prepare.add_argument("--cwd", type=Path, default=None)
    session_prepare.add_argument("--state-root", type=Path, default=None)
    session_prepare.add_argument("--manifest", type=Path, default=None)
    session_prepare.add_argument("--roots", default=None)
    session_prepare.add_argument(
        "--fresh",
        action="store_true",
        help="ignore the project engagement pin and start a new Target Graph",
    )
    session_prepare.add_argument(
        "--allow-unsafe-filesystem", action="store_true", help=argparse.SUPPRESS
    )

    tools = sub.add_parser("tools", help="capability registry, detection, and adapter invocation")
    tools_sub = tools.add_subparsers(dest="tools_command", required=True)
    tools_list = tools_sub.add_parser("list", help="list capabilities and detection status")
    _add_config(tools_list)
    tools_detect = tools_sub.add_parser("detect", help="detect one capability")
    _add_config(tools_detect)
    tools_detect.add_argument("capability_id")
    tools_health = tools_sub.add_parser("health", help="health-check one capability")
    _add_config(tools_health)
    tools_health.add_argument("capability_id")
    tools_run = tools_sub.add_parser("run", help="invoke one capability with JSON input")
    _add_config(tools_run)
    tools_run.add_argument("capability_id")
    tools_run.add_argument("--input", required=True, help="JSON request payload")
    tools_run.add_argument("--run-id", dest="tool_run_id", help="optional run id when recording a ToolRun")
    tools_run.add_argument("--retries-from", dest="retries_from")
    tools_doctor_cmd = tools_sub.add_parser("doctor", help="comprehensive tool diagnostics")
    _add_config(tools_doctor_cmd)

    def _graph_opts(command: argparse.ArgumentParser) -> None:
        command.add_argument("--graph-root", type=Path, required=True)
        command.add_argument("--stream", type=Path, required=True)
        command.add_argument("--allow-unsafe-filesystem", action="store_true", help=argparse.SUPPRESS)
        command.add_argument("--cluster")

    context = sub.add_parser("context", help="compile bounded context packs")
    context_sub = context.add_subparsers(dest="context_command", required=True)
    context_compile = context_sub.add_parser("compile", help="compile and print a context pack")
    _add_config(context_compile)
    _graph_opts(context_compile)
    context_compile.add_argument("--budget", type=int, default=4000)

    router = sub.add_parser("router", help="six-origin router")
    router_sub = router.add_subparsers(dest="router_command", required=True)
    for name, help_text in (
        ("status", "show router state"),
        ("step", "advance the router one cycle"),
        ("history", "show recent router decisions"),
    ):
        item = router_sub.add_parser(name, help=help_text)
        _add_config(item)
        _graph_opts(item)
        if name == "history":
            item.add_argument("--limit", type=int, default=20)

    coverage = sub.add_parser("coverage", help="coverage grid")
    coverage_sub = coverage.add_subparsers(dest="coverage_command", required=True)
    coverage_summary = coverage_sub.add_parser("summary", help="show coverage grid summary")
    _add_config(coverage_summary)
    _graph_opts(coverage_summary)
    coverage_cell = coverage_sub.add_parser("cell", help="show one cell")
    _add_config(coverage_cell)
    _graph_opts(coverage_cell)
    coverage_cell.add_argument("cell_id")

    maps = sub.add_parser("maps", help="print a map type")
    _add_config(maps)
    _graph_opts(maps)
    maps.add_argument(
        "map_type",
        choices=["attack_surface", "control_flow", "data_flow", "value_flow", "authority", "temporal"],
    )
    maps.add_argument("--source", type=Path)
    maps.add_argument("--slither-json", type=Path)

    evidence = sub.add_parser("evidence", help="hypothesis state transitions")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_transition = evidence_sub.add_parser("transition", help="request a legal state transition")
    _add_config(evidence_transition)
    _graph_opts(evidence_transition)
    evidence_transition.add_argument("hypothesis_id")
    evidence_transition.add_argument("--to", required=True)
    evidence_transition.add_argument("--evidence", default="{}")
    evidence_transition.add_argument("--actor")
    evidence_transition.add_argument("--cause")

    gate_a = sub.add_parser("gate-a", help="run Gate A on a supported hypothesis")
    _add_config(gate_a)
    _graph_opts(gate_a)
    gate_a.add_argument("hypothesis_id")
    gate_a.add_argument("--analysis", default="{}")
    gate_a.add_argument("--reconcile", action="store_true")

    gate_b = sub.add_parser("gate-b", help="run Gate B on an observed hypothesis")
    _add_config(gate_b)
    _graph_opts(gate_b)
    gate_b.add_argument("hypothesis_id")
    gate_b.add_argument("--obligations", default="{}")
    gate_b.add_argument("--poc-id")
    gate_b.add_argument("--profile", default="executable")

    dedup = sub.add_parser("dedup", help="deduplication")
    dedup_sub = dedup.add_subparsers(dest="dedup_command", required=True)
    dedup_check = dedup_sub.add_parser("check", help="check duplicates without deletion")
    _add_config(dedup_check)
    _graph_opts(dedup_check)
    dedup_check.add_argument("hypothesis_id")

    poc = sub.add_parser("poc", help="governed PoC workflow")
    poc_sub = poc.add_subparsers(dest="poc_command", required=True)
    poc_run = poc_sub.add_parser("run", help="execute or record a PoC")
    _add_config(poc_run)
    _graph_opts(poc_run)
    poc_run.add_argument("hypothesis_id")
    poc_run.add_argument("--experiment", default="{}")
    poc_run.add_argument("--recorded")
    poc_run.add_argument("--execute", action="store_true")
    poc_replay = poc_sub.add_parser("replay", help="clean-replay a PoC")
    _add_config(poc_replay)
    _graph_opts(poc_replay)
    poc_replay.add_argument("poc_id")
    poc_replay.add_argument("--recorded")

    finding = sub.add_parser("finding", help="canonical findings")
    finding_sub = finding.add_subparsers(dest="finding_command", required=True)
    finding_build = finding_sub.add_parser("build", help="build a Finding from a hypothesis")
    _add_config(finding_build)
    _graph_opts(finding_build)
    finding_build.add_argument("hypothesis_id")

    report = sub.add_parser("report", help="render and lint local reports")
    report_sub = report.add_subparsers(dest="report_command", required=True)
    report_render = report_sub.add_parser("render", help="render a finding")
    _add_config(report_render)
    _graph_opts(report_render)
    report_render.add_argument("finding_id")
    report_render.add_argument("--format", dest="report_format", choices=["markdown", "json"], default="markdown")
    report_lint = report_sub.add_parser("lint", help="lint a rendered finding")
    _add_config(report_lint)
    _graph_opts(report_lint)
    report_lint.add_argument("finding_id")

    knowledge = sub.add_parser("knowledge", help="Global Graph corpus registry and releases")
    knowledge_sub = knowledge.add_subparsers(dest="knowledge_command", required=True)
    knowledge_list = knowledge_sub.add_parser("list-sources", help="list registry entries")
    _add_config(knowledge_list)
    knowledge_list.add_argument("--knowledge-root", type=Path)
    knowledge_list.add_argument("--phase")
    knowledge_ingest = knowledge_sub.add_parser("ingest", help="ingest one approved source snapshot")
    _add_config(knowledge_ingest)
    knowledge_ingest.add_argument("source_id")
    knowledge_ingest.add_argument("--knowledge-root", type=Path)
    knowledge_ingest.add_argument("--graph-root", type=Path)
    knowledge_ingest.add_argument("--stream", type=Path)
    knowledge_ingest.add_argument("--allow-unsafe-filesystem", action="store_true", help=argparse.SUPPRESS)
    knowledge_release = knowledge_sub.add_parser("release", help="publish an immutable corpus release")
    _add_config(knowledge_release)
    knowledge_release.add_argument("--version", required=True)
    knowledge_release.add_argument("--knowledge-root", type=Path)
    knowledge_release.add_argument("--graph-root", type=Path)
    knowledge_release.add_argument("--stream", type=Path)
    knowledge_release.add_argument("--allow-unsafe-filesystem", action="store_true", help=argparse.SUPPRESS)
    knowledge_status_cmd = knowledge_sub.add_parser("status", help="show current corpus release")
    _add_config(knowledge_status_cmd)
    knowledge_status_cmd.add_argument("--knowledge-root", type=Path)
    knowledge_query = knowledge_sub.add_parser("query", help="query normalized corpus records")
    _add_config(knowledge_query)
    knowledge_query.add_argument("--knowledge-root", type=Path)
    knowledge_query.add_argument("--type", dest="record_type", required=True)
    knowledge_query.add_argument("--filter", dest="query_filter", default="{}")
    knowledge_tombstone = knowledge_sub.add_parser("tombstone", help="tombstone a source and republish")
    _add_config(knowledge_tombstone)
    knowledge_tombstone.add_argument("source_id")
    knowledge_tombstone.add_argument("--reason", required=True)
    knowledge_tombstone.add_argument("--knowledge-root", type=Path)
    knowledge_tombstone.add_argument("--version", dest="republish_version")
    knowledge_tombstone.add_argument("--graph-root", type=Path)
    knowledge_tombstone.add_argument("--stream", type=Path)
    knowledge_tombstone.add_argument("--allow-unsafe-filesystem", action="store_true", help=argparse.SUPPRESS)
    knowledge_audit = knowledge_sub.add_parser(
        "audit-registry", help="audit registry entries for fabricated ids and incomplete provenance"
    )
    _add_config(knowledge_audit)
    knowledge_audit.add_argument("--knowledge-root", type=Path)
    knowledge_enrich = knowledge_sub.add_parser(
        "enrich-postmortems",
        help="operator-sanctioned network enrichment: follow linked post-mortem write-ups for staged incident cards",
    )
    _add_config(knowledge_enrich)
    knowledge_enrich.add_argument("--source-id", default="defihacklabs")
    knowledge_enrich.add_argument("--limit", type=int)
    knowledge_enrich.add_argument("--delay", type=float)
    knowledge_enrich.add_argument("--timeout", type=int)
    knowledge_enrich.add_argument("--dry-run", action="store_true")
    knowledge_ingest_dhl = knowledge_sub.add_parser(
        "ingest-defihacklabs", help="offline ingest of a pinned DeFiHackLabs checkout"
    )
    _add_config(knowledge_ingest_dhl)
    knowledge_ingest_dhl.add_argument("root", type=Path)
    knowledge_ingest_dhl.add_argument("--commit", required=True)
    knowledge_ingest_dhl.add_argument("--archive-sha256", required=True)
    knowledge_ingest_dhl.add_argument("--limit", type=int)
    knowledge_ingest_dhl.add_argument("--knowledge-root", type=Path)
    knowledge_ingest_krait = knowledge_sub.add_parser(
        "ingest-krait", help="deep-ingest a pinned Krait check corpus"
    )
    _add_config(knowledge_ingest_krait)
    knowledge_ingest_krait.add_argument("root", type=Path)
    knowledge_ingest_krait.add_argument("--commit", required=True)
    knowledge_ingest_krait.add_argument("--archive-sha256", required=True)
    knowledge_ingest_krait.add_argument("--knowledge-root", type=Path)

    learning = sub.add_parser("learning", help="Learning Graph capture, review, promotion, and rollback")
    learning_sub = learning.add_subparsers(dest="learning_command", required=True)

    def _learning_graph(command: argparse.ArgumentParser) -> None:
        command.add_argument("--graph-root", type=Path)
        command.add_argument("--stream", type=Path)
        command.add_argument("--allow-unsafe-filesystem", action="store_true", help=argparse.SUPPRESS)
        command.add_argument("--learning-root", type=Path)

    learning_capture = learning_sub.add_parser("capture", help="capture outcomes from a completed run")
    _add_config(learning_capture)
    _add_run(learning_capture)
    _learning_graph(learning_capture)
    learning_capture.add_argument("--hypothesis")
    learning_capture.add_argument("--outcome-type", default="adjudicated")
    learning_queue = learning_sub.add_parser("queue", help="show quarantine queue")
    _add_config(learning_queue)
    _learning_graph(learning_queue)
    learning_review = learning_sub.add_parser("review", help="submit a review verdict")
    _add_config(learning_review)
    _learning_graph(learning_review)
    learning_review.add_argument("candidate_id")
    learning_review.add_argument("--verdict", required=True, choices=["approve", "reject", "needs-revision"])
    learning_review.add_argument("--reviewer-id", required=True)
    learning_review.add_argument("--reviewer-type", default="human", choices=["human", "independent_agent"])
    learning_review.add_argument("--notes", default="")
    learning_generalize = learning_sub.add_parser("generalize", help="generalize an approved outcome")
    _add_config(learning_generalize)
    _learning_graph(learning_generalize)
    learning_generalize.add_argument("outcome_id")
    learning_generalize.add_argument("--seed", default="0")
    learning_fixtures = learning_sub.add_parser("test-fixtures", help="generate positive and hard-negative fixtures")
    _add_config(learning_fixtures)
    _learning_graph(learning_fixtures)
    learning_fixtures.add_argument("candidate_id")
    learning_promote = learning_sub.add_parser("promote", help="run the full promotion pipeline")
    _add_config(learning_promote)
    _learning_graph(learning_promote)
    learning_promote.add_argument("candidate_id")
    learning_rollback = learning_sub.add_parser("rollback", help="rollback a learning release pointer")
    _add_config(learning_rollback)
    _learning_graph(learning_rollback)
    learning_rollback.add_argument("release_id")
    learning_status_cmd = learning_sub.add_parser("status", help="show learning graph status")
    _add_config(learning_status_cmd)
    _learning_graph(learning_status_cmd)
    learning_routing = learning_sub.add_parser("routing-policy", help="show a routing policy")
    _add_config(learning_routing)
    _learning_graph(learning_routing)
    learning_routing.add_argument("policy_id", nargs="?")

    eval_cmd = sub.add_parser("eval", help="sealed A0-A7 evaluation")
    eval_sub = eval_cmd.add_subparsers(dest="eval_command", required=True)
    eval_run = eval_sub.add_parser("run", help="run a sealed evaluation arm or the full sequence")
    _add_config(eval_run)
    eval_run.add_argument("--arm", help="A0..A7; omit to run the full sequence")
    eval_run.add_argument("--seed", type=int)
    eval_run.add_argument("--results-root", type=Path)
    eval_run.add_argument("--evals", type=Path)
    eval_run.add_argument("--knowledge-root", type=Path)
    eval_run.add_argument("--learning-root", type=Path)
    eval_run.add_argument("--live", action="store_true", help="run the live harness (scripted transport in CI)")
    eval_run.add_argument("--preregistration", type=Path)
    eval_run.add_argument("--targets", type=Path)
    eval_prereg = eval_sub.add_parser("preregister", help="journal an owner-signed live-eval preregistration")
    _add_config(eval_prereg)
    eval_prereg.add_argument("--manifest", type=Path, required=True)
    eval_prereg.add_argument("--results-root", type=Path)
    eval_pause = eval_sub.add_parser("pause", help="set the eval kill switch (honored between launches)")
    _add_config(eval_pause)
    eval_pause.add_argument("--results-root", type=Path, required=True)
    eval_adj = eval_sub.add_parser("adjudicate", help="adjudicate a completed evaluation session")
    _add_config(eval_adj)
    eval_adj.add_argument("--session", required=True)
    eval_adj.add_argument("--results-root", type=Path)
    eval_results = eval_sub.add_parser("results", help="show an immutable results manifest")
    _add_config(eval_results)
    eval_results.add_argument("--session", required=True)
    eval_results.add_argument("--results-root", type=Path)

    release = sub.add_parser("release", help="build, validate, install, rollback, and uninstall private bundles")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    release_build = release_sub.add_parser("build", help="build Ayran Layer or Complete")
    _add_config(release_build)
    release_kind = release_build.add_mutually_exclusive_group(required=True)
    release_kind.add_argument("--layer", action="store_true")
    release_kind.add_argument("--complete", action="store_true")
    release_build.add_argument("--destination", type=Path)
    release_build.add_argument("--root", type=Path)
    release_validate = release_sub.add_parser("validate", help="validate a release bundle")
    _add_config(release_validate)
    release_validate.add_argument("--path", type=Path, required=True)
    release_install = release_sub.add_parser("install", help="install Layer or Complete")
    _add_config(release_install)
    install_kind = release_install.add_mutually_exclusive_group(required=True)
    install_kind.add_argument("--layer", action="store_true")
    install_kind.add_argument("--complete", action="store_true")
    release_install.add_argument("--prime", type=Path)
    release_install.add_argument("--prefix", type=Path, required=True)
    release_install.add_argument("--source", type=Path)
    release_install.add_argument("--dry-run", action="store_true")
    release_rollback = release_sub.add_parser("rollback", help="restore the prior package pointer")
    _add_config(release_rollback)
    release_rollback.add_argument("--receipt", type=Path, required=True)
    release_uninstall = release_sub.add_parser("uninstall", help="remove receipt-listed Ayran paths only")
    _add_config(release_uninstall)
    release_uninstall.add_argument("--receipt", type=Path, required=True)

    graph = sub.add_parser("graph", help="operate on one M1 graph namespace")
    graph.add_argument("graph_argv", nargs=argparse.REMAINDER)
    return parser


def _command_doctor(config) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.compatibility.locks import check_compatibility

    result = check_compatibility(config)
    return {
        "schema_version": "1.0.0",
        "doctor_status": "healthy" if result["all_passed"] else "failed",
        "checks": result,
    }


def _command_status(config, run: str, state_root: Path | None) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.runtime.status import reconstruct_status

    return reconstruct_status(config, run_id=run, state_root=state_root)


def _command_diagnose(config, run: str, bundle: Path, state_root: Path | None) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.diagnostics.bundle import create_bundle

    return create_bundle(config, run_id=run, bundle_path=bundle, state_root=state_root)


def _command_stop(config, run: str, state_root: Path | None, graceful: bool, force_after: int | None) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.runtime.stop import stop_run

    return stop_run(config, run_id=run, state_root=state_root, graceful=graceful, force_after=force_after)


def _command_recover(config, run: str, state_root: Path | None) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.runtime.recover import recover_run

    return recover_run(config, run_id=run, state_root=state_root)


def _command_service(config, run: str, state_root: Path | None, socket: Path | None, token_file: Path | None) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.runtime.service_main import service_main

    return service_main(config, run_id=run, state_root=state_root, socket=socket, token_file=token_file)


def _command_session(config, arguments: argparse.Namespace) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.runtime.session import start_engagement

    if arguments.session_command != "prepare":
        raise ValueError(f"unsupported session command: {arguments.session_command}")
    cwd = Path(arguments.cwd) if arguments.cwd else Path.cwd()
    explicit = Path(arguments.state_root) if arguments.state_root else None
    unsafe = bool(getattr(arguments, "allow_unsafe_filesystem", False))
    fresh = bool(getattr(arguments, "fresh", False))
    fallback = Path(config.state_root)
    manifest = getattr(arguments, "manifest", None)
    roots_raw = getattr(arguments, "roots", None)
    if manifest is not None and roots_raw:
        raise ValueError("use only one of --manifest or --roots")
    if roots_raw:
        from ayran.policy.local_scope import parse_roots

        return start_engagement(
            cwd=cwd,
            roots=parse_roots(str(roots_raw)),
            state_root=explicit,
            fallback_state=fallback,
            allow_unsafe_filesystem=unsafe,
            fresh=fresh,
        )
    if manifest is not None:
        return start_engagement(
            cwd=cwd,
            manifest=Path(manifest),
            state_root=explicit,
            fallback_state=fallback,
            allow_unsafe_filesystem=unsafe,
            fresh=fresh,
        )
    return start_engagement(
        cwd=cwd,
        state_root=explicit,
        fallback_state=fallback,
        allow_unsafe_filesystem=unsafe,
        fresh=fresh,
    )


def _command_start(config, arguments: argparse.Namespace) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    from ayran.policy.local_scope import parse_roots
    from ayran.runtime.session import start_engagement

    cwd = Path(arguments.cwd) if arguments.cwd else Path.cwd()
    explicit = Path(arguments.state_root) if arguments.state_root else None
    fallback = Path(config.state_root)
    unsafe = bool(getattr(arguments, "allow_unsafe_filesystem", False))
    fresh = bool(getattr(arguments, "fresh", False))
    if arguments.manifest and arguments.roots:
        raise ValueError("use only one of --manifest or --roots")
    if arguments.roots:
        return start_engagement(
            cwd=cwd,
            roots=parse_roots(str(arguments.roots)),
            state_root=explicit,
            fallback_state=fallback,
            allow_unsafe_filesystem=unsafe,
            fresh=fresh,
        )
    if arguments.manifest:
        return start_engagement(
            cwd=cwd,
            manifest=Path(arguments.manifest),
            state_root=explicit,
            fallback_state=fallback,
            allow_unsafe_filesystem=unsafe,
            fresh=fresh,
        )
    return start_engagement(
        cwd=cwd,
        state_root=explicit,
        fallback_state=fallback,
        allow_unsafe_filesystem=unsafe,
        fresh=fresh,
    )


def _command_tools(config, arguments: argparse.Namespace) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    import asyncio
    import json

    from ayran.graph.ids import new_id
    from ayran.tools.doctor import default_environment, tools_doctor
    from ayran.tools.registry import CapabilityRegistry
    from ayran.tools.runner import RunContext, policy_from_scope, run_capability

    environment = default_environment()
    registry = CapabilityRegistry(environment=environment)
    command = arguments.tools_command
    if command == "list":
        return {
            "schema_version": "1.0.0",
            "capabilities": [item.as_dict() for item in registry.list_capabilities()],
        }
    if command == "detect":
        detected = asyncio.run(registry.detect(arguments.capability_id))
        return detected.as_dict()

    if command == "health":
        health = asyncio.run(registry.health(arguments.capability_id))
        return health.as_dict()
    if command == "doctor":
        return asyncio.run(tools_doctor(registry, config=config))
    if command == "run":
        payload = json.loads(arguments.input)
        if not isinstance(payload, dict):
            raise ValueError("tools run --input must be a JSON object")
        resolved = registry.resolve_id(arguments.capability_id)
        manifest = registry.manifests[resolved]
        policy = policy_from_scope(
            manifest=manifest,
            allow_install=bool(config.allow_install),
            offline=bool(config.offline),
        )
        run_id = getattr(arguments, "tool_run_id", None) or new_id("run")
        context = RunContext(
            run_id=run_id,
            target_identity={
                "target_id": "tgt_01J00000000000000000000001",
                "source_tree_hash": "sha256:" + "d" * 64,
                "scope_id": "scp_01J00000000000000000000001",
            },
            retries_from=getattr(arguments, "retries_from", None),
        )
        return asyncio.run(
            run_capability(
                registry,
                arguments.capability_id,
                payload,
                policy=policy,
                context=context,
                require_available=True,
            )
        )
    raise ValueError(f"unsupported tools command: {command}")


def _open_store(arguments: argparse.Namespace) -> Any:
    from ayran.graph.recovery import GraphStore

    stream = json.loads(Path(arguments.stream).read_text(encoding="utf-8"))
    if not isinstance(stream, dict):
        raise ValueError("stream identity must be a JSON object")
    return GraphStore(
        Path(arguments.graph_root),
        stream,
        allow_unsafe_filesystem=bool(getattr(arguments, "allow_unsafe_filesystem", False)),
    )


def _command_context(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.router.service import compile_pack

    store = _open_store(arguments)
    try:
        return compile_pack(
            store,
            cluster_id=getattr(arguments, "cluster", None),
            token_budget=int(getattr(arguments, "budget", 4000) or 4000),
        )
    finally:
        store.close()


def _command_router(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.router.service import router_history, router_status, router_step

    store = _open_store(arguments)
    try:
        command = arguments.router_command
        cluster = getattr(arguments, "cluster", None)
        if command == "status":
            return router_status(store, cluster_id=cluster)
        if command == "step":
            return router_step(store, cluster_id=cluster, persist=True)
        if command == "history":
            return router_history(store, limit=int(getattr(arguments, "limit", 20) or 20))
        raise ValueError(f"unsupported router command: {command}")
    finally:
        store.close()


def _command_coverage(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.router.service import coverage_cell, coverage_summary

    store = _open_store(arguments)
    try:
        if arguments.coverage_command == "summary":
            return coverage_summary(store, cluster_id=getattr(arguments, "cluster", None))
        if arguments.coverage_command == "cell":
            return coverage_cell(store, arguments.cell_id)
        raise ValueError(f"unsupported coverage command: {arguments.coverage_command}")
    finally:
        store.close()


def _command_maps(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.router.service import build_maps, get_map

    store = _open_store(arguments)
    try:
        source_text = None
        slither_json = None
        if getattr(arguments, "source", None):
            source_text = Path(arguments.source).read_text(encoding="utf-8")
        if getattr(arguments, "slither_json", None):
            slither_json = json.loads(Path(arguments.slither_json).read_text(encoding="utf-8"))
        if source_text or slither_json:
            return build_maps(
                store,
                arguments.map_type,
                cluster_id=getattr(arguments, "cluster", None),
                source_text=source_text,
                slither_json=slither_json if isinstance(slither_json, dict) else None,
            )
        return get_map(store, arguments.map_type, cluster_id=getattr(arguments, "cluster", None))
    finally:
        store.close()


def _json_object(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("JSON argument must be an object")
    return payload


def _command_evidence(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evidence.service import transition

    store = _open_store(arguments)
    try:
        actor = _json_object(getattr(arguments, "actor", None))
        return transition(
            store,
            arguments.hypothesis_id,
            arguments.to,
            evidence=_json_object(arguments.evidence),
            actor=actor or None,
            cause=getattr(arguments, "cause", None),
        )
    finally:
        store.close()


def _command_gate_a(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evidence.service import gate_a

    store = _open_store(arguments)
    try:
        return gate_a(
            store,
            arguments.hypothesis_id,
            analysis=_json_object(arguments.analysis),
            reconcile=bool(getattr(arguments, "reconcile", False)),
        )
    finally:
        store.close()


def _command_gate_b(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evidence.service import gate_b

    store = _open_store(arguments)
    try:
        return gate_b(
            store,
            arguments.hypothesis_id,
            obligations=_json_object(arguments.obligations),
            poc_id=getattr(arguments, "poc_id", None),
            profile=str(getattr(arguments, "profile", None) or "executable"),
        )
    finally:
        store.close()


def _command_dedup(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evidence.service import dedup_check

    store = _open_store(arguments)
    try:
        return dedup_check(store, arguments.hypothesis_id)
    finally:
        store.close()


def _command_poc(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evidence.service import poc_replay, poc_run

    store = _open_store(arguments)
    try:
        if arguments.poc_command == "run":
            experiment = _json_object(getattr(arguments, "experiment", None))
            if getattr(arguments, "execute", False):
                experiment["execute"] = True
            recorded = _json_object(getattr(arguments, "recorded", None)) if getattr(arguments, "recorded", None) else None
            return poc_run(store, arguments.hypothesis_id, experiment=experiment, recorded=recorded)
        if arguments.poc_command == "replay":
            recorded = _json_object(getattr(arguments, "recorded", None)) if getattr(arguments, "recorded", None) else None
            return poc_replay(store, arguments.poc_id, recorded=recorded)
        raise ValueError(f"unsupported poc command: {arguments.poc_command}")
    finally:
        store.close()


def _command_finding(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evidence.service import finding_build

    store = _open_store(arguments)
    try:
        return finding_build(store, arguments.hypothesis_id)
    finally:
        store.close()


def _optional_store(arguments: argparse.Namespace) -> Any | None:
    if not getattr(arguments, "graph_root", None) or not getattr(arguments, "stream", None):
        return None
    return _open_store(arguments)


def _command_knowledge(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.knowledge.errors import KnowledgeError
    from ayran.knowledge.service import (
        ingest_source,
        knowledge_status,
        list_sources,
        query_records,
        release_corpus,
        tombstone_source,
    )

    root = getattr(arguments, "knowledge_root", None)
    command = arguments.knowledge_command
    store = None
    try:
        if command == "list-sources":
            return list_sources(root, phase=getattr(arguments, "phase", None))
        if command == "status":
            return knowledge_status(root)
        if command == "query":
            return query_records(
                root,
                record_type=str(arguments.record_type),
                filters=_json_object(getattr(arguments, "query_filter", None)),
            )
        if command == "audit-registry":
            from ayran.knowledge.registry_audit import audit_registry

            return audit_registry(root)
        if command == "enrich-postmortems":
            from ayran.knowledge.service import enrich_postmortems

            return enrich_postmortems(
                root,
                source_id=str(arguments.source_id),
                limit=getattr(arguments, "limit", None),
                delay=getattr(arguments, "delay", None),
                timeout=getattr(arguments, "timeout", None),
                dry_run=bool(getattr(arguments, "dry_run", False)),
            )
        if command == "ingest-defihacklabs":
            from ayran.knowledge.service import ingest_defihacklabs

            return ingest_defihacklabs(
                root,
                arguments.root,
                commit=str(arguments.commit),
                archive_sha256=str(arguments.archive_sha256),
                limit=getattr(arguments, "limit", None),
            )
        if command == "ingest-krait":
            from ayran.knowledge.service import ingest_krait_deep

            return ingest_krait_deep(
                root,
                arguments.root,
                commit=str(arguments.commit),
                archive_sha256=str(arguments.archive_sha256),
            )
        store = _optional_store(arguments)
        if command == "ingest":
            return ingest_source(root, arguments.source_id, store=store)
        if command == "release":
            return release_corpus(root, str(arguments.version), store=store)
        if command == "tombstone":
            return tombstone_source(
                root,
                arguments.source_id,
                str(arguments.reason),
                store=store,
                republish_version=getattr(arguments, "republish_version", None),
            )
        raise ValueError(f"unsupported knowledge command: {command}")
    except KnowledgeError:
        raise
    finally:
        if store is not None:
            store.close()


def _command_learning(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.learning.errors import LearningError
    from ayran.learning.service import (
        capture,
        generalize_outcome,
        generate_test_fixtures,
        learning_status,
        promote_candidate,
        queue_status,
        review,
        rollback,
        routing_policy_status,
    )

    command = arguments.learning_command
    store = None
    try:
        if command in {"status", "routing-policy"} and not getattr(arguments, "graph_root", None):
            if command == "status":
                return learning_status(learning_root=getattr(arguments, "learning_root", None))
            return routing_policy_status(
                getattr(arguments, "policy_id", None),
                learning_root=getattr(arguments, "learning_root", None),
            )
        store = _optional_store(arguments)
        if command == "capture":
            if store is None:
                raise LearningError("LEARNING_NOT_FOUND", "learning capture requires --graph-root and --stream")
            return capture(
                str(arguments.run),
                store=store,
                outcome_type=str(getattr(arguments, "outcome_type", None) or "adjudicated"),
                hypothesis_id=str(getattr(arguments, "hypothesis", None) or ""),
            )
        if command == "queue":
            if store is None:
                raise LearningError("LEARNING_NOT_FOUND", "learning queue requires --graph-root and --stream")
            return queue_status(store)
        if command == "review":
            if store is None:
                raise LearningError("LEARNING_NOT_FOUND", "learning review requires --graph-root and --stream")
            return review(
                arguments.candidate_id,
                store=store,
                reviewer_id=str(arguments.reviewer_id),
                reviewer_type=str(arguments.reviewer_type),
                verdict=str(arguments.verdict),
                notes=str(getattr(arguments, "notes", "") or ""),
            )
        if command == "generalize":
            if store is None:
                raise LearningError("LEARNING_NOT_FOUND", "learning generalize requires --graph-root and --stream")
            return generalize_outcome(arguments.outcome_id, store=store, seed=str(getattr(arguments, "seed", None) or "0"))
        if command == "test-fixtures":
            if store is None:
                raise LearningError("LEARNING_NOT_FOUND", "learning test-fixtures requires --graph-root and --stream")
            return generate_test_fixtures(arguments.candidate_id, store=store)
        if command == "promote":
            if store is None:
                raise LearningError("LEARNING_NOT_FOUND", "learning promote requires --graph-root and --stream")
            return promote_candidate(
                arguments.candidate_id,
                store=store,
                learning_root=getattr(arguments, "learning_root", None),
            )
        if command == "rollback":
            return rollback(
                arguments.release_id,
                store=store,
                learning_root=getattr(arguments, "learning_root", None),
            )
        if command == "status":
            return learning_status(store=store, learning_root=getattr(arguments, "learning_root", None))
        if command == "routing-policy":
            return routing_policy_status(
                getattr(arguments, "policy_id", None),
                store=store,
                learning_root=getattr(arguments, "learning_root", None),
            )
        raise ValueError(f"unsupported learning command: {command}")
    except LearningError:
        raise
    finally:
        if store is not None:
            store.close()


def _command_eval(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evaluation.service import (
        adjudicate,
        pause_eval,
        preregister_eval,
        results,
        run_all,
        run_arm,
        run_live,
    )

    command = arguments.eval_command
    results_root = getattr(arguments, "results_root", None)
    if command == "preregister":
        if results_root is None:
            raise ValueError("eval preregister requires --results-root")
        return preregister_eval(arguments.manifest, results_root=results_root)
    if command == "pause":
        if results_root is None:
            raise ValueError("eval pause requires --results-root")
        return pause_eval(results_root=results_root)
    if command == "run":
        if getattr(arguments, "live", False) or getattr(arguments, "preregistration", None):
            if results_root is None:
                raise ValueError("live eval run requires --results-root")
            if getattr(arguments, "preregistration", None) is None:
                from ayran.evaluation.errors import PREREGISTRATION_REQUIRED, EvaluationError

                raise EvaluationError(PREREGISTRATION_REQUIRED, "live eval run requires --preregistration")
            if getattr(arguments, "targets", None) is None:
                raise ValueError("live eval run requires --targets")
            return run_live(
                preregistration=arguments.preregistration,
                targets=arguments.targets,
                results_root=results_root,
                seed=getattr(arguments, "seed", None),
                knowledge_root=getattr(arguments, "knowledge_root", None),
            )
        arm = getattr(arguments, "arm", None)
        kwargs = {
            "seed": getattr(arguments, "seed", None),
            "results_root": results_root,
            "evals": getattr(arguments, "evals", None),
            "knowledge_root": getattr(arguments, "knowledge_root", None),
            "learning_root": getattr(arguments, "learning_root", None),
        }
        if arm:
            return run_arm(str(arm), **kwargs)
        return run_all(**kwargs)
    if command == "adjudicate":
        return adjudicate(str(arguments.session), results_root=results_root)
    if command == "results":
        return results(str(arguments.session), results_root=results_root)
    raise ValueError(f"unsupported eval command: {command}")


def _command_release(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.release.service import (
        build,
        install_release,
        rollback_release,
        uninstall_release,
        validate,
    )

    command = arguments.release_command
    if command == "build":
        kind = "layer" if arguments.layer else "complete"
        return build(kind, destination=getattr(arguments, "destination", None), root=getattr(arguments, "root", None))
    if command == "validate":
        return validate(arguments.path)
    if command == "install":
        kind = "layer" if arguments.layer else "complete"
        return install_release(
            kind=kind,
            prefix=Path(arguments.prefix),
            source=getattr(arguments, "source", None),
            prime=getattr(arguments, "prime", None),
            dry_run=bool(getattr(arguments, "dry_run", False)),
        )
    if command == "rollback":
        return rollback_release(Path(arguments.receipt))
    if command == "uninstall":
        return uninstall_release(Path(arguments.receipt))
    raise ValueError(f"unsupported release command: {command}")


def _command_report(arguments: argparse.Namespace) -> dict[str, Any]:
    from ayran.evidence.service import report_lint, report_render

    store = _open_store(arguments)
    try:
        if arguments.report_command == "render":
            return report_render(
                store, arguments.finding_id, fmt=str(getattr(arguments, "report_format", None) or "markdown")
            )
        if arguments.report_command == "lint":
            return report_lint(store, arguments.finding_id)
        raise ValueError(f"unsupported report command: {arguments.report_command}")
    finally:
        store.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    from ayran.config.loader import ConfigError
    from ayran.evidence.errors import EvidenceError
    from ayran.graph.errors import GraphError

    try:
        config = _load_for_args(arguments)
    except ConfigError as error:
        payload = {"ok": False, "error": {"code": error.code, "message": str(error), "retryable": False}}
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 2
    state_root = _expand(arguments.state_root) if getattr(arguments, "state_root", None) else _expand(config.state_root)

    try:
        if arguments.command == "doctor":
            result = _command_doctor(config)
        elif arguments.command == "status":
            result = _command_status(config, arguments.run, state_root)
        elif arguments.command == "diagnose":
            result = _command_diagnose(config, arguments.run, arguments.bundle, state_root)
        elif arguments.command == "stop":
            result = _command_stop(config, arguments.run, state_root, arguments.graceful, arguments.force_after)
        elif arguments.command == "recover":
            result = _command_recover(config, arguments.run, state_root)
        elif arguments.command == "service":
            result = _command_service(config, arguments.run, state_root, arguments.socket, arguments.token_file)
        elif arguments.command == "start":
            result = _command_start(config, arguments)
        elif arguments.command == "session":
            result = _command_session(config, arguments)
        elif arguments.command == "tools":
            result = _command_tools(config, arguments)
        elif arguments.command == "context":
            result = _command_context(arguments)
        elif arguments.command == "router":
            result = _command_router(arguments)
        elif arguments.command == "coverage":
            result = _command_coverage(arguments)
        elif arguments.command == "maps":
            result = _command_maps(arguments)
        elif arguments.command == "evidence":
            result = _command_evidence(arguments)
        elif arguments.command == "gate-a":
            result = _command_gate_a(arguments)
        elif arguments.command == "gate-b":
            result = _command_gate_b(arguments)
        elif arguments.command == "dedup":
            result = _command_dedup(arguments)
        elif arguments.command == "poc":
            result = _command_poc(arguments)
        elif arguments.command == "finding":
            result = _command_finding(arguments)
        elif arguments.command == "report":
            result = _command_report(arguments)
        elif arguments.command == "knowledge":
            result = _command_knowledge(arguments)
        elif arguments.command == "learning":
            result = _command_learning(arguments)
        elif arguments.command == "eval":
            result = _command_eval(arguments)
        elif arguments.command == "release":
            result = _command_release(arguments)
        elif arguments.command == "graph":
            from ayran.graph.cli import main as graph_main

            return graph_main(["graph", *list(arguments.graph_argv)])
        else:
            parser.error(f"unsupported command: {arguments.command}")
            return 2
        sys.stdout.write(json.dumps({"ok": True, "result": result}, indent=2) + "\n")
        return 0
    except EvidenceError as error:
        payload = {"ok": False, "error": error.as_dict()}
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 2
    except GraphError as error:
        payload = {"ok": False, "error": error.as_dict()}
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
