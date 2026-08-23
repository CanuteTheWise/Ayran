"""Root-skill-side Gate A challenger plumbing (spec §7.1, §5.5, §11.4).

This module lives in ``src`` but NEVER spawns agents and NEVER calls ``rlm()``
itself: the Prime ``rlm()`` invocation arrives through an injected transport
callable (the live adapter is supplied by the root skill at runtime; CI uses a
scripted transport). Credential minting/verification moved to
:mod:`ayran.gates.credentials` (§11.4 relocation): key generation lives only
in the extension, the sidecar verifies/consumes against the enrolled key, and
per-spawn challenger tokens are minted by the extension and vaulted
server-side — the model never handles a challenger token. SO_PEERCRED alone
is insufficient (§11.4), so every challenger submission additionally presents
a short-TTL, child-bound, single-use credential verified through
:class:`~ayran.gates.credentials.CredentialAuthority`.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from ayran.gates.credentials import CredentialAuthority

# Node types whose ids/narrative must NEVER reach the challenger bundle (§5.5).
HISTORICAL_NODE_TYPES = frozenset({"MechanismCard", "IncidentCard", "ReasoningLens"})

# The scripted challenger runs as a REAL subprocess: it reads the bundle on
# stdin and writes its verdict JSON to stdout — a genuine process boundary for
# the isolation probe's facts, with deterministic output (no model calls).
_SCRIPTED_CHALLENGER_PROGRAM = r"""
import json, sys
bundle = json.load(sys.stdin)
scripted = sys.argv[1] if len(sys.argv) > 1 else None
if scripted:
    with open(scripted, "r", encoding="utf-8") as handle:
        verdict = json.load(handle)
else:
    claim = str(bundle.get("claim") or "")
    declared = str(bundle.get("violated_invariant") or "")
    steps = [str(item) for item in (bundle.get("attack_path") or [])]
    preconditions = [
        {
            "dimension": "declared:" + str(item.get("description", "precondition"))[:64],
            "present": True,
            "attacker_can_create": item.get("attacker_can_create"),
            "detail": str(item.get("description") or "declared precondition"),
        }
        for item in (bundle.get("preconditions") or [])
    ]
    verdict = {
        "violated_invariant": declared
        or ("claim requires an exact invariant statement: " + claim[:160]),
        "preconditions": preconditions
        or [
            {
                "dimension": "reachability",
                "present": True,
                "attacker_can_create": True,
                "detail": "unprivileged caller can reach the claimed entry point",
            }
        ],
        "strongest_benign_explanation": (
            "the claimed path may be the intended withdrawal flow; exact source "
            "lines must be quoted to exclude a benign reading"
        ),
        "cheapest_decisive_experiment": {
            "inputs": steps[:1] or ["one unprivileged call along the claimed path"],
            "expected_positive": "claimed invariant breaks with a numerical delta",
            "expected_negative": "benign call produces no attacker profit",
            "capability": "foundry.test",
        },
        "verdict": "poc_worthy" if declared else "needs_missing_fact",
    }
json.dump(verdict, sys.stdout)
"""


# --- blind challenger bundle (claim + target slice ONLY, §5.5) -----------------


def build_challenger_bundle(
    store: Any,
    hypothesis_id: str,
    *,
    max_slice_chars: int = 12000,
) -> dict[str, Any]:
    """Construct the knowledge-blind challenger input bundle.

    Contents are EXACTLY: claim, attack_path, declared preconditions, optional
    violated_invariant, and touched target-source slices. No HISTORICAL_REFERENCE
    nodes, no Global Graph retrieval for the cluster, no originator narrative.
    """

    from ayran.evidence.load import load_hypothesis

    hypothesis = load_hypothesis(store, hypothesis_id)
    if hypothesis is None:
        raise LookupError(hypothesis_id)
    slices: list[dict[str, str]] = []
    try:
        from ayran.context.queries import OntologyQueries, snapshot_view

        view = snapshot_view(
            OntologyQueries(store=store),
            cluster_id=None,
            run_id=str(store.stream.get("run_id") or ""),
        )
        for unit in list(view.source_units)[:8]:
            text = str(unit.get("source") or unit.get("text") or "")
            if not text:
                continue
            slices.append(
                {
                    "locator": str(unit.get("locator") or unit.get("name") or "target/src")[:512],
                    "source": text[:max_slice_chars],
                }
            )
    except Exception:
        slices = []
    preconditions = [
        {
            "description": str(item.get("description") or "")[:1024],
            "attacker_can_create": item.get("attacker_can_create")
            if isinstance(item.get("attacker_can_create"), bool)
            else None,
        }
        for item in (hypothesis.get("preconditions") or [])
        if isinstance(item, dict)
    ]
    bundle: dict[str, Any] = {
        "schema_version": "1.0.0",
        "hypothesis_id": str(hypothesis.get("hypothesis_id") or hypothesis_id),
        "claim": str(hypothesis.get("claim") or "")[:2048],
        "attack_path": [str(step)[:512] for step in (hypothesis.get("attack_path") or [])[:64]],
        "preconditions": preconditions,
        "violated_invariant": "",
        "target_source_slices": slices,
    }
    invariant_ids = list(hypothesis.get("invariant_ids") or [])
    if invariant_ids:
        bundle["invariant_ids"] = [str(item) for item in invariant_ids[:8]]
    return bundle


def forbidden_leakage_tokens(store: Any) -> list[str]:
    """Graph ids/narrative that must never appear in bundle or verdict bytes."""

    from ayran.evidence.load import load_nodes_by_type, node_props

    tokens: set[str] = set()
    for node_type in sorted(HISTORICAL_NODE_TYPES):
        for node in load_nodes_by_type(store, node_type):
            tokens.add(str(node.get("node_id") or ""))
            props = node_props(node)
            for key in ("title", "narrative", "summary"):
                value = str(props.get(key) or "").strip()
                if value:
                    tokens.add(value)
            for prop in node.get("properties") or []:
                if (
                    isinstance(prop, dict)
                    and str(prop.get("name") or "") == "classification"
                    and str(prop.get("value") or "") == "HISTORICAL_REFERENCE"
                ):
                    tokens.add(str(node.get("node_id") or ""))
    return sorted(token for token in tokens if token)


def leakage_scan(
    *,
    bundle_bytes: bytes,
    verdict_text: str,
    forbidden_tokens: list[str],
    scan_root: Path | None = None,
) -> dict[str, Any]:
    """Bidirectional leakage scan (S9.2 clause 2).

    Direction 1: the serialized bundle must contain zero leaked graph ids or
    historical narrative. Direction 2: the returned verdict text must contain
    zero leaked tokens. Both directions reuse the sealed-set scanning in
    ``evaluation/leakage.py`` when a scan root is given.
    """

    bundle_hits = [
        {"token": token, "direction": "bundle"}
        for token in forbidden_tokens
        if token and token.encode("utf-8") in bundle_bytes
    ]
    verdict_hits = [
        {"token": token, "direction": "verdict"}
        for token in forbidden_tokens
        if token and token in verdict_text
    ]
    hits = bundle_hits + verdict_hits
    sealed: dict[str, Any] | None = None
    if scan_root is not None:
        from ayran.evaluation.leakage import scan_leakage

        sealed = scan_leakage(extra_roots=[Path(scan_root)])
    return {
        "schema_version": "1.0.0",
        "clean": not hits and (sealed is None or sealed.get("clean") is True),
        "count": len(hits),
        "hits": hits,
        "sealed_scan": sealed,
    }


class ChallengerTransport:
    """Spawn the challenger as a REAL short-lived subprocess (isolation §11.2).

    The default program derives a deterministic stand-in verdict from the
    bundle; CI passes a ``script`` file carrying the scripted challenger's
    verdict (the scripted-challenger transport seam). No model calls, no
    network. Returns the verdict JSON plus process-boundary facts.
    """

    channel = "subprocess"

    def __init__(self, *, script: Path | None = None, timeout_seconds: float = 30.0) -> None:
        self.script = script
        self.timeout_seconds = timeout_seconds

    def facts(self) -> dict[str, Any]:
        """Process-boundary facts consumed by the isolation probe (§11.2)."""

        return {
            "channel": self.channel,
            "writable_roots": [],
            "has_sidecar_socket": False,
        }

    def run(self, bundle: dict[str, Any]) -> dict[str, Any]:
        bundle_bytes = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
        argv = [sys.executable, "-c", _SCRIPTED_CHALLENGER_PROGRAM]
        if self.script is not None:
            argv.append(str(self.script))
        completed = subprocess.run(
            argv,
            input=bundle_bytes,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"scripted challenger subprocess failed: {completed.stderr.decode('utf-8', 'replace')[:512]}"
            )
        verdict = json.loads(completed.stdout.decode("utf-8"))
        transcript = hashlib.sha256(bundle_bytes + completed.stdout).hexdigest()
        return {
            "verdict": verdict,
            "transcript_hash": f"sha256:{transcript}",
            "channel": self.channel,
            "child_pid": None,  # populated by callers that track the handle
            "bundle_bytes": bundle_bytes,
            "stdout": completed.stdout.decode("utf-8"),
        }


class HeadlessChallengerTransport(ChallengerTransport):
    """Degraded fallback (§11.2): a separate short-lived headless session whose
    verbs reduce to read-only target access via an operator-provided path copy.
    Same subprocess seam; different declared channel and verb set."""

    channel = "headless_session"

    def __init__(
        self,
        *,
        script: Path | None = None,
        timeout_seconds: float = 30.0,
        target_copy_root: Path | str = "",
    ) -> None:
        super().__init__(script=script, timeout_seconds=timeout_seconds)
        self.target_copy_root = str(target_copy_root)

    def facts(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "verbs": ["read_target_copy"],
            "target_copy_root": self.target_copy_root,
            "writable_roots": [],
            "has_sidecar_socket": False,
        }


def spool_verdict(spool_root: Path, *, child_id: str, verdict: dict[str, Any], transcript: str) -> dict[str, Any]:
    """Degraded mode (§11.2/§5.5): land the verdict in a sidecar-owned spool
    directory OUTSIDE the state root and outside included_roots, mode 0600."""

    spool_root.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(transcript.encode("utf-8")).hexdigest()
    path = spool_root / f"{child_id}.verdict.json"
    payload = json.dumps(verdict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    with open(path, "rb") as handle:
        readback = handle.read()
    if readback != payload:
        raise RuntimeError("spool readback mismatch")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return {
        "spool_path": str(path),
        "transcript_hash": f"sha256:{digest}",
        "mode_0600": True,
    }


def spawn_challenger(
    hypothesis_id: str,
    *,
    store: Any,
    credentials: CredentialAuthority,
    transport: ChallengerTransport | None = None,
    child_id: str = "chd-01j",
    reconcile: bool = False,
    spool_root: Path | None = None,
    scan_root: Path | None = None,
) -> dict[str, Any]:
    """Root-skill-side Gate A round trip (§7.1): bundle → challenger → submit.

    NEVER calls ``rlm()`` or spawns agents itself: the challenger runs inside
    the supplied transport (a real subprocess here; the live Prime ``rlm()``
    adapter is injected by the root skill at runtime). The submission lands in
    sidecar ``evidence.gate_a`` under the per-spawn credential minted here by
    the CALLER's authority (live flow: the extension mints and vaults the
    child token; this library seam serves CI and headless harnesses that act
    as the enrollment client).
    """

    bundle = build_challenger_bundle(store, hypothesis_id)
    used_transport = transport or ChallengerTransport()
    exchange = used_transport.run(bundle)
    verdict = exchange["verdict"]
    tokens = forbidden_leakage_tokens(store)
    scan = leakage_scan(
        bundle_bytes=exchange.get("bundle_bytes")
        or json.dumps(bundle, sort_keys=True).encode("utf-8"),
        verdict_text=exchange.get("stdout") or json.dumps(verdict, sort_keys=True),
        forbidden_tokens=tokens,
        scan_root=scan_root,
    )
    if scan["count"] != 0 or not scan["clean"]:
        raise RuntimeError(f"challenger leakage scan failed: {scan['hits'][:8]}")
    token = credentials.mint_challenger(child_id=child_id)
    transcript_hash = str(exchange.get("transcript_hash") or "")
    spool: dict[str, Any] | None = None
    if spool_root is not None:
        spool = spool_verdict(
            spool_root,
            child_id=child_id,
            verdict=verdict,
            transcript=str(exchange.get("stdout") or json.dumps(verdict, sort_keys=True)),
        )
        transcript_hash = spool["transcript_hash"]
    from ayran.evidence.service import gate_a

    result = gate_a(
        store,
        hypothesis_id,
        submission=verdict,
        credential=token,
        credentials=credentials,
        reconcile=reconcile,
        transcript_hash=transcript_hash,
    )
    result["bundle"] = bundle
    result["leakage_scan"] = scan
    result["credential_state"] = credentials.state()
    if spool is not None:
        result["spool"] = spool
    return result
