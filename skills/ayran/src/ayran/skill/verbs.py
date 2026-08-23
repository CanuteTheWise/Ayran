"""Skill verb client — the model's working interface to the sidecar (spec §7.1).

Ten thin verbs over :class:`~ayran.api.client.AyranClient`, one JSON-RPC call
(or a short fixed chain) each, plus tiny response shaping only. Connection
discovery follows the settings law: the environment supplies the socket path
(``AYRAN_SOCKET_PATH``) and the token FILE path (``AYRAN_TOKEN_FILE``) —
paths only, never token values; the client reads the token bytes from the
file itself. Nothing secret is logged. Verb-level authorization stays at the
RPC boundary (``_require_write`` / role ACLs): these verbs add NO authority.

In tests and headless harnesses, monkeypatch :func:`_connect` (or pass
``transport``-seam objects where noted) to drive an in-process dispatcher.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from ayran.api.client import AyranClient
from ayran.gates.credentials import CredentialAuthority
from ayran.gates.spawn_challenger import ChallengerTransport

__all__ = [
    "SkillVerbError",
    "attach_evidence",
    "coverage",
    "map_target",
    "remember",
    "report",
    "request_gate_a",
    "request_gate_b",
    "scan",
    "search_precedents",
    "spawn_challenger",
]


class SkillVerbError(RuntimeError):
    """Connection/configuration failure naming the missing variable."""


def _connect() -> AyranClient:
    """Build the owner-only client from env PATHS (never token values)."""

    socket_raw = (os.environ.get("AYRAN_SOCKET_PATH") or "").strip()
    if not socket_raw:
        raise SkillVerbError(
            "AYRAN_SOCKET_PATH is not set; the skill verbs cannot reach the sidecar socket"
        )
    token_raw = (os.environ.get("AYRAN_TOKEN_FILE") or "").strip()
    if not token_raw:
        raise SkillVerbError(
            "AYRAN_TOKEN_FILE is not set; the skill verbs cannot read the run bearer token"
        )
    token_path = Path(token_raw)
    if not token_path.is_file():
        raise SkillVerbError(
            f"AYRAN_TOKEN_FILE does not point at a readable token file: {token_path}"
        )
    token_bytes = token_path.read_bytes().strip()
    if not token_bytes:
        raise SkillVerbError(f"AYRAN_TOKEN_FILE is empty: {token_path}")
    return AyranClient(Path(socket_raw), token_bytes=token_bytes)


def _denied(result: Any) -> bool:
    return isinstance(result, dict) and result.get("accepted") is False and "error" in result


def map_target(force: bool = False) -> dict[str, Any]:
    """Build/refresh the attack-surface map and compile the enriched pack.

    Chain: ``maps.build`` (attack_surface; seeds the coverage grid) ->
    ``coverage.summary`` (census M/N + unexamined) -> ``context.compile``.
    ``force`` is forwarded for operator-forced rebuilds; today ``maps.build``
    always rebuilds (no cache), so the flag is reserved for cache semantics.
    """

    client = _connect()
    maps = client.call("maps.build", map_type="attack_surface", persist=True, force=bool(force))
    if _denied(maps):
        return maps  # type: ignore[no-any-return]
    census = client.call("coverage.summary")
    pack = client.call(
        "context.compile", token_budget=4000, purpose="map_target", role="root-auditor"
    )
    return {"schema_version": "1.0.0", "maps": maps, "coverage": census, "pack": pack}


def scan(adapter: str, input: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
    """Run one registered adapter supervised (``tools.run``).

    Findings come back as leads (evidence ceiling ``lead``). ``timeout`` is
    forwarded when given; the capability manifest's timeout policy governs
    execution limits today.
    """

    params: dict[str, Any] = {"capability_id": adapter, "input": dict(input)}
    if timeout is not None:
        params["timeout"] = timeout
    result = _connect().call("tools.run", **params)
    return result  # type: ignore[no-any-return]


def search_precedents(
    query: str,
    filters: dict[str, Any] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Ground hypotheses in prior art (``knowledge.query``).

    Ingested corpus ONLY — case-insensitive substring over record text fields
    plus exact-field ``filters``. The live Solodit POST stays
    operator-sanctioned-only (Executor Instruction #4); this verb never
    touches the network.
    """

    params: dict[str, Any] = {"query": str(query)}
    if filters:
        params["filter"] = dict(filters)
    result = _connect().call("knowledge.query", **params)
    if limit is not None and isinstance(result, dict) and isinstance(result.get("records"), list):
        trimmed = list(result["records"][: max(0, int(limit))])
        result = {**result, "records": trimmed, "count": len(trimmed)}
    return result  # type: ignore[no-any-return]


def remember(
    *,
    origin: str,
    claim: str,
    attack_path: list[str],
    preconditions: list[dict[str, Any]],
    cluster_id: str | None = None,
    **rest: Any,
) -> dict[str, Any]:
    """Author a hypothesis into the Target Graph (``hypotheses.remember``).

    The ONLY model→graph write path for reasoning content; writer identity is
    bound to the session channel server-side (§5.1, §11.4).
    """

    params: dict[str, Any] = {
        "origin": origin,
        "claim": claim,
        "attack_path": [str(step) for step in attack_path],
        "preconditions": preconditions,
    }
    if cluster_id:
        params["cluster_id"] = cluster_id
    params.update(rest)
    result = _connect().call("hypotheses.remember", **params)
    return result  # type: ignore[no-any-return]


def attach_evidence(hypothesis_id: str, artifact: str | bytes, kind: str = "text") -> dict[str, Any]:
    """Bind one artifact to a hypothesis (``evidence.attach``).

    Stores via the ArtifactStore and appends the graph link; the evidence
    grade stays ``lead`` — an attached artifact is a claim, not an executed
    observation.
    """

    result = _connect().call(
        "evidence.attach",
        hypothesis_id=hypothesis_id,
        artifact=artifact,
        kind=str(kind),
    )
    return result  # type: ignore[no-any-return]


def spawn_challenger(
    hypothesis_id: str,
    *,
    child_id: str | None = None,
    transport: ChallengerTransport | None = None,
    credentials: CredentialAuthority | None = None,
    session: str | None = None,
) -> dict[str, Any]:
    """Root-skill Gate A preparation round trip (§7.1 contract note).

    Chain: ``challenger.prepare`` (blind bundle; the sidecar never spawns
    agents and no longer mints — ``credential_minter`` is the extension) ->
    the challenger transport (scripted subprocess seam in CI; the live root
    skill substitutes its own Prime ``rlm()`` child) -> optional
    ``credentials.deliver``. Live flow: the EXTENSION mints and vaults the
    child-bound token (pass ``credentials=None``); headless/CI harnesses act
    as the enrollment client by passing their own authority. The model never
    handles a challenger token in either flow.
    """

    client = _connect()
    child = child_id or f"chd-{secrets.token_hex(6)}"
    prepared = client.call(
        "challenger.prepare", hypothesis_id=hypothesis_id, child_id=child, session=session
    )
    if _denied(prepared) or not isinstance(prepared, dict) or prepared.get("bundle") is None:
        return prepared  # type: ignore[no-any-return]
    used_transport = transport if transport is not None else ChallengerTransport()
    exchange = used_transport.run(prepared["bundle"])
    if credentials is not None:
        token = credentials.mint_challenger(child_id=child)
        delivered = client.call("credentials.deliver", child_id=child, credential=token)
        if _denied(delivered):
            return delivered  # type: ignore[no-any-return]
    return {
        "schema_version": "1.0.0",
        "child_id": child,
        "hypothesis_id": hypothesis_id,
        "credential_minter": prepared.get("credential_minter", "extension"),
        "bundle": prepared["bundle"],
        "verdict": exchange["verdict"],
        "transcript_hash": exchange.get("transcript_hash"),
        "isolation": prepared.get("isolation"),
        "spool_root": prepared.get("spool_root"),
    }


def request_gate_a(
    hypothesis_id: str,
    *,
    submission: dict[str, Any],
    child_id: str,
    transcript_hash: str | None = None,
    reconcile: bool = False,
) -> dict[str, Any]:
    """Submit the challenger verdict for structural validation + sealing.

    ``evidence.gate_a`` with ``child_id`` only (no credential): the sidecar
    consumes the extension-vaulted single-use token at the seal; the verdict
    enters ONLY through this credentialed channel (§5.5).
    """

    params: dict[str, Any] = {
        "hypothesis_id": hypothesis_id,
        "submission": submission,
        "child_id": child_id,
        "reconcile": bool(reconcile),
    }
    if transcript_hash:
        params["transcript_hash"] = transcript_hash
    result = _connect().call("evidence.gate_a", **params)
    return result  # type: ignore[no-any-return]


def request_gate_b(
    hypothesis_id: str,
    poc_id: str | None = None,
    **rest: Any,
) -> dict[str, Any]:
    """Executed-artifact post-PoC falsification (``evidence.gate_b``).

    Executed obligation records (command/argv/cwd/exit_code/stdout_sha256/
    duration_ms/artifact_ids) travel as ``obligations`` via ``**rest``;
    asserted booleans are rejected as forgery.
    """

    params: dict[str, Any] = {"hypothesis_id": hypothesis_id}
    if poc_id:
        params["poc_id"] = poc_id
    params.update(rest)
    result = _connect().call("evidence.gate_b", **params)
    return result  # type: ignore[no-any-return]


def coverage(cluster_id: str | None = None) -> dict[str, Any]:
    """Coverage posture: grid summary + census remainder (``coverage.summary``;
    ``coverage.cell`` is the per-cell detail RPC)."""

    params: dict[str, Any] = {}
    if cluster_id:
        params["cluster_id"] = cluster_id
    result = _connect().call("coverage.summary", **params)
    return result  # type: ignore[no-any-return]


def report(hypothesis_id: str, template: str | None = None) -> dict[str, Any]:
    """Render a submission draft (§7.3 flow 5).

    Chain: ``finding.build`` (assembles the canonical finding from graph
    state) -> ``report.render`` (``template`` selects the format, default
    markdown) -> ``report.lint``. Human approval boundaries are unchanged:
    nothing is sent anywhere.
    """

    client = _connect()
    finding = client.call("finding.build", hypothesis_id=hypothesis_id)
    if _denied(finding):
        return finding  # type: ignore[no-any-return]
    finding_id = str(finding.get("finding_id") or "")
    rendered = client.call(
        "report.render", finding_id=finding_id, format=str(template or "markdown")
    )
    if _denied(rendered):
        return rendered  # type: ignore[no-any-return]
    lint = client.call("report.lint", finding_id=finding_id)
    return {"schema_version": "1.0.0", "finding": finding, "report": rendered, "lint": lint}
