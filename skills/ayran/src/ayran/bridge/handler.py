"""JSON-RPC method dispatch for the M3 Prime lifecycle bridge."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING, Any

from ayran.artifacts.store import ArtifactStore
from ayran.bridge.context_pack import RECONSTRUCTION_TITLES
from ayran.bridge.kernel import detect_kernel
from ayran.bridge.lifecycle import record_child, record_session_event
from ayran.compatibility.locks import check_compatibility
from ayran.config.models import EffectiveConfig
from ayran.graph.canonical import canonical_hash
from ayran.graph.errors import CONTRACT_INVALID, GraphError
from ayran.graph.recovery import GraphStore
from ayran.policy.permissions import PolicyEngine
from ayran.policy.scope import ScopeManifest, load_scope
from ayran.process.supervisor import ProcessSupervisor
from ayran.runtime.logs import StructuredLogger
from ayran.runtime.recover import recover_run
from ayran.runtime.status import reconstruct_status
from ayran.runtime.stop import stop_run

if TYPE_CHECKING:
    from ayran.gates.credentials import CredentialAuthority
    from ayran.tools.registry import CapabilityRegistry


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _denial_reason(decision: Any) -> str:
    """Honest wire reason for a policy decision (S9.4: contains SCOPE_DENIED)."""

    if decision.permitted:
        return str(decision.reason)
    scope_reason = getattr(decision.scope_decision, "reason", None)
    if scope_reason:
        return f"SCOPE_DENIED: {scope_reason}"
    return str(decision.reason)


def _tool_action(tool_name: str, arguments: dict[str, Any]) -> tuple[str, str]:
    name = tool_name.lower()
    resource = str(
        arguments.get("path")
        or arguments.get("file")
        or arguments.get("resource")
        or ""
    )
    if not resource:
        resource = "target/src"
    if name in {"edit", "write"}:
        return "compile_local", resource
    if name in {"read"}:
        return "read_source", resource
    if name == "bash" and ("path" in arguments or "file" in arguments):
        return "test_local", resource
    # ipython maps to a plain ("ipython", resource) action: string-sniffing of
    # payloads is retired (§7.2 row 2) — enforcement is the single-writer
    # sidecar boundary + scope + verb ACLs at the RPC boundary, never
    # substring heuristics in tool payloads.
    return name, resource or "."


@dataclass(slots=True)
class BridgeDispatcher:
    run_id: str
    config: EffectiveConfig
    store: GraphStore
    logger: StructuredLogger
    artifact_store: ArtifactStore
    process_supervisor: ProcessSupervisor
    receipt: dict[str, Any]
    scope: ScopeManifest | None
    policy: PolicyEngine
    state_root: Path
    run_root: Path
    shutdown_callback: Callable[[], None] | None = None
    last_pack_hashes: dict[str, str] = field(default_factory=dict)
    children: dict[str, dict[str, Any]] = field(default_factory=dict)
    isolation_tampered: bool = False
    _credentials: CredentialAuthority | None = field(default=None, repr=False)
    _delivered_credentials: dict[str, str] = field(default_factory=dict, repr=False)
    _isolation_report: dict[str, Any] | None = field(default=None, repr=False)
    _lock: Lock = field(default_factory=Lock)
    _tools_registry: CapabilityRegistry | None = field(default=None, repr=False)

    @property
    def credentials(self) -> CredentialAuthority:
        """Enrolled per-run credential authority (§11.4); fail-closed until enrolled.

        Key GENERATION lives only in the extension: this process constructs the
        authority from the key enrolled via ``credentials.enroll`` (or supplied
        explicitly at construction) and only verifies/consumes against it. Any
        method needing the authority before enrollment fails closed with
        ``CREDENTIAL_UNENROLLED``.
        """

        if self._credentials is None:
            from ayran.gates.credentials import CredentialError

            raise CredentialError(
                "UNENROLLED",
                details={"hint": "call credentials.enroll (or construct with credentials) first"},
            )
        return self._credentials

    @property
    def spool_root(self) -> Path:
        """Sidecar-owned challenger spool, OUTSIDE the state root and included_roots."""

        return self.state_root.parent / "challenger-spool"

    def run_isolation_probe(self) -> dict[str, Any]:
        """Startup/before-first-cognitive-call isolation probe (§11.2)."""

        from ayran.gates.isolation import verify_isolation

        report = verify_isolation(
            state_root=self.state_root,
            spool_root=self.spool_root,
            included_roots=list(self.scope.included_roots) if self.scope else [],
            transport_facts={"channel": "subprocess", "writable_roots": [], "has_sidecar_socket": False},
            credential_grants=["gate_a_submission"],
            tampered=self.isolation_tampered,
        )
        self._isolation_report = report
        return report

    def isolation_report(self) -> dict[str, Any]:
        if self._isolation_report is None:
            return self.run_isolation_probe()
        return self._isolation_report

    def _require_isolation(self) -> None:
        """Fail-closed: cognitive methods refuse until a passing probe exists."""

        from ayran.evidence.errors import ISOLATION_UNVERIFIED, EvidenceError

        report = self.isolation_report()
        if not report.get("verified"):
            raise EvidenceError(
                ISOLATION_UNVERIFIED,
                "challenger isolation is unverified; cognitive methods refuse until a "
                f"passing probe exists: {report.get('refusals') or ['unknown']}",
                details={"refusals": report.get("refusals") or []},
            )

    def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "run.status": self.status,
            "run.doctor": self.doctor,
            "run.stop": self.stop,
            "run.recover": self.recover,
            "run.checkpoint": self.checkpoint,
            "run.shutdown": self.shutdown,
            "scope.load": self.scope_load,
            "context.pack": self.context_pack,
            "policy.authorize": self.authorize,
            "lifecycle.record": self.lifecycle_record,
            "child.register": self.child_register,
            "child.complete": self.child_complete,
            "child.fail": self.child_fail,
            "kernel.detect": self.kernel_detect,
            "graph.query": self.graph_query,
            "artifact.get": self.artifact_get,
            "tools.list": self.tools_list,
            "tools.detect": self.tools_detect,
            "tools.health": self.tools_health,
            "tools.run": self.tools_run,
            "context.compile": self.context_compile,
            "ontology.query": self.ontology_query,
            "router.status": self.router_status,
            "router.step": self.router_step,
            "router.history": self.router_history,
            "coverage.summary": self.coverage_summary,
            "coverage.cell": self.coverage_cell,
            "maps.get": self.maps_get,
            "maps.build": self.maps_build,
            "evidence.transition": self.evidence_transition,
            "evidence.attach": self.evidence_attach,
            "evidence.gate_a": self.evidence_gate_a,
            "evidence.gate_b": self.evidence_gate_b,
            "hypotheses.remember": self.hypotheses_remember,
            "challenger.prepare": self.challenger_prepare,
            "credentials.enroll": self.credentials_enroll,
            "credentials.deliver": self.credentials_deliver,
            "evidence.dedup_check": self.evidence_dedup_check,
            "evidence.impact_assess": self.evidence_impact_assess,
            "evidence.severity_assess": self.evidence_severity_assess,
            "evidence.poc_run": self.evidence_poc_run,
            "evidence.poc_replay": self.evidence_poc_replay,
            "finding.build": self.finding_build,
            "report.render": self.report_render,
            "report.lint": self.report_lint,
            "knowledge.list_sources": self.knowledge_list_sources,
            "knowledge.ingest": self.knowledge_ingest,
            "knowledge.release": self.knowledge_release,
            "knowledge.query": self.knowledge_query,
            "knowledge.status": self.knowledge_status,
            "knowledge.tombstone": self.knowledge_tombstone,
            "learning.capture": self.learning_capture,
            "learning.submit_review": self.learning_submit_review,
            "learning.review": self.learning_review,
            "learning.generalize": self.learning_generalize,
            "learning.generate_fixtures": self.learning_generate_fixtures,
            "learning.contamination_check": self.learning_contamination_check,
            "learning.run_ablation": self.learning_run_ablation,
            "learning.promote": self.learning_promote,
            "learning.rollback": self.learning_rollback,
            "learning.status": self.learning_status,
            "eval.run": self.eval_run,
            "eval.adjudicate": self.eval_adjudicate,
            "eval.results": self.eval_results,
            "release.build": self.release_build,
            "release.validate": self.release_validate,
            "release.install": self.release_install,
            "release.rollback": self.release_rollback,
            "release.uninstall": self.release_uninstall,
        }
        handler = handlers.get(method)
        if handler is None:
            raise LookupError(method)
        with self._lock:
            return handler(params)

    def status(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _ = params
        reconstructed = reconstruct_status(self.config, self.run_id, self.state_root)
        graph = self.store.queries.status()
        kernel = detect_kernel()
        return {
            "schema_version": "1.0.0",
            "run_id": self.run_id,
            "graph_health": graph,
            "run": reconstructed,
            "receipt": dict(self.receipt),
            "tool_availability": {
                "ipython": True,
                "ayran_python": kernel.get("ayran_importable"),
                "managed_kernel": kernel.get("managed"),
            },
            "active_children": list(self.children.values()),
            "sidecar": "reachable",
        }

    def doctor(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _ = params
        compatibility = check_compatibility(self.config)
        graph = self.store.doctor()
        kernel = detect_kernel()
        policy_loaded = self.scope is not None
        return {
            "schema_version": "1.0.0",
            "doctor_status": "healthy"
            if compatibility.get("all_passed") and graph.get("status") == "ok"
            else "degraded",
            "sidecar_connectivity": "ok",
            "journal_integrity": graph,
            "policy_loaded": policy_loaded,
            "tool_detection": kernel,
            "compatibility": compatibility,
        }

    def stop(self, params: dict[str, Any]) -> dict[str, Any]:
        graceful = bool(params.get("graceful", True))
        force_after = params.get("force_after")
        force = int(force_after) if isinstance(force_after, int) else None
        return stop_run(
            self.config,
            self.run_id,
            self.state_root,
            graceful=graceful,
            force_after=force,
        )

    def recover(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _ = params
        return recover_run(self.config, self.run_id, self.state_root)

    def checkpoint(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _ = params
        value = self.store.checkpoint(config_hash=None)
        return {
            "schema_version": "1.0.0",
            "run_id": self.run_id,
            "checkpoint_id": value.get("checkpoint_id"),
            "graph_cursor": value.get("journal_cursor"),
            "content_hash": (value.get("integrity") or {}).get("content_hash"),
        }

    def shutdown(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _ = params
        captured: dict[str, Any] | None = None
        try:
            from ayran.learning.capture import capture_run_outcomes

            captured = capture_run_outcomes(self.store, run_id=self.run_id)
        except Exception as error:
            captured = {"captured": [], "count": 0, "error": type(error).__name__}
        checkpoint = self.store.checkpoint(config_hash=None)
        self.store.close()
        self.receipt["run_state"] = "stopped"
        if self.shutdown_callback is not None:
            self.shutdown_callback()
        return {
            "schema_version": "1.0.0",
            "run_id": self.run_id,
            "run_state": "stopped",
            "checkpoint_id": checkpoint.get("checkpoint_id"),
            "graph_cursor": checkpoint.get("journal_cursor"),
            "learning_capture": captured,
        }

    def scope_load(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.runtime.session import bind_scope_to_run

        raw = str(params.get("manifest") or "").strip()
        if not raw:
            raise GraphError(CONTRACT_INVALID, "scope.load requires a manifest path.")
        source = Path(raw).expanduser()
        if not source.is_file():
            raise GraphError(CONTRACT_INVALID, f"scope manifest is not a file: {source}")
        manifest = bind_scope_to_run(source, run_id=self.run_id, dest_root=self.run_root)
        self.scope = manifest
        self.policy = PolicyEngine(manifest, config=self.config)
        return {
            "schema_version": "1.0.0",
            "run_id": self.run_id,
            "scope_id": manifest.scope_id,
            "scope_hash": manifest.hash,
            "scope_file": str(self.run_root / "scope.json"),
            "policy_loaded": True,
        }

    def context_pack(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.context_compile(params)

    def context_compile(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.router.service import compile_pack

        budget = params.get("token_budget", 4000)
        token_budget = int(budget) if isinstance(budget, int) else 4000
        purpose = str(params.get("purpose") or "audit-turn")
        role = str(params.get("role") or "root-auditor")
        cluster_id = str(params["cluster_id"]) if params.get("cluster_id") else None
        result = compile_pack(
            self.store,
            cluster_id=cluster_id,
            token_budget=max(256, min(token_budget, 1000000)),
            purpose=purpose,
            role=role,
            knowledge_policy=str(params["knowledge_policy"]) if params.get("knowledge_policy") else None,
            included_roots=list(self.scope.included_roots) if self.scope else None,
            scope_id=self.scope.scope_id if self.scope else None,
        )
        pack = result["pack"]
        reconstruction = {
            title: next(
                (
                    canonical_hash({"title": section["title"], "content": section["content"]})
                    for section in pack["sections"]
                    if section["title"] == title
                ),
                None,
            )
            for title in RECONSTRUCTION_TITLES
        }
        self.last_pack_hashes = {key: value for key, value in reconstruction.items() if value}
        titles = {section["title"] for section in pack["sections"]}
        reconstructed = set(RECONSTRUCTION_TITLES).issubset(titles)
        result["reconstruction"] = reconstruction
        result["reconstruction_ok"] = reconstructed
        result["content_hash"] = pack["integrity"]["content_hash"]
        return result

    def ontology_query(self, params: dict[str, Any]) -> Any:
        from ayran.context.queries import OntologyQueries

        name = str(params.get("name") or "")
        query_params = params.get("params")
        if not isinstance(query_params, dict):
            query_params = {key: value for key, value in params.items() if key != "name"}
        return OntologyQueries(store=self.store).dispatch(f"ontology.{name}" if not name.startswith("ontology.") else name, query_params)

    def router_status(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        from ayran.router.service import router_status

        payload = params or {}
        cluster = str(payload["cluster_id"]) if payload.get("cluster_id") else None
        return router_status(self.store, cluster_id=cluster)

    def router_step(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        from ayran.router.service import router_step

        payload = params or {}
        cluster = str(payload["cluster_id"]) if payload.get("cluster_id") else None
        persist = bool(payload.get("persist", True))
        return router_step(self.store, cluster_id=cluster, persist=persist)

    def router_history(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        from ayran.router.service import router_history

        payload = params or {}
        limit = int(payload.get("limit") or 20)
        return router_history(self.store, limit=limit)

    def coverage_summary(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        from ayran.router.service import coverage_summary

        payload = params or {}
        cluster = str(payload["cluster_id"]) if payload.get("cluster_id") else None
        return coverage_summary(self.store, cluster_id=cluster)

    def coverage_cell(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.router.service import coverage_cell

        return coverage_cell(self.store, str(params.get("cell_id") or ""))

    def maps_get(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.router.service import get_map

        return get_map(
            self.store,
            str(params.get("map_type") or "attack_surface"),
            cluster_id=str(params["cluster_id"]) if params.get("cluster_id") else None,
        )

    def maps_build(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.router.service import build_maps

        slither = params.get("slither_json")
        solc = params.get("solc_json")
        return build_maps(
            self.store,
            str(params.get("map_type") or "attack_surface"),
            cluster_id=str(params["cluster_id"]) if params.get("cluster_id") else None,
            source_text=str(params["source_text"]) if params.get("source_text") else None,
            slither_json=slither if isinstance(slither, dict) else None,
            solc_json=solc if isinstance(solc, dict) else None,
            persist=bool(params.get("persist", True)),
        )

    def _require_write(self, params: dict[str, Any], action: str = "graph_write") -> None:
        resource = str(params.get("resource") or ".")
        decision = self.policy.authorize(action, resource=resource)
        if not decision.permitted:
            reason = _denial_reason(decision)
            self._journal_policy_denial(
                request_type="rpc_write", action=action, resource=resource, reason=reason
            )
            raise PermissionError(reason)

    def _journal_policy_denial(
        self,
        *,
        request_type: str,
        action: str,
        resource: str,
        reason: str,
        tool_name: str = "",
    ) -> None:
        """Journal a boundary denial with actor=policy in the event payload (S9.4).

        The graph actor enum is closed (no ``policy`` kind), so the policy
        actor identity lives in the journal event payload itself.
        """

        payload: dict[str, Any] = {
            "actor": "policy",
            "request_type": request_type,
            "action": action[:128],
            "resource": resource[:512],
            "reason": reason[:512],
        }
        if tool_name:
            payload["tool_name"] = tool_name[:128]
        try:
            record_session_event(
                self.store,
                run_id=self.run_id,
                event_type="policy_denial",
                payload=payload,
            )
        except Exception as error:  # a journaling failure must never mask the denial itself
            self.logger.event(
                "WARN",
                "bridge.policy_denial_journal_failed",
                request_type=request_type,
                error=type(error).__name__,
            )

    def evidence_transition(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import transition

        self._require_write(params)
        evidence = params.get("evidence")
        actor = params.get("actor")
        try:
            return transition(
                self.store,
                str(params.get("hypothesis_id") or ""),
                str(params.get("to") or params.get("target") or ""),
                evidence=evidence if isinstance(evidence, dict) else {},
                actor=actor if isinstance(actor, dict) else None,
                cause=str(params["cause"]) if params.get("cause") else None,
            )
        except EvidenceError as error:
            return error.as_result()

    def _journal_denial(self, event_type: str, *, session_id: str, reason: str) -> None:
        try:
            record_session_event(
                self.store,
                run_id=self.run_id,
                event_type=event_type,
                payload={"reason": reason[:512], "session_id": session_id[:128]},
            )
        except Exception as error:  # a journaling failure must never mask the denial itself
            self.logger.event(
                "WARN",
                "bridge.denial_journal_failed",
                method=event_type,
                error=type(error).__name__,
            )

    def _derive_writer(self, params: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Writer identity derived SERVER-SIDE from the channel credential mapping (§11.4)."""

        from ayran.evidence.errors import CREDENTIAL_DENIED, WRITER_IMPERSONATION, EvidenceError
        from ayran.gates.credentials import CREDENTIAL_GRANT_REMEMBER, CredentialError

        session = str(params.get("session") or self.run_id)
        raw_credential = params.get("credential") or params.get("writer_credential")
        if raw_credential:
            if self._credentials is None:
                # Fail closed (§11.4/W7): no credential can verify before the
                # extension-side key has been enrolled.
                raise EvidenceError(
                    "CREDENTIAL_UNENROLLED",
                    "writer credential refused: no credential key is enrolled; "
                    "call credentials.enroll first",
                )
            try:
                payload = self._credentials.verify(str(raw_credential), grant=CREDENTIAL_GRANT_REMEMBER)
            except CredentialError as error:
                raise EvidenceError(
                    CREDENTIAL_DENIED,
                    f"writer credential refused: {error.reason}",
                    details=error.as_dict(),
                ) from error
            bound = payload.get("writer") or {}
            writer = {"kind": str(bound.get("kind") or ""), "id": str(bound.get("id") or "")}
        else:
            # The authenticated owner channel maps to the root model writer of the session.
            writer = {"kind": "model", "id": f"prime:{session}"}
        supplied = params.get("writer")
        if isinstance(supplied, dict) and (
            str(supplied.get("kind") or ""),
            str(supplied.get("id") or ""),
        ) != (writer["kind"], writer["id"]):
            raise EvidenceError(
                WRITER_IMPERSONATION,
                "client-supplied writer does not match the channel-bound identity",
                details={"bound": writer, "supplied": supplied},
            )
        return writer, session

    def hypotheses_remember(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import (
            ISOLATION_UNVERIFIED,
            ORIGIN_WRITER_DENIED,
            WRITER_IMPERSONATION,
            EvidenceError,
        )
        from ayran.evidence.service import remember

        self._require_write(params)
        try:
            self._require_isolation()
            writer, session = self._derive_writer(params)
        except EvidenceError as error:
            event = (
                "writer_impersonation_denied"
                if error.code == WRITER_IMPERSONATION
                else "writer_credential_denied"
                if error.code != ISOLATION_UNVERIFIED
                else "isolation_refusal"
            )
            self._journal_denial(
                event,
                session_id=str(params.get("session") or self.run_id),
                reason=f"{error.code}: {error.message}",
            )
            return error.as_result()
        preconditions = params.get("preconditions")
        try:
            return remember(
                self.store,
                origin=str(params.get("origin") or ""),
                claim=str(params.get("claim") or ""),
                attack_path=[str(item) for item in (params.get("attack_path") or [])],
                preconditions=preconditions if isinstance(preconditions, list) else [],
                violated_invariant=str(params["violated_invariant"]) if params.get("violated_invariant") else None,
                cluster_id=str(params.get("cluster_id") or ""),
                writer=writer,
                session=session,
                pack_hash=str(params["pack_hash"]) if params.get("pack_hash") else None,
            )
        except EvidenceError as error:
            if error.code == ORIGIN_WRITER_DENIED:
                self._journal_denial(
                    "origin_writer_denied", session_id=session, reason=error.message
                )
            return error.as_result()

    def evidence_gate_a(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import (
            CREDENTIAL_DENIED,
            ISOLATION_UNVERIFIED,
            VERDICT_OVERRIDE_FORBIDDEN,
            EvidenceError,
        )
        from ayran.evidence.service import gate_a

        self._require_write(params)
        analysis = params.get("analysis")
        submission = params.get("submission")
        credential = params.get("credential") or params.get("challenger_credential")
        child_id = str(params.get("child_id") or "")
        try:
            self._require_isolation()
            # §11.4/W7: when the caller omits the credential (the model-facing
            # flow), the token minted by the EXTENSION and vaulted via
            # credentials.deliver is used implicitly — the model never handles
            # a challenger token. Explicit credentials keep working so CI and
            # headless harnesses can act AS the extension client.
            vaulted = False
            if not credential and child_id and submission is not None:
                vaulted_token = self._delivered_credentials.get(child_id)
                if vaulted_token is None:
                    raise EvidenceError(
                        CREDENTIAL_DENIED,
                        f"no unconsumed vaulted credential for child {child_id}; "
                        "the extension must mint and deliver it first",
                        details={"child_id": child_id},
                    )
                credential = vaulted_token
                vaulted = True
            if credential is not None and self._credentials is None:
                raise EvidenceError(
                    "CREDENTIAL_UNENROLLED",
                    "challenger credential refused: no credential key is enrolled; "
                    "call credentials.enroll first",
                )
            return_value = gate_a(
                self.store,
                str(params.get("hypothesis_id") or ""),
                analysis=analysis if isinstance(analysis, dict) else None,
                submission=submission if isinstance(submission, dict) else None,
                credential=str(credential) if credential else None,
                credentials=self._credentials,
                reconcile=bool(params.get("reconcile")),
                transcript_hash=str(params["transcript_hash"]) if params.get("transcript_hash") else None,
            )
            if vaulted and isinstance(return_value, dict) and return_value.get("record") is not None:
                # Sealed: the vaulted single-use token was consumed at the seal.
                self._delivered_credentials.pop(child_id, None)
            return return_value
        except EvidenceError as error:
            if error.code == VERDICT_OVERRIDE_FORBIDDEN:
                self._journal_denial(
                    "verdict_override_denied",
                    session_id=str(params.get("session") or self.run_id),
                    reason=f"{error.code}: {error.message}",
                )
            elif error.code == CREDENTIAL_DENIED:
                self._journal_denial(
                    "challenger_credential_denied",
                    session_id=str(params.get("session") or self.run_id),
                    reason=f"{error.code}: {error.message}",
                )
            elif error.code == ISOLATION_UNVERIFIED:
                self._journal_denial(
                    "isolation_refusal",
                    session_id=str(params.get("session") or self.run_id),
                    reason=f"{error.code}: {error.message}",
                )
            elif error.code == "CREDENTIAL_UNENROLLED":
                self._journal_denial(
                    "credential_unenrolled",
                    session_id=str(params.get("session") or self.run_id),
                    reason=f"{error.code}: {error.message}",
                )
            else:
                self._journal_denial(
                    "challenger_credential_denied",
                    session_id=str(params.get("session") or self.run_id),
                    reason=f"{error.code}: {error.message}",
                )
            return error.as_result()

    def challenger_prepare(self, params: dict[str, Any]) -> dict[str, Any]:
        """Root-skill Gate A preparation: blind bundle only (§7.1, §11.4/W7).

        The sidecar never spawns agents and no longer mints challenger
        credentials: key generation lives only in the extension, which mints
        the child-bound ``gate_a_submission`` token and vaults it via
        ``credentials.deliver``. This method returns the knowledge-blind bundle
        (§5.5) so the root skill can drive the challenger round trip itself.
        """

        from ayran.evidence.errors import (
            HYPOTHESIS_NOT_FOUND,
            SUBMISSION_INVALID,
            EvidenceError,
        )
        from ayran.gates.spawn_challenger import build_challenger_bundle

        self._require_write(params)
        child_id = str(params.get("child_id") or "")
        hypothesis_id = str(params.get("hypothesis_id") or "")
        try:
            self._require_isolation()
            if not child_id:
                raise EvidenceError(
                    SUBMISSION_INVALID, "challenger.prepare requires child_id"
                )
            try:
                bundle = build_challenger_bundle(self.store, hypothesis_id)
            except LookupError as error:
                raise EvidenceError(
                    HYPOTHESIS_NOT_FOUND,
                    f"hypothesis {hypothesis_id} was not found",
                ) from error
            return {
                "schema_version": "1.0.0",
                "child_id": child_id,
                "hypothesis_id": hypothesis_id,
                "credential_minter": "extension",
                "bundle": bundle,
                "isolation": self.isolation_report(),
                "spool_root": str(self.spool_root),
            }
        except EvidenceError as error:
            self._journal_denial(
                "challenger_prepare_denied",
                session_id=str(params.get("session") or self.run_id),
                reason=f"{error.code}: {error.message}",
            )
            return error.as_result()

    def credentials_enroll(self, params: dict[str, Any]) -> dict[str, Any]:
        """Enroll the run's credential key (§11.4/W7 relocation).

        The extension generates the 32-byte session key and enrolls it over the
        bearer-authenticated channel; this process constructs the run's
        :class:`CredentialAuthority` FROM those bytes and only verifies and
        consumes against them afterwards. Second enrollment fails closed with
        ``CREDENTIAL_ALREADY_ENROLLED``. The journal event never carries key
        material or tokens.
        """

        import base64
        import binascii

        from ayran.gates.credentials import CredentialAuthority, CredentialError

        raw = str(params.get("key_b64") or "").strip()
        try:
            key = base64.b64decode(raw, validate=True)
        except (ValueError, binascii.Error):
            return {
                "accepted": False,
                "error": CredentialError(
                    "MALFORMED", details={"hint": "key_b64 must be standard base64"}
                ).as_dict(),
            }
        if len(key) != 32:
            return {
                "accepted": False,
                "error": CredentialError(
                    "MALFORMED", details={"key_bytes": len(key), "required": 32}
                ).as_dict(),
            }
        if self._credentials is not None:
            return {
                "accepted": False,
                "error": {
                    "code": "CREDENTIAL_ALREADY_ENROLLED",
                    "reason": "ALREADY_ENROLLED",
                    "message": "a credential key is already enrolled for this run; enrollment is single-shot and fail-closed",
                },
            }
        self._credentials = CredentialAuthority(key)
        record_session_event(
            self.store,
            run_id=self.run_id,
            event_type="credentials_enrolled",
            payload={
                "reason": "extension-enrolled session credential key (§11.4)",
                "session_id": str(params.get("session") or self.run_id)[:128],
            },
        )
        return {
            "schema_version": "1.0.0",
            "accepted": True,
            "credentials": self._credentials.state(),
        }

    def credentials_deliver(self, params: dict[str, Any]) -> dict[str, Any]:
        """Vault one extension-minted child-bound token (§11.4/W7).

        The extension mints the ``gate_a_submission`` token outside
        model-reachable Python and delivers it here keyed by ``child_id``.
        Stored tokens are never returned; overwrite of an unconsumed token is
        refused with ``CREDENTIAL_ALREADY_DELIVERED``. ``evidence.gate_a``
        consumes the vaulted token implicitly when the caller supplies only
        ``child_id``.
        """

        from ayran.gates.credentials import CredentialError

        child_id = str(params.get("child_id") or "")
        # NB: the param is "credential", never "token" — the wire protocol
        # reserves params.token for the run bearer (popped by AyranServer).
        token = str(params.get("credential") or "")
        if self._credentials is None:
            return {
                "accepted": False,
                "error": CredentialError(
                    "UNENROLLED", details={"hint": "credentials.enroll first"}
                ).as_dict(),
            }
        if not child_id or not token:
            return {
                "accepted": False,
                "error": CredentialError(
                    "MALFORMED", details={"required": ["child_id", "token"]}
                ).as_dict(),
            }
        try:
            # Structural pre-verification (no consumption): signature, TTL and
            # child binding must already hold at delivery time.
            payload = self._credentials.verify(token, grant="gate_a_submission")
        except CredentialError as error:
            return {"accepted": False, "error": error.as_dict()}
        delivered_child = str(payload.get("child_id") or "")
        if delivered_child != child_id:
            return {
                "accepted": False,
                "error": CredentialError(
                    "BOUND_ID_MISMATCH", details={"required": child_id}
                ).as_dict(),
            }
        if child_id in self._delivered_credentials:
            return {
                "accepted": False,
                "error": {
                    "code": "CREDENTIAL_ALREADY_DELIVERED",
                    "reason": "ALREADY_DELIVERED",
                    "message": "an unconsumed credential is already vaulted for this child_id",
                },
            }
        self._delivered_credentials[child_id] = token
        record_session_event(
            self.store,
            run_id=self.run_id,
            event_type="credentials_delivered",
            payload={
                "reason": f"extension-minted challenger credential vaulted for rlm:{child_id}",
                "session_id": str(params.get("session") or self.run_id)[:128],
            },
        )
        return {"schema_version": "1.0.0", "accepted": True, "child_id": child_id}

    def evidence_attach(self, params: dict[str, Any]) -> dict[str, Any]:
        """Thin model→evidence binding verb (§7.1 ``attach_evidence``).

        Stores the artifact bytes through the existing :class:`ArtifactStore`
        and appends one ``evidence-artifact`` graph node linking the hypothesis
        via ``supports`` — the same storage format every adapter already uses;
        no new format, no elevation (grade stays ``lead``: an attached artifact
        is a claim, not an executed observation).
        """

        from ayran.api.validators import validate_contract
        from ayran.evidence.errors import HYPOTHESIS_NOT_FOUND, SUBMISSION_INVALID, EvidenceError
        from ayran.evidence.load import load_hypothesis
        from ayran.graph.canonical import object_hash, utc_now
        from ayran.graph.ids import new_id
        from ayran.graph.types import AppendCommand, AppendItem
        from ayran.tools.types import ADAPTER_VERSION, ZERO_HASH

        self._require_write(params)
        hypothesis_id = str(params.get("hypothesis_id") or "")
        artifact = params.get("artifact")
        kind = str(params.get("kind") or "text").lower()
        session = str(params.get("session") or self.run_id)
        try:
            if hypothesis_id and load_hypothesis(self.store, hypothesis_id) is None:
                raise EvidenceError(
                    HYPOTHESIS_NOT_FOUND, f"hypothesis {hypothesis_id} was not found"
                )
            if not isinstance(artifact, (str, bytes)) or not artifact:
                raise EvidenceError(
                    SUBMISSION_INVALID, "evidence.attach requires a non-empty artifact payload"
                )
            payload = artifact.encode("utf-8") if isinstance(artifact, str) else artifact
            media_type = {
                "text": "text/plain",
                "json": "application/json",
                "markdown": "text/markdown",
            }.get(kind, "application/octet-stream")
            stored = self.artifact_store.store(
                payload, media_type=media_type, source=f"attach:{hypothesis_id or 'session'}"
            )
            digest = str(stored["content_hash"])
            writer, _session = self._derive_writer(params)
            identity = self.store.stream.get("target_identity")
            target_identity = dict(identity) if isinstance(identity, dict) else {
                "target_id": "tgt_01J00000000000000000000001",
                "source_tree_hash": ZERO_HASH,
                "scope_id": "scp_01J00000000000000000000001",
            }
            created = utc_now()
            evidence: dict[str, Any] = {
                "schema_version": "1.0.0",
                "evidence_id": new_id("evd"),
                "created_at": created,
                "run_id": self.run_id,
                "target_identity": target_identity,
                "artifact_hash": digest,
                "size_bytes": int(stored["size_bytes"]),
                "mime_type": media_type,
                "producer": {"kind": writer["kind"] or "model", "id": str(writer["id"] or f"prime:{session}").lower(), "version": ADAPTER_VERSION},
                "producer_version": ADAPTER_VERSION,
                "input_hashes": [digest],
                "config_hash": ZERO_HASH,
                "fork_identity_hash": None,
                "raw_locator": f"artifacts/{digest.removeprefix('sha256:')}",
                "normalized_locator": f"artifacts/{digest.removeprefix('sha256:')}",
                "evidence_grade": "lead",
                "trust_class": "model_observation",
                "confidence": 1.0,
                "supports": [hypothesis_id] if hypothesis_id else [],
                "refutes": [],
                "redaction": {"profile": "default", "secret_scan_passed": True, "redacted": False},
                "reproduction": {
                    "argv": ["evidence.attach"],
                    # RelativePath contract: anchors are run-root-relative.
                    "working_root": ".",
                    "environment_hash": ZERO_HASH,
                    "expected_result_hash": digest,
                },
                "provenance": [
                    {
                        "provenance_id": new_id("prv"),
                        "source_uri": f"urn:ayran:attach:{hypothesis_id or session}",
                        "source_version": "1.0.0",
                        "raw_hash": digest,
                        "retrieved_at": created,
                        "license_or_terms": "engagement-local",
                        "transformation_lineage": [],
                    }
                ],
                "integrity": {
                    "algorithm": "sha256",
                    "canonicalization": "rfc8785",
                    "content_hash": ZERO_HASH,
                    "excluded_fields": ["integrity.content_hash"],
                },
            }
            evidence["integrity"]["content_hash"] = object_hash(evidence)
            validate_contract("evidence-artifact", evidence)
            command = AppendCommand(
                f"evidence-attach:{evidence['evidence_id']}",
                (AppendItem("evidence-artifact@1.0.0", "evidence_artifact.recorded", evidence),),
                {str(evidence["evidence_id"]): 0},
                {"kind": writer["kind"] or "model", "id": str(writer["id"] or f"prime:{session}").lower(), "version": "1.0.0"},
                ZERO_HASH,
                ADAPTER_VERSION,
                created_at=created,
            )
            acknowledgement = self.store.append(command)
            return {
                "schema_version": "1.0.0",
                "accepted": True,
                "evidence_id": str(evidence["evidence_id"]),
                "hypothesis_id": hypothesis_id,
                "sha256": digest,
                "evidence_grade": "lead",
                "acknowledgement": acknowledgement,
            }
        except EvidenceError as error:
            self._journal_denial(
                "evidence_attach_denied",
                session_id=str(params.get("session") or self.run_id),
                reason=f"{error.code}: {error.message}",
            )
            return error.as_result()

    def evidence_gate_b(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import gate_b

        self._require_write(params)
        obligations = params.get("obligations")
        # Minimal R2 passthrough: the caller identity comes from the same
        # channel-credential mapping as hypotheses.remember (§11.4) so forgery
        # events name the real submitter.
        try:
            caller, _session = self._derive_writer(params)
        except EvidenceError as error:
            self._journal_denial(
                "writer_credential_denied",
                session_id=str(params.get("session") or self.run_id),
                reason=f"{error.code}: {error.message}",
            )
            return error.as_result()
        try:
            return gate_b(
                self.store,
                str(params.get("hypothesis_id") or ""),
                obligations=obligations if isinstance(obligations, dict) else None,
                poc_id=str(params["poc_id"]) if params.get("poc_id") else None,
                profile=str(params.get("profile") or "executable"),
                caller=caller,
            )
        except EvidenceError as error:
            return error.as_result()

    def evidence_dedup_check(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import dedup_check

        self._require_write(params, "graph_read")
        try:
            return dedup_check(self.store, str(params.get("hypothesis_id") or ""))
        except EvidenceError as error:
            return error.as_result()

    def evidence_impact_assess(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import impact_assess

        self._require_write(params)
        assumptions = params.get("assumptions")
        try:
            return impact_assess(
                self.store,
                str(params.get("hypothesis_id") or ""),
                assumptions=assumptions if isinstance(assumptions, dict) else None,
            )
        except EvidenceError as error:
            return error.as_result()

    def evidence_severity_assess(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import severity_assess

        self._require_write(params)
        try:
            return severity_assess(
                self.store,
                str(params.get("hypothesis_id") or ""),
                policy_id=str(params["policy_id"]) if params.get("policy_id") else None,
            )
        except EvidenceError as error:
            return error.as_result()

    def evidence_poc_run(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import poc_run

        action = "test_local" if params.get("execute") else "graph_write"
        if params.get("execute") and not params.get("resource"):
            params = {**params, "resource": "target/src"}
        self._require_write(params, action)
        experiment = params.get("experiment")
        if not isinstance(experiment, dict):
            experiment = {}
        if params.get("execute"):
            experiment = {**experiment, "execute": True}
        recorded = params.get("recorded")
        try:
            return poc_run(
                self.store,
                str(params.get("hypothesis_id") or ""),
                experiment=experiment,
                recorded=recorded if isinstance(recorded, dict) else None,
            )
        except EvidenceError as error:
            return error.as_result()

    def evidence_poc_replay(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import poc_replay

        self._require_write(params, "graph_write")
        recorded = params.get("recorded")
        try:
            return poc_replay(
                self.store,
                str(params.get("poc_id") or ""),
                recorded=recorded if isinstance(recorded, dict) else None,
            )
        except EvidenceError as error:
            return error.as_result()

    def finding_build(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import finding_build

        self._require_write(params)
        try:
            return finding_build(self.store, str(params.get("hypothesis_id") or ""))
        except EvidenceError as error:
            return error.as_result()

    def report_render(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import report_render

        self._require_write(params, "graph_read")
        try:
            return report_render(
                self.store,
                str(params.get("finding_id") or ""),
                fmt=str(params.get("format") or "markdown"),
            )
        except EvidenceError as error:
            return error.as_result()

    def report_lint(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evidence.errors import EvidenceError
        from ayran.evidence.service import report_lint

        self._require_write(params, "graph_read")
        try:
            return report_lint(self.store, str(params.get("finding_id") or ""))
        except EvidenceError as error:
            return error.as_result()

    def _knowledge_root(self, params: dict[str, Any]) -> Path | None:
        raw = params.get("knowledge_root")
        return Path(str(raw)) if raw else None

    def knowledge_list_sources(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.knowledge.errors import KnowledgeError
        from ayran.knowledge.service import list_sources

        self._require_write(params, "graph_read")
        try:
            return list_sources(self._knowledge_root(params), phase=params.get("phase"))
        except KnowledgeError as error:
            return error.as_result()

    def knowledge_ingest(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.knowledge.errors import KnowledgeError
        from ayran.knowledge.service import ingest_source

        self._require_write(params)
        try:
            return ingest_source(
                self._knowledge_root(params),
                str(params.get("source_id") or ""),
                store=self.store,
                artifact_store=self.artifact_store,
            )
        except KnowledgeError as error:
            return error.as_result()

    def knowledge_release(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.knowledge.errors import KnowledgeError
        from ayran.knowledge.service import release_corpus

        self._require_write(params)
        try:
            return release_corpus(
                self._knowledge_root(params),
                str(params.get("version") or "v0.1.0"),
                store=self.store,
            )
        except KnowledgeError as error:
            return error.as_result()

    def knowledge_query(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.knowledge.errors import KnowledgeError
        from ayran.knowledge.service import query_records

        self._require_write(params, "graph_read")
        filters = params.get("filter")
        if not isinstance(filters, dict):
            filters = {}
        # Free-text query (§7.1 search_precedents): case-insensitive substring
        # over the corpus records' text fields — ingested corpus ONLY; the live
        # Solodit POST stays operator-sanctioned-only.
        raw_query = str(params.get("query") or "").strip()
        try:
            result = query_records(
                self._knowledge_root(params),
                record_type=str(params.get("type") or params.get("record_type") or "") or None,
                filters=filters,
            )
            if raw_query:
                needle = raw_query.lower()
                text_fields = ("title", "summary", "mechanism", "protocol", "component", "citation")
                records = [
                    record
                    for record in result["records"]
                    if any(needle in str(record.get(field) or "").lower() for field in text_fields)
                ]
                result = {**result, "records": records, "count": len(records), "query": raw_query}
            return result
        except KnowledgeError as error:
            return error.as_result()

    def knowledge_status(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        from ayran.knowledge.errors import KnowledgeError
        from ayran.knowledge.service import knowledge_status

        payload = params or {}
        self._require_write(payload, "graph_read")
        try:
            return knowledge_status(self._knowledge_root(payload))
        except KnowledgeError as error:
            return error.as_result()

    def knowledge_tombstone(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.knowledge.errors import KnowledgeError
        from ayran.knowledge.service import tombstone_source

        self._require_write(params)
        try:
            return tombstone_source(
                self._knowledge_root(params),
                str(params.get("source_id") or ""),
                str(params.get("reason") or "revoked"),
                store=self.store,
                republish_version=str(params["version"]) if params.get("version") else None,
            )
        except KnowledgeError as error:
            return error.as_result()

    def _learning_root(self, params: dict[str, Any]) -> Path | None:
        raw = params.get("learning_root") or params.get("knowledge_root")
        return Path(str(raw)) / "learning" if raw and params.get("knowledge_root") and not params.get("learning_root") else (
            Path(str(raw)) if raw else None
        )

    def learning_capture(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import capture

        self._require_write(params)
        try:
            return capture(
                str(params.get("run_id") or self.run_id),
                store=self.store,
                outcome_type=str(params.get("outcome_type") or "adjudicated"),
                hypothesis_id=str(params.get("hypothesis_id") or ""),
                gate_verdicts=list(params.get("gate_verdicts") or []) if isinstance(params.get("gate_verdicts"), list) else None,
                tool_runs=list(params.get("tool_runs") or []) if isinstance(params.get("tool_runs"), list) else None,
                artifacts=list(params.get("artifacts") or []) if isinstance(params.get("artifacts"), list) else None,
            )
        except LearningError as error:
            return error.as_result()

    def learning_submit_review(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import submit_review

        self._require_write(params)
        try:
            return submit_review(str(params.get("outcome_id") or ""), store=self.store)
        except LearningError as error:
            return error.as_result()

    def learning_review(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import review

        self._require_write(params)
        try:
            return review(
                str(params.get("candidate_id") or params.get("outcome_id") or ""),
                store=self.store,
                reviewer_id=str(params.get("reviewer_id") or ""),
                reviewer_type=str(params.get("reviewer_type") or "human"),
                verdict=str(params.get("verdict") or ""),
                notes=str(params.get("notes") or ""),
            )
        except LearningError as error:
            return error.as_result()

    def learning_generalize(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import generalize_outcome

        self._require_write(params)
        try:
            return generalize_outcome(
                str(params.get("outcome_id") or ""),
                store=self.store,
                seed=str(params.get("seed") or "0"),
            )
        except LearningError as error:
            return error.as_result()

    def learning_generate_fixtures(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import generate_test_fixtures

        self._require_write(params)
        try:
            return generate_test_fixtures(str(params.get("candidate_id") or ""), store=self.store)
        except LearningError as error:
            return error.as_result()

    def learning_contamination_check(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import contamination_check

        self._require_write(params)
        holdouts = params.get("holdouts")
        try:
            return contamination_check(
                str(params.get("candidate_id") or ""),
                store=self.store,
                holdouts=holdouts if isinstance(holdouts, list) else None,
            )
        except LearningError as error:
            return error.as_result()

    def learning_run_ablation(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import run_ablation

        self._require_write(params)
        try:
            return run_ablation(str(params.get("candidate_id") or ""), store=self.store)
        except LearningError as error:
            return error.as_result()

    def learning_promote(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import promote_candidate

        self._require_write(params)
        try:
            return promote_candidate(
                str(params.get("candidate_id") or ""),
                store=self.store,
                learning_root=self._learning_root(params),
            )
        except LearningError as error:
            return error.as_result()

    def learning_rollback(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import rollback

        self._require_write(params)
        try:
            return rollback(
                str(params.get("release_id") or ""),
                store=self.store,
                learning_root=self._learning_root(params),
            )
        except LearningError as error:
            return error.as_result()

    def learning_status(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        from ayran.learning.errors import LearningError
        from ayran.learning.service import learning_status

        payload = params or {}
        self._require_write(payload, "graph_read")
        try:
            return learning_status(store=self.store, learning_root=self._learning_root(payload))
        except LearningError as error:
            return error.as_result()

    def eval_run(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evaluation.errors import EvaluationError
        from ayran.evaluation.service import run_all, run_arm

        self._require_write(params, "graph_read")
        try:
            arm = params.get("arm")
            seed = int(params["seed"]) if params.get("seed") is not None else None
            results_root = Path(str(params["results_root"])) if params.get("results_root") else None
            evals = Path(str(params["evals"])) if params.get("evals") else None
            knowledge_root = (
                Path(str(params["knowledge_root"])) if params.get("knowledge_root") else None
            )
            learning_root = (
                Path(str(params["learning_root"])) if params.get("learning_root") else None
            )
            if params.get("live") or params.get("preregistration"):
                from ayran.evaluation.service import run_live

                if not results_root:
                    raise EvaluationError("EVALUATION_INVALID", "live eval.run requires results_root")
                prereg = params.get("preregistration")
                targets = params.get("targets")
                if not prereg:
                    from ayran.evaluation.errors import PREREGISTRATION_REQUIRED

                    raise EvaluationError(PREREGISTRATION_REQUIRED, "live eval.run requires preregistration")
                if not targets:
                    raise EvaluationError("EVALUATION_INVALID", "live eval.run requires targets")
                return run_live(
                    preregistration=Path(str(prereg)),
                    targets=Path(str(targets)),
                    results_root=results_root,
                    seed=seed,
                )
            if arm:
                return run_arm(
                    str(arm),
                    seed=seed,
                    results_root=results_root,
                    evals=evals,
                    knowledge_root=knowledge_root,
                    learning_root=learning_root,
                )
            return run_all(
                seed=seed,
                results_root=results_root,
                evals=evals,
                knowledge_root=knowledge_root,
                learning_root=learning_root,
            )
        except EvaluationError as error:
            return error.as_result()

    def eval_adjudicate(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evaluation.errors import EvaluationError
        from ayran.evaluation.service import adjudicate

        self._require_write(params, "graph_read")
        try:
            return adjudicate(
                str(params.get("session") or params.get("session_id") or ""),
                results_root=Path(str(params["results_root"])) if params.get("results_root") else None,
            )
        except EvaluationError as error:
            return error.as_result()

    def eval_results(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.evaluation.errors import EvaluationError
        from ayran.evaluation.service import results

        self._require_write(params, "graph_read")
        try:
            return results(
                str(params.get("session") or params.get("session_id") or ""),
                results_root=Path(str(params["results_root"])) if params.get("results_root") else None,
            )
        except EvaluationError as error:
            return error.as_result()

    def release_build(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.release.errors import ReleaseError
        from ayran.release.service import build

        self._require_write(params)
        try:
            kind = str(params.get("kind") or ("complete" if params.get("complete") else "layer"))
            return build(
                kind,
                destination=Path(str(params["destination"])) if params.get("destination") else None,
                root=Path(str(params["root"])) if params.get("root") else None,
            )
        except ReleaseError as error:
            return error.as_result()

    def release_validate(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.release.errors import ReleaseError
        from ayran.release.service import validate

        self._require_write(params, "graph_read")
        try:
            return validate(str(params.get("path") or ""))
        except ReleaseError as error:
            return error.as_result()

    def release_install(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.release.errors import ReleaseError
        from ayran.release.service import install_release

        self._require_write(params)
        try:
            kind = str(params.get("kind") or ("complete" if params.get("complete") else "layer"))
            return install_release(
                kind=kind,
                prefix=Path(str(params.get("prefix") or "")),
                source=Path(str(params["source"])) if params.get("source") else None,
                prime=Path(str(params["prime"])) if params.get("prime") else None,
                dry_run=bool(params.get("dry_run")),
            )
        except ReleaseError as error:
            return error.as_result()

    def release_rollback(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.release.errors import ReleaseError
        from ayran.release.service import rollback_release

        self._require_write(params)
        try:
            return rollback_release(Path(str(params.get("receipt") or "")))
        except ReleaseError as error:
            return error.as_result()

    def release_uninstall(self, params: dict[str, Any]) -> dict[str, Any]:
        from ayran.release.errors import ReleaseError
        from ayran.release.service import uninstall_release

        self._require_write(params)
        try:
            return uninstall_release(Path(str(params.get("receipt") or "")))
        except ReleaseError as error:
            return error.as_result()

    def authorize(self, params: dict[str, Any]) -> dict[str, Any]:
        """Boundary decision for one Prime tool call (§7.2 row 1).

        Native tool flow: approved calls are NOT intercepted — the response
        carries only ``permitted`` and optional ``reason`` so the stock Prime
        tool_call hook proceeds locally on approval; deny still wins. The
        routed-JSON detour is retired (the skill client speaks RPC directly).
        """
        tool_name = str(params.get("tool_name") or "")
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        if (
            self.scope is not None
            and self.scope.allowed_tools
            and tool_name
            and tool_name not in self.scope.allowed_tools
        ):
            return {
                "permitted": False,
                "reason": f"tool {tool_name!r} is not in the scope allowed_tools list",
                "action": tool_name,
                "resource": ".",
            }
        action, resource = _tool_action(tool_name, arguments)
        if params.get("resource"):
            resource = str(params["resource"])
        if params.get("action"):
            action = str(params["action"])
        if self.policy.classify(action) is None:
            return {
                "permitted": True,
                "reason": "unmapped tool pass-through",
                "action": action,
                "resource": resource,
                "authority": "pass_through",
            }
        decision = self.policy.authorize(action, resource=resource)
        if not decision.permitted:
            reason = _denial_reason(decision)
            self._journal_policy_denial(
                request_type="tool_call",
                action=action,
                resource=resource,
                reason=reason,
                tool_name=tool_name,
            )
        else:
            reason = str(decision.reason)
        return {
            "permitted": decision.permitted,
            "reason": reason,
            "action": action,
            "resource": resource,
            "authority": decision.authority.name.lower(),
        }

    def lifecycle_record(self, params: dict[str, Any]) -> dict[str, Any]:
        event_type = str(params.get("event_type") or "unknown")
        payload = params.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        hashes_only = {key: value for key, value in payload.items() if key.endswith("_hash") or key in {"reason", "session_id"}}
        recorded = record_session_event(
            self.store,
            run_id=self.run_id,
            event_type=event_type,
            payload=hashes_only or {"event_type": event_type},
        )
        self.logger.event(
            "INFO",
            "bridge.lifecycle",
            method=event_type,
            content_hash=recorded["acknowledgement"].get("commit_hash"),
            outcome="recorded",
        )
        return recorded

    def child_register(self, params: dict[str, Any]) -> dict[str, Any]:
        handle = _as_dict(params.get("handle"))
        child_id = str(handle.get("rlm_child_id") or handle.get("child_id") or "")
        self.children[child_id] = {"handle": handle, "status": "running"}
        recorded = record_child(self.store, run_id=self.run_id, status="running", handle=handle)
        return {"registered": True, "child_id": child_id, "record": recorded}

    def child_complete(self, params: dict[str, Any]) -> dict[str, Any]:
        handle = _as_dict(params.get("handle"))
        result = _as_dict(params.get("result"))
        child_id = str(handle.get("rlm_child_id") or handle.get("child_id") or "")
        self.children[child_id] = {"handle": handle, "status": "completed"}
        recorded = record_child(
            self.store, run_id=self.run_id, status="completed", handle=handle, result=result
        )
        return {"completed": True, "child_id": child_id, "record": recorded}

    def child_fail(self, params: dict[str, Any]) -> dict[str, Any]:
        handle = _as_dict(params.get("handle"))
        error = str(params.get("error") or "child failed")
        child_id = str(handle.get("rlm_child_id") or handle.get("child_id") or "")
        self.children[child_id] = {"handle": handle, "status": "error"}
        recorded = record_child(
            self.store, run_id=self.run_id, status="error", handle=handle, error=error
        )
        return {"failed": True, "child_id": child_id, "record": recorded}

    def kernel_detect(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _ = params
        return detect_kernel()

    def graph_query(self, params: dict[str, Any]) -> Any:
        name = str(params.get("name") or "status")
        raw_params = params.get("params")
        query_params = raw_params if isinstance(raw_params, dict) else {}
        if name in {"status", "graph.status"}:
            return self.store.queries.status()
        if name in {"fts", "fts.lookup"}:
            return self.store.queries.fts(str(query_params.get("text") or ""), limit=int(query_params.get("limit") or 50))
        if name in {"entity.get"}:
            return self.store.queries.get_entity(str(query_params.get("object_id") or ""))
        if name in {"neighborhood", "graph.neighborhood"}:
            return self.store.queries.neighborhood(
                str(query_params.get("node_id") or ""),
                hops=int(query_params.get("hops") or 1),
            )
        raise LookupError(name)

    def artifact_get(self, params: dict[str, Any]) -> Any:
        digest = str(params.get("content_hash") or "")
        return self.artifact_store.verify(digest)

    def _registry(self) -> CapabilityRegistry:
        if self._tools_registry is None:
            from ayran.tools.doctor import default_environment
            from ayran.tools.registry import CapabilityRegistry

            self._tools_registry = CapabilityRegistry(environment=default_environment())
        return self._tools_registry

    def tools_list(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        _ = params
        return {
            "schema_version": "1.0.0",
            "capabilities": [item.as_dict() for item in self._registry().list_capabilities()],
        }

    def tools_detect(self, params: dict[str, Any]) -> dict[str, Any]:
        import asyncio

        capability_id = str(params.get("capability_id") or "")
        result = asyncio.run(self._registry().detect(capability_id))
        return result.as_dict()

    def tools_health(self, params: dict[str, Any]) -> dict[str, Any]:
        import asyncio

        capability_id = str(params.get("capability_id") or "")
        result = asyncio.run(self._registry().health(capability_id))
        return result.as_dict()

    def tools_run(self, params: dict[str, Any]) -> dict[str, Any]:
        import asyncio

        from ayran.tools.recording import evidence_from_tool_run, record_tool_run
        from ayran.tools.runner import RunContext, policy_from_scope, run_capability

        capability_id = str(params.get("capability_id") or "")
        payload = params.get("input")
        if not isinstance(payload, dict):
            payload = {}
        action = "compile_local"
        if capability_id in {"foundry.test"} or capability_id.endswith("F0RG000000000000000001"):
            action = "test_local"
        if capability_id in {"solodit.search"} or capability_id.endswith("S0DT000000000000000001"):
            action = "approved_api_query"
        resource = str(params.get("resource") or "target/src")
        decision = self.policy.authorize(action, resource=resource)
        if not decision.permitted:
            return {
                "permitted": False,
                "reason": decision.reason,
                "tool_run": None,
            }
        registry = self._registry()
        resolved = registry.resolve_id(capability_id)
        manifest = registry.manifests[resolved]
        hosts: list[str] = []
        if self.scope is not None:
            hosts = [str(item) for item in self.scope.value.get("allowed_hosts") or []]
        policy = policy_from_scope(
            manifest=manifest,
            allowed_hosts=hosts,
            allow_install=bool(self.config.allow_install),
            offline=bool(self.config.offline),
            scope_hash=self.scope.hash if self.scope is not None else "sha256:" + "0" * 64,
        )
        identity = self.store.stream.get("target_identity")
        if not isinstance(identity, dict):
            identity = {
                "target_id": "tgt_01J00000000000000000000001",
                "source_tree_hash": "sha256:" + "d" * 64,
                "scope_id": "scp_01J00000000000000000000001",
            }
        context = RunContext(
            run_id=self.run_id,
            target_identity=identity,
            artifact_store=self.artifact_store,
            retries_from=str(params["retries_from"]) if params.get("retries_from") else None,
        )
        result = asyncio.run(
            run_capability(
                registry,
                capability_id,
                payload,
                policy=policy,
                context=context,
                require_available=True,
            )
        )
        tool_run = result["tool_run"]
        evidence = None
        if result.get("parsed") is not None and tool_run.get("artifact_refs"):
            digest = tool_run["artifact_refs"][-1]
            evidence = evidence_from_tool_run(
                tool_run,
                normalized_hash=digest,
                size_bytes=1,
                grade=str(tool_run.get("evidence_ceiling") or "lead"),
            )
        acknowledgement = record_tool_run(
            self.store,
            tool_run,
            evidence=evidence,
        )
        result["acknowledgement"] = acknowledgement
        result["permitted"] = True
        return result


def load_run_scope(run_root: Path) -> ScopeManifest | None:
    for name in ("scope.json", "scope-manifest.json"):
        path = run_root / name
        if path.is_file():
            return load_scope(path)
    return None


def build_dispatcher(
    *,
    run_id: str,
    config: EffectiveConfig,
    store: GraphStore,
    logger: StructuredLogger,
    artifact_store: ArtifactStore,
    process_supervisor: ProcessSupervisor,
    receipt: dict[str, Any],
    state_root: Path,
    run_root: Path,
    shutdown_callback: Callable[[], None] | None = None,
    credentials: CredentialAuthority | None = None,
) -> BridgeDispatcher:
    scope = load_run_scope(run_root)
    policy = PolicyEngine(scope, config=config)
    dispatcher = BridgeDispatcher(
        run_id=run_id,
        config=config,
        store=store,
        logger=logger,
        artifact_store=artifact_store,
        process_supervisor=process_supervisor,
        receipt=receipt,
        scope=scope,
        policy=policy,
        state_root=state_root,
        run_root=run_root,
        shutdown_callback=shutdown_callback,
        _credentials=credentials,
    )
    # §11.2: isolation verification runs at startup; failure is fail-closed for
    # cognitive verbs (they re-check before the first cognitive call).
    probe = dispatcher.run_isolation_probe()
    logger.event(
        "INFO" if probe.get("verified") else "WARN",
        "bridge.isolation_probe",
        mode=probe.get("mode"),
        verified=bool(probe.get("verified")),
        refusals=";".join(probe.get("refusals") or []) or None,
    )
    return dispatcher
