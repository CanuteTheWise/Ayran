"""Adapter protocol, argv/env/path safety, and bounded executable/HTTP runtimes.

Adapters never invoke a shell.  A successful exit code is not evidence: parsers
and the capability evidence ceiling decide semantics.  Secrets never appear in
returned environment maps; only hashes are retained.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel

from ayran.graph.canonical import sha256_bytes, utc_now
from ayran.tools.errors import (
    PARSER_FAILED,
    PRIVACY_REJECTED,
    SYMLINK_ESCAPE,
    UNAVAILABLE,
    ToolError,
)
from ayran.tools.types import (
    ALLOWLISTED_ENV,
    DEFAULT_OUTPUT_CAP_BYTES,
    TRUNCATED_MARKER,
    CleanupResult,
    DetectionResult,
    Environment,
    ExecutionPolicy,
    HealthResult,
    InstallPlan,
    RawRun,
)

HttpTransport = Callable[[str, str, bytes | None, dict[str, str], int], "HttpResponse"]


def mapping_of(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class HttpResponse:
    def __init__(self, status: int, body: bytes, headers: Mapping[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = dict(headers or {})


class ToolAdapter(Protocol):
    manifest: dict[str, Any]
    alias: str

    async def detect(self, env: Environment) -> DetectionResult: ...

    async def health(self, env: Environment) -> HealthResult: ...

    async def plan_install(self, env: Environment) -> InstallPlan: ...

    async def run(self, request: BaseModel, policy: ExecutionPolicy) -> RawRun: ...

    def parse(self, raw: RawRun) -> BaseModel: ...

    async def cleanup(self, run: RawRun) -> CleanupResult: ...


def bytes_hash(payload: bytes) -> str:
    return sha256_bytes(payload)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def unique_hashes(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in values:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def env_fingerprint(env: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    for key in sorted(env):
        value = env[key]
        digest.update(key.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(hashlib.sha256(value.encode("utf-8")).digest())
        digest.update(b"\x00")
    return "sha256:" + digest.hexdigest()


def hashed_environment(env: Mapping[str, str]) -> list[dict[str, str]]:
    entries = [
        {"name": key, "value": "sha256:" + hashlib.sha256(env[key].encode("utf-8")).hexdigest()}
        for key in sorted(env)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", key)
    ]
    entries.append({"name": "ENV_FINGERPRINT", "value": env_fingerprint(env)})
    return entries[:64]


def filter_env(
    source: Mapping[str, str] | None,
    *,
    extra_allowlist: Sequence[str] = (),
    overlay: Mapping[str, str] | None = None,
) -> dict[str, str]:
    allow = {item.upper() for item in ALLOWLISTED_ENV}
    allow.update(item.upper() for item in extra_allowlist)
    incoming = dict(os.environ if source is None else source)
    if overlay:
        incoming.update(overlay)
    filtered: dict[str, str] = {}
    for key, value in incoming.items():
        if key.upper() not in allow:
            continue
        if any(marker in key.upper() for marker in ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "PRIVATE")):
            continue
        filtered[key] = value
    if "LC_ALL" not in filtered and "LC_ALL" in allow:
        filtered["LC_ALL"] = "C"
    return filtered


def build_argv(template: Sequence[str], substitutions: Mapping[str, str | Sequence[str]]) -> list[str]:
    """Expand ``{placeholders}`` in an argv template.  Never returns a shell string."""

    if not template:
        raise ToolError("CONTRACT_INVALID", "argv template must not be empty")
    argv: list[str] = []
    for item in template:
        if not isinstance(item, str) or "\x00" in item or "\n" in item or "\r" in item:
            raise ToolError("CONTRACT_INVALID", "argv template items must be single-line strings")
        if item.startswith("{") and item.endswith("}") and len(item) > 2 and item.count("{") == 1:
            key = item[1:-1]
            if key not in substitutions:
                raise ToolError("CONTRACT_INVALID", f"argv placeholder {item!r} is unbound")
            value = substitutions[key]
            if isinstance(value, str):
                _reject_unsafe_arg(value)
                argv.append(value)
            else:
                for part in value:
                    _reject_unsafe_arg(part)
                    argv.append(part)
            continue
        argv.append(item)
    if not argv:
        raise ToolError("CONTRACT_INVALID", "expanded argv must not be empty")
    return argv


def _reject_unsafe_arg(value: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ToolError("CONTRACT_INVALID", "argv substitution is empty or contains control characters")


def _under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_executable(
    argv0: str,
    *,
    env: Environment,
    path_env: str | None,
) -> Path:
    if not argv0 or "\x00" in argv0:
        raise ToolError("CONTRACT_INVALID", "argv[0] is empty or contains NUL")
    override = env.which_override.get(argv0)
    candidate = Path(override) if override else Path(argv0)
    if not candidate.is_absolute():
        found = shutil.which(argv0, path=path_env)
        if found is None:
            raise ToolError(UNAVAILABLE, f"executable {argv0!r} was not found on PATH", details={"argv0": argv0})
        candidate = Path(found)
    return reject_symlink_escape(candidate, env.allowed_binary_roots)


def reject_symlink_escape(path: Path, allowed_roots: tuple[Path, ...]) -> Path:
    """Resolve ``path`` and reject a symlink that escapes allowed roots or ``/mnt``."""

    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        if current.is_symlink():
            resolved_parent = current.resolve()
            if _is_drvfs(resolved_parent):
                raise ToolError(
                    SYMLINK_ESCAPE,
                    "executable realpath resolves onto DrvFS; WSL Linux tools must stay on ext4",
                    details={"path": str(path), "resolved": str(resolved_parent)},
                )
            if allowed_roots and not any(
                _under_root(resolved_parent, root.resolve(strict=False)) for root in allowed_roots
            ):
                raise ToolError(
                    SYMLINK_ESCAPE,
                    "symlink escapes the allowed binary roots",
                    details={"path": str(path), "resolved": str(resolved_parent)},
                )
    if not path.exists():
        raise ToolError(UNAVAILABLE, f"executable {path} does not exist")
    real = path.resolve(strict=True)
    if _is_drvfs(real):
        raise ToolError(
            SYMLINK_ESCAPE,
            "executable realpath resolves onto DrvFS; WSL Linux tools must stay on ext4",
            details={"path": str(path), "resolved": str(real)},
        )
    if allowed_roots and not any(
        _under_root(real, root.resolve(strict=False)) for root in allowed_roots
    ):
        raise ToolError(
            SYMLINK_ESCAPE,
            f"executable {path} resolves outside allowed binary roots",
            details={"resolved": str(real)},
        )
    return real


def _is_drvfs(path: Path) -> bool:
    posix = path.as_posix().replace("\\", "/")
    lowered = posix.lower()
    return bool(lowered.startswith("/mnt/") or re.match(r"^[a-z]:/", lowered))


def _terminate_group(handle: subprocess.Popen[bytes], pgid: int | None) -> None:
    if os.name == "nt":
        handle.terminate()
        return
    if pgid is None:
        handle.terminate()
        return
    try:
        _killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, AttributeError):
        handle.terminate()


def _killpg(pgid: int, signum: int) -> None:
    killer = getattr(os, "killpg", None)
    if killer is None:
        return
    killer(pgid, signum)


def _kill_group(handle: subprocess.Popen[bytes], pgid: int | None) -> None:
    if os.name == "nt":
        handle.kill()
        return
    if pgid is None:
        handle.kill()
        return
    try:
        _killpg(pgid, int(getattr(signal, "SIGKILL", 9)))
    except (ProcessLookupError, PermissionError, AttributeError):
        handle.kill()


def _group_absent(pgid: int | None, pid: int | None) -> bool:
    if os.name == "nt" or pgid is None:
        return True
    try:
        _killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        pass
    if pid is None or not Path("/proc").exists():
        return False
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            stat_path = Path("/proc") / name / "stat"
            try:
                text = stat_path.read_text(encoding="utf-8")
                closing = text.rindex(")")
                fields = text[closing + 2 :].split()
                if len(fields) > 4 and int(fields[4]) == pgid:
                    return False
            except (OSError, ValueError, IndexError):
                continue
    except OSError:
        return False
    return True


def invoke_executable(
    argv: Sequence[str],
    *,
    cwd: Path | None,
    env: Mapping[str, str],
    timeout_seconds: int,
    max_output_bytes: int = DEFAULT_OUTPUT_CAP_BYTES,
    graceful_stop_seconds: float = 2,
    input_paths: Sequence[Path] = (),
    extra_output_files: Sequence[Path] = (),
) -> RawRun:
    """Run ``argv`` in a new process group with bounded output and a hard timeout."""

    if not argv:
        raise ToolError("CONTRACT_INVALID", "argv must not be empty")
    started = utc_now()
    with tempfile.NamedTemporaryFile(prefix="ayran-stdout-", suffix=".spool", delete=False) as stdout_spool:
        stdout_path = Path(stdout_spool.name)
    with tempfile.NamedTemporaryFile(prefix="ayran-stderr-", suffix=".spool", delete=False) as stderr_spool:
        stderr_path = Path(stderr_spool.name)
    truncated = {"stdout": False, "stderr": False}
    try:
        handle = subprocess.Popen(
            list(argv),
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        ended = utc_now()
        empty = b""
        return RawRun(
            argv=list(argv),
            cwd=str(cwd) if cwd else None,
            env_fingerprint=env_fingerprint(env),
            started_at=started,
            ended_at=ended,
            exit_code=None,
            signal=None,
            stdout=empty,
            stderr=str(error).encode("utf-8", errors="replace"),
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_hash=bytes_hash(empty),
            stderr_hash=bytes_hash(str(error).encode("utf-8", errors="replace")),
            output_file_hashes={},
            input_hashes=[file_sha256(path) for path in input_paths if path.is_file()],
            executable_hash=None,
            timeout=False,
            failure_type="prerequisite",
            extra={"spawn_error": type(error).__name__},
        )
    pgid: int | None
    try:
        pgid = os.getpgid(handle.pid) if hasattr(os, "getpgid") else None
    except (OSError, AttributeError):
        pgid = None

    def _drain(stream: Any, destination: Path, label: str) -> None:
        written = 0
        with destination.open("wb") as out:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                if truncated[label]:
                    continue
                remaining = max_output_bytes - written
                if remaining <= 0:
                    out.write(TRUNCATED_MARKER)
                    truncated[label] = True
                    continue
                if len(chunk) > remaining:
                    out.write(chunk[:remaining])
                    out.write(TRUNCATED_MARKER)
                    truncated[label] = True
                    written = max_output_bytes
                else:
                    out.write(chunk)
                    written += len(chunk)

    assert handle.stdout is not None
    assert handle.stderr is not None
    threads = [
        threading.Thread(target=_drain, args=(handle.stdout, stdout_path, "stdout"), daemon=True),
        threading.Thread(target=_drain, args=(handle.stderr, stderr_path, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        handle.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_group(handle, pgid)
        time.sleep(max(0.05, graceful_stop_seconds))
        if handle.poll() is None:
            _kill_group(handle, pgid)
            handle.wait(timeout=5)
        if os.name != "nt" and not _group_absent(pgid, handle.pid):
            _kill_group(handle, pgid)
    for thread in threads:
        thread.join(timeout=5)
    ended = utc_now()
    stdout = stdout_path.read_bytes() if stdout_path.is_file() else b""
    stderr = stderr_path.read_bytes() if stderr_path.is_file() else b""
    code = handle.returncode
    signal_name: str | None = None
    if code is not None and code < 0:
        signal_name = str(-code)
    output_hashes: dict[str, str] = {}
    for extra in extra_output_files:
        if extra.is_file():
            output_hashes[str(extra)] = file_sha256(extra)
    executable_hash = None
    try:
        executable_hash = file_sha256(Path(argv[0]))
    except OSError:
        executable_hash = None
    failure: Any = None
    if timed_out:
        failure = "timeout"
    return RawRun(
        argv=list(argv),
        cwd=str(cwd) if cwd else None,
        env_fingerprint=env_fingerprint(env),
        started_at=started,
        ended_at=ended,
        exit_code=code,
        signal=signal_name,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=truncated["stdout"],
        stderr_truncated=truncated["stderr"],
        stdout_hash=bytes_hash(stdout),
        stderr_hash=bytes_hash(stderr),
        output_file_hashes=output_hashes,
        input_hashes=unique_hashes([file_sha256(path) for path in input_paths if path.is_file()]),
        executable_hash=executable_hash,
        timeout=timed_out,
        failure_type=failure,
        truncated=truncated["stdout"] or truncated["stderr"],
    )


def default_install_plan(manifest: Mapping[str, Any], alias: str, *, enabled: bool, reason: str) -> InstallPlan:
    resources = mapping_of(manifest.get("resources"))
    return InstallPlan(
        capability_id=str(manifest.get("capability_id")),
        alias=alias,
        tool=alias.split(".", 1)[0],
        version=str(manifest.get("version")),
        source="official",
        enabled=enabled,
        expected_artifact_hash=None,
        install_prefix="~/.local/share/ayran/tools",
        disk_mib=int(resources.get("disk_mib") or 0),
        memory_mib=int(resources.get("memory_mib") or 64),
        cpu=int(resources.get("cpu") or 1),
        network=str(resources.get("network") or "none"),
        dependency_conflicts=[],
        rollback_plan="restore the previous current pointer from the install receipt; remove only receipt-listed paths",
        cleanup_plan="delete receipt-owned prefix paths after verifying they remain inside the tool prefix",
        drvfs_warning=None,
        free_ext4_mib=None,
        blocked_reason=None if enabled else reason,
    )


class ExecutableAdapter:
    """Base class for solc, Foundry, and Slither adapters."""

    alias: str = ""
    extra_env_allowlist: tuple[str, ...] = ()
    request_type: type[BaseModel] = BaseModel

    def __init__(self, manifest: dict[str, Any], *, environment: Environment | None = None) -> None:
        self.manifest = manifest
        self.environment = environment or Environment()

    def expected_version(self) -> str:
        return str(self.manifest.get("version") or "")

    def timeout_seconds(self) -> int:
        return int(self.manifest.get("timeout_seconds") or 60)

    def detect_parser_name(self) -> str:
        detect = mapping_of(self.manifest.get("detect"))
        return str(detect.get("parser") or "")

    def parse_version(self, output: str) -> str | None:
        match = re.search(r"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)", output)
        return match.group(1) if match else None

    def version_compatible(self, observed: str, expected: str) -> bool:
        obs = observed.split("+", 1)[0].split("-", 1)[0]
        exp = expected.split("+", 1)[0].split("-", 1)[0]
        return obs == exp or obs.startswith(exp.rsplit(".", 1)[0] + ".")

    async def detect(self, env: Environment) -> DetectionResult:
        detect = mapping_of(self.manifest.get("detect"))
        template = detect.get("argv")
        if not isinstance(template, list) or not template:
            return DetectionResult(
                self.manifest["capability_id"],
                self.alias,
                "unavailable_broken",
                None,
                None,
                None,
                None,
                None,
                "detect.argv is missing",
            )
        path_env = env.path or os.environ.get("PATH")
        try:
            resolved = resolve_executable(str(template[0]), env=env, path_env=path_env)
        except ToolError as error:
            status: Any = "unavailable_not_found" if error.code == UNAVAILABLE else "unavailable_broken"
            if error.code == SYMLINK_ESCAPE:
                status = "unavailable_broken"
            return DetectionResult(
                self.manifest["capability_id"],
                self.alias,
                status,
                None,
                None,
                None,
                None,
                None,
                error.message,
            )
        filtered = filter_env(os.environ, extra_allowlist=self.extra_env_allowlist, overlay=_env_overlay(env))
        argv = [str(resolved), *[str(item) for item in template[1:]]]
        raw = invoke_executable(argv, cwd=None, env=filtered, timeout_seconds=15, max_output_bytes=65536)
        output = (raw.stdout or b"") + b"\n" + (raw.stderr or b"")
        text = output.decode("utf-8", errors="replace")
        version = self.parse_version(text)
        executable_hash = raw.executable_hash
        if raw.exit_code not in {0, None} and version is None:
            return DetectionResult(
                self.manifest["capability_id"],
                self.alias,
                "unavailable_broken",
                str(resolved),
                str(resolved),
                version,
                bytes_hash(output),
                executable_hash,
                f"detect exited {raw.exit_code}",
            )
        if version is None:
            return DetectionResult(
                self.manifest["capability_id"],
                self.alias,
                "unavailable_broken",
                str(resolved),
                str(resolved),
                None,
                bytes_hash(output),
                executable_hash,
                "version parser produced no version string",
            )
        expected = self.expected_upstream_version()
        status_name: Any = (
            "available" if self.version_compatible(version, expected) else "unavailable_wrong_version"
        )
        return DetectionResult(
            self.manifest["capability_id"],
            self.alias,
            status_name,
            str(resolved),
            str(resolved),
            version,
            bytes_hash(output),
            executable_hash,
            f"observed {version}, expected {expected}",
        )

    def expected_upstream_version(self) -> str:
        return str(self.manifest.get("version") or "0.0.0")

    async def health(self, env: Environment) -> HealthResult:
        detected = await self.detect(env)
        healthy = detected.status == "available"
        return HealthResult(
            detected.capability_id,
            detected.alias,
            detected.status,
            healthy,
            detected.detail,
            detected.version,
        )

    async def plan_install(self, env: Environment) -> InstallPlan:
        _ = env
        return default_install_plan(
            self.manifest,
            self.alias,
            enabled=False,
            reason="controlled installation is disabled by default; adapters never mutate existing tools",
        )

    async def cleanup(self, run: RawRun) -> CleanupResult:
        removed: list[str] = []
        if run.working_copy:
            copy_path = Path(run.working_copy)
            if copy_path.is_dir() and "ayran-tool-copy-" in copy_path.name:
                shutil.rmtree(copy_path, ignore_errors=True)
                removed.append(str(copy_path))
        return CleanupResult(removed, list(run.output_file_hashes), "run-scoped copies removed")

    def parse(self, raw: RawRun) -> BaseModel:
        raise ToolError(PARSER_FAILED, f"{self.alias} parser is not implemented")

    async def run(self, request: BaseModel, policy: ExecutionPolicy) -> RawRun:
        raise ToolError("CONTRACT_INVALID", f"{self.alias} run is not implemented")


def _env_overlay(env: Environment) -> dict[str, str]:
    overlay: dict[str, str] = {}
    if env.path:
        overlay["PATH"] = env.path
    if env.home:
        overlay["HOME"] = str(env.home)
    if env.tmpdir:
        overlay["TMPDIR"] = str(env.tmpdir)
        overlay["TEMP"] = str(env.tmpdir)
        overlay["TMP"] = str(env.tmpdir)
    overlay.update(env.extra_env)
    return overlay


class HttpAdapter:
    """Bounded HTTP adapter used by Solodit.  Never logs request bodies with identifiers."""

    alias: str = ""
    request_type: type[BaseModel] = BaseModel
    default_endpoint = "https://solodit.cyfrin.io"
    max_response_bytes = 10 * 1024 * 1024
    qps = 1.0
    max_queries_per_engagement = 20

    def __init__(
        self,
        manifest: dict[str, Any],
        *,
        environment: Environment | None = None,
        transport: HttpTransport | None = None,
    ) -> None:
        self.manifest = manifest
        self.environment = environment or Environment()
        self.transport = transport
        self._last_request = 0.0
        self._query_count = 0
        self._lock = threading.Lock()

    def endpoint(self, env: Environment | None = None) -> str:
        current = env or self.environment
        return (current.solodit_endpoint or self.default_endpoint).rstrip("/")

    def _rate_limit(self) -> None:
        with self._lock:
            if self._query_count >= self.max_queries_per_engagement:
                raise ToolError("network", "Solodit engagement query budget exhausted")
            wait = (self._last_request + (1.0 / self.qps)) - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()
            self._query_count += 1

    def http_get(self, url: str, *, timeout: int, headers: dict[str, str] | None = None) -> HttpResponse:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ToolError(PRIVACY_REJECTED, "HTTP adapter only allows http(s) URLs")
        hdrs = {"User-Agent": "ayran-solodit-adapter/1.0", "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        if self.transport is not None:
            return self.transport("GET", url, None, hdrs, timeout)
        request = urllib.request.Request(url, headers=hdrs, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(getattr(response, "status", 200))
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise ToolError("network", "HTTP response exceeded the 10 MiB cap")
                    chunks.append(chunk)
                header_map = {str(key): str(value) for key, value in response.headers.items()}
                return HttpResponse(status, b"".join(chunks), header_map)
        except urllib.error.HTTPError as error:
            body = error.read()[: self.max_response_bytes]
            return HttpResponse(int(error.code), body, dict(error.headers.items()) if error.headers else {})
        except urllib.error.URLError as error:
            raise ToolError("network", f"HTTP request failed: {error.reason}") from error

    async def detect(self, env: Environment) -> DetectionResult:
        if env.probe_http is False:
            return DetectionResult(
                self.manifest["capability_id"],
                self.alias,
                "unverified",
                None,
                None,
                None,
                None,
                None,
                f"HTTP health check deferred; endpoint {self.endpoint(env)}",
            )
        try:
            response = self.http_get(self.endpoint(env), timeout=min(3, int(self.manifest.get("timeout_seconds") or 30)))
        except ToolError as error:
            return DetectionResult(
                self.manifest["capability_id"],
                self.alias,
                "unavailable_broken",
                None,
                None,
                None,
                None,
                None,
                error.message,
            )
        status_name: Any = "available" if response.status < 500 else "unavailable_broken"
        if response.status >= 400 and response.status < 500:
            status_name = "unverified"
        return DetectionResult(
            self.manifest["capability_id"],
            self.alias,
            status_name,
            self.endpoint(env),
            self.endpoint(env),
            "api-v1",
            bytes_hash(response.body[:4096]),
            None,
            f"HTTP {response.status}",
        )

    async def health(self, env: Environment) -> HealthResult:
        probed = Environment(
            path=env.path,
            home=env.home,
            tmpdir=env.tmpdir,
            extra_env=env.extra_env,
            allowed_binary_roots=env.allowed_binary_roots,
            extra_env_allowlist=env.extra_env_allowlist,
            solodit_endpoint=env.solodit_endpoint,
            probe_http=True,
            which_override=env.which_override,
        )
        detected = await self.detect(probed)
        return HealthResult(
            detected.capability_id,
            detected.alias,
            detected.status,
            detected.status == "available",
            detected.detail,
            detected.version,
        )

    async def plan_install(self, env: Environment) -> InstallPlan:
        _ = env
        return default_install_plan(
            self.manifest,
            self.alias,
            enabled=False,
            reason="Solodit is an HTTP API; there is no local installer",
        )

    async def cleanup(self, run: RawRun) -> CleanupResult:
        _ = run
        return CleanupResult([], [], "HTTP adapter holds no process tree")

    def parse(self, raw: RawRun) -> BaseModel:
        raise ToolError(PARSER_FAILED, f"{self.alias} parser is not implemented")

    async def run(self, request: BaseModel, policy: ExecutionPolicy) -> RawRun:
        raise ToolError("CONTRACT_INVALID", f"{self.alias} run is not implemented")
