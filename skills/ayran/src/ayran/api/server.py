"""Owner-only Unix-domain JSON-RPC ayrand service.

The server binds one run-scoped socket path inside the ext4 runtime directory,
enforces owner socket permission (``SO_PEERCRED`` pid must match the current
uid), and requires the run bearer token on every request.  No network
transfer, no model code execution, and no response body carries the token.
"""

from __future__ import annotations

import contextlib
import hmac
import os
import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ayran.runtime.logs import StructuredLogger

from . import protocol


@dataclass(slots=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def read_peer_credentials(connection: socket.socket) -> PeerCredentials:
    raw = connection.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED", 17), struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


class ServiceErrorCode:
    PERMISSION_DENIED = "PERMISSION_DENIED"
    METHOD_NOT_FOUND = "METHOD_NOT_FOUND"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    INTERNAL_INVARIANT_BROKEN = "INTERNAL_INVARIANT_BROKEN"
    STORE_BUSY = "STORE_BUSY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class AyranServer:
    """Owner-only UDS server with bearer auth, one frame per line."""

    def __init__(
        self,
        socket_path: Path,
        *,
        token: bytes,
        logger: StructuredLogger,
        handler: Callable[[str, dict[str, Any], PeerCredentials], Any],
        run_id: str,
    ) -> None:
        self.socket_path = socket_path
        self.token = token
        self.logger = logger
        self.handler = handler
        self.run_id = run_id
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._listen: socket.socket | None = None
        self.expected_uid = getattr(os, "getuid", lambda: os.getpid())()

    def _bind(self) -> socket.socket:
        if self.socket_path.exists():
            raise SystemExit(f"socket path already exists: {self.socket_path}")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        server = socket.socket(getattr(socket, "AF_UNIX", 1), socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(16)
        server.settimeout(0.2)
        return server

    def _verify_peer(self, connection: socket.socket) -> PeerCredentials:
        credentials = read_peer_credentials(connection)
        if credentials.uid != self.expected_uid:
            self.logger.event(
                "WARN",
                "service.rejected_non_owner_peer",
                pid=credentials.pid,
                terminated_by="owner_uid_mismatch",
            )
            raise PermissionError("peer uid does not match the service owner")
        return credentials

    def _verify_token(self, params: dict[str, Any]) -> None:
        token = params.pop("token", None)
        if not isinstance(token, str) or not token:
            raise PermissionError("run bearer token is required")
        if not hmac.compare_digest(token.encode("utf-8"), self.token):
            raise PermissionError("run bearer token mismatch")

    def serve_forever(self) -> None:
        server = self._bind()
        self._listen = server
        self.logger.event("INFO", "service.listening", path_role="service_socket", run_state="starting")
        try:
            while not self._stop.is_set():
                try:
                    connection, _peer_addr = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                thread = threading.Thread(target=self._serve_connection, args=(connection,), daemon=True)
                thread.start()
        finally:
            server.close()
            self.logger.event("INFO", "service.stopped", run_state="stopped")

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name=f"ayrand-{self.run_id}", daemon=True)
        thread.start()
        self._thread = thread
        return thread

    def stop(self) -> None:
        self._stop.set()
        if self._listen is not None:
            with contextlib.suppress(OSError):
                self._listen.close()
            self._listen = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        with contextlib.suppress(OSError):
            self.socket_path.unlink(missing_ok=True)

    def _serve_connection(self, connection: socket.socket) -> None:
        connection.settimeout(5)
        try:
            credentials = self._verify_peer(connection)
        except PermissionError:
            connection.sendall(protocol.encode_error(protocol.AUTHENTICATION_REQUIRED, None))
            connection.close()
            return
        with connection:
            buffer = b""
            while True:
                try:
                    chunk = connection.recv(65536)
                except (TimeoutError, ConnectionResetError):
                    return
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    raw_line, buffer = buffer.split(b"\n", 1)
                    self._handle_frame(connection, raw_line + b"\n", credentials)

    def _handle_frame(self, connection: socket.socket, raw: bytes, credentials: PeerCredentials) -> None:
        started = time.monotonic()
        request_id: Any = None
        method: str = ""
        try:
            frame = protocol.parse_frame(raw)
            request_id = frame.get("id") if isinstance(frame, dict) else None
            method = frame.get("method", "") if isinstance(frame, dict) else ""
            if not isinstance(frame, dict) or frame.get("jsonrpc") != "2.0":
                raise protocol.ProtocolError(protocol.INVALID_REQUEST)
            params = frame.get("params", {})
            if not isinstance(params, dict):
                raise protocol.ProtocolError(protocol.INVALID_PARAMS)
            self._verify_token(params)
            try:
                result = self.handler(method, params, credentials)
            except LookupError as error:
                raise protocol.ProtocolError(
                    {**protocol.METHOD_NOT_FOUND, "details": {"code": ServiceErrorCode.METHOD_NOT_FOUND}}
                ) from error
            connection.sendall(protocol.encode_result(result, request_id))
            duration_ms = int((time.monotonic() - started) * 1000)
            self.logger.event(
                "INFO",
                "service.request",
                operation_id=frame.get("id") if isinstance(frame, dict) else None,
                method=method,
                outcome="success",
                duration_ms=duration_ms,
            )
        except protocol.ProtocolError as error:
            connection.sendall(protocol.encode_error(error.error, request_id))
            self.logger.error("service.request_error", error, method=method or None)
        except PermissionError as error:
            connection.sendall(
                protocol.encode_error(
                    {
                        "code": -32603,
                        "message": str(error),
                        "retryable": False,
                        "details": {"code": ServiceErrorCode.PERMISSION_DENIED},
                    },
                    request_id,
                )
            )
            self.logger.error("service.request_error", error, method=method or None)
        except Exception as error:
            # Unexpected exceptions become INTERNAL_INVARIANT_BROKEN; the client
            # never sees a raw traceback.
            connection.sendall(
                protocol.encode_error(
                    {
                        "code": -32603,
                        "message": f"{type(error).__name__}: {str(error)[:128]}",
                        "retryable": False,
                        "details": {"code": ServiceErrorCode.INTERNAL_INVARIANT_BROKEN},
                    },
                    request_id,
                )
            )
            self.logger.error("service.internal_error", error, method=method or None)
