"""Blocking owner-only JSON-RPC client with per-run bearer authentication.

The client reads the bearer directly from the file descriptor the service or
launcher provided (never from an environment-secret value) and presents it in
each request's ``params.token`` field; the socket itself enforces the peer is
the same uid, so cross-user connection fails before application parsing.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

from . import protocol


class ClientError(RuntimeError):
    def __init__(self, error: dict[str, Any]) -> None:
        self.error = error
        self.code = error.get("details", {}).get("code") or error.get("code")
        super().__init__(str(error))


class AyranClient:
    def __init__(
        self,
        socket_path: Path,
        *,
        token_fd: int | None = None,
        token_bytes: bytes | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.socket_path = socket_path
        self.timeout = timeout
        self._token_bytes: bytes
        if token_fd is not None:
            descriptor = os.dup(token_fd)
            try:
                self._token_bytes = os.read(descriptor, 1024)
            finally:
                os.close(descriptor)
        elif token_bytes is not None:
            self._token_bytes = token_bytes
        else:
            raise ValueError("either token_fd or token_bytes must be provided")

    def call(self, method: str, **params: Any) -> Any:
        params = dict(params)
        params["token"] = self._token_bytes.decode("utf-8")
        request = protocol.encode_request(method, params, request_id=None)
        with socket.socket(getattr(socket, "AF_UNIX", 1), socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(str(self.socket_path))
            connection.sendall(request)
            buffer = b""
            while b"\n" not in buffer:
                chunk = connection.recv(65536)
                if not chunk:
                    raise ClientError({"code": -32603, "message": "service closed connection without responding"})
                buffer += chunk
        response = protocol.parse_frame(buffer.split(b"\n", 1)[0])
        if "error" in response:
            raise ClientError(response["error"])
        return response.get("result")
