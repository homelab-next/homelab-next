# SPDX-License-Identifier: Apache-2.0
"""A client for a running broker's Unix socket (:mod:`homelabnext.broker.server`).

``BrokerClient(socket_path)`` sends one request per connection and returns the result, or
raises the broker contract's exception (:class:`~conformance.protocols.broker.Denied`,
:class:`~conformance.protocols.broker.InvalidArguments` or
:class:`~conformance.protocols.broker.BrokerError`) with the broker's machine ``reason``.  It
never sends an identity: the broker takes it from this process's credentials.  The CLI
(``hnx broker ... --socket``), the broker MCP server and the hub's approvals page use it.

Stdlib only.  ``timeout_s`` bounds connecting and the whole exchange; keep it above the longest
handler timeout of the actions you run.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Mapping
from typing import Any

from conformance.protocols.broker import BrokerError, Denied, InvalidArguments

__all__ = ["DEFAULT_CLIENT_TIMEOUT_S", "MAX_RESPONSE_BYTES", "BrokerClient"]

DEFAULT_CLIENT_TIMEOUT_S = 600.0
MAX_RESPONSE_BYTES = 64 << 20


def _raise(response: Mapping[str, Any]) -> None:
    reason = str(response.get("error") or "broker-error")
    message = str(response.get("message") or reason)
    kind = response.get("kind")
    if kind == "Denied":
        raise Denied(message, reason=reason)
    err = InvalidArguments(message) if kind == "InvalidArguments" else BrokerError(message)
    err.reason = reason  # type: ignore[attr-defined]
    raise err


class BrokerClient:
    """One broker socket.  Every method is one request (see the server's protocol table)."""

    def __init__(
        self, socket_path: str | os.PathLike[str], *, timeout_s: float = DEFAULT_CLIENT_TIMEOUT_S
    ) -> None:
        self.socket_path = os.fspath(socket_path)
        self.timeout_s = timeout_s

    def request(self, op: str, **fields: Any) -> Any:
        """Send ``{"v": 1, "op": op, **fields}`` (None fields dropped); the result or raise."""
        body = {"v": 1, "op": op, **{k: v for k, v in fields.items() if v is not None}}
        data = json.dumps(body, sort_keys=True).encode("utf-8") + b"\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout_s)
            try:
                sock.connect(self.socket_path)
                try:
                    sock.sendall(data)
                    sock.shutdown(socket.SHUT_WR)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the broker answered without reading (busy, a stranger): read it
                raw = self._receive(sock)
            except OSError as exc:  # TimeoutError included
                err = BrokerError(f"broker socket {self.socket_path}: {exc.strerror or exc}")
                err.reason = "transport-error"  # type: ignore[attr-defined]
                raise err from None
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            response = None
        if not isinstance(response, dict) or "ok" not in response:
            err = BrokerError("the broker sent no valid response")
            err.reason = "transport-error"  # type: ignore[attr-defined]
            raise err
        if not response["ok"]:
            _raise(response)
        return response.get("result")

    @staticmethod
    def _receive(sock: socket.socket) -> bytes:
        chunks, size = [], 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise OSError("response too large")
            chunks.append(chunk)
        return b"".join(chunks)

    # ---------------------------------------------------------------- a caller (an agent)
    def actions(self) -> dict[str, Any]:
        """``{caller, actions}``: what this peer may ask for, from the manifest."""
        return self.request("actions")

    def call(
        self, action: str, params: Mapping[str, Any] | None = None, *, target: str | None = None
    ) -> Any:
        return self.request("call", action=action, params=dict(params or {}), target=target)[
            "result"
        ]

    def submit(
        self, action: str, params: Mapping[str, Any] | None = None, *, target: str | None = None
    ) -> dict[str, Any]:
        """``{request_id, state, awaiting_approval}``."""
        return self.request("submit", action=action, params=dict(params or {}), target=target)

    def status(self, request_id: str) -> dict[str, Any]:
        return self.request("status", request_id=request_id)

    def run(self, request_id: str) -> Any:
        return self.request("run", request_id=request_id)["result"]

    def cancel(self, request_id: str) -> dict[str, Any]:
        return self.request("cancel", request_id=request_id)

    def pending_for_me(self) -> list[dict[str, Any]]:
        return self.request("pending-for-me")["requests"]

    # ---------------------------------------------------------------- an approval relay
    def approve(
        self, request_id: str, issuer: str, subject: str, *, note: str | None = None
    ) -> dict[str, Any]:
        """File an approval for the human ``issuer``/``subject`` this relay authenticated."""
        return self.request(
            "approve",
            request_id=request_id,
            approver={"issuer": issuer, "subject": subject},
            note=note,
        )

    def deny(
        self, request_id: str, issuer: str, subject: str, *, note: str | None = None
    ) -> dict[str, Any]:
        return self.request(
            "deny",
            request_id=request_id,
            approver={"issuer": issuer, "subject": subject},
            note=note,
        )

    def pending(self) -> list[dict[str, Any]]:
        """Every request awaiting an approver (relay only)."""
        return self.request("pending")["requests"]

    def audit(self, *, tail: int = 50, **match: str | None) -> list[dict[str, Any]]:
        """The last ``tail`` audit records matching ``match`` (relay only)."""
        return self.request("audit", tail=tail, **match)["records"]
