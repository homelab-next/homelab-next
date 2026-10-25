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
        err: BrokerError = Denied(message, reason=reason)
    else:
        err = InvalidArguments(message) if kind == "InvalidArguments" else BrokerError(message)
        err.reason = reason  # type: ignore[attr-defined]
    for field in ("request_id", "request_digest"):  # the request a refusal was about, if built
        if isinstance(response.get(field), str):
            setattr(err, field, response[field])
    raise err


class BrokerClient:
    """One broker socket.  Every method is one request (see the server's protocol table)."""

    def __init__(
        self, socket_path: str | os.PathLike[str], *, timeout_s: float = DEFAULT_CLIENT_TIMEOUT_S
    ) -> None:
        self.socket_path = os.fspath(socket_path)
        self.timeout_s = timeout_s

    def request(self, op: str, *, bearer: str | None = None, **fields: Any) -> Any:
        """Send ``{"v": 1, "op": op, **fields}`` (None fields dropped); the result or raise.
        ``bearer`` (a sandbox's Code Mode token) goes as its own line ahead of the body, never
        inside it."""
        body = {"v": 1, "op": op, **{k: v for k, v in fields.items() if v is not None}}
        data = json.dumps(body, sort_keys=True).encode("utf-8") + b"\n"
        if bearer is not None:
            if "\n" in bearer or not bearer.startswith("hnxcmt_"):
                raise BrokerError("a bearer is one line, a Code Mode token")
            data = bearer.encode("ascii") + b"\n" + data
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

    # ---------------------------------------------------------------- Code Mode (manifest 1.7)
    def token_issue(
        self,
        request_id: str,
        *,
        sandbox_id: str,
        actions: list[str],
        max_calls: int | None = None,
        ttl_s: int | None = None,
    ) -> dict[str, Any]:
        """``{secret, claims}``: a token for the running ``codemode.execute`` (runner only)."""
        return self.request(
            "token-issue",
            request_id=request_id,
            sandbox_id=sandbox_id,
            actions=list(actions),
            max_calls=max_calls,
            ttl_s=ttl_s,
        )

    def token_spend(self, token_id: str, outcome: str = "finished") -> dict[str, Any]:
        return self.request("token-spend", token_id=token_id, outcome=outcome)

    def token_status(self, token_id: str) -> dict[str, Any]:
        return self.request("token-status", token_id=token_id)

    def token_call(
        self,
        token: str,
        action: str,
        params: Mapping[str, Any] | None = None,
        *,
        target: str | None = None,
    ) -> dict[str, Any]:
        """A call made with a token (sandbox only), as the token's actor: ``{result, request_id,
        request_digest}``, or ``{state: pending, ...}`` when it needs approval (the token is
        paused)."""
        fields = {"action": action, "params": dict(params or {}), "target": target}
        return self.request("token-call", bearer=token, **fields)

    def token_submit(
        self,
        token: str,
        action: str,
        params: Mapping[str, Any] | None = None,
        *,
        target: str | None = None,
    ) -> dict[str, Any]:
        """``{state: pending, request_id, request_digest}``: the token is paused from here on."""
        fields = {"action": action, "params": dict(params or {}), "target": target}
        return self.request("token-submit", bearer=token, **fields)

    def token_run(self, token: str, request_id: str) -> dict[str, Any]:
        """Run the request an earlier token of the execution paused on, once approved
        (sandbox only): ``{result, request_id, request_digest}``."""
        return self.request("token-run", bearer=token, request_id=request_id)
