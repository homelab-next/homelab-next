# SPDX-License-Identifier: Apache-2.0
"""Senders: an in-memory fake for tests and an ntfy-style HTTP publisher (stdlib only)."""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from homelabnext._http import check_plaintext, safe_urlopen

from .core import Message, SendError

_TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_EMAIL_RE = re.compile(r"^[^\s@<>,;]+@[^\s@<>,;]+$")


class FakeSender:
    """Records every message; ``fail_next`` makes the next ``send`` raise (for retry tests)."""

    def __init__(self) -> None:
        self.sent: list[Message] = []
        self.fail_next = 0

    def send(self, message: Message) -> None:
        if self.fail_next > 0:
            self.fail_next -= 1
            raise SendError("fake sender configured to fail")
        self.sent.append(message)

    @property
    def titles(self) -> list[str]:
        return [m.title for m in self.sent]


def _header(value: str) -> str:
    """One header-safe line: no CR/LF (injection) and latin-1 encodable."""
    one_line = " ".join(value.split())
    return one_line.encode("latin-1", "replace").decode("latin-1")


class NtfySender:
    """POST ``<endpoint>/<topic>`` with ntfy headers (Title, Priority, Tags, Email, Click).

    ``endpoint`` is resolved at send time and is never a default literal: pass a callable
    returning a base URL (or an object with ``.url``), or leave it ``None`` to resolve the
    ``notify`` capability through the ``resolver`` you pass (a ``homelabnext.registry.Resolver``),
    else the ``HNX_ENDPOINT_NOTIFY`` override, else an error.
    ``auth`` is an optional callable returning an ``Authorization`` header value, read at send
    time so the secret never sits in this object's repr or logs.  A token is never sent over
    plain ``http`` to a non-loopback host unless ``allow_plaintext=True``; redirects are followed
    only within the same origin.
    """

    def __init__(
        self,
        endpoint: Callable[[], Any] | Any | None = None,
        *,
        default_topic: str | None = None,
        auth: Callable[[], str | None] | None = None,
        opener: Callable[..., Any] | None = None,
        timeout: float = 10.0,
        capability: str = "notify",
        resolver: Any | None = None,
        allow_plaintext: bool = False,
    ):
        self._endpoint = endpoint
        self.allow_plaintext = allow_plaintext
        self._resolver = resolver
        self.default_topic = default_topic
        self._auth = auth
        self._opener = opener if opener is not None else safe_urlopen
        self.timeout = timeout
        self.capability = capability

    def __repr__(self) -> str:
        return f"NtfySender(capability={self.capability!r}, default_topic={self.default_topic!r})"

    def base_url(self) -> str:
        ep = self._endpoint
        if ep is None:
            ep = self._resolve_capability()
        elif callable(ep):
            ep = ep()
        url = getattr(ep, "url", ep)
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise SendError(f"notify endpoint is not an http(s) URL: {url!r}")
        return url.rstrip("/")

    def _resolve_capability(self) -> Any:
        """No explicit endpoint: ask the resolver, else the env override, else refuse."""
        from homelabnext.registry import ResolutionError, env_var_name
        from homelabnext.registry.resolver import parse_override

        if self._resolver is not None:
            return self._resolver.resolve(self.capability)
        var = env_var_name(self.capability)
        value = os.environ.get(var)
        if value:
            return parse_override(self.capability, var, value)
        raise ResolutionError(
            self.capability,
            "no endpoint, resolver or environment override configured (never defaulted)",
            [f"env {var} (unset)"],
        )

    def build_request(self, message: Message) -> urllib.request.Request:
        topic = message.topic or self.default_topic
        if not topic or not _TOPIC_RE.match(topic):
            raise SendError(f"invalid or missing topic {topic!r}")
        headers = {
            "Title": _header(message.title),
            "Priority": str(message.effective_priority),
            "Content-Type": "text/plain; charset=utf-8",
        }
        if message.tags:
            headers["Tags"] = _header(",".join(message.tags))
        if message.email:
            if not _EMAIL_RE.match(message.email):
                raise SendError("invalid email target")
            headers["Email"] = _header(message.email)
        if message.click:
            headers["Click"] = _header(message.click)
        base = self.base_url()
        if self._auth is not None:
            token = self._auth()
            if token:
                try:
                    check_plaintext(base, credentials=True, allow_plaintext=self.allow_plaintext)
                except ValueError as exc:
                    raise SendError(str(exc)) from None
                headers["Authorization"] = _header(token)
        return urllib.request.Request(
            f"{base}/{topic}",
            data=message.body.encode("utf-8"),
            headers=headers,
            method="POST",
        )

    def send(self, message: Message) -> None:
        req = self.build_request(message)
        try:
            resp = self._opener(req, timeout=self.timeout)
        except (urllib.error.URLError, OSError) as exc:
            raise SendError(f"notify delivery failed: {type(exc).__name__}") from exc
        status = getattr(resp, "status", getattr(resp, "code", 200))
        close = getattr(resp, "close", None)
        if close:
            close()
        if not (200 <= int(status) < 300):
            raise SendError(f"notify endpoint answered HTTP {status}")
