# SPDX-License-Identifier: Apache-2.0
"""Shared guards for the stdlib HTTP clients (notify, events forwarder, OpenAI-compatible adapter).

* :func:`check_plaintext` refuses to send credentials over plain ``http`` to a host that is not
  loopback unless the caller passed ``allow_plaintext=True`` (the same rule as
  :class:`homelabnext.lake.trino.TrinoLake`).
* :func:`safe_opener` follows a redirect only to the same scheme, host and port, so an
  ``Authorization`` header is never replayed to another origin and https is never downgraded.
* :func:`read_bounded` reads at most ``limit`` bytes and refuses a longer reply instead of
  buffering whatever a server chooses to send.
"""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_MAX_BYTES = 1 << 20  # 1 MiB


class ResponseTooLarge(ValueError):
    """The server sent more than the caller's limit."""


def is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_plaintext(url: str, *, credentials: bool, allow_plaintext: bool) -> None:
    """ValueError when ``url`` is plain http to a non-loopback host and credentials would go."""
    parts = urllib.parse.urlsplit(url)
    if (
        credentials
        and parts.scheme == "http"
        and not allow_plaintext
        and not is_loopback(parts.hostname)
    ):
        raise ValueError(
            f"refusing to send credentials over plaintext http to {parts.hostname}: "
            "use https or pass allow_plaintext=True explicitly"
        )


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlsplit(url)
    default = {"http": 80, "https": 443}.get(p.scheme)
    return p.scheme, (p.hostname or "").lower(), p.port or default


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only within the same scheme, host and port; refuse anything else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        target = urllib.parse.urljoin(req.full_url, newurl)
        if _origin(target) != _origin(req.full_url):
            raise urllib.error.HTTPError(
                req.full_url, code, f"refusing cross-origin redirect ({msg})", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(SameOriginRedirectHandler)


def safe_urlopen(req: Any, timeout: float | None = None) -> Any:
    """Drop-in for ``urllib.request.urlopen`` with :class:`SameOriginRedirectHandler`."""
    return safe_opener().open(req, timeout=timeout)


def read_bounded(resp: Any, limit: int = DEFAULT_MAX_BYTES) -> bytes:
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise ResponseTooLarge(f"response larger than {limit} bytes")
    return data
