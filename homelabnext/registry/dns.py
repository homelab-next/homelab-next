# SPDX-License-Identifier: Apache-2.0
"""DNS and hosts-file backends for the resolver, plus a fake for tests."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


class DNSBackend(Protocol):
    def lookup_host(self, name: str) -> list[str]:
        """A/AAAA answers for ``name``; empty list when it does not resolve."""

    def lookup_srv(self, name: str) -> tuple[str, int] | None:
        """(target, port) of the best SRV record, or None."""

    def lookup_txt(self, name: str) -> list[str]:
        """TXT strings, or an empty list."""


class SystemDNS:
    """Real resolver: ``getaddrinfo`` for addresses. The standard library has
    no SRV/TXT client, so those return nothing (SERVER-only: use a DNS library
    adapter in the deployment image)."""

    def lookup_host(self, name: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return []
        return sorted({i[4][0] for i in infos})

    def lookup_srv(self, name: str) -> tuple[str, int] | None:
        return None

    def lookup_txt(self, name: str) -> list[str]:
        return []


@dataclass
class FakeDNS:
    """In-memory DNS used by tests. Records every query for assertions."""

    a: dict[str, list[str]] = field(default_factory=dict)
    srv: dict[str, tuple[str, int]] = field(default_factory=dict)
    txt: dict[str, list[str]] = field(default_factory=dict)
    queries: list[tuple[str, str]] = field(default_factory=list)

    def lookup_host(self, name: str) -> list[str]:
        self.queries.append(("A", name))
        return list(self.a.get(name.rstrip(".").lower(), []))

    def lookup_srv(self, name: str) -> tuple[str, int] | None:
        self.queries.append(("SRV", name))
        return self.srv.get(name.rstrip(".").lower())

    def lookup_txt(self, name: str) -> list[str]:
        self.queries.append(("TXT", name))
        return list(self.txt.get(name.rstrip(".").lower(), []))


def parse_hosts(text: str) -> dict[str, list[str]]:
    """Parse hosts(5) text into name -> [addresses] (names lower-cased)."""
    out: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        addr, names = parts[0], parts[1:]
        for n in names:
            out.setdefault(n.lower(), []).append(addr)
    return out


def read_hosts(path: str | Path = "/etc/hosts") -> dict[str, list[str]]:
    try:
        return parse_hosts(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return {}
