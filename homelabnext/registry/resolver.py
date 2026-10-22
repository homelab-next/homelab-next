# SPDX-License-Identifier: Apache-2.0
"""Capability endpoint resolver.

``resolve("lake-query")`` answers with an :class:`Endpoint`. Order of
consultation, first definitive answer wins:

1. **env override**  ``HNX_ENDPOINT_<CAPABILITY>`` (or the service's own
   ``env_var``) holding a full URL. For staging, tests, and break-glass.
2. **registry**      supplies the *shape*: scheme, port and the alias name
   ``<capability>.<svc_label>.<domain>``.
3. **DNS**           must answer for the alias (A/AAAA). Without a registry
   the SRV record ``_<capability>._tcp.<alias zone>`` supplies target and
   port, and a ``scheme=`` TXT record the scheme.
4. **hosts file**    fallback when DNS does not answer for the alias.

The URL always names the alias, never an address, so swapping the product
behind a capability changes DNS only. If nothing answers the resolver raises
:class:`ResolutionError`; it never falls back to a literal host or port.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from .dns import DNSBackend, SystemDNS, read_hosts
from .model import Registry, env_var_name


class ResolutionError(Exception):
    """A capability could not be resolved. ``trail`` records what was tried."""

    def __init__(self, capability: str, message: str, trail: list[str] | None = None):
        self.capability = capability
        self.trail = list(trail or [])
        detail = "".join(f"\n  tried: {t}" for t in self.trail)
        super().__init__(f"cannot resolve capability {capability!r}: {message}{detail}")


class UnknownCapability(ResolutionError):
    pass


class InvalidOverride(ResolutionError):
    pass


@dataclass(frozen=True)
class Endpoint:
    capability: str
    scheme: str
    host: str
    port: int
    source: str  # env | dns | hosts

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def hostport(self) -> str:
        return f"{self.host}:{self.port}"

    def __str__(self) -> str:
        return self.url


# the registry's protocols, plus ``tls`` for an override only: NATS over TLS (``tls://host:port``)
_VALID_SCHEMES = {"http", "https", "grpc", "tcp", "udp", "postgres", "nats", "tls", "dns", "ssh"}


def parse_override(capability: str, var: str, value: str) -> Endpoint:
    parts = urlsplit(value.strip())
    if parts.scheme not in _VALID_SCHEMES or not parts.hostname:
        raise InvalidOverride(capability, f"{var}={value!r} is not a scheme://host:port URL")
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        raise InvalidOverride(capability, f"{var}={value!r} has no explicit port")
    return Endpoint(capability, parts.scheme, parts.hostname, port, "env")


class Resolver:
    def __init__(
        self,
        registry: Registry | None = None,
        *,
        domain: str | None = None,
        svc_label: str = "svc",
        dns: DNSBackend | None = None,
        hosts: Mapping[str, list[str]] | None = None,
        environ: Mapping[str, str] | None = None,
    ):
        if registry is None and domain is None:
            raise ValueError("Resolver needs a registry or an explicit domain")
        self.registry = registry
        self.zone = registry.alias_zone if registry else f"{svc_label}.{domain}"
        self.dns = dns if dns is not None else SystemDNS()
        self._hosts = hosts
        self.environ = environ if environ is not None else os.environ

    def _hosts_map(self) -> Mapping[str, list[str]]:
        return self._hosts if self._hosts is not None else read_hosts()

    def alias(self, capability: str) -> str:
        return f"{capability}.{self.zone}"

    def resolve(self, capability: str) -> Endpoint:
        trail: list[str] = []
        svc = self.registry.by_capability(capability) if self.registry else None
        if self.registry and svc is None:
            raise UnknownCapability(
                capability, "not in the registry", [f"registry ({self.registry.digest[:12]})"]
            )
        var = svc.endpoint_env_var if svc else env_var_name(capability)
        value = self.environ.get(var)
        if value is not None and value.strip() == "":
            raise InvalidOverride(capability, f"{var} is set but empty")
        if value is not None:
            return parse_override(capability, var, value)
        trail.append(f"env {var} (unset)")
        alias = self.alias(capability)
        if svc is not None:
            trail.append(f"registry (scheme={svc.scheme} port={svc.port})")
            return self._resolve_name(capability, svc.scheme, svc.port, alias, trail)
        return self._resolve_srv(capability, alias, trail)

    def _resolve_name(
        self, capability: str, scheme: str, port: int, alias: str, trail: list[str]
    ) -> Endpoint:
        if self.dns.lookup_host(alias):
            return Endpoint(capability, scheme, alias, port, "dns")
        trail.append(f"dns A/AAAA {alias} (no answer)")
        if self._hosts_map().get(alias.lower()):
            return Endpoint(capability, scheme, alias, port, "hosts")
        trail.append(f"hosts file {alias} (no entry)")
        raise ResolutionError(
            capability,
            f"alias {alias} does not resolve; set the override env var or publish the alias",
            trail,
        )

    def _resolve_srv(self, capability: str, alias: str, trail: list[str]) -> Endpoint:
        srv_name = f"_{capability}._tcp.{self.zone}"
        rec = self.dns.lookup_srv(srv_name)
        if rec is None:
            trail.append(f"dns SRV {srv_name} (no answer)")
            trail.append("registry (none loaded; hosts file cannot supply a port)")
            raise ResolutionError(capability, "no registry loaded and no SRV record", trail)
        target, port = rec
        scheme = None
        for txt in self.dns.lookup_txt(srv_name):
            if txt.startswith("scheme="):
                scheme = txt.split("=", 1)[1]
        if scheme not in _VALID_SCHEMES:
            trail.append(f"dns TXT {srv_name} scheme= (missing or invalid: {scheme!r})")
            raise ResolutionError(capability, "SRV found but no valid scheme= TXT record", trail)
        return Endpoint(capability, scheme, target.rstrip("."), port, "dns")


def resolve(capability: str, **kwargs) -> Endpoint:
    """Convenience: build a Resolver from keyword arguments and resolve."""
    return Resolver(**kwargs).resolve(capability)
