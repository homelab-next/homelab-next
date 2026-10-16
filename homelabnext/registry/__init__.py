# SPDX-License-Identifier: Apache-2.0
"""Service registry: format, loader and capability resolver."""

from .dns import FakeDNS, SystemDNS, parse_hosts, read_hosts
from .model import Host, Registry, RegistryError, Service, Zone, env_var_name, load, loads
from .resolver import (
    Endpoint,
    InvalidOverride,
    ResolutionError,
    Resolver,
    UnknownCapability,
    resolve,
)

__all__ = [
    "Endpoint",
    "FakeDNS",
    "Host",
    "InvalidOverride",
    "Registry",
    "RegistryError",
    "ResolutionError",
    "Resolver",
    "Service",
    "SystemDNS",
    "UnknownCapability",
    "Zone",
    "env_var_name",
    "load",
    "loads",
    "parse_hosts",
    "read_hosts",
    "resolve",
]
