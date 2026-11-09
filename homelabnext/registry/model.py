# SPDX-License-Identifier: Apache-2.0
"""Registry data model, loader and validation for ``services.yml``.

Validation has two layers: the JSON Schema (``schemas/platform/service.json``,
shape) and :func:`semantic_problems` (cross references and uniqueness).
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths, sops, tlp
from homelabnext._schema_text import safe_message
from homelabnext._yaml import ExpansionRefused, UniqueKeyLoader
from homelabnext.capability_names import platform_capabilities as _platform_capabilities


class RegistryError(Exception):
    """The registry file is unreadable, malformed or inconsistent."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        detail = "".join(f"\n  - {p}" for p in self.problems)
        super().__init__(message + detail)


class RegistryUnreadable(RegistryError):
    """The registry file cannot be read, decrypted or parsed: bad input, not an invalid registry."""


class _RegistryLoader(UniqueKeyLoader):
    """The registry's YAML reader: duplicate keys refused and every document held to the shared
    expansion budget (:class:`homelabnext._yaml.UniqueKeyLoader`), and no alias at all: a
    registry is plain data (no example uses one), so an alias is refused outright rather than
    expanded."""

    allow_aliases = False


# homelabnext.swap.flip reads the registry through it too
_UniqueKeyLoader = _RegistryLoader


@dataclass(frozen=True)
class Zone:
    name: str
    cidr: str
    description: str = ""


@dataclass(frozen=True)
class Host:
    name: str
    address: str
    zone: str
    role: str = ""


@dataclass(frozen=True)
class Service:
    name: str
    capability: str
    host: str
    protocol: str
    port: int
    owner: str
    version: str
    tls: str
    impl: str = ""
    health: dict = field(default_factory=lambda: {"kind": "none"})
    metrics: dict | None = None
    upstreams: tuple[str, ...] = ()
    clients: tuple[str, ...] = ()
    auth: str = "none"
    public_hostname: str | None = None
    backup_job: str | None = None
    env_var: str | None = None
    mcp: dict | None = None
    tags: tuple[str, ...] = ()
    status_sources: tuple[dict, ...] = ()
    front_door: dict | None = None
    description: str = ""  # 2.4: one line, informational (the generated maps)
    #: 2.7: the group-to-role table of single sign-on (ADR-0034): role -> the IdP groups holding it
    roles: dict = field(default_factory=dict)
    #: 2.8: the TLP ceiling of what an egress service receives (ADR-0033), or None (undeclared)
    tlp_ceiling: str | None = None
    #: 2.9: the row's standing among its capability's rows (ADR-0039): one of :data:`STANDINGS`
    standing: str = "primary"
    #: 2.9: a non-primary row's date (YYYY-MM-DD) and its one-line reason
    until: str | None = None
    why: str = ""
    #: 2.9: the capability whose data this row serves from a second place, or None
    replica_of: str | None = None

    @property
    def is_primary(self) -> bool:
        return self.standing == "primary"

    @property
    def scheme(self) -> str:
        """URL scheme a client should use (``tls`` upgrades http to https)."""
        if self.protocol in ("http", "https"):
            return (
                "https"
                if (self.protocol == "https" or self.tls in ("internal", "public", "mtls"))
                else "http"
            )
        return self.protocol

    @property
    def endpoint_env_var(self) -> str:
        """A primary's override variable is its capability's; an eval or retiring row's is its
        own row name's (ADR-0039 decision 2), so it can never claim the capability's."""
        return self.env_var or env_var_name(self.capability if self.is_primary else self.name)

    @property
    def answers_by(self) -> str | None:
        """The alias-zone label this row answers by (ADR-0039 decision 2): a primary its
        capability, an ``eval`` or ``retiring`` row its own row name, a ``legacy`` row none."""
        if self.is_primary:
            return self.capability
        if self.standing in ANSWERING_TIERS:
            return self.name
        return None


#: the capabilities whose row may declare a ``tlp_ceiling`` (2.8): a service data leaves the lab's
#: stores to, so what it receives has a ceiling (ADR-0033 decisions 6 and 13)
EGRESS_CAPABILITIES = frozenset({"notify", "events", "backup", "webhook"})


#: 2.9: a row's standing (ADR-0039 decision 1); absent ``standing`` means ``primary``
STANDINGS = ("primary", "eval", "retiring", "legacy")
#: the non-primary tiers that answer by their own row name (ADR-0039 decision 2); a ``legacy``
#: row answers by no name, as the old lab serves its own
ANSWERING_TIERS = ("eval", "retiring")

#: 2.9: a capability name carries no tier (ADR-0039 decision 5): these endings are refused, and
#: the replica endings are refused without ``replica_of``
_TIER_SUFFIX = re.compile(r"-(?:legacy|old|new|next|eval|test|candidate|v[0-9]+)$")
_REPLICA_SUFFIX = re.compile(r"-(?:secondary|tertiary|replica)$")


def standing_of(s: Mapping[str, Any]) -> str:
    """The standing of a service document: its ``standing.tier``, else ``primary``."""
    return (s.get("standing") or {}).get("tier", "primary")


def row_name_label(sname: str, s: Mapping[str, Any]) -> str | None:
    """The DNS label and endpoint-variable stem a row answers by (ADR-0039 decision 2): a
    primary by its capability, an ``eval`` or ``retiring`` row by its own row name, and a
    ``legacy`` row by nothing (the old lab serves its own name)."""
    tier = standing_of(s)
    if tier == "primary":
        return s["capability"]
    if tier in ANSWERING_TIERS:
        return sname
    return None


def env_var_name(capability: str) -> str:
    """Default environment variable overriding a capability endpoint."""
    return "HNX_ENDPOINT_" + capability.upper().replace("-", "_")


@dataclass(frozen=True)
class Registry:
    lab_name: str
    domain: str
    svc_label: str
    owner: str
    zones: dict[str, Zone]
    hosts: dict[str, Host]
    #: the rows consumers see: the primaries only (ADR-0039 decision 2)
    services: dict[str, Service]
    digest: str
    #: 2.9: the eval, retiring and legacy rows, validated and held back from every consumer that
    #: does not ask for them: a generator or reader that may see a tier reads it through
    #: :meth:`rows` or :meth:`row`, naming the tiers ADR-0039 decision 2 gives it
    non_primary: dict[str, Service] = field(default_factory=dict)

    @property
    def alias_zone(self) -> str:
        return f"{self.svc_label}.{self.domain}"

    def alias(self, capability: str) -> str:
        return f"{capability}.{self.alias_zone}"

    def by_capability(self, capability: str) -> Service | None:
        """The capability's primary, or None: never another tier (ADR-0039 decision 2)."""
        for svc in self.services.values():
            if svc.capability == capability and svc.is_primary:
                return svc
        return None

    def address_of(self, svc: Service) -> str:
        """The alias-zone name ``svc`` answers by: a primary's capability alias, an ``eval`` or
        ``retiring`` row's row-name record (ADR-0039 decision 2).  A ``legacy`` row has none."""
        label = svc.answers_by
        if label is None:
            raise ValueError(f"{svc.name} is a {svc.standing} row: it answers by no name")
        return self.alias(label)

    def rows(self, *tiers: str) -> list[Service]:
        """The rows whose standing is one of ``tiers``, sorted by name.  Each generator and
        reader that widens past the primaries names the tiers ADR-0039 decision 2 gives it;
        there is no default, so no caller reaches a non-primary row by leaving one out."""
        unknown = sorted(set(tiers) - set(STANDINGS))
        if unknown or not tiers:
            raise ValueError(f"rows() needs tiers from {list(STANDINGS)}, not {unknown or 'none'}")
        every = {**self.non_primary, **self.services}
        return [every[k] for k in sorted(every) if every[k].standing in tiers]

    def row(self, name: str, *tiers: str) -> Service | None:
        """The row named ``name`` if its standing is one of ``tiers``, else None (a by-name
        lookup: the caller names the tiers it may reach)."""
        return next((s for s in self.rows(*tiers) if s.name == name), None)

    def host_of(self, svc: Service) -> Host:
        return self.hosts[svc.host]

    def sorted_services(self) -> list[Service]:
        return [self.services[k] for k in sorted(self.services)]


def schema() -> dict:
    return json.loads(paths.schema_file("platform", "service.json").read_text(encoding="utf-8"))


def schema_problems(doc: Any) -> list[str]:
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema())
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"schema: {where}: {safe_message(err)}")
    return out


_V4_MAPPED = ipaddress.IPv6Network("::ffff:0:0/96")


def semantic_problems(doc: dict) -> list[str]:
    """Cross-reference and uniqueness checks. Assumes the schema already passed."""
    problems: list[str] = []
    zones = doc["zones"]
    hosts = doc["hosts"]
    services = doc["services"]
    nets = {}
    for zname, z in zones.items():
        try:
            net = ipaddress.ip_network(z["cidr"], strict=True)
        except ValueError as exc:
            problems.append(f"zone {zname}: bad cidr {z['cidr']!r}: {exc}")
            continue
        # an IPv4-mapped IPv6 zone (::ffff:0:0/96) names IPv4 addresses a second time, so it
        # would get past the overlap and duplicate-address checks below
        if net.version == 6 and net.subnet_of(_V4_MAPPED):
            problems.append(f"zone {zname}: cidr {net} is IPv4-mapped; use the IPv4 cidr")
            continue
        nets[zname] = net
    named = sorted(nets.items())
    for i, (za, na) in enumerate(named):
        for zb, nb in named[i + 1 :]:
            # an IPv4 and an IPv6 network never overlap (ipaddress returns False across families)
            if na.overlaps(nb):
                problems.append(f"zone {zb}: cidr {nb} overlaps zone {za} ({na})")
    seen_addr: dict[ipaddress.IPv4Address | ipaddress.IPv6Address, str] = {}
    for hname, h in hosts.items():
        if h["zone"] not in zones:
            problems.append(f"host {hname}: unknown zone {h['zone']!r}")
        try:
            ip = ipaddress.ip_address(h["address"])
        except ValueError:
            problems.append(f"host {hname}: bad address {h['address']!r}")
            continue
        if ip.version == 6 and ip.ipv4_mapped is not None:
            problems.append(
                f"host {hname}: address {h['address']} is IPv4-mapped; use {ip.ipv4_mapped}"
            )
            continue
        # compared as addresses, not strings: two spellings of one IPv6 address (2001:db8::1 and
        # 2001:db8:0::1) are the same host address
        if ip in seen_addr:
            problems.append(f"host {hname}: address {h['address']} already used by {seen_addr[ip]}")
        seen_addr[ip] = hname
        net = nets.get(h["zone"])
        if net is not None and ip not in net:
            problems.append(
                f"host {hname}: address {h['address']} is outside zone {h['zone']} ({net})"
            )
    caps: set[str] = {s["capability"] for s in services.values()}
    # 2.9 (ADR-0039 decision 1): at most one primary per capability; "provided" means "has a
    # primary", so a capability whose only rows are non-primary fails closed
    primaries: dict[str, list[str]] = {}
    for sname, s in services.items():
        if standing_of(s) == "primary":
            primaries.setdefault(s["capability"], []).append(sname)
    for cap, names in primaries.items():
        if len(names) > 1:
            count = "two" if len(names) == 2 else str(len(names))
            problems.append(f"capability {cap} has {count} primaries: {', '.join(names)}")
    primary = {cap: services[names[0]] for cap, names in primaries.items()}
    problems += _standing_problems(services, primary)
    ports: dict[tuple[str, int, str], str] = {}
    pubs: dict[str, str] = {}
    mcps: dict[str, str] = {}
    for sname, s in services.items():
        if s["host"] not in hosts:
            problems.append(f"service {sname}: unknown host {s['host']!r}")
        l4 = "udp" if s["protocol"] in ("udp", "dns") else "tcp"
        key = (s["host"], s["port"], l4)
        if key in ports:
            problems.append(
                f"service {sname}: port {s['port']}/{l4} on {s['host']} already used by {ports[key]}"
            )
        ports[key] = sname
        pub = s.get("public_hostname")
        if pub:
            if pub in pubs:
                problems.append(
                    f"service {sname}: public_hostname {pub!r} already used by {pubs[pub]}"
                )
            pubs[pub] = sname
            # the same rule a module's rows meet (modules/rules.py): the edge publishes the
            # site, so a row with no login of its own and no IdP in front is open to anyone
            # who reaches the edge; mtls is refused too, as the edge terminates TLS and adds
            # no client-certificate check (ADR-0034)
            if s.get("auth", "none") == "none":
                problems.append(f"service {sname}: a public route needs auth")
            elif s["auth"] == "mtls":
                problems.append(
                    f"service {sname}: a public route needs auth: idp or own "
                    "(the edge terminates TLS, so mtls is never checked)"
                )
        for z in s.get("clients", []):
            if z not in zones:
                problems.append(f"service {sname}: clients names unknown zone {z!r}")
        mcp = s.get("mcp")
        if mcp:
            if mcp["name"] in mcps:
                problems.append(
                    f"service {sname}: mcp name {mcp['name']!r} already used by {mcps[mcp['name']]}"
                )
            mcps[mcp["name"]] = sname
            if s["protocol"] not in ("http", "https"):
                problems.append(f"service {sname}: mcp requires an http(s) protocol")
        if s.get("auth") == "idp" and "idp" not in primary:
            problems.append(f"service {sname}: auth=idp but no primary provides capability 'idp'")
        # the edge's forward auth (ADR-0034 decision 3): a public auth: idp site behind no
        # primary auth-proxy would be published with no login; a non-primary one is not it
        if s.get("auth") == "idp" and pub and "auth-proxy" not in primary:
            problems.append(
                f"service {sname}: a public auth: idp route needs a primary 'auth-proxy' "
                "(the edge's forward auth)"
            )
        if s.get("roles") and s.get("auth") != "idp":
            problems.append(
                f"service {sname}: roles needs auth: idp (the IdP grants them at sign-in)"
            )
        if s.get("tlp_ceiling") and s["capability"] not in EGRESS_CAPABILITIES:
            problems.append(
                f"service {sname}: tlp_ceiling is for an egress capability "
                f"({', '.join(sorted(EGRESS_CAPABILITIES))}), not {s['capability']}"
            )
        if s.get("front_door") and (s.get("auth") != "idp" or not pub):
            problems.append(
                f"service {sname}: front_door needs auth: idp and a public_hostname (the edge adds it)"
            )
    problems += upstream_problems(services)
    # a primary answers by its capability, an eval or retiring row by its row name (ADR-0039
    # decision 2): both the endpoint variables and the alias-zone names must stay unique, so a
    # row named like another capability is refused
    envs: dict[str, str] = {}
    labels: dict[str, str] = {}
    for sname, s in services.items():
        label = row_name_label(sname, s)
        twin = None
        if label is not None:
            # a second primary of one capability is reported above; its name and variable
            # clash too
            twin = labels.get(label)
            if twin is not None and not (
                standing_of(s) == "primary" and standing_of(services[twin]) == "primary"
            ):
                problems.append(
                    f"service {sname}: alias-zone name {label!r} already used by {twin}"
                )
            labels.setdefault(label, sname)
        # an explicit env_var is held unique whatever the tier: a legacy row answers by no name,
        # but its env_var would still be read by whatever reads that variable
        var = s.get("env_var") or (env_var_name(label) if label is not None else None)
        if var is None:
            continue
        if var in envs and (twin is None or s.get("env_var")):
            problems.append(f"service {sname}: env var {var} already used by {envs[var]}")
        envs[var] = sname
    problems += _name_claim_problems(services, caps)
    problems += status_source_problems(services)
    problems += secret_ref_problems(service_secret_refs(services))
    return problems


def upstream_problems(services: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """A row's ``upstreams`` name capabilities of the registry, never its own, and each one with
    a primary (ADR-0039 decision 3: an upstream is a binding, and a binding reaches only a
    primary).  The one binding the registry holds itself; ``hnx registry bindings`` reuses it."""
    caps = {s["capability"] for s in services.values()}
    primary = {s["capability"] for s in services.values() if standing_of(s) == "primary"}
    problems = []
    for sname, s in services.items():
        for up in s.get("upstreams", []):
            if up not in caps:
                problems.append(f"service {sname}: upstream {up!r} is not a registered capability")
            elif up == s["capability"]:
                problems.append(f"service {sname}: lists itself as upstream")
            elif up not in primary:
                problems.append(
                    f"service {sname}: upstream {up!r} has no primary (a binding reaches only a "
                    "primary)"
                )
    return problems


def _a(word: str) -> str:
    return ("an " if word[:1] in "aeiou" else "a ") + word


def platform_capabilities() -> frozenset[str]:
    """Every capability name the platform knows (the capability-class table, the conformance
    contracts), without the ``cap:`` prefix: the names an eval or retiring row may never take
    (:func:`homelabnext.capability_names.platform_capabilities`)."""
    return _platform_capabilities()


def _name_claim_problems(services: Mapping[str, Any], caps: set[str]) -> list[str]:
    """ADR-0039 decision 2: a capability's alias and its default variable are its primary's
    alone, whether or not the capability has a primary today.  A consumer with no registry (an
    adapter resolving ``HNX_ENDPOINT_<CAPABILITY>``, a resolver given only a domain, a reader of
    the aggregate env file) cannot tell a row name from a capability, so:

    * an ``eval`` or ``retiring`` row's name is no capability of this registry (any tier) and no
      capability the platform knows, and neither is its variable's stem;
    * an ``eval`` or ``retiring`` row declares no ``env_var`` (its variable is its row name's);
    * every capability's default variable ``HNX_ENDPOINT_<CAPABILITY>`` is reserved for that
      capability's primary, even when the primary declares an ``env_var`` of its own or there is
      no primary: no other row's explicit ``env_var`` may take it."""
    out = []
    reserved = caps | platform_capabilities()
    reserved_vars = {env_var_name(c): c for c in reserved}
    for sname, s in services.items():
        tier = standing_of(s)
        explicit = s.get("env_var")
        if tier in ANSWERING_TIERS:
            if sname in reserved:
                out.append(
                    f"service {sname}: {_a(tier)} row answers by its row name, and {sname!r} is a "
                    "capability name; rename the row"
                )
            elif env_var_name(sname) in reserved_vars:
                out.append(
                    f"service {sname}: its variable {env_var_name(sname)} is capability "
                    f"{reserved_vars[env_var_name(sname)]!r}'s; rename the row"
                )
            if explicit:
                out.append(
                    f"service {sname}: env_var is for a primary or legacy row ({_a(tier)} row's "
                    f"variable is its row name's, {env_var_name(sname)})"
                )
            continue
        owner = reserved_vars.get(explicit) if explicit else None
        if owner is not None and not (tier == "primary" and s["capability"] == owner):
            out.append(
                f"service {sname}: env_var {explicit} is reserved for capability {owner!r}'s "
                "primary"
            )
    return out


def _standing_problems(services: Mapping[str, Any], primary: Mapping[str, Any]) -> list[str]:
    """2.9 (ADR-0039 decisions 1, 2, 4 and 5): a non-primary row's date, route and ceiling; a
    replica's relation; and capability names that carry a tier."""
    out = []
    for sname, s in services.items():
        cap = s["capability"]
        tier = standing_of(s)
        until = (s.get("standing") or {}).get("until")
        if until is not None:
            try:
                datetime.date.fromisoformat(until)
            except ValueError:
                out.append(f"service {sname}: standing.until {until!r} is not a calendar date")
        if _TIER_SUFFIX.search(cap):
            out.append(
                f"service {sname}: capability {cap!r} carries a tier in its name; "
                "use standing (and the capability it competes for)"
            )
        suffix = _REPLICA_SUFFIX.search(cap)
        source = s.get("replica_of")
        if suffix and not source:
            out.append(
                f"service {sname}: capability {cap!r} reads as a replica; declare replica_of"
            )
        elif suffix and source != cap and cap != f"{source}{suffix.group(0)}":
            out.append(
                f"service {sname}: a replica capability is named for what it replicates: "
                f"{source}{suffix.group(0)}, not {cap}"
            )
        if source:
            of = primary.get(source)
            if source == cap:
                out.append(f"service {sname}: replica_of names its own capability {cap!r}")
            elif of is None:
                out.append(f"service {sname}: replica_of {source!r} has no primary")
            elif not s.get("impl") and not of.get("impl"):
                out.append(
                    f"service {sname}: replica_of {source!r} needs an impl on both rows "
                    "(a replica serves the same product's data)"
                )
            elif s.get("impl") != of.get("impl"):
                out.append(
                    f"service {sname}: replica_of {source!r} needs the primary's impl "
                    f"({of.get('impl') or 'none'}), not {s.get('impl') or 'none'}"
                )
        if tier == "primary":
            extra = sorted(set(s.get("standing") or {}) & {"until", "why"})
            if extra:
                out.append(
                    f"service {sname}: standing {' and '.join(extra)} is for a non-primary row "
                    "(a primary has no end date)"
                )
            continue
        if s.get("public_hostname"):
            out.append(
                f"service {sname}: public_hostname is for a primary row only, not a {tier} one"
            )
        if cap in EGRESS_CAPABILITIES:
            # every non-primary egress row is held to the primary's ceiling, legacy included:
            # a legacy row needs none (this repository sends nothing to it), but one it declares
            # must not be above what the capability's consumers send to
            mine = s.get("tlp_ceiling")
            theirs = (primary.get(cap) or {}).get("tlp_ceiling")
            if not mine and tier == "legacy":
                pass
            elif not mine:
                out.append(
                    f"service {sname}: a {tier} row of egress capability {cap!r} declares its "
                    "own tlp_ceiling"
                )
            elif not theirs:
                out.append(
                    f"service {sname}: tlp_ceiling cannot be held to the primary's: "
                    f"no primary of {cap!r} declares one"
                )
            elif tlp.parse_stored(mine) > tlp.parse_stored(theirs):
                out.append(f"service {sname}: tlp_ceiling {mine} is above the primary's ({theirs})")
    return out


def service_secret_refs(services: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(where, reference)`` of every secret reference of the registry's services (a front
    door's ``secret``, a status source's ``auth.secret``); ``services`` maps name to a service
    document or a :class:`Service`."""
    out = []
    for sname, s in services.items():
        get = s.get if isinstance(s, Mapping) else lambda k, d=None, s=s: getattr(s, k, d)
        fd = get("front_door") or {}
        if isinstance(fd, Mapping) and isinstance(fd.get("secret"), str):
            out.append((f"service {sname}: front_door.secret", fd["secret"]))
        for src in get("status_sources") or ():
            auth = src.get("auth") if isinstance(src, Mapping) else None
            if isinstance(auth, Mapping) and isinstance(auth.get("secret"), str):
                out.append((f"status source {src.get('id')}: auth.secret", auth["secret"]))
    return out


def secret_ref_problems(refs: Iterable[tuple[str, str]]) -> list[str]:
    """Two different secret references delivered in one environment variable: refused, since
    :func:`secret_env_name` maps every non-alphanumeric to ``_`` (``a/b-c`` and ``a/b_c``
    collide) and one would silently be given the other's value.  The same reference twice is
    one secret, and fine."""
    seen: dict[str, tuple[str, str]] = {}
    out = []
    for where, ref in refs:
        env = secret_env_name(ref)
        first = seen.setdefault(env, (where, ref))
        if first[1] != ref:
            out.append(
                f"{where}: {ref} and {first[1]} ({first[0]}) are both delivered in {env};"
                " rename one"
            )
    return out


def secret_env_name(ref: str) -> str:
    """The environment variable a secret-store reference is delivered in at run time:
    ``secret:status/front-door-secret`` -> ``HNX_SECRET_STATUS_FRONT_DOOR_SECRET`` (the value never appears in
    the registry, a generated file or the repository)."""
    name = ref.removeprefix("secret:")
    return "HNX_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()


#: status-source kinds that poll a registry service over HTTP (target.service + target.path)
_HTTP_STATUS_KINDS = (
    "poll-http-json",
    "poll-prometheus",
    "poll-uptime-kuma",
    "poll-stackstorm",
    "poll-nifi",
)
#: the product kinds (stage 2): their mapping is the product's own (homelabnext.status.products)
_PRODUCT_STATUS_KINDS = _HTTP_STATUS_KINDS[1:]
#: built-in mappers of the agent-activity kind (homelabnext.status.agents.sources)
_AGENT_BUILTINS = ("agent-spool", "agentmetry-jsonl", "agent-push")
#: built-in mappers of one kind only, and the keys each takes beside builtin
_KIND_BUILTINS = {
    "invariants-results": ("poll-file", {"module"}),
    "records-lanes": ("poll-file", {"module", "warn_after_s"}),
    "broker-pending": ("poll-file", {"module", "warn_after_s"}),
    "job-last-run": ("poll-file", {"module", "warn_after_s"}),
    "orchestrator-queue": ("poll-http-json", {"module", "warn_after_s"}),
    "agentmetry-audit": ("poll-http-json", {"module", "warn_after_s"}),
    "prometheus-alerts": ("poll-prometheus", {"module", "states", "item"}),
}
_RAW_ADDRESS = re.compile(r"://|(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w])|\blocalhost\b", re.I)


def status_source_problems(services: dict) -> list[str]:
    """Rules for ``status_sources`` (ADR-0013) that the schema cannot state: unique ids, targets
    that name a registered http(s) service, sane timing, the target a kind needs, and no raw
    address anywhere in a source."""
    problems: list[str] = []
    ids: dict[str, str] = {}
    for sname, s in services.items():
        for src in s.get("status_sources", []):
            sid = src["id"]
            where = f"service {sname}: status source {sid}"
            if sid in ids:
                problems.append(f"{where}: id already used by service {ids[sid]}")
            ids[sid] = sname
            for v in (v for v in _strings(src) if _RAW_ADDRESS.search(v)):
                problems.append(f"{where}: raw address {v!r}; name a registry service instead")
            interval = src["interval_s"]
            stale = src.get("stale_after_s", 3 * interval)
            timeout = src.get("timeout_s", 10)
            if stale < interval:
                problems.append(f"{where}: stale_after_s {stale} is below interval_s {interval}")
            if timeout >= interval:
                problems.append(f"{where}: timeout_s {timeout} must be below interval_s {interval}")
            target = src.get("target", {})
            kind = src["kind"]
            if kind in _HTTP_STATUS_KINDS:
                tname = target.get("service", sname)
                tsvc = services.get(tname)
                if tsvc is None:
                    problems.append(f"{where}: target service {tname!r} is not registered")
                elif tsvc["protocol"] not in ("http", "https"):
                    problems.append(f"{where}: target service {tname!r} does not speak http(s)")
                if "path" not in target:
                    problems.append(f"{where}: {kind} needs target.path")
                if "file" in target:
                    problems.append(f"{where}: {kind} takes no target.file")
                if kind in _PRODUCT_STATUS_KINDS:
                    from homelabnext.status.products import source_problems

                    problems += source_problems(src, where)
            elif kind == "poll-nut":
                tname = target.get("service", sname)
                tsvc = services.get(tname)
                if tsvc is None:
                    problems.append(f"{where}: target service {tname!r} is not registered")
                elif tsvc["protocol"] != "tcp":
                    problems.append(f"{where}: target service {tname!r} is not tcp (upsd)")
                from homelabnext.status.nut import source_problems as nut_problems

                problems += nut_problems(src, where)
            elif kind == "poll-file":
                if "file" not in target:
                    problems.append(f"{where}: poll-file needs target.file")
                if "path" in target or "service" in target:
                    problems.append(f"{where}: poll-file takes only target.file")
            elif kind == "agent-activity":
                builtin = (src.get("mapping") or {}).get("builtin")
                if builtin not in _AGENT_BUILTINS:
                    problems.append(
                        f"{where}: agent-activity needs mapping.builtin, one of {list(_AGENT_BUILTINS)}"
                    )
                if "path" in target or "service" in target:
                    problems.append(f"{where}: agent-activity takes only target.file")
                if builtin == "agent-push" and "file" in target:
                    problems.append(
                        f"{where}: agent-push reads the activity store (no target.file)"
                    )
                if builtin in ("agent-spool", "agentmetry-jsonl") and "file" not in target:
                    problems.append(f"{where}: {builtin} needs target.file")
            elif target.get("path") or target.get("file"):
                problems.append(f"{where}: push-event sources are not polled (no path or file)")
            if src.get("auth") and kind not in (*_HTTP_STATUS_KINDS, "poll-nut"):
                problems.append(f"{where}: auth is for the HTTP kinds and poll-nut only")
            if src.get("auth", {}).get("username") and kind != "poll-nut":
                problems.append(f"{where}: auth.username is for poll-nut only")
            mapping = src.get("mapping")
            builtin = (mapping or {}).get("builtin")
            if builtin in _AGENT_BUILTINS and kind != "agent-activity":
                problems.append(f"{where}: builtin {mapping['builtin']} is for agent-activity only")
            if builtin in _KIND_BUILTINS and kind != _KIND_BUILTINS[builtin][0]:
                problems.append(
                    f"{where}: builtin {builtin} is for {_KIND_BUILTINS[builtin][0]} only"
                )
            if kind in ("poll-http-json", "poll-file", "agent-activity", "poll-prometheus") and (
                not mapping
            ):
                problems.append(f"{where}: {kind} needs a mapping")
            if kind in (*_PRODUCT_STATUS_KINDS, "poll-nut"):
                pass  # the product's own mapping keys: checked by source_problems above
            elif mapping and builtin is not None:
                allowed = _KIND_BUILTINS.get(builtin, (None, {"module", "warn_after_s"}))[1]
                if set(mapping) - {"builtin"} - allowed:
                    problems.append(f"{where}: a builtin mapping takes no selectors")
            elif mapping and "state" not in mapping:
                problems.append(f"{where}: a declarative mapping needs a state selector")
            elif mapping and set(mapping) & _PRODUCT_MAPPING_KEYS:
                extra = sorted(set(mapping) & _PRODUCT_MAPPING_KEYS)
                problems.append(f"{where}: {extra} are for the product kinds only")
    return problems


#: mapping keys only the product kinds read (homelabnext.status.products)
_PRODUCT_MAPPING_KEYS = {"query", "thresholds", "empty", "window_s", "limit"}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


#: per-service keys the digest leaves out: read only by the status hub (ADR-0013), never by a
#: generator, so registering a status source changes no generated file and no golden
_UNDIGESTED_SERVICE_KEYS = ("status_sources",)


def canonical_digest(doc: dict) -> str:
    """sha256 of the registry as the generators consume it (every generated header cites it)."""
    services = doc.get("services")
    if isinstance(services, dict):
        doc = {
            **doc,
            "services": {
                k: {f: v for f, v in s.items() if f not in _UNDIGESTED_SERVICE_KEYS}
                if isinstance(s, dict)
                else s
                for k, s in services.items()
            },
        }
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_registry(doc: dict) -> Registry:
    """Validate a parsed document and return the model, or raise RegistryError."""
    if not isinstance(doc, dict):
        raise RegistryError("registry root must be a mapping")
    from homelabnext.generators.safe import control_char_paths  # local: generators imports registry

    # schema-independent backstop: every value lands in a line-oriented generated file
    problems = [f"unsafe: {m}" for m in control_char_paths(doc)]
    problems += schema_problems(doc)
    if not problems:
        problems = semantic_problems(doc)
    if problems:
        raise RegistryError("invalid registry", problems)
    lab = doc["lab"]
    zones = {k: Zone(k, v["cidr"], v.get("description", "")) for k, v in doc["zones"].items()}
    hosts = {
        k: Host(k, v["address"], v["zone"], v.get("role", "")) for k, v in doc["hosts"].items()
    }
    services = {}
    for k, s in doc["services"].items():
        services[k] = Service(
            name=k,
            capability=s["capability"],
            host=s["host"],
            protocol=s["protocol"],
            port=s["port"],
            owner=s["owner"],
            version=s["version"],
            tls=s["tls"],
            impl=s.get("impl", ""),
            health=s.get("health", {"kind": "none"}),
            metrics=s.get("metrics"),
            upstreams=tuple(s.get("upstreams", [])),
            clients=tuple(s.get("clients", [])),
            auth=s.get("auth", "none"),
            public_hostname=s.get("public_hostname"),
            backup_job=s.get("backup_job"),
            env_var=s.get("env_var"),
            mcp=s.get("mcp"),
            tags=tuple(sorted(s.get("tags", []))),
            status_sources=tuple(s.get("status_sources", [])),
            front_door=s.get("front_door"),
            description=s.get("description", ""),
            roles={r: tuple(g) for r, g in sorted((s.get("roles") or {}).items())},
            tlp_ceiling=s.get("tlp_ceiling"),
            standing=standing_of(s),
            until=(s.get("standing") or {}).get("until"),
            why=(s.get("standing") or {}).get("why", ""),
            replica_of=s.get("replica_of"),
        )
    return Registry(
        lab_name=lab["name"],
        domain=lab["domain"],
        svc_label=lab.get("svc_label", "svc"),
        owner=lab.get("owner", ""),
        zones=zones,
        hosts=hosts,
        services={k: v for k, v in services.items() if v.is_primary},
        digest=canonical_digest(doc),
        non_primary={k: v for k, v in services.items() if not v.is_primary},
    )


#: the largest registry text read: far above any lab (a few hundred KB), and a bound on what one
#: scalar can cost every reader that walks the document
MAX_REGISTRY_BYTES = 4 * 1024 * 1024


def read_registry_doc(text: str) -> Any:
    """The parsed registry document, or :class:`RegistryUnreadable`: over
    :data:`MAX_REGISTRY_BYTES`, invalid YAML, an alias, or past the shared expansion budget (the
    loader refuses those before anything is constructed)."""
    if len(text) > MAX_REGISTRY_BYTES:
        raise RegistryUnreadable(f"registry is over {MAX_REGISTRY_BYTES} bytes")
    try:
        return yaml.load(text, Loader=_UniqueKeyLoader)
    except ExpansionRefused as exc:
        raise RegistryUnreadable(f"registry refused: {exc}") from None
    except yaml.YAMLError as exc:
        raise RegistryUnreadable(f"registry is not valid YAML: {exc}") from exc


def loads(text: str) -> Registry:
    return build_registry(read_registry_doc(text))


def load(path: str | Path) -> Registry:
    p = Path(path)
    try:
        text = sops.read_text(p)
    except OSError as exc:
        raise RegistryUnreadable(f"cannot read registry {p}: {exc}") from exc
    except sops.SopsError as exc:
        raise RegistryUnreadable(str(exc)) from exc
    return loads(text)
