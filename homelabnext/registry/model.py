# SPDX-License-Identifier: Apache-2.0
"""Registry data model, loader and validation for ``services.yml``.

Validation has two layers: the JSON Schema (``schemas/platform/service.json``,
shape) and :func:`semantic_problems` (cross references and uniqueness).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._yaml import UniqueKeyLoader


class RegistryError(Exception):
    """The registry file is unreadable, malformed or inconsistent."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        detail = "".join(f"\n  - {p}" for p in self.problems)
        super().__init__(message + detail)


# refuses duplicate mapping keys (a silent override is a bug); homelabnext.swap.flip uses it too
_UniqueKeyLoader = UniqueKeyLoader


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
        return self.env_var or env_var_name(self.capability)


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
    services: dict[str, Service]
    digest: str

    @property
    def alias_zone(self) -> str:
        return f"{self.svc_label}.{self.domain}"

    def alias(self, capability: str) -> str:
        return f"{capability}.{self.alias_zone}"

    def by_capability(self, capability: str) -> Service | None:
        for svc in self.services.values():
            if svc.capability == capability:
                return svc
        return None

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
        out.append(f"schema: {where}: {err.message}")
    return out


def semantic_problems(doc: dict) -> list[str]:
    """Cross-reference and uniqueness checks. Assumes the schema already passed."""
    problems: list[str] = []
    zones = doc["zones"]
    hosts = doc["hosts"]
    services = doc["services"]
    nets = {}
    for zname, z in zones.items():
        try:
            nets[zname] = ipaddress.ip_network(z["cidr"], strict=True)
        except ValueError as exc:
            problems.append(f"zone {zname}: bad cidr {z['cidr']!r}: {exc}")
    seen_addr: dict[str, str] = {}
    for hname, h in hosts.items():
        if h["zone"] not in zones:
            problems.append(f"host {hname}: unknown zone {h['zone']!r}")
        try:
            ip = ipaddress.ip_address(h["address"])
        except ValueError:
            problems.append(f"host {hname}: bad address {h['address']!r}")
            continue
        if h["address"] in seen_addr:
            problems.append(
                f"host {hname}: address {h['address']} already used by {seen_addr[h['address']]}"
            )
        seen_addr[h["address"]] = hname
        net = nets.get(h["zone"])
        if net is not None and ip not in net:
            problems.append(
                f"host {hname}: address {h['address']} is outside zone {h['zone']} ({net})"
            )
    caps: dict[str, str] = {}
    ports: dict[tuple[str, int, str], str] = {}
    pubs: dict[str, str] = {}
    mcps: dict[str, str] = {}
    for sname, s in services.items():
        cap = s["capability"]
        if cap in caps:
            problems.append(f"service {sname}: capability {cap!r} already provided by {caps[cap]}")
        caps[cap] = sname
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
        if s.get("auth") == "idp" and not any(x["capability"] == "idp" for x in services.values()):
            problems.append(f"service {sname}: auth=idp but no service provides capability 'idp'")
        if s.get("front_door") and (s.get("auth") != "idp" or not pub):
            problems.append(
                f"service {sname}: front_door needs auth: idp and a public_hostname (the edge adds it)"
            )
    for sname, s in services.items():
        for up in s.get("upstreams", []):
            if up not in caps:
                problems.append(f"service {sname}: upstream {up!r} is not a registered capability")
            elif up == s["capability"]:
                problems.append(f"service {sname}: lists itself as upstream")
    envs: dict[str, str] = {}
    for sname, s in services.items():
        var = s.get("env_var") or env_var_name(s["capability"])
        if var in envs:
            problems.append(f"service {sname}: env var {var} already used by {envs[var]}")
        envs[var] = sname
    problems += status_source_problems(services)
    return problems


def secret_env_name(ref: str) -> str:
    """The environment variable a secret-store reference is delivered in at run time:
    ``secret:status/front-door-secret`` -> ``HNX_SECRET_STATUS_FRONT_DOOR_SECRET`` (the value never appears in
    the registry, a generated file or the repository)."""
    name = ref.removeprefix("secret:")
    return "HNX_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()


#: status-source kinds that poll a registry service over HTTP (target.service + target.path)
_HTTP_STATUS_KINDS = ("poll-http-json", "poll-prometheus")
#: built-in mappers of the agent-activity kind (homelabnext.status.agents.sources)
_AGENT_BUILTINS = ("agent-spool", "agentmetry-jsonl", "agent-push")
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
            mapping = src.get("mapping")
            if mapping and mapping.get("builtin") in _AGENT_BUILTINS and kind != "agent-activity":
                problems.append(f"{where}: builtin {mapping['builtin']} is for agent-activity only")
            if kind in ("poll-http-json", "poll-file", "agent-activity") and not mapping:
                problems.append(f"{where}: {kind} needs a mapping")
            if (
                mapping
                and "builtin" in mapping
                and set(mapping) - {"builtin", "warn_after_s", "module"}
            ):
                problems.append(f"{where}: a builtin mapping takes no selectors")
            if mapping and "builtin" not in mapping and "state" not in mapping:
                problems.append(f"{where}: a declarative mapping needs a state selector")
    return problems


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
        )
    return Registry(
        lab_name=lab["name"],
        domain=lab["domain"],
        svc_label=lab.get("svc_label", "svc"),
        owner=lab.get("owner", ""),
        zones=zones,
        hosts=hosts,
        services=services,
        digest=canonical_digest(doc),
    )


def loads(text: str) -> Registry:
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise RegistryError(f"registry is not valid YAML: {exc}") from exc
    return build_registry(doc)


def load(path: str | Path) -> Registry:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistryError(f"cannot read registry {p}: {exc}") from exc
    return loads(text)
