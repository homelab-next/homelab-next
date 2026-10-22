# SPDX-License-Identifier: Apache-2.0
"""Render LLM gateway configuration (LiteLLM proxy and Bifrost) from the model-role table.

One source of truth (ADR-0007): the role table (``schemas/platform/model_roles.json``) names every
role, its bindings and limits; the agent profiles name which role each agent calls and whether its
data may leave the lab (``data_tier``).  A small *gateway spec* adds only what the gateway needs
and the role table does not say: where each ``svc:`` backend is and whether it is local or cloud,
which secret holds each key, and any extra non-agent keys.  From those three this module renders:

* ``litellm/config.yaml``  - the proxy ``model_list`` (one entry per binding, ``model_name`` = the
  role), role fallbacks, per-deployment request/token limits, master key and database by
  environment reference only;
* ``litellm/keys.json``    - the virtual keys to create (``/key/generate`` bodies; LiteLLM keeps
  keys in Postgres, not in the config file), each naming the environment variable holding the
  key, never the key;
* ``bifrost/config.json``  - providers (one per backend, role -> model id as key aliases), virtual
  keys, per-role rate limits and budgets, routing rules for ordered bindings and fallbacks;
* ``bifrost/pricing.json``, ``bifrost/model-parameters.json`` - empty local datasheets: Bifrost
  will not start when it cannot download its datasheets, and a lab gateway must not need egress.

Rules enforced at render time (a violation raises :class:`GatewaySpecError`, nothing is written):

* **No cross-provider fallback on an agent role, and no cloud anywhere behind a local-only one.**
  A role is *local-only* when a ``data_tier: local-only`` profile or key uses it, or the spec lists
  it under ``local_only``: its bindings and every role in its fallback chain must be on ``local``
  backends.  A role any agent uses must not change locality along its chain at all: falling back
  per request would switch a running agent session between local and cloud models, which is the
  orchestrator's session-level decision, not the gateway's.
* Every secret is a ``secret:<name>`` reference, delivered in ``HNX_SECRET_<NAME>`` (the same
  mapping as the registry); a literal value is refused.  No two client credentials (keys, the
  master key, the database URL) share a reference or a resulting variable, and none is a
  backend's upstream key.
* Every backend a role binds is declared in the spec, and every declared value is one line.
* A ``local`` backend is local because of where it is, not because the spec says so: it must be a
  registry service whose host sits in a non-cloud zone, or its host must be under the lab's
  internal service domain (``<svc_label>.<domain>``).  ``{locality: local, host: <a cloud API>}``
  is refused, and the audit counts such a host as cloud.

:func:`audit` re-checks the *rendered* files (``hnx gen gateway --check`` runs it on what is on
disk), so a hand edit that adds a cloud fallback to a local-only role fails the check even though
the generator would never write it.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import ipaddress
import json
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from homelabnext._yaml import UniqueKeyLoader
from homelabnext.registry.model import secret_env_name
from homelabnext.registry.models import RoleTable, RoleTableError

from .core import MARKER, check_tree, write_tree

__all__ = [
    "GatewaySpecError",
    "Spec",
    "audit",
    "load_spec",
    "main",
    "render",
    "render_file",
]

SECRET_RE = re.compile(r"^secret:[a-z0-9][a-z0-9/_.-]*$")
SVC_RE = re.compile(r"^svc:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$")
MDL_RE = re.compile(r"^mdl:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$")
SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
ROLE_LIMIT_KEYS = ("max_requests", "max_tokens", "max_cost", "cost_per_1k_tokens")
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
LOCALITIES = ("local", "cloud")
DATA_TIERS = ("local-only", "cloud-allowed")
#: cloud providers the renderers know how to name (LiteLLM prefix == Bifrost provider name)
CLOUD_PROVIDERS = ("anthropic", "openai", "gemini", "mistral")
PROVIDER_PREFIX = "hnx-"  # Bifrost provider name of a local backend: hnx-<svc name>
HEADER = f"# {MARKER} llm_gateway from {{spec}} - do not edit; sha256:{{digest}}\n"


class GatewaySpecError(ValueError):
    """The gateway spec, the role table or the profiles break a rule.  ``problems`` lists all."""

    def __init__(self, message: str, problems: Iterable[str] = ()):
        self.problems = list(problems)
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


@dataclass(frozen=True)
class Backend:
    name: str  # svc name without the prefix
    locality: str
    provider: str = ""  # cloud only: anthropic | openai | ...
    host: str = ""  # local only: the registry-style alias
    port: int = 0
    scheme: str = "http"
    api_key: str | None = None  # secret: reference

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def bifrost_provider(self) -> str:
        return self.provider if self.locality == "cloud" else PROVIDER_PREFIX + self.name


@dataclass(frozen=True)
class Key:
    name: str  # slug; the key alias
    secret: str  # secret: reference holding the key value
    roles: tuple[str, ...]
    data_tier: str
    owner: str = ""  # profile:<id> for agent keys
    window_s: int | None = None
    max_requests: int | None = None
    max_tokens: int | None = None


@dataclass
class Spec:
    source: str
    table: RoleTable
    backends: dict[str, Backend]
    keys: list[Key]
    master_key: str
    database_url: str
    local_only: dict[str, str] = field(default_factory=dict)  # role -> why
    agent_roles: dict[str, str] = field(default_factory=dict)  # role -> first profile using it
    bifrost_data_dir: str = "/app/data"
    #: the lab's internal service domain (``<svc_label>.<domain>``): a local host must be under it
    service_domain: str = "svc.example.internal"
    #: hosts that resolved through a registry service in a non-cloud zone
    registry_hosts: frozenset[str] = frozenset()


def internal_host(spec: Spec, host: str) -> bool:
    """A host a ``local`` backend may use: a registry service's alias, or a name under the lab's
    internal service domain.  Anything else (a cloud API, a bare public name, an address) is not
    local, whatever the spec calls it."""
    host = host.lower().rstrip(".")
    return host in spec.registry_hosts or host.endswith("." + spec.service_domain)


def _cloud_zone(registry: Any, svc: Any) -> bool:
    """A registry zone is cloud when it is named so or its network is publicly routable."""
    zone = registry.zones.get(registry.hosts[svc.host].zone) if svc.host in registry.hosts else None
    if zone is None:
        return True
    try:
        net = ipaddress.ip_network(zone.cidr, strict=False)
    except ValueError:
        return True
    return zone.name == "cloud" or net.is_global


# ---------------------------------------------------------------------------- loading
def _secret(where: str, value: Any, problems: list[str]) -> str:
    if not isinstance(value, str) or not SECRET_RE.match(value):
        problems.append(f"{where}: must be a secret:<name> reference, never a literal value")
        return "secret:invalid"
    return value


def _one_line(where: str, value: Any, problems: list[str]) -> None:
    if isinstance(value, str) and any(ord(c) < 32 for c in value):
        problems.append(f"{where}: control characters are not allowed")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _one_line(f"{where}.{k}", v, problems)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _one_line(f"{where}[{i}]", v, problems)


def _role_name(where: str, value: Any, problems: list[str]) -> str | None:
    m = MDL_RE.match(str(value))
    if not m:
        problems.append(f"{where}: {value!r} is not an mdl: role id")
        return None
    return m.group(1)


def _whole(value: Any) -> int | None:
    """``value`` as a positive whole number, or ``None`` (a bool, a string, 0, 2.5 are not)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    return int(value) if value >= 1 else None


def per_minute(count: int, window_s: int) -> int | None:
    """``count`` per ``window_s`` as a per-minute limit that is never looser, or ``None``.

    LiteLLM counts every rpm/tpm limit over one sliding 60 s window.  ``count`` per ``k`` minutes
    becomes ``floor(count / k)`` per minute: any ``k``-minute span then holds at most ``count``
    (rounding down only tightens).  A window that is not a whole number of minutes cannot be
    expressed that way (90 s: two sliding minutes fit in it), nor can a share below one a minute
    (1 per hour is not "1 a minute"), so those are ``None`` and the spec is refused."""
    if window_s % 60:
        return None
    share = count // (window_s // 60)
    return share if share >= 1 else None


def limit_problems(where: str, raw: Any, *, allowed: Iterable[str]) -> list[str]:
    """Problems with a ``limits`` mapping (a role's or a key's); empty when both gateways can
    enforce it exactly as declared or tighter.  A zero or missing count never means unlimited."""
    allowed = tuple(allowed)
    if not isinstance(raw, Mapping) or set(raw) - set(allowed):
        return [f"{where}: limits takes {', '.join(allowed)}"]
    w = _whole(raw.get("window_s"))
    if w is None:
        return [f"{where}: limits.window_s must be a whole number of seconds, at least 1"]
    problems: list[str] = []
    counts = [k for k in ("max_requests", "max_tokens") if k in raw]
    for k in counts:
        n = _whole(raw[k])
        if n is None:
            problems.append(
                f"{where}: limits.{k} must be a whole number, at least 1 ({raw[k]!r} is not; "
                "0 would read as unlimited, so it is refused)"
            )
        elif per_minute(n, w) is None:
            problems.append(
                f"{where}: limits.{k} {n} per {w}s cannot be a per-minute limit (LiteLLM's only "
                "window) without loosening it: use a window of whole minutes with at least one "
                "call per minute"
            )
    if "max_cost" in raw and (
        isinstance(raw["max_cost"], bool)
        or not isinstance(raw["max_cost"], int | float)
        or raw["max_cost"] <= 0
    ):
        problems.append(f"{where}: limits.max_cost must be a positive number")
    if not counts and "max_cost" not in raw:
        problems.append(f"{where}: limits needs max_requests, max_tokens or max_cost")
    return problems


def _limits(where: str, raw: Any, problems: list[str]) -> dict[str, Any]:
    if raw is None:
        return {}
    found = limit_problems(where, raw, allowed=("window_s", "max_requests", "max_tokens"))
    if found:
        problems += found
        return {}
    return {k: int(v) for k, v in raw.items()}


def _profile_slug(pid: str) -> str:
    return pid.removeprefix("profile:")


def load_spec(path: str | Path) -> Spec:
    """Read and validate a gateway spec; relative paths in it resolve against its directory."""
    path = Path(path)
    doc = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    return spec_from_dict(doc, base=path.parent, source=path.as_posix())


def spec_from_dict(doc: Any, *, base: Path, source: str = "<spec>") -> Spec:
    problems: list[str] = []
    if not isinstance(doc, Mapping):
        raise GatewaySpecError(f"{source}: the gateway spec must be a mapping")
    _one_line("spec", dict(doc), problems)
    known = {
        "roles", "profiles", "registry", "domain", "svc_label", "master_key", "database_url",
        "backends", "local_only", "keys", "bifrost",
    }  # fmt: skip
    for k in sorted(set(doc) - known):
        problems.append(f"unknown key {k!r}")

    roles_path = doc.get("roles")
    if not isinstance(roles_path, str):
        raise GatewaySpecError(f"{source}: 'roles' (the role table path) is required")
    try:
        table = RoleTable.load(base / roles_path)
    except RoleTableError as exc:
        raise GatewaySpecError(f"{source}: role table invalid", exc.problems) from None
    except (OSError, ValueError) as exc:
        raise GatewaySpecError(f"{source}: cannot read role table {roles_path}: {exc}") from None

    registry = None
    if doc.get("registry"):
        from homelabnext.registry import load as load_registry

        registry = load_registry(base / str(doc["registry"]))
    domain = str(doc.get("domain") or (registry.domain if registry else "example.internal"))
    svc_label = str(doc.get("svc_label") or (registry.svc_label if registry else "svc"))
    service_domain = f"{svc_label}.{domain}".lower()
    registry_hosts: set[str] = set()

    backends: dict[str, Backend] = {}
    raw_backends = doc.get("backends")
    if not isinstance(raw_backends, Mapping) or not raw_backends:
        problems.append("backends: declare every svc: backend the role table binds")
        raw_backends = {}
    for sid, b in raw_backends.items():
        m = SVC_RE.match(str(sid))
        where = f"backends.{sid}"
        if not m or not isinstance(b, Mapping):
            problems.append(f"{where}: key must be a svc: id and the value a mapping")
            continue
        name = m.group(1)
        loc = b.get("locality")
        if loc not in LOCALITIES:
            problems.append(f"{where}: locality must be one of {LOCALITIES}")
            continue
        key = _secret(f"{where}.api_key", b["api_key"], problems) if "api_key" in b else None
        if loc == "cloud":
            prov = b.get("provider")
            if prov not in CLOUD_PROVIDERS:
                problems.append(f"{where}: a cloud backend needs provider in {CLOUD_PROVIDERS}")
                continue
            if key is None:
                problems.append(f"{where}: a cloud backend needs api_key (a secret: reference)")
            backends[name] = Backend(name, loc, provider=str(prov), api_key=key)
            continue
        svc = registry.services.get(name) if registry else None
        if svc is not None:
            if _cloud_zone(registry, svc):
                problems.append(
                    f"{where}: registry service {name} is not in a lab zone, so it is not local"
                )
                continue
            host = f"{svc.capability}.{svc_label}.{domain}".lower()
            port, scheme = svc.port, svc.scheme
            registry_hosts.add(host)
        else:
            host = str(b.get("host") or f"{name}.{svc_label}.{domain}").lower()
            port, scheme = b.get("port"), str(b.get("scheme", "http"))
            if not host.endswith("." + service_domain):
                problems.append(
                    f"{where}: locality local is not self-declared: {host} is neither a registry "
                    f"service nor under the lab's service domain {service_domain}"
                )
                continue
        if not isinstance(port, int) or not 0 < port < 65536:
            problems.append(f"{where}: a local backend needs a port (or a registry service)")
            continue
        if not HOST_RE.match(host) or scheme not in ("http", "https"):
            problems.append(f"{where}: host must be a DNS name and scheme http or https")
            continue
        backends[name] = Backend(name, loc, host=host, port=port, scheme=scheme, api_key=key)

    for rname, role in sorted(table.roles.items()):
        if role.limits:
            problems += limit_problems(
                f"mdl:{rname}", role.limits, allowed=("window_s", *ROLE_LIMIT_KEYS)
            )
        for b in role.bindings:
            if b.backend not in backends:
                problems.append(
                    f"mdl:{rname}: binds svc:{b.backend}, which backends does not declare"
                )

    local_only: dict[str, str] = {}
    agent_roles: dict[str, str] = {}
    keys: list[Key] = []
    for i, r in enumerate(doc.get("local_only") or []):
        rn = _role_name(f"local_only[{i}]", r, problems)
        if rn:
            local_only.setdefault(rn, "listed under local_only")

    for pattern in doc.get("profiles") or []:
        matches = sorted(glob.glob(str(base / str(pattern))))
        if not matches:
            problems.append(f"profiles: {pattern!r} matches no file")
        for p in matches:
            prof = json.loads(Path(p).read_text(encoding="utf-8"))
            pid, tier = str(prof.get("id", "")), prof.get("data_tier")
            rn = _role_name(f"{pid or p}.model_role", prof.get("model_role"), problems)
            if not pid.startswith("profile:") or tier not in DATA_TIERS or rn is None:
                problems.append(f"{p}: a profile needs id, model_role and data_tier")
                continue
            agent_roles.setdefault(rn, pid)
            if tier == "local-only":
                local_only.setdefault(rn, f"{pid} is data_tier local-only")
            slug = _profile_slug(pid)
            keys.append(
                Key(
                    name=f"agent-{slug}",
                    secret="secret:llm-gateway/key-" + slug,
                    roles=(rn,),
                    data_tier=str(tier),
                    owner=pid,
                )
            )

    for i, k in enumerate(doc.get("keys") or []):
        where = f"keys[{i}]"
        if not isinstance(k, Mapping) or not SLUG_RE.match(str(k.get("name", ""))):
            problems.append(f"{where}: needs a slug name")
            continue
        tier = k.get("data_tier", "local-only")
        if tier not in DATA_TIERS:
            problems.append(f"{where}: data_tier must be one of {DATA_TIERS}")
            continue
        rs = tuple(
            r
            for j, x in enumerate(k.get("roles") or [])
            if (r := _role_name(f"{where}.roles[{j}]", x, problems))
        )
        if not rs:
            problems.append(f"{where}: needs at least one role")
        lim = _limits(where, k.get("limits"), problems)
        for rn in rs:
            if tier == "local-only":
                local_only.setdefault(rn, f"key {k['name']} is data_tier local-only")
        keys.append(
            Key(
                name=str(k["name"]),
                secret=_secret(f"{where}.key", k.get("key"), problems),
                roles=rs,
                data_tier=str(tier),
                window_s=lim.get("window_s"),
                max_requests=lim.get("max_requests"),
                max_tokens=lim.get("max_tokens"),
            )
        )
    names = [k.name for k in keys]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        problems.append(f"key name {dup!r} is used twice")
    for k in keys:
        for rn in k.roles:
            if rn not in table.roles:
                problems.append(f"key {k.name}: role mdl:{rn} is not in the role table")
    for rn in sorted(set(local_only) | set(agent_roles)):
        if rn not in table.roles:
            problems.append(f"mdl:{rn} is used but not in the role table")

    bif = doc.get("bifrost") or {}
    data_dir = str(bif.get("data_dir", "/app/data")) if isinstance(bif, Mapping) else "/app/data"
    if not data_dir.startswith("/"):
        problems.append("bifrost.data_dir must be an absolute path")

    master_key = _secret("master_key", doc.get("master_key"), problems)
    database_url = _secret("database_url", doc.get("database_url"), problems)
    problems += _secret_collisions(keys, master_key, database_url, backends)

    spec = Spec(
        source=source,
        table=table,
        backends=backends,
        keys=keys,
        master_key=master_key,
        database_url=database_url,
        local_only=local_only,
        agent_roles=agent_roles,
        bifrost_data_dir=data_dir,
        service_domain=service_domain,
        registry_hosts=frozenset(registry_hosts),
    )
    if not problems:
        problems += locality_problems(spec)
    if problems:
        raise GatewaySpecError(f"{source}: invalid gateway spec", problems)
    return spec


def _secret_collisions(
    keys: list[Key], master_key: str, database_url: str, backends: Mapping[str, Backend]
) -> list[str]:
    """Every client credential is its own secret.  Two keys (or a key and the master key or the
    database URL) sharing a ``secret:`` reference, or two distinct references that map to the same
    ``HNX_SECRET_*`` variable (``key-private`` and ``key.private``), would make one value both a
    local-only key and a cloud-allowed one.  A client credential may not be a backend's upstream
    key either; backends may share an upstream key among themselves."""
    owners = [(f"key {k.name}", k.secret) for k in keys]
    owners += [("master_key", master_key), ("database_url", database_url)]
    owners = [(who, ref) for who, ref in owners if ref != "secret:invalid"]
    problems: list[str] = []
    by_ref: dict[str, list[str]] = {}
    by_env: dict[str, list[tuple[str, str]]] = {}
    for who, ref in owners:
        by_ref.setdefault(ref, []).append(who)
        by_env.setdefault(secret_env_name(ref), []).append((who, ref))
    for ref, whos in sorted(by_ref.items()):
        if len(whos) > 1:
            problems.append(f"{' and '.join(whos)} use the same secret {ref}")
    for env, uses in sorted(by_env.items()):
        if len({ref for _, ref in uses}) > 1:
            named = ", ".join(f"{who} ({ref})" for who, ref in uses)
            problems.append(f"{named} are all delivered in {env}: one value, several credentials")
    upstream = {
        secret_env_name(b.api_key): f"backend svc:{b.name}" for b in backends.values() if b.api_key
    }
    for who, ref in owners:
        env = secret_env_name(ref)
        if env in upstream:
            problems.append(
                f"{who} ({ref}) is delivered in {env}, the upstream key of {upstream[env]}"
            )
    return problems


# ---------------------------------------------------------------------------- the rule
def chain(table: RoleTable, role: str) -> list[str]:
    """The role and its fallback chain, in order (the role table already refuses loops)."""
    out = [role]
    cur = table.roles[role].fallback
    while cur is not None and cur not in out:
        out.append(cur)
        cur = table.roles[cur].fallback
    return out


def localities(spec: Spec, role: str) -> set[str]:
    return {spec.backends[b.backend].locality for b in spec.table.roles[role].bindings}


def locality_problems(spec: Spec) -> list[str]:
    """Every local-only role stays local along its whole chain; no agent role changes locality."""
    problems: list[str] = []
    for role, why in sorted(spec.local_only.items()):
        for step in chain(spec.table, role):
            for b in spec.table.roles[step].bindings:
                if spec.backends[b.backend].locality != "local":
                    via = "binds" if step == role else f"falls back to mdl:{step}, which binds"
                    problems.append(
                        f"mdl:{role} is local-only ({why}) but {via} cloud backend svc:{b.backend}"
                    )
    for role, pid in sorted(spec.agent_roles.items()):
        if role in spec.local_only:
            continue  # covered above, with the stronger rule
        own = localities(spec, role)
        if len(own) > 1:
            problems.append(f"mdl:{role} (used by {pid}) mixes local and cloud bindings")
            continue
        for step in chain(spec.table, role)[1:]:
            if localities(spec, step) != own:
                problems.append(
                    f"mdl:{role} (used by {pid}) falls back across providers to mdl:{step}: "
                    "a per-request fallback would switch an agent session between local and cloud"
                )
    return problems


# ---------------------------------------------------------------------------- rendering
def _env_ref_litellm(secret: str) -> str:
    return f"os.environ/{secret_env_name(secret)}"


def _env_ref_bifrost(secret: str) -> str:
    return f"env.{secret_env_name(secret)}"


def _per_minute(count: float, window_s: float) -> int:
    """The validated per-minute form of a limit (:func:`per_minute`; the loader refused the rest)."""
    share = per_minute(int(count), int(window_s))
    if share is None:  # unreachable after load_spec: never render a looser limit
        raise GatewaySpecError(f"{count:g} per {window_s:g}s has no per-minute form")
    return share


def _duration(window_s: float) -> str:
    """A whole-second window as Bifrost's/LiteLLM's duration string (``60`` -> ``1m``)."""
    s = int(window_s)
    if s != window_s or s < 1:
        raise GatewaySpecError(f"window {window_s!r} is not a whole number of seconds")
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s % n == 0:
            return f"{s // n}{unit}"
    return f"{s}s"


def _fallback_targets(spec: Spec, role: str) -> list[str]:
    """The roles a request for ``role`` may fall back to.  The render-time rule already refused
    every forbidden chain, so this is the role table's chain as is."""
    return chain(spec.table, role)[1:]


def render_litellm(spec: Spec) -> tuple[str, str]:
    model_list: list[dict[str, Any]] = []
    notes: list[str] = []
    for rname, role in sorted(spec.table.roles.items()):
        lim = role.limits
        for i, b in enumerate(role.bindings):
            be = spec.backends[b.backend]
            params: dict[str, Any] = {}
            if be.locality == "cloud":
                params["model"] = f"{be.provider}/{b.model_id}"
            else:
                params["model"] = f"openai/{b.model_id}"
                params["api_base"] = f"{be.base_url}/v1"
            params["api_key"] = _env_ref_litellm(be.api_key) if be.api_key else "no-key"
            params["order"] = i + 1
            if lim.get("max_requests"):
                params["rpm"] = _per_minute(lim["max_requests"], lim["window_s"])
            if lim.get("max_tokens"):
                params["tpm"] = _per_minute(lim["max_tokens"], lim["window_s"])
            if lim.get("max_cost"):
                params["max_budget"] = lim["max_cost"]
                params["budget_duration"] = _duration(lim["window_s"])
            info: dict[str, Any] = {"id": f"{rname}-{i + 1}"}
            if role.kind == "embedding":
                info["mode"] = "embedding"
            if role.max_context_tokens:
                info["max_input_tokens"] = role.max_context_tokens
            if lim.get("cost_per_1k_tokens") is not None:
                per_token = lim["cost_per_1k_tokens"] / 1000
                info["input_cost_per_token"] = per_token
                info["output_cost_per_token"] = per_token
            model_list.append({"model_name": rname, "litellm_params": params, "model_info": info})
        if lim and lim.get("window_s") != 60 and (lim.get("max_requests") or lim.get("max_tokens")):
            notes.append(
                f"mdl:{rname}: limits are per {lim['window_s']:g}s; LiteLLM counts per minute, "
                "so rpm/tpm are the per-minute share rounded down (never looser)"
            )
        if len(role.bindings) > 1 and (lim.get("max_requests") or lim.get("max_tokens")):
            notes.append(f"mdl:{rname}: rpm/tpm apply per deployment ({len(role.bindings)} here)")
    fallbacks = [
        {rname: _fallback_targets(spec, rname)}
        for rname in sorted(spec.table.roles)
        if _fallback_targets(spec, rname)
    ]
    router: dict[str, Any] = {
        "routing_strategy": "simple-shuffle",
        # enforces per-deployment rpm/tpm (429 "No deployments available") and context limits
        "enable_pre_call_checks": True,
    }
    if fallbacks:
        router["fallbacks"] = fallbacks
    doc = {
        "model_list": model_list,
        "router_settings": router,
        "litellm_settings": {"drop_params": True},
        "general_settings": {
            "master_key": _env_ref_litellm(spec.master_key),
            # keys, budgets and spend live in Postgres: without it a wrong key answers
            # "No connected db" instead of 401 (the failure this lab exists to rule out)
            "database_url": _env_ref_litellm(spec.database_url),
        },
    }
    body = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, width=100)
    head = "# SPDX-License-Identifier: Apache-2.0\n" + "".join(f"# note: {n}\n" for n in notes)
    keys = [
        {
            "key_alias": k.name,
            "key_env": secret_env_name(k.secret),
            "models": sorted(_allowed(spec, k)),
            "metadata": {"owner": k.owner or k.name, "data_tier": k.data_tier},
            **(
                {"rpm_limit": _per_minute(k.max_requests, k.window_s)}
                if k.max_requests and k.window_s
                else {}
            ),
            **(
                {"tpm_limit": _per_minute(k.max_tokens, k.window_s)}
                if k.max_tokens and k.window_s
                else {}
            ),
        }
        for k in sorted(spec.keys, key=lambda k: k.name)
    ]
    return head + body, json.dumps({"keys": keys}, indent=2) + "\n"


def _allowed(spec: Spec, key: Key) -> set[str]:
    """The roles a key may call: its own and their fallback chains (a fallback the key could not
    call would fail mid-request)."""
    return {r for role in key.roles for r in chain(spec.table, role)}


def render_bifrost(spec: Spec) -> str:
    data = spec.bifrost_data_dir.rstrip("/")
    providers: dict[str, Any] = {}
    served: dict[str, list[str]] = {}  # bifrost provider -> roles it serves
    for rname, role in sorted(spec.table.roles.items()):
        for b in role.bindings:
            served.setdefault(spec.backends[b.backend].bifrost_provider, []).append(rname)
    for be in sorted(spec.backends.values(), key=lambda b: b.bifrost_provider):
        prov = be.bifrost_provider
        roles = sorted(set(served.get(prov, [])))
        if not roles:
            continue
        aliases = {
            rname: b.model_id
            for rname in roles
            for b in spec.table.roles[rname].bindings
            if spec.backends[b.backend].bifrost_provider == prov
        }
        key = {
            "id": f"{prov}-key",
            "name": f"{prov}-key",
            "value": _env_ref_bifrost(be.api_key) if be.api_key else "no-key",
            "models": roles,
            "aliases": aliases,
            "weight": 1.0,
        }
        entry: dict[str, Any] = {"keys": [key]}
        if be.locality == "local":
            entry["network_config"] = {
                "base_url": be.base_url,
                "default_request_timeout_in_seconds": 120,
            }
            entry["custom_provider_config"] = {"base_provider_type": "openai"}
        providers[prov] = entry

    rate_limits: list[dict[str, Any]] = []
    budgets: list[dict[str, Any]] = []
    model_configs: list[dict[str, Any]] = []
    for rname, role in sorted(spec.table.roles.items()):
        lim = role.limits
        if not lim:
            continue
        mc: dict[str, Any] = {"id": f"mc-{rname}", "model_name": rname, "scope": "global"}
        if lim.get("max_requests") or lim.get("max_tokens"):
            rl: dict[str, Any] = {"id": f"rl-role-{rname}"}
            if lim.get("max_requests"):
                rl["request_max_limit"] = int(lim["max_requests"])
                rl["request_reset_duration"] = _duration(lim["window_s"])
            if lim.get("max_tokens"):
                rl["token_max_limit"] = int(lim["max_tokens"])
                rl["token_reset_duration"] = _duration(lim["window_s"])
            rate_limits.append(rl)
            mc["rate_limit_id"] = rl["id"]
        if lim.get("max_cost"):
            budgets.append(
                {
                    "id": f"budget-role-{rname}",
                    "max_limit": lim["max_cost"],
                    "reset_duration": _duration(lim["window_s"]),
                }
            )
            mc["budget_id"] = f"budget-role-{rname}"
        model_configs.append(mc)

    def provider_configs(roles: Iterable[str], rl_id: str | None = None) -> list[dict[str, Any]]:
        by_prov: dict[str, set[str]] = {}
        for r in roles:
            for b in spec.table.roles[r].bindings:
                by_prov.setdefault(spec.backends[b.backend].bifrost_provider, set()).add(r)
        return [
            {
                "provider": p,
                "allowed_models": sorted(rs),
                "key_ids": ["*"],
                "weight": 1.0,
                **({"rate_limit_id": rl_id} if rl_id else {}),
            }
            for p, rs in sorted(by_prov.items())
        ]

    vks: list[dict[str, Any]] = [
        {
            "id": "vk-gateway-admin",
            "name": "gateway-admin",
            "value": _env_ref_bifrost(spec.master_key),
            "is_active": True,
            "provider_configs": provider_configs(sorted(spec.table.roles)),
        }
    ]
    for k in sorted(spec.keys, key=lambda k: k.name):
        vk: dict[str, Any] = {
            "id": f"vk-{k.name}",
            "name": k.name,
            "value": _env_ref_bifrost(k.secret),
            "is_active": True,
        }
        if k.window_s and (k.max_requests or k.max_tokens):
            rl = {"id": f"rl-key-{k.name}"}
            if k.max_requests:
                rl |= {
                    "request_max_limit": k.max_requests,
                    "request_reset_duration": _duration(k.window_s),
                }
            if k.max_tokens:
                rl |= {
                    "token_max_limit": k.max_tokens,
                    "token_reset_duration": _duration(k.window_s),
                }
            rate_limits.append(rl)
            vk["rate_limit_id"] = rl["id"]
        vk["provider_configs"] = provider_configs(sorted(_allowed(spec, k)))
        vks.append(vk)

    rules: list[dict[str, Any]] = []
    for rname, role in sorted(spec.table.roles.items()):
        first = spec.backends[role.bindings[0].backend].bifrost_provider
        rest = [f"{spec.backends[b.backend].bifrost_provider}/{rname}" for b in role.bindings[1:]]
        for fb in _fallback_targets(spec, rname):
            rest += [
                f"{spec.backends[b.backend].bifrost_provider}/{fb}"
                for b in spec.table.roles[fb].bindings
            ]
        if not rest:
            continue
        rules.append(
            {
                "id": f"route-{rname}",
                "name": f"mdl:{rname} bindings in priority order, then its fallback chain",
                "cel_expression": f"model == '{rname}'",
                "targets": [{"provider": first, "model": rname, "weight": 1.0}],
                "fallbacks": rest,
            }
        )

    governance: dict[str, Any] = {}
    if rate_limits:
        governance["rate_limits"] = rate_limits
    if budgets:
        governance["budgets"] = budgets
    if model_configs:
        governance["model_configs"] = model_configs
    governance["virtual_keys"] = vks
    if rules:
        governance["routing_rules"] = rules
    doc = {
        "$schema": "https://www.getbifrost.ai/schema",
        "client": {
            "enforce_auth_on_inference": True,
            "drop_excess_requests": False,
            "disable_content_logging": True,
        },
        "config_store": {
            "enabled": True,
            "type": "sqlite",
            "config": {"path": f"{data}/config.db"},
        },
        "logs_store": {"enabled": False},
        "framework": {
            "pricing": {
                # local, empty datasheets: no egress at startup (the default URL is fatal offline)
                "pricing_url": f"file://{data}/pricing.json",
                "model_parameters_url": f"file://{data}/model-parameters.json",
                "mcp_library_sync_interval": 0,
            }
        },
        "providers": providers,
        "governance": governance,
    }
    return json.dumps(doc, indent=2) + "\n"


def render(spec: Spec) -> dict[str, str]:
    """``{relative path: text}`` for both gateways; deterministic for a given spec."""
    config, keys = render_litellm(spec)
    files = {
        "litellm/config.yaml": config,
        "litellm/keys.json": keys,
        "bifrost/config.json": render_bifrost(spec),
        "bifrost/pricing.json": "{}\n",
        "bifrost/model-parameters.json": "{}\n",
    }
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:16]
    files["litellm/config.yaml"] = (
        HEADER.format(spec=Path(spec.source).name, digest=digest) + config
    )
    problems = audit(files, spec)
    if problems:  # the renderer itself must never produce what the audit refuses
        raise GatewaySpecError("rendered gateway config fails its own audit", problems)
    return dict(sorted(files.items()))


def render_file(path: str | Path) -> dict[str, str]:
    return render(load_spec(path))


# ---------------------------------------------------------------------------- audit
def _local_hosts(spec: Spec) -> set[str]:
    """Hosts of local backends that really are internal (a self-declared one is not)."""
    return {
        b.host.lower()
        for b in spec.backends.values()
        if b.locality == "local" and internal_host(spec, b.host)
    }


def audit(files: Mapping[str, str], spec: Spec) -> list[str]:
    """Check rendered (or on-disk) gateway files against the locality rule; empty = clean.

    Locality is read from the files themselves, not from the spec: a LiteLLM deployment is local
    only when it is ``openai/`` on an ``api_base`` whose host is a declared local backend that is
    really internal (:func:`internal_host`); a Bifrost provider only when it is a custom provider
    whose ``base_url`` host is one.  Anything else - a cloud prefix, an unknown host, a provider
    without a base URL, a backend that only calls itself local - counts as cloud.
    """
    problems: list[str] = [
        f"backend svc:{b.name} is declared local but {b.host} is neither a registry service nor "
        f"under {spec.service_domain}"
        for b in sorted(spec.backends.values(), key=lambda b: b.name)
        if b.locality == "local" and not internal_host(spec, b.host)
    ]
    hosts = _local_hosts(spec)
    strict = dict(spec.local_only)
    for role, pid in spec.agent_roles.items():
        strict.setdefault(role, f"used by {pid}")
    lt = files.get("litellm/config.yaml")
    if lt is not None:
        problems += [f"litellm/config.yaml: {p}" for p in _audit_litellm(lt, hosts, strict)]
    bf = files.get("bifrost/config.json")
    if bf is not None:
        problems += [f"bifrost/config.json: {p}" for p in _audit_bifrost(bf, hosts, strict, spec)]
    return problems


def _host(url: Any) -> str:
    try:
        return (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return ""


def _audit_litellm(text: str, hosts: set[str], strict: Mapping[str, str]) -> list[str]:
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return [f"not YAML ({exc})"]
    local: dict[str, bool] = {}
    for d in doc.get("model_list") or []:
        p = d.get("litellm_params") or {}
        is_local = (
            str(p.get("model", "")).startswith("openai/") and _host(p.get("api_base")) in hosts
        )
        name = str(d.get("model_name"))
        local[name] = local.get(name, True) and is_local
    problems = [
        f"local-only/agent role {r} ({why}) has a cloud deployment"
        for r, why in sorted(strict.items())
        if r in local and not local[r]
    ]
    sections = [doc.get("router_settings") or {}, doc.get("litellm_settings") or {}]
    for sec in sections:
        for key in ("fallbacks", "context_window_fallbacks", "content_policy_fallbacks"):
            for entry in sec.get(key) or []:
                for src, targets in (entry or {}).items():
                    if src not in strict:
                        continue
                    for t in targets or []:
                        if not local.get(str(t), False):
                            problems.append(
                                f"{key}: {src} ({strict[src]}) falls back to non-local {t}"
                            )
        for t in sec.get("default_fallbacks") or []:
            if strict and not local.get(str(t), False):
                problems.append(
                    f"default_fallbacks names non-local {t}, which applies to every role"
                )
    return problems


def _audit_bifrost(text: str, hosts: set[str], strict: Mapping[str, str], spec: Spec) -> list[str]:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return [f"not JSON ({exc})"]
    local_prov = {
        name
        for name, p in (doc.get("providers") or {}).items()
        if (p.get("custom_provider_config") or {}).get("base_provider_type") == "openai"
        and _host((p.get("network_config") or {}).get("base_url")) in hosts
    }
    problems: list[str] = []
    for name, p in sorted((doc.get("providers") or {}).items()):
        if name in local_prov:
            continue
        for k in p.get("keys") or []:
            served = set(k.get("models") or []) | set((k.get("aliases") or {}).keys())
            for r in sorted(served & set(strict)):
                problems.append(
                    f"local-only/agent role {r} ({strict[r]}) is served by non-local {name}"
                )
            if "*" in served and strict:
                problems.append(f"non-local provider {name} serves every model ('*')")
    for rule in (doc.get("governance") or {}).get("routing_rules") or []:
        cel = str(rule.get("cel_expression", "true")).strip()
        hit = [r for r in strict if cel == "true" or f"'{r}'" in cel or f'"{r}"' in cel]
        if not hit:
            continue
        targets = [t.get("provider", "") for t in rule.get("targets") or []]
        for fb in rule.get("fallbacks") or []:
            targets.append(
                fb.get("provider", "") if isinstance(fb, Mapping) else str(fb).split("/")[0]
            )
        for t in targets:
            if t and t not in local_prov:
                problems.append(
                    f"routing rule {rule.get('id')} sends {', '.join(sorted(hit))} to non-local {t}"
                )
    strict_keys = {k.name for k in spec.keys if k.data_tier == "local-only"}
    for vk in (doc.get("governance") or {}).get("virtual_keys") or []:
        if vk.get("name") not in strict_keys:
            continue
        if vk.get("allow_all_providers"):
            problems.append(f"local-only key {vk['name']} allows every provider")
        for pc in vk.get("provider_configs") or []:
            if pc.get("provider") not in local_prov:
                problems.append(
                    f"local-only key {vk['name']} may call non-local {pc.get('provider')}"
                )
    return problems


# ---------------------------------------------------------------------------- provisioning
def provision_litellm(
    keys_doc: Mapping[str, Any],
    base_url: str,
    master_key: str,
    *,
    environ: Mapping[str, str],
    allow_plaintext: bool = False,
) -> list[str]:
    """Create, update or rotate every key of ``litellm/keys.json`` on a running LiteLLM proxy.

    LiteLLM keeps virtual keys in Postgres, so they cannot be in ``config.yaml``; this is the
    deploy step that puts them there.  Each key value comes from the environment variable the
    file names.  Keys are found by ``key_alias`` (``/key/list``), because LiteLLM's ``key`` field
    on ``/key/update`` names the *existing* key, not a new value:

    * the alias holds this value (LiteLLM stores the sha256 of an ``sk-`` key as its ``token``):
      the key is updated in place by its token;
    * the alias holds another value (the secret was rotated): the old key is deleted by token,
      so it stops working, and the new value is created;
    * the alias is unknown: the key is created.

    Idempotent.  Returns one line per key.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    from homelabnext._http import check_plaintext, safe_urlopen

    check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)

    def call(path: str, body: dict | None = None) -> tuple[int, str]:
        req = urllib.request.Request(
            base_url.rstrip("/") + path,
            data=None if body is None else json.dumps(body).encode(),
            method="GET" if body is None else "POST",
            headers={"Authorization": f"Bearer {master_key}", "Content-Type": "application/json"},
        )
        try:
            with safe_urlopen(req, timeout=30) as resp:
                return resp.status, resp.read(1 << 20).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(4096).decode("utf-8", "replace")

    def ok(alias: str, what: str, status: int, text: str) -> None:
        if status != 200:
            raise GatewaySpecError(f"key {alias}: {what}: HTTP {status}: {text[:200]}")

    def tokens_of(alias: str) -> list[str]:
        q = urllib.parse.urlencode({"key_alias": alias, "return_full_object": "true"})
        status, text = call(f"/key/list?{q}")
        ok(alias, "/key/list", status, text)
        try:
            listed = json.loads(text).get("keys") or []
        except (ValueError, AttributeError):
            raise GatewaySpecError(f"key {alias}: /key/list: not a key list") from None
        out = []
        for item in listed:  # tokens, or full objects with return_full_object
            if isinstance(item, Mapping):
                if item.get("key_alias") not in (None, alias):
                    continue  # a substring match from an older proxy: not this key
                item = item.get("token")
            if isinstance(item, str) and item:
                out.append(item)
        return out

    out = []
    for k in keys_doc.get("keys") or []:
        alias = k["key_alias"]
        value = environ.get(k["key_env"], "")
        if not value:
            raise GatewaySpecError(f"key {alias}: {k['key_env']} is not set")
        params = {kk: v for kk, v in k.items() if kk != "key_env"}
        token = hashlib.sha256(value.encode()).hexdigest()
        existing = tokens_of(alias)
        stale = [t for t in existing if t != token]
        if stale:  # rotated (or duplicated): the old value must stop working before the new one
            ok(alias, "/key/delete", *call("/key/delete", {"keys": stale}))
        if token in existing:
            ok(alias, "/key/update", *call("/key/update", params | {"key": token}))
            verb = "rotated" if stale else "updated"
        else:
            ok(alias, "/key/generate", *call("/key/generate", params | {"key": value}))
            verb = "rotated" if stale else "created"
        out.append(f"key {alias}: {verb} ({', '.join(k['models'])})")
    return out


# ---------------------------------------------------------------------------- CLI
def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hnx gen gateway",
        description="Render LiteLLM and Bifrost gateway config from the model-role table",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    rd = sub.add_parser("render", help="render SPEC into OUT_DIR (or --check for drift + audit)")
    rd.add_argument("spec")
    rd.add_argument("out_dir")
    rd.add_argument("--check", action="store_true", help="fail on drift or an audit finding")
    pv = sub.add_parser("provision", help="create the virtual keys of litellm/keys.json")
    pv.add_argument("keys")
    pv.add_argument("--endpoint-env", default="HNX_ENDPOINT_LLM_GATEWAY")
    pv.add_argument("--master-key-env", default=secret_env_name("secret:llm-gateway/master-key"))
    pv.add_argument(
        "--allow-plaintext", action="store_true", help="send the master key over http (lab only)"
    )
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.cmd == "provision":
        import os

        url, master = os.environ.get(args.endpoint_env), os.environ.get(args.master_key_env)
        if not url or not master:
            print(f"gateway: set {args.endpoint_env} and {args.master_key_env}", file=sys.stderr)
            return 2
        try:
            doc = json.loads(Path(args.keys).read_text(encoding="utf-8"))
            lines = provision_litellm(
                doc, url, master, environ=os.environ, allow_plaintext=args.allow_plaintext
            )
            for line in lines:
                print(line)
        except (OSError, ValueError) as exc:
            print(f"gateway: {exc}", file=sys.stderr)
            return 1
        return 0
    try:
        spec = load_spec(args.spec)
        files = render(spec)
    except GatewaySpecError as exc:
        print(f"gateway: {exc}", file=sys.stderr)
        return 1
    except (OSError, yaml.YAMLError) as exc:
        print(f"gateway: cannot read spec: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out_dir)
    if args.check:
        problems = check_tree(out, files)
        on_disk = {
            rel: (out / rel).read_text(encoding="utf-8") for rel in files if (out / rel).is_file()
        }
        problems += audit(on_disk, spec)
        for p in problems:
            print(f"gateway: {p}", file=sys.stderr)
        if problems:
            return 1
        print(f"gateway: {len(files)} files match {args.spec} and pass the locality audit")
        return 0
    res = write_tree(out, files)
    print(f"gateway: wrote {len(res.written)}, unchanged {len(res.unchanged)} in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
