# SPDX-License-Identifier: Apache-2.0
"""Render LLM gateway configuration (the LiteLLM proxy) from the model-role table.

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
  key, never the key, and each tagged ``metadata["hnx-managed"]`` so provisioning can delete the
  keys of profiles later removed from the spec.

LiteLLM is the only gateway (ADR-0022).  Bifrost was evaluated and its renderer removed on
2026-10-31; a spec with a ``bifrost:`` block is refused like any other unknown key.

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
  ``serving: <serving spec>`` declares the store-served ones from the serving plan
  (:mod:`homelabnext.models.serving`): each becomes ``{locality: local, port}`` and every binding
  on it must resolve to a store entry its engine may serve.
* A ``local`` backend is local because of where it is, not because the spec says so: it must be a
  registry service whose host sits in a non-cloud zone, or its host must be under the lab's
  internal service domain (``<svc_label>.<domain>``).  ``{locality: local, host: <a cloud API>}``
  is refused, and the audit counts such a host as cloud.

:func:`audit` re-checks the *rendered* files (``hnx gen gateway --check`` runs it on what is on
disk), so a hand edit that adds a cloud fallback to a local-only role fails the check even though
the generator would never write it; it also fails a key in ``keys.json`` without the
``hnx-managed`` tag or with a duplicate alias, since provisioning prunes by that tag.  With a
``controller:`` block (the orchestration controller's config and the ``HERMES_HOME`` of each of
its backends) ``--check`` also holds the controller's backend list to the spec and the role table
(:func:`homelabnext.generators.agent_homes.controller_problems`): every backend ``name`` is a
``svc:`` of the spec, its home's ``model.default`` is a role bound to it, and its ``max_context``
is that role's ``max_context_tokens``.  ``hnx gen gateway homes`` checks that a home names no IP
address and no engine model id (invariant A-14).

**The test-only render** (``render --conformance``, ADR-0038 decision 7): a spec's
``conformance:`` block (honoured only with the flag, refused without it) points every cloud
deployment at the fake inference server (``cloud_base_url``, a host under the lab's service
domain) instead of its provider's API, and ``--conformance-host`` (loopback only) moves every
deployment's host to the machine the suite runs on.  The render writes only ``gateway/``, its
``gateway.json`` carries ``"conformance_only": true`` (the gateway refuses to start on it outside
its conformance mode on loopback), and its audit requires exactly that, where a lab render's
audit refuses it.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import ipaddress
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from homelabnext import tlp
from homelabnext._yaml import UniqueKeyLoader
from homelabnext.models.store import ProblemsError
from homelabnext.modules import rules as module_rules
from homelabnext.registry.model import RegistryError, secret_env_name
from homelabnext.registry.model_tlp import DATA_TIERS, send_ceiling, tier_disagreement
from homelabnext.registry.models import RoleTable, RoleTableError

from . import agent_homes
from .agent_homes import ControllerRef, controller_problems, parse_controller
from .core import MARKER, check_tree, write_tree

__all__ = [
    "GatewaySpecError",
    "Spec",
    "audit",
    "load_spec",
    "main",
    "render",
    "render_file",
    "render_neutral",
]

SECRET_RE = re.compile(r"^secret:[a-z0-9][a-z0-9/_.-]*\Z")
SVC_RE = re.compile(r"^svc:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\Z")
MDL_RE = re.compile(r"^mdl:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\Z")
SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
ROLE_LIMIT_KEYS = ("max_requests", "max_tokens", "max_cost", "cost_per_1k_tokens")
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
LOCALITIES = ("local", "cloud")
#: the ``metadata`` tag on every key this generator declares: provisioning deletes a tagged key
#: whose alias the spec no longer declares, and never touches an untagged one
MANAGED = "hnx-managed"
#: the telemetry reader (docs/orchestration-telemetry.md): its key's alias, the one route it may
#: call, LiteLLM's view-only admin role, and the model name that blocks every model
READER_ALIAS = "telemetry-reader"
READER_ROUTES = ("/spend/logs/v2",)
READER_ROLE = "proxy_admin_viewer"
NO_MODELS = "no-default-models"
#: cloud providers the renderer knows how to name (the LiteLLM model prefix)
CLOUD_PROVIDERS = ("anthropic", "openai", "gemini", "mistral")
#: API domains of hosted model providers: no service domain or local host may sit under one, so a
#: spec that names one as the lab's ``domain`` cannot make a cloud API look internal
CLOUD_API_DOMAINS = (
    "anthropic.com",
    "openai.com",
    "googleapis.com",
    "mistral.ai",
    "azure.com",
    "amazonaws.com",
    "cohere.ai",
    "cohere.com",
    "groq.com",
    "together.xyz",
    "together.ai",
    "deepseek.com",
    "x.ai",
    "openrouter.ai",
    "fireworks.ai",
    "perplexity.ai",
)
HEADER = f"# {MARKER} llm_gateway from {{spec}} - do not edit; sha256:{{digest}}\n"
#: the product-neutral gateway config (ADR-0038 decision 1; schema platform/gateway_config, a
#: draft) and the marker beside it: JSON carries no comment and the contract allows no extra key,
#: so the generated-by line, the render digest and the file's own sha256 live in the sibling
NEUTRAL = "gateway/gateway.json"
NEUTRAL_MARKER = "gateway/.hnx-generated"
NEUTRAL_VERSION = "1.0"
NEUTRAL_SCHEMA = ("platform", "gateway_config.schema.json")
#: the API base of each cloud provider the neutral config can express, and its wire protocol
NEUTRAL_CLOUD = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}


class GatewaySpecError(ProblemsError):
    """The gateway spec, the role table or the profiles break a rule.  ``problems`` lists all."""


#: the hosts ``--conformance-host`` takes: the gateway's conformance mode serves loopback only,
#: and the fake it calls runs beside it
CONFORMANCE_HOSTS = ("127.0.0.1", "localhost")  # no-raw-endpoint: allow the loopback names


@dataclass(frozen=True)
class Conformance:
    """The test-only render (``--conformance``): ``cloud_base_url`` replaces every cloud
    deployment's provider API (the spec's ``conformance.cloud_base_url``, or None to keep the
    provider's), and ``host`` every deployment's host (``--conformance-host``, or None)."""

    cloud_base_url: str | None = None
    host: str | None = None

    def url(self, base_url: str) -> str:
        """``base_url`` with its host moved to :attr:`host` (its scheme and port kept)."""
        if self.host is None:
            return base_url
        parts = urlsplit(base_url)
        port = f":{parts.port}" if parts.port else ""
        return f"{parts.scheme}://{self.host}{port}"


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
    #: the key's sending TLP ceiling (ADR-0033 decision 11): its profile's ``tlp_ceiling``, a
    #: spec key's own, or what its ``data_tier`` allows (``cloud-allowed``: clear, else red)
    tlp_ceiling: tlp.Label = tlp.Label.RED


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
    #: the lab's internal service domain (``<svc_label>.<domain>``): a local host must be under it
    service_domain: str = "svc.example.internal"
    #: hosts that resolved through a registry service in a non-cloud zone
    registry_hosts: frozenset[str] = frozenset()
    #: this gateway's identity: the value of every key's ``metadata["hnx-managed"]`` tag, which
    #: provisioning prunes by (unnamed: keys are tagged ``true`` and never pruned)
    name: str = ""
    #: the orchestration controller whose backends sit behind this gateway (``--check`` holds its
    #: backend list and homes to the spec); None when the spec has no ``controller:`` block
    controller: ControllerRef | None = None
    #: the telemetry reader's key (``telemetry_reader.key``, a secret reference), or None
    telemetry_reader: str | None = None
    #: role -> its TLP ceiling as the gateway holds it (:func:`role_ceilings`); a role absent here
    #: is read as clear (:func:`ceiling_of`)
    ceilings: dict[str, tlp.Label] = field(default_factory=dict)
    #: the role table's roles as read (``leaves_lab`` of a role: :func:`leaves_lab_roles`)
    raw_roles: dict[str, Any] = field(default_factory=dict)
    #: the test-only render's options (``--conformance``), or None for a lab render
    conformance: Conformance | None = None

    @property
    def reader_user(self) -> str:
        """The LiteLLM user that owns the telemetry reader's key."""
        return f"hnx-{READER_ALIAS}-{self.name}" if self.name else f"hnx-{READER_ALIAS}"


def internal_host(spec: Spec, host: str) -> bool:
    """A host a ``local`` backend may use: a registry service's alias, or a name under the lab's
    internal service domain.  Anything else (a cloud API, a bare public name, an address) is not
    local, whatever the spec calls it."""
    host = host.lower().rstrip(".")
    if _under_cloud_api(host):
        return False
    return host in spec.registry_hosts or host.endswith("." + spec.service_domain)


def _under_cloud_api(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in CLOUD_API_DOMAINS)


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


def _deployment_share_problems(rname: str, role: Any) -> list[str]:
    """A role's limit is the role's, not each binding's.  LiteLLM enforces rpm/tpm and
    ``max_budget`` per deployment (one per binding), and its pre-call checks move an over-limit
    request onto the next deployment, so a role with ``n`` bindings gets ``1/n`` of the per-minute
    share on each (rounded down: never looser).  A share that rounds to nothing is refused."""
    n = len(role.bindings)
    out: list[str] = []
    for k in ("max_requests", "max_tokens"):
        count = role.limits.get(k)
        if not count or n < 2:
            continue
        share = per_minute(int(count), int(role.limits["window_s"]))
        if share is not None and share // n < 1:
            out.append(
                f"mdl:{rname}: limits.{k} {count:g} per {role.limits['window_s']:g}s is {share} a "
                f"minute, which cannot be split over its {n} bindings (the proxy limits each "
                "deployment) without loosening it: raise the count or bind fewer backends"
            )
    return out


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


def _registry_host_problem(registry: Any, host: str, service_domain: str, port: Any) -> str | None:
    """Why a self-declared local ``host`` (with ``port``) in the registry's alias zone may not be
    a backend (ADR-0039 decision 3: a gateway backend binds only a primary):

    * a capability's primary alias is that registry service, judged by the registry checks
      (zone, port, scheme) before this is called: a candidate usually shares the primary's
      host, so the alias with another port would reach it;
    * any other host with a label that names a registry row or capability is refused: a row's
      record (an ``eval`` or ``retiring`` row answers by its row name) or a made-up name under it.

    Any other name in the alias zone answers nothing: the registry generates every record there
    and site validation refuses a static one (``hnx site validate``)."""
    from homelabnext.registry.model import STANDINGS

    prefix = host[: -len(service_domain) - 1]
    if registry.by_capability(prefix) is not None:
        return None  # a primary alias is the registry service (spec_from_dict's registry checks)
    rows = {r.name: r for r in registry.rows(*STANDINGS)}
    caps = {r.capability for r in rows.values()}
    for label in prefix.split("."):
        row = rows.get(label)
        if row is not None and not row.is_primary:
            article = "an" if row.standing == "eval" else "a"
            where = "is" if label == prefix else "is under"
            return (
                f"host {host} {where} {article} {row.standing} row's record ({row.name}); a "
                "gateway backend binds only a primary (ADR-0039 decision 3)"
            )
        if row is not None or label in caps:
            kind = "row" if row is not None else "capability"
            return (
                f"host {host} names registry {kind} {label} but is not a capability's primary "
                "alias; name the registry row as the backend, or use the capability alias"
            )
    return None


def _role_table(base: Path, rel: str, root: Path | None = None) -> tuple[RoleTable, Any]:
    """The spec's role table and its raw ``roles``, read inside ``root`` (the caller's: default
    the working directory ``hnx`` runs in, never one discovered from the spec's directory)
    without following a symbolic link (:func:`homelabnext.modules.loader.read_contained`, as
    ``hnx registry bindings`` reads it) and validated by :meth:`RoleTable.loads`."""
    from homelabnext.modules import loader as ld

    try:
        data = ld.read_contained(base, rel, root)
    except ld.Unreadable as exc:
        raise OSError(str(exc)) from None
    table = RoleTable.loads(data, rel)
    return table, json.loads(data.decode("utf-8"))["roles"]


def load_spec(
    path: str | Path,
    *,
    conformance: bool = False,
    conformance_host: str | None = None,
    registry: Any = None,
    root: Path | None = None,
) -> Spec:
    """Read and validate a gateway spec; relative paths in it resolve against its directory.
    ``conformance`` (and ``conformance_host``) select the test-only render (module docstring);
    ``registry`` replaces the spec's own ``registry:`` file."""
    path = Path(path)
    doc = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    return spec_from_dict(
        doc,
        base=path.parent,
        source=path.as_posix(),
        conformance=conformance,
        conformance_host=conformance_host,
        registry=registry,
        root=root,
    )


def spec_from_dict(
    doc: Any,
    *,
    base: Path,
    source: str = "<spec>",
    conformance: bool = False,
    conformance_host: str | None = None,
    registry: Any = None,
    root: Path | None = None,
) -> Spec:
    """``root`` bounds the role table's path (default: the working directory when the spec is
    in it, else the spec's directory).  ``registry`` (a loaded :class:`~homelabnext.registry.model.Registry`) is used instead of
    the spec's own ``registry:`` file when given (``hnx registry bindings --gateway``)."""
    problems: list[str] = []
    if not isinstance(doc, Mapping):
        raise GatewaySpecError(f"{source}: the gateway spec must be a mapping")
    _one_line("spec", dict(doc), problems)
    known = {
        "roles", "profiles", "registry", "domain", "svc_label", "master_key", "database_url",
        "backends", "local_only", "keys", "serving", "name", "controller",
        "telemetry_reader", "conformance",
    }  # fmt: skip
    spec_name = doc.get("name", "")
    if spec_name != "" and not (isinstance(spec_name, str) and SLUG_RE.match(spec_name)):
        problems.append(
            f"name {spec_name!r} must be a lower-case slug (it tags this gateway's keys)"
        )
        spec_name = ""
    for k in sorted(set(doc) - known):
        problems.append(f"unknown key {k!r}")

    roles_path = doc.get("roles")
    if not isinstance(roles_path, str):
        raise GatewaySpecError(f"{source}: 'roles' (the role table path) is required")
    try:
        table, raw_roles = _role_table(base, roles_path, root)
    except RoleTableError as exc:
        raise GatewaySpecError(f"{source}: role table invalid", exc.problems) from None
    except (OSError, ValueError) as exc:
        raise GatewaySpecError(f"{source}: cannot read role table {roles_path}: {exc}") from None
    problems += [f"{roles_path}: {p}" for p in module_rules.role_ceiling_problems(raw_roles)]

    if registry is None and doc.get("registry"):
        from homelabnext.registry import load as load_registry

        registry = load_registry(base / str(doc["registry"]))
    domain = str(doc.get("domain") or (registry.domain if registry else "example.internal"))
    svc_label = str(doc.get("svc_label") or (registry.svc_label if registry else "svc"))
    service_domain = f"{svc_label}.{domain}".lower()
    if registry is not None:
        for field, ours, theirs in (
            ("domain", domain, registry.domain),
            ("svc_label", svc_label, registry.svc_label),
        ):
            if str(ours).lower() != str(theirs).lower():
                problems.append(
                    f"{source}: {field} {ours!r} differs from the registry's {theirs!r}; "
                    "the service domain comes from the registry"
                )
    if _under_cloud_api(service_domain):
        problems.append(
            f"{source}: the service domain {service_domain} is under a model provider's API "
            "domain, so nothing under it is local"
        )
    registry_hosts: set[str] = set()

    backends: dict[str, Backend] = {}
    raw_backends = doc.get("backends")
    if doc.get("serving") is not None:
        raw_backends = _served_backends(
            base, roles_path, doc["serving"], raw_backends or {}, problems
        )
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
        other = registry.row(name, "eval", "retiring", "legacy") if registry else None
        if svc is None and other is not None:
            # its row-name record would take the non-registry path below and reach the row
            problems.append(
                f"{where}: registry row {name} is {'an' if other.standing == 'eval' else 'a'} "
                f"{other.standing} row; a gateway backend binds only a primary (ADR-0039 "
                "decision 3)"
            )
            continue
        if svc is None and registry is not None:
            # a self-declared host that is a capability's primary alias is that registry
            # service: it meets the registry checks below (zone, port, scheme), never the
            # self-declared path's, which does not know where the service runs
            alias = str(b.get("host") or f"{name}.{svc_label}.{domain}").lower()
            if alias.endswith("." + service_domain):
                svc = registry.by_capability(alias[: -len(service_domain) - 1])
            via = f" (host {alias} is its capability alias)" if svc is not None else ""
        else:
            via = ""
        if svc is not None:
            if _cloud_zone(registry, svc):
                problems.append(
                    f"{where}: registry service {svc.name}{via} is not in a lab zone, so it is "
                    "not local"
                )
                continue
            host = f"{svc.capability}.{svc_label}.{domain}".lower()
            if "port" in b and b["port"] != svc.port:
                problems.append(
                    f"{where}: port {b['port']} (the spec or the serving plan) is not registry "
                    f"service {svc.name}'s port {svc.port}{via}; the gateway would call one and "
                    "the engine listen on the other (make them agree; a second API port is a "
                    "second registry row)"
                )
                continue
            if b.get("host") and str(b["host"]).lower() != host:
                problems.append(
                    f"{where}: host {b['host']} is not registry service {svc.name}'s {host}"
                )
                continue
            if "scheme" in b and str(b["scheme"]) != svc.scheme:
                problems.append(
                    f"{where}: scheme {b['scheme']} is not registry service {svc.name}'s "
                    f"{svc.scheme}{via}"
                )
                continue
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
            why = _registry_host_problem(registry, host, service_domain, port) if registry else None
            if why:
                problems.append(f"{where}: {why}")
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
            found = limit_problems(
                f"mdl:{rname}", role.limits, allowed=("window_s", *ROLE_LIMIT_KEYS)
            )
            problems += found or _deployment_share_problems(rname, role)
        for b in role.bindings:
            if b.backend not in backends:
                problems.append(
                    f"mdl:{rname}: binds svc:{b.backend}, which backends does not declare"
                )

    problems += leaves_lab_problems(raw_roles, backends, roles_path)

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
            ceiling = _key_ceiling(p, prof, tier, problems)
            if ceiling is None:
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
                    tlp_ceiling=ceiling,
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
        ceiling = _key_ceiling(where, k, tier, problems)
        if ceiling is None:
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
                tlp_ceiling=ceiling,
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

    master_key = _secret("master_key", doc.get("master_key"), problems)
    database_url = _secret("database_url", doc.get("database_url"), problems)
    reader = None
    raw_reader = doc.get("telemetry_reader")
    if raw_reader is not None:
        if not isinstance(raw_reader, Mapping) or set(raw_reader) != {"key"}:
            problems.append(
                "telemetry_reader takes key (a secret: reference for the spend-log reader's key)"
            )
        else:
            reader = _secret("telemetry_reader.key", raw_reader["key"], problems)
        if READER_ALIAS in {k.name for k in keys}:
            problems.append(f"key name {READER_ALIAS!r} is the telemetry reader's; rename the key")
    controller = None
    if doc.get("controller") is not None:
        controller = parse_controller(doc["controller"], base, problems)
    others: dict[str, str] = {}
    if reader is not None:
        others["telemetry_reader.key"] = reader
    problems += _secret_collisions(keys, master_key, database_url, backends, others)
    test_only = _conformance(
        doc.get("conformance"), conformance, conformance_host, service_domain, problems
    )
    cloud = sorted(b.name for b in backends.values() if b.locality == "cloud")
    if test_only is not None and test_only.cloud_base_url is None and cloud:
        problems.append(
            f"--conformance: cloud backend(s) {', '.join(f'svc:{c}' for c in cloud)} would call "
            "their provider with the suite's prompts and a real key; give the spec "
            "conformance.cloud_base_url (the fake inference server)"
        )

    spec = Spec(
        name=spec_name,
        source=source,
        table=table,
        backends=backends,
        keys=keys,
        master_key=master_key,
        database_url=database_url,
        local_only=local_only,
        agent_roles=agent_roles,
        service_domain=service_domain,
        registry_hosts=frozenset(registry_hosts),
        controller=controller,
        telemetry_reader=reader,
        raw_roles=dict(raw_roles) if isinstance(raw_roles, Mapping) else {},
        conformance=test_only,
    )
    if not problems:
        spec.ceilings = role_ceilings(spec, raw_roles)
        problems += locality_problems(spec)
        problems += tlp_problems(spec)
    if problems:
        raise GatewaySpecError(f"{source}: invalid gateway spec", problems)
    return spec


def _conformance(
    raw: Any, enabled: bool, host: str | None, service_domain: str, problems: list[str]
) -> Conformance | None:
    """The test-only render's options, or None for a lab render.  The spec's ``conformance:``
    block is refused without ``--conformance``, so no lab render can point a cloud deployment
    anywhere but its provider; ``cloud_base_url`` must be an http(s) origin under the lab's
    service domain (the fake inference server), and ``host`` a loopback name."""
    if not enabled:
        if raw is not None:
            problems.append(
                "conformance: is honoured only by the test-only render (render --conformance); "
                "a lab spec never carries it"
            )
        if host is not None:
            problems.append("--conformance-host needs --conformance")
        return None
    if host is not None and host not in CONFORMANCE_HOSTS:
        problems.append(
            f"--conformance-host {host!r}: the gateway's conformance mode serves loopback only, "
            f"so the host is one of {', '.join(CONFORMANCE_HOSTS)}"
        )
        host = None
    if raw is None:
        return Conformance(host=host)
    if not isinstance(raw, Mapping) or set(raw) - {"cloud_base_url"}:
        problems.append("conformance takes cloud_base_url (the fake inference server's origin)")
        return Conformance(host=host)
    url = raw.get("cloud_base_url")
    parts = urlsplit(url) if isinstance(url, str) else None
    try:
        port_ok = parts is not None and (parts.port is None or 0 < parts.port < 65536)
    except ValueError:
        port_ok = False
    if (
        parts is None
        or not port_ok
        or parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path
        or parts.query
        or parts.fragment
        or url != f"{parts.scheme}://{parts.netloc}"
        or not parts.hostname.endswith("." + service_domain)
        or _under_cloud_api(parts.hostname)
    ):
        problems.append(
            f"conformance.cloud_base_url {url!r}: an http(s) origin (no path, no slash) under "
            f"the lab's service domain {service_domain} (the fake inference server)"
        )
        return Conformance(host=host)
    return Conformance(cloud_base_url=str(url), host=host)


def _served_backends(
    base: Path, roles_path: str, serving: Any, declared: Any, problems: list[str]
) -> Mapping[str, Any]:
    """``backends`` with every backend of the serving plan added as ``{locality: local, port}``.

    The serving plan (``homelabnext.models.serving``) says which engine serves which store entry
    on which port; the gateway needs only where each backend is.  A backend the spec also declares
    must agree (local, same port), and the plan must be built on this spec's role table, or the
    gateway and the engines would disagree about what a role is."""
    from homelabnext.models.serving import ServingSpecError, load_plan

    if not isinstance(declared, Mapping):
        return declared
    try:
        plan = load_plan(base / str(serving))
    except ServingSpecError as exc:
        problems += [f"serving: {p}" for p in exc.problems] or [f"serving: {exc}"]
        return declared
    except (OSError, yaml.YAMLError) as exc:
        problems.append(f"serving: cannot read {serving}: {exc}")
        return declared
    if plan.roles_path != (base / roles_path).resolve():
        problems.append(f"serving: {serving} is built on another role table than {roles_path}")
    if plan.exposure != "zone":
        problems.append(
            f"serving: {serving} has exposure {plan.exposure}: its engines listen on the host's "
            "loopback, and the gateway reaches a backend over the network as "
            "<name>.<svc_label>.<domain>; set exposure: zone (and the host's zone address as "
            "vllm_server_listen_address)"
        )
    merged = dict(declared)
    for name, b in sorted(plan.backends.items()):
        sid = f"svc:{name}"
        if sid not in merged:
            merged[sid] = {"locality": "local", "port": b.port}
            continue
        have = merged[sid]
        if isinstance(have, Mapping) and (
            have.get("locality") != "local" or have.get("port", b.port) != b.port
        ):
            problems.append(
                f"backends.{sid}: the serving plan runs it locally on port {b.port} "
                f"({b.engine}); drop the declaration or match it"
            )
    return merged


def _secret_collisions(
    keys: list[Key],
    master_key: str,
    database_url: str,
    backends: Mapping[str, Backend],
    others: Mapping[str, str] | None = None,
) -> list[str]:
    """Every client credential is its own secret.  Two keys (or a key and the master key or the
    database URL) sharing a ``secret:`` reference, or two distinct references that map to the same
    ``HNX_SECRET_*`` variable (``key-private`` and ``key.private``), would make one value both a
    local-only key and a cloud-allowed one.  A client credential may not be a backend's upstream
    key either; backends may share an upstream key among themselves."""
    owners = [(f"key {k.name}", k.secret) for k in keys]
    owners += [("master_key", master_key), ("database_url", database_url)]
    owners += list((others or {}).items())
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


def _key_ceiling(where: str, doc: Mapping[str, Any], tier: Any, problems: list[str]):
    """A key's sending TLP ceiling (ADR-0033 decisions 11 and 12): a declared ``tlp_ceiling`` (a
    canonical label that agrees with the key's ``data_tier``), else the one its ``data_tier``
    allows (:func:`~homelabnext.registry.model_tlp.send_ceiling`: ``cloud-allowed`` is clear,
    anything else red).  ``None`` (with a problem) when the declaration is refused."""
    if "tlp_ceiling" not in doc:
        return send_ceiling(data_tier=tier)
    raw = doc["tlp_ceiling"]
    try:
        label = tlp.parse(raw)
    except ValueError as exc:
        problems.append(f"{where}: tlp_ceiling: {exc}")
        return None
    if raw != str(label):
        problems.append(f"{where}: tlp_ceiling {raw!r} is not written as {str(label)!r}")
        return None
    bad = tier_disagreement(tier, label, f"tlp_ceiling {label}")
    if bad:
        problems.append(f"{where}: {bad}")
        return None
    return label


def leaves_lab_problems(
    raw_roles: Mapping[str, Any], backends: Mapping[str, Backend], roles_path: str
) -> list[str]:
    """Every binding the spec puts on a cloud backend is marked ``leaves_lab: true`` in the role
    table, and no binding on a local backend is (ADR-0033 decision 10).

    The role table is the one source of a role's ``leaves_lab`` and so of its TLP ceiling: the
    per-request rule (:func:`homelabnext.registry.model_tlp.admit`) and ``grants.cloud_models``
    read it and nothing else.  A cloud binding the table does not mark would let ``admit`` judge
    the role as staying in the lab (ceiling ``red``) while this gateway sends its prompts out, so
    the disagreement is refused here rather than reconciled."""
    problems: list[str] = []
    for rname, r in sorted(raw_roles.items()):
        if not isinstance(r, Mapping):
            continue
        for i, b in enumerate(r.get("bindings") or []):
            if not isinstance(b, Mapping):
                continue
            be = backends.get(str(b.get("backend", "")).removeprefix("svc:"))
            if be is None:
                continue  # reported as an undeclared backend
            marked = b.get("leaves_lab") is True
            where = f"{roles_path}: mdl:{rname} bindings[{i}] (svc:{be.name})"
            if be.locality == "cloud" and not marked:
                problems.append(
                    f"{where}: the gateway spec puts it on a cloud backend but the role table "
                    "does not mark it leaves_lab: true, so the role's TLP ceiling would read as "
                    "red (ADR-0033 decision 10); mark it, or bind a local backend"
                )
            elif be.locality != "cloud" and marked:
                problems.append(
                    f"{where}: marked leaves_lab: true but the gateway spec puts it on a local "
                    "backend; the role table and the gateway must agree where prompts go"
                )
    return problems


def role_ceilings(spec: Spec, raw_roles: Mapping[str, Any]) -> dict[str, tlp.Label]:
    """Role -> its TLP ceiling at this gateway (ADR-0033 decision 10): the role table's
    (:func:`homelabnext.modules.rules.role_ceiling`), exactly what
    :func:`homelabnext.registry.model_tlp.admit` reads.  :func:`leaves_lab_problems` has already
    refused a spec whose cloud bindings the table does not mark, so the two cannot disagree."""
    return {role: module_rules.role_ceiling(dict(raw_roles), role) for role in spec.table.roles}


def tlp_problems(spec: Spec) -> list[str]:
    """No key is scoped to a role whose TLP ceiling is below the key's sending ceiling (ADR-0033
    decision 11).  For a role that leaves the lab a request is judged at the higher of its claimed
    label and the sender's ceiling, so every request from such a key would be above the role's
    ceiling; the gateway itself cannot read a request's label (no admission code, ADR-0022), so
    the one part of the rule that needs no request is applied here, as key scope."""
    problems: list[str] = []
    for k in sorted(spec.keys, key=lambda k: k.name):
        for role in sorted(_allowed(spec, k)):
            ceiling = spec.ceilings.get(role, module_rules.CLOUD_CEILING)
            if k.tlp_ceiling > ceiling:
                via = "" if role in k.roles else " (down a fallback chain)"
                problems.append(
                    f"key {k.name} sends at TLP ceiling {k.tlp_ceiling} but may call "
                    f"mdl:{role}{via}, whose prompts can leave the lab at ceiling {ceiling}: every "
                    "request from it would be above the role's ceiling (ADR-0033 decision 11)"
                )
    return problems


# ---------------------------------------------------------------------------- rendering
def _env_ref_litellm(secret: str) -> str:
    return f"os.environ/{secret_env_name(secret)}"


def _per_minute(count: float, window_s: float, deployments: int = 1) -> int:
    """The validated per-minute form of a limit (:func:`per_minute`; the loader refused the rest),
    split evenly over ``deployments`` and rounded down."""
    share = per_minute(int(count), int(window_s))
    if share is None or share // deployments < 1:  # unreachable after load_spec: never looser
        raise GatewaySpecError(
            f"{count:g} per {window_s:g}s has no per-minute form over {deployments} deployment(s)"
        )
    return share // deployments


def _duration(window_s: float) -> str:
    """A whole-second window as LiteLLM's duration string (``60`` -> ``1m``)."""
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
        n = len(role.bindings)  # the proxy limits each deployment: each gets 1/n of the role's
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
                params["rpm"] = _per_minute(lim["max_requests"], lim["window_s"], n)
            if lim.get("max_tokens"):
                params["tpm"] = _per_minute(lim["max_tokens"], lim["window_s"], n)
            if lim.get("max_cost"):
                params["max_budget"] = lim["max_cost"] / n
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
        if n > 1 and lim:
            notes.append(
                f"mdl:{rname}: the proxy limits each deployment, so each of its {n} gets 1/{n} of "
                "the role's rpm/tpm (rounded down) and max_budget: the sum is never looser"
            )
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
            "metadata": {
                "owner": k.owner or k.name,
                "data_tier": k.data_tier,
                "tlp_ceiling": str(k.tlp_ceiling),
                MANAGED: spec.name or True,
            },
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
    doc_keys: dict[str, Any] = {"managed_by": spec.name} if spec.name else {}
    if spec.telemetry_reader is not None:
        # a view-only admin that may call no model, owning one key restricted to the spend-log
        # route (docs/orchestration-telemetry.md): three locks, each enough on its own
        doc_keys["users"] = [
            {"user_id": spec.reader_user, "user_role": READER_ROLE, "models": [NO_MODELS]}
        ]
        keys.append(
            {
                "key_alias": READER_ALIAS,
                "key_env": secret_env_name(spec.telemetry_reader),
                "user_id": spec.reader_user,
                "models": [NO_MODELS],
                "allowed_routes": list(READER_ROUTES),
                "metadata": {"owner": "telemetry", MANAGED: spec.name or True},
            }
        )
    return head + body, json.dumps(doc_keys | {"keys": keys}, indent=2) + "\n"


def _allowed(spec: Spec, key: Key) -> set[str]:
    """The roles a key may call: its own and their fallback chains (a fallback the key could not
    call would fail mid-request)."""
    return {r for role in key.roles for r in chain(spec.table, role)}


def leaves_lab_roles(spec: Spec) -> set[str]:
    """The roles a prompt can leave the lab through (bare names): the role table's
    :func:`homelabnext.modules.rules.cloud_roles`, the same reading the TLP rules use."""
    return {r.removeprefix("mdl:") for r in module_rules.cloud_roles(dict(spec.raw_roles))}


def neutral_refusals(spec: Spec) -> list[str]:
    """What in ``spec`` the gateway config contract (ADR-0038) cannot express; empty when
    :func:`render_neutral` can render it.  The LiteLLM files do not depend on this."""
    problems: list[str] = []
    for rname, role in sorted(spec.table.roles.items()):
        for i, b in enumerate(role.bindings):
            be = spec.backends[b.backend]
            where = f"mdl:{rname} bindings[{i}] (svc:{be.name})"
            if be.locality == "cloud" and be.provider not in NEUTRAL_CLOUD:
                problems.append(
                    f"{where}: cloud provider {be.provider} has no protocol in the gateway "
                    f"config (only {', '.join(sorted(NEUTRAL_CLOUD))}; ADR-0038 decision 3)"
                )
            elif role.kind == "embedding" and _protocol(be) == "anthropic":
                problems.append(
                    f"{where}: an embedding role on an anthropic deployment (the Messages API "
                    "has no embeddings)"
                )
        lim = role.limits
        if lim.get("max_cost") and lim.get("cost_per_1k_tokens") is None:
            problems.append(
                f"mdl:{rname}: limits.max_cost without limits.cost_per_1k_tokens: the gateway "
                "counts cost from tokens and would have nothing to count"
            )
    return problems


def _protocol(be: Backend) -> str:
    """A deployment's wire protocol: a local backend is OpenAI-compatible, a cloud one speaks its
    provider's (only the providers of :data:`NEUTRAL_CLOUD`)."""
    return be.provider if be.locality == "cloud" else "openai"


def _count(value: Any) -> int | None:
    return int(value) if value else None


def render_neutral(spec: Spec) -> str:
    """``gateway/gateway.json``: the product-neutral gateway config of ADR-0038 (schema
    ``platform/gateway_config``), from the same spec :func:`render_litellm` renders.

    Each role's TLP ceiling is :func:`role_ceilings`' and ``leaves_lab`` is
    :func:`leaves_lab_roles`' (what ``model_tlp.admit`` reads); deployments are the bindings in
    order; ``fallbacks`` is :func:`_fallback_targets` and a key's ``roles`` :func:`_allowed`, as
    LiteLLM gets them; limits are the declared ones, whole (one budget per role, never split per
    deployment); every credential is the environment name its ``secret:`` reference maps to.
    Raises :class:`GatewaySpecError` with :func:`neutral_refusals` when the contract cannot
    express the spec."""
    refused = neutral_refusals(spec)
    if refused:
        raise GatewaySpecError("the gateway config contract cannot express this spec", refused)
    return json.dumps(_neutral_doc(spec), indent=2, sort_keys=True) + "\n"


def _neutral_doc(spec: Spec) -> dict[str, Any]:
    """The document :func:`render_neutral` writes, for a spec :func:`neutral_refusals` passes
    (the audit compares an on-disk file with it).  Counts are JSON integers: the Go loader
    decodes ``window_s``, ``max_requests`` and ``max_tokens`` strictly, and the role table holds
    limits as floats."""
    leaving = leaves_lab_roles(spec)
    roles: dict[str, Any] = {}
    for rname, role in sorted(spec.table.roles.items()):
        deployments = []
        for i, b in enumerate(role.bindings):
            be = spec.backends[b.backend]
            deployments.append(
                {
                    "id": f"{rname}-{i + 1}",
                    "backend": be.name,
                    "locality": be.locality,
                    "protocol": _protocol(be),
                    "base_url": _base_url(spec, be),
                    "model": b.model_id,
                    "api_key_env": secret_env_name(be.api_key) if be.api_key else None,
                }
            )
        lim = role.limits
        roles[rname] = {
            "kind": role.kind,
            "max_context_tokens": role.max_context_tokens or None,
            "tlp_ceiling": str(spec.ceilings.get(rname, module_rules.CLOUD_CEILING)),
            "leaves_lab": rname in leaving,
            "deployments": deployments,
            "fallbacks": _fallback_targets(spec, rname),
            "limits": {
                "window_s": int(lim["window_s"]),
                "max_requests": _count(lim.get("max_requests")),
                "max_tokens": _count(lim.get("max_tokens")),
                "max_cost": lim.get("max_cost") or None,
            }
            if lim
            else None,
            "cost_per_1k_tokens": lim.get("cost_per_1k_tokens"),
        }
    keys = [
        {
            "alias": k.name,
            "key_env": secret_env_name(k.secret),
            "owner": k.owner or k.name,
            "data_tier": k.data_tier,
            "tlp_ceiling": str(k.tlp_ceiling),
            "roles": sorted(_allowed(spec, k)),
            "limits": {
                "window_s": int(k.window_s),
                "max_requests": _count(k.max_requests),
                "max_tokens": _count(k.max_tokens),
            }
            if k.window_s
            else None,
        }
        for k in sorted(spec.keys, key=lambda k: k.name)
    ]
    doc = {
        "version": NEUTRAL_VERSION,
        "name": spec.name,
        "admin_key_env": secret_env_name(spec.master_key),
        "roles": roles,
        "keys": keys,
        "telemetry_reader": {"key_env": secret_env_name(spec.telemetry_reader)}
        if spec.telemetry_reader is not None
        else None,
    }
    if spec.conformance is not None:  # contract R14: the one optional key
        doc["conformance_only"] = True
    return doc


def _base_url(spec: Spec, be: Backend) -> str:
    """A deployment's ``base_url``: its provider's API for a cloud backend, its own origin for a
    local one; in the test-only render, the fake's origin for a cloud backend when the spec names
    one, and every host moved to ``--conformance-host``."""
    test = spec.conformance
    if be.locality == "cloud":
        url = test.cloud_base_url if test and test.cloud_base_url else NEUTRAL_CLOUD[be.provider]
    else:
        url = be.base_url
    return test.url(url) if test else url


def _neutral_marker(spec: Spec, digest: str, neutral: str) -> str:
    """The generated-by marker beside ``gateway.json`` (which cannot carry one): the same header
    line as ``litellm/config.yaml`` (same digest), then the file's own sha256."""
    file_digest = hashlib.sha256(neutral.encode()).hexdigest()
    test_only = (
        "# conformance_only: a test-only render (render --conformance) for a conformance run\n"
        "# against the fake inference server; no lab gateway serves it\n"
        if spec.conformance is not None
        else ""
    )
    return (
        HEADER.format(spec=Path(spec.source).name, digest=digest)
        + "# gateway.json is the ADR-0038 gateway config (schema platform/gateway_config); JSON\n"
        + "# carries no comment, so this file marks it generated and holds its sha256\n"
        + test_only
        + f"gateway.json sha256:{file_digest}\n"
    )


def render(spec: Spec) -> dict[str, str]:
    """``{relative path: text}`` for the gateway; deterministic for a given spec.

    ``litellm/`` is always rendered.  ``gateway/gateway.json`` (and its marker) is rendered for
    every spec the gateway config contract can express; for one it cannot, the LiteLLM files are
    still written and ``litellm/config.yaml`` carries a ``# note:`` line per reason
    (:func:`neutral_refusals`), so a LiteLLM-only spec keeps working until the cutover.  The
    test-only render (``spec.conformance``) writes ``gateway/`` alone: LiteLLM has no
    conformance mode, and no lab gateway may read what it writes."""
    if spec.conformance is not None:
        return _render_conformance(spec)
    config, keys = render_litellm(spec)
    refused = neutral_refusals(spec)
    if refused:  # after the SPDX line, with the proxy config's other notes
        notes = "".join(f"# note: {NEUTRAL} is not rendered: {p}\n" for p in refused)
        config = config.replace("\n", "\n" + notes, 1)
    files = {
        "litellm/config.yaml": config,
        "litellm/keys.json": keys,
    }
    if not refused:
        files[NEUTRAL] = render_neutral(spec)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:16]
    files["litellm/config.yaml"] = (
        HEADER.format(spec=Path(spec.source).name, digest=digest) + config
    )
    if NEUTRAL in files:
        files[NEUTRAL_MARKER] = _neutral_marker(spec, digest, files[NEUTRAL])
    problems = audit(files, spec)
    if problems:  # the renderer itself must never produce what the audit refuses
        raise GatewaySpecError("rendered gateway config fails its own audit", problems)
    return dict(sorted(files.items()))


def _render_conformance(spec: Spec) -> dict[str, str]:
    """``gateway/`` of the test-only render (``render --conformance``): the neutral config with
    ``conformance_only`` and its marker; refused when the contract cannot express the spec."""
    neutral = render_neutral(spec)
    digest = hashlib.sha256(json.dumps({NEUTRAL: neutral}).encode()).hexdigest()[:16]
    files = {NEUTRAL: neutral, NEUTRAL_MARKER: _neutral_marker(spec, digest, neutral)}
    problems = audit(files, spec)
    if problems:
        raise GatewaySpecError("rendered gateway config fails its own audit", problems)
    return files


def render_file(path: str | Path) -> dict[str, str]:
    return render(load_spec(path))


# ---------------------------------------------------------------------------- audit
def _local_hosts(spec: Spec) -> set[str]:
    """Hosts of local backends that really are internal (a self-declared one is not); in the
    test-only render, the ``--conformance-host`` they were all moved to."""
    hosts = {
        b.host.lower()
        for b in spec.backends.values()
        if b.locality == "local" and internal_host(spec, b.host)
    }
    if spec.conformance is not None and spec.conformance.host is not None and hosts:
        return {spec.conformance.host}
    return hosts


def audit(files: Mapping[str, str], spec: Spec) -> list[str]:
    """Check rendered (or on-disk) gateway files against the locality rule; empty = clean.

    Locality is read from the files themselves, not from the spec: a LiteLLM deployment is local
    only when it is ``openai/`` on an ``api_base`` whose host is a declared local backend that is
    really internal (:func:`internal_host`).  Anything else - a cloud prefix, an unknown host, a
    deployment without an ``api_base``, a backend that only calls itself local - counts as cloud.
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
    kj = files.get("litellm/keys.json")
    if kj is not None:
        found = _audit_keys(kj, spec.name)
        if lt is not None:
            found += _audit_key_ceilings(kj, lt, hosts, spec)
        problems += [f"litellm/keys.json: {p}" for p in found]
    nj = files.get(NEUTRAL)
    if nj is not None:
        problems += [f"{NEUTRAL}: {p}" for p in _audit_neutral(nj, hosts, strict, spec)]
        marker = files.get(NEUTRAL_MARKER)
        if marker is not None:
            problems += [f"{NEUTRAL_MARKER}: {p}" for p in _audit_neutral_marker(marker, nj)]
    return problems


def _schema_problems(doc: Any) -> list[str]:
    """``doc`` against ``platform/gateway_config`` (fail closed: no validator is a problem)."""
    try:
        from homelabnext.schema_registry import validator
    except ImportError:  # pragma: no cover - the schema extra is part of every test install
        return ["cannot validate: jsonschema is not installed (the schema extra)"]
    try:
        v = validator(*NEUTRAL_SCHEMA)
    except (ImportError, OSError, ValueError) as exc:
        return [f"cannot validate against platform/gateway_config: {exc}"]
    return [
        f"schema: {'/'.join(map(str, e.absolute_path)) or '(top)'}: {e.message}"
        for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]


def _neutral_local(dep: Any, hosts: set[str]) -> bool:
    """A neutral deployment is local only when it says so, speaks OpenAI on a declared local
    host and carries no path: anything else counts as cloud, whatever its ``locality`` says."""
    if not isinstance(dep, Mapping) or dep.get("locality") != "local":
        return False
    return dep.get("protocol") == "openai" and _host(dep.get("base_url")) in hosts


def _audit_neutral(text: str, hosts: set[str], strict: Mapping[str, str], spec: Spec) -> list[str]:
    """Check a rendered (or on-disk) ``gateway/gateway.json``: schema-valid; no local-only or
    agent role (``strict``) has a cloud deployment or a fallback that has one (locality read from
    the file as :func:`_neutral_local` reads it); every role's ``tlp_ceiling`` and
    ``leaves_lab`` are the spec's (a role the file sends to the cloud is held to the cloud
    ceiling); every key is one the spec declares, with its data tier, sending ceiling and no
    role beyond :func:`_allowed`, and none reaches a role whose ceiling is below its own; key
    aliases sorted and unique; no ``conformance_only`` (R14: a test-only render is never a lab's);
    no ``local-only`` key may call a role with a cloud deployment or
    ``leaves_lab`` (amendment R13, which the gateway's loader also refuses); a cloud deployment's
    ``base_url`` is its provider's API; a missing or unknown ceiling reads as ``red`` (R1); no
    credential environment variable serves two purposes; every key's ``roles`` hold the
    ``fallbacks`` of each role it lists (the contract's invariant); and every field the spec
    decides is the spec's (:func:`_neutral_spec_problems`)."""
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return [f"not JSON ({exc})"]
    problems = _schema_problems(doc)
    if not isinstance(doc, Mapping):
        return problems
    if spec.conformance is not None:  # the test-only render: marked, always
        if doc.get("conformance_only") is not True:
            problems.append("conformance_only must be true in a test-only render (--conformance)")
    elif doc.get("conformance_only", False) is not False:  # contract R14: never in a lab render
        problems.append(
            "conformance_only is set: a config for a conformance run against a fake is never a "
            "lab gateway's config"
        )
    roles = doc.get("roles") if isinstance(doc.get("roles"), Mapping) else {}
    keys = [k for k in doc.get("keys") or [] if isinstance(k, Mapping)]

    def deps(role: str) -> list[Any]:
        r = roles.get(role)
        return list(r.get("deployments") or []) if isinstance(r, Mapping) else []

    def falls(role: str) -> list[str]:
        r = roles.get(role)
        return [str(f) for f in r.get("fallbacks") or []] if isinstance(r, Mapping) else []

    def cloud(role: str) -> bool:
        return any(not _neutral_local(d, hosts) for d in deps(role))

    for role in sorted(roles):
        for f in falls(role):
            if f == role:
                problems.append(f"role {role} lists itself as a fallback")
            elif f not in roles:
                problems.append(f"role {role} falls back to {f}, which is not a role here")
    for k in keys:  # the contract's invariant (the Go loader refuses a key that breaks it)
        listed = {str(r) for r in k.get("roles") or []}
        for role in sorted(listed & set(roles)):
            for f in falls(role):
                if f not in listed:
                    problems.append(
                        f"key {k.get('alias')} may call {role} but not its fallback {f}: a key's "
                        "roles hold the fallbacks of every role it lists"
                    )
    for role in sorted(roles):  # a cloud deployment calls its provider's real API, nothing else
        for d in deps(role):
            if not isinstance(d, Mapping) or d.get("locality") != "cloud":
                continue
            want_url = NEUTRAL_CLOUD.get(str(d.get("protocol")))
            test = spec.conformance
            if test is not None and test.cloud_base_url and want_url:  # the fake, test-only
                want_url = test.url(test.cloud_base_url)
            if d.get("base_url") != want_url:
                problems.append(
                    f"role {role} deployment {d.get('id')}: a cloud {d.get('protocol')} "
                    f"deployment's base_url must be {want_url}"
                )
    for role, why in sorted(strict.items()):
        if role not in roles:
            continue
        if cloud(role):
            problems.append(f"local-only/agent role {role} ({why}) has a cloud deployment")
        for f in falls(role):
            if f in roles and cloud(f):
                problems.append(f"local-only/agent role {role} ({why}) falls back to non-local {f}")

    # each role's ceiling as the gateway must hold it: the spec's, never above the cloud
    # ceiling when the file sends the role (or its chain) out while the spec reads it as local
    held: dict[str, tlp.Label] = {}
    for role in sorted(roles):
        r = roles[role] if isinstance(roles[role], Mapping) else {}
        out = cloud(role) or any(cloud(f) for f in falls(role) if f in roles)
        want = spec.ceilings.get(role, module_rules.CLOUD_CEILING)
        if out and want is tlp.Label.RED:
            want = module_rules.CLOUD_CEILING
        have = tlp.read(r.get("tlp_ceiling"))
        if have != want:
            problems.append(
                f"role {role}: tlp_ceiling read as {have}, but the role's ceiling is {want}"
            )
        should_leave = out or role in leaves_lab_roles(spec)
        if r.get("leaves_lab") is not should_leave:
            problems.append(f"role {role}: leaves_lab must be {str(should_leave).lower()}")
        held[role] = min(have, want)

    declared = {k.name: k for k in spec.keys}
    aliases = [str(k.get("alias")) for k in keys]
    if aliases != sorted(aliases):
        problems.append("keys are not sorted by alias")
    for dup in sorted({a for a in aliases if aliases.count(a) > 1}):
        problems.append(f"key {dup} is declared twice")
    for k in keys:
        alias = str(k.get("alias"))
        mine = declared.get(alias)
        if mine is None:
            problems.append(f"key {alias} is not a key of the spec")
            continue
        sender = tlp.read(k.get("tlp_ceiling"))
        if sender != mine.tlp_ceiling:
            problems.append(
                f"key {alias}: tlp_ceiling read as {sender}, the spec's is {mine.tlp_ceiling}"
            )
        sender = max(sender, mine.tlp_ceiling)
        if k.get("data_tier") != mine.data_tier:
            problems.append(f"key {alias}: data_tier must be {mine.data_tier}")
        listed = [str(r) for r in k.get("roles") or []]
        if "local-only" in (k.get("data_tier"), mine.data_tier):  # R13: what the loader refuses
            for role in listed:
                r = roles.get(role)
                if isinstance(r, Mapping) and (cloud(role) or r.get("leaves_lab") is not False):
                    problems.append(
                        f"key {alias} is local-only but may call {role}, which has a cloud "
                        "deployment or leaves the lab"
                    )
        wider = sorted(set(listed) - _allowed(spec, mine))
        if wider:
            problems.append(
                f"key {alias}: may call {', '.join(wider)}, which the spec does not grant"
            )
        for role in listed:
            if role not in roles:
                problems.append(f"key {alias}: role {role} is not a role here")
                continue
            ceiling = held[role]
            if sender > ceiling:
                problems.append(
                    f"key {alias} (tlp_ceiling {sender}) may call {role}, whose TLP ceiling "
                    f"is {ceiling} (ADR-0033 decision 11)"
                )

    # one environment variable, one credential: no client key is the admin's, the reader's or
    # another key's, and none is a deployment's upstream key
    client: dict[str, list[str]] = {}
    for who, env in [
        ("admin_key_env", doc.get("admin_key_env")),
        *[(f"key {k.get('alias')}", k.get("key_env")) for k in keys],
        *(
            [("telemetry_reader", doc["telemetry_reader"].get("key_env"))]
            if isinstance(doc.get("telemetry_reader"), Mapping)
            else []
        ),
    ]:
        client.setdefault(str(env), []).append(who)
    for env, whos in sorted(client.items()):
        if len(whos) > 1:
            problems.append(f"{' and '.join(whos)} share {env}: one value, several credentials")
    upstream = {
        str(d.get("api_key_env")): f"{role} deployment {d.get('id')}"
        for role in sorted(roles)
        for d in deps(role)
        if isinstance(d, Mapping) and d.get("api_key_env")
    }
    for env, whos in sorted(client.items()):
        if env in upstream:
            problems.append(f"{', '.join(whos)} ({env}) is the upstream key of {upstream[env]}")
    return problems + _neutral_spec_problems(doc, spec)


#: the fields of a deployment the spec's binding decides, compared one by one by the audit
NEUTRAL_DEPLOYMENT = ("id", "backend", "locality", "protocol", "base_url", "model", "api_key_env")
#: role and key fields compared with the spec as written (TLP fields have their own checks)
NEUTRAL_ROLE = ("kind", "max_context_tokens", "fallbacks", "limits", "cost_per_1k_tokens")
NEUTRAL_KEY = ("key_env", "owner", "roles", "limits")


def _same(have: Any, want: Any) -> bool:
    """Equal as JSON (so ``60.0`` is not ``60``: the Go loader decodes counts strictly)."""
    return json.dumps(have, sort_keys=True) == json.dumps(want, sort_keys=True)


def _neutral_spec_problems(doc: Mapping[str, Any], spec: Spec) -> list[str]:
    """``gateway.json`` says what the spec renders, field by field: the role set, each role's
    deployments (what its bindings render), fallbacks (:func:`_fallback_targets`), limits and
    cost; each key's credential, owner, roles (:func:`_allowed`) and limits; the admin and
    telemetry credentials.  A file that is internally consistent but is not this spec's (an
    added fallback, swapped credentials, a deployment moved to another declared host) is refused
    here, whatever its marker records."""
    refused = neutral_refusals(spec)
    if refused:
        return [f"the spec has no gateway config, so this file is not its: {p}" for p in refused]
    want = _neutral_doc(spec)
    problems: list[str] = []
    for name in ("version", "name", "admin_key_env", "telemetry_reader"):
        if not _same(doc.get(name), want[name]):
            problems.append(f"{name} must be {json.dumps(want[name])}, the spec's")
    have_roles = doc.get("roles") if isinstance(doc.get("roles"), Mapping) else {}
    want_roles: dict[str, Any] = want["roles"]
    for role in sorted(set(want_roles) - set(have_roles)):
        problems.append(f"role {role} of the spec is missing")
    for role in sorted(set(have_roles) - set(want_roles)):
        problems.append(f"role {role} is not a role of the spec")
    for role in sorted(set(have_roles) & set(want_roles)):
        have, w = have_roles[role], want_roles[role]
        if not isinstance(have, Mapping):
            continue  # the schema has said so
        for name in NEUTRAL_ROLE:
            if not _same(have.get(name), w[name]):
                problems.append(f"role {role}: {name} must be {json.dumps(w[name])}, the spec's")
        deps = have.get("deployments") if isinstance(have.get("deployments"), list) else []
        if len(deps) != len(w["deployments"]):
            problems.append(
                f"role {role}: {len(deps)} deployment(s), but the spec binds "
                f"{len(w['deployments'])}"
            )
        for i, (d, wd) in enumerate(zip(deps, w["deployments"], strict=False)):
            d = d if isinstance(d, Mapping) else {}
            for name in NEUTRAL_DEPLOYMENT:
                if not _same(d.get(name), wd[name]):
                    problems.append(
                        f"role {role} deployments[{i}]: {name} must be {json.dumps(wd[name])}, "
                        "what the spec's binding renders"
                    )
    want_keys = {k["alias"]: k for k in want["keys"]}
    have_keys = {str(k.get("alias")): k for k in doc.get("keys") or [] if isinstance(k, Mapping)}
    for alias in sorted(set(want_keys) - set(have_keys)):
        problems.append(f"key {alias} of the spec is missing")
    for alias in sorted(set(have_keys) & set(want_keys)):
        for name in NEUTRAL_KEY:
            have, w = have_keys[alias].get(name), want_keys[alias][name]
            if not _same(have, w):
                problems.append(f"key {alias}: {name} must be {json.dumps(w)}, the spec's")
    return problems


def _audit_neutral_marker(marker: str, neutral: str) -> list[str]:
    """The marker beside ``gateway.json`` is the generator's and names that file's sha256."""
    if MARKER not in marker.split("\n", 1)[0]:
        return [f"first line is not the {MARKER!r} header"]
    want = f"gateway.json sha256:{hashlib.sha256(neutral.encode()).hexdigest()}"
    if want not in marker.splitlines():
        return ["gateway.json does not have the sha256 this marker records (edited by hand?)"]
    return []


def _audit_key_ceilings(keys_text: str, config_text: str, hosts: set[str], spec: Spec) -> list[str]:
    """No key reaches a model with a cloud deployment (read from the rendered config, as the
    locality audit reads it) whose TLP ceiling is below the key's ``metadata.tlp_ceiling``
    (ADR-0033 decision 11): a model it lists, an alias target, or a fallback of either
    (:func:`_reachable`).  A key's ceiling is read as data, so a missing or edited one is red;
    a model's is the spec's, never above clear when the file deploys it to the cloud while the
    spec reads it as local."""
    try:
        keys = (json.loads(keys_text) or {}).get("keys")
        doc = yaml.safe_load(config_text) or {}
    except (ValueError, yaml.YAMLError, AttributeError):
        return []  # the key and locality audits already report an unreadable file
    cloud = {
        str(d.get("model_name"))
        for d in doc.get("model_list") or []
        if not _local_deployment(d, hosts)
    }
    falls = _fallbacks(doc)
    problems: list[str] = []
    for k in keys if isinstance(keys, list) else []:
        if not isinstance(k, Mapping) or k.get("key_alias") == READER_ALIAS:
            continue
        sender = tlp.read((k.get("metadata") or {}).get("tlp_ceiling"))
        for m in _reachable(k, falls):
            if m not in cloud:
                continue
            ceiling = spec.ceilings.get(str(m), module_rules.CLOUD_CEILING)
            if ceiling is tlp.Label.RED:  # the spec reads it as local; the file deploys it out
                ceiling = module_rules.CLOUD_CEILING
            if sender > ceiling:
                problems.append(
                    f"key {k.get('key_alias')} (metadata.tlp_ceiling read as {sender}) reaches "
                    f"{m}, which has a cloud deployment at TLP ceiling {ceiling}"
                )
    return problems


def _reachable(key: Mapping[str, Any], falls: list[tuple[str, str | None, str]]) -> list[str]:
    """The models a key's request can be served by: the ones it lists, the targets of its
    ``aliases``, and every fallback (and default fallback) from any of them, transitively."""
    aliases = key.get("aliases") if isinstance(key.get("aliases"), Mapping) else {}
    todo = [str(m) for m in [*(key.get("models") or []), *aliases.values()]]
    seen: list[str] = []
    while todo:
        m = todo.pop(0)
        if m in seen:
            continue
        seen.append(m)
        todo += [t for _, src, t in falls if src is None or src == m]
    return seen


def _audit_keys(text: str, name: str = "") -> list[str]:
    """Every key is tagged ``hnx-managed`` with this gateway's ``name`` (what provisioning prunes
    by; ``true`` for an unnamed spec), ``managed_by`` says the same, and aliases are unique."""
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        return ["not a JSON object with a keys list"]
    problems, seen = [], set()
    want: Any = name or True
    if doc.get("managed_by", "") != name:
        problems.append(f"managed_by is {doc.get('managed_by')!r}, the spec's name is {name!r}")
    for k in keys:
        alias = k.get("key_alias") if isinstance(k, Mapping) else None
        if not alias:
            problems.append("a key has no key_alias")
            continue
        if alias in seen:
            problems.append(f"key {alias} is declared twice")
        seen.add(alias)
        tag = (k.get("metadata") or {}).get(MANAGED)
        if tag != want or type(tag) is not type(want):
            problems.append(
                f"key {alias} is not tagged metadata.{MANAGED}={want!r}: provisioning would "
                "never delete it once its profile is removed"
            )
    return problems + grant_problems(doc)


#: key fields that widen what a key may do beyond its declared models, which no generated key
#: carries: LiteLLM's key_type rewrites allowed_routes after the body is read (llm_api,
#: management), a team turns off the user's model block, and permissions open spend routes
_WIDENING = ("key_type", "team_id", "permissions")
_ALL_MODELS = ("all-proxy-models", "*")
_READER_FIELDS = {"key_alias", "key_env", "user_id", "models", "allowed_routes", "metadata"}


def grant_problems(doc: Any) -> list[str]:
    """What in a keys file would grant more than the gateway spec declares (empty = nothing).
    :func:`provision_litellm` refuses a file with any, so a hand-edited or stale file cannot
    create an admin or an unrestricted key on the proxy."""
    if not isinstance(doc, Mapping):
        return ["not a JSON object"]
    keys = doc.get("keys") if isinstance(doc.get("keys"), list) else []
    problems: list[str] = []
    users = doc.get("users", [])
    good_users = set()
    for u in users if isinstance(users, list) else [None]:
        if not (
            isinstance(u, Mapping)
            and set(u) == {"user_id", "user_role", "models"}
            and isinstance(u["user_id"], str)
            and u["user_role"] == READER_ROLE
            and u["models"] == [NO_MODELS]
        ):
            problems.append(
                f"users: each user is the telemetry reader ({READER_ROLE}, models "
                f"[{NO_MODELS!r}]), got {u!r}"
            )
            continue
        good_users.add(u["user_id"])
    for k in keys:
        if not isinstance(k, Mapping):
            continue
        alias = k.get("key_alias")
        for name in _WIDENING:
            if name in k:
                problems.append(f"key {alias}: {name} widens what the key may do")
        models = k.get("models")
        if isinstance(models, list) and any(m in _ALL_MODELS for m in models):
            problems.append(f"key {alias}: models names every model")
        reader = alias == READER_ALIAS or "user_id" in k or "allowed_routes" in k
        if reader and not (
            alias == READER_ALIAS
            and set(k) == _READER_FIELDS
            and k["allowed_routes"] == list(READER_ROUTES)
            and k["models"] == [NO_MODELS]
            and k["user_id"] in good_users
        ):
            problems.append(
                f"key {alias}: only the telemetry reader has a user or allowed_routes; it has "
                f"exactly {sorted(_READER_FIELDS)}, routes {list(READER_ROUTES)}, models "
                f"[{NO_MODELS!r}] and a user of users"
            )
    return problems


def _host(url: Any) -> str:
    try:
        return (urlsplit(str(url)).hostname or "").lower()
    except ValueError:
        return ""


def _local_deployment(entry: Any, hosts: set[str]) -> bool:
    """A ``model_list`` entry is local only when it is ``openai/`` on a declared local host."""
    p = (entry.get("litellm_params") if isinstance(entry, Mapping) else None) or {}
    return str(p.get("model", "")).startswith("openai/") and _host(p.get("api_base")) in hosts


def _audit_litellm(text: str, hosts: set[str], strict: Mapping[str, str]) -> list[str]:
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return [f"not YAML ({exc})"]
    local: dict[str, bool] = {}
    for d in doc.get("model_list") or []:
        name = str(d.get("model_name"))
        local[name] = local.get(name, True) and _local_deployment(d, hosts)
    problems = [
        f"local-only/agent role {r} ({why}) has a cloud deployment"
        for r, why in sorted(strict.items())
        if r in local and not local[r]
    ]
    for key, src, t in _fallbacks(doc):
        if local.get(t, False):
            continue
        if src is None:
            if strict:
                problems.append(
                    f"default_fallbacks names non-local {t}, which applies to every role"
                )
        elif src in strict:
            problems.append(f"{key}: {src} ({strict[src]}) falls back to non-local {t}")
    return problems


#: the proxy config's per-role fallback lists (``{role: [targets]}`` entries)
_FALLBACK_KEYS = ("fallbacks", "context_window_fallbacks", "content_policy_fallbacks")


def _fallbacks(doc: Any) -> list[tuple[str, str | None, str]]:
    """``(key, source role, target)`` for every fallback the rendered proxy config declares, in
    its router and proxy settings; a ``default_fallbacks`` target has no source (``None``: it
    applies to every role)."""
    out: list[tuple[str, str | None, str]] = []
    if not isinstance(doc, Mapping):
        return out
    for name in ("router_settings", "litellm_settings"):
        sec = doc.get(name) if isinstance(doc.get(name), Mapping) else {}
        for key in _FALLBACK_KEYS:
            for entry in sec.get(key) or []:
                for src, targets in (entry if isinstance(entry, Mapping) else {}).items():
                    out += [(key, str(src), str(t)) for t in targets or []]
        out += [("default_fallbacks", None, str(t)) for t in sec.get("default_fallbacks") or []]
    return out


# ---------------------------------------------------------------------------- provisioning
#: ``/key/list`` page size (LiteLLM's maximum)
_PAGE = 100


def provision_litellm(
    keys_doc: Mapping[str, Any],
    base_url: str,
    master_key: str,
    *,
    environ: Mapping[str, str],
    allow_plaintext: bool = False,
    prune: bool = True,
    dry_run: bool = False,
    emit: Callable[[str], None] | None = None,
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

    Then (``prune``, the default) every key on the proxy whose ``metadata["hnx-managed"]`` equals
    this file's ``managed_by`` (the gateway spec's ``name``) and whose alias the file no longer
    declares is deleted: a profile removed from the spec must not leave a working key behind.
    Keys tagged by another gateway spec, or not at all, are never touched; a file without
    ``managed_by`` (an unnamed spec) prunes nothing, and one that declares no keys refuses to.
    Untagged keys whose alias the file does not declare are listed (a key made before the tag
    existed has to be deleted by hand once).  ``dry_run`` sends no write and says what would
    change.  Each line is passed to ``emit`` as it happens, so a failure part-way still shows
    what was done.

    Idempotent.  Returns one line per key.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    from homelabnext._http import check_plaintext, safe_urlopen

    check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
    declared_keys = keys_doc.get("keys") if isinstance(keys_doc, Mapping) else None
    if not isinstance(declared_keys, list) or not all(
        isinstance(k, Mapping) and k.get("key_alias") for k in declared_keys
    ):
        raise GatewaySpecError(
            "keys file: not an object with a list of keys, each with a key_alias"
        )
    granted = grant_problems(keys_doc)
    if granted:
        raise GatewaySpecError("keys file grants more than a gateway spec declares", granted)
    identity = keys_doc.get("managed_by")
    out: list[str] = []

    def say(line: str) -> None:
        out.append(line)
        if emit is not None:
            emit(line)

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

    def ok(alias: str, what: str, status: int, text: str, kind: str = "key") -> None:
        if status != 200:
            raise GatewaySpecError(f"{kind} {alias}: {what}: HTTP {status}: {text[:200]}")

    def write(alias: str, path: str, body: dict, kind: str = "key") -> None:
        if not dry_run:
            ok(alias, path, *call(path, body), kind=kind)

    def tokens_of(alias: str) -> list[str]:
        q = urllib.parse.urlencode({"key_alias": alias, "return_full_object": "true"})
        status, text = call(f"/key/list?{q}")
        ok(alias, "/key/list", status, text)
        try:
            listed = json.loads(text).get("keys") or []
        except (ValueError, AttributeError):
            raise GatewaySpecError(f"key {alias}: /key/list: not a key list") from None
        found = []
        for item in listed:  # tokens, or full objects with return_full_object
            if isinstance(item, Mapping):
                if item.get("key_alias") not in (None, alias):
                    continue  # a substring match from an older proxy: not this key
                item = item.get("token")
            if isinstance(item, str) and item:
                found.append(item)
        return found

    would = "would be " if dry_run else ""
    users = keys_doc.get("users", [])
    if not isinstance(users, list) or not all(
        isinstance(u, Mapping) and isinstance(u.get("user_id"), str) and u["user_id"] for u in users
    ):
        raise GatewaySpecError("keys file: users must be a list of objects with a user_id")
    for u in users:
        uid = u["user_id"]
        q = urllib.parse.urlencode({"user_id": uid})
        status, text = call(f"/user/info?{q}")
        fields = {kk: v for kk, v in u.items() if kk != "user_id"}
        if status == 404:  # LiteLLM answers an unknown user_id with 404
            # auto_create_key false: /user/new would otherwise mint a key nothing declares
            write(uid, "/user/new", {"user_id": uid, **fields, "auto_create_key": False}, "user")
            verb = "created"
        else:
            ok(uid, "/user/info", status, text, kind="user")
            write(uid, "/user/update", {"user_id": uid, **fields}, "user")
            verb = "updated"
        say(f"user {uid}: {would}{verb} ({u.get('user_role')})")
    for k in declared_keys:
        alias = k["key_alias"]
        value = environ.get(k["key_env"], "")
        if not value:
            raise GatewaySpecError(f"key {alias}: {k['key_env']} is not set")
        params = {kk: v for kk, v in k.items() if kk != "key_env"}
        digest = hashlib.sha256(value.encode()).hexdigest()  # LiteLLM's token for this value
        existing = tokens_of(alias)
        stale = [t for t in existing if t != digest]
        if stale:  # rotated (or duplicated): the old value must stop working before the new one
            write(alias, "/key/delete", {"keys": stale})
        if digest in existing:
            write(alias, "/key/update", params | {"key": digest})
            verb = "rotated" if stale else "updated"
        else:
            write(alias, "/key/generate", params | {"key": value})
            verb = "rotated" if stale else "created"
        grant = (
            f"routes {', '.join(k['allowed_routes'])}"
            if k.get("allowed_routes")
            else ", ".join(k["models"])
        )
        say(f"key {alias}: {would}{verb} ({grant})")
    if not prune:
        return out
    declared = {k["key_alias"] for k in declared_keys}
    if not declared:
        say("prune refused: the keys file declares no keys (a wrong or empty file must not delete)")
        return out
    if not isinstance(identity, str) or not identity:
        say("prune skipped: the keys file has no managed_by (give the gateway spec a name)")
        return out
    mine, untagged = _listed_keys(call, ok, identity)
    for alias, tokens in sorted(mine.items()):
        if alias not in declared:
            write(alias, "/key/delete", {"keys": sorted(tokens)})
            say(f"key {alias}: {would}deleted (no longer declared by {identity})")
    left = sorted(a for a in untagged if a not in declared)
    if left:
        say(
            f"{len(left)} untagged key(s) whose alias this file does not declare were left alone "
            f"(delete by hand if they belonged to a removed profile): {', '.join(left)}"
        )
    return out


def _listed_keys(call: Any, ok: Any, identity: str) -> tuple[dict[str, set[str]], set[str]]:
    """Over every ``/key/list`` page: alias -> tokens of the keys tagged with ``identity``, and
    the aliases of keys carrying no :data:`MANAGED` tag at all."""
    import urllib.parse

    mine: dict[str, set[str]] = {}
    untagged: set[str] = set()
    page, pages = 1, 1
    while page <= pages:
        q = urllib.parse.urlencode({"return_full_object": "true", "page": page, "size": _PAGE})
        status, text = call(f"/key/list?{q}")
        ok("*", "/key/list", status, text)
        try:
            doc = json.loads(text)
            listed = doc.get("keys") or []
            pages = int(doc.get("total_pages") or 1)
        except (ValueError, AttributeError, TypeError):
            raise GatewaySpecError("/key/list: not a key list") from None
        for item in listed:
            if not isinstance(item, Mapping):
                continue  # a bare token carries no metadata: not provably anyone's
            meta = item.get("metadata")
            if isinstance(meta, str):  # some versions return the JSON column as text
                try:
                    meta = json.loads(meta)
                except ValueError:
                    meta = None
            meta = meta if isinstance(meta, Mapping) else {}
            token, alias = item.get("token"), item.get("key_alias")
            if not (token and alias):
                continue
            if meta.get(MANAGED) == identity:
                mine.setdefault(str(alias), set()).add(str(token))
            elif MANAGED not in meta:
                untagged.add(str(alias))
        page += 1
    return mine, untagged


# ---------------------------------------------------------------------------- CLI
def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hnx gen gateway",
        description="Render LiteLLM gateway config from the model-role table",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    rd = sub.add_parser("render", help="render SPEC into OUT_DIR (or --check for drift + audit)")
    rd.add_argument("spec")
    rd.add_argument("out_dir")
    rd.add_argument("--check", action="store_true", help="fail on drift or an audit finding")
    rd.add_argument(
        "--conformance",
        action="store_true",
        help="the test-only render: gateway/ alone, conformance_only, cloud deployments on the "
        "spec's conformance.cloud_base_url (ADR-0038 decision 7)",
    )
    rd.add_argument(
        "--conformance-host",
        metavar="HOST",
        help=f"with --conformance: move every deployment to HOST ({', '.join(CONFORMANCE_HOSTS)})",
    )
    rd.add_argument(
        "--root",
        help="the checkout the spec belongs to: its role table must stay inside it (default: the "
        "working directory when it is a checkout holding the spec, else the spec's directory)",
    )
    hm = sub.add_parser("homes", help=agent_homes.HOMES_HELP, description=agent_homes.HOMES_HELP)
    agent_homes.add_arguments(hm)
    pv = sub.add_parser("provision", help="create the virtual keys of litellm/keys.json")
    pv.add_argument("keys")
    pv.add_argument("--endpoint-env", default="HNX_ENDPOINT_LLM_GATEWAY")
    pv.add_argument("--master-key-env", default=secret_env_name("secret:llm-gateway/master-key"))
    pv.add_argument(
        "--allow-plaintext", action="store_true", help="send the master key over http (lab only)"
    )
    pv.add_argument(
        "--keep-undeclared",
        action="store_true",
        help=f"do not delete this gateway's {MANAGED} keys whose alias the file no longer declares",
    )
    pv.add_argument("--dry-run", action="store_true", help="send no write; print what would change")
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.cmd == "homes":
        return agent_homes.run(args)
    if args.cmd == "provision":
        import os

        url, master = os.environ.get(args.endpoint_env), os.environ.get(args.master_key_env)
        if not url or not master:
            print(f"gateway: set {args.endpoint_env} and {args.master_key_env}", file=sys.stderr)
            return 2
        try:
            doc = json.loads(Path(args.keys).read_text(encoding="utf-8"))
            provision_litellm(
                doc,
                url,
                master,
                environ=os.environ,
                allow_plaintext=args.allow_plaintext,
                prune=not args.keep_undeclared,
                dry_run=args.dry_run,
                emit=lambda line: print(line, flush=True),
            )
        except (OSError, ValueError) as exc:
            print(f"gateway: {exc}", file=sys.stderr)
            return 1
        return 0
    try:
        spec = load_spec(
            args.spec,
            conformance=args.conformance,
            conformance_host=args.conformance_host,
            root=Path(args.root) if args.root else None,
        )
        files = render(spec)
    except GatewaySpecError as exc:
        print(f"gateway: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, yaml.YAMLError, RegistryError) as exc:
        # an unreadable spec, profile or registry (a profile that is not JSON is a ValueError)
        print(f"gateway: cannot read spec: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out_dir)
    refused = [] if NEUTRAL in files else neutral_refusals(spec)
    for p in refused:
        print(f"gateway: {NEUTRAL} not rendered: {p}", file=sys.stderr)
    if args.check:
        problems = check_tree(out, files)
        problems += [f"stale: {rel} (no longer rendered)" for rel in _stale_neutral(out, files)]
        on_disk = {
            rel: (out / rel).read_text(encoding="utf-8") for rel in files if (out / rel).is_file()
        }
        problems += audit(on_disk, spec)
        problems += controller_problems(spec)
        for p in problems:
            print(f"gateway: {p}", file=sys.stderr)
        if problems:
            return 1
        also = " and the controller's backends agree with it" if spec.controller else ""
        print(f"gateway: {len(files)} files match {args.spec} and pass the locality audit{also}")
        return 0
    res = write_tree(out, files)
    for rel in _stale_neutral(out, files):  # never leave a config the gateway would still read
        (out / rel).unlink()
        res.pruned.append(rel)
    pruned = f", pruned {len(res.pruned)}" if res.pruned else ""
    print(f"gateway: wrote {len(res.written)}, unchanged {len(res.unchanged)}{pruned} in {out}")
    return 0


def _stale_neutral(out: Path, files: Mapping[str, str]) -> list[str]:
    """``gateway/gateway.json`` and its marker on disk when this render no longer produces them
    (the spec stopped being expressible).  The JSON file carries no marker of its own, so
    :func:`~homelabnext.generators.core.write_tree` cannot prune it.  ``gateway/gateway.json`` in
    this generator's output directory is the gateway's config whether or not its marker survived:
    a gateway would still read it, so it is stale (and removed) without one."""
    if NEUTRAL in files:
        return []
    return [rel for rel in (NEUTRAL, NEUTRAL_MARKER) if (out / rel).is_file()]


if __name__ == "__main__":
    sys.exit(main())
