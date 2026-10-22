# SPDX-License-Identifier: Apache-2.0
"""Client configurations rendered from the MCP catalog, never written by hand (ADR-0024).

``hnx mcp catalog render`` turns catalog records plus agent profiles into what a client reads:

* **instances.**  A record declares a server once; an *instance* is that server for one granted
  profile in one lane (``real``, ``shadow``, ...), with its ``parameters`` resolved (the grant's
  value from the render spec, else the default, templated over ``{id}``, ``{profile}`` and
  ``{lane}``) and checked against their type.  Its name is the record's ``instance`` template
  (default ``{id}``).  An unparameterized server granted twice in one home renders once; two
  different definitions under one name are refused.
* **clients.**  ``claude-code`` (``.mcp.json``), ``claude-desktop`` (stdio servers only),
  ``generic`` (``mcpServers`` with an explicit transport), ``hermes`` (a ``mcp_servers:`` YAML
  block, Hermes Agent's ``config.yaml`` shape) and ``llm-orchestrator`` (its
  ``configs/mcp_catalog.yaml`` kinds and each profile's ``grants:`` block, byte for byte the shape
  its ``internal/grants`` package reads).
* **secrets** are never values: an ``env`` secret, a ``secret:`` argument or header becomes
  ``${HNX_SECRET_<NAME>}`` (:func:`homelabnext.registry.model.secret_env_name`), which Claude Code
  expands from the environment at start and every other client gets from the deploy that installs
  the file.  **Endpoints** are built from the registry (scheme, capability alias, port, path),
  never written in a record.

A render *spec* (YAML) names the client, the catalog, the registry, the lanes, the profiles with
their grants' parameter values, and every output: one per runtime home (a primary and a fallback
Hermes home from one source), or for llm-orchestrator the catalog file and each profile's file
whose ``grants:`` block is spliced.  ``--check`` compares every output and fails on any drift, so
a hand edit or a home that lost an entry is caught.
"""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext.registry.model import secret_env_name

from . import servers

CLIENTS = ("claude-code", "claude-desktop", "generic", "hermes", "llm-orchestrator")
#: llm-orchestrator's server-name rule (internal/grants/grants.go:68, nameRe)
ORCH_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
#: the keys llm-orchestrator's catalog kinds and grants accept (grants.go:28-32, 44-47, read with
#: KnownFields at grants.go:85): anything else would be refused
ORCH_KIND_KEYS = ("command", "args", "timeout", "env", "allowed_env")
ORCH_GRANT_KEYS = ("name", "kind", "env", "timeout")
ORCH_LANES = ("real", "shadow")
#: the marker line a profile's spliced ``grants:`` block starts at (everything after it is ours)
GRANTS_MARKER = "# Per-job MCP grants (ADR-022)."
_SECRET_REF = re.compile(r"secret:[a-z][a-z0-9_-]*(?:/[a-z][a-z0-9_-]*)*")


class RenderError(ValueError):
    """The spec, a profile or a grant cannot be rendered; ``problems`` lists every reason."""

    def __init__(self, problems: list[str]):
        self.problems = list(problems)
        super().__init__("cannot render: " + "; ".join(self.problems))


@dataclass
class Instance:
    """One server instance: a record for one profile in one lane, parameters resolved."""

    name: str
    server: str
    profile: str
    lane: str
    record: Mapping[str, Any]
    params: dict[str, str]
    #: the values of parameters delivered in the environment (``{ENV: value}``)
    param_env: dict[str, str] = field(default_factory=dict)
    profile_file: str = ""

    def vars(self) -> dict[str, str]:
        return {"id": self.server, "profile": self.profile, "lane": self.lane, **self.params}


def _fill(text: str, values: Mapping[str, str]) -> str:
    return servers.TEMPLATE.sub(lambda m: values.get(m.group(1), m.group(0)), text)


def _placeholder(ref: str) -> str:
    return "${" + secret_env_name(ref) + "}"


def _secret_text(text: str) -> str:
    """``secret:<name>`` inside a value -> ``${HNX_SECRET_<NAME>}`` (never a value)."""
    return _SECRET_REF.sub(lambda m: _placeholder(m.group(0)), text)


def profile_name(pid: str) -> str:
    return pid.split(":", 1)[1] if ":" in pid else pid


def granted(profile: Mapping[str, Any]) -> list[str]:
    """The MCP server ids a compiled (``grants.mcp``) or lean (``mcp``) profile is granted."""
    g = profile.get("grants") if isinstance(profile.get("grants"), Mapping) else profile
    return sorted({str(x) for x in g.get("mcp") or ()})


def instances(
    cat: servers.Catalog,
    profile: Mapping[str, Any],
    *,
    lanes: Iterable[str] = ("real",),
    params: Mapping[str, Mapping[str, Any]] | None = None,
    profile_file: str = "",
) -> list[Instance]:
    """Every instance of every server ``profile`` is granted, per lane.  ``params``:
    ``{server: {parameter: value}}`` (the grant's values; ``server@lane`` overrides one lane; a
    list value expands into one instance per element).  Raises :class:`RenderError` listing
    every unknown, ungrantable or ill-typed grant."""
    pid = str(profile.get("id", "profile:?"))
    who = profile_name(pid)
    params = params or {}
    problems: list[str] = []
    out: list[Instance] = []
    names = granted(profile)
    for key in params:
        sid = key.split("@", 1)[0]
        if sid not in names:
            problems.append(f"{pid}: parameters for {key}, which the profile is not granted")
    for sid in names:
        rec = cat.get(sid)
        if rec is None:
            problems.append(f"{pid}: MCP server {sid!r} is not in the catalog {cat.root}")
            continue
        if rec.get("status") not in servers.GRANTABLE:
            problems.append(f"{pid}: MCP server {sid!r} is {rec.get('status')} (not grantable)")
            continue
        declared = rec.get("parameters") or {}
        for lane in lanes:
            given = {**(params.get(sid) or {}), **(params.get(f"{sid}@{lane}") or {})}
            unknown = sorted(set(given) - set(declared))
            if unknown:
                problems.append(f"{pid}: {sid} has no parameter(s) {unknown}")
                continue
            base = {"id": sid, "profile": who, "lane": lane}
            choices: list[list[tuple[str, str]]] = []
            for pname, p in declared.items():
                if pname in given:
                    raw = given[pname]
                    vals = [str(v) for v in raw] if isinstance(raw, list) else [str(raw)]
                elif p.get("default") is not None:
                    vals = [_fill(str(p["default"]), base)]
                else:
                    problems.append(f"{pid}: {sid}: parameter {pname} needs a value ({lane})")
                    vals = []
                for v in vals:
                    bad = servers.value_problem(p, v)
                    if bad:
                        problems.append(f"{pid}: {sid}: parameter {pname}: {bad}")
                choices.append([(pname, v) for v in vals])
            for combo in itertools.product(*choices) if declared else [()]:
                values = dict(combo)
                inst = Instance(
                    name="",
                    server=sid,
                    profile=who,
                    lane=lane,
                    record=rec,
                    params=values,
                    param_env={
                        declared[n]["env"]: v for n, v in values.items() if declared[n].get("env")
                    },
                    profile_file=profile_file,
                )
                inst.name = _fill(str(rec.get("instance") or "{id}"), inst.vars())
                if not ORCH_NAME.match(inst.name):
                    problems.append(
                        f"{pid}: {sid}: instance name {inst.name!r} is not a valid name"
                    )
                out.append(inst)
    if problems:
        raise RenderError(problems)
    return out


# ------------------------------------------------------------------------------- one instance
def _args(inst: Instance) -> list[str]:
    values = {**inst.vars(), servers.PROFILE_FILE: inst.profile_file}
    return [_secret_text(_fill(str(a), values)) for a in inst.record["transport"].get("args") or ()]


def _env(inst: Instance, *, fixed_only: bool = False) -> dict[str, str]:
    rec = inst.record
    env = {k: _fill(str(v), inst.vars()) for k, v in (rec.get("settings") or {}).items()}
    env.update({k: _placeholder(str(v)) for k, v in (rec.get("env") or {}).items()})
    if not fixed_only:
        env.update(inst.param_env)
    return dict(sorted(env.items()))


def _url(inst: Instance, registry: Any) -> str:
    t = inst.record["transport"]
    if registry is None:
        raise RenderError([f"{inst.server}: an HTTP server needs the registry for its URL"])
    svc = registry.services.get(str(t["endpoint"]).removeprefix("svc:"))
    if svc is None:
        raise RenderError([f"{inst.server}: endpoint {t['endpoint']} is not a registry service"])
    return f"{svc.scheme}://{registry.alias(svc.capability)}:{svc.port}{t.get('path', '/mcp')}"


def _headers(inst: Instance) -> dict[str, str]:
    return {k: _secret_text(str(v)) for k, v in sorted((inst.record.get("headers") or {}).items())}


def definition(inst: Instance, client: str, registry: Any = None) -> dict[str, Any] | None:
    """One instance's entry in ``client``'s format (``None``: the client cannot take it)."""
    t = inst.record["transport"]
    stdio = t["type"] == "stdio"
    if client == "claude-desktop" and not stdio:
        return None
    d: dict[str, Any] = {}
    if client in ("claude-code", "generic"):
        d["type" if client == "claude-code" else "transport"] = (
            "http" if t["type"] == "streamable-http" and client == "claude-code" else t["type"]
        )
    if stdio:
        d["command"] = t["command"]
        d["args"] = _args(inst)
        env = _env(inst)
        if env:
            d["env"] = env
    else:
        d["url"] = _url(inst, registry)
        headers = _headers(inst)
        if headers:
            d["headers"] = headers
    if client in ("hermes", "generic") and inst.record.get("timeout"):
        d["timeout"] = int(inst.record["timeout"])
    return d


def home_servers(
    insts: Iterable[Instance], client: str, registry: Any = None
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """``{name: definition}`` for one home, and the names a client could not take.  The same
    name twice is fine when the definitions are equal (a shared server), refused otherwise."""
    out: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []
    problems: list[str] = []
    for inst in insts:
        d = definition(inst, client, registry)
        if d is None:
            skipped.append(inst.name)
            continue
        if inst.name in out and out[inst.name] != d:
            problems.append(
                f"instance name {inst.name!r} renders two different servers (add {{profile}} "
                f"or {{lane}} to {inst.server}'s instance template)"
            )
        out[inst.name] = d
    if problems:
        raise RenderError(sorted(set(problems)))
    return dict(sorted(out.items())), sorted(set(skipped))


def generated_note(cat: servers.Catalog, what: str) -> str:
    return (
        f"generated by hnx mcp catalog render from the MCP catalog ({cat.root.name}/, "
        f"{cat.digest()[:19]}) for {what}; do not edit, render again"
    )


def render_home(
    insts: list[Instance], client: str, cat: servers.Catalog, registry: Any, what: str
) -> tuple[str, list[str]]:
    """The text of one client file (and the instance names it could not hold)."""
    servers_, skipped = home_servers(insts, client, registry)
    note = generated_note(cat, what)
    if client == "hermes":
        text = f"# {note}\n" + yaml.safe_dump({"mcp_servers": servers_}, sort_keys=True, width=100)
    else:
        text = json.dumps({"_generated": note, "mcpServers": servers_}, indent=2, sort_keys=True)
        text += "\n"
    return text, skipped


# ------------------------------------------------------------------------- llm-orchestrator
ORCH_CATALOG_HEAD = (
    "# MCP server catalog (ADR-022). GENERATED by hnx mcp catalog render --client "
    "llm-orchestrator\n"
    "# from the homelab-next MCP catalog; edit the catalog, never this file. One entry per server "
    "KIND:\n"
    "# command/args/fixed env are the catalog's; a profile's grant may set only allowed_env keys\n"
    "# (internal/grants also hard-denies PATH, LD_*, PYTHON*, HOME, HERMES_HOME and friends).\n"
)
ORCH_GRANTS_HEAD = (
    "\n" + GRANTS_MARKER + " Generated by hnx mcp catalog render --client llm-orchestrator\n"
    "# from the homelab-next MCP catalog and this profile's grants; edit those, never this "
    "block.\n"
)


def orch_kind(sid: str, rec: Mapping[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    """A record as an llm-orchestrator catalog kind, or None (not a stdio server) and why not."""
    t = rec.get("transport") or {}
    if t.get("type") != "stdio":
        return None, [f"{sid}: llm-orchestrator kinds start a command; {t.get('type')} is skipped"]
    problems: list[str] = []
    args = [str(a) for a in t.get("args") or ()]
    if any(servers.TEMPLATE.search(a) for a in args):
        problems.append(
            f"{sid}: an argument is per instance; llm-orchestrator kinds take per-instance "
            "values only through allowed_env (make it a parameter with env)"
        )
    settings = rec.get("settings") or {}
    if any(servers.TEMPLATE.search(str(v)) for v in settings.values()):
        problems.append(f"{sid}: a setting is per instance; make it a parameter with env")
    entry: dict[str, Any] = {"command": t["command"], "args": [_secret_text(a) for a in args]}
    if rec.get("timeout"):
        entry["timeout"] = int(rec["timeout"])
    env = {k: str(v) for k, v in settings.items()}
    env.update({k: _placeholder(str(v)) for k, v in (rec.get("env") or {}).items()})
    if env:
        entry["env"] = dict(sorted(env.items()))
    allowed = sorted(p["env"] for p in (rec.get("parameters") or {}).values() if p.get("env"))
    if allowed:
        entry["allowed_env"] = allowed
    return entry, problems


def orch_catalog(cat: servers.Catalog, granted_ids: Iterable[str] = ()) -> tuple[str, list[str]]:
    """``configs/mcp_catalog.yaml``: every grantable stdio server as a kind.  A server that
    cannot be a kind is skipped with a note, or refused when a rendered profile is granted it."""
    granted_ids = set(granted_ids)
    kinds: dict[str, Any] = {}
    notes: list[str] = []
    problems: list[str] = []
    for sid, rec in cat:
        if rec.get("status") not in servers.GRANTABLE:
            continue
        entry, why = orch_kind(sid, rec)
        if entry is None or (why and sid not in granted_ids):
            notes += why
            continue
        problems += why
        kinds[sid] = entry
    if problems:
        raise RenderError(problems)
    return ORCH_CATALOG_HEAD + yaml.safe_dump({"kinds": kinds}, sort_keys=True, width=100), notes


def orch_grants(insts: list[Instance], lanes: Iterable[str]) -> str:
    """One profile's ``grants:`` block (``real`` and ``shadow`` lists, by instance name)."""
    out: dict[str, list[dict[str, Any]]] = {lane: [] for lane in ORCH_LANES}
    for lane in lanes:
        out.setdefault(lane, [])
    for inst in sorted(insts, key=lambda i: (i.lane, i.name)):
        if (inst.record.get("transport") or {}).get("type") != "stdio":
            continue
        g: dict[str, Any] = {"name": inst.name, "kind": inst.server}
        if inst.param_env:
            g["env"] = dict(sorted(inst.param_env.items()))
        out[inst.lane].append(g)
    return ORCH_GRANTS_HEAD + yaml.safe_dump({"grants": out}, sort_keys=False, width=100)


def splice_grants(existing: str, block: str) -> str:
    """``existing`` (a profile file) with its generated grants block replaced by ``block``
    (appended when it has none)."""
    at = existing.find("\n" + GRANTS_MARKER)
    head = existing if at < 0 else existing[:at]
    return head.rstrip("\n") + "\n" + block


def orch_accepts(catalog_text: str, grant_blocks: Mapping[str, str]) -> list[str]:
    """What llm-orchestrator's ``internal/grants`` would refuse in these files, its rules encoded
    here (grants.go at llm-orchestrator commit 68ffbcd): known fields only (85, KnownFields), kind
    and server names (68, 90, 111), a command (94), no hard-denied allowed_env key (71, 98), no
    duplicate server (115), a known kind (119), only allowed, non-denied env keys (127)."""
    problems: list[str] = []
    doc = yaml.safe_load(catalog_text) or {}
    if set(doc) != {"kinds"}:
        problems.append(f"catalog: top-level keys {sorted(doc)} (only kinds)")
    kinds = doc.get("kinds") or {}
    for name, k in kinds.items():
        if not ORCH_NAME.match(name):
            problems.append(f"kind {name!r}: bad name")
        extra = set(k) - set(ORCH_KIND_KEYS)
        if extra:
            problems.append(f"kind {name}: unknown field(s) {sorted(extra)}")
        if not k.get("command"):
            problems.append(f"kind {name}: command is required")
        for key in k.get("allowed_env") or ():
            if servers.DENIED_ENV.match(key):
                problems.append(f"kind {name}: env key {key} may never be grant-settable")
    for who, block in grant_blocks.items():
        doc = yaml.safe_load(block) or {}
        lanes = doc.get("grants") or {}
        extra = set(lanes) - set(ORCH_LANES)
        if extra:
            problems.append(f"{who}: unknown lane(s) {sorted(extra)}")
        for lane, gs in lanes.items():
            seen: set[str] = set()
            for g in gs or ():
                if set(g) - set(ORCH_GRANT_KEYS):
                    problems.append(
                        f"{who}/{lane}: unknown grant field(s) {sorted(set(g) - set(ORCH_GRANT_KEYS))}"
                    )
                name = str(g.get("name"))
                if not ORCH_NAME.match(name):
                    problems.append(f"{who}/{lane}: server name {name!r}")
                if name in seen:
                    problems.append(f"{who}/{lane}: server {name} granted twice")
                seen.add(name)
                k = kinds.get(g.get("kind"))
                if k is None:
                    problems.append(f"{who}/{lane}: server {name}: unknown kind {g.get('kind')!r}")
                    continue
                for key in g.get("env") or {}:
                    if servers.DENIED_ENV.match(key) or key not in (k.get("allowed_env") or ()):
                        problems.append(f"{who}/{lane}: server {name} may not set env {key}")
    return problems


# --------------------------------------------------------------------------------- the spec
@dataclass
class Output:
    path: Path
    text: str
    #: ``splice``: the text is a grants block spliced into the file at ``path``
    splice: bool = False

    def expected(self) -> str:
        if not self.splice:
            return self.text
        old = self.path.read_text(encoding="utf-8") if self.path.is_file() else ""
        return splice_grants(old, self.text)


@dataclass
class Rendered:
    outputs: list[Output] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _load_profile(path: Path) -> dict[str, Any]:
    from homelabnext.agent.compiler import profile_digest

    try:
        text = path.read_text(encoding="utf-8")
        doc = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RenderError([f"{path}: cannot read the profile: {exc}"]) from None
    if not isinstance(doc, Mapping) or not str(doc.get("id", "")).startswith("profile:"):
        raise RenderError([f"{path}: not an agent profile (no profile: id)"])
    if "grants" in doc and doc.get("digest") and profile_digest(doc) != doc["digest"]:
        raise RenderError([f"{path}: the profile's digest does not match its content"])
    return dict(doc)


def render_profile(
    cat: servers.Catalog,
    profile_path: str | Path,
    client: str,
    *,
    registry: Any = None,
    params: Mapping[str, Mapping[str, Any]] | None = None,
    lanes: Iterable[str] = ("real",),
    profile_file: str | None = None,
) -> tuple[str, list[str]]:
    """One profile's client file (``--profile``)."""
    p = Path(profile_path)
    prof = _load_profile(p)
    lanes = list(lanes)
    insts = instances(
        cat, prof, lanes=lanes, params=params, profile_file=profile_file or str(profile_path)
    )
    if client == "llm-orchestrator":
        return orch_grants(insts, lanes), []
    text, skipped = render_home(insts, client, cat, registry, prof["id"])
    return text, [f"{client} cannot hold {n} (not a stdio server)" for n in skipped]


def _spec_problems(spec: Any) -> list[str]:
    if not isinstance(spec, Mapping):
        return ["the spec must be a mapping"]
    out = []
    extra = set(spec) - {"client", "catalog", "registry", "lanes", "profiles", "outputs"}
    if extra:
        out.append(f"unknown key(s) {sorted(extra)}")
    if spec.get("client") not in CLIENTS:
        out.append(f"client must be one of {list(CLIENTS)}")
    if not isinstance(spec.get("profiles"), list) or not spec.get("profiles"):
        out.append("profiles must list at least one profile")
    if not isinstance(spec.get("outputs"), list) or not spec.get("outputs"):
        out.append("outputs must list at least one file")
    return out


def render_spec(spec_path: str | Path) -> Rendered:
    """Every output a render spec names (see the module docstring)."""
    from homelabnext.registry.model import RegistryError, load

    sp = Path(spec_path)
    try:
        spec = yaml.safe_load(sp.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RenderError([f"{sp}: cannot read: {exc}"]) from None
    problems = _spec_problems(spec)
    if problems:
        raise RenderError([f"{sp}: {p}" for p in problems])
    base = sp.parent
    cat = servers.load((base / str(spec.get("catalog", ".."))).resolve())
    registry = None
    if spec.get("registry"):
        try:
            registry = load(base / str(spec["registry"]))
        except RegistryError as exc:
            raise RenderError([str(exc)]) from None
    client = spec["client"]
    lanes = [str(x) for x in spec.get("lanes") or ["real"]]
    res = Rendered()
    every: list[Instance] = []
    blocks: dict[str, tuple[Path, str]] = {}
    for entry in spec["profiles"]:
        pf = base / str(entry["file"])
        prof = _load_profile(pf)
        insts = instances(
            cat,
            prof,
            lanes=lanes,
            params=entry.get("params") or {},
            profile_file=str(entry.get("profile_file") or pf),
        )
        every += insts
        if client == "llm-orchestrator":
            if not entry.get("grants_file"):
                raise RenderError([f"{sp}: {prof['id']}: llm-orchestrator needs grants_file"])
            blocks[prof["id"]] = (base / str(entry["grants_file"]), orch_grants(insts, lanes))
    if client == "llm-orchestrator":
        text, notes = orch_catalog(cat, {i.server for i in every})
        res.notes += notes
        bad = orch_accepts(text, {k: v[1] for k, v in blocks.items()})
        if bad:
            raise RenderError(bad)
        for out in spec["outputs"]:
            res.outputs.append(Output(base / str(out["path"]), text))
        for path, block in blocks.values():
            res.outputs.append(Output(path, block, splice=True))
        return res
    for out in spec["outputs"]:
        what = f"home {out['home']}" if out.get("home") else f"{sp.name}"
        text, skipped = render_home(every, client, cat, registry, what)
        res.notes += [f"{what}: {client} cannot hold {n}" for n in skipped]
        res.outputs.append(Output(base / str(out["path"]), text))
    return res


def write(rendered: Rendered) -> list[Path]:
    paths = []
    for o in rendered.outputs:
        o.path.parent.mkdir(parents=True, exist_ok=True)
        o.path.write_text(o.expected(), encoding="utf-8")
        paths.append(o.path)
    return paths


def drift(rendered: Rendered) -> list[str]:
    """The outputs whose file differs from the render (missing, hand-edited, stale)."""
    out = []
    for o in rendered.outputs:
        if not o.path.is_file():
            out.append(f"{o.path}: missing")
        elif o.path.read_text(encoding="utf-8") != o.expected():
            out.append(f"{o.path}: differs from the render (hand-edited or stale)")
    return out
