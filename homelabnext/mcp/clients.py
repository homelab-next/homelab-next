# SPDX-License-Identifier: Apache-2.0
"""Client configurations rendered from the MCP catalog, never written by hand (ADR-0024).

``hnx mcp catalog render`` turns catalog records plus agent profiles into what a client reads:

* **instances.**  A record declares a server once; an *instance* is that server for one granted
  profile in one lane (``real``, ``shadow``, ...), with its ``parameters`` resolved (the grant's
  value from the render spec, overridden per home by an output's ``params``, else the default,
  templated over ``{id}``, ``{profile}``, ``{lane}`` and ``{home}``) and checked against their
  type.  Its name is the record's ``instance`` template
  (default ``{id}``).  An unparameterized server granted twice in one home renders once; two
  different definitions under one name are refused.
* **clients.**  ``claude-code`` (``.mcp.json``), ``claude-desktop`` (a fragment of stdio
  servers that need no secret: Desktop does not expand ``${VAR}``),
  ``generic`` (``mcpServers`` with an explicit transport), ``hermes`` (a ``mcp_servers:`` YAML
  block, Hermes Agent's ``config.yaml`` shape; no sse, which it has no field for) and ``llm-orchestrator`` (its
  ``configs/mcp_catalog.yaml`` kinds and each profile's ``grants:`` block, byte for byte the shape
  its ``internal/grants`` package reads).
* **secrets** are never values: an ``env`` secret, a ``secret:`` argument or header becomes
  ``${HNX_SECRET_<NAME>}`` (:func:`homelabnext.registry.model.secret_env_name`), which Claude Code
  expands from the environment at start and Hermes and llm-orchestrator get from the deploy that
  installs the file.  **Endpoints** are built from the registry (scheme, capability alias, port, path),
  never written in a record.

A render *spec* (YAML) names the client, the catalog, the registry, the lanes, the profiles with
their grants' parameter values, and every output: one per runtime home (a primary and a fallback
Hermes home from one source), or for llm-orchestrator the catalog file and each profile's file
whose ``grants:`` block is spliced (``check_profiles``: every orchestrator profile that must
accept the rendered catalog).  ``--check`` compares every output and fails on any drift, so a
hand edit or a home that lost an entry is caught, and on any file under the spec's ``owns``
globs that no output renders.
"""

from __future__ import annotations

import itertools
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext._yaml import UniqueKeyLoader
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
#: a lane or a runtime home: both are templated into names, arguments and settings ({lane},
#: {home}), so they are plain names, never a value a client would expand or resolve
NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
#: the marker line a profile's spliced ``grants:`` block starts at (everything after it is ours)
GRANTS_MARKER = "# Per-job MCP grants (ADR-022)."
_SECRET_REF = re.compile(r"secret:[a-z][a-z0-9_-]*(?:/[a-z][a-z0-9_-]*)*")


def refuse_unsound_records(cat: servers.Catalog, sids: Iterable[str]) -> None:
    """Refuse to render records that ``hnx mcp catalog check`` would refuse: unpinned or not
    launched as pinned, a literal credential, an untyped parameter, missing reviews (with the
    review policy beside the catalog, as check finds it).  Render never writes what check would
    have stopped."""
    problems = servers.record_problems(cat, sids, policy=servers.default_policy(cat))
    if problems:
        raise RenderError(
            [*problems, "(the catalog fails hnx mcp catalog check for what this render writes)"]
        )


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
    #: the render spec output (runtime home) this instance is rendered for (``{home}``)
    runtime_home: str = ""

    def vars(self) -> dict[str, str]:
        return {
            "id": self.server,
            "profile": self.profile,
            "lane": self.lane,
            "home": self.runtime_home,
            **self.params,
        }


def _fill(text: str, values: Mapping[str, str]) -> str:
    return servers.TEMPLATE.sub(lambda m: values.get(m.group(1), m.group(0)), text)


def _placeholder(ref: str) -> str:
    return "${" + secret_env_name(ref) + "}"


def _secret_text(text: str) -> str:
    """``secret:<name>`` inside a value -> ``${HNX_SECRET_<NAME>}`` (never a value)."""
    return _SECRET_REF.sub(lambda m: _placeholder(m.group(0)), text)


#: what a parameter value may never contain: a client would expand ``$VAR``/``${VAR}``/``$(...)``
#: from its own environment, and ``secret:`` would become a secret placeholder, so a value could
#: route any secret to any server; control characters split a line or an argument
_UNSAFE_VALUE = re.compile(r"\$|secret[:]|[\x00-\x1f\x7f]")


def unsafe_value(value: Any) -> str | None:
    """Why a parameter value from a grant may not be used, or None.  A value is a string (YAML
    ``true`` or ``0755`` would arrive as ``True`` and ``493``) and is passed through verbatim,
    so it may not carry a variable reference, a secret reference or a control character."""
    if not isinstance(value, str):
        return f"{value!r} is not a string (quote it: YAML reads true and 0755 as other types)"
    if _UNSAFE_VALUE.search(value):
        return (
            f"{value!r} carries $, secret: or a control character (a value is never expanded; "
            "secrets come only from the record's own env, headers and arguments)"
        )
    return None


def profile_name(pid: str) -> str:
    return pid.split(":", 1)[1] if ":" in pid else pid


def granted(profile: Mapping[str, Any]) -> list[str]:
    """The MCP server ids a compiled (``grants.mcp``) or lean (``mcp``) profile is granted."""
    g = profile.get("grants") if isinstance(profile.get("grants"), Mapping) else profile
    return sorted({str(x) for x in g.get("mcp") or ()})


def deprecation_notes(cat: servers.Catalog, profile: Mapping[str, Any]) -> list[str]:
    """A note per granted server that is deprecated (still rendered), naming its replacement."""
    out = []
    for sid in granted(profile):
        rec = cat.get(sid) or {}
        if rec.get("status") == "deprecated":
            instead = rec.get("replaced_by")
            out.append(
                f"{profile.get('id')}: MCP server {sid!r} is deprecated: {rec.get('reason')}"
                + (f"; grant {instead!r} instead" if instead else "")
            )
    return out


def instances(
    cat: servers.Catalog,
    profile: Mapping[str, Any],
    *,
    lanes: Iterable[str] = ("real",),
    params: Mapping[str, Mapping[str, Any]] | None = None,
    profile_file: str = "",
    home: str = "",
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
    lanes = list(lanes)
    bad_file = unsafe_value(profile_file)
    if bad_file:
        problems.append(f"{pid}: profile_file {bad_file}")
    for what, value in [*(("lane", lane) for lane in lanes), *([("home", home)] if home else [])]:
        if not isinstance(value, str) or not NAME.fullmatch(value):
            problems.append(f"{pid}: {what} {value!r} is not a plain name ({NAME.pattern})")
    for key in params:
        sid, at, lane = str(key).partition("@")
        if sid not in names:
            problems.append(f"{pid}: parameters for {key}, which the profile is not granted")
        elif at and lane not in lanes:
            problems.append(f"{pid}: parameters for {key}: {lane!r} is not a lane ({lanes})")
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
            base = {"id": sid, "profile": who, "lane": lane, "home": home}
            choices: list[list[tuple[str, str]]] = []
            for pname, p in declared.items():
                if pname in given:
                    raw = given[pname]
                    vals = list(raw) if isinstance(raw, list) else [raw]
                elif p.get("default") is not None:
                    vals = [_fill(str(p["default"]), base)]
                else:
                    problems.append(f"{pid}: {sid}: parameter {pname} needs a value ({lane})")
                    vals = []
                for v in vals:
                    bad = unsafe_value(v) or servers.value_problem(p, v)
                    if bad:
                        problems.append(f"{pid}: {sid}: parameter {pname}: {bad}")
                vals = [v for v in vals if isinstance(v, str)]
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
                    runtime_home=home,
                )
                inst.name = _fill(str(rec.get("instance") or "{id}"), inst.vars())
                if not ORCH_NAME.fullmatch(inst.name):
                    problems.append(
                        f"{pid}: {sid}: instance name {inst.name!r} is not a valid name"
                    )
                out.append(inst)
    if problems:
        raise RenderError(problems)
    return out


# ------------------------------------------------------------------------------- one instance
def _args(inst: Instance) -> list[str]:
    """The record's arguments: its own literal ``secret:`` references become placeholders first,
    then templates are filled, so a substituted value is never read as a secret reference."""
    values = {**inst.vars(), servers.PROFILE_FILE: inst.profile_file}
    return [_fill(_secret_text(str(a)), values) for a in inst.record["transport"].get("args") or ()]


def _launch(
    record: Mapping[str, Any], sid: str, ctx: servers.LaunchContext | None = None
) -> tuple[str, list[str]]:
    """The generated launch (:func:`homelabnext.mcp.servers.launch`), anchored by ``ctx`` (the
    spec's ``npm_prefix`` and ``checkout_root``): never the record's."""
    try:
        got = servers.launch(record, ctx)
    except ValueError as exc:
        raise RenderError(
            [
                f"{sid}: {exc} (the render spec's npm_prefix/checkout_root, or --npm-prefix/"
                "--checkout-root)"
            ]
        ) from None
    if ctx is not None and ctx.checkout_root:
        # the absolute path the client runs: a file in the checkout, never through a symlink
        bad = servers.path_bin_problems(record, sid, Path(ctx.checkout_root))
        if bad:
            raise RenderError([f"{b} (under checkout_root)" for b in bad])
    return got


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


def secret_refs(rec: Mapping[str, Any]) -> list[str]:
    """Every ``secret:`` reference a record delivers (env, headers, arguments)."""
    text = [str(v) for v in (rec.get("env") or {}).values()]
    text += [str(v) for v in (rec.get("headers") or {}).values()]
    text += [str(a) for a in (rec.get("transport") or {}).get("args") or ()]
    return sorted({m for t in text for m in _SECRET_REF.findall(t)})


def _headers(inst: Instance) -> dict[str, str]:
    return {k: _secret_text(str(v)) for k, v in sorted((inst.record.get("headers") or {}).items())}


def definition(
    inst: Instance, client: str, registry: Any = None, ctx: servers.LaunchContext | None = None
) -> dict[str, Any] | None:
    """One instance's entry in ``client``'s format (``None``: the client cannot take it)."""
    t = inst.record["transport"]
    stdio = t["type"] == "stdio"
    if client == "claude-desktop" and not stdio:
        return None
    if client == "claude-desktop" and secret_refs(inst.record):
        raise RenderError(
            [
                f"{inst.name}: claude-desktop does not expand ${{VAR}} in "
                f"claude_desktop_config.json, and {inst.server} needs {secret_refs(inst.record)}: "
                "start it through a wrapper that reads them from the secret store, or use a "
                "client that expands them (claude-code)"
            ]
        )
    if client == "hermes" and t["type"] == "sse":
        raise RenderError(
            [
                f"{inst.name}: {inst.server} speaks the legacy sse transport; a Hermes "
                "mcp_servers entry has no transport field, so it would be reached as "
                "streamable HTTP (serve it over streamable-http, or use another client)"
            ]
        )
    d: dict[str, Any] = {}
    if client in ("claude-code", "generic"):
        d["type" if client == "claude-code" else "transport"] = (
            "http" if t["type"] == "streamable-http" and client == "claude-code" else t["type"]
        )
    if stdio:
        command, launcher_args = _launch(inst.record, inst.server, ctx)
        d["command"] = command
        d["args"] = [*launcher_args, *_args(inst)]
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
    insts: Iterable[Instance],
    client: str,
    registry: Any = None,
    ctx: servers.LaunchContext | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """``{name: definition}`` for one home, and the names a client could not take.  The same
    name twice is fine when the definitions are equal (a shared server), refused otherwise."""
    out: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []
    problems: list[str] = []
    for inst in insts:
        d = definition(inst, client, registry, ctx)
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


def generated_note(
    cat: servers.Catalog, what: str, records: Mapping[str, Mapping[str, Any]] | None = None
) -> str:
    """The header of a rendered file, with the digest of the records it was built from (only
    those: editing a record a file does not hold never makes that file drift)."""
    from homelabnext.agent.digest import digest_of

    digest = cat.digest() if records is None else digest_of(dict(sorted(records.items())))
    return (
        f"generated by hnx mcp catalog render from the MCP catalog ({cat.root.name}/, "
        f"{digest[:19]}) for {what}; do not edit, render again"
    )


def render_home(
    insts: list[Instance],
    client: str,
    cat: servers.Catalog,
    registry: Any,
    what: str,
    ctx: servers.LaunchContext | None = None,
) -> tuple[str, list[str]]:
    """The text of one client file (and the instance names it could not hold)."""
    servers_, skipped = home_servers(insts, client, registry, ctx)
    held = {i.server: i.record for i in insts if i.name in servers_}
    note = generated_note(cat, what, held)
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


def orch_kind(
    sid: str, rec: Mapping[str, Any], ctx: servers.LaunchContext | None = None
) -> tuple[dict[str, Any] | None, list[str]]:
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
    command, launcher_args = _launch(rec, sid, ctx)
    entry: dict[str, Any] = {
        "command": command,
        "args": [*launcher_args, *(_secret_text(a) for a in args)],
    }
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


def orch_catalog(
    cat: servers.Catalog, granted_ids: Iterable[str] = (), ctx: servers.LaunchContext | None = None
) -> tuple[str, list[str]]:
    """``configs/mcp_catalog.yaml``: every grantable stdio server as a kind.  A server that
    cannot be a kind is skipped with a note, or refused when a rendered profile is granted it."""
    granted_ids = set(granted_ids)
    kinds: dict[str, Any] = {}
    notes: list[str] = []
    problems: list[str] = []
    for sid, rec in cat:
        if rec.get("status") not in servers.GRANTABLE:
            continue
        entry, why = orch_kind(sid, rec, ctx)
        if entry is None or (why and sid not in granted_ids):
            notes += why
            continue
        problems += why
        kinds[sid] = entry
    if problems:
        raise RenderError(problems)
    note = generated_note(cat, "llm-orchestrator", {k: cat.servers[k] for k in kinds})
    head = ORCH_CATALOG_HEAD + f"# {note}\n"
    return head + yaml.safe_dump({"kinds": kinds}, sort_keys=True, width=100), notes


def orch_grants(insts: list[Instance], lanes: Iterable[str]) -> str:
    """One profile's ``grants:`` block (``real`` and ``shadow`` lists, by instance name).  A
    granted server llm-orchestrator cannot start (a remote one: its kinds start a command) is
    refused, never dropped: the job would silently run without it."""
    out: dict[str, list[dict[str, Any]]] = {lane: [] for lane in ORCH_LANES}
    for lane in lanes:
        out.setdefault(lane, [])
    problems: list[str] = []
    for inst in sorted(insts, key=lambda i: (i.lane, i.name)):
        kind = (inst.record.get("transport") or {}).get("type")
        if kind != "stdio":
            problems.append(
                f"profile:{inst.profile}: granted {inst.server}, a {kind} server; llm-orchestrator "
                "kinds start a command, so it cannot be granted there"
            )
            continue
        g: dict[str, Any] = {"name": inst.name, "kind": inst.server}
        if inst.param_env:
            g["env"] = dict(sorted(inst.param_env.items()))
        out[inst.lane].append(g)
    if problems:
        raise RenderError(sorted(set(problems)))
    return ORCH_GRANTS_HEAD + yaml.safe_dump({"grants": out}, sort_keys=False, width=100)


def load_strict(text: str, what: str) -> Any:
    """``text`` as YAML, refusing a duplicate key as llm-orchestrator's yaml.v3 does (PyYAML
    keeps the last one silently); a :class:`RenderError` names ``what``."""
    try:
        return yaml.load(text, Loader=UniqueKeyLoader)  # a SafeLoader subclass
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        at = f" (line {mark.line + 1})" if mark is not None else ""
        why = getattr(exc, "problem", None) or exc
        raise RenderError([f"{what}: not YAML llm-orchestrator can read{at}: {why}"]) from None


def splice_grants(existing: str, block: str, what: str = "profile") -> str:
    """``existing`` (a profile file) with its generated grants block replaced by ``block``
    (appended when it has none).  Refused: a ``grants:`` key outside the generated block (the
    result would have two, which yaml.v3 rejects), and keys after the block's marker (the splice
    would delete them)."""
    at = existing.find(GRANTS_MARKER)
    if at > 0 and existing[at - 1] != "\n":
        at = existing.find("\n" + GRANTS_MARKER) + 1 or -1
    head = existing if at < 0 else existing[:at]
    tail = "" if at < 0 else existing[at:]
    head_doc = load_strict(head, what) if head.strip() else {}
    if isinstance(head_doc, Mapping) and "grants" in head_doc:
        raise RenderError(
            [
                f"{what}: has a grants: key outside the generated block (remove it; the block "
                f"is rendered after the line {GRANTS_MARKER!r})"
            ]
        )
    tail_doc = load_strict(tail, what) if tail.strip() else {}
    extra = sorted(set(tail_doc) - {"grants"}) if isinstance(tail_doc, Mapping) else []
    if extra:
        raise RenderError(
            [
                f"{what}: key(s) {extra} follow the generated grants block and would be "
                "deleted (move them above it)"
            ]
        )
    text = head.rstrip("\n") + "\n" + block if head.strip() else block.lstrip("\n")
    load_strict(text, what)
    return text


def orch_accepts(catalog_text: str, grant_blocks: Mapping[str, str]) -> list[str]:
    """What llm-orchestrator would refuse in these files (a catalog, and profile files or their
    grants blocks), its rules encoded here (llm-orchestrator commit 68ffbcd): YAML without a
    duplicate key (yaml.v3), and internal/grants/grants.go's known fields only (85, KnownFields),
    kind and server names (68, 90, 111), a command (94), no hard-denied allowed_env key (71, 98), no
    duplicate server (115), a known kind (119), only allowed, non-denied env keys (127); and
    internal/queue/scheduler.go:626, which fails every job of a lane with no grants when the
    other lane has some."""
    problems: list[str] = []
    try:
        doc = load_strict(catalog_text, "catalog") or {}
        docs = {who: load_strict(text, who) or {} for who, text in grant_blocks.items()}
    except RenderError as exc:
        return exc.problems
    if set(doc) != {"kinds"}:
        problems.append(f"catalog: top-level keys {sorted(doc)} (only kinds)")
    kinds = doc.get("kinds") or {}
    for name, k in kinds.items():
        if not ORCH_NAME.fullmatch(name):
            problems.append(f"kind {name!r}: bad name")
        extra = set(k) - set(ORCH_KIND_KEYS)
        if extra:
            problems.append(f"kind {name}: unknown field(s) {sorted(extra)}")
        if not k.get("command"):
            problems.append(f"kind {name}: command is required")
        for key in k.get("allowed_env") or ():
            if servers.ORCH_DENIED_ENV.match(key) or servers.denied_env(key):
                problems.append(f"kind {name}: env key {key} may never be grant-settable")
    for who, doc in docs.items():
        lanes = (doc.get("grants") if isinstance(doc, Mapping) else None) or {}
        extra = set(lanes) - set(ORCH_LANES)
        if extra:
            problems.append(f"{who}: unknown lane(s) {sorted(extra)}")
        empty = [lane for lane in ORCH_LANES if not lanes.get(lane)]
        if len(empty) == 1:
            problems.append(
                f"{who}: grants the {ORCH_LANES[1 - ORCH_LANES.index(empty[0])]} lane but not "
                f"{empty[0]}: llm-orchestrator fails every {empty[0]} job (render both lanes)"
            )
        for lane, gs in lanes.items():
            seen: set[str] = set()
            for g in gs or ():
                if set(g) - set(ORCH_GRANT_KEYS):
                    problems.append(
                        f"{who}/{lane}: unknown grant field(s) {sorted(set(g) - set(ORCH_GRANT_KEYS))}"
                    )
                name = str(g.get("name"))
                if not ORCH_NAME.fullmatch(name):
                    problems.append(f"{who}/{lane}: server name {name!r}")
                if name in seen:
                    problems.append(f"{who}/{lane}: server {name} granted twice")
                seen.add(name)
                k = kinds.get(g.get("kind"))
                if k is None:
                    problems.append(f"{who}/{lane}: server {name}: unknown kind {g.get('kind')!r}")
                    continue
                for key in g.get("env") or {}:
                    if servers.denied_env(key) or key not in (k.get("allowed_env") or ()):
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
        if not self.path.is_file():
            raise RenderError(
                [
                    f"{self.path}: no such profile file (the grants block is spliced into the "
                    "orchestrator's own profile; create it there first)"
                ]
            )
        return splice_grants(self.path.read_text(encoding="utf-8"), self.text, str(self.path))


@dataclass
class Rendered:
    outputs: list[Output] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: files the spec owns (``owns:`` globs) that no output renders: stale or hand-written
    unlisted: list[Path] = field(default_factory=list)


def load_policy(path: str | Path) -> Any:
    """A ceiling policy file (``hnx agent verify --policy``'s shape: ``ceilings:``)."""
    from homelabnext.agent.compiler import CeilingPolicy
    from homelabnext.agent.errors import AgentError

    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return CeilingPolicy.from_mapping(doc or {}, source=str(path))
    except (OSError, yaml.YAMLError, AgentError) as exc:
        raise RenderError([f"{path}: not a ceiling policy: {exc}"]) from None


def load_lock(path: str | Path) -> dict[str, str]:
    """Reviewed digests (``hnx agent verify --lock``'s shape: ``profiles: {id: digest}``)."""
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RenderError([f"{path}: cannot read the lock: {exc}"]) from None
    lock = doc.get("profiles") if isinstance(doc, Mapping) else None
    if not isinstance(lock, Mapping):
        raise RenderError([f"{path}: expected a 'profiles' mapping of profile id -> digest"])
    return {str(k): str(v) for k, v in lock.items()}


def profile_refusals(
    doc: Mapping[str, Any],
    cat: servers.Catalog,
    policy: Any = None,
    lock: Mapping[str, str] | None = None,
) -> list[str]:
    """Why a profile may not be rendered.  A compiled profile: everything ``hnx agent verify
    --policy [--lock]`` refuses (schema, the reader rule and catalog grants judged against *this*
    catalog, the policy's ceiling (the stored one may not be wider), budgets, a digest that is
    present and matches, and with ``lock`` the reviewed digest); it is refused without a
    ``policy``, since its stored ceiling and digest are whatever edited it.  A lean one
    (``platform/agent_profile``): its schema, the same grant rules, ``mcp`` within
    ``mcp_ceiling``, and ``mcp`` and ``capabilities`` within the policy's ceiling; it is refused
    without a ``policy`` too (its own ``mcp_ceiling`` is whatever edited the file).  Rendering
    never trusts a profile the compiler would not have produced."""
    from homelabnext.agent.compiler import verify_profile
    from homelabnext.agent.errors import AgentError, CeilingViolation
    from homelabnext.agent.readers import ToolClasses, profile_problems
    from homelabnext.agent.schemas import schema_errors

    try:
        classes = ToolClasses.from_catalog(cat)
    except AgentError as exc:
        return [str(exc)]
    if "grants" in doc:
        if not doc.get("digest"):
            return ["a compiled profile carries its digest (hnx agent compile)"]
        if policy is None:
            return [
                "a compiled profile is rendered against the ceiling policy (spec policy:, "
                "--policy): its stored ceiling and digest are whatever last edited the file"
            ]
        return verify_profile(doc, policy=policy, lock=lock, classes=classes)
    problems = schema_errors("platform", "agent_profile", json.loads(json.dumps(doc)))
    if problems:
        return [f"not a compiled or lean agent profile: {p}" for p in problems]
    problems = profile_problems(doc, classes)
    over = sorted(set(doc.get("mcp") or ()) - set(doc.get("mcp_ceiling") or ()))
    if over:
        problems.append(f"mcp outside mcp_ceiling: {over}")
    if policy is None:
        return [
            *problems,
            "a lean profile is rendered against the ceiling policy too (spec policy:, --policy): "
            "its own mcp_ceiling is whatever last edited the file",
        ]
    try:
        ceiling = policy.ceiling(str(doc.get("id")))
    except CeilingViolation as exc:
        return problems + list(exc.problems)
    for key in ("mcp", "capabilities"):
        wide = sorted(set(doc.get(key) or ()) - set(ceiling.get(key) or ()))
        if wide:
            problems.append(f"{key} outside the policy's ceiling ({policy.source}): {wide}")
    return problems


def _load_profile(
    path: Path, cat: servers.Catalog, policy: Any = None, lock: Mapping[str, str] | None = None
) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
        doc = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RenderError([f"{path}: cannot read the profile: {exc}"]) from None
    if not isinstance(doc, Mapping) or not str(doc.get("id", "")).startswith("profile:"):
        raise RenderError([f"{path}: not an agent profile (no profile: id)"])
    refused = profile_refusals(doc, cat, policy, lock)
    if refused:
        raise RenderError([f"{path}: refused: {p}" for p in refused])
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
    policy: Any = None,
    lock: Mapping[str, str] | None = None,
    npm_prefix: str | None = None,
    checkout_root: str | None = None,
) -> tuple[str, list[str]]:
    """One profile's client file (``--profile``); ``policy``/``lock``: :func:`profile_refusals`;
    ``npm_prefix``/``checkout_root``: :class:`homelabnext.mcp.servers.LaunchContext`."""
    ctx = launch_context(npm_prefix, checkout_root)
    p = Path(profile_path)
    prof = _load_profile(p, cat, policy, lock)
    lanes = list(lanes)
    refuse_unsound_records(cat, _rendered_ids(cat, client, [prof]))
    insts = instances(
        cat, prof, lanes=lanes, params=params, profile_file=profile_file or str(profile_path)
    )
    notes = deprecation_notes(cat, prof)
    if client == "llm-orchestrator":
        block = orch_grants(insts, lanes)
        catalog_text, _ = orch_catalog(cat, {i.server for i in insts}, ctx)
        bad = orch_accepts(catalog_text, {prof["id"]: block})
        if bad:
            raise RenderError(bad)
        return block, notes
    text, skipped = render_home(insts, client, cat, registry, prof["id"], ctx)
    return text, notes + [f"{client} cannot hold {n} (not a stdio server)" for n in skipped]


def _spec_problems(spec: Any) -> list[str]:
    if not isinstance(spec, Mapping):
        return ["the spec must be a mapping"]
    out = []
    extra = set(spec) - {
        "client", "catalog", "registry", "lanes", "profiles", "outputs", "owns", "check_profiles",
        "policy", "lock", "npm_prefix", "checkout_root",
    }  # fmt: skip
    if extra:
        out.append(f"unknown key(s) {sorted(extra)}")
    if spec.get("client") not in CLIENTS:
        out.append(f"client must be one of {list(CLIENTS)}")
    if not isinstance(spec.get("profiles"), list) or not spec.get("profiles"):
        out.append("profiles must list at least one profile")
    outputs = spec.get("outputs")
    if not isinstance(outputs, list) or not outputs:
        out.append("outputs must list at least one file")
        return out
    for i, o in enumerate(outputs):
        if not isinstance(o, Mapping) or not o.get("path"):
            out.append(f"outputs[{i}] needs a path")
            continue
        extra = set(o) - {"path", "home", "params"}
        if extra:
            out.append(f"outputs[{i}]: unknown key(s) {sorted(extra)}")
        if spec.get("client") == "llm-orchestrator" and ({"home", "params"} & set(o)):
            out.append(f"outputs[{i}]: llm-orchestrator's catalog has no home or params")
        if o.get("home") is not None and not (
            isinstance(o["home"], str) and NAME.fullmatch(o["home"])
        ):
            out.append(f"outputs[{i}]: home must be a plain name ({NAME.pattern})")
        if o.get("params") is not None and not isinstance(o["params"], Mapping):
            out.append(f"outputs[{i}]: params must map SERVER (or SERVER@LANE) to values")
    lanes = spec.get("lanes")
    if lanes is not None and (
        not isinstance(lanes, list)
        or not lanes
        or not all(isinstance(x, str) and NAME.fullmatch(x) for x in lanes)
    ):
        out.append(f"lanes must list plain names ({NAME.pattern})")
    return out


def _inside(root: Path, rel: Any, what: str) -> Path:
    """``root / rel`` for a path the render writes (or splices): relative, not a symlink, and
    still under ``root`` once resolved."""
    raw = Path(str(rel))
    if raw.is_absolute():
        raise RenderError([f"{what} {rel}: an absolute path (write it relative to {root})"])
    p = root / raw
    if p.is_symlink():
        raise RenderError([f"{what} {rel}: a symlink (the render never writes through one)"])
    if not p.resolve().is_relative_to(root.resolve()):
        raise RenderError([f"{what} {rel}: outside {root}"])
    return p


def render_spec(spec_path: str | Path, root: str | Path | None = None) -> Rendered:
    """Every output a render spec names (see the module docstring).  Output and ``grants_file``
    paths are relative to ``root`` (default: the spec's directory) and must stay under it."""
    from homelabnext.registry.model import RegistryError, load

    sp = Path(spec_path)
    try:
        spec = yaml.safe_load(sp.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RenderError([f"{sp}: cannot read: {exc}"]) from None
    problems = _spec_problems(spec)
    if problems:
        raise RenderError([f"{sp}: {p}" for p in problems])
    try:
        ctx = launch_context(spec.get("npm_prefix"), spec.get("checkout_root"))
    except RenderError as exc:
        raise RenderError([f"{sp}: {p}" for p in exc.problems]) from None
    base = sp.parent
    out_root = Path(root) if root is not None else base
    cat = servers.load((base / str(spec.get("catalog", ".."))).resolve())
    registry = None
    if spec.get("registry"):
        try:
            registry = load(base / str(spec["registry"]))
        except RegistryError as exc:
            raise RenderError([str(exc)]) from None
    policy = load_policy(base / str(spec["policy"])) if spec.get("policy") else None
    lock = load_lock(base / str(spec["lock"])) if spec.get("lock") else None
    client = spec["client"]
    lanes = [str(x) for x in spec.get("lanes") or ["real"]]
    res = Rendered()
    every: list[Instance] = []
    blocks: dict[str, tuple[Path, str]] = {}
    loaded: list[tuple[Mapping[str, Any], dict[str, Any], Path]] = []
    for entry in spec["profiles"]:
        pf = base / str(entry["file"])
        loaded.append((entry, _load_profile(pf, cat, policy, lock), pf))
    refuse_unsound_records(cat, _rendered_ids(cat, client, [prof for _, prof, _ in loaded]))
    for entry, prof, pf in loaded:
        res.notes += deprecation_notes(cat, prof)
        if client != "llm-orchestrator":
            continue
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
            gf = _inside(out_root, entry["grants_file"], "grants_file")
            blocks[prof["id"]] = (gf, orch_grants(insts, lanes))
    if client == "llm-orchestrator":
        text, notes = orch_catalog(cat, {i.server for i in every}, ctx)
        res.notes += notes
        for out in spec["outputs"]:
            res.outputs.append(Output(_inside(out_root, out["path"], "output"), text))
        full: dict[str, str] = {}
        for path, block in blocks.values():
            o = Output(path, block, splice=True)
            full[str(path)] = o.expected()  # the whole profile file, as the orchestrator reads it
            res.outputs.append(o)
        # every profile the orchestrator loads must accept the catalog that replaces its own,
        # not only the profiles this spec renders (its controller refuses to start otherwise)
        for f in _owned(out_root, spec.get("check_profiles")):
            if str(f) not in full and f.is_file():
                other = f.read_text(encoding="utf-8")
                if "grants" in (load_strict(other, str(f)) or {}):
                    full[str(f)] = other
        bad = orch_accepts(text, full)
        if bad:
            raise RenderError(bad)
    else:
        every_granted = {sid for _, prof, _ in loaded for sid in granted(prof)}
        for i, out in enumerate(spec["outputs"]):
            for key in out.get("params") or {}:
                sid, at, lane = str(key).partition("@")
                if sid not in every_granted:
                    why = f"no profile of the spec is granted {sid}"
                elif at and lane not in lanes:
                    why = f"{lane!r} is not a lane ({lanes})"
                else:
                    continue
                raise RenderError([f"{sp}: outputs[{i}].params {key}: {why}"])
        for out in spec["outputs"]:
            what = f"home {out['home']}" if out.get("home") else f"{sp.name}"
            home_insts: list[Instance] = []
            for entry, prof, pf in loaded:
                home_insts += instances(
                    cat,
                    prof,
                    lanes=lanes,
                    params=_home_params(entry.get("params") or {}, out.get("params"), prof),
                    profile_file=str(entry.get("profile_file") or pf),
                    home=str(out.get("home") or ""),
                )
            text, skipped = render_home(home_insts, client, cat, registry, what, ctx)
            res.notes += [f"{what}: {client} cannot hold {n}" for n in skipped]
            res.outputs.append(Output(_inside(out_root, out["path"], "output"), text))
    mine = {o.path.resolve() for o in res.outputs}
    res.unlisted = [f for f in _owned(out_root, spec.get("owns")) if f.resolve() not in mine]
    res.notes += [f"{f}: owned by the spec but not rendered (stale?)" for f in res.unlisted]
    return res


def launch_context(npm_prefix: Any = None, checkout_root: Any = None) -> servers.LaunchContext:
    """The anchors a render gives every launch; a value given must be an absolute path (a
    missing one is refused only by a launch that needs it)."""
    problems = [
        bad
        for value, what in ((npm_prefix, "npm_prefix"), (checkout_root, "checkout_root"))
        if value is not None and (bad := servers.anchor_problem(value, what))
    ]
    if problems:
        raise RenderError(problems)
    return servers.LaunchContext(npm_prefix, checkout_root)


def _rendered_ids(
    cat: servers.Catalog, client: str, profiles: Iterable[Mapping[str, Any]]
) -> set[str]:
    """The records a render writes: the profiles' grants, and for llm-orchestrator every
    grantable record (its catalog holds a kind per grantable stdio server)."""
    out = {sid for prof in profiles for sid in granted(prof)}
    if client == "llm-orchestrator":
        out |= {sid for sid, rec in cat if rec.get("status") in servers.GRANTABLE}
    return out


def _home_params(
    given: Mapping[str, Mapping[str, Any]], home: Any, profile: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """A profile's parameter values for one home: the profile entry's, overridden by the
    output's ``params`` for every server the profile is granted (``SERVER`` or ``SERVER@LANE``)."""
    out = {k: dict(v or {}) for k, v in given.items()}
    names = set(granted(profile))
    for key, values in (home or {}).items():
        if str(key).split("@", 1)[0] in names:
            out[str(key)] = {**out.get(str(key), {}), **dict(values or {})}
    return out


def _owned(root: Path, globs: Any) -> list[Path]:
    """Files under ``root`` matching a spec's globs (``owns``, ``check_profiles``)."""
    if isinstance(globs, str):
        globs = [globs]
    out: set[Path] = set()
    for g in globs or ():
        if Path(str(g)).is_absolute() or ".." in Path(str(g)).parts:
            raise RenderError([f"glob {g}: write it relative to {root}, inside it"])
        out |= {f for f in root.glob(str(g)) if f.is_file()}
    return sorted(out)


def write(rendered: Rendered) -> list[Path]:
    """Write every output: refuse a symlink, write a temporary file beside it and rename it over
    the old one, so a reader never sees half a file and a link never redirects the write."""
    texts = [(o.path, o.expected()) for o in rendered.outputs]  # every splice first, then write
    for path, _ in texts:
        if path.is_symlink():
            raise RenderError([f"{path}: a symlink (the render never writes through one)"])
    paths = []
    for path, text in texts:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.hnx-render")
        tmp.unlink(missing_ok=True)
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
        paths.append(path)
    return paths


def _same(text: str) -> str:
    """Text compared for drift: line endings and trailing newlines are an editor's, not drift."""
    return text.replace("\r\n", "\n").rstrip("\n")


def drift(rendered: Rendered) -> list[str]:
    """The outputs whose file differs from the render (missing, hand-edited, stale), and every
    file the spec owns that no output renders."""
    out = []
    for o in rendered.outputs:
        if not o.path.is_file():
            out.append(f"{o.path}: missing")
        elif _same(o.path.read_text(encoding="utf-8")) != _same(o.expected()):
            out.append(f"{o.path}: differs from the render (hand-edited or stale)")
    out += [f"{f}: owned by the spec (owns:) but not rendered by it" for f in rendered.unlisted]
    return out
