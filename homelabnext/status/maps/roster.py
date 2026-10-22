# SPDX-License-Identifier: Apache-2.0
"""Agent roster: every agent profile the repository knows, what it may do and when it last did
anything.

Sources of truth (``roster.yml``, ``schemas/status/roster.schema.json``, names where they are):

* the **compiled profiles** (``schemas/agent/profile``): persona, model role, data tier,
  ``reads_untrusted``, the granted tier, capabilities and MCP servers, memory scopes, budgets;
* the **model role table**: the backends a profile's model role is bound to;
* the **broker manifests**: each grant's actions (tier, approval) and, for an action that writes a
  lane, that lane -- the only places a profile may write;
* the **workflow packs**: the profile each pack acts as;
* the roster's own entries: the owner, the runtime and one line on what the agent does, which no
  other file holds.

A profile named anywhere is listed, so the page cannot hide one: a broker grant or a pack actor
with no compiled profile shows that gap, and so does a profile with no roster entry.  Last
activity is the agent-activity tier's (``status.json`` ``agents.sessions``, with ``--agents``):
the sessions whose ``agent`` is the profile id, its bare name or one of its ``activity_names``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._yaml import UniqueKeyLoader
from homelabnext.status.model import parse_iso

from . import svg

#: the agent-activity session states, worst first (homelabnext.status.agents.model)
_SESSION_CHIP = {
    "errored": "fail",
    "stuck": "stale",
    "waiting": "warn",
    "working": "ok",
    "done": "unknown",
}


class RosterError(ValueError):
    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


@cache
def _validator():
    import jsonschema

    schema = json.loads(paths.schema_file("status", "roster.schema.json").read_text("utf-8"))
    return jsonschema.Draft202012Validator(schema)


def _read(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.load(text, Loader=UniqueKeyLoader)


def _inside(root: Path, base: Path, f: Path) -> Path:
    """``f``, when it resolves inside ``root`` (``..`` and a symlink included)."""
    top, real = root.resolve(), f.resolve()
    if real != top and top not in real.parents:
        raise ValueError(f"{os.path.relpath(f, base)}: resolves outside {root}")
    return f


def _files(root: Path, base: Path, patterns: Sequence[str]) -> list[Path]:
    """The files ``patterns`` name under ``base``: a glob's matches, a plain path as it is (so a
    missing one is an error, not an empty list); each must resolve inside ``root``."""
    out: list[Path] = []
    for pat in patterns:
        if any(c in pat for c in "*?["):
            out += [h for h in sorted(base.glob(pat)) if h.is_file()]
        else:
            out.append(base / pat)
    return [_inside(root, base, f) for f in dict.fromkeys(out)]


def gather(path: str | Path, root: str | Path | None = None) -> dict[str, Any]:
    """The roster file and everything it names, read (raises :class:`RosterError` on a roster
    that does not validate, a file it names that cannot be read, or one that resolves outside
    ``root``: the checkout the hub reads, ``--maps ROOT``; default the roster's directory).
    Its paths are relative to the roster file and may climb (``../../schemas/...``), but never
    out of ``root``, whether by ``..``, a glob or a symlink."""
    p = Path(path)
    try:
        doc = _read(p)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RosterError(f"cannot read the roster {p}: {exc}") from None
    errs = sorted(_validator().iter_errors(doc), key=lambda e: [str(x) for x in e.absolute_path])
    if errs:
        raise RosterError(
            f"invalid roster {p}",
            [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}" for e in errs],
        )
    base = p.parent
    top = Path(root) if root is not None else base

    out: dict[str, Any] = {"roster": doc, "profiles": [], "brokers": [], "packs": [], "roles": {}}
    try:
        for f in _files(top, base, doc.get("profiles") or ()):
            out["profiles"].append({"file": os.path.relpath(f, base), "doc": _read(f)})
        for f in _files(top, base, doc.get("brokers") or ()):
            out["brokers"].append({"file": os.path.relpath(f, base), "doc": _read(f)})
        for f in _files(top, base, doc.get("packs") or ()):
            out["packs"].append({"file": os.path.relpath(f, base), "doc": _read(f)})
        if doc.get("model_roles"):
            out["roles"] = _read(_inside(top, base, base / doc["model_roles"])).get("roles") or {}
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RosterError(f"roster {p}: {exc}") from None
    return out


def _bare(pid: str) -> str:
    return pid.split(":", 1)[1] if ":" in pid else pid


def build(
    inputs: Mapping[str, Any], sessions: Sequence[Mapping[str, Any]] | None = None
) -> dict[str, Any]:
    """The roster view-model.  ``sessions``: the agent-activity tier's sessions (None: the tier
    is not configured)."""
    declared = {a["profile"]: a for a in inputs["roster"].get("agents") or ()}
    compiled = {}
    for item in inputs["profiles"]:
        d = item["doc"]
        if isinstance(d, Mapping) and isinstance(d.get("id"), str):
            compiled[d["id"]] = {**d, "_file": item["file"]}
    actions: dict[str, list[dict[str, Any]]] = {}
    lanes: dict[str, list[dict[str, Any]]] = {}
    for item in inputs["brokers"]:
        m = item["doc"] or {}
        mid = str(m.get("manifest_id", item["file"]))
        acts = {a["action"]: a for a in m.get("actions") or () if isinstance(a, Mapping)}
        known_lanes = {ln["name"]: ln for ln in m.get("lanes") or () if isinstance(ln, Mapping)}
        for g in m.get("grants") or ():
            pid = g.get("profile")
            for name in g.get("actions") or ():
                a = acts.get(name, {})
                actions.setdefault(pid, []).append(
                    {
                        "broker": mid,
                        "action": name,
                        "tier": a.get("tier"),
                        "approval": bool(a.get("requires_approval")),
                    }
                )
                if a.get("lane"):
                    ln = known_lanes.get(a["lane"], {})
                    lanes.setdefault(pid, []).append(
                        {
                            "broker": mid,
                            "lane": a["lane"],
                            "kind": ln.get("kind"),
                            "per_actor": bool(ln.get("per_actor")),
                            "via": name,
                        }
                    )
    packs: dict[str, list[str]] = {}
    for item in inputs["packs"]:
        d = item["doc"] or {}
        if d.get("actor"):
            packs.setdefault(d["actor"], []).append(str(d.get("pack", item["file"])))
    roles = inputs.get("roles") or {}
    ids = sorted(set(declared) | set(compiled) | set(actions) | set(packs))
    problems = []
    agents = []
    for pid in ids:
        dec, prof = declared.get(pid), compiled.get(pid)
        grants = (prof or {}).get("grants") or {}
        role = (prof or {}).get("model_role")
        role_doc = roles.get(_bare(role)) if role else None
        names = {pid, _bare(pid), *((dec or {}).get("activity_names") or ())}
        mine = [s for s in sessions or () if s.get("agent") in names]
        if dec is None:
            problems.append(f"{pid}: no roster entry (owner and runtime unknown)")
        if prof is None:
            problems.append(f"{pid}: no compiled profile (grants and MCP servers unknown)")
        agents.append(
            {
                "id": pid,
                "owner": (dec or {}).get("owner"),
                "runtime": (dec or {}).get("runtime"),
                "what": (dec or {}).get("what", ""),
                "profile_file": (prof or {}).get("_file"),
                "persona": (prof or {}).get("persona"),
                "model_role": role,
                "model_backends": sorted(
                    {
                        b["backend"]
                        for b in (role_doc or {}).get("bindings") or ()
                        if b.get("backend")
                    }
                ),
                "data_tier": (prof or {}).get("data_tier"),
                "reads_untrusted": (prof or {}).get("reads_untrusted"),
                "tier": grants.get("tier"),
                "capabilities": list(grants.get("capabilities") or ()),
                "mcp": list(grants.get("mcp") or ()),
                "memory_scopes": list((prof or {}).get("memory_scopes") or ()),
                "budgets": dict((prof or {}).get("budgets") or {}),
                "actions": sorted(actions.get(pid, []), key=lambda a: (a["broker"], a["action"])),
                "lanes": sorted(lanes.get(pid, []), key=lambda a: (a["broker"], a["lane"])),
                "packs": sorted(packs.get(pid, [])),
                "activity": _activity(mine) if sessions is not None else None,
            }
        )
    return {
        "agents": agents,
        "activity": sessions is not None,
        "counts": {
            "agents": len(agents),
            "compiled": sum(1 for a in agents if a["profile_file"]),
            "writers": sum(1 for a in agents if a["lanes"]),
            "active": sum(1 for a in agents if a["activity"] and a["activity"]["sessions"]),
        },
        "problems": problems,
    }


def _activity(sessions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not sessions:
        return {"sessions": 0, "last_seen": None, "state": None, "runtimes": []}
    last = max(sessions, key=lambda s: parse_iso(s["last_seen"]))
    return {
        "sessions": len(sessions),
        "last_seen": last["last_seen"],
        "state": last["state"],
        "runtimes": sorted({s["runtime"] for s in sessions if s.get("runtime")}),
    }


# ------------------------------------------------------------------------------ render
def _none(text: str = "none") -> str:
    return f'<span class="muted">{svg.e(text)}</span>'


def _last(a: Mapping[str, Any], tier: bool) -> str:
    act = a["activity"]
    if not tier:
        return _none("activity tier not configured")
    if not act["sessions"]:
        return _none("no sessions in the store")
    st = act["state"]
    return (
        f'{svg.e(act["last_seen"])} <span class="s {_SESSION_CHIP.get(st, "unknown")}">'
        f"{svg.e(st)}</span><br>"
        f'<span class="muted">{act["sessions"]} session(s) &middot; '
        f"{svg.e(', '.join(act['runtimes']) or 'no runtime')}</span>"
    )


def _grants(a: Mapping[str, Any]) -> str:
    if a["profile_file"]:
        out = [f"tier <b>{svg.e(a['tier'])}</b>", f"caps {svg.codes(a['capabilities'])}"]
        if a["reads_untrusted"]:
            out.append("reads untrusted input (no acting grant)")
    else:
        out = [_none("no compiled profile")]
    acts = ", ".join(
        svg.code(x["action"]) + (" (approval)" if x["approval"] else "") for x in a["actions"]
    )
    if acts:
        out.append(f"broker {acts}")
    return "<br>".join(out)


def _lanes(a: Mapping[str, Any]) -> str:
    if not a["lanes"]:
        return _none("writes no lane")
    return "<br>".join(
        f"{svg.code(ln['lane'])} {svg.e(ln['kind'] or '')}"
        + (" (its own)" if ln["per_actor"] else "")
        + f' <span class="muted">via {svg.e(ln["via"])}</span>'
        for ln in a["lanes"]
    )


def _runtime(a: Mapping[str, Any]) -> str:
    out = [svg.e(a["runtime"]) if a["runtime"] else _none("not declared")]
    if a["model_role"]:
        backends = ", ".join(a["model_backends"])
        out.append(svg.code(a["model_role"]) + (f" on {svg.e(backends)}" if backends else ""))
    if a["data_tier"]:
        out.append(f'<span class="muted">data {svg.e(a["data_tier"])}</span>')
    return "<br>".join(out)


def render(vm: Mapping[str, Any]) -> str:
    c = vm["counts"]
    parts = [
        '<p class="chips">'
        f"<b>{c['agents']} agent profiles</b><b>{c['compiled']} compiled</b>"
        f"<b>{c['writers']} may write a lane</b>"
        + (f"<b>{c['active']} with sessions</b>" if vm["activity"] else "")
        + "</p>",
    ]
    probs = "".join(f"<li>{svg.e(p)}</li>" for p in vm["problems"])
    if probs:
        parts.append(f'<ul class="warn">{probs}</ul>')
    parts.append(
        svg.table(
            "Agent roster",
            (
                "Agent",
                "Owner",
                "Runtime and model",
                "Grants",
                "MCP servers",
                "May write",
                "Last activity",
            ),
            [
                (
                    svg.code(a["id"])
                    + (f"<br>{svg.e(a['what'])}" if a["what"] else "")
                    + (
                        f'<br><span class="muted">packs: {svg.e(", ".join(a["packs"]))}</span>'
                        if a["packs"]
                        else ""
                    ),
                    svg.e(a["owner"]) if a["owner"] else _none("not declared"),
                    _runtime(a),
                    _grants(a),
                    svg.codes(a["mcp"]),
                    _lanes(a),
                    _last(a, vm["activity"]),
                )
                for a in vm["agents"]
            ],
        )
    )
    return "".join(parts)
