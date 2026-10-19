# SPDX-License-Identifier: Apache-2.0
"""Render, refresh and check per-system SOP pages.

A page has YAML front-matter and nine fixed sections.  Machine-known facts live inside
``<!-- hnx:gen:NAME -->`` ... ``<!-- /hnx:gen -->`` blocks, which regeneration rewrites; human
prose lives outside them, in ``<!-- hnx:todo -->`` blocks that regeneration never touches.  Links
between pages are relative (``other.md``) and path-qualified ``[[systems/other|other]]`` wiki-links
resolve in an Obsidian vault opened at ``docs/`` (where ``docs/capabilities/`` holds pages of the
same names, so a bare ``[[other]]`` would be ambiguous).  The ``what`` block links the service's
capability reference page when the capability is one of the conformance capabilities.
Credentials appear as secret-store NAMES only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext.conform.registry import CAPABILITIES
from homelabnext.registry.model import Registry, Service

GEN_RE = re.compile(
    r"(?P<open><!-- hnx:gen:(?P<name>[a-z-]+) -->\n)(?P<body>.*?)(?P<close><!-- /hnx:gen -->)",
    re.DOTALL,
)
TODO_RE = re.compile(r"<!-- hnx:todo:(?P<name>[a-z-]+)")
FRONT_RE = re.compile(r"\A---\n(?P<fm>.*?)\n---\n", re.DOTALL)

# (key, heading, what the human section must say)
SECTIONS: tuple[tuple[str, str, str], ...] = (
    ("what", "What it does", "one paragraph: the job, who needs it, what breaks without it"),
    ("inputs", "Inputs", "what it consumes and in what format (schemas, queues, files, requests)"),
    ("outputs", "Outputs", "what it produces, each with its format and where it lands"),
    ("use", "How to use it", "the everyday commands or clicks, with one worked example"),
    (
        "verify",
        "How to verify it is healthy",
        "the observable that proves it works, beyond the probe",
    ),
    ("failure", "Failure modes", "symptom, likely cause, first check, fix: one row each"),
    (
        "deps",
        "Depends on / depended on by",
        "anything the registry cannot know (data, humans, schedules)",
    ),
    ("access", "Credentials and access", "secret-store NAMES only (never values), who may use it"),
    ("source", "Source of truth", "where the config, runbook and decisions live"),
)

TODO_TEXT = "TODO(human): "


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-")


def _link(name: str) -> str:
    return f"[{name}]({slug(name)}.md) ([[systems/{slug(name)}|{slug(name)}]])"


def _contract(capability: str) -> str:
    if capability in CAPABILITIES:
        c = slug(capability)
        return (
            f"[{c} capability reference](../capabilities/{c}.md)"
            f" ([[capabilities/{c}|{c} capability]]): operations, data shapes, conformance checks,"
            " adapters"
        )
    return f"none (`{capability}` is not one of the conformance capabilities)"


def _health(s: Service) -> str:
    h = s.health or {"kind": "none"}
    kind = h.get("kind", "none")
    if kind == "http":
        return f"HTTP GET `{h.get('path', '/')}` expects status `{h.get('expect_status', 200)}`" + (
            f" every {h['interval_s']}s" if h.get("interval_s") else ""
        )
    if kind == "tcp":
        return f"TCP connect to port `{s.port}`"
    return "no probe is defined in the registry (a gap: add one, or say why none is possible)"


def _gen_blocks(reg: Registry, s: Service) -> dict[str, str]:
    host = reg.hosts[s.host]
    downstream = sorted(o.name for o in reg.services.values() if s.name in o.upstreams)
    ups = [_link(u) for u in s.upstreams] or ["none declared"]
    downs = [_link(d) for d in downstream] or ["none declared"]
    metrics = s.metrics or {}
    gen: dict[str, str] = {
        "what": (
            f"- Capability: `{s.capability}`\n- Contract: {_contract(s.capability)}\n"
            f"- Implementation: `{s.impl or 'unspecified'}`"
            f" {s.version}\n- Owner: {s.owner}\n- Tags: {', '.join(s.tags) or 'none'}\n"
        ),
        "inputs": (
            f"- Listens on `{s.protocol}` port `{s.port}` on host `{s.host}` (zone"
            f" `{host.zone}`)\n- TLS: `{s.tls}`\n- Allowed client zones:"
            f" {', '.join(s.clients) or 'not restricted in the registry'}\n"
        ),
        "outputs": (
            (
                f"- Metrics: `{metrics.get('path', '/metrics')}`"
                f"{' on port ' + str(metrics['port']) if metrics.get('port') else ''}\n"
                if s.metrics
                else "- Metrics: none declared\n"
            )
            + (
                f"- MCP tool server `{s.mcp['name']}` ({s.mcp['transport']}, `{s.mcp['path']}`)\n"
                if s.mcp
                else "- MCP: none\n"
            )
        ),
        "verify": f"- Registry health probe: {_health(s)}\n",
        "deps": (
            "- Depends on: " + ", ".join(ups) + "\n- Depended on by: " + ", ".join(downs) + "\n"
        ),
        "access": (
            f"- Authentication: `{s.auth}`\n"
            + (f"- Public hostname: `{s.public_hostname}`\n" if s.public_hostname else "")
            + f"- Endpoint override variable: `{s.endpoint_env_var}`\n"
        ),
        "source": (
            f"- Registry row: `services.{s.name}`\n"
            f"- Backup: {('job `' + s.backup_job + '`') if s.backup_job else 'not in a backup job'}\n"
        ),
    }
    return gen


def _front(reg: Registry, s: Service | None) -> dict[str, Any]:
    if s is None:
        return {
            "title": "<service>",
            "type": "system",
            "service": "<service>",
            "capability": "<capability>",
            "status": "draft",
        }
    return {
        "title": s.name,
        "type": "system",
        "service": s.name,
        "capability": s.capability,
        "impl": s.impl or None,
        "owner": s.owner,
        "host": s.host,
        "port": s.port,
        "protocol": s.protocol,
        "health": (s.health or {}).get("kind", "none"),
        "backup_job": s.backup_job,
        "tags": list(s.tags),
        "status": "draft",
    }


def _dump_front(fm: Mapping[str, Any]) -> str:
    return (
        "---\n"
        + yaml.safe_dump(dict(fm), sort_keys=False, default_flow_style=None).rstrip()
        + "\n---\n"
    )


def _todo(key: str, hint: str) -> str:
    return f"<!-- hnx:todo:{key} -->\n> {TODO_TEXT}{hint}.\n<!-- /hnx:todo -->\n"


def _body(gen: Mapping[str, str] | None) -> str:
    out = ["\n# {{title}}\n".replace("{{title}}", "<service>" if gen is None else "@@TITLE@@")]
    for key, heading, hint in SECTIONS:
        out.append(f"\n## {heading}\n\n")
        if gen is None or key in _GEN_KEYS:
            body = "" if gen is None else gen[key]
            if gen is None:
                body = "- (machine-known facts from the registry are filled in here)\n"
            out.append(f"<!-- hnx:gen:{key} -->\n{body}<!-- /hnx:gen -->\n\n")
        out.append(_todo(key, hint))
    return "".join(out)


_GEN_KEYS = {"what", "inputs", "outputs", "verify", "deps", "access", "source"}


def render_page(reg: Registry, s: Service) -> str:
    text = _dump_front(_front(reg, s)) + _body(_gen_blocks(reg, s))
    return text.replace("@@TITLE@@", s.name)


def render_template() -> str:
    """The blank skeleton: ``docs/systems/_TEMPLATE.md`` is exactly this."""
    return _dump_front(_front_blank()) + _body(None)


def _front_blank() -> dict[str, Any]:
    return _front(None, None)  # type: ignore[arg-type]


def refresh_page(existing: str, fresh: str) -> str:
    """Rewrite only the generated blocks and the machine front-matter keys of ``existing``."""
    gens = {m["name"]: m["body"] for m in GEN_RE.finditer(fresh)}
    out = GEN_RE.sub(lambda m: m["open"] + gens.get(m["name"], m["body"]) + m["close"], existing)
    fm_new = yaml.safe_load(FRONT_RE.match(fresh)["fm"])
    m = FRONT_RE.match(out)
    if not m:
        return fresh
    fm_old = yaml.safe_load(m["fm"]) or {}
    keep = {k: fm_old[k] for k in ("status", "reviewed") if k in fm_old}
    merged = {**fm_new, **keep}
    return _dump_front(merged) + out[m.end() :]


@dataclass
class GenResult:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)


def generate_pages(reg: Registry, out_dir: str | Path) -> GenResult:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    res = GenResult()
    for s in reg.sorted_services():
        path = out / f"{slug(s.name)}.md"
        fresh = render_page(reg, s)
        if not path.exists():
            path.write_text(fresh, encoding="utf-8")
            res.created.append(path.name)
            continue
        old = path.read_text(encoding="utf-8")
        new = refresh_page(old, fresh)
        if new == old:
            res.unchanged.append(path.name)
        else:
            path.write_text(new, encoding="utf-8")
            res.updated.append(path.name)
    return res


@dataclass
class CheckReport:
    missing: list[str] = field(default_factory=list)  # registry row without a page
    orphans: list[str] = field(default_factory=list)  # page without a registry row
    stale: list[str] = field(default_factory=list)  # generated block differs from the registry
    malformed: list[str] = field(default_factory=list)
    todo_open: dict[str, int] = field(default_factory=dict)  # page -> unfilled TODO blocks

    def ok(self, require_complete: bool = False) -> bool:
        bad = self.missing or self.orphans or self.stale or self.malformed
        return not bad and not (require_complete and any(self.todo_open.values()))

    def lines(self) -> list[str]:
        out = [f"missing page for service: {n}" for n in self.missing]
        out += [f"orphan page (no registry row): {n}" for n in self.orphans]
        out += [f"stale generated block (run `hnx docs systems generate`): {n}" for n in self.stale]
        out += [f"malformed page: {n}" for n in self.malformed]
        return out


def _unfilled(text: str) -> int:
    return text.count(TODO_TEXT)


def check_pages(reg: Registry, pages_dir: str | Path) -> CheckReport:
    d = Path(pages_dir)
    rep = CheckReport()
    pages = (
        {p.name: p for p in sorted(d.glob("*.md")) if not p.name.startswith("_")}
        if d.is_dir()
        else {}
    )
    by_service: dict[str, Path] = {}
    for name, p in pages.items():
        m = FRONT_RE.match(p.read_text(encoding="utf-8"))
        try:
            fm = yaml.safe_load(m["fm"]) if m else None
        except yaml.YAMLError:
            fm = None
        if not isinstance(fm, dict) or fm.get("type") != "system" or not fm.get("service"):
            rep.malformed.append(name)
            continue
        if fm["service"] in by_service or slug(str(fm["service"])) + ".md" != name:
            rep.malformed.append(name)
            continue
        by_service[fm["service"]] = p
    for s in reg.sorted_services():
        p = by_service.get(s.name)
        if p is None:
            rep.missing.append(s.name)
            continue
        text = p.read_text(encoding="utf-8")
        if refresh_page(text, render_page(reg, s)) != text:
            rep.stale.append(p.name)
        rep.todo_open[p.name] = _unfilled(text)
    rep.orphans = sorted(p.name for n, p in by_service.items() if n not in reg.services)
    return rep
