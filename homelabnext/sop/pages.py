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

Reviews (:mod:`homelabnext.reviews`): the front-matter carries ``author:``; the reviews are
append-only event files beside the page, ``docs/systems/<service>.events/``
(:mod:`homelabnext.registers.events`; an inline ``reviews:`` list still counts, ``hnx registers
events migrate docs/systems`` moves it out), and ``status: reviewed`` is checked against the review policy (``system-page.reviewed``), with no
TODO(human) left.  A review's digest (:func:`page_digest`) covers only what people own, the
``hnx:todo`` blocks and any human front-matter field, never the ``hnx:gen`` blocks, so
regenerating machine facts keeps a review current and editing the prose drops it.
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
TODO_BLOCK_RE = re.compile(
    r"<!-- hnx:todo:(?P<name>[a-z-]+) -->\n(?P<body>.*?)<!-- /hnx:todo -->", re.DOTALL
)
# front-matter keys people own: preserved by regeneration; status/author/reviews are about the
# page, not its content, so they are outside the review digest
HUMAN_KEYS = ("status", "reviewed", "author", "reviews")
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


def _mcp_lines(s: Service, catalog: Any = None) -> str:
    """The MCP line(s) of a page.  With the MCP catalog (:mod:`homelabnext.mcp.servers`): every
    catalog server whose endpoint is this service, with its classes, owner, status and record;
    without one, the registry's own ``mcp`` entry."""
    if catalog is None:
        if s.mcp:
            return (
                f"- MCP tool server `{s.mcp['name']}` ({s.mcp['transport']}, `{s.mcp['path']}`)\n"
            )
        return "- MCP: none\n"
    lines = []
    for sid, rec in catalog:
        t = rec.get("transport") or {}
        if t.get("endpoint") != f"svc:{s.name}":
            continue
        classes = sorted({c for tool in rec.get("tools") or () for c in tool.get("classes") or ()})
        lines.append(
            f"- MCP server `{sid}` ({t.get('type')}, `{t.get('path', '/mcp')}`): "
            f"{', '.join(classes) or 'no tools classed'}; owner {rec.get('owner')}; "
            f"{rec.get('status')}; catalog record `{catalog.rel(sid)}`\n"
        )
    if lines:
        return "".join(lines)
    if s.mcp:
        return f"- MCP tool server `{s.mcp['name']}`: not in the MCP catalog\n"
    return "- MCP: none\n"


def _gen_blocks(reg: Registry, s: Service, catalog: Any = None) -> dict[str, str]:
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
            + _mcp_lines(s, catalog)
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
            f"- Registry row (Veritas, ADR-0028): `services.{s.name}`\n"
            f"- Backup: {('job `' + s.backup_job + '`') if s.backup_job else 'not in a backup job'}\n"
        ),
    }
    return gen


def system_summary(s: Service) -> str:
    """The page's level-0 summary (ADR-0032), derived only from the registry row: what the service
    is for, what implements it and who owns it.  One line of at most 160 characters."""
    from homelabnext.context.levels import clean, cut

    impl = f" ({s.impl})" if s.impl else ""
    owner = f", owned by {s.owner}" if s.owner else ""
    return cut(clean(f"{s.name} provides the {s.capability} capability{impl}{owner}."))


def _front(reg: Registry, s: Service | None) -> dict[str, Any]:
    if s is None:
        return {
            "title": "<service>",
            "type": "system",
            "service": "<service>",
            "capability": "<capability>",
            "status": "draft",
            "author": "unknown",
        }
    return {
        "title": s.name,
        "type": "system",
        "summary": system_summary(s),
        "summary_generated": True,
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
        "author": "unknown",
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


def render_page(reg: Registry, s: Service, catalog: Any = None) -> str:
    """One page; ``catalog``: the MCP catalog its MCP line is generated from (else the
    registry's ``mcp`` entry)."""
    text = _dump_front(_front(reg, s)) + _body(_gen_blocks(reg, s, catalog))
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
    machine = set(fm_new) - set(HUMAN_KEYS)
    keep = {k: v for k, v in fm_old.items() if k not in machine}
    merged = {**fm_new, **keep}
    return _dump_front(merged) + out[m.end() :]


@dataclass
class GenResult:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)


def generate_pages(reg: Registry, out_dir: str | Path, catalog: Any = None) -> GenResult:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    res = GenResult()
    for s in reg.sorted_services():
        path = out / f"{slug(s.name)}.md"
        fresh = render_page(reg, s, catalog)
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
    review_problems: list[str] = field(default_factory=list)  # fatal review rule or claim
    drafts: dict[str, list[str]] = field(default_factory=dict)  # draft -> tiers `reviewed` needs

    def ok(self, require_complete: bool = False) -> bool:
        bad = self.missing or self.orphans or self.stale or self.malformed or self.review_problems
        return not bad and not (require_complete and any(self.todo_open.values()))

    def lines(self) -> list[str]:
        out = [f"missing page for service: {n}" for n in self.missing]
        out += [f"orphan page (no registry row): {n}" for n in self.orphans]
        out += [f"stale generated block (run `hnx docs systems generate`): {n}" for n in self.stale]
        out += [f"malformed page: {n}" for n in self.malformed]
        out += [f"review: {p}" for p in self.review_problems]
        return out

    def info(self) -> list[str]:
        """Draft pages grouped by the review tiers ``reviewed`` would still need."""
        groups: dict[tuple[str, ...], list[str]] = {}
        for name, need in sorted(self.drafts.items()):
            groups.setdefault(tuple(need), []).append(name)
        return [
            f"draft ({'needs ' + ', '.join(need) if need else 'reviews complete'}): "
            + ", ".join(names)
            for need, names in groups.items()
        ]


def _unfilled(text: str) -> int:
    return text.count(TODO_TEXT)


_MACHINE_KEYS = frozenset(_front_blank()) | {
    "summary",
    "summary_generated",
    "summary_of",
    "impl",
    "owner",
    "host",
    "port",
    "protocol",
    "health",
    "backup_job",
    "tags",
}


def page_digest(text: str) -> str:
    """The digest a review of this page carries: its human blocks and human front-matter only."""
    from homelabnext.reviews import content_digest

    m = FRONT_RE.match(text)
    fm = (yaml.safe_load(m["fm"]) if m else None) or {}
    if not isinstance(fm, dict):
        raise ValueError("front-matter must be a mapping")
    human_fm = {k: v for k, v in fm.items() if k not in _MACHINE_KEYS and k not in HUMAN_KEYS}
    blocks = {b["name"]: b["body"].strip() for b in TODO_BLOCK_RE.finditer(text)}
    return content_digest({"front": human_fm, "blocks": blocks})


def page_reviews(path: Path, fm: Mapping[str, Any], problems: list[str]) -> list:
    """The page's reviews: an inline ``reviews:`` list, then its ``<service>.events/`` events."""
    from homelabnext.registers import events as ev

    events = ev.read_events(ev.events_dir(path), problems, path.name)
    return ev.derive(dict(fm), events, "system-page", problems, path.name).get("reviews")


def _review_page(
    name: str, text: str, fm: dict, policy, rep: CheckReport, path: Path | None = None
) -> None:
    from homelabnext.reviews import evaluate, missing_message

    if path is not None:
        fm = {**fm, "reviews": page_reviews(path, fm, rep.review_problems)}
    status = fm.get("status", "draft")
    if status not in ("draft", "reviewed"):
        rep.review_problems.append(f"{name}: status must be draft or reviewed, not {status!r}")
        return
    digest = page_digest(text)
    ev = evaluate(
        fm.get("reviews"),
        author=fm.get("author"),
        digest=digest,
        artefact="system-page",
        state=status,
        policy=policy,
        who=name,
    )
    rep.review_problems += ev.problems
    if policy is None:
        return
    if status == "reviewed":
        if ev.missing:
            rep.review_problems.append(missing_message(name, status, ev, digest))
        if _unfilled(text):
            rep.review_problems.append(f"{name}: status reviewed with TODO(human) left")
    else:
        need = evaluate(
            fm.get("reviews"),
            author=fm.get("author"),
            digest=digest,
            artefact="system-page",
            state="reviewed",
            policy=policy,
        ).missing
        rep.drafts[name] = need


def check_pages(
    reg: Registry, pages_dir: str | Path, policy=None, catalog: Any = None
) -> CheckReport:
    """Missing, orphan, malformed and stale pages; and with a review ``policy``
    (:func:`homelabnext.reviews.load_policy`) every page's status against its reviews.
    ``catalog``: the MCP catalog the pages' MCP lines come from."""
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
        if refresh_page(text, render_page(reg, s, catalog)) != text:
            rep.stale.append(p.name)
        rep.todo_open[p.name] = _unfilled(text)
        _review_page(p.name, text, yaml.safe_load(FRONT_RE.match(text)["fm"]), policy, rep, p)
    rep.orphans = sorted(p.name for n, p in by_service.items() if n not in reg.services)
    return rep
