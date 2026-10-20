# SPDX-License-Identifier: Apache-2.0
"""Linked knowledge for a context pack: a profile's ``include:`` rules run over the repository
graph (:mod:`homelabnext.graph`), filtered by what the profile is granted.

:func:`select_knowledge` returns a :class:`Selection`: the included nodes with their content (the
record or page text itself, not a pointer to it), ordered by :func:`homelabnext.graph.related`
rank, and every exclusion with its reason.  :func:`~homelabnext.agent.pack.assemble_pack` turns it
into volatile sections and records :meth:`Selection.record` in the pack, so a run says exactly
which ids and which content digests it carried.

**Grant filtering is the security property.**  The access-bearing nodes are capabilities
(``cap:``), services (``svc:``), MCP servers (``mcp:``) and broker actions (``action:``).  The
profile's *granted* set is its granted capabilities, its granted MCP servers and the services
that provide a granted capability; broker actions are never in it (the access block lists them).
A node's *subjects* are the access-bearing nodes it is directly linked to, in either direction,
looking through the nodes that only name one: a system tag (to what it ``resolves_to``), a
product (to the services that ``run`` it), an adapter (to what it ``implements``) and a compose
service (to what it ``provides``).  A node is eligible only when it has a subject and **every**
subject is granted: a page about a granted and an ungranted capability is excluded, one hop away
or not.  Candidates are found on the graph with ungranted access-bearing nodes removed (nothing
is reached *through* one), but subjects are read on the full graph, so removing a node can never
make a candidate look clean.

Also excluded, with the reason recorded: inactive records (retired, superseded, incorporated;
never included), records missing a review tier the rule requires (``require_reviews`` applies to
the reviewable kinds, lessons, runbooks and criteria; other kinds are code reviewed in git), a
node over its rule's ``budget`` (lowest rank first), and content that cannot be read.  An
ungranted capability, service or MCP server named in the task text is dropped as a seed.

Content.  A node whose ``path`` is a file only it defines contributes that file (a lesson, a
runbook, a page, a schema); a node that shares its file (a conformance check, an invariant) or has
none contributes a rendering of its own graph record.  Paths never leave ``root``.

Determinism: the selection is a function of the profile, the graph and the task; ordering is by
distance, then score, then id, and the record carries the graph's digest.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext.graph import Edge, Graph, dumps, is_active, related, seeds_for

from .compiler import profile_digest
from .digest import canonical_json, sha256_text
from .errors import SpecError
from .include import normalise_include
from .pack import KNOWLEDGE_PREFIX

ACCESS_KINDS = frozenset({"action", "cap", "mcp", "svc"})
REVIEWABLE_KINDS = frozenset({"inv", "lesson", "runbook"})
#: kinds that only name an access-bearing node: (edge type, direction) to follow from them
_PROXIES: dict[str, tuple[str, str]] = {
    "system": ("resolves_to", "out"),
    "product": ("runs", "in"),
    "adapter": ("implements", "out"),
    "compose": ("provides", "out"),
}
_UNBOUNDED = 1_000_000


@dataclass(frozen=True)
class Selection:
    """What :func:`select_knowledge` chose: ``included`` (rank order, each with ``text``) and
    ``excluded`` (by id), plus the seeds of each rule and the inputs' digests."""

    profile: str
    profile_digest: str
    graph_digest: str
    rules: tuple[dict, ...]
    seeds: tuple[tuple[str, ...], ...]
    included: tuple[dict, ...]
    excluded: tuple[dict, ...]

    def record(self) -> dict[str, Any]:
        """The pack's ``knowledge`` block: everything but the content itself."""
        return {
            "profile": self.profile,
            "profile_digest": self.profile_digest,
            "graph_digest": self.graph_digest,
            "rules": [dict(r) for r in self.rules],
            "seeds": [list(s) for s in self.seeds],
            "included": [{k: v for k, v in i.items() if k != "text"} for i in self.included],
            "excluded": [dict(e) for e in self.excluded],
        }

    def sections(self) -> list[dict[str, Any]]:
        """One volatile section per included node, named so pack order is rank order."""
        return [
            {
                "name": i["section"],
                "tier": "volatile",
                "source": "knowledge",
                "required": False,
                "max_chars": i["max_chars"],
                "text": i["text"],
            }
            for i in self.included
        ]


def granted_nodes(graph: Graph, grants: Mapping[str, Any]) -> set[str]:
    """Access-bearing node ids the profile holds: granted caps and MCP servers, and the services
    providing a granted cap."""
    caps = set(grants.get("capabilities") or ())
    out = caps | {f"mcp:{m}" for m in grants.get("mcp") or ()}
    for cap in caps:
        out |= {e.src for e in graph.in_edges(cap) if e.type == "provides" and e.src[:4] == "svc:"}
    return out


def subjects(graph: Graph, nid: str) -> set[str]:
    """The access-bearing nodes ``nid`` is about (see the module doc)."""
    out: set[str] = set()
    edges = [(e, e.dst) for e in graph.out_edges(nid)] + [(e, e.src) for e in graph.in_edges(nid)]
    for _, other in edges:
        node = graph.nodes.get(other)
        if node is None:
            continue
        if node.kind in ACCESS_KINDS:
            out.add(other)
        elif node.kind in _PROXIES:
            etype, direction = _PROXIES[node.kind]
            hops = graph.out_edges(other) if direction == "out" else graph.in_edges(other)
            for e in hops:
                far = e.dst if direction == "out" else e.src
                if e.type == etype and far != nid and far[: far.find(":")] in ACCESS_KINDS:
                    out.add(far)
    return out


def _pruned(graph: Graph, granted: set[str]) -> Graph:
    """The search graph: ungranted access-bearing nodes removed, and system tags made
    transparent (a record ``about`` a tag is also ``about`` what the tag resolves to, one hop)."""
    drop = {n.id for n in graph.nodes.values() if n.kind in ACCESS_KINDS and n.id not in granted}
    nodes = {k: v for k, v in graph.nodes.items() if k not in drop}
    edges = [e for e in graph.edges if e.src not in drop and e.dst not in drop]
    for tag in graph.of_kind("system"):
        targets = [e.dst for e in graph.out_edges(tag.id) if e.type == "resolves_to"]
        for e in graph.in_edges(tag.id):
            if e.type == "about":
                edges += [
                    Edge(e.src, t, "about", f"{e.source} via {tag.id}")
                    for t in targets
                    if t in nodes
                ]
    return Graph(nodes, edges)


def _content(graph: Graph, nid: str, root: Path, shared: Mapping[str, int]) -> str | None:
    node = graph.nodes[nid]
    if node.path and shared.get(node.path) == 1:
        target = (root / node.path).resolve()
        if root != target and root not in target.parents:
            return None
        try:
            return target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
    lines = [f"{node.kind} {node.id}: {node.title}".rstrip(": ")]
    if node.path:
        lines.append(f"defined in: {node.path}")
    lines += [f"{k}: {canonical_json(v)}" for k, v in sorted(node.attrs.items())]
    return "\n".join(lines) + "\n"


def _section_name(rank: int, nid: str) -> str:
    return f"{KNOWLEDGE_PREFIX}{rank:03d}-" + re.sub(r"[^A-Za-z0-9._-]+", "-", nid).strip("-")


def _check_profile(profile: Mapping[str, Any]) -> None:
    if not isinstance(profile, Mapping) or not profile.get("id") or not profile.get("digest"):
        raise SpecError("knowledge needs a compiled agent profile (id and digest)")
    if profile_digest(profile) != profile["digest"]:
        raise SpecError(f"{profile['id']}: profile digest does not match its content")


def select_knowledge(
    profile: Mapping[str, Any],
    graph: Graph,
    root: str | Path,
    *,
    task_paths: Iterable[str] = (),
    task_text: str = "",
    graph_digest: str | None = None,
) -> Selection:
    """Run ``profile``'s ``include`` rules over ``graph`` (built from the checkout at ``root``).

    The rules are re-checked against the profile's grants here (the compiler's check is not
    trusted), so an edited profile that seeds from an ungranted thing raises
    :class:`~homelabnext.agent.errors.IncludeViolation`."""
    _check_profile(profile)
    grants = profile.get("grants") or {}
    rules = normalise_include(profile.get("include"), grants)
    root = Path(root).resolve()
    granted = granted_nodes(graph, grants)
    pruned = _pruned(graph, granted)
    shared: dict[str, int] = {}
    for n in graph.nodes.values():
        shared[n.path] = shared.get(n.path, 0) + 1
    task_paths = sorted(set(task_paths))

    best: dict[str, dict[str, Any]] = {}  # included: id -> entry
    excluded: dict[str, dict[str, Any]] = {}
    all_seeds: list[tuple[str, ...]] = []

    def exclude(nid: str, reason: str, rule: int) -> None:
        if nid not in excluded:
            kind = graph.nodes[nid].kind if nid in graph.nodes else nid.split(":", 1)[0]
            excluded[nid] = {"id": nid, "kind": kind, "reason": reason, "rule": rule}

    for ri, rule in enumerate(rules):
        src = rule["from"]
        if src == "capabilities":
            seeds = list(rule.get("only") or grants.get("capabilities") or ())
        elif src == "mcp":
            seeds = [f"mcp:{m}" for m in rule.get("only") or grants.get("mcp") or ()]
        elif src == "services":
            seeds = sorted(n for n in granted if n.startswith("svc:"))
        else:
            seeds = []
            for s in seeds_for(graph, task_paths, task_text):
                if graph.nodes[s].kind in ACCESS_KINDS and s not in granted:
                    exclude(s, f"task names {s}, which the profile is not granted: not a seed", ri)
                else:
                    seeds.append(s)
        seeds = sorted(s for s in set(seeds) if s in pruned.nodes)
        all_seeds.append(tuple(seeds))
        kinds = set(rule["kinds"])
        cands = [
            (0, 1.0, "seed", s, s)
            for s in seeds
            if pruned.nodes[s].kind in kinds and is_active(pruned.nodes[s])
        ]
        cands += [
            (r.distance, r.score, r.via, r.parent, r.id)
            for r in related(pruned, seeds, budget=_UNBOUNDED, max_depth=rule["depth"])
            if r.kind in kinds
        ]
        for r in related(
            pruned, seeds, budget=_UNBOUNDED, max_depth=rule["depth"], include_inactive=True
        ):
            if r.kind in kinds and not is_active(pruned.nodes[r.id]):
                status = pruned.nodes[r.id].attrs.get("status")
                exclude(r.id, f"inactive record (status: {status}): never included", ri)
        taken = 0
        for dist, score, via, parent, nid in cands:
            node = graph.nodes[nid]
            about = subjects(graph, nid)
            reason = None
            if not about:
                reason = "not about anything the profile is granted"
            elif about - granted:
                reason = "about what the profile is not granted: " + ", ".join(
                    sorted(about - granted)
                )
            elif "require_reviews" in rule and node.kind in REVIEWABLE_KINDS:
                have = set(node.attrs.get("reviewed") or ())
                missing = sorted(set(rule["require_reviews"]) - have)
                if missing:
                    reason = (
                        f"reviews: no current {', '.join(missing)} "
                        f"(has: {', '.join(sorted(have)) or 'none'})"
                    )
            if reason is None and nid in best:
                if taken < rule["budget"]:  # already included by an earlier rule
                    best[nid]["rules"].append(ri)
                    best[nid]["max_chars"] = max(best[nid]["max_chars"], rule["max_chars"])
                    if (dist, -score) < (best[nid]["distance"], -best[nid]["score"]):
                        best[nid].update(distance=dist, score=round(score, 6), via=via)
                        best[nid]["from"] = parent
                    taken += 1
                continue
            if reason is None and taken >= rule["budget"]:
                reason = f"over budget: rule {ri} includes at most {rule['budget']} nodes"
            text = None
            if reason is None:
                text = _content(graph, nid, root, shared)
                if text is None:
                    reason = f"content unreadable: {node.path}"
            if reason is not None:
                exclude(nid, reason, ri)
                continue
            taken += 1
            best[nid] = {
                "id": nid,
                "kind": node.kind,
                "title": node.title,
                "path": node.path,
                "reviewed": sorted(node.attrs.get("reviewed") or ()),
                "distance": dist,
                "score": round(score, 6),
                "via": via,
                "from": parent,
                "rules": [ri],
                "max_chars": rule["max_chars"],
                "digest": sha256_text(text),
                "text": text,
            }

    order = sorted(best.values(), key=lambda i: (i["distance"], -i["score"], i["id"]))
    included = []
    for rank, item in enumerate(order, 1):
        excluded.pop(item["id"], None)  # another rule included it
        entry = {**item, "rank": rank, "section": _section_name(rank, item["id"])}
        entry["text"] = _header(entry) + item["text"]
        included.append(entry)
    return Selection(
        profile=profile["id"],
        profile_digest=profile["digest"],
        graph_digest=graph_digest or sha256_text(dumps(graph)),
        rules=tuple(rules),
        seeds=tuple(all_seeds),
        included=tuple(included),
        excluded=tuple(excluded[k] for k in sorted(excluded)),
    )


def _header(item: Mapping[str, Any]) -> str:
    """The trusted header of an included node: id, path, review tiers, rank and digest."""
    how = "a seed" if item["via"] == "seed" else f"{item['via']} from {item['from']}"
    return (
        f"knowledge {item['id']} ({item['kind']}): {item['title']}\n"
        f"path: {item['path'] or '(none)'}\n"
        f"reviews: {', '.join(item['reviewed']) or 'none'}\n"
        f"rank: {item['rank']} (distance {item['distance']}, {how})\n"
        f"content digest: {item['digest']}\n"
        "---\n"
    )


def explain(selection: Selection) -> str:
    """Human-readable account of a selection: rules, seeds, inclusions and exclusions."""
    lines = [
        f"profile {selection.profile} {selection.profile_digest}",
        f"graph {selection.graph_digest}",
    ]
    for n, (rule, seeds) in enumerate(zip(selection.rules, selection.seeds, strict=True)):
        lines.append(f"rule {n}: {canonical_json(rule)}")
        lines.append(f"  seeds: {', '.join(seeds) or '(none)'}")
    lines.append(f"included ({len(selection.included)}):")
    for i in selection.included:
        how = "seed" if i["via"] == "seed" else f"{i['via']} <- {i['from']}"
        lines.append(
            f"  {i['rank']:>3}  d={i['distance']} {i['score']:.3f}  {i['id']}  [{how}]"
            f"  reviews: {', '.join(i['reviewed']) or 'none'}  rules {i['rules']}"
        )
    lines.append(f"excluded ({len(selection.excluded)}):")
    for e in selection.excluded:
        lines.append(f"  {e['id']}  rule {e['rule']}: {e['reason']}")
    return "\n".join(lines) + "\n"
