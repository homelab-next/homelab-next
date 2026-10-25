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
looking through the nodes that only name one, transitively: a system tag (to what it
``resolves_to``), a product (to the services and compose services that ``run`` it and the adapters
written ``for`` it), an adapter (to what it ``implements``) and a compose service (to what it
``provides``).  A proxy that reaches nothing access-bearing counts as an ungranted subject (fail
closed).  A node is eligible only when it has a subject and **every** subject is granted: a page about a granted and an ungranted capability is excluded, one hop away
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

**Detail** (``detail:`` on a rule, ADR-0032).  ``full`` (the default) carries the whole content, as
it always did.  ``summary`` carries only the node's level 0 (the authored front-matter ``summary:``,
else its first paragraph, else for a node built from attributes a derived line; see
:func:`homelabnext.context.levels.summary_of`) and ``outline`` adds the heading outline with sizes
(slugs and paths the MCP ``section`` tool takes).  A node with no summary carries its title line and
``(no summary)``, with ``summary_source: none`` recorded; it never falls back to the full text.
A node included by several rules is carried at the richest detail any asks.  The pack record keeps
the digest of the FULL content whatever was emitted, and for a non-``full`` node also says its
``detail``, ``summary_source`` and ``content_chars`` (a ``full`` node carries none of the three,
so a pack without a ``detail`` rule is byte-for-byte what it was).  ``max_chars`` caps what is
emitted.
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
#: kinds that only name an access-bearing node: the (edge type, direction) pairs to follow from
#: them -- a system tag to what it resolves to, a product to the services and compose services that
#: run it and the adapters written for it, an adapter to what it implements, a compose service to
#: what it provides
_PROXIES: dict[str, tuple[tuple[str, str], ...]] = {
    "system": (("resolves_to", "out"),),
    "product": (("runs", "in"), ("for", "in")),
    "adapter": (("implements", "out"),),
    "compose": (("provides", "out"),),
}
#: proxies followed through at most this many in a chain (system -> product -> compose -> cap is 3)
_PROXY_DEPTH = 4
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
    """The access-bearing nodes ``nid`` is about (see the module doc).

    A proxy is looked through transitively (bounded by ``_PROXY_DEPTH``): a tag naming a product
    reaches the services that run it and the capabilities its adapters implement.  A proxy that
    links onward but reaches nothing access-bearing is itself a subject, and never granted, so a
    record about it is excluded (fail closed).  A system tag that resolves to nothing at all is a
    free-form topic (``tls``), not a proxy, and adds no subject."""
    out: set[str] = set()
    edges = [e.dst for e in graph.out_edges(nid)] + [e.src for e in graph.in_edges(nid)]
    for other in edges:
        node = graph.nodes.get(other)
        if node is None:
            continue
        if node.kind in ACCESS_KINDS:
            out.add(other)
        elif node.kind in _PROXIES:
            hops = _proxy_hops(graph, other, nid)
            if hops:
                reached = _through(graph, other, nid)
                out |= reached or {other}
    return out


def _proxy_hops(graph: Graph, proxy: str, origin: str) -> list[str]:
    """The nodes ``proxy`` names, by its kind's edges (never back to ``origin``)."""
    out = []
    for etype, direction in _PROXIES[graph.nodes[proxy].kind]:
        if direction == "out":
            out += [e.dst for e in graph.out_edges(proxy) if e.type == etype]
        else:
            out += [e.src for e in graph.in_edges(proxy) if e.type == etype]
    return [x for x in out if x != origin]


def _through(graph: Graph, proxy: str, origin: str) -> set[str]:
    """Access-bearing nodes reachable from ``proxy`` through proxies only."""
    found: set[str] = set()
    seen = {proxy, origin}
    frontier = [proxy]
    for _ in range(_PROXY_DEPTH):
        nxt = []
        for p in frontier:
            for far in _proxy_hops(graph, p, origin):
                if far in seen:
                    continue
                seen.add(far)
                kind = graph.nodes[far].kind if far in graph.nodes else far.split(":", 1)[0]
                if kind in ACCESS_KINDS:
                    found.add(far)
                elif kind in _PROXIES and far in graph.nodes:
                    nxt.append(far)
        frontier = nxt
    return found


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


def _content_of(
    graph: Graph, nid: str, root: Path, shared: Mapping[str, int], served: bool = False
) -> tuple[str | None, bool]:
    """``(content, file_backed)``: the file that defines the node when it defines nothing else,
    else a text built from the node's attributes (``file_backed`` False).

    ``served`` is for a ``summary`` or ``outline`` node: the text is then exactly what the context
    store indexes (:func:`homelabnext.context.repo.read_served`: undecodable bytes replaced, a file
    over the store's cap replaced by the node's attributes), so the slugs and the digest of a level
    are the ones the MCP server serves.  The default (``full``) reads strictly, as it always did."""
    node = graph.nodes[nid]
    if node.path and shared.get(node.path) == 1:
        target = (root / node.path).resolve()
        if root != target and root not in target.parents:
            return None, True
        if served:
            from homelabnext.context.repo import _summary as indexed_text
            from homelabnext.context.repo import read_served

            if not target.is_file():
                return None, True
            text = read_served(root, node.path)
            return (text, True) if text is not None else (indexed_text(node), False)
        try:
            return target.read_text(encoding="utf-8"), True
        except (OSError, UnicodeDecodeError):
            return None, True
    lines = [f"{node.kind} {node.id}: {node.title}".rstrip(": ")]
    if node.path:
        lines.append(f"defined in: {node.path}")
    lines += [f"{k}: {canonical_json(v)}" for k, v in sorted(node.attrs.items())]
    return "\n".join(lines) + "\n", False


#: how much each detail reads; a node several rules include is carried at the richest
_RICHNESS = {"summary": 0, "outline": 1, "full": 2}


def _leveled(
    graph: Graph, nid: str, text: str, file_backed: bool, detail: str, room: int = 1 << 30
):
    """``(body, summary_source)`` for a ``summary`` or ``outline`` node: level 0 of the node's
    content, and for ``outline`` the heading outline with sizes.  ``room`` bounds the body: an
    outline that would not fit stops at the last whole heading that does, and says how many it
    left out, so a document with a hundred thousand headings never costs more than its rule's
    ``max_chars``."""
    from homelabnext.context import digest
    from homelabnext.context.levels import is_markdown, parse, summary_of
    from homelabnext.context.repo import _summary as indexed_text  # what the MCP serves

    node = graph.nodes[nid]
    if file_backed:
        summary, source = summary_of(text, node.path)
    else:
        summary, source = summary_of(indexed_text(node), "", node.id)
    lines = [f"summary: {summary}" if summary else "(no summary)"]
    if detail == "outline":
        # the value MCP `section` takes as outline_digest (bare hex: the header's
        # `content digest` carries the sha256: prefix of the pack record)
        lines.append(f"outline_digest: {digest(text)}")
        if not file_backed:
            lines.append("outline: (no headings: built from attributes)")
        elif not is_markdown(node.path):
            lines.append("outline: (no headings: not a Markdown document)")
        else:
            parsed = parse(text)
            n = len(parsed.headings)
            lines.append(
                f"outline ({n} heading{'s' * (n != 1)}; "
                "open one with the MCP section tool, by slug or path):"
            )
            used = sum(len(x) + 1 for x in lines)
            for listed, h in enumerate(parsed.headings):
                line = (
                    f"{'  ' * (h.level - 1)}- {'#' * h.level} {h.title}"
                    f"  slug={h.slug}  path={h.path}  chars={h.chars}"
                )
                cut = f"(outline cut: {n - listed} of {n} headings not listed)"
                if used + len(line) + 1 + len(cut) + 1 > room:
                    lines.append(cut)
                    break
                lines.append(line)
                used += len(line) + 1
            else:
                if parsed.truncated:
                    lines.append(
                        f"(outline cut: only the first {parsed.parsed_chars} characters read)"
                    )
    return "\n".join(lines) + "\n", source


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
                from homelabnext.reviews import ROLE_ALIASES  # (reviews imports this package)

                # a profile compiled before the rename may still say `challenge` (now `audit`)
                need = {ROLE_ALIASES.get(t, t) for t in rule["require_reviews"]}
                missing = sorted(need - have)
                if missing:
                    reason = (
                        f"reviews: no current {', '.join(missing)} "
                        f"(has: {', '.join(sorted(have)) or 'none'})"
                    )
            if reason is None and nid in best:
                if taken < rule["budget"]:  # already included by an earlier rule
                    best[nid]["rules"].append(ri)
                    # detail and max_chars come from the rules at the richest detail only: a
                    # roomy summary rule must not widen a tight full rule
                    got, have = rule.get("detail", "full"), best[nid]["detail"]
                    if _RICHNESS[got] > _RICHNESS[have]:
                        upgraded = True
                        if got == "full" and best[nid]["_served"]:
                            # full reads strictly: it carries the file itself, not its served view
                            full, backed_full = _content_of(graph, nid, root, shared)
                            upgraded = full is not None
                            if upgraded:
                                best[nid].update(text=full, digest=sha256_text(full))
                                best[nid]["_content"], best[nid]["_served"] = backed_full, False
                        if upgraded:
                            best[nid].update(detail=got, max_chars=rule["max_chars"])
                    elif got == have:
                        best[nid]["max_chars"] = max(best[nid]["max_chars"], rule["max_chars"])
                    if (dist, -score) < (best[nid]["distance"], -best[nid]["score"]):
                        best[nid].update(distance=dist, score=round(score, 6), via=via)
                        best[nid]["from"] = parent
                    taken += 1
                continue
            if reason is None and taken >= rule["budget"]:
                reason = f"over budget: rule {ri} includes at most {rule['budget']} nodes"
            text = None
            backed = True
            if reason is None:
                text, backed = _content_of(
                    graph, nid, root, shared, served=rule.get("detail", "full") != "full"
                )
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
                "detail": rule.get("detail", "full"),
                "_content": backed,
                "_served": rule.get("detail", "full") != "full",
            }

    order = sorted(best.values(), key=lambda i: (i["distance"], -i["score"], i["id"]))
    included = []
    for rank, item in enumerate(order, 1):
        excluded.pop(item["id"], None)  # another rule included it
        entry = {**item, "rank": rank, "section": _section_name(rank, item["id"])}
        backed = entry.pop("_content")
        entry.pop("_served")
        if entry["detail"] == "full":
            del entry["detail"]  # absent means full: such a pack is unchanged
            entry["text"] = _header(entry) + item["text"]
        else:
            entry.update(summary_source="none", content_chars=len(item["text"]))
            _, source = _leveled(graph, item["id"], item["text"], backed, "summary")
            entry["summary_source"] = source
            header = _header(entry)
            body, _ = _leveled(
                graph, item["id"], item["text"], backed, entry["detail"],
                room=entry["max_chars"] - len(header),
            )  # fmt: skip
            entry["text"] = header + body
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
        + (
            f"detail: {item['detail']} (summary source: {item['summary_source']}; "
            f"{item['content_chars']} characters in full)\n"
            if "detail" in item
            else ""
        )
        + "---\n"
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
            f"  detail: {i.get('detail', 'full')}"
        )
    lines.append(f"excluded ({len(selection.excluded)}):")
    for e in selection.excluded:
        lines.append(f"  {e['id']}  rule {e['rule']}: {e['reason']}")
    return "\n".join(lines) + "\n"
