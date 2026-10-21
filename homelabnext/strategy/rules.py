# SPDX-License-Identifier: Apache-2.0
"""Validation of a strategy tree: identity, schemas, link rules, lifecycle, reviews, doctrine.

Identity (fatal; ADR-0019): every record carries a canonical ``uid`` (a UUIDv7), unique in the
tree (the strategy record's included), and a ``type`` its directory holds; siblings (same type,
same parent) never share an ``order``.  A legacy numbered reference (``SO-001``) is reported as
such: ``hnx records assign-uids`` migrates it.

Link rules (the doctrine's ``hierarchy`` and ``links``, :mod:`.doctrine`; the defaults are the
shipped model):

* ``parent``: a record's parent is a record of one of its type's parent types (an OO's an SO, a
  TO's an OO, a TT's a TO, a MOP's or MOE's an objective, a PIR's optionally a PIR); a type with
  none takes no parent (an SO hangs from the strategy); the parent graph has no cycle;
* ``supports``: every requirement supports one or more SO, OO or TO;
* ``serves``: a CCIR serves nothing, an FFIR serves CCIRs, a PIR serves CCIRs or FFIRs, and the
  serves graph has no cycle;
* ``raised_by``: an RFI is raised by a measure or a requirement;
* every link names a record that exists (by uid), and an active record never links to a closed
  one through ``parent`` or ``supports``.

The doctrine rules (:mod:`.doctrine`) that can be decided from the records run here too; those
that grade readings run in :mod:`.measure`.  :func:`validate` collects everything at once.
Problems name a record by its computed display number and its uid (``OO 1.2 <uid>``).
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from homelabnext.identity import node_of, order_problems
from homelabnext.identity.types import LEGACY_CODE_RE
from homelabnext.identity.uid import is_uid

from .doctrine import Doctrine, load_doctrine
from .records import ARTEFACT, DIRS, TYPE_DIR, Tree, definition_digest, record_digest

__all__ = [
    "CLOSED",
    "INITIAL",
    "LIFECYCLE",
    "Report",
    "find_cycle",
    "schema_problems",
    "self_measured",
    "validate",
]

#: directory -> {status: statuses a transition may reach from it}
LIFECYCLE: dict[str, dict[str, tuple[str, ...]]] = {
    "objectives": {"active": ("achieved", "retired")},
    "measures": {"active": ("retired",)},
    "requirements": {"active": ("answered", "expired", "retired")},
    "rfis": {"open": ("answered", "expired", "no-find")},
}
INITIAL = {kind: next(iter(states)) for kind, states in LIFECYCLE.items()}
CLOSED = frozenset(s for states in LIFECYCLE.values() for t in states.values() for s in t)
_SCHEMA = {"strategy": "strategy", **{k: v for k, v in ARTEFACT.items() if k != "strategy"}}
OBJECTIVE_TYPES = ("SO", "OO", "TO", "TT")


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, level: str, message: str) -> None:
        if level == "error":
            self.errors.append(message)
        elif level == "warn":
            self.warnings.append(message)


def _validator(name: str):
    from homelabnext.registers.events import schema_validator

    return schema_validator("strategy", f"{name}.schema.json")


def schema_problems(name: str, data: Any, who: str) -> list[str]:
    """Every problem of ``data`` against ``schemas/strategy/<name>.schema.json``."""
    from homelabnext.registers.events import _iso

    plain = json.loads(json.dumps(data, default=_iso))
    errs = sorted(_validator(name).iter_errors(plain), key=lambda e: [str(p) for p in e.path])
    return [f"{who}: {'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}" for e in errs]


def find_cycle(graph: Mapping[str, Iterable[str]]) -> list[str] | None:
    """One cycle of a directed graph as ``[a, b, ..., a]``, or None (iterative DFS)."""
    state: dict[str, int] = {}
    for start in sorted(graph):
        if state.get(start):
            continue
        stack: list[tuple[str, list[str]]] = [(start, sorted(graph.get(start, ())))]
        path = [start]
        state[start] = 1
        while stack:
            node, todo = stack[-1]
            if not todo:
                state[node] = 2
                stack.pop()
                path.pop()
                continue
            nxt = todo.pop(0)
            if state.get(nxt) == 1:
                return [*path[path.index(nxt) :], nxt]
            if not state.get(nxt):
                state[nxt] = 1
                path.append(nxt)
                stack.append((nxt, sorted(graph.get(nxt, ()))))
    return None


def _active(entry: Mapping[str, Any] | None) -> bool:
    return entry is not None and entry.get("status") not in CLOSED


def self_measured(measure: Mapping[str, Any], tree: Tree) -> bool:
    """Measured manually, not at all, or by the owner of the objective it measures."""
    if measure.get("source") in ("manual", "none"):
        return True
    obj = tree.get(str(measure.get("parent"))) or {}
    return bool(measure.get("measured_by")) and measure.get("measured_by") == obj.get("owner")


def measures_of(tree: Tree, uid: str, rtype: str | None = None) -> list[str]:
    """The measures whose parent is the objective ``uid`` (of ``rtype`` only, if given), in
    display-number order."""
    return tree.children(uid, (rtype,) if rtype else ("MOP", "MOE"))


def _sibling(root: pathlib.Path, *names: str) -> pathlib.Path | None:
    for d in (root, root.parent):
        for n in names:
            if (d / n).is_file():
                return d / n
    return None


def _catalogs(root: pathlib.Path) -> tuple[set[str] | None, set[str] | None]:
    """Invariant ids and status source ids the bindings may name: ``invariants.yml`` (or
    ``registers/invariants.yml``) and ``services.yml`` in or beside the root; None when absent."""
    inv = stat = None
    p = _sibling(root, "invariants.yml", "registers/invariants.yml")
    if p:
        from homelabnext.registers import load_register

        inv = {str(c.get("id")) for c in load_register(p, "invariants").get("criteria") or ()}
    p = _sibling(root, "services.yml")
    if p:
        from homelabnext.registry.model import load
        from homelabnext.status.model import sources_from_registry

        stat = {s.id for s in sources_from_registry(load(p))}
    return inv, stat


def _policy(root: pathlib.Path):
    from homelabnext.registers.render import find_policy
    from homelabnext.reviews import ReviewError, load_policy

    pp = find_policy(root)
    try:
        return load_policy(pp) if pp else None
    except ReviewError as ex:
        from homelabnext.registers.schema import RegisterError

        raise RegisterError("review policy", ex.problems) from None


def validate(
    tree: Tree,
    *,
    doctrine: Doctrine | None = None,
    policy: Any = None,
    invariant_ids: set[str] | None = None,
    status_ids: set[str] | None = None,
    require_reviews: bool = True,
) -> Report:
    """Every problem of the tree.  ``policy`` (a review policy, ``False`` for none) and the
    binding catalogs default to the files in or beside the root, like the registers' build."""
    rep = Report()
    doctrine = doctrine or load_doctrine(tree.root)
    if policy is None:
        policy = _policy(tree.root)
    if invariant_ids is None and status_ids is None:
        invariant_ids, status_ids = _catalogs(tree.root)
    if tree.strategy is None:
        rep.errors.append(f"{tree.root}: no strategy.md (the one strategy record)")
    for kind, key, entry in tree.items():
        who = _who(tree, key)
        rep.errors += schema_problems(_SCHEMA[kind], entry, who)
        _identity(kind, who, entry, rep)
        _lifecycle(kind, who, entry, rep)
        _reviews(kind, who, entry, policy or None, rep, require_reviews)
    nodes = [node_of(e) for k in DIRS for e in tree.of(k).values() if is_uid(e.get("uid"))]
    rep.errors += order_problems(nodes, {u: _who(tree, u) for u in tree.labels})
    _parents(tree, doctrine, rep)
    _measures(tree, rep, invariant_ids, status_ids)
    _links(tree, doctrine, rep)
    _doctrine(tree, doctrine, rep)
    return rep


def _a(rtype: str) -> str:
    """The article a type takes when read aloud (an SO, an OO, an FFIR, an RFI; a TO, a MOE)."""
    return f"an {rtype}" if rtype in ("SO", "OO", "FFIR", "RFI") else f"a {rtype}"


def _who(tree: Tree, key: str) -> str:
    """How a problem names a record: ``OO 1.2 <uid>`` (``strategy`` for the strategy)."""
    return key if key == "strategy" or key not in tree.labels else f"{tree.label(key)} {key}"


def _identity(kind: str, who: str, e: Mapping[str, Any], rep: Report) -> None:
    """The record's type belongs in its directory (the schema checks the uid's form)."""
    if kind == "strategy":
        return
    rtype = str(e.get("type"))
    if rtype in TYPE_DIR and TYPE_DIR[rtype] != kind:
        rep.errors.append(f"{who}: {_a(rtype)} lives in {TYPE_DIR[rtype]}/, not {kind}/")


def _lifecycle(kind: str, who: str, e: Mapping[str, Any], rep: Report) -> None:
    status = e.get("status")
    if status in CLOSED and not e.get("resolution"):
        rep.errors.append(
            f"{who}: status {status} is reached by a transition (file a strategy-transition "
            "intent; the decider records its resolution), never by editing `status`"
        )
    if status not in CLOSED and "resolution" in e:
        rep.errors.append(f"{who}: `resolution` belongs to a closed record only")


def _reviews(kind, who, e, policy, rep: Report, require: bool) -> None:
    from homelabnext.reviews import evaluate, missing_message

    digest = record_digest(e)
    state = str(e.get("status"))
    res = evaluate(
        e.get("reviews"),
        author=e.get("author"),
        digest=digest,
        artefact=ARTEFACT[kind],
        state=state,
        policy=policy,
        who=who,
    )
    rep.errors += res.problems
    if res.missing and require:
        rep.errors.append(missing_message(who, state, res, digest))


def _ref(tree: Tree, who: str, field_: str, ref, allowed: Iterable[str], rep: Report, rtype=""):
    """The record ``ref`` (a uid) names, if it exists and is of an allowed type (else a
    problem)."""
    if ref is None:
        return None
    ref, allowed = str(ref), tuple(allowed)
    if not is_uid(ref):
        legacy = LEGACY_CODE_RE.fullmatch(ref)
        why = (
            "is a legacy numbered code; records link by uid (`hnx records assign-uids`)"
            if legacy
            else "is not a uid"
        )
        rep.errors.append(f"{who}: {field_} {ref} {why}")
        return None
    target = tree.get(ref)
    if target is None:
        rep.errors.append(f"{who}: {field_} {ref} does not exist")
        return None
    if target.get("type") not in allowed:
        what = ", ".join(allowed) if allowed else "nothing"
        rep.errors.append(
            f"{who}: {field_} {tree.label(ref)} {ref} is {_a(str(target.get('type')))}; "
            f"{_a(rtype)} names {what} as its {field_}"
        )
        return None
    return target


def _parents(tree: Tree, d: Doctrine, rep: Report) -> None:
    """Every record's parent per the doctrine's hierarchy, and no parent cycle."""
    graph: dict[str, list[str]] = {}
    for kind in DIRS:
        for key, e in tree.of(kind).items():
            who, rtype, parent = _who(tree, key), str(e.get("type")), e.get("parent")
            want = d.parents(rtype)
            if not want:
                if parent:
                    rep.errors.append(f"{who}: {_a(rtype)} has no parent (a top-level record)")
                continue
            if not parent:
                if not d.parent_optional(rtype):
                    rep.errors.append(
                        f"{who}: {_a(rtype)}'s parent is {' or '.join(map(_a, want))}; none is named"
                    )
                continue
            graph[key] = [str(parent)]
            p = _ref(tree, who, "parent", parent, want, rep, rtype)
            if p is not None and _active(e) and not _active(p):
                rep.errors.append(f"{who}: parent {tree.label(str(parent))} is {p.get('status')}")
    if cyc := find_cycle(graph):
        rep.errors.append(f"parent cycle {' -> '.join(tree.label(c) for c in cyc)}")


def _measures(tree: Tree, rep: Report, inv: set[str] | None, stat: set[str] | None) -> None:
    for key, m in tree.of("measures").items():
        src = str(m.get("source") or "")
        kind, _, name = src.partition(":")
        if kind == "invariant" and inv is not None and name not in inv:
            rep.errors.append(f"{_who(tree, key)}: source {src}: no such invariant")
        if kind == "status" and stat is not None and name.split("/", 1)[0] not in stat:
            rep.errors.append(f"{_who(tree, key)}: source {src}: no such registered status source")


def _links(tree: Tree, d: Doctrine, rep: Report) -> None:
    """``supports``, ``serves`` and ``raised_by`` per the doctrine's link table."""
    serves: dict[str, list[str]] = {}
    for kind in DIRS:
        for key, e in tree.of(kind).items():
            who, rtype = _who(tree, key), str(e.get("type"))
            for field_ in ("supports", "serves", "raised_by"):
                v = e.get(field_)
                refs = [v] if isinstance(v, str) else list(v or ())
                if not refs:
                    continue
                allowed = d.link_targets(field_, rtype)
                if allowed is None:
                    rep.errors.append(f"{who}: {_a(rtype)} carries no `{field_}`")
                    continue
                for r in refs:
                    o = _ref(tree, who, field_, r, allowed, rep, rtype)
                    if field_ == "supports" and o is not None and _active(e) and not _active(o):
                        rep.errors.append(
                            f"{who}: supports {tree.label(str(r))}, which is {o.get('status')}"
                        )
                    if field_ == "serves":
                        serves.setdefault(key, []).append(str(r))
    if cyc := find_cycle(serves):
        rep.errors.append(f"requirements: serves cycle {' -> '.join(tree.label(c) for c in cyc)}")


def _doctrine(tree: Tree, d: Doctrine, rep: Report) -> None:
    objectives, measures = tree.of("objectives"), tree.of("measures")
    reqs = tree.of("requirements")
    active_m = {k: m for k, m in measures.items() if _active(m)}
    if d.on("activity_never_moe"):
        kinds = set(d.opt("activity_never_moe", "kinds"))
        for k, m in active_m.items():
            if m.get("type") == "MOE" and m.get("kind") in kinds:
                rep.add(
                    d.level("activity_never_moe"),
                    f"{_who(tree, k)}: an activity count is never a MOE (kind {m.get('kind')}; "
                    "make it a MOP)",
                )
    if d.on("moe_per_objective"):
        need, levels = d.opt("moe_per_objective", "min"), d.opt("moe_per_objective", "levels")
        for k, o in objectives.items():
            if not _active(o) or o.get("type") not in levels:
                continue
            moes = [m for m in measures_of(tree, k, "MOE") if _active(measures.get(m))]
            if len(moes) < need:
                rep.add(
                    d.level("moe_per_objective"),
                    f"{_who(tree, k)}: {len(moes)} active MOE(s); the doctrine wants at least "
                    f"{need} per objective (is it working?, not only are we doing it?)",
                )
    if d.on("measures_per_owner"):
        cap, by_owner = d.opt("measures_per_owner", "max"), {}
        for k, m in active_m.items():
            owner = (tree.get(str(m.get("parent"))) or {}).get("owner")
            by_owner.setdefault(owner, []).append(k)
        for owner, ms in sorted(by_owner.items(), key=lambda kv: str(kv[0])):
            if len(ms) > cap:
                rep.add(d.level("measures_per_owner"), f"{owner}: {len(ms)} measures > {cap}")
    for k, m in measures.items():
        who = _who(tree, k)
        if m.get("source") == "none":
            if d.on("not_measurable_is_finding") and not m.get("not_measurable"):
                rep.add(
                    d.level("not_measurable_is_finding"),
                    f"{who}: source none needs a `## Not measurable` section: not measurable is "
                    "a finding (why, and what would make it measurable), never a blank",
                )
            if d.on("never_fabricate") and any("value" in v for v in m.get("values") or ()):
                rep.add(
                    d.level("never_fabricate"),
                    f"{who}: a measure that is not measurable has no values",
                )
        if d.on("no_silent_redefinition"):
            _redefinition(who, m, d, rep)
    if d.on("baseline_so"):
        _baseline_so(tree, reqs, objectives, d, rep)
    if d.on("so_supported"):
        supported = {s for r in reqs.values() if _active(r) for s in r.get("supports") or ()}
        for k, o in objectives.items():
            if o.get("type") == "SO" and _active(o) and k not in supported:
                rep.add(
                    d.level("so_supported"),
                    f"{_who(tree, k)}: no active requirement supports this SO",
                )


def _redefinition(who: str, m: Mapping[str, Any], d: Doctrine, rep: Report) -> None:
    """A definition_version names one definition: two digests under one version, or the
    current definition under a version a reading took with another digest, is a silent edit."""
    seen: dict[Any, str] = {}
    for v in m.get("values") or ():
        ver, dig = v.get("definition_version"), v.get("definition_digest")
        if seen.setdefault(ver, dig) != dig:
            rep.add(
                d.level("no_silent_redefinition"),
                f"{who}: readings under definition_version {ver} have two definitions",
            )
    cur = seen.get(m.get("definition_version"))
    if cur is not None and cur != definition_digest(m):
        rep.add(
            d.level("no_silent_redefinition"),
            f"{who}: definition, source or unit changed under definition_version "
            f"{m.get('definition_version')}; bump definition_version (a redefinition is never "
            "silent, and the next reading starts a new baseline)",
        )


def _baseline_so(tree, reqs, objectives, d: Doctrine, rep: Report) -> None:
    types, exactly = set(d.opt("baseline_so", "types")), d.opt("baseline_so", "exactly")
    owner: dict[str, str] = {}
    for k in tree.ordered("requirements"):
        r = reqs[k]
        if not _active(r) or r.get("type") not in types:
            continue
        sos = [
            s
            for s in r.get("supports") or ()
            if (objectives.get(str(s)) or {}).get("type") == "SO"
            and not (objectives.get(str(s)) or {}).get("supplemental")
        ]
        if len(sos) != exactly:
            rep.add(
                d.level("baseline_so"),
                f"{_who(tree, k)}: supports {len(sos)} baseline SO(s); the doctrine wants exactly "
                f"{exactly} (mark an additional one `supplemental: true`)",
            )
        for s in sos:
            if s in owner and owner[s] != k:
                rep.add(
                    d.level("baseline_so"),
                    f"{_who(tree, k)}: {tree.label(s)} is already the baseline SO of "
                    f"{tree.label(owner[s])}; one SO per requirement, or their measures cannot "
                    "roll up apart",
                )
            owner.setdefault(s, k)
