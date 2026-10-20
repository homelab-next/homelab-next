# SPDX-License-Identifier: Apache-2.0
"""Validation of a strategy tree: schemas, link rules, lifecycle, reviews and the doctrine.

Link rules (fixed; the model's shape, not a policy):

* an SO has no parent; an OO's parent is an SO, a TO's an OO, a TT's a TO (:data:`PARENT_LEVEL`);
* every requirement (CCIR, FFIR, PIR) ``supports`` one or more SO, OO or TO;
* ``serves``: a CCIR serves nothing, an FFIR serves CCIRs, a PIR serves CCIRs or FFIRs
  (:data:`SERVES`), and the serves graph has no cycle;
* a measure names its ``objective`` and that objective lists it under ``measures`` (both ways);
* an RFI is ``raised_by`` a measure or a requirement;
* every link names a record that exists (a tombstoned id is reported as retired), and an active
  record never links to a closed one through ``parent`` or ``supports``.

The doctrine rules (:mod:`.doctrine`) that can be decided from the records run here too; those
that grade readings run in :mod:`.measure`.  :func:`validate` collects everything at once.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .doctrine import Doctrine, load_doctrine
from .records import ARTEFACT, Tree, definition_digest, dir_for, record_digest

__all__ = [
    "CLOSED",
    "INITIAL",
    "LIFECYCLE",
    "PARENT_LEVEL",
    "SERVES",
    "Report",
    "find_cycle",
    "schema_problems",
    "self_measured",
    "validate",
]

PARENT_LEVEL = {"SO": None, "OO": "SO", "TO": "OO", "TT": "TO"}
SUPPORTABLE = ("SO", "OO", "TO")
SERVES: dict[str, tuple[str, ...]] = {"CCIR": (), "FFIR": ("CCIR",), "PIR": ("CCIR", "FFIR")}
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


def _prefix(ident: Any) -> str:
    return str(ident).rsplit("-", 1)[0]


def _active(entry: Mapping[str, Any] | None) -> bool:
    return entry is not None and entry.get("status") not in CLOSED


def self_measured(measure: Mapping[str, Any], tree: Tree) -> bool:
    """Measured manually, not at all, or by the owner of the objective it measures."""
    if measure.get("source") in ("manual", "none"):
        return True
    obj = tree.get(str(measure.get("objective"))) or {}
    return bool(measure.get("measured_by")) and measure.get("measured_by") == obj.get("owner")


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
        rep.errors += schema_problems(_SCHEMA[kind], entry, key)
        _lifecycle(kind, key, entry, rep)
        _reviews(kind, key, entry, policy or None, rep, require_reviews)
    _objectives(tree, rep)
    _measures(tree, rep, invariant_ids, status_ids)
    _requirements(tree, rep)
    for key, r in tree.of("rfis").items():
        _ref(tree, key, "raised_by", r.get("raised_by"), ("MOP", "MOE", "CCIR", "FFIR", "PIR"), rep)
    _doctrine(tree, doctrine, rep)
    return rep


def _lifecycle(kind: str, key: str, e: Mapping[str, Any], rep: Report) -> None:
    status = e.get("status")
    if status in CLOSED and not e.get("resolution"):
        rep.errors.append(
            f"{key}: status {status} is reached by a transition (file a strategy-transition "
            "intent; the decider records its resolution), never by editing `status`"
        )
    if status not in CLOSED and "resolution" in e:
        rep.errors.append(f"{key}: `resolution` belongs to a closed record only")


def _reviews(kind, key, e, policy, rep: Report, require: bool) -> None:
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
        who=key,
    )
    rep.errors += res.problems
    if res.missing and require:
        rep.errors.append(missing_message(key, state, res, digest))


def _ref(tree: Tree, who: str, field: str, ident, allowed: Iterable[str], rep: Report):
    """The record ``ident`` names, if it exists and has an allowed prefix (else a problem)."""
    if ident is None:
        return None
    if _prefix(ident) not in allowed:
        rep.errors.append(f"{who}: {field} {ident} must be one of {', '.join(allowed)}")
        return None
    target = tree.get(str(ident))
    if target is None:
        why = "is a retired id" if str(ident) in tree.retired else "does not exist"
        rep.errors.append(f"{who}: {field} {ident} {why}")
    return target


def _objectives(tree: Tree, rep: Report) -> None:
    for key, o in tree.of("objectives").items():
        level = o.get("level")
        if level != _prefix(o.get("id")):
            rep.errors.append(f"{key}: level {level} disagrees with its id prefix")
            continue
        want = PARENT_LEVEL.get(str(level))
        parent = o.get("parent")
        if want is None:
            if parent:
                rep.errors.append(f"{key}: an SO has no parent (it hangs from the strategy)")
            continue
        if not parent:
            rep.errors.append(f"{key}: a {level}'s parent is an {want}; none is named")
            continue
        p = _ref(tree, key, "parent", parent, (want,), rep)
        if p is not None and _active(o) and not _active(p):
            rep.errors.append(f"{key}: parent {parent} is {p.get('status')}")
    parents = {k: [str(o["parent"])] for k, o in tree.of("objectives").items() if o.get("parent")}
    if cyc := find_cycle(parents):
        rep.errors.append(f"objectives: parent cycle {' -> '.join(cyc)}")


def _measures(tree: Tree, rep: Report, inv: set[str] | None, stat: set[str] | None) -> None:
    for key, o in tree.of("objectives").items():
        for m in o.get("measures") or ():
            target = _ref(tree, key, "measures", m, ("MOP", "MOE"), rep)
            if target is not None and target.get("objective") != o.get("id"):
                rep.errors.append(
                    f"{key}: lists {m}, which measures {target.get('objective')} (both name it)"
                )
    for key, m in tree.of("measures").items():
        obj = _ref(tree, key, "objective", m.get("objective"), tuple(PARENT_LEVEL), rep)
        if obj is not None and m.get("id") not in (obj.get("measures") or ()):
            rep.errors.append(f"{key}: {m.get('objective')} does not list it under measures")
        src = str(m.get("source") or "")
        kind, _, name = src.partition(":")
        if kind == "invariant" and inv is not None and name not in inv:
            rep.errors.append(f"{key}: source {src}: no such invariant")
        if kind == "status" and stat is not None and name.split("/", 1)[0] not in stat:
            rep.errors.append(f"{key}: source {src}: no such registered status source")


def _requirements(tree: Tree, rep: Report) -> None:
    serves: dict[str, list[str]] = {}
    for key, r in tree.of("requirements").items():
        rtype = _prefix(r.get("id"))
        for s in r.get("supports") or ():
            o = _ref(tree, key, "supports", s, SUPPORTABLE, rep)
            if o is not None and _active(r) and not _active(o):
                rep.errors.append(f"{key}: supports {s}, which is {o.get('status')}")
        allowed = SERVES.get(rtype, ())
        for s in r.get("serves") or ():
            serves.setdefault(key, []).append(str(s))
            if _prefix(s) not in allowed:
                what = ", ".join(allowed) if allowed else "nothing"
                rep.errors.append(f"{key}: a {rtype} serves {what}, not {s}")
            elif tree.get(str(s)) is None:
                rep.errors.append(f"{key}: serves {s}, which does not exist")
    if cyc := find_cycle(serves):
        rep.errors.append(f"requirements: serves cycle {' -> '.join(cyc)}")


def _doctrine(tree: Tree, d: Doctrine, rep: Report) -> None:
    objectives, measures = tree.of("objectives"), tree.of("measures")
    reqs = tree.of("requirements")
    active_m = {k: m for k, m in measures.items() if _active(m)}
    if d.on("activity_never_moe"):
        kinds = set(d.opt("activity_never_moe", "kinds"))
        for k, m in active_m.items():
            if _prefix(m.get("id")) == "MOE" and m.get("kind") in kinds:
                rep.add(
                    d.level("activity_never_moe"),
                    f"{k}: an activity count is never a MOE (kind {m.get('kind')}; make it a MOP)",
                )
    if d.on("moe_per_objective"):
        need, levels = d.opt("moe_per_objective", "min"), d.opt("moe_per_objective", "levels")
        for k, o in objectives.items():
            if not _active(o) or o.get("level") not in levels:
                continue
            moes = [
                m
                for m in o.get("measures") or ()
                if _prefix(m) == "MOE" and _active(measures.get(str(m)))
            ]
            if len(moes) < need:
                rep.add(
                    d.level("moe_per_objective"),
                    f"{k}: {len(moes)} active MOE(s); the doctrine wants at least {need} per "
                    "objective (is it working?, not only are we doing it?)",
                )
    if d.on("measures_per_owner"):
        cap, by_owner = d.opt("measures_per_owner", "max"), {}
        for k, m in active_m.items():
            owner = (tree.get(str(m.get("objective"))) or {}).get("owner")
            by_owner.setdefault(owner, []).append(k)
        for owner, ms in sorted(by_owner.items(), key=lambda kv: str(kv[0])):
            if len(ms) > cap:
                rep.add(d.level("measures_per_owner"), f"{owner}: {len(ms)} measures > {cap}")
    for k, m in measures.items():
        if m.get("source") == "none":
            if d.on("not_measurable_is_finding") and not m.get("not_measurable"):
                rep.add(
                    d.level("not_measurable_is_finding"),
                    f"{k}: source none needs a `## Not measurable` section: not measurable is "
                    "a finding (why, and what would make it measurable), never a blank",
                )
            if d.on("never_fabricate") and any("value" in v for v in m.get("values") or ()):
                rep.add(
                    d.level("never_fabricate"),
                    f"{k}: a measure that is not measurable has no values",
                )
        if d.on("no_silent_redefinition"):
            _redefinition(k, m, d, rep)
    if d.on("baseline_so"):
        _baseline_so(tree, reqs, objectives, d, rep)
    if d.on("so_supported"):
        supported = {s for r in reqs.values() if _active(r) for s in r.get("supports") or ()}
        for k, o in objectives.items():
            if o.get("level") == "SO" and _active(o) and o.get("id") not in supported:
                rep.add(d.level("so_supported"), f"{k}: no active requirement supports this SO")


def _redefinition(key: str, m: Mapping[str, Any], d: Doctrine, rep: Report) -> None:
    """A definition_version names one definition: two digests under one version, or the
    current definition under a version a reading took with another digest, is a silent edit."""
    seen: dict[Any, str] = {}
    for v in m.get("values") or ():
        ver, dig = v.get("definition_version"), v.get("definition_digest")
        if seen.setdefault(ver, dig) != dig:
            rep.add(
                d.level("no_silent_redefinition"),
                f"{key}: readings under definition_version {ver} have two definitions",
            )
    cur = seen.get(m.get("definition_version"))
    if cur is not None and cur != definition_digest(m):
        rep.add(
            d.level("no_silent_redefinition"),
            f"{key}: definition, source or unit changed under definition_version "
            f"{m.get('definition_version')}; bump definition_version (a redefinition is never "
            "silent, and the next reading starts a new baseline)",
        )


def _baseline_so(tree, reqs, objectives, d: Doctrine, rep: Report) -> None:
    types, exactly = set(d.opt("baseline_so", "types")), d.opt("baseline_so", "exactly")
    owner: dict[str, str] = {}
    for k, r in reqs.items():
        if not _active(r) or _prefix(r.get("id")) not in types:
            continue
        sos = [
            s
            for s in r.get("supports") or ()
            if _prefix(s) == "SO" and not (objectives.get(str(s)) or {}).get("supplemental")
        ]
        if len(sos) != exactly:
            rep.add(
                d.level("baseline_so"),
                f"{k}: supports {len(sos)} baseline SO(s); the doctrine wants exactly {exactly} "
                "(mark an additional one `supplemental: true`)",
            )
        for s in sos:
            if s in owner and owner[s] != k:
                rep.add(
                    d.level("baseline_so"),
                    f"{k}: {s} is already the baseline SO of {owner[s]}; one SO per requirement, "
                    "or their measures cannot roll up apart",
                )
            owner.setdefault(s, k)


def binding_kind(source: str) -> str:
    return str(source).partition(":")[0]


def initial_of(ident: str) -> str | None:
    kind = dir_for(ident)
    return INITIAL.get(kind) if kind else None
