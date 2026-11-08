# SPDX-License-Identifier: Apache-2.0
"""``hnx registry bindings``: consumers bind only to a primary (ADR-0039 decision 3).

A *binding* is a reference that makes a consumer call a service.  This check reads a registry and
the files that bind to it, and refuses each binding that would reach a row other than its
capability's primary:

* a row's ``upstreams`` (by capability): the registry's own rule since service registry 2.9
  (:func:`homelabnext.registry.model.upstream_problems`, which loading a registry already runs),
  applied here to every tier;
* a model-role binding's ``backend: svc:<name>`` (``model_roles.json``);
* a workflow pack step's ``target: svc:<name>`` and every other ``svc:`` id in a pack or its
  fixtures, event sources included (``workflows/packs/*.yml``);
* a module's ``requires`` resolved through the site selection: the provider a site selects for a
  required capability must be its primary's product, never a non-primary row's.

A ``svc:`` id may name a row or a capability; a capability name means its primary.  An id that
names a non-primary row, or a capability whose rows are all non-primary, is refused.  In a pack,
an id that names no registry row, no capability and no :data:`PLATFORM_SOURCES` entry is refused
too; a capability the platform knows (:func:`homelabnext.capability_names.platform_capabilities`)
that this registry does not place is a note, not a problem, because a pack is platform content and
a site that places none of a capability deploys no pack against it.

Two exceptions are declared here (:data:`EXCEPTIONS`), never inferred from a file name or a call
path: the evaluation report's ``canary`` bindings may name an ``eval`` row, and a conformance
target file may name any non-legacy row.

Not bindings, so not read: status sources, the census, ``hnx decommission`` and the ledger read
every tier (watching a row is not depending on it), and an agent lane (``real``/``shadow``) names
an executor, not a registry row.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext.capability_names import platform_capabilities

from .model import STANDINGS, Registry, upstream_problems

__all__ = [
    "EXCEPTIONS",
    "PLATFORM_SOURCES",
    "Declared",
    "Report",
    "canary_problems",
    "check",
    "pack_problems",
    "requires_problems",
    "role_problems",
    "row_upstream_problems",
    "target_problems",
]

SVC_ID = re.compile(r"svc:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\Z")


@dataclass(frozen=True)
class Declared:
    """A name or an exception this check accepts by declaration, with the reason."""

    name: str
    why: str


#: ``svc:`` ids a pack may name that are no registry row and no capability.  Each entry leaves
#: with the change that ends its reason.
PLATFORM_SOURCES: tuple[Declared, ...] = (
    Declared(
        "broker",
        "the action broker: part of the platform, not a capability a site places (ADR-0039 "
        "decision 3); its records-inbox lane is the producer of proposal events",
    ),
    Declared(
        "llm-orchestrator",
        "the controller's old event source, kept for the length of its one-release overlap "
        "(ADR-0026 amendment, decision 16); removed by the change that drops that source at "
        "cutover+1",
    ),
)

#: the two exceptions to "a binding names a primary" (ADR-0039 decision 3)
EXCEPTIONS: tuple[Declared, ...] = (
    Declared(
        "canary",
        "the evaluation report's canary bindings (model_roles.eval.json) may name an eval row: "
        "the egress canary vets a candidate before its switch, and the swap gate reads that "
        "report from the base commit",
    ),
    Declared(
        "conformance-target",
        "a conformance target file may name any non-legacy row: a candidate, or a former "
        "primary in its rollback window, is proven by its row name",
    ),
)
_PLATFORM = {d.name for d in PLATFORM_SOURCES}


@dataclass
class Report:
    """What the check found: ``problems`` fail it, ``notes`` are printed and do not."""

    problems: list[str]
    notes: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems


def _article(word: str) -> str:
    return ("an " if word[:1] in "aeiou" else "a ") + word


def _judge(registry: Registry, name: str, allowed: tuple[str, ...]) -> str | None:
    """Why ``svc:<name>`` may not be bound to, or None when it may (a primary row, a capability
    with a primary, or a row of an ``allowed`` tier).  ``"unknown"`` when it names neither a row
    nor a capability of the registry."""
    if registry.by_capability(name) is not None:
        return None  # a capability name means its primary
    row = registry.row(name, *STANDINGS)
    if row is not None:
        if row.is_primary or row.standing in allowed:
            return None
        return f"names {_article(row.standing)} row (a binding reaches only a primary)"
    rows = [s for s in registry.rows(*STANDINGS) if s.capability == name]
    if rows:
        tiers = ", ".join(f"{s.name} ({s.standing})" for s in rows)
        return f"names capability {name}, which has no primary (its rows: {tiers})"
    return "unknown"


def row_upstream_problems(registry: Registry) -> list[str]:
    """The registry's upstream rule over every tier of a loaded registry: an upstream names a
    capability with a primary."""
    docs = {
        s.name: {
            "capability": s.capability,
            "upstreams": list(s.upstreams),
            "standing": {"tier": s.standing},
        }
        for s in registry.rows(*STANDINGS)
    }
    return upstream_problems(docs)


def _backend_problem(registry: Registry, where: str, backend: str, allowed: tuple[str, ...]):
    m = SVC_ID.match(backend if backend.startswith("svc:") else f"svc:{backend}")
    if m is None:
        return f"{where}: backend {backend!r} is not a svc: id"
    why = _judge(registry, m.group(1), allowed)
    if why is None:
        return None
    if why == "unknown":
        why = "names no registry row or capability"
    return f"{where}: svc:{m.group(1)} {why}"


def role_problems(registry: Registry, table: Any, where: str = "model_roles") -> list[str]:
    """Every binding of a role table (:class:`~homelabnext.registry.models.RoleTable`) names a
    primary row or a capability with a primary."""
    out = []
    for rname, role in sorted(table.roles.items()):
        for i, b in enumerate(role.bindings):
            p = _backend_problem(registry, f"{where}: mdl:{rname} bindings[{i}]", b.backend, ())
            if p:
                out.append(p)
    return out


def canary_problems(registry: Registry, report: Any, where: str = "model_roles.eval") -> list[str]:
    """The evaluation report's ``canary`` bindings: each names a primary or an ``eval`` row (the
    declared ``canary`` exception), never a retiring or legacy one."""
    canary = report.get("canary") if isinstance(report, Mapping) else None
    if canary is None:
        return []
    if not isinstance(canary, Mapping):
        return [f"{where}: canary is not a mapping of role to entry"]
    out = []
    for rname in sorted(canary, key=str):
        entry = canary[rname]
        bindings = entry.get("bindings") if isinstance(entry, Mapping) else None
        if not isinstance(bindings, list):
            out.append(f"{where}: canary.{rname}: bindings is not a list")
            continue
        for i, b in enumerate(bindings):
            backend = b.get("backend") if isinstance(b, Mapping) else None
            at = f"{where}: canary.{rname}.bindings[{i}]"
            if not isinstance(backend, str):
                out.append(f"{at}: no backend")
                continue
            p = _backend_problem(registry, at, backend, ("eval",))
            if p:
                out.append(p)
    return out


def _svc_ids(doc: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """``(where, name)`` for every string in ``doc`` that is a whole ``svc:`` id."""
    if isinstance(doc, Mapping):
        for k in sorted(doc, key=str):
            yield from _svc_ids(doc[k], f"{path}.{k}" if path else str(k))
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from _svc_ids(v, f"{path}[{i}]")
    elif isinstance(doc, str):
        m = SVC_ID.match(doc)
        if m is not None:
            yield path, m.group(1)


def pack_problems(registry: Registry, pack: Any, where: str) -> Report:
    """Every ``svc:`` id in a workflow pack and its fixtures (step targets, event sources, the
    calls a fixture expects): a primary row, a capability with a primary or a declared platform
    source.  A capability the platform knows and this registry does not place is a note."""
    rep = Report([], [])
    known = platform_capabilities()
    seen: set[str] = set()
    for path, name in _svc_ids(pack):
        if name in _PLATFORM:
            continue
        why = _judge(registry, name, ())
        if why is None:
            continue
        if why == "unknown":
            if name in known:
                if name not in seen:
                    rep.notes.append(
                        f"{where}: svc:{name} is a platform capability this registry does not "
                        "place: the pack has no target here"
                    )
                    seen.add(name)
                continue
            why = "names no registry row, capability or declared platform source"
        rep.problems.append(f"{where}: {path}: svc:{name} {why}")
    return rep


def target_problems(registry: Registry, target: Any, where: str) -> list[str]:
    """A conformance target file (the declared ``conformance-target`` exception): every ``svc:``
    id in it names a primary, an ``eval`` or a ``retiring`` row (or a capability with a primary),
    never a legacy row and never a name the registry does not hold."""
    out = []
    for path, name in _svc_ids(target):
        why = _judge(registry, name, ("eval", "retiring"))
        if why is None:
            continue
        if why == "unknown":
            why = "names no registry row or capability"
        out.append(f"{where}: {path}: svc:{name} {why}")
    return out


def _selected(site: Mapping[str, Any]) -> set[str]:
    """The module ids a site runs: every provider its slots select, its features, its core."""
    ids: set[str] = set()
    for lines in (site.get("slots") or {}).values():
        if isinstance(lines, list):
            ids |= {c["provider"] for c in lines if isinstance(c, Mapping) and "provider" in c}
    for key in ("features", "core"):
        block = site.get(key)
        if isinstance(block, Mapping):
            ids |= {str(k) for k in block}
    return ids


def requires_problems(
    registry: Registry, site: Mapping[str, Any], mods: Mapping[str, Mapping[str, Any]]
) -> list[str]:
    """Each ``requires`` capability of a module the site runs, resolved through the selection,
    reaches its primary: a capability the registry holds rows of needs a primary, and when the
    selection's provider for it is the product of a non-primary row and not of the primary, the
    requirement would reach that row.  A requirement on a capability the registry holds no row
    of is the loader's to judge (``hnx modules check``)."""
    from homelabnext.modules.providers import ProviderLookupError, provider_for

    out = []
    for mid in sorted(_selected(site)):
        m = mods.get(mid)
        if not isinstance(m, Mapping):
            continue
        reqs = (m.get("requires") or {}).get("capabilities") or []
        for req in reqs:
            if not isinstance(req, Mapping) or not isinstance(req.get("cap"), str):
                continue
            cap = req["cap"].removeprefix("cap:")
            where = f"{mid}: requires cap:{cap}"
            rows = [s for s in registry.rows(*STANDINGS) if s.capability == cap]
            if not rows:
                continue
            primary = registry.by_capability(cap)
            if primary is None:
                tiers = ", ".join(f"{s.name} ({s.standing})" for s in rows)
                out.append(f"{where}: the capability has no primary (its rows: {tiers})")
                continue
            try:
                lines = (site.get("slots") or {}).get(cap)
                instance = req.get("instance") if isinstance(req.get("instance"), str) else None
                prov = (
                    provider_for(site, dict(mods), cap, instance)
                    if isinstance(lines, list)
                    else None
                )
            except ProviderLookupError:
                continue  # several instances, or none named: the loader reports the selection
            if prov is None:
                continue
            names = {prov.product, *prov.aliases}
            if primary.impl in names:
                continue
            for s in rows:
                if not s.is_primary and s.impl in names:
                    out.append(
                        f"{where}: the selection's provider {prov.module} ({prov.product}) is "
                        f"{_article(s.standing)} row's product ({s.name}), not the primary's "
                        f"({primary.name}, impl {primary.impl}): the requirement would reach a "
                        "non-primary row"
                    )
                    break
    return out


def check(
    registry: Registry,
    *,
    tables: Iterable[tuple[str, Any]] = (),
    reports: Iterable[tuple[str, Any]] = (),
    packs: Iterable[tuple[str, Any]] = (),
    targets: Iterable[tuple[str, Any]] = (),
    site: Mapping[str, Any] | None = None,
    mods: Mapping[str, Mapping[str, Any]] | None = None,
) -> Report:
    """Every binding site over ``registry``: its upstreams, each ``(where, RoleTable)``, each
    ``(where, evaluation report)``, each ``(where, pack)``, each ``(where, conformance target)``
    and, with ``site`` and ``mods``, the selected modules' requirements."""
    rep = Report(row_upstream_problems(registry), [])
    for where, table in tables:
        rep.problems += role_problems(registry, table, where)
    for where, doc in reports:
        rep.problems += canary_problems(registry, doc, where)
    for where, doc in packs:
        found = pack_problems(registry, doc, where)
        rep.problems += found.problems
        rep.notes += found.notes
    for where, doc in targets:
        rep.problems += target_problems(registry, doc, where)
    if site is not None:
        rep.problems += requires_problems(registry, site, mods or {})
    return rep
