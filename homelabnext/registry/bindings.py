# SPDX-License-Identifier: Apache-2.0
"""``hnx registry bindings``: consumers bind only to a primary (ADR-0039 decision 3).

A *binding* is a reference that makes a consumer call a service.  This check reads a registry and
the files that bind to it, and refuses each binding that would reach a row other than its
capability's primary:

* a row's ``upstreams`` (by capability): the registry's own rule since service registry 2.9
  (:func:`homelabnext.registry.model.upstream_problems`, which loading a registry already runs),
  applied here to every tier;
* a model-role binding's ``backend: svc:<name>`` (``model_roles.json``);
* an LLM gateway spec's backends and the role table it renders (the gateway generator's own
  rules, run against this registry: a backend named after a non-primary row, or a self-declared
  host that reaches one, is refused);
* a workflow pack step's ``target: svc:<name>`` and every other ``svc:`` id in a pack or its
  fixtures, event sources included (``workflows/packs/*.yml``);
* a module's ``requires`` resolved through the site selection.  The provider a site selects is
  matched against a row by product name: a row's ``impl`` is the provider's product or one of its
  aliases, by the same convention ``registry_impl_problems`` uses; a row whose ``impl`` follows
  another spelling is not matched.

A ``svc:`` id may name a row or a capability; a capability name means its primary.  An id that
names a non-primary row, or a capability whose rows are all non-primary, is refused.  A string
that starts with ``svc:`` but is not a lower-case kebab id (:data:`SVC_ID`) is refused as
malformed, never skipped.  In a pack, an id that names no registry row and no capability is
refused unless it is a declared platform source (:data:`PLATFORM_SOURCES`; one declared an event
source only is refused as a ``target``) or a declared
unplaced capability of that pack (:data:`UNPLACED`, a note) and the check runs over the
reference examples (``--reference-examples``, which only ``make check`` passes; a lab's check
never gets it): the leniency is a list with a reason
and an end per entry, not a rule.

Two exceptions are declared here (:data:`EXCEPTIONS`), never inferred from a file name or a call
path: the evaluation report's ``canary`` bindings may name an ``eval`` row, and a conformance
target file may name any non-legacy row.  The second checks only ``svc:`` strings in the target
file; a target reaches a row through its adapter's configuration and ``HNX_ENDPOINT_<ROW>``, which
this check does not see, and no target file names a row today.

Not bindings, so not read: status sources, the census, ``hnx decommission`` and the ledger read
every tier (watching a row is not depending on it), and an agent lane (``real``/``shadow``) names
an executor, not a registry row.

The inputs are read by :func:`read_input`, which refuses a symbolic link anywhere on a relative
path (a lab's change cannot point the check at a file outside the checkout).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import STANDINGS, Registry, upstream_problems

__all__ = [
    "EXCEPTIONS",
    "PLATFORM_SOURCES",
    "UNPLACED",
    "BindingsInputError",
    "Declared",
    "Report",
    "canary_problems",
    "check",
    "gateway_problems",
    "load_eval_reports",
    "load_gateways",
    "load_packs",
    "load_role_tables",
    "load_selection",
    "load_targets",
    "pack_problems",
    "read_input",
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
    #: for an :data:`UNPLACED` entry: the packs (by ``pack:`` name) it covers, and no other
    packs: tuple[str, ...] = ()
    #: for a :data:`PLATFORM_SOURCES` entry: an event source only, refused as a step's or an
    #: expected call's ``target``
    source_only: bool = False


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
        "(ADR-0026 amendment, decision 16); an event source only, never a target; removed by "
        "the change that drops that source at cutover+1",
        source_only=True,
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
#: platform capabilities a pack may name although the reference example registry places no row of
#: them: a note, not a problem, for the packs listed only and only with ``reference_examples``
#: (``make check``); against a lab registry they are refused like any other unplaced name.  Each entry ends with the change
#: its reason names; a registry that holds any row of the capability judges it as usual.
UNPLACED: tuple[Declared, ...] = (
    Declared(
        "cases",
        "example packs no deploy manifest pins: the reference registry places no case store "
        "until ADR-0049 brings the cases provider module and its row",
        ("case-opened-notify", "new-critical-alert", "phishing-report"),
    ),
    Declared(
        "siem-source",
        "example packs no deploy manifest pins: the reference registry places no SIEM source "
        "until the SOC modules of ADR-0049 do",
        ("new-critical-alert", "phishing-report"),
    ),
    Declared(
        "mail-gateway",
        "an example pack no deploy manifest pins: no reference registry places a mail relay; "
        "the entry goes with the pack or when a reference registry places one",
        ("phishing-report",),
    ),
)
_PLATFORM = {d.name for d in PLATFORM_SOURCES}
_SOURCE_ONLY = {d.name for d in PLATFORM_SOURCES if d.source_only}
_UNPLACED = {d.name: set(d.packs) for d in UNPLACED}

#: the start of a ``svc:`` id; a string with it that :data:`SVC_ID` does not match is malformed
SVC_PREFIX = "svc:"


class BindingsInputError(ValueError):
    """An input of the check that cannot be read (the CLI's exit 2)."""


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


def _svc_ids(doc: Any, path: str = "") -> Iterator[tuple[str, str | None]]:
    """``(where, name)`` for every string in ``doc`` that starts with ``svc:``; ``name`` is None
    when the rest is not a lower-case kebab id (malformed)."""
    if isinstance(doc, Mapping):
        for k in sorted(doc, key=str):
            yield from _svc_ids(doc[k], f"{path}.{k}" if path else str(k))
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            yield from _svc_ids(v, f"{path}[{i}]")
    elif isinstance(doc, str) and doc.startswith(SVC_PREFIX):
        m = SVC_ID.match(doc)
        yield path, (m.group(1) if m is not None else None)


def _malformed(where: str, path: str, doc: Any) -> str:
    return f"{where}: {path}: malformed svc: id (a lower-case kebab name follows svc:)"


def pack_problems(
    registry: Registry, pack: Any, where: str, *, reference_examples: bool = False
) -> Report:
    """Every ``svc:`` id in a workflow pack and its fixtures (step targets, event sources, the
    calls a fixture expects): a primary row, a capability with a primary or a declared platform
    source; with ``reference_examples`` (``make check`` over this repository's examples, never a
    lab), a declared :data:`UNPLACED` capability of this pack that the registry holds no row of
    is a note."""
    rep = Report([], [])
    pack_name = pack.get("pack") if isinstance(pack, Mapping) else None
    seen: set[str] = set()
    for path, name in _svc_ids(pack):
        if name is None:
            rep.problems.append(_malformed(where, path, pack))
            continue
        if name in _PLATFORM:
            if name in _SOURCE_ONLY and path.rsplit(".", 1)[-1] == "target":
                rep.problems.append(
                    f"{where}: {path}: svc:{name} is a declared platform source, an event source "
                    "only: it is never a target"
                )
            continue
        why = _judge(registry, name, ())
        if why is None:
            continue
        if why == "unknown":
            if reference_examples and pack_name in _UNPLACED.get(name, ()):
                if name not in seen:
                    rep.notes.append(
                        f"{where}: svc:{name} is a declared unplaced capability of this pack "
                        "(bindings.UNPLACED): the pack has no target here"
                    )
                    seen.add(name)
                continue
            why = "names no registry row, capability or declared platform source"
        rep.problems.append(f"{where}: {path}: svc:{name} {why}")
    return rep


def target_problems(registry: Registry, target: Any, where: str) -> list[str]:
    """A conformance target file (the declared ``conformance-target`` exception): every ``svc:``
    id in it names a primary, an ``eval`` or a ``retiring`` row (or a capability with a primary),
    never a legacy row and never a name the registry does not hold.  Only ``svc:`` strings are
    read: an adapter that reaches a row through its configuration or ``HNX_ENDPOINT_<ROW>`` is
    not seen here."""
    out = []
    for path, name in _svc_ids(target):
        if name is None:
            out.append(_malformed(where, path, target))
            continue
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


def gateway_problems(registry: Registry, path: str | Path) -> list[str]:
    """An LLM gateway spec (and the role table it names) validated against ``registry`` by the
    gateway generator's own rules, so a backend that reaches a non-primary row is refused here as
    it is at render time.  A conformance spec is read in its test-only mode."""
    from homelabnext.generators import llm_gateway as gw

    doc = _parse(read_input(path), str(path))
    conformance = isinstance(doc, Mapping) and bool(doc.get("conformance"))
    out: list[str] = []
    try:
        gw.load_spec(path, conformance=conformance, registry=registry)
    except gw.GatewaySpecError as exc:
        found = list(getattr(exc, "problems", None) or [])
        out += [f"{path}: {p}" for p in found] or [str(exc)]
    except (OSError, ValueError) as exc:
        raise BindingsInputError(f"{path}: {exc}") from None
    return out + _gateway_role_problems(registry, Path(path), doc)


def _gateway_role_problems(registry: Registry, path: Path, doc: Any) -> list[str]:
    """The spec's role table: a binding naming a registry row or capability is judged as any
    role binding is; a name the registry does not hold is one of the spec's own backends, which
    the gateway rules above have judged."""
    from .models import RoleTable, RoleTableError

    rel = doc.get("roles") if isinstance(doc, Mapping) else None
    if not isinstance(rel, str):
        return []
    table_path = path.parent / rel
    try:
        read_input(table_path)
        table = RoleTable.load(table_path)
    except RoleTableError as exc:
        raise BindingsInputError(f"{table_path}: {exc}") from None
    known = {r.name for r in registry.rows(*STANDINGS)} | {
        r.capability for r in registry.rows(*STANDINGS)
    }
    out = []
    for rname, role in sorted(table.roles.items()):
        for i, b in enumerate(role.bindings):
            if b.backend not in known:
                continue
            at = f"{path}: {rel}: mdl:{rname} bindings[{i}]"
            p = _backend_problem(registry, at, b.backend, ())
            if p:
                out.append(p)
    return out


def check(
    registry: Registry,
    *,
    tables: Iterable[tuple[str, Any]] = (),
    reports: Iterable[tuple[str, Any]] = (),
    packs: Iterable[tuple[str, Any]] = (),
    targets: Iterable[tuple[str, Any]] = (),
    gateways: Iterable[str | Path] = (),
    site: Mapping[str, Any] | None = None,
    mods: Mapping[str, Mapping[str, Any]] | None = None,
    reference_examples: bool = False,
) -> Report:
    """Every binding site over ``registry``: its upstreams, each ``(where, RoleTable)``, each
    ``(where, evaluation report)``, each ``(where, pack)``, each ``(where, conformance target)``,
    each gateway spec path and, with ``site`` and ``mods``, the selected modules' requirements."""
    rep = Report(row_upstream_problems(registry), [])
    for where, table in tables:
        rep.problems += role_problems(registry, table, where)
    for where, doc in reports:
        rep.problems += canary_problems(registry, doc, where)
    for where, doc in packs:
        found = pack_problems(registry, doc, where, reference_examples=reference_examples)
        rep.problems += found.problems
        rep.notes += found.notes
    for where, doc in targets:
        rep.problems += target_problems(registry, doc, where)
    for path in gateways:
        rep.problems += gateway_problems(registry, path)
    if site is not None:
        rep.problems += requires_problems(registry, site, mods or {})
    return rep


# ---------------------------------------------------------------- inputs


def read_input(path: str | Path) -> bytes:
    """A regular file's bytes, never through a symbolic link: on a relative path, no component
    may be a link (the overlay's ``lab/`` files); on an absolute one, the final component."""
    from homelabnext.modules import loader as ld

    p = Path(path)
    try:
        if not p.is_absolute() and ld.path_has_symlink(".", p.as_posix()):
            raise BindingsInputError(f"{path}: a symbolic link on its path")
        return ld.read_bytes(p, follow=False)
    except (ld.Unreadable, OSError) as exc:
        raise BindingsInputError(f"{path}: {exc}") from None


def _parse(data: bytes, where: str) -> Any:
    from homelabnext.modules import loader as ld

    try:
        text = data.decode("utf-8")
        if where.endswith(".json"):
            return json.loads(text)
        return ld.parse_yaml(text)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise BindingsInputError(f"{where}: cannot be parsed ({exc})") from None


def load_doc(path: str | Path) -> Any:
    """A YAML or JSON input (JSON by its suffix), read by :func:`read_input`."""
    return _parse(read_input(path), str(path))


def load_role_tables(paths: Iterable[str]) -> list[tuple[str, Any]]:
    """Each role table, validated against ``model_roles.json`` as :meth:`RoleTable.load` does."""
    from .models import RoleTable, RoleTableError, schema_problems

    out = []
    for path in paths:
        doc = load_doc(path)
        if problems := schema_problems(doc):
            raise BindingsInputError(
                f"{path}: role table does not match model_roles.json: " + "; ".join(problems[:5])
            )
        try:
            out.append((path, RoleTable.from_dict(doc)))
        except RoleTableError as exc:
            raise BindingsInputError(f"{path}: {exc}") from None
    return out


def load_targets(paths: Iterable[str]) -> list[tuple[str, Any]]:
    return [(path, load_doc(path)) for path in paths]


def load_gateways(paths: Iterable[str]) -> list[str]:
    for path in paths:
        read_input(path)  # refused before the generator opens it
    return list(paths)


def load_eval_reports(
    paths: Iterable[str], *, root: str | Path = ".", base: str | None = None
) -> list[tuple[str, Any]]:
    """Each evaluation report as the working tree has it and, with ``base``, also as that commit
    has it (the copy the swap gate trusts).  A report absent from the tree or the base is skipped
    there; one in neither is an input error."""
    out = []
    for rel in paths:
        head = None
        if Path(rel).exists() or Path(rel).is_symlink():
            head = load_doc(rel)
            out.append((rel, head))
        if base is None:
            if head is None:
                raise BindingsInputError(f"{rel}: no such file")
            continue
        from homelabnext.modules.swap_evidence import EvidenceError, read_base

        try:
            data = read_base(Path(root), base, rel, missing_ok=True)
        except EvidenceError as exc:
            raise BindingsInputError(str(exc)) from None
        if data is not None:
            out.append((f"{rel}@{base[:12]}", _parse(data, rel)))
    return out


def load_packs(paths: Iterable[str], deployed: str | None = None) -> list[tuple[str, Any]]:
    """The packs under ``paths`` (files, or directories of packs); with ``deployed`` (a workflow
    deploy manifest) only the packs it pins, every one of which must be among them."""
    from homelabnext.workflows.pack import WorkflowError, expand
    from homelabnext.workflows.pack import load_doc as load_pack

    packs = []
    try:
        for f in expand(Path(p) for p in paths):
            read_input(f)  # refused through a link before the pack reader opens it
            packs.append((str(f), load_pack(f)))  # the pack format's own YAML reader
    except WorkflowError as exc:
        raise BindingsInputError(str(exc)) from None
    if deployed is None:
        return packs
    manifest = load_doc(deployed)
    pins = manifest.get("pins") if isinstance(manifest, Mapping) else None
    if not isinstance(pins, list):
        raise BindingsInputError(f"{deployed}: no pins list")
    names = {p.get("pack") for p in pins if isinstance(p, Mapping)}
    held = {doc.get("pack") for _w, doc in packs if isinstance(doc, Mapping)}
    missing = sorted(str(n) for n in names - held)
    if missing:
        raise BindingsInputError(
            f"{deployed} pins {', '.join(missing)}, which --packs does not hold"
        )
    return [(w, d) for w, d in packs if isinstance(d, Mapping) and d.get("pack") in names]


def load_selection(site_path: str, modules: Iterable[str]) -> tuple[dict, dict]:
    """A site selection and the module manifests under ``modules`` (each read by the module
    loader, which refuses a linked module directory or manifest)."""
    from homelabnext.modules import loader as ld

    site = load_doc(site_path)
    if not isinstance(site, dict):
        raise BindingsInputError(f"{site_path}: not a mapping")
    mods: dict = {}
    for d in modules:
        tree, problems = ld.discover(public=Path(d))
        if problems:
            raise BindingsInputError("; ".join(str(p) for p in problems))
        twice = sorted(set(mods) & set(tree.mods))
        if twice:
            raise BindingsInputError(
                f"{d}: module(s) {', '.join(twice)} already under another --modules"
            )
        mods.update(tree.mods)
    return site, mods
