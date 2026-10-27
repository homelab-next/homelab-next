# SPDX-License-Identifier: Apache-2.0
"""The module-keyed part of swap record 1.2 (draft schema ``platform/module_swap`` 1.0;
docs/modules.md, "Swap record 1.2"), as plain functions over a swap document, the manifests and
the site selection the swap starts from.

Like :mod:`homelabnext.modules.rules`, this is the specification in executable form: ADR-0027 is
proposed, there is no loader, and the swap kit (:mod:`homelabnext.swap`) still drives the 1.1
record.  The contract tests apply it to the fictional examples.

:func:`dependants_report` is the re-check the cutover waits on.  Every selected module that
requires or prefers a moving slot instance (core modules included) is checked against what the
**incoming** provider offers for that slot: the features it requires and the formats it reads.
A failed requirement blocks; a failed preference falls back.  A swap document's report is never
trusted as written: :func:`module_swap_problems` recomputes it and refuses a difference.

A swap that moves the ``inference`` slot may rebind model roles: each ``model_roles`` leg names a
role, its outgoing and incoming binding (by pin digest or by model-store entry) and the pinned
evaluation report for the role table after the rebind.  :func:`model_role_problems` checks a leg
against :class:`ModelEvidence` (both role tables, the reports, optionally the store): the role is
in both tables, each binding resolves, and the report is the one pinned and passes
``hnx golden pins check`` against the new table, canary entry of the new binding included, live
when the leg requires it.  Calibration refit is not a field of the record, so it is not enforced.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from homelabnext.golden import pins as gp
from homelabnext.models.store import Store, resolve_binding
from homelabnext.modules.rules import selected
from homelabnext.registry.models import Binding, RoleTable, UnknownRole

Doc = dict[str, Any]


def _offer(mod: Doc, slot: str) -> Doc | None:
    return mod.get("provides", {}).get("slots", {}).get(slot)


def _asks(mod: Doc, slot: str, instance: str) -> list[tuple[str, Doc]]:
    """The module's requirements and preferences on this slot instance: one naming another
    instance does not ask for this one; one naming none may be served by any, so it is asked."""
    out = []
    for relation, block in (
        ("requires", mod.get("requires", {})),
        ("prefers", mod.get("prefers", {})),
    ):
        for ask in block.get("capabilities", []):
            if ask["cap"] == f"cap:{slot}" and ask.get("instance", instance) == instance:
                out.append((relation, ask))
    return out


def _lines(site: Doc, slot: str) -> list[Doc]:
    """The site's selection lines for a slot: none for ``none``, ``pass-through`` or no entry."""
    chosen = site.get("slots", {}).get(slot)
    return chosen if isinstance(chosen, list) else []


def _key(e: Doc) -> tuple:
    # a module may ask twice for one instance: the whole entry breaks the tie, so order is stable
    return (e["slot"], e["instance"], e["module"], e["relation"], json.dumps(e, sort_keys=True))


def _fmt(f: Doc) -> str:
    return f"{f['format']}@{f['version']}"


def dependants_report(swap: Doc, mods: dict[str, Doc], site: Doc) -> list[Doc]:
    """Every selected module that asks for a moving slot instance, re-checked against the
    incoming provider; sorted by slot, instance and module."""
    incoming = mods[swap["to_module"]]
    movers = {swap["from_module"], swap["to_module"]}
    out = []
    for si in swap["slots"]:
        slot, instance = si["slot"], si["instance"]
        offer = _offer(incoming, slot) or {}
        have_features = set(offer.get("features", []))
        have_formats = {_fmt(f) for f in offer.get("formats", [])}
        for mid, mod in selected(site, mods).items():
            if mid in movers:
                continue
            for relation, ask in _asks(mod, slot, instance):
                reasons = []
                missing_f = sorted(set(ask.get("features", [])) - have_features)
                missing_x = sorted({_fmt(f) for f in ask.get("formats", [])} - have_formats)
                if missing_f:
                    reasons.append(f"{swap['to_module']} does not offer {', '.join(missing_f)}")
                if missing_x:
                    reasons.append(f"{swap['to_module']} does not speak {', '.join(missing_x)}")
                checks = {
                    "features": (
                        "not-asked"
                        if not ask.get("features")
                        else "fails"
                        if missing_f
                        else "holds"
                    ),
                    "formats": (
                        "not-asked" if not ask.get("formats") else "fails" if missing_x else "holds"
                    ),
                }
                verdict = "holds"
                if reasons:
                    verdict = "blocks" if relation == "requires" else "falls-back"
                entry = {
                    "module": mid,
                    "kind": mod["kind"],
                    "relation": relation,
                    "slot": slot,
                    "instance": instance,
                    "checks": checks,
                    "verdict": verdict,
                }
                if reasons:
                    entry["reasons"] = reasons
                out.append(entry)
    return sorted(out, key=_key)


def blocked(report: list[Doc]) -> list[str]:
    """The modules whose verdict blocks the cutover, sorted and listed once."""
    return sorted({e["module"] for e in report if e["verdict"] == "blocks"})


@dataclass(frozen=True)
class ModelEvidence:
    """What a swap's model-role legs are checked against: the role table the swap starts from,
    the table after the rebind, the evaluation reports a leg may pin (any number, matched by
    :func:`homelabnext.golden.pins.report_digest`), the golden suites ``pins check`` runs with, and
    the model store a leg naming a store entry resolves through."""

    before: RoleTable
    after: RoleTable
    reports: Sequence[Any] = ()
    suites: Sequence[Path] = field(default_factory=lambda: tuple(gp.DEFAULT_SUITES))
    store: Store | None = None


def _pin_of(b: Binding) -> str:
    return gp.pin_digest(
        {"backend": f"svc:{b.backend}", "model_id": b.model_id, "version": b.version,
         "digest": b.digest}
    )  # fmt: skip


def _binding(
    ref: Doc, table: RoleTable, role: str, store: Store | None
) -> tuple[Binding | None, str]:
    """The one binding of ``role`` in ``table`` a leg's ``from`` or ``to`` names, or ``(None, why)``."""
    bindings = table.get(role).bindings
    if "pin" in ref:
        hit = [b for b in bindings if _pin_of(b) == ref["pin"]]
        return (hit[0], "") if hit else (None, f"pin {ref['pin'][:19]}... is no binding of it")
    if store is None:
        return None, f"it names store entry {ref['store_entry']!r}, and no model store is given"
    entry = store.entries.get(ref["store_entry"])
    if entry is None:
        return None, f"store entry {ref['store_entry']!r} is not in the model store"
    hit = [b for b in bindings if (b.model_id, b.digest) == (entry.served_model_name, entry.digest)]
    if len(hit) != 1:
        return None, f"store entry {entry.id!r} is {len(hit)} bindings of it, not one"
    return hit[0], ""


def model_role_problems(swap: Doc, models: ModelEvidence) -> list[str]:
    """Each ``model_roles`` leg against the role tables, the store and the pinned reports: the role
    is in both tables, the old binding is one of the table the swap starts from, the new one
    resolves in the table after it (and in the store, when one is given) and differs, and the
    report the leg pins passes ``pins check`` against the table after (with ``--require-live``
    when the leg requires live; without it, the fake-canary guard ``pins check`` applies)."""
    out: list[str] = []
    moving = {si["instance"] for si in swap["slots"] if si["slot"] == "inference"}
    reports = {gp.report_digest(r): r for r in models.reports}
    seen: set[str] = set()
    for leg in swap.get("model_roles", []):
        role = leg["role"]
        where = f"model_roles {role}"
        if leg["instance"] not in moving:
            out.append(
                f"{where}: inference/{leg['instance']} is not a slot instance the swap moves"
            )
        if role in seen:
            out.append(f"{where}: the role is rebound by more than one leg")
        seen.add(role)
        try:
            models.before.get(role)
            models.after.get(role)
        except UnknownRole as exc:
            out.append(f"{where}: {exc.args[0]}")
            continue
        old, why_old = _binding(leg["from"], models.before, role, models.store)
        if old is None:
            out.append(
                f"{where}: the old binding does not resolve in the role table before: {why_old}"
            )
        new, why_new = _binding(leg["to"], models.after, role, models.store)
        if new is None:
            out.append(
                f"{where}: the new binding does not resolve in the role table after: {why_new}"
            )
            continue
        if old is not None and _pin_of(old) == _pin_of(new):
            out.append(f"{where}: the old and new binding are the same pin; nothing is rebound")
        if models.store is not None:
            entry, why = resolve_binding(models.store, new.model_id, digest=new.digest)
            if entry is None:
                out.append(f"{where}: the new binding does not resolve in the model store: {why}")
        ev = leg["evaluation"]
        report = reports.get(ev["report"])
        if report is None:
            out.append(
                f"{where}: the evaluation report {ev['report'][:19]}... is not supplied; the leg's "
                "evidence is the pinned report for the role table after the rebind"
            )
            continue
        live = bool(ev.get("require_live", False))
        found = gp.check_report(report, models.after, models.suites, require_live=live)
        if not live and (guard := gp.fake_canary_on_a_real_table(report, models.after)):
            found.append(guard)
        out += [f"{where}: pins check: {p}" for p in found]
    return out


def module_swap_problems(
    swap: Doc, mods: dict[str, Doc], site: Doc, *, models: ModelEvidence | None = None
) -> list[str]:
    """The rules JSON Schema cannot say, against the manifests and the site the swap starts from.
    Each problem is one string; an empty list is a record that holds.  Whether its cutover may run
    is :func:`cutover_problems`, which also refuses a blocking dependant.  A record with
    ``model_roles`` legs needs ``models``, their evidence (:func:`model_role_problems`)."""
    out: list[str] = []
    frm, to = swap["from_module"], swap["to_module"]
    # gate modules-differ (it replaces 1.1's adapters-differ: the same adapter is normal)
    if frm == to:
        return [f"from_module and to_module are both {frm!r}: a swap moves between two modules"]
    for role, mid in (("from_module", frm), ("to_module", to)):
        if mid not in mods:
            out.append(f"{role} {mid!r} has no manifest")
        elif mods[mid]["kind"] != "provider":
            out.append(f"{role} {mid!r} is a {mods[mid]['kind']} module, not a provider")
    if out:
        return out
    pairs = [(si["slot"], si["instance"]) for si in swap["slots"]]
    for slot, instance in pairs:
        for mid in (frm, to):
            if _offer(mods[mid], slot) is None:
                out.append(f"{mid} does not fill the {slot} slot")
        serving = [c["provider"] for c in _lines(site, slot) if c.get("instance") == instance]
        if serving != [frm]:
            out.append(
                f"{slot}/{instance} is served by {serving or 'nothing'} in the site, not {frm}: "
                "the site is the selection the swap starts from"
            )
    diff = swap["route"].get("selection_diff")
    if diff is not None:
        got = sorted((d["slot"], d["instance"], d["from"], d["to"]) for d in diff)
        want = sorted((s, i, frm, to) for s, i in pairs)
        if got != want:
            out.append(
                f"route.selection_diff is {got}, but the swap changes exactly {want}: "
                "one line per slot instance, from the outgoing to the incoming module"
            )
    legs = swap.get("legs")
    if legs is not None:
        if sorted(leg["instance"] for leg in legs) != sorted({i for _, i in pairs}) or len(
            legs
        ) != len({i for _, i in pairs}):
            out.append("legs must name every instance of the swap exactly once")
        if sorted(leg["order"] for leg in legs) != list(range(1, len(legs) + 1)):
            out.append("legs' orders must be 1..n, each once")
    for ask in mods[to].get("requires", {}).get("capabilities", []):
        need = ask["cap"].removeprefix("cap:")
        if not _lines(site, need):
            out.append(f"{to} requires {ask['cap']}, which the site does not select")
    try:
        want_report = dependants_report(swap, mods, site)
    except KeyError as exc:
        return [*out, f"the site selects a module with no manifest: {exc}"]
    got_report = sorted(swap["dependants"]["report"], key=_key)
    if got_report != want_report:
        missing = [e["module"] for e in want_report if e not in got_report]
        extra = [e["module"] for e in got_report if e not in want_report]
        out.append(
            "dependants.report differs from the re-check of the manifests "
            f"(missing or different: {missing or 'none'}; not expected: {extra or 'none'})"
        )
    if sorted(swap["dependants"]["blocked"]) != blocked(want_report):
        out.append(
            f"dependants.blocked is {sorted(swap['dependants']['blocked'])}, "
            f"the re-check blocks {blocked(want_report)}"
        )
    mig = swap.get("migration")
    if mig is not None:
        for slot, _ in pairs:
            for mid in (frm, to):
                fmts = (_offer(mods[mid], slot) or {}).get("migration", {}).get("formats", [])
                if mig["format"] not in fmts:
                    out.append(
                        f"migration.format {mig['format']!r} is not one {mid} migrates {slot} in"
                    )
        if mig["import_result"]["rejected"]:
            out.append(
                f"migration rejected {mig['import_result']['rejected']} record(s): every exported "
                "record is imported, or the swap starts empty by decision"
            )
        if mig["import_result"]["imported"] != mig["boundary"]["count"]:
            out.append(
                f"migration imported {mig['import_result']['imported']} but the boundary counts "
                f"{mig['boundary']['count']}"
            )
    if mig is not None and "start_empty" in swap:
        out.append("migration and start_empty are exclusive: the data moves or it does not")
    issued = {c["secret"] for c in mods[frm].get("credentials", [])}
    for s in swap.get("credentials_revoked", []):
        if s not in issued:
            out.append(f"credentials_revoked names {s}, which {frm} does not issue")
    if swap.get("model_roles"):
        if models is None:
            out.append("the record rebinds model roles, and no model evidence is given to check it")
        else:
            out += model_role_problems(swap, models)
    return out


def cutover_problems(
    swap: Doc, mods: dict[str, Doc], site: Doc, *, models: ModelEvidence | None = None
) -> list[str]:
    """The cutover gate: the record holds (:func:`module_swap_problems`, its model-role legs
    included), no dependant blocks, and the data either moved (``migration``) or the swap starts
    empty by a recorded decision."""
    out = module_swap_problems(swap, mods, site, models=models)
    if out:
        return out
    stop = blocked(dependants_report(swap, mods, site))
    if stop:
        out.append(f"the cutover is blocked by {', '.join(stop)}")
    if "migration" not in swap and "start_empty" not in swap:
        out.append("the cutover waits on a migration or a recorded start_empty decision")
    return out


def credentials_outstanding(swap: Doc, mods: dict[str, Doc]) -> list[str]:
    """The outgoing provider's credentials not yet revoked."""
    issued = {c["secret"] for c in mods[swap["from_module"]].get("credentials", [])}
    return sorted(issued - set(swap.get("credentials_revoked", [])))


def decommission_problems(swap: Doc, mods: dict[str, Doc], after: Doc) -> list[str]:
    """The decommission gate, against the selection after the cutover: once the outgoing module
    serves nothing, every credential it issued is revoked.  While it still serves another
    instance its credentials stay (revoking them would break that instance), so none is owed."""
    frm = swap["from_module"]
    if frm in selected(after, mods):
        return []
    return [f"{s} is not revoked" for s in credentials_outstanding(swap, mods)]


def apply_selection_diff(
    site: Doc, swap: Doc, mods: dict[str, Doc], *, models: ModelEvidence | None = None
) -> Doc:
    """The cutover of a swap whose route is a selection diff: a copy of ``site`` with each changed
    line flipped to the incoming module.  It runs :func:`cutover_problems` first and refuses on
    any, so the diff is the record's checked one; a line that does not read ``from`` refuses, so a
    diff cannot be applied to a selection it was not checked against (the result included)."""
    problems = cutover_problems(swap, mods, site, models=models)
    if problems:
        raise ValueError("cutover refused: " + "; ".join(problems))
    if "selection_diff" not in swap["route"]:
        raise ValueError("the route is an endpoint: there is no selection diff to apply")
    out = copy.deepcopy(site)
    for d in swap["route"]["selection_diff"]:
        lines = [c for c in _lines(out, d["slot"]) if c.get("instance") == d["instance"]]
        if len(lines) != 1 or lines[0]["provider"] != d["from"]:
            raise ValueError(
                f"{d['slot']}/{d['instance']}: the site does not select it from {d['from']}"
            )
        lines[0]["provider"] = d["to"]
    return out
