# SPDX-License-Identifier: Apache-2.0
"""Guest baselines and defense layers (ADR-0016): the set, its checks and per-guest resolution.

A *baseline set* (``_baselines.yml`` beside the guest files, ``baseline_set.schema.json``) is a
catalogue of generic, product-neutral defense **controls**, each in one :data:`LAYERS` layer and
each bound to the Ansible role that implements it (``role: null`` until a product is chosen), plus
named **baselines** of controls that may ``extends`` other baselines.  A guest names its
baselines (``baseline.names``), may add or remove single controls, or carries a documented
``baseline.exemption``.

Resolution order is deterministic: for each named baseline in the order the guest lists them,
depth-first through ``extends`` (parents first, in listed order), then the baseline's own
controls in listed order; a control or baseline already seen is skipped; then ``add`` in order;
``remove`` drops its controls.  The product is chosen in one place: the control's ``role``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._yaml import UniqueKeyStrDateLoader
from homelabnext.generators.safe import control_char_paths

from .model import ComputeError, Guest, Problem

BASELINES_FILE = "_baselines.yml"
#: the defense-in-depth layers, outermost concern first; a closed set (the schema's enum)
LAYERS: tuple[str, ...] = ("identity", "host", "network", "detection", "data", "recovery")
WHERE = BASELINES_FILE


@dataclass(frozen=True)
class BaselineSet:
    """A schema-valid baseline set: ``controls`` and ``baselines`` as written."""

    controls: Mapping[str, Mapping[str, Any]]
    baselines: Mapping[str, Mapping[str, Any]]
    source: str = WHERE

    def layer(self, control: str) -> str:
        return self.controls[control]["layer"]

    def role(self, control: str) -> str | None:
        return self.controls[control].get("role")

    def ordered_controls(self) -> list[str]:
        """Every control, by layer (in :data:`LAYERS` order) then id."""
        return sorted(self.controls, key=lambda c: (LAYERS.index(self.layer(c)), c))

    def expand(self, names: list[str]) -> tuple[list[str], list[str]]:
        """``(baselines, controls)`` for ``names``: every baseline reached through ``extends``
        and their controls, in resolution order (module docstring).  Unknown names and cycles
        are skipped here; :func:`set_problems` and :func:`guest_problems` report them."""
        seen_b: list[str] = []
        seen_c: list[str] = []
        stack: list[str] = []

        def visit(b: str) -> None:
            if b in seen_b or b in stack or b not in self.baselines:
                return
            stack.append(b)
            for parent in self.baselines[b].get("extends", []):
                visit(parent)
            stack.pop()
            seen_b.append(b)
            for c in self.baselines[b].get("controls", []):
                if c not in seen_c:
                    seen_c.append(c)

        for n in names:
            visit(n)
        return seen_b, seen_c


@dataclass(frozen=True)
class Resolution:
    """One guest's effective baselines and controls (empty for an exempt or undeclared guest)."""

    guest: str
    baselines: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    exemption: Mapping[str, Any] | None = None
    declared: bool = True
    by_layer: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def missing(self) -> bool:
        """Neither a baseline nor an exemption."""
        return not self.declared


def schema() -> dict:
    return json.loads(
        paths.schema_file("platform", "baseline_set.schema.json").read_text(encoding="utf-8")
    )


def load_baselines(path: str | Path) -> tuple[BaselineSet | None, list[Problem]]:
    """Read and schema-check a baseline set.  ``(None, problems)`` when it cannot be used."""
    import jsonschema

    p = Path(path)
    try:
        doc = yaml.load(p.read_text(encoding="utf-8"), Loader=UniqueKeyStrDateLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ComputeError(f"cannot read baseline set {p}: {exc}") from exc
    where = p.name
    out = [Problem(where, f"unsafe: {m}") for m in control_char_paths(doc)]
    validator = jsonschema.Draft202012Validator(schema())
    for err in sorted(validator.iter_errors(doc), key=lambda e: [str(x) for x in e.absolute_path]):
        loc = "/".join(str(x) for x in err.absolute_path) or "<root>"
        out.append(Problem(where, f"schema: {loc}: {err.message}"))
    if out:
        return None, out
    return BaselineSet(dict(doc["controls"]), dict(doc["baselines"]), source=where), []


def set_problems(bs: BaselineSet) -> list[Problem]:
    """What the schema cannot say about a set: names that resolve, no cycles, no empty baseline."""
    out: list[Problem] = []
    w = bs.source
    for c, spec in sorted(bs.controls.items()):
        if spec.get("layer") not in LAYERS:  # the schema's enum; kept for sets built in code
            out.append(Problem(w, f"control {c!r} is in no known layer ({', '.join(LAYERS)})"))
    for b, spec in sorted(bs.baselines.items()):
        for parent in spec.get("extends", []):
            if parent not in bs.baselines:
                out.append(Problem(w, f"baseline {b!r} extends {parent!r}, which is not defined"))
        for c in spec.get("controls", []):
            if c not in bs.controls:
                out.append(Problem(w, f"baseline {b!r} names control {c!r}, which is not defined"))
    for cycle in _cycles(bs):
        out.append(Problem(w, "extends cycle: " + " -> ".join(cycle)))
    for b in sorted(bs.baselines):
        if not bs.expand([b])[1]:
            out.append(
                Problem(w, f"baseline {b!r} resolves to no controls (use a guest exemption)")
            )
    return out


def _cycles(bs: BaselineSet) -> list[list[str]]:
    """Each distinct ``extends`` cycle once, rotated to start at its smallest name."""
    found: set[tuple[str, ...]] = set()

    def walk(b: str, path: list[str]) -> None:
        if b in path:
            cyc = path[path.index(b) :]
            i = cyc.index(min(cyc))
            found.add(tuple(cyc[i:] + cyc[:i]))
            return
        for parent in bs.baselines.get(b, {}).get("extends", []):
            if parent in bs.baselines:
                walk(parent, [*path, b])

    for b in sorted(bs.baselines):
        walk(b, [])
    return [[*c, c[0]] for c in sorted(found)]


def guest_problems(g: Guest, bs: BaselineSet | None) -> list[Problem]:
    """A guest's ``baseline`` against the set; with a set, a guest must declare one."""
    spec = g.baseline
    if bs is None:
        if spec:
            return [
                Problem(g.id, f"baseline is set but there is no baseline set ({BASELINES_FILE})")
            ]
        return []
    if not spec:
        return [
            Problem(
                g.id,
                "no baseline: add baseline.names from the baseline set, or "
                "baseline.exemption.reason to record why this guest has none",
            )
        ]
    out: list[Problem] = []
    names = list(spec.get("names", []))
    if spec.get("exemption"):
        extra = [k for k in ("names", "add", "remove") if spec.get(k)]
        if extra:
            out.append(
                Problem(g.id, f"baseline.exemption cannot be combined with {', '.join(extra)}")
            )
        return out
    for n in names:
        if n not in bs.baselines:
            out.append(Problem(g.id, f"baseline {n!r} is not defined in the baseline set"))
    _, have = bs.expand(names)
    for c in spec.get("add", []):
        if c not in bs.controls:
            out.append(Problem(g.id, f"baseline.add: control {c!r} is not defined"))
        elif c in have:
            out.append(Problem(g.id, f"baseline.add: {c!r} already comes from its baselines"))
    removed = [r["control"] for r in spec.get("remove", [])]
    if len(removed) != len(set(removed)):
        out.append(Problem(g.id, "baseline.remove names a control twice"))
    for c in removed:
        if c not in bs.controls:
            out.append(Problem(g.id, f"baseline.remove: control {c!r} is not defined"))
        elif c not in have:
            out.append(Problem(g.id, f"baseline.remove: {c!r} is not in its baselines (stale)"))
    return out


def resolve(g: Guest, bs: BaselineSet) -> Resolution:
    """The guest's effective baselines and controls (see the module docstring for the order)."""
    spec = g.baseline
    if not spec:
        return Resolution(g.id, declared=False)
    if spec.get("exemption"):
        return Resolution(g.id, exemption=spec["exemption"])
    names, controls = bs.expand(list(spec.get("names", [])))
    for c in spec.get("add", []):
        if c in bs.controls and c not in controls:
            controls.append(c)
    removed = tuple(r["control"] for r in spec.get("remove", []))
    controls = [c for c in controls if c not in removed]
    by_layer = {layer: tuple(c for c in controls if bs.layer(c) == layer) for layer in LAYERS}
    return Resolution(g.id, tuple(names), tuple(controls), removed, None, True, by_layer)


def coverage(guests: list[Guest], bs: BaselineSet) -> dict[str, Any]:
    """The guest x layer coverage report (``hnx guests baselines --json``)."""
    rows = []
    needed: dict[str, list[str]] = {}
    for g in sorted(guests, key=lambda x: x.id):
        r = resolve(g, bs)
        for c in r.controls:
            needed.setdefault(c, []).append(g.id)
        rows.append(
            {
                "id": g.id,
                "kind": g.kind,
                "scope": g.scope or "in",
                "baselines": list(r.baselines),
                "controls": list(r.controls),
                "removed": list(r.removed),
                "exemption": dict(r.exemption) if r.exemption else None,
                "missing": r.missing,
                "by_layer": {k: list(v) for k, v in r.by_layer.items()},
            }
        )
    unbound = [c for c in bs.ordered_controls() if c in needed and bs.role(c) is None]
    return {
        "layers": list(LAYERS),
        "guests": rows,
        "controls": {
            c: {
                "layer": bs.layer(c),
                "role": bs.role(c),
                "verify": bs.controls[c]["verify"],
                "needed_by": needed.get(c, []),
            }
            for c in bs.ordered_controls()
        },
        "unbound": unbound,
        "summary": {
            "guests": len(rows),
            "with_baseline": sum(1 for r in rows if r["baselines"]),
            "exempt": sum(1 for r in rows if r["exemption"]),
            "missing": sum(1 for r in rows if r["missing"]),
            "controls": len(bs.controls),
            "unbound_needed": len(unbound),
        },
    }


def coverage_text(report: Mapping[str, Any]) -> str:
    """The coverage matrix as aligned text: one row per guest, one column per layer."""
    layers = report["layers"]
    head = ["guest", "baselines", *layers]
    table = [head]
    for r in report["guests"]:
        name = r["id"].removeprefix("guest:")
        if r["missing"]:
            table.append([name, "MISSING", *["-"] * len(layers)])
        elif r["exemption"]:
            table.append([name, "exempt", *["-"] * len(layers)])
        else:
            cells = [str(len(r["by_layer"][x])) if r["by_layer"][x] else "." for x in layers]
            table.append([name, ",".join(r["baselines"]), *cells])
    widths = [max(len(row[i]) for row in table) for i in range(len(head))]
    lines = [
        "  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip() for row in table
    ]
    lines.append("")
    lines.append("cells: controls per layer ('.' none). exemptions:")
    ex = [r for r in report["guests"] if r["exemption"]]
    lines += [f"  {r['id']}: {r['exemption']['reason']}" for r in ex] or ["  none"]
    s = report["summary"]
    lines.append(
        f"{s['guests']} guests: {s['with_baseline']} with a baseline, {s['exempt']} exempt, "
        f"{s['missing']} missing; {s['controls']} controls, "
        f"{s['unbound_needed']} needed but not bound to a role"
        + (f" ({', '.join(report['unbound'])})" if report["unbound"] else "")
    )
    return "\n".join(lines) + "\n"
