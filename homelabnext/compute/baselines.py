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

A bound role reaches a guest in one of two ways (``apply``, baseline set 1.1, ADR-0016 decision 7):
``guest`` (the default) runs it on every guest that needs the control; ``central`` runs it once on
the central product host (the ``group`` inventory group, e.g. ``cap_sensor``) and hands it the
guests that need the control, which that product enrolls (monitored addresses, scan targets).

**Settings** (baseline set 1.2): a baseline lists a control as its id or as ``{id, with}``; ``with``
sets inputs of the control's bound role, named as that role's ``meta/argument_specs.yml`` main
options without the ``<role>_`` prefix and typed there (the one source of truth; a control's
``settings`` list may narrow which inputs a baseline may set).  A guest's settings for a control
merge over the baselines it resolves to, parents first, so a baseline overrides what the
baselines it extends set.  Two baselines that set one input differently are a conflict unless the
last of them extends the other; a guest file carries no settings of its own (a per-guest value is a
one-guest baseline that extends the shared one, so every value is reviewed in the set).  The
settings reach a role as its prefixed variables (:func:`role_vars`).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._schema_text import safe_message
from homelabnext._yaml import UniqueKeyStrDateLoader
from homelabnext.generators.safe import control_char_paths

from .model import ComputeError, ComputeUnreadable, Guest, Problem, allowed_groups

BASELINES_FILE = "_baselines.yml"
#: how a control's role reaches a guest (baseline set 1.1): on the guest, or on a central host
APPLY_GUEST = "guest"
APPLY_CENTRAL = "central"
#: the defense-in-depth layers, outermost concern first; a closed set (the schema's enum)
LAYERS: tuple[str, ...] = ("identity", "host", "network", "detection", "data", "recovery")
WHERE = BASELINES_FILE
#: where the bound roles' meta/argument_specs.yml are read from (settings are checked against them)
ROLES_DIR_ENV = "HNX_ROLES_DIR"
#: argument_specs ``type`` -> the Python types a ``with`` value of that type may have
SPEC_TYPES: dict[str, tuple[type, ...]] = {
    "str": (str,),
    "path": (str,),
    "int": (int,),
    "float": (int, float),
    "bool": (bool,),
    "list": (list,),
    "dict": (dict,),
    "raw": (object,),
}


def control_id(entry: Any) -> str:
    """A baseline's ``controls`` entry: a control id, or ``{id, with}`` (1.2)."""
    return entry["id"] if isinstance(entry, Mapping) else entry


def default_roles_dir() -> Path | None:
    """``$HNX_ROLES_DIR``, else the checkout's ``ansible/roles`` (None in a bare wheel install)."""
    if os.environ.get(ROLES_DIR_ENV):
        return Path(os.environ[ROLES_DIR_ENV])
    root = paths.checkout_root()
    return root / "ansible" / "roles" if root else None


def role_options(role: str, roles_dir: Path | None) -> dict[str, dict[str, Any]] | None:
    """The role's ``main`` options from its argument_specs, keyed without the role prefix; None
    when the file cannot be found."""
    if roles_dir is None:
        return None
    spec = roles_dir / role / "meta" / "argument_specs.yml"
    try:
        doc = yaml.safe_load(spec.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None
    opts = ((doc.get("argument_specs") or {}).get("main") or {}).get("options") or {}
    prefix = f"{role}_"
    return {k.removeprefix(prefix): dict(v) for k, v in opts.items() if k.startswith(prefix)}


def _type_problem(value: Any, spec: Mapping[str, Any]) -> str | None:
    want = spec.get("type", "raw")
    types = SPEC_TYPES.get(want, (object,))
    if isinstance(value, bool) and bool not in types and object not in types:
        return f"is {value!r}, not a {want}"
    if not isinstance(value, types):
        return f"is {type(value).__name__} {value!r}, not a {want}"
    if "choices" in spec and value not in spec["choices"]:
        return f"is {value!r}, not one of {spec['choices']}"
    elements = spec.get("elements")
    if want == "list" and elements in SPEC_TYPES:
        for item in value:
            if (r := _type_problem(item, {"type": elements})) is not None:
                return f"has an element that {r}"
    return None


@dataclass(frozen=True)
class BaselineSet:
    """A schema-valid baseline set: ``controls`` and ``baselines`` as written."""

    controls: Mapping[str, Mapping[str, Any]]
    baselines: Mapping[str, Mapping[str, Any]]
    source: str = WHERE
    roles_dir: Path | None = None

    def layer(self, control: str) -> str:
        return self.controls[control]["layer"]

    def role(self, control: str) -> str | None:
        return self.controls[control].get("role")

    def apply(self, control: str) -> str:
        """``guest`` (the default) or ``central``."""
        return self.controls[control].get("apply", APPLY_GUEST)

    def group(self, control: str) -> str | None:
        """The central product host's inventory group (``apply: central``), else None."""
        return self.controls[control].get("group")

    def own_controls(self, baseline: str) -> list[str]:
        """The control ids a baseline lists itself (``extends`` not followed)."""
        return [control_id(e) for e in self.baselines[baseline].get("controls", [])]

    def own_settings(self, baseline: str) -> dict[str, dict[str, Any]]:
        """``{control: {input: value}}`` a baseline sets itself (1.2 ``with``)."""
        out: dict[str, dict[str, Any]] = {}
        for e in self.baselines[baseline].get("controls", []):
            if isinstance(e, Mapping) and e.get("with"):
                out.setdefault(e["id"], {}).update(e["with"])
        return out

    def ancestors(self, baseline: str) -> set[str]:
        """Every baseline ``baseline`` extends, directly or through others."""
        seen: set[str] = set()
        todo = list(self.baselines.get(baseline, {}).get("extends", []))
        while todo:
            b = todo.pop()
            if b in seen or b not in self.baselines:
                continue
            seen.add(b)
            todo += self.baselines[b].get("extends", [])
        return seen

    def settings(
        self, names: list[str]
    ) -> tuple[dict[str, dict[str, Any]], list[tuple[str, str, str, Any, str, Any]]]:
        """The merged settings of the baselines ``names`` resolve to, and the conflicts.

        Baselines merge in resolution order (parents first), so a later one overrides; a value
        is a conflict when the baseline that set the final value does not extend the one that
        set a different value.  Conflicts are ``(control, input, baseline, value, baseline,
        value)``."""
        order, _ = self.expand(names)
        setters: dict[tuple[str, str], list[tuple[str, Any]]] = {}
        for b in order:
            for c, kv in self.own_settings(b).items():
                for k, v in kv.items():
                    setters.setdefault((c, k), []).append((b, v))
        merged: dict[str, dict[str, Any]] = {}
        conflicts = []
        for (c, k), rows in setters.items():
            last_b, last_v = rows[-1]
            merged.setdefault(c, {})[k] = last_v
            up = self.ancestors(last_b)
            for b, v in rows[:-1]:
                if v != last_v and b not in up:
                    conflicts.append((c, k, b, v, last_b, last_v))
        return merged, conflicts

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
            for c in self.own_controls(b):
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
    #: control -> {input: value} (1.2 ``with``), for the controls the guest needs
    settings: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    @property
    def missing(self) -> bool:
        """Neither a baseline nor an exemption."""
        return not self.declared


def schema() -> dict:
    return json.loads(
        paths.schema_file("platform", "baseline_set.schema.json").read_text(encoding="utf-8")
    )


def load_baselines(
    path: str | Path, roles_dir: Path | None = None
) -> tuple[BaselineSet | None, list[Problem]]:
    """Read and schema-check a baseline set.  ``(None, problems)`` when it cannot be used.
    ``roles_dir`` holds the bound roles settings are checked against (:func:`default_roles_dir`)."""
    import jsonschema

    p = Path(path)
    try:
        doc = yaml.load(p.read_text(encoding="utf-8"), Loader=UniqueKeyStrDateLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ComputeUnreadable(f"cannot read baseline set {p}: {exc}") from exc
    where = p.name
    out = [Problem(where, f"unsafe: {m}") for m in control_char_paths(doc)]
    validator = jsonschema.Draft202012Validator(schema())
    for err in sorted(validator.iter_errors(doc), key=lambda e: [str(x) for x in e.absolute_path]):
        loc = "/".join(str(x) for x in err.absolute_path) or "<root>"
        out.append(Problem(where, f"schema: {loc}: {safe_message(err)}"))
    if out:
        return None, out
    rd = roles_dir if roles_dir is not None else default_roles_dir()
    return BaselineSet(dict(doc["controls"]), dict(doc["baselines"]), where, rd), []


def set_problems(bs: BaselineSet) -> list[Problem]:
    """What the schema cannot say about a set: names that resolve, no cycles, no empty baseline."""
    out: list[Problem] = []
    w = bs.source
    for c, spec in sorted(bs.controls.items()):
        if spec.get("layer") not in LAYERS:  # the schema's enum; kept for sets built in code
            out.append(Problem(w, f"control {c!r} is in no known layer ({', '.join(LAYERS)})"))
        out += _apply_problems(w, c, spec)
    for b, spec in sorted(bs.baselines.items()):
        for parent in spec.get("extends", []):
            if parent not in bs.baselines:
                out.append(Problem(w, f"baseline {b!r} extends {parent!r}, which is not defined"))
        for c in bs.own_controls(b):
            if c not in bs.controls:
                out.append(Problem(w, f"baseline {b!r} names control {c!r}, which is not defined"))
    out += settings_problems(bs)
    for cycle in _cycles(bs):
        out.append(Problem(w, "extends cycle: " + " -> ".join(cycle)))
    for b in sorted(bs.baselines):
        if not bs.expand([b])[1]:
            out.append(
                Problem(w, f"baseline {b!r} resolves to no controls (use a guest exemption)")
            )
    return out


def settings_problems(bs: BaselineSet) -> list[Problem]:
    """1.2 settings: each control's ``settings`` and each baseline's ``with`` name inputs of the
    bound role, with values of the type its argument_specs gives; a baseline's own merge (through
    ``extends``) has no conflict."""
    out: list[Problem] = []
    w = bs.source
    opts: dict[str, dict[str, dict[str, Any]] | None] = {}

    def options(c: str) -> dict[str, dict[str, Any]] | None:
        role = bs.role(c)
        if role and role not in opts:
            opts[role] = role_options(role, bs.roles_dir)
        return opts.get(role) if role else None

    for c, spec in sorted(bs.controls.items()):
        if not spec.get("settings"):
            continue
        o = options(c)
        if bs.role(c) is None:
            out.append(Problem(w, f"control {c!r} declares settings but is bound to no role"))
        elif o is None:
            if bs.roles_dir is None:
                continue  # a bare install ships no roles: nothing to check settings against
            out.append(
                Problem(
                    w,
                    f"control {c!r}: cannot read the meta/argument_specs.yml of role {bs.role(c)!r} under {bs.roles_dir} (set {ROLES_DIR_ENV})",
                )
            )
        else:
            for k in spec["settings"]:
                if k not in o:
                    out.append(
                        Problem(
                            w,
                            f"control {c!r}: setting {k!r} is not an input of role {bs.role(c)!r}",
                        )
                    )
    for b in sorted(bs.baselines):
        for c, kv in sorted(bs.own_settings(b).items()):
            if c not in bs.controls:
                continue  # reported as an undefined control
            where = f"baseline {b!r}, control {c!r}"
            o = options(c)
            if bs.role(c) is None:
                out.append(
                    Problem(w, f"{where}: `with` needs a bound role to check its settings against")
                )
                continue
            if o is None:
                if bs.roles_dir is None:
                    continue  # a bare install ships no roles: nothing to check settings against
                out.append(
                    Problem(
                        w,
                        f"{where}: cannot read the meta/argument_specs.yml of role {bs.role(c)!r} under {bs.roles_dir} (set {ROLES_DIR_ENV})",
                    )
                )
                continue
            allowed = bs.controls[c].get("settings")
            for k, v in sorted(kv.items()):
                if k not in o:
                    out.append(
                        Problem(
                            w,
                            f"{where}: unknown setting {k!r} (role {bs.role(c)!r} has no input {bs.role(c)}_{k})",
                        )
                    )
                elif allowed is not None and k not in allowed:
                    out.append(
                        Problem(
                            w, f"{where}: setting {k!r} is not in the control's settings {allowed}"
                        )
                    )
                elif (r := _type_problem(v, o[k])) is not None:
                    out.append(Problem(w, f"{where}: setting {k!r} {r}"))
        _, conflicts = bs.settings([b])
        out += [Problem(w, f"baseline {b!r}: " + _conflict_text(x)) for x in conflicts]
    return out


def _conflict_text(x: tuple[str, str, str, Any, str, Any]) -> str:
    c, k, b1, v1, b2, v2 = x
    return (
        f"setting {c}.{k} is {v1!r} in {b1!r} and {v2!r} in {b2!r}, and neither extends the "
        "other (set it in one baseline that extends both, or in one place)"
    )


def role_vars(bs: BaselineSet, r: Resolution, central: bool = False) -> dict[str, Any]:
    """A guest's settings as role variables (``<role>_<input>``) for the controls applied per
    guest (``central=False``) or centrally (``central=True``); a variable two controls set
    differently is reported by :func:`guest_problems` and keeps the first value here."""
    out: dict[str, Any] = {}
    for c in r.controls:
        role = bs.role(c)
        if role is None or (bs.apply(c) == APPLY_CENTRAL) is not central:
            continue
        for k, v in sorted(r.settings.get(c, {}).items()):
            out.setdefault(f"{role}_{k}", v)
    return out


def _apply_problems(w: str, c: str, spec: Mapping[str, Any]) -> list[Problem]:
    """``apply``/``group`` agree (the schema cannot say so without stopping being additive)."""
    apply, group = spec.get("apply", APPLY_GUEST), spec.get("group")
    if apply == APPLY_CENTRAL and not group:
        return [
            Problem(
                w,
                f"control {c!r} is applied centrally but names no group "
                "(the inventory group of its central product host, e.g. cap_sensor)",
            )
        ]
    if apply != APPLY_CENTRAL and group:
        return [
            Problem(
                w,
                f"control {c!r} names group {group!r} but is applied per guest "
                "(set apply: central, or drop group)",
            )
        ]
    if group and group not in allowed_groups():
        return [
            Problem(
                w,
                f"control {c!r}: group {group!r} is not a known inventory group "
                "(docs/role-interface.md section 5)",
            )
        ]
    return []


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
    _, conflicts = bs.settings(names)
    out += [Problem(g.id, _conflict_text(x)) for x in conflicts]
    if out or any(c not in bs.controls for b in bs.expand(names)[0] for c in bs.own_controls(b)):
        return out  # settings are read once the names resolve
    r = resolve(g, bs)
    seen: dict[str, tuple[str, Any]] = {}
    for c in r.controls:
        for k, v in r.settings.get(c, {}).items():
            var = f"{bs.role(c)}_{k}"
            if var in seen and seen[var][1] != v:
                out.append(
                    Problem(
                        g.id,
                        f"{var} is {seen[var][1]!r} for {seen[var][0]} and {v!r} for {c} (one role, two values)",
                    )
                )
            seen.setdefault(var, (c, v))
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
    merged, _ = bs.settings(list(spec.get("names", [])))
    settings = {c: merged[c] for c in controls if c in merged}
    return Resolution(g.id, tuple(names), tuple(controls), removed, None, True, by_layer, settings)


def coverage(guests: list[Guest], bs: BaselineSet) -> dict[str, Any]:
    """The guest x layer coverage report (``hnx guests baselines --json``).

    ``unplaced``: centrally applied, bound controls some guest needs whose ``group`` holds no
    guest of the model, so the play has nowhere to run (``--require-bound`` fails on them)."""
    rows = []
    needed: dict[str, list[str]] = {}
    in_group: set[str] = {grp for g in guests for grp in g.groups}
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
                "settings": {c: dict(v) for c, v in r.settings.items()},
            }
        )
    unbound = [c for c in bs.ordered_controls() if c in needed and bs.role(c) is None]
    unplaced = [
        c
        for c in bs.ordered_controls()
        if c in needed
        and bs.role(c) is not None
        and bs.apply(c) == APPLY_CENTRAL
        and bs.group(c) not in in_group
    ]
    return {
        "layers": list(LAYERS),
        "guests": rows,
        "controls": {
            c: {
                "layer": bs.layer(c),
                "role": bs.role(c),
                "apply": bs.apply(c),
                "group": bs.group(c),
                "verify": bs.controls[c]["verify"],
                "needed_by": needed.get(c, []),
            }
            for c in bs.ordered_controls()
        },
        "unbound": unbound,
        "unplaced": unplaced,
        "settings": non_default_settings(bs),
        "summary": {
            "guests": len(rows),
            "with_baseline": sum(1 for r in rows if r["baselines"]),
            "exempt": sum(1 for r in rows if r["exemption"]),
            "missing": sum(1 for r in rows if r["missing"]),
            "controls": len(bs.controls),
            "unbound_needed": len(unbound),
            "unplaced_needed": len(unplaced),
        },
    }


def non_default_settings(bs: BaselineSet) -> list[dict[str, Any]]:
    """Every value a baseline sets (1.2 ``with``) that differs from the bound role's own default:
    ``{baseline, control, setting, value, default}``, by baseline then control then setting.  A
    required input has no default (``None``) and is always listed."""
    out: list[dict[str, Any]] = []
    for b in sorted(bs.baselines):
        for c, kv in sorted(bs.own_settings(b).items()):
            role = bs.role(c) if c in bs.controls else None
            opts = (role_options(role, bs.roles_dir) if role else None) or {}
            for k, v in sorted(kv.items()):
                default = opts.get(k, {}).get("default")
                if v != default:
                    out.append(
                        {"baseline": b, "control": c, "setting": k, "value": v, "default": default}
                    )
    return out


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
    central = {c: i for c, i in report["controls"].items() if i["apply"] == APPLY_CENTRAL}
    lines.append("central controls (one play on the product host, which enrolls the guests):")
    lines += [
        f"  {c}: {i['role'] or 'not bound'} on {i['group']}, {len(i['needed_by'])} guests"
        + (" (NO HOST: no guest is in that group)" if c in report["unplaced"] else "")
        for c, i in central.items()
    ] or ["  none"]
    lines.append("settings (baseline with:, where they differ from the role's default):")
    lines += [
        f"  {x['baseline']}: {x['control']} {x['setting']}={json.dumps(x['value'], sort_keys=True)}"
        for x in report.get("settings", [])
    ] or ["  none"]
    s = report["summary"]
    lines.append(
        f"{s['guests']} guests: {s['with_baseline']} with a baseline, {s['exempt']} exempt, "
        f"{s['missing']} missing; {s['controls']} controls, "
        f"{s['unbound_needed']} needed but not bound to a role"
        + (f" ({', '.join(report['unbound'])})" if report["unbound"] else "")
    )
    return "\n".join(lines) + "\n"
