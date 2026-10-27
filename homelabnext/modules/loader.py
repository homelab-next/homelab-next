# SPDX-License-Identifier: Apache-2.0
"""The module loader (ADR-0027 follow-up 9; docs/modules.md, "What the loader checks").

It finds the manifests, refuses what cannot be loaded and runs every rule with every input the
rules need, so no rule is skipped because a caller forgot an argument:

1. **Discovery** (:func:`discover`): ``<id>/module.yml`` under the public ``modules/`` tree, a
   fixture root (the fictional ``examples/modules/``, for the contract tests and ``make``) and an
   overlay's ``lab/modules/``.  An overlay module that shadows a shipped id, a directory whose
   name is not its manifest's id, and a reserved id are refused.
2. **Per manifest**: the manifest validates against ``platform/module`` before any rule reads it
   (the rules assume a schema-valid document); every contributed file exists, is a regular file
   inside the module (no symbolic link on the way, realpath containment) and validates against
   its record type (MCP records, service rows, prompt templates, lake tables, interface schemas);
   then :func:`homelabnext.modules.rules.module_problems`.
3. **Across manifests**: :func:`~homelabnext.modules.rules.tree_problems`, and no module name
   (id, service row of a feature or core module) that is one of the core's own names
   (:class:`CoreNames`).
4. **Per site** (with a selection): the selection validates against ``platform/module_selection``,
   then :func:`~homelabnext.modules.rules.site_problems` with the rows, units, privileged units and
   model roles built here, and :func:`homelabnext.modules.supply.lock_problems` for the selected
   modules (a fetched module without a lock is refused; an in-tree-only site needs none).
5. **Two-way, against what runs** (with an inventory, ``platform/module_inventory``): every
   running unit, service row, MCP server, agent and table bound to a module id is declared by
   that module, which the site selects, and every declared one runs.  Without an inventory the
   report says the runtime half was not checked; it never passes silently.

Everything is returned as sorted :class:`Problem` values; :mod:`homelabnext.modules.cli` prints
them.  Reading is deterministic: manifests in sorted order, YAML with duplicate keys refused.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._schema_text import safe_message
from homelabnext._yaml import UniqueKeyLoader
from homelabnext.modules import rules as mr
from homelabnext.modules import supply
from homelabnext.schemas.module_manifest import RESERVED_IDS

Doc = dict[str, Any]

__all__ = [
    "CoreNames",
    "LoaderError",
    "Problem",
    "Report",
    "Tree",
    "check",
    "contributed_files",
    "core_names",
    "discover",
    "inputs",
    "load_yaml",
    "running_problems",
]

#: files a fixture root's modules may name without shipping (the fictional examples carry no
#: Ansible): never skipped for the public tree or an overlay
FIXTURE_UNSHIPPED = ("roles/", "playbooks/")
#: the inventory kinds and, per kind, the separator a running name is bound to its module by
INVENTORY_KINDS = ("units", "rows", "mcp_servers", "agents", "tables")


class LoaderError(ValueError):
    """An input that cannot be read at all (a usage error, exit 2)."""


@dataclass(frozen=True, order=True)
class Problem:
    where: str  # a module id, ``site``, ``lock``, ``running`` or a file
    message: str

    def __str__(self) -> str:
        return f"{self.where}: {self.message}"


@dataclass
class Tree:
    """The discovered manifests: ``mods`` (id -> manifest), ``dirs`` (id -> directory) and
    ``origin`` (id -> ``public``, ``fixture`` or ``overlay``)."""

    mods: dict[str, Doc] = field(default_factory=dict)
    dirs: dict[str, Path] = field(default_factory=dict)
    origin: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CoreNames:
    """Names the core itself uses, which no module may take: the reserved ids
    (:data:`homelabnext.schemas.module_manifest.RESERVED_IDS`) and the service rows of the core
    registry (``services.yml``).  A provider's row is keyed by its slot and renamed to the
    instance at bind time, so only feature and core rows are compared."""

    ids: frozenset[str] = frozenset(RESERVED_IDS)
    rows: frozenset[str] = frozenset()


@dataclass
class Report:
    problems: list[Problem]
    notes: list[str]  # what was not checked, and why

    @property
    def ok(self) -> bool:
        return not self.problems


def load_yaml(path: str | Path) -> Any:
    """A YAML file, duplicate keys refused (the contract tests read the same way)."""
    return yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)


def _schema(*parts: str) -> Doc:
    return json.loads(paths.schema_file(*parts).read_text(encoding="utf-8"))


def _errors(schema: Doc, doc: Any) -> list[str]:
    import jsonschema

    from homelabnext.schema_registry import schema_registry

    v = jsonschema.Draft202012Validator(schema, registry=schema_registry())
    errs = sorted(v.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    return [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {safe_message(e)}" for e in errs]


# ----------------------------------------------------------------------------- discovery


def discover(
    public: Path | None = None, fixtures: Path | None = None, overlay: Path | None = None
) -> tuple[Tree, list[Problem]]:
    """Every ``<id>/module.yml`` under the given roots (``overlay`` is the overlay checkout: its
    ``lab/modules/`` is read).  A manifest that does not parse, names another id than its
    directory, takes a reserved id, or (from the overlay) shadows a shipped one is refused and
    left out of the tree."""
    tree, out = Tree(), []
    roots = [("public", public), ("fixture", fixtures)]
    if overlay is not None:
        roots.append(("overlay", overlay / "lab" / "modules"))
    for origin, root in roots:
        if root is None or not root.is_dir():
            continue
        for mf in sorted(root.glob("*/module.yml")):
            name = mf.parent.name
            try:
                doc = load_yaml(mf)
            except (OSError, yaml.YAMLError, ValueError) as exc:
                out.append(Problem(name, f"module.yml cannot be read ({exc.__class__.__name__})"))
                continue
            if not isinstance(doc, dict):
                out.append(Problem(name, "module.yml is not a mapping"))
                continue
            if doc.get("id") != name:
                out.append(
                    Problem(name, f"the manifest's id {doc.get('id')!r:.60} is not its directory")
                )
                continue
            if name in RESERVED_IDS:
                out.append(Problem(name, "a reserved id"))
                continue
            if name in tree.mods:
                if origin == "overlay":
                    out.append(
                        Problem(
                            name,
                            f"an overlay module shadows the {tree.origin[name]} module of that id",
                        )
                    )
                else:
                    out.append(
                        Problem(
                            name, f"defined under both the {tree.origin[name]} and {origin} roots"
                        )
                    )
                continue
            tree.mods[name], tree.dirs[name], tree.origin[name] = doc, mf.parent, origin
    return tree, out


# ----------------------------------------------------------------------------- per manifest


def contributed_files(doc: Doc) -> Iterator[tuple[str, str]]:
    """``(contribution key, module-relative path)`` for every file a manifest names."""
    c = doc.get("contributes", {})
    for key, entries in c.items():
        for e in entries:
            if isinstance(e, dict):
                for f in ("file", "charter", "spec", "context_manifest"):
                    if f in e:
                        yield key, e[f]
                yield from (("prompts", f) for f in e.get("prompts", {}).values())
    for i in doc.get("interfaces", []):
        if "schema" in i:
            yield "interfaces", i["schema"]
    for e in doc.get("provides", {}).get("slots", {}).values():
        if "conformance" in e:
            yield "conformance", e["conformance"]["target"]


def _file_problems(doc: Doc, mod_dir: Path, fixture: bool) -> list[str]:
    """Each contributed file is a regular file inside the module, reached through no link."""
    out, root = [], mod_dir.resolve()
    for _, rel in contributed_files(doc):
        if fixture and rel.startswith(FIXTURE_UNSHIPPED):
            continue
        p = mod_dir / rel
        hops = [mod_dir / Path(*Path(rel).parts[: i + 1]) for i in range(len(Path(rel).parts))]
        if any(h.is_symlink() for h in hops):
            out.append(f"{rel}: reached through a symbolic link")
        elif not p.is_file():
            out.append(f"{rel}: not a regular file in the module")
        elif not p.resolve().is_relative_to(root):
            out.append(f"{rel}: outside the module")
    return out


def _record_problems(doc: Doc, mod_dir: Path) -> list[str]:
    """Each contributed record validates against its record type."""
    out: list[str] = []
    c, mid = doc.get("contributes", {}), doc["id"]

    def each(entries, schema, what):
        for e in entries:
            try:
                rec = load_yaml(mod_dir / e)
            except (OSError, yaml.YAMLError, ValueError) as exc:
                out.append(f"{e}: cannot be read ({exc.__class__.__name__})")
                continue
            out.extend(f"{e}: {what}: {m}" for m in _errors(schema, rec))
            yield e, rec

    for e, rec in each(
        [x["file"] for x in c.get("mcp_servers", [])],
        _schema("platform", "mcp_server.schema.json"),
        "MCP record",
    ):
        if isinstance(rec, dict) and rec.get("id") != Path(e).stem:
            out.append(f"{e}: an MCP record's id is its file name")
    service = _schema("platform", "service.json")
    row_schema = {"$ref": service["$id"] + "#/$defs/service"}
    for e in [x["file"] for x in c.get("services", [])]:
        try:
            rows = load_yaml(mod_dir / e)["services"]
        except (OSError, yaml.YAMLError, ValueError, KeyError, TypeError) as exc:
            out.append(f"{e}: cannot be read as service rows ({exc.__class__.__name__})")
            continue
        for name, r in rows.items():
            if doc["kind"] == "provider":
                if "version" in r:
                    out.append(
                        f"{e}: {name}: a provider's row takes its version from product.version"
                    )
                r = {**r, "version": str(doc.get("product", {}).get("version"))}
            out.extend(f"{e}: {name}: {m}" for m in _errors(row_schema, r))
    prompts = [f for a in c.get("agents", []) for f in a.get("prompts", {}).values()]
    list(each(prompts, _schema("agent", "prompt_template.schema.json"), "prompt template"))
    for e, rec in each(
        [x["file"] for x in c.get("lake_tables", [])],
        _schema("platform", "lake_table.schema.json"),
        "lake table",
    ):
        if isinstance(rec, dict) and rec.get("owner") != mid:
            out.append(f"{e}: a lake table's owner is the module")
    for i in doc.get("interfaces", []):
        if "schema" not in i:
            continue
        try:
            s = json.loads((mod_dir / i["schema"]).read_text(encoding="utf-8"))
            import jsonschema

            jsonschema.Draft202012Validator.check_schema(s)
        except (OSError, ValueError) as exc:
            out.append(f"{i['schema']}: not a JSON Schema ({exc.__class__.__name__})")
            continue
        except Exception as exc:  # jsonschema's SchemaError
            out.append(f"{i['schema']}: not a JSON Schema ({safe_message(exc)})")
            continue
        if f"/modules/{mid}/" not in str(s.get("$id", "")):
            out.append(f"{i['schema']}: its $id is not in the owning module's namespace")
    return out


# ----------------------------------------------------------------------------- inputs


@dataclass(frozen=True)
class Inputs:
    """What the site rules and the generators read from the manifests' contributed files."""

    rows: dict[str, dict[str, Doc]]
    units: dict[str, set[str]]
    privileged_units: dict[str, set[str]]


def inputs(tree: Tree) -> Inputs:
    """Rows, unit names and privileged unit names per module (each from its contributed files)."""
    rows, units, priv = {}, {}, {}
    for n, m in tree.mods.items():
        d = tree.dirs[n]
        rows[n] = mr._rows(m, d, load_yaml)
        units[n] = mr._units(m, d, load_yaml)
        priv[n] = mr._privileged_units(m, d, load_yaml)
    return Inputs(rows, units, priv)


def core_names(services: Mapping[str, Any] | None) -> CoreNames:
    """The core's names from its service registry (``services.yml``; None: the reserved ids only)."""
    rows = frozenset(map(str, (services or {}).get("services", {}) or {}))
    return CoreNames(rows=rows)


def _core_problems(tree: Tree, ins: Inputs, core: CoreNames) -> list[Problem]:
    out = []
    for n in sorted(tree.mods):
        if n in core.rows:
            out.append(Problem(n, "the module id is a core service name"))
        if tree.mods[n]["kind"] == "provider":
            continue
        out += [
            Problem(n, f"service row {r} is a core service name")
            for r in sorted(set(ins.rows[n]) & core.rows)
        ]
    return out


# ----------------------------------------------------------------------------- two-way, running


def _declared(
    tree: Tree, ins: Inputs, site: Doc, sel: Mapping[str, Doc]
) -> dict[str, dict[str, str]]:
    """Per inventory kind, ``{name: module}`` for what the selected modules declare.  A
    provider's service row is the instance the site names, not its slot key."""
    out: dict[str, dict[str, str]] = {k: {} for k in INVENTORY_KINDS}
    chosen = [c for v in site.get("slots", {}).values() if isinstance(v, list) for c in v]
    for n, m in sel.items():
        d = tree.dirs[n]
        out["units"].update(dict.fromkeys(ins.units[n], n))
        if m["kind"] == "provider" and ins.rows[n]:
            out["rows"].update({c["instance"]: n for c in chosen if c["provider"] == n})
        elif m["kind"] != "provider":
            out["rows"].update(dict.fromkeys(ins.rows[n], n))
        out["mcp_servers"].update(dict.fromkeys(mr._mcp_ids(m, d, load_yaml), n))
        out["agents"].update({a["key"]: n for a in mr._agents(m)})
        out["tables"].update({x["table"]: n for x in m.get("data", []) if "table" in x})
    return out


def _bound_to(kind: str, name: str, ids: set[str]) -> str | None:
    """The module a running name is bound to (``table:<id_>.<name>``; ``<id>`` or ``<id>-...``)."""
    if kind == "tables":
        schema = name.removeprefix("table:").split(".", 1)[0]
        return next((i for i in sorted(ids) if mr.us(i) == schema), None)
    return mr._owner(name, ids, "-")


def running_problems(
    tree: Tree, ins: Inputs, site: Doc, sel: Mapping[str, Doc], inventory: Doc
) -> list[Problem]:
    """Every running name bound to a module id is declared by that module, which the site
    selects; every declared name runs.  A name bound to no module id is the core's and is not
    judged here."""
    declared = _declared(tree, ins, site, sel)
    ids = set(tree.mods)
    out = []
    for kind in INVENTORY_KINDS:
        running = set(inventory.get(kind, []))
        for name in sorted(running - set(declared[kind])):
            owner = _bound_to(kind, name, ids)
            if owner is None:
                continue
            if owner not in sel:
                out.append(
                    Problem(
                        "running", f"{kind} {name} runs for {owner}, which the site does not select"
                    )
                )
            else:
                out.append(
                    Problem("running", f"{kind} {name} runs but {owner} declares no such entry")
                )
        for name in sorted(set(declared[kind]) - running):
            out.append(
                Problem(
                    "running", f"{kind} {name} ({declared[kind][name]}) is declared but not running"
                )
            )
    return out


# ----------------------------------------------------------------------------- the check


def check(
    tree: Tree,
    *,
    slots: Mapping[str, Doc],
    roles: Mapping[str, Doc],
    in_tree_roots: tuple[Path, ...],
    core: CoreNames | None = None,
    site: Doc | None = None,
    lock: Any = None,
    policy: Any = None,
    inventory: Doc | None = None,
) -> Report:
    """Every rule of "What the loader checks" over ``tree``; with ``site`` the site rules and
    the supply chain, with ``inventory`` the runtime half of the two-way check."""
    problems: list[Problem] = []
    notes: list[str] = []
    module_schema = _schema("platform", "module.schema.json")
    valid: dict[str, Doc] = {}
    for n in sorted(tree.mods):
        errs = _errors(module_schema, tree.mods[n])
        if errs:
            problems += [Problem(n, f"schema: {e}") for e in errs]
            continue
        valid[n] = tree.mods[n]
    vtree = Tree(valid, {n: tree.dirs[n] for n in valid}, {n: tree.origin[n] for n in valid})
    for n, m in valid.items():
        d = tree.dirs[n]
        problems += [Problem(n, p) for p in _file_problems(m, d, tree.origin[n] == "fixture")]
        problems += [Problem(n, p) for p in _record_problems(m, d)]
        try:
            problems += [
                Problem(n, p)
                for p in mr.module_problems(m, d, dict(slots), load_yaml, in_tree_roots)
            ]
        except Exception as exc:  # a contributed file the rules cannot read
            problems.append(
                Problem(n, f"the module rules could not read it ({exc.__class__.__name__}: {exc})")
            )
    try:
        ins = inputs(vtree)
    except Exception as exc:
        problems.append(
            Problem("modules", f"a contributed file cannot be read ({exc.__class__.__name__})")
        )
        return Report(sorted(set(problems)), notes)
    problems += [Problem("modules", p) for p in mr.tree_problems(valid, vtree.dirs, load_yaml)]
    problems += _core_problems(vtree, ins, core or CoreNames())
    if not tree.mods:
        notes.append("no module manifests were found under the given roots")
    if site is None:
        notes.append(
            "no site selection: the site rules, the supply chain and the runtime check did not run"
        )
        return Report(sorted(set(problems)), notes)
    errs = _errors(_schema("platform", "module_selection.schema.json"), site)
    if errs:
        problems += [Problem("site", f"schema: {e}") for e in errs]
        return Report(sorted(set(problems)), notes)
    if set(tree.mods) - set(valid):
        notes.append("the site rules ran without the manifests that failed their schema")
    problems += [
        Problem("site", p)
        for p in mr.site_problems(
            site, valid, dict(slots), rows=ins.rows, units=ins.units,
            privileged_units=ins.privileged_units, roles=dict(roles),
        )
    ]  # fmt: skip
    try:
        sel = mr.selected(site, valid)
    except KeyError:
        return Report(sorted(set(problems)), notes)  # site_problems reported it
    fetched = [n for n, m in sel.items() if m.get("origin", {}).get("kind") != "in-tree"]
    if lock is not None or fetched:
        the_lock = (
            lock if lock is not None else {"schema_version": supply.LOCK_VERSION, "modules": {}}
        )
        if lock is None:
            notes.append("no lock file: every fetched module is refused")
        problems += [
            Problem("lock", p)
            for p in supply.lock_problems(sel, tree.dirs, the_lock, policy, in_tree_roots)
        ]
    if inventory is None:
        notes.append("no inventory of what runs: the runtime half of the two-way check did not run")
    else:
        errs = _errors(_schema("platform", "module_inventory.schema.json"), inventory)
        if errs:
            problems += [Problem("running", f"schema: {e}") for e in errs]
        else:
            problems += running_problems(vtree, ins, site, sel, inventory)
    return Report(sorted(set(problems)), notes)


def units_fn(ins: Inputs) -> Callable[[str], set[str]]:
    return lambda mid: ins.units.get(mid, set())


def rows_fn(ins: Inputs) -> Callable[[str], dict[str, Doc]]:
    return lambda mid: ins.rows.get(mid, {})
