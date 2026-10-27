# SPDX-License-Identifier: Apache-2.0
"""The module loader (ADR-0027 follow-up 9; docs/modules.md, "What the loader checks").

It finds the manifests, refuses what cannot be loaded and runs every rule with every input the
rules need, so no rule is skipped because a caller forgot an argument:

1. **Discovery** (:func:`discover`): ``<id>/module.yml`` under the public ``modules/`` tree, a
   fixture root (the fictional ``examples/modules/``, for the contract tests and ``make``) and an
   overlay's ``lab/modules/``.  A manifest that cannot be read, a symbolic-link module directory
   or manifest, a directory whose name is not its manifest's id, a reserved id, an id under two
   shipped roots and an overlay module that shadows a shipped id are refused.
2. **Per manifest**: the manifest validates against ``platform/module`` before any rule reads it
   (the rules assume a schema-valid document).  Every contributed file is a regular file inside
   the module, reached through no symbolic link, with one link (a hard link could alias a file
   outside the module).  A module with a file that fails is not read further.  The kinds that
   have a record type are validated against it (:data:`VALIDATED_KINDS`); the others are
   checked for containment only, and the report says which.  Then
   :func:`homelabnext.modules.rules.module_problems`.
3. **Across manifests**: :func:`~homelabnext.modules.rules.tree_problems`, and no module id,
   feature or core service row, MCP server id, agent key, table, table namespace or notify pair
   title that is one of the core's own names (:class:`CoreNames`).
4. **Per site** (with a selection): the selection validates against ``platform/module_selection``,
   then :func:`~homelabnext.modules.rules.site_problems` with the rows, units, privileged units and
   model roles built here, no provider instance that takes a core service name for another
   capability, one declaration per notify pair problem title and a recovery that names no other
   title (:func:`pair_problems`), and
   :func:`homelabnext.modules.supply.lock_problems` for the selected modules (a
   fetched module without a lock is refused; an in-tree-only site needs none).
5. **Two-way, against what runs** (with an inventory, ``platform/module_inventory``): every
   running unit, service row, MCP server, agent and table bound to a module id is declared by
   that module, which the site selects, and every declared one runs; with the inventory's
   ``notify_pairs``, the same for the running notifier's recovery pairs, compared by both titles.

What was not checked is a note in the report, never a pass.  Every file is read the same way
(:func:`read_bytes`): opened without blocking, a regular file only, at most :data:`MAX_BYTES`;
YAML with duplicate keys and aliases refused, and a document nested too deeply refused.  The
files of one module, and of the whole run, are held to a :class:`Budget`, and each contributed
file is read and parsed once per run (:class:`ModuleReader`), so a planted tree cannot stall
the run.  A file that breaks any of these is a named problem, never a skip and never an internal
error.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping
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
    "MAX_BYTES",
    "MODULE_BYTES",
    "RUN_BYTES",
    "VALIDATED_KINDS",
    "Budget",
    "CoreNames",
    "LoaderError",
    "ModuleReader",
    "Problem",
    "Report",
    "Tree",
    "Unreadable",
    "check",
    "contributed_files",
    "core_mcp_records",
    "core_names",
    "core_table_names",
    "discover",
    "inputs",
    "load_input",
    "load_json",
    "load_yaml",
    "pair_problems",
    "path_has_symlink",
    "read_bytes",
    "read_tree_file",
    "running_pair_problems",
    "running_problems",
]

#: the largest file the loader reads (a manifest, a record, the selection, the inventory, the role
#: table, the registry, the lock; one cap for all): a larger one is refused, never skipped
MAX_BYTES = 1_000_000  # no input needs more: the largest example (services.yml) is 13 kB
#: what one module's files, and the whole run's, may add up to; refused once spent (a parse of
#: dense YAML runs at well under a megabyte a second, so these bound the run's time)
MODULE_BYTES = 2_000_000
RUN_BYTES = 8_000_000
#: the most entries a core catalog directory (the MCP catalog, the OCSF tables) may hold: a larger
#: one is refused, never read in part (the core's are a few dozen)
MAX_CATALOG_FILES = 1_000
#: files a fixture root's modules may name without shipping (the fictional examples carry no
#: Ansible): never exempt for the public tree or an overlay
FIXTURE_UNSHIPPED = ("roles/", "playbooks/")
#: the kinds of what runs that the two-way check compares, as the inventory names them
INVENTORY_KINDS = ("units", "rows", "mcp_servers", "agents", "tables")
#: contributed kinds validated against a record type (the rest are checked for containment only)
VALIDATED_KINDS = (
    "mcp_servers",  # platform/mcp_server
    "services",  # platform/service rows
    "prompts",  # agent/prompt_template
    "lake_tables",  # platform/lake_table
    "interfaces",  # a JSON Schema, in the owner's $id namespace
    "scheduler_jobs",  # the fleet_units validator (module_problems)
    "detections",  # a Sigma rule (homelabnext.detections.sigma)
)


class LoaderError(ValueError):
    """An input that cannot be read at all (a usage error, exit 2)."""


class Unreadable(ValueError):
    """A file the loader refuses to read: not a regular file, too large, not UTF-8, not valid
    YAML or JSON, with an alias, or nested too deeply."""


def _shown(text: str) -> str:
    """An untrusted name as it is printed: as is when it is a plain identifier, else quoted with
    every control character escaped, so it cannot carry a terminal escape, a line break or a CI
    workflow command."""
    s = str(text)
    plain = s and all(c.isalnum() or c in "-_.:/@+ " for c in s) and not s.startswith("::")
    return s if plain and s.isascii() else repr(s)


@dataclass(frozen=True, order=True)
class Problem:
    where: str  # a module id, ``site``, ``lock``, ``running``, ``registry`` or a file
    message: str

    def __str__(self) -> str:
        line = f"{_shown(self.where)}: {self.message}"
        return "".join(c if c.isprintable() else repr(c)[1:-1] for c in line)


@dataclass
class Tree:
    """The discovered manifests: ``mods`` (id -> manifest), ``dirs`` (id -> directory) and
    ``origin`` (id -> ``public``, ``fixture`` or ``overlay``)."""

    mods: dict[str, Doc] = field(default_factory=dict)
    dirs: dict[str, Path] = field(default_factory=dict)
    origin: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CoreNames:
    """Names the core itself uses, which no module may take, each read from a source the core
    already has (:func:`core_names`), never from a list kept for this check:

    * ``ids``: the reserved ids (:data:`homelabnext.schemas.module_manifest.RESERVED_IDS`);
    * ``rows``: the service rows of the core registry (``services.yml``), each with its capability;
    * ``mcp_servers``: the ids of the core's MCP catalog (``mcp/`` beside the registry);
    * ``agents``: the agent keys of the keyring's agent principals (``profile:<key>``), the
      generated map of every principal (``hnx agent keyring build``);
    * ``tables`` and ``table_namespace``: the core's OCSF tables (``schemas/ocsf``) and the lake
      namespace they live in (:data:`homelabnext.lake.tables.CORE_NAMESPACE`);
    * ``pairs``: the core's own notify pairs, problem title to recovery title
      (:data:`homelabnext.notify.core_pairs.CORE_PAIRS`, the list the core registers from).

    The core's own units have no source to read (no fleet_units spec of the core's is in the
    repository), so they are not compared; a module's units carry its id, which a core name
    never is."""

    ids: frozenset[str] = frozenset(RESERVED_IDS)
    rows: Mapping[str, str] = field(default_factory=dict)  # row name -> capability
    mcp_servers: frozenset[str] = frozenset()
    agents: frozenset[str] = frozenset()
    tables: frozenset[str] = frozenset()  # table:<namespace>.<name>
    table_namespace: str | None = None
    pairs: Mapping[str, str] = field(default_factory=dict)  # problem title -> recovery title


@dataclass
class Report:
    problems: list[Problem]
    notes: list[str]  # what was not checked, and why

    @property
    def ok(self) -> bool:
        return not self.problems


# ----------------------------------------------------------------------------- reading


def read_bytes(path: str | Path, *, follow: bool = True) -> bytes:
    """A regular file's bytes, at most :data:`MAX_BYTES`.  It is opened without blocking (a FIFO
    or a device is refused, never waited on) and, with ``follow=False``, never through a final
    symbolic link."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    if not follow:
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Unreadable(f"cannot be opened ({exc.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Unreadable("not a regular file")
        if st.st_size > MAX_BYTES:
            raise Unreadable(f"over {MAX_BYTES} bytes")
        chunks, size = [], 0
        while chunk := os.read(fd, 1 << 20):
            size += len(chunk)
            if size > MAX_BYTES:
                raise Unreadable(f"over {MAX_BYTES} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def path_has_symlink(root: str | Path, rel: str) -> bool:
    """True when ``root`` itself, or any component of ``rel`` under it, is a symbolic link."""
    cur = Path(root)
    if cur.is_symlink():
        return True
    for part in rel.split("/"):
        cur = cur / part
        if cur.is_symlink():
            return True
    return False


def read_tree_file(root: str | Path, rel: str) -> bytes | str | None:
    """The working-tree bytes of ``rel`` under ``root`` (read like :func:`read_bytes` with
    ``follow=False``), None when it is absent, or why it cannot be read: a symbolic link anywhere
    on its path, or a file :func:`read_bytes` refuses."""
    if path_has_symlink(root, rel):
        return "a symbolic link on its path"
    p = Path(root) / rel
    if not os.path.lexists(p):
        return None
    try:
        return read_bytes(p, follow=False)
    except (Unreadable, OSError) as exc:
        return f"cannot be read ({exc})"


class _Loader(UniqueKeyLoader):
    """Duplicate keys refused (UniqueKeyLoader), and aliases refused outright: no manifest or
    record needs one, and an alias is how a small file expands into a huge document."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            ev = self.peek_event()
            raise yaml.composer.ComposerError(None, None, "an alias (refused)", ev.start_mark)
        return super().compose_node(parent, index)


class Budget:
    """The bytes a run may read: :data:`MODULE_BYTES` per module and :data:`RUN_BYTES` in all,
    refused (:class:`Unreadable`) once spent."""

    def __init__(self, per_module: int | None = None, per_run: int | None = None) -> None:
        self.per_module = MODULE_BYTES if per_module is None else per_module
        self.per_run = RUN_BYTES if per_run is None else per_run
        self.spent: dict[str, int] = {}
        self.total = 0

    def charge(self, key: str, n: int) -> None:
        self.spent[key] = self.spent.get(key, 0) + n
        self.total += n
        if self.spent[key] > self.per_module:
            raise Unreadable(f"its files add up to over {self.per_module} bytes")
        if self.total > self.per_run:
            raise Unreadable(f"the run's files add up to over {self.per_run} bytes")


def _decoded(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Unreadable("not UTF-8") from None


def _text(path: str | Path, follow: bool) -> str:
    return _decoded(read_bytes(path, follow=follow))


def load_yaml(path: str | Path, *, follow: bool = True) -> Any:
    """A YAML file read safely (:func:`read_bytes`): duplicate keys and aliases refused, and a
    document nested too deeply refused; each as :class:`Unreadable`."""
    return parse_yaml(_text(path, follow))


def parse_yaml(text: str) -> Any:
    """YAML text with duplicate keys and aliases refused and deep nesting refused."""
    try:
        return yaml.load(text, Loader=_Loader)
    except yaml.YAMLError as exc:
        raise Unreadable(
            f"not valid YAML ({exc.__class__.__name__}: {getattr(exc, 'problem', '') or exc})"
        ) from None
    except RecursionError:
        raise Unreadable("nested too deeply") from None


def load_input(path: str | Path, budget: Budget | None = None) -> Any:
    """A site input (the selection, the inventory, the role table, the registry, the lock, the
    slot registry): JSON by its suffix, else YAML, read safely and charged to the run's budget."""
    data = read_bytes(path)
    if budget is not None:
        budget.charge("inputs", len(data))
    text = _decoded(data)
    if Path(path).suffix != ".json":
        return parse_yaml(text)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise Unreadable(f"not valid JSON ({exc.__class__.__name__})") from None
    except RecursionError:
        raise Unreadable("nested too deeply") from None


def load_json(path: str | Path) -> Any:
    """A JSON file read safely (:func:`read_bytes`), a document nested too deeply refused."""
    text = _text(path, True)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise Unreadable(f"not valid JSON ({exc.__class__.__name__})") from None
    except RecursionError:
        raise Unreadable("nested too deeply") from None


def _schema(*parts: str) -> Doc:
    return json.loads(paths.schema_file(*parts).read_text(encoding="utf-8"))


def _errors(schema: Doc, doc: Any) -> list[str]:
    import jsonschema

    from homelabnext.schema_registry import schema_registry

    v = jsonschema.Draft202012Validator(schema, registry=schema_registry())
    try:
        errs = sorted(v.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    except RecursionError:
        return ["$: nested too deeply to validate"]
    return [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {safe_message(e)}" for e in errs]


# ----------------------------------------------------------------------------- discovery


def discover(
    public: Path | None = None,
    fixtures: Path | None = None,
    overlay: Path | None = None,
    budget: Budget | None = None,
) -> tuple[Tree, list[Problem]]:
    """Every ``<id>/module.yml`` under the given roots (``overlay`` is the overlay checkout: its
    ``lab/modules/`` is read).  A manifest that cannot be read, a symbolic-link module directory
    or manifest, an id that is not its directory, a reserved id, an id under two shipped roots,
    or (from the overlay) an id that shadows a shipped one is refused and left out of the tree."""
    tree, out = Tree(), []
    budget = budget or Budget()
    roots = [("public", public), ("fixture", fixtures)]
    if overlay is not None:
        roots.append(("overlay", overlay / "lab" / "modules"))
    for origin, root in roots:
        if root is None or not root.is_dir():
            continue
        for d in sorted(root.iterdir()):
            mf = d / "module.yml"
            if not os.path.lexists(mf):
                continue
            name = d.name
            if d.is_symlink() or mf.is_symlink():
                out.append(Problem(name, "a symbolic-link module directory or module.yml"))
                continue
            try:
                if mf.lstat().st_nlink > 1:
                    raise Unreadable("a hard link (it may alias a file outside the module)")
                data = read_bytes(mf, follow=False)
                budget.charge(name, len(data))
                doc = parse_yaml(_decoded(data))
            except Unreadable as exc:
                out.append(Problem(name, f"module.yml: {exc}"))
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
                    why = f"an overlay module shadows the {tree.origin[name]} module of that id"
                else:
                    why = f"defined under both the {tree.origin[name]} and {origin} roots"
                out.append(Problem(name, why))
                continue
            tree.mods[name], tree.dirs[name], tree.origin[name] = doc, d, origin
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


def _contained(mod_dir: Path, rel: str) -> str | None:
    """Why ``rel`` is not a contained regular file of the module, or None."""
    parts = Path(rel).parts
    for i in range(len(parts)):
        hop = mod_dir.joinpath(*parts[: i + 1])
        if hop.is_symlink():
            return "reached through a symbolic link"
    p = mod_dir / rel
    try:
        st = p.lstat()
    except OSError:
        return "not a regular file in the module"
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file in the module"
    if st.st_nlink > 1:
        return "a hard link (it may alias a file outside the module)"
    if not p.resolve().is_relative_to(mod_dir.resolve()):
        return "outside the module"
    return None


def _file_problems(doc: Doc, mod_dir: Path, fixture: bool) -> tuple[list[str], bool]:
    """(problems, whether the fixture exemption applied) for every contributed file."""
    out, exempt = [], False
    for _, rel in contributed_files(doc):
        if fixture and rel.startswith(FIXTURE_UNSHIPPED):
            exempt = True
            continue
        why = _contained(mod_dir, rel)
        if why:
            out.append(f"{rel}: {why}")
    return out, exempt


class ModuleReader:
    """The ``load`` the rules read contributed files with: only a contained regular file of one
    of the tree's modules (:func:`_contained`), read safely (:func:`read_bytes`, never through a
    final link), charged to the module's and the run's :class:`Budget`, and parsed once per run
    (the rules read some files more than once)."""

    def __init__(self, tree: Tree, budget: Budget | None = None) -> None:
        self._dirs = sorted(tree.dirs.items(), key=lambda kv: -len(str(kv[1])))
        self.budget = budget or Budget()
        self._texts: dict[Path, str] = {}
        self._docs: dict[Path, Any] = {}

    def text(self, path: Path) -> str:
        p = Path(path)
        if p in self._texts:
            return self._texts[p]
        for mid, d in self._dirs:
            if p.is_relative_to(d):
                rel = p.relative_to(d).as_posix()
                why = _contained(d, rel)
                if why:
                    raise Unreadable(f"{rel}: {why}")
                data = read_bytes(p, follow=False)
                self.budget.charge(mid, len(data))
                self._texts[p] = _decoded(data)
                return self._texts[p]
        raise Unreadable(f"{p}: outside every module")

    def __call__(self, path: Path) -> Any:
        p = Path(path)
        if p not in self._docs:
            self._docs[p] = parse_yaml(self.text(p))
        return self._docs[p]


def module_reader(tree: Tree, budget: Budget | None = None) -> ModuleReader:
    return ModuleReader(tree, budget)


def _record_problems(doc: Doc, mod_dir: Path, load) -> list[str]:
    """Each contributed file of a :data:`VALIDATED_KINDS` kind validates against its record type;
    files the rules index into have the shape they index."""
    out: list[str] = []
    c, mid = doc.get("contributes", {}), doc["id"]

    def read(rel: str) -> Any:
        try:
            return load(mod_dir / rel)
        except Unreadable as exc:
            out.append(f"{rel}: {exc}")
            return _UNREAD

    def each(entries, schema, what):
        for e in entries:
            rec = read(e)
            if rec is _UNREAD:
                continue
            out.extend(f"{e}: {what}: {m}" for m in _errors(schema, rec))
            yield e, rec

    mcp = _schema("platform", "mcp_server.schema.json")
    for e, rec in each([x["file"] for x in c.get("mcp_servers", [])], mcp, "MCP record"):
        if not isinstance(rec, dict) or rec.get("id") != Path(e).stem:
            out.append(f"{e}: an MCP record's id is its file name")
    service = _schema("platform", "service.json")
    row_schema = {"$ref": service["$id"] + "#/$defs/service"}
    for e in [x["file"] for x in c.get("services", [])]:
        doc_rows = read(e)
        if doc_rows is _UNREAD:
            continue
        rows = doc_rows.get("services") if isinstance(doc_rows, dict) else None
        if not isinstance(rows, dict) or not all(
            isinstance(k, str) and isinstance(v, dict) for k, v in rows.items()
        ):
            out.append(f"{e}: not a services mapping of row name to row")
            continue
        for name, r in rows.items():
            if doc["kind"] == "provider":
                if "version" in r:
                    out.append(
                        f"{e}: {name}: a provider's row takes its version from product.version"
                    )
                r = {**r, "version": str(doc.get("product", {}).get("version"))}
            out.extend(f"{e}: {name}: {m}" for m in _errors(row_schema, r))
    for job in c.get("scheduler_jobs", []):
        if "file" not in job:
            continue
        units = read(job["file"])
        if units is not _UNREAD and not (
            isinstance(units, list) and all(isinstance(u, dict) for u in units)
        ):
            out.append(f"{job['file']}: not a list of unit specs")
    prompts = [f for a in c.get("agents", []) for f in a.get("prompts", {}).values()]
    list(each(prompts, _schema("agent", "prompt_template.schema.json"), "prompt template"))
    table = _schema("platform", "lake_table.schema.json")
    for e, rec in each([x["file"] for x in c.get("lake_tables", [])], table, "lake table"):
        if isinstance(rec, dict) and rec.get("owner") != mid:
            out.append(f"{e}: a lake table's owner is the module")
    for e in [x["file"] for x in c.get("detections", [])]:
        if read(e) is _UNREAD:
            continue
        from homelabnext.detections.sigma import RuleError, load_rule

        try:
            load_rule(mod_dir / e, text=load.text(mod_dir / e))
        except RuleError as exc:
            out.append(f"{e}: not a Sigma rule ({str(exc).rsplit(': ', 1)[-1]})")
    for i in doc.get("interfaces", []):
        if "schema" not in i:
            continue
        s = read(i["schema"])
        if s is _UNREAD:
            continue
        import jsonschema

        try:
            jsonschema.Draft202012Validator.check_schema(s)
        except jsonschema.exceptions.SchemaError as exc:
            out.append(f"{i['schema']}: not a JSON Schema ({safe_message(exc)})")
            continue
        if not isinstance(s, dict) or f"/modules/{mid}/" not in str(s.get("$id", "")):
            out.append(f"{i['schema']}: its $id is not in the owning module's namespace")
    return out


_UNREAD = object()


def _unvalidated_kinds(mods: Mapping[str, Doc]) -> list[str]:
    """The contributed kinds present that have no record type the loader validates."""
    kinds = {k for m in mods.values() for k, _ in contributed_files(m)}
    return sorted(kinds - set(VALIDATED_KINDS))


# ----------------------------------------------------------------------------- inputs


@dataclass(frozen=True)
class Inputs:
    """What the site rules and the generators read from the manifests' contributed files."""

    rows: dict[str, dict[str, Doc]]
    units: dict[str, set[str]]
    privileged_units: dict[str, set[str]]


def inputs(tree: Tree, load=None) -> Inputs:
    """Rows, unit names and privileged unit names per module (each from its contributed files,
    read with ``load``, by default :func:`module_reader`)."""
    load = load or module_reader(tree)
    rows, units, priv = {}, {}, {}
    for n, m in tree.mods.items():
        d = tree.dirs[n]
        rows[n] = mr._rows(m, d, load)
        units[n] = mr._units(m, d, load)
        priv[n] = mr._privileged_units(m, d, load)
    return Inputs(rows, units, priv)


def core_names(
    services: Any,
    *,
    mcp: Iterable[tuple[str, Any]] | None = None,
    keyring: Any = None,
    tables: Iterable[str] | None = None,
    table_namespace: str | None = None,
    pairs: Mapping[str, str] | None = None,
) -> tuple[CoreNames, list[Problem]]:
    """The core's names from the sources it already has: its service registry (``services.yml``;
    None: the reserved ids only), its MCP catalog's records (``(file name, record)``, as
    :func:`core_mcp_records` reads them), the keyring (its agent principals) and the names of its
    OCSF tables in ``table_namespace``, and its notify pairs (problem title to recovery title).  A
    source that is malformed is a ``registry`` problem,
    never a silently smaller set."""
    out: list[Problem] = []
    names: dict[str, str] = {}
    if services is not None:
        rows = services.get("services") if isinstance(services, dict) else None
        if not isinstance(rows, dict):
            out.append(Problem("registry", "services is not a mapping of row name to row"))
        else:
            for k, v in rows.items():
                if not isinstance(k, str) or not isinstance(v, dict):
                    out.append(
                        Problem("registry", f"service row {_shown(k)} is not a named mapping")
                    )
                    continue
                names[k] = str(v.get("capability", ""))
    mcp_ids: set[str] = set()
    for fname, rec in mcp or ():
        # the id as the catalog's own loader takes it: the record's, else the file's stem; the
        # catalog's integrity check requires the two to agree
        stem = Path(fname).stem
        if not isinstance(rec, dict):
            out.append(Problem("registry", f"mcp/{_shown(fname)}: a record must be a mapping"))
            continue
        sid = rec.get("id")
        if sid is not None and (not isinstance(sid, str) or not sid):
            out.append(Problem("registry", f"mcp/{_shown(fname)}: an id that is not a string"))
            continue
        sid = sid or stem
        if sid != stem:
            why = f"mcp/{_shown(fname)}: id {_shown(sid)} is not the file name"
            out.append(Problem("registry", why))
        mcp_ids.add(sid)
    agents: set[str] = set()
    if keyring is not None:
        principals = keyring.get("principals") if isinstance(keyring, dict) else None
        if not isinstance(principals, list):
            out.append(Problem("registry", "the keyring's principals is not a list"))
        else:
            for p in principals:
                name = p.get("principal") if isinstance(p, dict) else None
                if not isinstance(name, str):
                    out.append(Problem("registry", "a keyring principal without a name"))
                    continue
                if p.get("kind") == "agent" and name.startswith("profile:"):
                    agents.add(name.removeprefix("profile:"))
    core_tables = frozenset(f"table:{table_namespace}.{t}" for t in tables or ())
    return (
        CoreNames(
            rows=names,
            mcp_servers=frozenset(mcp_ids),
            agents=frozenset(agents),
            tables=core_tables if table_namespace else frozenset(),
            table_namespace=table_namespace,
            pairs=dict(pairs or {}),
        ),
        out,
    )


def _catalog(directory: str | Path, what: str) -> tuple[list[Path], list[Problem]]:
    """The entries of a core catalog directory, sorted by name: a directory that is a symbolic
    link, is missing or holds more than :data:`MAX_CATALOG_FILES` entries is a ``registry``
    problem (nothing of it is read)."""
    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        return [], [Problem("registry", f"{what} {root.name}/ is not a directory")]
    entries: list[Path] = []
    for f in root.iterdir():
        entries.append(f)
        if len(entries) > MAX_CATALOG_FILES:
            why = f"{what} {root.name}/ holds over {MAX_CATALOG_FILES} entries"
            return [], [Problem("registry", why)]
    return sorted(entries, key=lambda p: p.name), []


def _catalog_read(f: Path, budget: Budget | None) -> bytes:
    data = read_bytes(f, follow=False)
    if budget is not None:
        budget.charge("inputs", len(data))
    return data


def core_mcp_records(
    directory: str | Path, budget: Budget | None = None
) -> tuple[list[tuple[str, Any]], list[Problem]]:
    """The core MCP catalog's records (every ``*.yml`` in ``directory``), each read like any
    other input (:func:`read_bytes` without following a final link, charged to ``budget``).  A
    record that cannot be read, another record-like file (``*.yaml``, ``*.json``, any case: the
    catalog's own loader, :func:`homelabnext.mcp.servers.load`, refuses them too), or a directory
    that is a symbolic link, missing or over :data:`MAX_CATALOG_FILES` entries is a ``registry``
    problem."""
    entries, out = _catalog(directory, "the MCP catalog")
    recs: list[tuple[str, Any]] = []
    for f in entries:
        if f.suffix != ".yml":
            if f.suffix.lower() in (".yml", ".yaml", ".json"):
                why = f"mcp/{_shown(f.name)}: a record file is <id>.yml; this one is not read"
                out.append(Problem("registry", why))
            continue
        try:
            recs.append((f.name, parse_yaml(_decoded(_catalog_read(f, budget)))))
        except Unreadable as exc:
            out.append(Problem("registry", f"mcp/{_shown(f.name)}: {exc}"))
    return recs, out


def core_table_names(
    directory: str | Path, budget: Budget | None = None
) -> tuple[list[str], list[Problem]]:
    """The names of the core's OCSF tables: every ``*.v*.json`` subset in ``directory`` (as
    :func:`homelabnext.lake.tables.load_schemas` reads them), each read like any other input.  A
    subset that cannot be read or parsed, or a directory that is a symbolic link, missing, over
    :data:`MAX_CATALOG_FILES` entries or without a subset, is a ``registry`` problem."""
    from homelabnext.lake.errors import LakeError
    from homelabnext.lake.tables import schema_from_json

    entries, out = _catalog(directory, "the OCSF tables")
    names: list[str] = []
    for f in entries:
        if not (f.suffix == ".json" and ".v" in f.stem):
            continue
        try:
            doc = json.loads(_decoded(_catalog_read(f, budget)))
            names.append(schema_from_json(doc).name)
        except (Unreadable, ValueError, LakeError, KeyError, TypeError, AttributeError) as exc:
            out.append(Problem("registry", f"ocsf/{_shown(f.name)}: {exc}"))
    if not names and not out:
        out.append(Problem("registry", "the OCSF tables: no subset (*.v*.json)"))
    return sorted(names), out


def _module_tables(m: Doc, d: Path, load) -> set[str]:
    """The tables a module names as its own: its ``data`` tables and its lake table records."""
    out = {x["table"] for x in m.get("data", []) if "table" in x}
    for e in m.get("contributes", {}).get("lake_tables", []):
        try:
            rec = load(d / e["file"])
        except Unreadable:
            continue  # a record that cannot be read fails where the rules load it
        if isinstance(rec, dict) and isinstance(rec.get("id"), str):
            out.add(rec["id"])
    return out


def _core_problems(tree: Tree, ins: Inputs, core: CoreNames, load=None) -> list[Problem]:
    load = load or module_reader(tree)
    out = []
    for n in sorted(tree.mods):
        m, d = tree.mods[n], tree.dirs[n]
        if n in core.rows:
            out.append(Problem(n, "the module id is a core service name"))
        if core.table_namespace and mr.us(n) == core.table_namespace:
            out.append(
                Problem(n, f"the module's table namespace is the core's ({core.table_namespace})")
            )
        out += [
            Problem(n, f"MCP server {i} is a core MCP server id")
            for i in sorted(mr._mcp_ids(m, d, load) & core.mcp_servers)
        ]
        out += [
            Problem(n, f"agent {k} is a core agent key")
            for k in sorted({a["key"] for a in mr._agents(m)} & core.agents)
        ]
        out += [
            Problem(n, f"table {t} is a core table")
            for t in sorted(_module_tables(m, d, load) & core.tables)
        ]
        core_titles = {*core.pairs, *core.pairs.values()}
        for pr in _pairs(m):
            for which in ("problem", "recovery"):
                if pr[which] in core_titles:
                    why = f"notify pair {_title(pr['problem'])}: its {which} title is a core title"
                    out.append(Problem(n, why))
        if m["kind"] == "provider":
            continue
        out += [
            Problem(n, f"service row {r} is a core service name")
            for r in sorted(set(ins.rows.get(n, {})) & set(core.rows))
        ]
    return out


def _instance_problems(site: Doc, core: CoreNames) -> list[Problem]:
    """A provider instance named like a core service row is that row, so the row's capability
    must be one of the slots the instance fills (``inference`` filling ``cap:inference``)."""
    fills: dict[str, set[str]] = {}
    for slot, v in site.get("slots", {}).items():
        for c in v if isinstance(v, list) else []:
            fills.setdefault(c["instance"], set()).add(slot)
    return [
        Problem("site", f"instance {i} takes the core service name of {core.rows[i]}")
        for i in sorted(fills)
        if i in core.rows and core.rows[i] not in fills[i]
    ]


# ----------------------------------------------------------------------------- two-way, running


def _declared(
    tree: Tree, ins: Inputs, site: Doc, sel: Mapping[str, Doc], load
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
        out["mcp_servers"].update(dict.fromkeys(mr._mcp_ids(m, d, load), n))
        out["agents"].update({a["key"]: n for a in mr._agents(m)})
        out["tables"].update({x["table"]: n for x in m.get("data", []) if "table" in x})
    return out


def _bound_to(kind: str, name: str, ids: set[str]) -> str | None:
    """The module a running name is bound to (``table:<id_>.<name>``; ``<id>`` or ``<id>-...``)."""
    if kind == "tables":
        schema = name.removeprefix("table:").split(".", 1)[0]
        return next((i for i in sorted(ids) if mr.us(i) == schema), None)
    return mr._owner(name, ids, "-")


def _title(text: str) -> str:
    """A notify title as it is printed: always quoted (a title has spaces and colons), with every
    control character escaped."""
    return repr(str(text))


def _pairs(m: Doc) -> list[Doc]:
    return m.get("contributes", {}).get("notify_pairs", [])


def pair_problems(sel: Mapping[str, Doc]) -> list[Problem]:
    """The notifier keys its pairs by problem title (:class:`homelabnext.notify.core.Notifier`),
    so across the selected modules a problem title is declared once.  Every title names one
    thing: a recovery is not its own problem's title, another pair's problem title, or another
    pair's recovery (so a recovery page always says which alert cleared).  The core's own titles
    are refused per module (:class:`CoreNames`)."""
    seen: dict[str, str] = {}
    problems = {pr["problem"] for m in sel.values() for pr in _pairs(m)}
    recoveries: dict[str, tuple[str, str]] = {}  # recovery -> (module, problem)
    out = []
    for n in sorted(sel):
        for pr in _pairs(sel[n]):
            title, rec = pr["problem"], pr["recovery"]
            what = f"notify pair {_title(title)}"
            if rec == title:
                out.append(Problem(n, f"{what}: the recovery is its own title"))
            elif rec in problems:
                out.append(Problem(n, f"{what}: the recovery {_title(rec)} is a problem title"))
            if title in seen:
                other = seen[title]
                why = f"{what} is also declared by {other}"
                out.append(Problem(n, why if other != n else f"{what} twice"))
                continue
            seen[title] = n
            if rec in recoveries and rec != title:
                other, ptitle = recoveries[rec]
                why = f"{what}: the recovery {_title(rec)} is also {other}'s for {_title(ptitle)}"
                out.append(Problem(n, why))
            recoveries.setdefault(rec, (n, title))
    return out


def running_pair_problems(tree: Tree, sel: Mapping[str, Doc], running: list[Doc]) -> list[Problem]:
    """The running notifier's pairs (``{problem, recovery, module?}``) against the selected
    modules' declared ones, compared exactly (both titles): a pair bound to a module is declared
    by that module, which the site selects, with the same recovery; every declared pair runs.  A
    pair bound to no module is the core's and is not judged here."""
    declared = {n: {p["problem"]: p["recovery"] for p in _pairs(m)} for n, m in sel.items()}
    out = []
    seen: set[tuple[str, str]] = set()
    titles: set[str] = set()
    for r in running:
        title, mid = r["problem"], r.get("module")
        what = f"notify pair {_title(title)}"
        if title in titles:
            out.append(Problem("running", f"{what} runs twice (the notifier holds one per title)"))
        titles.add(title)
        if mid is None:
            continue
        seen.add((mid, title))
        if mid not in tree.mods:
            out.append(Problem("running", f"{what} runs for {mid}, which is no module"))
        elif mid not in sel:
            out.append(Problem("running", f"{what} runs for {mid}, which the site does not select"))
        elif title not in declared[mid]:
            out.append(Problem("running", f"{what} runs but {mid} declares no such pair"))
        elif r["recovery"] != declared[mid][title]:
            why = (
                f"{what} runs with recovery {_title(r['recovery'])} but {mid} declares "
                f"{_title(declared[mid][title])}"
            )
            out.append(Problem("running", why))
    for n in sorted(declared):
        for title in sorted(declared[n]):
            if (n, title) not in seen:
                why = f"notify pair {_title(title)} ({n}) is declared but not running"
                out.append(Problem("running", why))
    return out


def running_problems(
    tree: Tree, ins: Inputs, site: Doc, sel: Mapping[str, Doc], inventory: Doc, load=None
) -> list[Problem]:
    """Every running name bound to a module id is declared by that module, which the site
    selects; every declared name runs.  A name bound to no module id is the core's and is not
    judged here.  With the inventory's ``notify_pairs``, the same for recovery pairs
    (:func:`running_pair_problems`)."""
    declared = _declared(tree, ins, site, sel, load or module_reader(tree))
    ids = set(tree.mods)
    out = []
    for kind in INVENTORY_KINDS:
        running = set(inventory.get(kind, []))
        for name in sorted(running - set(declared[kind])):
            owner = _bound_to(kind, name, ids)
            if owner is None:
                continue
            if owner not in sel:
                why = f"{kind} {name} runs for {owner}, which the site does not select"
            else:
                why = f"{kind} {name} runs but {owner} declares no such entry"
            out.append(Problem("running", why))
        for name in sorted(set(declared[kind]) - running):
            why = f"{kind} {name} ({declared[kind][name]}) is declared but not running"
            out.append(Problem("running", why))
    if isinstance(inventory.get("notify_pairs"), list):
        out += running_pair_problems(tree, sel, inventory["notify_pairs"])
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
    budget: Budget | None = None,
) -> Report:
    """Every rule of "What the loader checks" over ``tree``; with ``site`` the site rules and
    the supply chain, with ``inventory`` the runtime half of the two-way check."""
    problems: list[Problem] = []
    notes: list[str] = []
    core = core or CoreNames()
    load = module_reader(tree, budget)
    module_schema = _schema("platform", "module.schema.json")
    valid: dict[str, Doc] = {}
    exempted = []
    for n in sorted(tree.mods):
        m, d = tree.mods[n], tree.dirs[n]
        errs = _errors(module_schema, m)
        if errs:
            problems += [Problem(n, f"schema: {e}") for e in errs]
            continue
        files, exempt = _file_problems(m, d, tree.origin[n] == "fixture")
        if exempt:
            exempted.append(n)
        if files:  # nothing reads a file that is not contained
            problems += [Problem(n, p) for p in files]
            continue
        try:
            recs = _record_problems(m, d, load)
            if recs:
                problems += [Problem(n, p) for p in recs]
                continue
            problems += [
                Problem(n, p) for p in mr.module_problems(m, d, dict(slots), load, in_tree_roots)
            ]
        except Unreadable as exc:
            problems.append(Problem(n, str(exc)))
            continue
        except (KeyError, TypeError, AttributeError, ValueError, RecursionError) as exc:
            problems.append(
                Problem(n, f"a contributed record the rules cannot read ({exc.__class__.__name__})")
            )
            continue
        valid[n] = m
    if len(valid) < len(tree.mods):
        notes.append(
            f"{len(tree.mods) - len(valid)} module(s) with problems above were left out of the "
            "rules across manifests and of the site"
        )
    if exempted:
        notes.append(
            "the fixture root's modules may omit roles/ and playbooks/ (the examples ship no "
            f"Ansible): {', '.join(exempted)}"
        )
    unvalidated = _unvalidated_kinds(valid)
    if unvalidated:
        notes.append(
            "contributed files checked for containment only (no record type is validated): "
            + ", ".join(unvalidated)
        )
    vtree = Tree(valid, {n: tree.dirs[n] for n in valid}, {n: tree.origin[n] for n in valid})
    ins = inputs(vtree, load)
    problems += [Problem("modules", p) for p in mr.tree_problems(valid, vtree.dirs, load)]
    problems += _core_problems(vtree, ins, core, load)
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
    problems += [
        Problem("site", p)
        for p in mr.site_problems(
            site, valid, dict(slots), rows=ins.rows, units=ins.units,
            privileged_units=ins.privileged_units, roles=dict(roles),
        )
    ]  # fmt: skip
    problems += _instance_problems(site, core)
    try:
        sel = mr.selected(site, valid)
    except KeyError:
        return Report(sorted(set(problems)), notes)  # site_problems reported it
    problems += pair_problems(sel)
    fetched = [n for n, m in sel.items() if m.get("origin", {}).get("kind") != "in-tree"]
    if lock is not None or fetched:
        the_lock = lock
        if lock is None:
            the_lock = {"schema_version": supply.LOCK_VERSION, "modules": {}}
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
            problems += running_problems(vtree, ins, site, sel, inventory, load)
            if "notify_pairs" not in inventory:
                notes.append(
                    "the inventory names no notify_pairs: the recovery pairs were not compared"
                )
    return Report(sorted(set(problems)), notes)


def units_fn(ins: Inputs) -> Callable[[str], set[str]]:
    return lambda mid: ins.units.get(mid, set())


def rows_fn(ins: Inputs) -> Callable[[str], dict[str, Doc]]:
    return lambda mid: ins.rows.get(mid, {})
