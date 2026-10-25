# SPDX-License-Identifier: Apache-2.0
"""Render and check the capability reference pages (``docs/capabilities/``).

One page per conformance capability, generated entirely from code, never edited by hand:

* what it does      the contract module's docstring (``conformance/protocols/<module>.py``);
* how to use it     every method of every Protocol in the contract, with its signature, its
                    docstring and the contract exceptions that docstring names;
* data shapes       every dataclass, enum, TypedDict and constant of the contract (and the data
                    types their annotations reach), as field tables; the exception hierarchy; JSON
                    Schemas the contract's code demonstrably loads (a ``schemas/...json`` literal,
                    ``paths.schema_file(...)`` or ``paths.ocsf_dir()``), nothing guessed;
* behaviour         the suite's checks (id, MUST/SHOULD, summary, required features), the features
                    an adapter may declare and the defective fakes (mutants) the suite must catch;
* implementations   the built-in fake, every target-file binding in the checkout (real-product
                    adapters with the limits their docstrings record), client adapters the contract
                    imports, and the registry services that provide or depend on the capability;
* integrating       the factory/target/run steps, from the real factory pattern.

``README.md`` is the index: a capability x (operations, checks, adapters, services) matrix.
The same model is exposed as plain data by :func:`summary_data` and :func:`contract_data` (the
read-only MCP server, ``homelabnext.mcp``, answers from them), so a page and a tool answer cannot
disagree.

Pages assume they live at ``docs/capabilities/`` (links to sources are ``../../<path>``) and use
relative Markdown links plus path-qualified ``[[folder/page|label]]`` wiki-links, so the same
files read on GitHub and in an Obsidian vault opened at ``docs/``.  Output is deterministic: no
timestamps, source order or sorted order everywhere.  The suites and fakes live in
``conformance/`` of a source checkout (only the contracts are in the wheel), so generation needs one.
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import importlib
import inspect
import io
import re
import sys
import tokenize
import typing
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

from homelabnext import paths
from homelabnext.context.levels import generated_summary_lines
from homelabnext.registry.model import Registry, env_var_name

PAGES_DIR = "docs/capabilities"
INDEX = "README.md"
GENERATOR = "hnx docs capabilities generate"
TARGET_GLOBS = ("conformance/targets/*.yml", "compose/*/targets/*.yml")
REAL_ADAPTERS = "homelabnext.conform.adapters"
# modules whose text mentions schemas generically (the resolver, the harness); never a link source
_SCHEMA_SCAN_SKIP = ("homelabnext.paths", "homelabnext.conform.")
_BUILTIN_ERRORS = (
    "ValueError",
    "TypeError",
    "KeyError",
    "PermissionError",
    "FileExistsError",
    "FileNotFoundError",
    "TimeoutError",
    "LookupError",
)
_SCHEMA_LITERAL = re.compile(r"schemas/[a-z_]+/[A-Za-z0-9_.-]+\.json")
_SCHEMA_FILE_CALL = re.compile(r"schema_file\(\s*\"([a-z_]+)\"\s*,\s*\"([A-Za-z0-9_.-]+\.json)\"")
_OCSF_DIR_CALL = re.compile(r"\bocsf_dir\(\)")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class NotACheckoutError(RuntimeError):
    """Generation needs ``conformance/`` of a source checkout."""


# --------------------------------------------------------------------------- model


@dataclass
class Param:
    name: str
    type: str
    default: str  # "" when required
    kind: str  # "", "keyword-only", "*args", "**kwargs"


@dataclass
class Method:
    name: str
    params: list[Param]
    returns: str
    doc: str
    raises: list[str]
    defined_in: str  # qualified class name when inherited from a base protocol, else ""


@dataclass
class Field:
    name: str
    type: str
    default: str
    note: str


@dataclass
class Shape:
    """A Protocol, dataclass, enum, TypedDict or exception of the contract."""

    name: str
    kind: str  # protocol | dataclass | enum | typeddict | exception
    module: str
    doc: str
    fields: list[Field] = field(default_factory=list)
    methods: list[Method] = field(default_factory=list)
    base: str = ""  # exceptions: the parent class
    frozen: bool = False


@dataclass
class Check:
    id: str
    severity: str
    summary: str
    requires: tuple[str, ...]


@dataclass
class Binding:
    target_file: str  # repo-relative path
    target_name: str
    adapter: str  # module:factory
    module_file: str  # repo-relative path, "" if not found
    real: bool
    client_only: bool
    product: str  # first sentence of the module docstring
    factory_sig: str
    features: tuple[str, ...]
    config: dict[str, Any]
    limits: list[str]
    full_doc: str


@dataclass
class Capability:
    name: str
    summary: str
    protocol: str  # module:Class
    contract_module: str
    contract_doc: str
    suite_module: str
    protocols: list[Shape]
    data: list[Shape]
    constants: list[tuple[str, str]]
    errors: list[Shape]
    schemas: list[tuple[str, str]]  # (repo-relative schema path, module that loads it)
    checks: list[Check]
    hooks: frozenset[str]
    mutants: list[tuple[str, str, str]]  # (name, check it must fail, defect)
    fake: tuple[str, str, str]  # (class name, module, doc summary)
    bindings: list[Binding]
    providers: list[tuple[str, str]]  # (service, impl)
    consumers: list[str]

    @property
    def operations(self) -> int:
        return sum(len(p.methods) for p in self.protocols)

    def count(self, severity: str) -> int:
        return sum(1 for c in self.checks if c.severity == severity)

    @property
    def real_bindings(self) -> list[Binding]:
        return [b for b in self.bindings if b.real]


# --------------------------------------------------------------------------- checkout


def resolve_root(root: str | Path | None = None) -> Path:
    """The source checkout holding ``conformance/``; :class:`NotACheckoutError` without one."""
    if root is not None:
        r = Path(root).resolve()
    else:
        found = paths.checkout_root()
        if found is None:
            raise NotACheckoutError(
                "hnx docs capabilities needs a homelabnext source checkout: the suites and fakes "
                "live in conformance/, which the wheel does not carry; run it from a checkout or "
                "pass --root"
            )
        r = found
    if (
        not (r / "conformance" / "suites").is_dir()
        or not (r / "conformance" / "protocols").is_dir()
    ):
        raise NotACheckoutError(
            f"{r} is not a homelabnext source checkout (no conformance/suites and "
            "conformance/protocols); pass --root"
        )
    return r


# --------------------------------------------------------------------------- docstrings


def _md(doc: str | None) -> str:
    """A docstring as Markdown: ``x`` -> `x`, Sphinx roles dropped, dedented, stripped."""
    if not doc:
        return ""
    text = inspect.cleandoc(doc)
    text = re.sub(r":[a-z]+:(`[^`]+`)", r"\1", text)
    text = text.replace("``", "`")
    return text.strip()


def _first_para(text: str) -> str:
    return " ".join(text.split("\n\n", 1)[0].split()) if text else ""


def _own_doc(cls: type) -> str:
    doc = cls.__dict__.get("__doc__")
    if not doc or (dataclasses.is_dataclass(cls) and doc.startswith(cls.__name__ + "(")):
        return ""
    return _md(doc)


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _code(text: str) -> str:
    return f"`{text}`" if text else ""


# --------------------------------------------------------------------------- introspection


def _ann(a: Any) -> str:
    if a is inspect.Parameter.empty or a is inspect.Signature.empty:
        return ""
    if isinstance(a, str):
        return a
    return re.sub(r"\b(typing|collections\.abc)\.", "", inspect.formatannotation(a))


def _method(func: Callable[..., Any], errors: Iterable[str], defined_in: str) -> Method:
    sig = inspect.signature(func)
    params: list[Param] = []
    for p in list(sig.parameters.values())[1:]:  # drop self
        kind = {
            inspect.Parameter.KEYWORD_ONLY: "keyword-only",
            inspect.Parameter.VAR_POSITIONAL: "*args",
            inspect.Parameter.VAR_KEYWORD: "**kwargs",
        }.get(p.kind, "")
        default = "" if p.default is inspect.Parameter.empty else repr(p.default)
        params.append(Param(p.name, _ann(p.annotation), default, kind))
    doc = _md(func.__doc__)
    names = [*errors, *_BUILTIN_ERRORS]
    hits = sorted(
        {n: m.start() for n in names if (m := re.search(rf"(?<![\w.]){n}\b", doc))}.items(),
        key=lambda kv: kv[1],
    )
    return Method(
        func.__name__, params, _ann(sig.return_annotation), doc, [h for h, _ in hits], defined_in
    )


def render_signature(m: Method) -> str:
    parts: list[str] = []
    star = False
    for p in m.params:
        if p.kind == "keyword-only" and not star:
            parts.append("*")
            star = True
        name = {"*args": "*", "**kwargs": "**"}.get(p.kind, "") + p.name
        if p.kind == "*args":
            star = True
        s = f"{name}: {p.type}" if p.type else name
        if p.default:
            s += f" = {p.default}" if p.type else f"={p.default}"
        parts.append(s)
    ret = f" -> {m.returns}" if m.returns else ""
    one = f"def {m.name}({', '.join(parts)}){ret}"
    if len(one) <= 96:
        return one
    return f"def {m.name}(\n" + "".join(f"    {p},\n" for p in parts) + f"){ret}"


def _is_protocol(obj: Any) -> bool:
    return (
        isinstance(obj, type)
        and getattr(obj, "_is_protocol", False)
        and obj is not typing.Protocol
        and obj.__module__ != "typing"
    )


def _field_comments(cls: type) -> dict[str, str]:
    """Trailing ``# comment`` of each annotated attribute line in the class body."""
    try:
        src = inspect.getsource(cls)
    except (OSError, TypeError):
        return {}
    src = inspect.cleandoc("\n" + src) if src.startswith((" ", "\t")) else src
    comments: dict[int, str] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                comments[tok.start[0]] = tok.string.lstrip("#").strip()
        tree = ast.parse(src)
    except (tokenize.TokenError, SyntaxError):
        return {}
    out: dict[str, str] = {}
    node = tree.body[0] if tree.body else None
    if isinstance(node, ast.ClassDef):
        for st in node.body:
            if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                c = comments.get(st.end_lineno or st.lineno)
                if c:
                    out[st.target.id] = c
    return out


def _public_methods(cls: type, errors: Iterable[str]) -> list[Method]:
    seen: set[str] = set()
    out: list[Method] = []
    chain = [k for k in cls.__mro__ if k not in (object, typing.Protocol, typing.Generic)]
    for k in chain:
        if k.__module__ == "typing":
            continue
        for name, obj in k.__dict__.items():
            if name.startswith("_") or name in seen or not inspect.isfunction(obj):
                continue
            seen.add(name)
            out.append(_method(obj, errors, "" if k is cls else k.__qualname__))
    return out


def _dataclass_fields(cls: type) -> list[Field]:
    notes = _field_comments(cls)
    out = []
    for f in dataclasses.fields(cls):
        if f.name.startswith("_"):
            continue
        if f.default is not dataclasses.MISSING:
            default = _code(repr(f.default))
        elif f.default_factory is not dataclasses.MISSING:  # type: ignore[misc]
            default = _code(f"{getattr(f.default_factory, '__name__', 'factory')}()")
        else:
            default = "required"
        out.append(Field(f.name, _ann(f.type), default, notes.get(f.name, "")))
    return out


def _shape(cls: type, errors: Iterable[str]) -> Shape:
    if _is_protocol(cls):
        notes = _field_comments(cls)
        attrs = [
            Field(n, _ann(t), "required", notes.get(n, ""))
            for n, t in inspect.get_annotations(cls).items()
            if not n.startswith("_")
        ]
        return Shape(
            cls.__name__,
            "protocol",
            cls.__module__,
            _own_doc(cls),
            attrs,
            _public_methods(cls, errors),
        )
    if isinstance(cls, type) and issubclass(cls, BaseException):
        return Shape(
            cls.__name__, "exception", cls.__module__, _own_doc(cls), base=cls.__bases__[0].__name__
        )
    if isinstance(cls, enum.EnumMeta):
        members = [Field(m.name, "", _code(repr(m.value)), "") for m in cls]  # type: ignore[var-annotated]
        return Shape(cls.__name__, "enum", cls.__module__, _own_doc(cls), members)
    if typing.is_typeddict(cls):
        req = getattr(cls, "__required_keys__", frozenset())
        notes = _field_comments(cls)
        flds = [
            Field(n, _ann(t), "required" if n in req else "optional", notes.get(n, ""))
            for n, t in cls.__annotations__.items()
        ]
        return Shape(cls.__name__, "typeddict", cls.__module__, _own_doc(cls), flds)
    params = getattr(cls, "__dataclass_params__", None)
    methods = [
        _method(obj, errors, "")
        for name, obj in cls.__dict__.items()
        if not name.startswith("_") and inspect.isfunction(obj)
    ]
    return Shape(
        cls.__name__,
        "dataclass",
        cls.__module__,
        _own_doc(cls),
        _dataclass_fields(cls),
        methods,
        frozen=bool(params and params.frozen),
    )


def _documentable(obj: Any) -> bool:
    if not isinstance(obj, type) or not obj.__module__.startswith(("homelabnext", "conformance")):
        return False
    return (
        _is_protocol(obj)
        or dataclasses.is_dataclass(obj)
        or isinstance(obj, enum.EnumMeta)
        or typing.is_typeddict(obj)
    )


def _referenced(shape: Shape) -> list[str]:
    """Identifiers in the shape's annotations, in order of appearance."""
    texts = [f.type for f in shape.fields]
    for m in shape.methods:
        texts += [p.type for p in m.params] + [m.returns]
    out: list[str] = []
    for t in texts:
        for name in _IDENT.findall(t):
            if name not in out:
                out.append(name)
    return out


def _contract(
    mod: ModuleType,
) -> tuple[list[Shape], list[Shape], list[tuple[str, str]], list[Shape]]:
    """(protocols, data shapes, constants, exceptions) of a contract module."""
    exported = list(getattr(mod, "__all__", ()))
    objs = {n: getattr(mod, n) for n in exported}
    exc_classes: list[type] = [
        o for o in objs.values() if isinstance(o, type) and issubclass(o, BaseException)
    ]
    # an exported base's subclasses defined beside it (homelabnext.lake.errors: RowRejected, ...)
    for base in list(exc_classes):
        home = sys.modules[base.__module__]
        for o in vars(home).values():
            if (
                isinstance(o, type)
                and issubclass(o, base)
                and o not in exc_classes
                and o.__module__ == base.__module__
            ):
                exc_classes.append(o)
    error_names = [e.__name__ for e in exc_classes]
    errors = _order_errors(exc_classes)

    constants = [
        (n, repr(o))
        for n, o in objs.items()
        if not isinstance(o, type) and not callable(o) and not isinstance(o, ModuleType)
    ]
    todo: list[type] = [o for o in objs.values() if _documentable(o)]
    done: dict[type, Shape] = {}
    while todo:
        cls = todo.pop(0)
        if cls in done:
            continue
        shape = _shape(cls, error_names)
        done[cls] = shape
        home = vars(sys.modules[cls.__module__])
        for name in _referenced(shape):
            ref = home.get(name)
            if _documentable(ref) and ref not in done and ref not in todo:
                todo.append(ref)
    shapes = list(done.values())
    return (
        [s for s in shapes if s.kind == "protocol"],
        [s for s in shapes if s.kind != "protocol"],
        constants,
        errors,
    )


def _order_errors(classes: list[type]) -> list[Shape]:
    """Depth-first from each root, children in the order found."""
    out: list[Shape] = []
    placed: set[type] = set()

    def visit(c: type) -> None:
        placed.add(c)
        out.append(_shape(c, ()))
        for k in classes:
            if k not in placed and k.__bases__[0] is c:
                visit(k)

    for c in classes:
        if c not in placed and c.__bases__[0] not in classes:
            visit(c)
    for c in classes:
        if c not in placed:
            visit(c)
    return out


def _module_file(name: str, root: Path) -> str:
    """``a.b.c`` -> ``a/b/c.py`` (or ``a/b/c/__init__.py``) under ``root``, or ``""``.

    Mapped onto the checkout, never looked up through ``sys.modules`` or ``sys.path``: a test or a
    ``--root`` run may have imported the same dotted name from another tree, and the page must
    not change with what happens to be imported.
    """
    base = root.joinpath(*name.split("."))
    for p in (base.with_suffix(".py"), base / "__init__.py"):
        if p.is_file():
            return p.relative_to(root).as_posix()
    return ""


def _imports(path: Path, root: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    pkg = path.parent.relative_to(root).as_posix().replace("/", ".")
    out: list[str] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            if n.level:
                base = pkg.rsplit(".", n.level - 1)[0] if n.level > 1 else pkg
                out.append(base + ("." + n.module if n.module else ""))
            elif n.module:
                out.append(n.module)
        elif isinstance(n, ast.Import):
            out += [a.name for a in n.names]
    return [m for m in out if m.startswith(("homelabnext", "conformance"))]


def _schema_links(start: Iterable[str], root: Path, depth: int = 2) -> list[tuple[str, str]]:
    """JSON Schemas the contract's code loads: modules reachable in ``depth`` import hops."""
    files: dict[str, Path] = {}
    frontier = [(m, 0) for m in start]
    while frontier:
        name, d = frontier.pop(0)
        if name in files:
            continue
        rel = _module_file(name, root)
        if not rel:
            continue
        files[name] = root / rel
        if d < depth:
            frontier += [(m, d + 1) for m in _imports(root / rel, root)]
    found: dict[str, str] = {}
    for name, f in sorted(files.items()):
        if name.startswith(_SCHEMA_SCAN_SKIP) and not name.startswith(REAL_ADAPTERS):
            continue
        text = f.read_text(encoding="utf-8")
        hits = list(_SCHEMA_LITERAL.findall(text))
        hits += [f"schemas/{a}/{b}" for a, b in _SCHEMA_FILE_CALL.findall(text)]
        if _OCSF_DIR_CALL.search(text):
            hits += sorted(
                p.relative_to(root).as_posix() for p in (root / "schemas/ocsf").glob("*.v1.json")
            )
        for h in hits:
            if (root / h).is_file():
                found.setdefault(h, name)
    return sorted(found.items())


def _fake(suite_mod: ModuleType, root: Path) -> tuple[str, str, str]:
    fn = getattr(suite_mod, "make_fake", None)
    if fn is None:
        return ("", "", "")
    tree = ast.parse(inspect.cleandoc("\n" + inspect.getsource(fn)))
    ret = next((n.value for n in ast.walk(tree) if isinstance(n, ast.Return)), None)
    name = ""
    if isinstance(ret, ast.Call):
        name = ast.unparse(ret.func)
    obj = getattr(suite_mod, name.split(".")[0], None)
    for part in name.split(".")[1:]:
        obj = getattr(obj, part, None)
    if not isinstance(obj, type):
        return (name, "", "")
    doc = _own_doc(obj) or _md(sys.modules[obj.__module__].__doc__)
    return (obj.__name__, obj.__module__, _first_para(doc))


# --------------------------------------------------------------------------- targets / adapters


def _ast_module(module: str, root: Path) -> tuple[str, ast.Module | None]:
    """The module's file under ``root`` and its parsed source (never imported)."""
    rel = _module_file(module, root)
    if not rel:
        return ("", None)
    return (rel, ast.parse((root / rel).read_text(encoding="utf-8")))


def _factory_sig(tree: ast.Module | None, factory: str) -> str:
    if tree is None:
        return ""
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == factory:
            ret = f" -> {ast.unparse(n.returns)}" if n.returns else ""
            return f"{n.name}({ast.unparse(n.args)}){ret}"
        if isinstance(n, ast.ClassDef) and n.name == factory:
            for b in n.body:
                if isinstance(b, ast.FunctionDef) and b.name == "__init__":
                    args = ast.unparse(b.args)
                    args = re.sub(r"^self,?\s*", "", args)
                    return f"{n.name}({args})"
            return f"{n.name}()"
    return ""


def _limits(doc: str) -> list[str]:
    """Paragraphs that record product limits: ``Findings ...`` and ``... specifics ...``."""
    paras = [p.strip() for p in doc.split("\n\n") if p.strip()]
    out: list[str] = []
    take = False
    for p in paras:
        head = p.splitlines()[0]
        if re.match(r"^(Findings\b|[\w ]*\bspecifics\b)", head):
            out.append(p)
            take = head.rstrip().endswith(":")
        elif take and p.lstrip().startswith(("* ", "- ")):
            out.append(p)
        else:
            take = False
    return out


def _binding(
    target_file: str,
    target_name: str,
    adapter: str,
    spec: dict[str, Any],
    root: Path,
    client_only: bool,
) -> Binding:
    module, _, factory = adapter.partition(":")
    rel, tree = _ast_module(module, root)
    doc = _md(ast.get_docstring(tree)) if tree else ""
    return Binding(
        target_file=target_file,
        target_name=target_name,
        adapter=adapter,
        module_file=rel,
        real=module.startswith(REAL_ADAPTERS + "."),
        client_only=client_only,
        product=_first_para(doc),
        factory_sig=_factory_sig(tree, factory),
        features=tuple(spec.get("features") or ()),
        config=dict(spec.get("config") or {}),
        limits=_limits(doc),
        full_doc=doc,
    )


def target_bindings(root: Path) -> dict[str, list[Binding]]:
    """capability -> every ``adapter:`` binding of a target file in the checkout."""
    out: dict[str, list[Binding]] = {}
    files = sorted({p for g in TARGET_GLOBS for p in root.glob(g)})
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        caps = doc.get("capabilities") if isinstance(doc, dict) else None
        if not isinstance(caps, dict):
            continue
        for cap, spec in caps.items():
            if isinstance(spec, dict) and isinstance(spec.get("adapter"), str):
                rel = f.relative_to(root).as_posix()
                b = _binding(rel, str(doc.get("name", "")), spec["adapter"], spec, root, False)
                out.setdefault(cap, []).append(b)
    return out


def _client_adapters(contract: ModuleType, root: Path, bound: Iterable[Binding]) -> list[Binding]:
    """Real-product client adapters the contract module imports but no target file binds."""
    have = {b.adapter.partition(":")[0] for b in bound}
    _, tree = _ast_module(contract.__name__, root)
    out: list[Binding] = []
    for n in tree.body if tree else ():
        if not isinstance(n, ast.ImportFrom) or not (n.module or "").startswith(
            REAL_ADAPTERS + "."
        ):
            continue
        module = str(n.module)
        if module in have:
            continue
        _, mtree = _ast_module(module, root)
        mod = sys.modules.get(module)
        # the client: the first public class of the module that is neither an error nor a record
        cls = next(
            (
                c.name
                for c in (mtree.body if mtree else ())
                if isinstance(c, ast.ClassDef)
                and not c.name.startswith("_")
                and isinstance(k := getattr(mod, c.name, None), type)
                and not issubclass(k, BaseException)
                and not dataclasses.is_dataclass(k)
            ),
            "",
        )
        out.append(_binding("", "", f"{module}:{cls}", {}, root, True))
    return out


# --------------------------------------------------------------------------- collect


def collect(root: Path, registry: Registry | None = None) -> list[Capability]:
    """Every conformance capability, introspected from the checkout at ``root``."""
    from homelabnext.conform.core import TEST_HOOKS
    from homelabnext.conform.registry import CAPABILITIES, load_module

    bindings = target_bindings(root)
    out: list[Capability] = []
    for cap in CAPABILITIES:
        smod = load_module(cap, root)
        suite = smod.SUITE
        mod_name, _, proto_name = suite.protocol.partition(":")
        contract = importlib.import_module(mod_name)
        protocols, data, constants, errors = _contract(contract)
        # the suite's Protocol first, then the rest in contract order
        protocols.sort(key=lambda s: s.name != proto_name)
        checks = [Check(s.id, s.severity, s.summary, s.requires) for s in suite.specs]
        mutants = [
            (n, m.fails, m.description) for n, m in sorted(getattr(smod, "MUTANTS", {}).items())
        ]
        fake = _fake(smod, root)
        bound = bindings.get(cap, [])
        bound = sorted(bound, key=lambda b: (not b.real, b.target_file))
        clients = _client_adapters(contract, root, bound)
        start = [mod_name, smod.__name__] + ([fake[1]] if fake[1] else [])
        providers: list[tuple[str, str]] = []
        consumers: list[str] = []
        if registry is not None:
            providers = [
                (s.name, s.impl or "") for s in registry.sorted_services() if s.capability == cap
            ]
            names = {p for p, _ in providers}
            consumers = sorted(
                s.name
                for s in registry.sorted_services()
                if names & set(s.upstreams) and s.name not in names
            )
        out.append(
            Capability(
                name=cap,
                summary=suite.summary,
                protocol=suite.protocol,
                contract_module=mod_name,
                contract_doc=_md(contract.__doc__),
                suite_module=smod.__name__,
                protocols=protocols,
                data=data,
                constants=constants,
                errors=errors,
                schemas=_schema_links(start, root),
                checks=checks,
                hooks=frozenset(TEST_HOOKS),
                mutants=mutants,
                fake=fake,
                bindings=bound + clients,
                providers=providers,
                consumers=consumers,
            )
        )
    return out


# --------------------------------------------------------------------------- data


def features(c: Capability) -> list[tuple[str, bool, list[str]]]:
    """``(feature, is a test hook, ids of the checks needing it)`` for every feature a check
    requires, sorted by name."""
    feats = sorted({r for ch in c.checks for r in ch.requires})
    return [(f, f in c.hooks, [ch.id for ch in c.checks if f in ch.requires]) for f in feats]


def _binding_data(b: Binding) -> dict[str, Any]:
    return {
        "adapter": b.adapter,
        "module_file": b.module_file,
        "target_file": b.target_file,
        "target_name": b.target_name,
        "real": b.real,
        "client_only": b.client_only,
        "product": b.product,
        "factory": b.factory_sig,
        "features": list(b.features),
        "config": b.config,
        "limits": list(b.limits),
    }


def _method_data(m: Method) -> dict[str, Any]:
    return {
        "name": m.name,
        "signature": render_signature(m),
        "params": [dataclasses.asdict(p) for p in m.params],
        "returns": m.returns,
        "raises": list(m.raises),
        "doc": m.doc,
        "defined_in": m.defined_in,
    }


def _shape_data(s: Shape) -> dict[str, Any]:
    out: dict[str, Any] = {"name": s.name, "kind": s.kind, "module": s.module, "doc": s.doc}
    if s.kind == "exception":
        out["base"] = s.base
    else:
        out["frozen"] = s.frozen
        out["fields"] = [dataclasses.asdict(f) for f in s.fields]
        out["methods"] = [_method_data(m) for m in s.methods]
    return out


def summary_data(c: Capability) -> dict[str, Any]:
    """One row of the capability index as plain data (``hnx mcp``'s ``list_capabilities``)."""
    return {
        "name": c.name,
        "purpose": c.summary,
        "operations": c.operations,
        "must": c.count("must"),
        "should": c.count("should"),
        "implementations": {
            "fake": c.fake[0] if c.fake[1] else "",
            "adapters": [
                {"adapter": b.adapter, "target_file": b.target_file, "real": b.real}
                for b in c.bindings
            ],
            "services": [s for s, _ in c.providers],
        },
    }


def contract_data(c: Capability) -> dict[str, Any]:
    """Everything a capability page shows, as plain data (``hnx mcp``'s ``get_contract``): the
    same model :func:`render_page` renders, so the two cannot disagree."""
    return {
        "name": c.name,
        "purpose": c.summary,
        "protocol": c.protocol,
        "contract_module": c.contract_module,
        "suite_module": c.suite_module,
        "description": c.contract_doc,
        "operations": [
            {"protocol": p.name, **_method_data(m)} for p in c.protocols for m in p.methods
        ],
        "protocols": [{"name": p.name, "module": p.module, "doc": p.doc} for p in c.protocols],
        "data_shapes": [_shape_data(s) for s in c.data],
        "constants": [{"name": n, "value": v} for n, v in c.constants],
        "errors": [_shape_data(e) for e in c.errors],
        "schemas": [{"path": p, "loaded_by": m} for p, m in c.schemas],
        "checks": [
            {
                "id": ch.id,
                "level": ch.severity.upper(),
                "assertion": ch.summary,
                "requires": list(ch.requires),
            }
            for ch in c.checks
        ],
        "features": [
            {"name": f, "kind": "test-hook" if hook else "product", "checks": ids}
            for f, hook, ids in features(c)
        ],
        "mutants": [{"name": n, "must_fail": f, "defect": d} for n, f, d in c.mutants],
        "fake": {"class": c.fake[0], "module": c.fake[1], "summary": c.fake[2]},
        "adapters": [_binding_data(b) for b in c.bindings],
        "services": {
            "providers": [{"name": s, "impl": impl} for s, impl in c.providers],
            "consumers": list(c.consumers),
        },
    }


# --------------------------------------------------------------------------- rendering


def _src(rel: str, label: str | None = None) -> str:
    """A link from docs/capabilities/ to a repository file."""
    return f"[`{label or rel}`](../../{rel})" if rel else _code(label or "")


def _cap_link(name: str, label: str | None = None) -> str:
    return f"[{label or name}]({name}.md) ([[capabilities/{name}\\|{label or name}]])"


def _cap_link_text(name: str, label: str | None = None) -> str:
    """The same link outside a table (no escaped pipe)."""
    return f"[{label or name}]({name}.md) ([[capabilities/{name}|{label or name}]])"


def _sys_link(service: str, in_table: bool = False) -> str:
    bar = "\\|" if in_table else "|"
    return f"[{service}](../systems/{service}.md) ([[systems/{service}{bar}{service}]])"


def _module_link(module: str, root: Path) -> str:
    return _src(_module_file(module, root), module)


def _render_method(m: Method, owner: str) -> list[str]:
    out = [f"#### `{owner}.{m.name}`\n", "```python", render_signature(m), "```\n"]
    if m.defined_in:
        out.append(f"Inherited from `{m.defined_in}`.\n")
    if m.params:
        out += ["| Parameter | Type | Default | Passing |", "|---|---|---|---|"]
        for p in m.params:
            out.append(
                f"| `{p.name}` | {_code(_cell(p.type))} | {_code(_cell(p.default)) or 'required'}"
                f" | {p.kind or 'positional or keyword'} |"
            )
        out.append("")
    out.append(f"**Returns:** {_code(_cell(m.returns)) or 'not annotated'}\n")
    if m.doc:
        out.append(m.doc + "\n")
    if m.raises:
        out.append("**Raises:** " + ", ".join(f"`{r}`" for r in m.raises) + "\n")
    return out


def _field_table(fields: list[Field], header: str = "Field") -> list[str]:
    out = [f"| {header} | Type | Default | Notes |", "|---|---|---|---|"]
    for f in fields:
        out.append(
            f"| `{f.name}` | {_code(_cell(f.type))} | {_cell(f.default)} | {_cell(_md(f.note))} |"
        )
    return [*out, ""]


INDEX_SUMMARY = (
    "Every capability contract: what it is for, how many operations and checks it has, "
    "and which adapters and services provide it."
)


def capability_summary(c: Capability) -> str:
    """The page's level-0 summary (ADR-0032): the contract's one-line purpose as a sentence, cut to
    the summary limit."""
    from homelabnext.context.levels import clean, cut

    purpose = clean(c.summary)
    first = purpose[:1].upper() + purpose[1:]
    return cut(f"{first.rstrip('.')}.")


def render_page(c: Capability, root: Path) -> str:
    L: list[str] = [
        "---",
        f"title: {c.name}",
        "type: capability",
        generated_summary_lines(capability_summary(c)),
        f"capability: {c.name}",
        f"protocol: '{c.protocol}'",
        f"generated_by: {GENERATOR}",
        "---",
        "",
        f"# {c.name}",
        "",
        f"> Generated by `{GENERATOR}` from the contract, the conformance suite, the fakes, the"
        " target files and the service registry. Do not edit: change the code and regenerate.",
        "",
        f"**{c.summary[:1].upper() + c.summary[1:]}.**",
        "",
        f"- Contract: {_module_link(c.contract_module, root)} (`{c.protocol}`)",
        f"- Conformance suite: {_module_link(c.suite_module, root)}"
        f" ({len(c.checks)} checks: {c.count('must')} MUST, {c.count('should')} SHOULD)",
        f"- Index: {_cap_link_text('README', 'all capabilities')}"
        " · [Conformance harness](../conformance.md) ([[conformance]])"
        " · [Swap procedure](../swap.md) ([[swap]])",
        "",
        "## What it does",
        "",
        c.contract_doc or "_The contract module has no docstring._",
        "",
        "## How to use it",
        "",
        "Every operation of the contract. A subject (an adapter's object) implements the Protocols"
        " below; methods documented on data types are part of the contract too.",
        "",
    ]
    for p in c.protocols:
        L.append(f"### `{p.name}` (Protocol)\n")
        L.append(f"Defined in {_module_link(p.module, root)}.\n")
        if p.doc:
            L.append(p.doc + "\n")
        if p.fields:
            L.append("Attributes the subject must expose:\n")
            L += _field_table(p.fields, "Attribute")
        for m in p.methods:
            L += _render_method(m, p.name)
    L += ["## Data shapes in and out", ""]
    if not c.data and not c.constants:
        L.append(
            "The contract declares no data types of its own; operations take and return the"
            " built-in types shown in their signatures.\n"
        )
    for s in c.data:
        kind = {"dataclass": "dataclass" + (", frozen" if s.frozen else "")}.get(s.kind, s.kind)
        L.append(f"### `{s.name}` ({kind})\n")
        L.append(f"Defined in {_module_link(s.module, root)}.\n")
        if s.doc:
            L.append(s.doc + "\n")
        if s.fields:
            L += _field_table(s.fields, "Member" if s.kind == "enum" else "Field")
        for m in s.methods:
            L += _render_method(m, s.name)
    if c.constants:
        L += ["### Constants\n", "| Name | Value |", "|---|---|"]
        L += [f"| `{n}` | `{_cell(v)}` |" for n, v in c.constants]
        L.append("")
    L += ["### Errors\n"]
    if c.errors:
        L += [
            "Adapters raise these (never a bare product exception); a check that expects a"
            " rejection pins the type.\n",
            "| Exception | Base | Meaning | Named by |",
            "|---|---|---|---|",
        ]
        for e in c.errors:
            users = [
                f"`{p.name}.{m.name}`"
                for p in (*c.protocols, *c.data)
                for m in p.methods
                if e.name in m.raises
            ]
            L.append(
                f"| `{e.name}` | `{e.base}` | {_cell(_first_para(e.doc))} | {', '.join(users)} |"
            )
        L.append("")
    else:
        L.append("The contract exports no exception types; see the method docstrings.\n")
    L += ["### JSON Schemas\n"]
    if c.schemas:
        L += [
            "Schemas the contract's own code loads (found in the source, not curated):\n",
            "| Schema | Loaded by |",
            "|---|---|",
        ]
        L += [f"| {_src(path)} | `{mod}` |" for path, mod in c.schemas]
        L.append("")
    else:
        L.append(
            "None: no module of this contract, its suite or its fake loads a schema from"
            " `schemas/`.\n"
        )
    L += [
        "## Behavioural contract",
        "",
        "What `hnx conform run` proves. A MUST failure fails the capability; a SHOULD failure is"
        " reported and fails only with `--strict` (or may be waived with a reason in the target"
        " file).",
        "",
        "| Check | Level | Asserts | Requires |",
        "|---|---|---|---|",
    ]
    for ch in c.checks:
        L.append(
            f"| `{ch.id}` | {ch.severity.upper()} | {_cell(ch.summary)} |"
            f" {', '.join(f'`{r}`' for r in ch.requires)} |"
        )
    L.append("")
    feats = features(c)
    L += ["### Features an adapter may declare\n"]
    if feats:
        L += ["| Feature | Kind | Checks that need it |", "|---|---|---|"]
        for f, hook, needed_by in feats:
            kind = (
                "test hook (a MUST check needing it is `untested` without it)"
                if hook
                else "product feature (checks skip without it)"
            )
            ids = ", ".join(f"`{i}`" for i in needed_by)
            L.append(f"| `{f}` | {kind} | {ids} |")
        L.append("")
    else:
        L.append("None: every check runs against every target.\n")
    if c.mutants:
        L += [
            "### Defects the suite is proven to catch\n",
            "Each is a deliberately broken fake (`hnx conform run"
            f" {c.name} --target broken:<mutant>` must fail the named check).\n",
            "| Mutant | Must fail | Defect |",
            "|---|---|---|",
        ]
        L += [f"| `{n}` | `{f}` | {_cell(d)} |" for n, f, d in c.mutants]
        L.append("")
    L += ["## Implementations", "", "### Built-in fake", ""]
    name, module, doc = c.fake
    if module:
        L.append(
            f"`{name}` in {_module_link(module, root)}: `hnx conform run {c.name}` (the default"
            " target `fake`) runs the suite against it.\n"
        )
        if doc:
            L.append(f"> {doc}\n")
    else:
        L.append("None found.\n")
    real = c.real_bindings
    L.append("### Real-product adapters\n")
    if not real:
        L.append(
            "None yet in this repository. See [Integrating a new product](#integrating-a-new-product).\n"
        )
    for b in real:
        L.append(f"#### {_src(b.module_file, b.adapter)}\n")
        L.append(f"{b.product}\n")
        if b.target_file:
            L.append(f"- Target file: {_src(b.target_file)} (target `{b.target_name}`)")
        else:
            L.append(
                "- Target file: none in the repository (the contract module imports this"
                " client; it is driven by the fake's server in the suite)"
            )
        if b.factory_sig:
            L.append(f"- Factory: `{b.factory_sig}`")
        if b.config:
            L.append(f"- Config in the target: `{_cell(_flow(b.config))}`")
        if b.features:
            L.append("- Features declared: " + ", ".join(f"`{f}`" for f in b.features))
        L.append("")
        if b.limits:
            L.append("**Product limits recorded by the adapter:**\n")
            L += [lim + "\n" for lim in b.limits]
        if b.full_doc and b.full_doc != b.product:
            L += [
                "<details><summary>Full adapter notes</summary>",
                "",
                b.full_doc,
                "",
                "</details>",
                "",
            ]
    others = [b for b in c.bindings if not b.real]
    if others:
        L += [
            "### Other targets in the repository\n",
            "Stand-ins wired through target files (fakes or adapters over a local test double).\n",
            "| Target file | Adapter | What it is |",
            "|---|---|---|",
        ]
        for b in others:
            L.append(
                f"| {_src(b.target_file)} | {_src(b.module_file, b.adapter)} | {_cell(b.product)} |"
            )
        L.append("")
    L += ["### Registry services\n"]
    if c.providers:
        L.append("Provided by (`examples/services.yml`):\n")
        L += ["| Service | Implementation |", "|---|---|"]
        L += [f"| {_sys_link(s, True)} | `{impl or 'unspecified'}` |" for s, impl in c.providers]
        L.append("")
        if c.consumers:
            L.append("Depended on by: " + ", ".join(_sys_link(s) for s in c.consumers) + "\n")
    else:
        L.append(f"No service in `examples/services.yml` declares `capability: {c.name}`.\n")
    L += _integration(c)
    return "\n".join(L).rstrip() + "\n"


def _flow(d: dict[str, Any]) -> str:
    return yaml.safe_dump(d, default_flow_style=True, sort_keys=False, width=1000).strip()


def _integration(c: Capability) -> list[str]:
    mod, _, proto = c.protocol.partition(":")
    hooks = sorted({r for ch in c.checks for r in ch.requires if r in c.hooks})
    product = sorted({r for ch in c.checks for r in ch.requires if r not in c.hooks})
    exported = _exported_names(c)
    raised = {r for p in (*c.protocols, *c.data) for m in p.methods for r in m.raises}
    errs = [
        e.name
        for e in c.errors
        if e.name in exported and (e.name in raised or e.base == "Exception")
    ]
    example = next((b for b in c.real_bindings if b.factory_sig), None)
    names = [proto, *errs]
    # ruff formats Python fences in Markdown: one name inline, several exploded (trailing comma)
    imports = (
        [f"   from {mod} import {proto}"]
        if len(names) == 1
        else [f"   from {mod} import (", *(f"       {n}," for n in names), "   )"]
    )
    L = [
        "## Integrating a new product",
        "",
        f"1. **Implement the contract.** Write an object that satisfies `{proto}` (every operation"
        " above) and raises the contract's errors, never the product's own exceptions:",
        "",
        "   ```python",
        *imports,
        "   ```",
        "",
        "2. **Write a factory.** A target file names `package.module:factory`; the harness calls"
        " `factory(**config)` and runs the suite on what it returns. Take only keyword options;"
        " resolve the endpoint through the registry resolver"
        f" (`{env_var_name(c.name)}` overrides it, as the lab-in-a-box smoke exports), never from"
        " a URL in the target, and read credentials from named environment variables at request"
        " time.",
        "",
        "   ```python",
        f"   def make(**config) -> {proto}: ...",
        "   ```",
        "",
    ]
    if example:
        L += [
            f"   The factory this repository ships: `{example.adapter}` is `{example.factory_sig}`.",
            "",
        ]
    target = {
        "name": "my-target",
        "capabilities": {
            c.name: {
                "adapter": "my_adapters.my_product:make",
                "config": {},
                **({"features": product} if product else {}),
            }
        },
    }
    L += [
        "3. **Describe the target** (YAML; `features` lists only what the product really offers"
        + (f"; the test hooks {', '.join(f'`{h}`' for h in hooks)} are for fakes" if hooks else "")
        + "; `waive:` takes SHOULD check ids with a reason, never a MUST):",
        "",
        "   ```yaml",
        *("   " + line for line in yaml.safe_dump(target, sort_keys=False).rstrip().splitlines()),
        "   ```",
        "",
        "4. **Prove it:**",
        "",
        "   ```",
        f"   hnx conform run {c.name} --target path/to/my-target.yml -v",
        f"   hnx conform run {c.name} --target path/to/my-target.yml --strict   # SHOULD checks too",
        "   ```",
        "",
        f"   Every MUST check ({c.count('must')}) has to pass. Then follow the"
        " [swap procedure](../swap.md) ([[swap]]) to replace the incumbent.",
        "",
    ]
    return L


def _exported_names(c: Capability) -> set[str]:
    mod = sys.modules.get(c.contract_module)
    return set(getattr(mod, "__all__", ()))


def render_index(caps: list[Capability], registry: Registry | None) -> str:
    L = [
        "---",
        "title: Capabilities",
        "type: capability-index",
        generated_summary_lines(INDEX_SUMMARY),
        f"generated_by: {GENERATOR}",
        "---",
        "",
        "# Capabilities",
        "",
        f"> Generated by `{GENERATOR}`. Do not edit: change the code and regenerate.",
        "",
        "Each capability is a seam: a small contract (`conformance/protocols/`), a conformance"
        " suite that proves any implementation of it, a built-in fake, and the adapters that bind"
        " real products. Use this table to choose a tool and to see what integrating one costs;"
        " each page has the operations, the data shapes in and out, the checks, the adapters and"
        " their product limits.",
        "",
        "| Capability | What it is | Operations | MUST | SHOULD | Real-product adapters | Provided by |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in caps:
        adapters = (
            ", ".join(
                dict.fromkeys(  # one adapter behind several target files is listed once
                    f"`{b.adapter.partition(':')[0].rsplit('.', 1)[-1]}`"
                    + (" (client)" if b.client_only else "")
                    for b in c.real_bindings
                )
            )
            or "none yet"
        )
        provided = ", ".join(_sys_link(s, True) for s, _ in c.providers) or "none"
        L.append(
            f"| {_cap_link(c.name)} | {_cell(c.summary)} | {c.operations} | {c.count('must')} |"
            f" {c.count('should')} | {adapters} | {provided} |"
        )
    L.append("")
    if registry is not None:
        names = {c.name for c in caps}
        L += [
            "## Registry services and their capability",
            "",
            "Every service in `examples/services.yml`, and the capability page that holds its"
            " contract where it is one of the conformance capabilities.",
            "",
            "| Service | Capability | Implementation | Contract |",
            "|---|---|---|---|",
        ]
        for s in registry.sorted_services():
            contract = _cap_link(s.capability) if s.capability in names else "no conformance suite"
            L.append(
                f"| {_sys_link(s.name, True)} | `{s.capability}` | `{s.impl or 'unspecified'}` | {contract} |"
            )
        L.append("")
    L += [
        "## Regenerate and check",
        "",
        "```",
        "hnx docs capabilities generate   # rewrite every page from the checkout",
        "hnx docs capabilities check      # exit 1 on a stale, missing or orphan page (make check, CI)",
        "```",
        "",
        "See also: [docs home](../README.md) ([[README|docs home]]),"
        " [system pages](../systems.md) ([[systems]]),"
        " [conformance harness](../conformance.md) ([[conformance]]).",
    ]
    return "\n".join(L) + "\n"


def render_all(root: Path, registry: Registry | None) -> dict[str, str]:
    """``{file name: content}`` for every page of ``docs/capabilities``."""
    caps = collect(root, registry)
    pages = {f"{c.name}.md": render_page(c, root) for c in caps}
    pages[INDEX] = render_index(caps, registry)
    return dict(sorted(pages.items()))


# --------------------------------------------------------------------------- generate / check


@dataclass
class Report:
    missing: list[str] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)
    orphans: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not (self.missing or self.stale or self.orphans)

    def lines(self) -> list[str]:
        out = [f"missing page: {n}" for n in self.missing]
        out += [f"stale page (run `{GENERATOR}`): {n}" for n in self.stale]
        out += [f"orphan page (no such capability): {n}" for n in self.orphans]
        return out


def generate(
    out_dir: str | Path, root: Path, registry: Registry | None
) -> tuple[list[str], list[str]]:
    """Write every page; remove orphans.  Returns (written, removed).

    Orphans are removed only from a directory this generator owns
    (:func:`homelabnext._generated.claim`: ``<root>/docs/capabilities``, or one it created or
    marked); any other ``out_dir`` is written to and nothing in it is deleted."""
    from homelabnext._generated import claim

    out = Path(out_dir)
    prune = claim(out, "hnx docs capabilities", Path(root) / PAGES_DIR)
    pages = render_all(root, registry)
    written = []
    for name, text in pages.items():
        p = out / name
        if not p.exists() or p.read_text(encoding="utf-8") != text:
            p.write_text(text, encoding="utf-8")
            written.append(name)
    removed = sorted(p.name for p in out.glob("*.md") if p.name not in pages) if prune else []
    for n in removed:
        (out / n).unlink()
    return written, removed


def check(out_dir: str | Path, root: Path, registry: Registry | None) -> Report:
    d = Path(out_dir)
    pages = render_all(root, registry)
    rep = Report()
    for name, text in pages.items():
        p = d / name
        if not p.is_file():
            rep.missing.append(name)
        elif p.read_text(encoding="utf-8") != text:
            rep.stale.append(name)
    rep.orphans = (
        sorted(p.name for p in d.glob("*.md") if p.name not in pages) if d.is_dir() else []
    )
    return rep
