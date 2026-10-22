# SPDX-License-Identifier: Apache-2.0
"""The MCP catalog: one record per MCP server, the single source of truth (ADR-0024).

A catalog is a directory of YAML records, ``<catalog>/<id>.yml``, each one
``schemas/platform/mcp_server.schema.json`` (1.0).  The example lab's is ``examples/mcp/``; a real
lab's lives in its private overlay beside its registry (``lab/mcp/``), found the same way the other
example data is (``HNX_EXAMPLES_DIR``, ``HNX_DATA_DIR``; ``docs/private-overlay.md``).

Everything else that knows about MCP servers is derived from it:

* the ``mcp`` section of the capability-class table (:meth:`Catalog.classes`, read by
  :meth:`homelabnext.agent.readers.ToolClasses.load`): a server's classes are the union of its
  tools' classes, so ``hnx agent`` levels and the reader rule judge the catalog's servers;
* the knowledge graph's ``mcp:<id>`` nodes and their edges (``homelabnext.graph.sources``);
* the MCP line of the system pages (``homelabnext.sop.pages``) and the hub's MCP servers page;
* every client configuration (:mod:`.clients`, ``hnx mcp catalog render``).

:func:`check` is fatal, like the other registers: schema, the id is the file name (so ids are
unique), a third-party origin is pinned (an exact version with a hash or lock, an image digest, a
40-hex commit), every tool is classed with the table's vocabulary, egress agrees with the tools'
classes, credentials are secret names that stay distinct and no setting names one, parameters are
typed with env keys that are never hard-denied (:data:`DENIED_ENV`) or shared, templates name only
builtins and parameters, endpoints and hosts resolve in the registry and every registry ``mcp``
entry resolves to a catalog server, a retired or deprecated server says why, ``replaced_by`` names
an active server, ``implements`` names a capability contract, and an active server carries the
reviews the review policy asks of ``mcp-server.active``.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from homelabnext.registry.model import secret_env_name

from . import launch

#: the schema every record validates against
SCHEMA = ("platform", "mcp_server")
#: the review policy's artefact kind (``homelabnext.reviews.ARTEFACT_STATES``)
ARTEFACT = "mcp-server"
STATUSES = ("draft", "active", "deprecated", "retired")
#: statuses a profile may be granted (deprecated with a warning)
GRANTABLE = ("active", "deprecated")
HTTP_TRANSPORTS = ("streamable-http", "sse")
#: registry ``mcp.transport`` -> catalog transport type
REGISTRY_TRANSPORT = {"http": "streamable-http", "sse": "sse", "stdio": "stdio"}
#: the directory name of a catalog beside a registry file or under an examples tree
CATALOG_DIR = "mcp"
#: environment keys no grant may ever set, whatever a record says: they change what code runs
#: or how, not what a server is scoped to.  The same list as llm-orchestrator's
#: internal/grants/grants.go:71 (deniedEnvRe), so a rendered catalog it would refuse fails here.
DENIED_ENV = re.compile(
    r"^(LD_.*|DYLD_.*|PATH|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONINSPECT|HOME|SHELL|BASH_ENV"
    r"|ENV|NODE_OPTIONS|HERMES_HOME)$"
)
#: ``{name}`` in an instance name, an argument, a setting or a parameter default
TEMPLATE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
#: template names every instance has: the record id, the profile's bare name, the lane, the
#: render spec output's ``home`` (empty outside one), and (in arguments only) the rendered
#: profile's file
BUILTINS = ("id", "profile", "lane", "home")
PROFILE_FILE = "profile_file"
#: a setting key that names a credential: its value belongs in the secret store (``env``)
SECRET_KEY = re.compile(r"TOKEN|SECRET|PASSW|API_?KEY|PRIVATE|CREDENTIAL|COOKIE|SESSION", re.I)


class CatalogError(ValueError):
    """The catalog cannot be read at all (a missing directory, a file that is not YAML)."""


@dataclass
class Catalog:
    """The records of one catalog directory, by id (``servers``) and by file (``files``)."""

    root: Path
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    files: dict[str, Path] = field(default_factory=dict)
    #: problems found while loading (duplicate ids, a record that is not a mapping)
    problems: list[str] = field(default_factory=list)
    #: :func:`integrity_problems`, computed once
    _integrity: list[str] | None = field(default=None, repr=False, compare=False)

    def __iter__(self):
        return iter(sorted(self.servers.items()))

    def get(self, sid: str) -> dict[str, Any] | None:
        return self.servers.get(sid)

    def classes(self) -> dict[str, list[str]]:
        """``{id: [classes]}``: each server's classes, the union of its tools' (the derived
        ``mcp`` section of the capability-class table).  A server with no tools is left out, so
        a grant of it is judged unknown (refused for a reader)."""
        out: dict[str, list[str]] = {}
        for sid, rec in self:
            got = sorted({c for t in rec.get("tools") or () for c in t.get("classes") or ()})
            if got:
                out[sid] = got
        return out

    def status(self, sid: str) -> str | None:
        rec = self.servers.get(sid)
        return None if rec is None else str(rec.get("status"))

    def digest(self) -> str:
        """sha256 of the canonical JSON of every record (what a rendered config was built from)."""
        from homelabnext.agent.digest import digest_of

        return digest_of(dict(self))

    def rel(self, sid: str) -> str:
        """The record's file as ``<catalog dir name>/<file>`` (how pages and messages name it)."""
        f = self.files[sid]
        return f"{f.parent.name}/{f.name}"


def default_dir() -> Path:
    """The catalog under the example data (``HNX_EXAMPLES_DIR`` / ``HNX_DATA_DIR`` aware)."""
    from homelabnext import paths

    return paths.examples_dir() / CATALOG_DIR


def beside(registry_path: str | Path) -> Path:
    """The catalog directory a registry file implies: ``mcp/`` next to it."""
    return Path(registry_path).resolve().parent / CATALOG_DIR


def _read(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogError(f"{path}: cannot read: {exc}") from exc


def load(path: str | Path | None = None) -> Catalog:
    """Read every ``*.yml`` record of a catalog directory (not validated: :func:`check`).  Another
    record-like file (``*.yaml``, ``*.json``) is a load problem, never silently skipped."""
    root = Path(path) if path is not None else default_dir()
    if not root.is_dir():
        raise CatalogError(f"{root}: no MCP catalog directory")
    cat = Catalog(root)
    for f in sorted(root.iterdir()):
        if f.is_file() and f.suffix.lower() in (".yml", ".yaml", ".json") and f.suffix != ".yml":
            cat.problems.append(
                f"{f.name}: a record file is <id>.yml; this one is not read (rename it)"
            )
    for f in sorted(root.glob("*.yml")):
        doc = _read(f)
        if not isinstance(doc, Mapping):
            cat.problems.append(f"{f.name}: a record must be a mapping")
            continue
        sid = str(doc.get("id") or f.stem)
        if sid in cat.servers:
            cat.problems.append(
                f"{f.name}: id {sid!r} is already defined by {cat.files[sid].name} (ids are unique)"
            )
            continue
        cat.servers[sid] = dict(doc)
        cat.files[sid] = f
    return cat


@cache
def _cached(path: str) -> Catalog:
    return load(path)


def load_cached(path: str | Path | None = None) -> Catalog:
    """:func:`load`, cached per resolved directory for the process (the class table, the graph)."""
    root = Path(path) if path is not None else default_dir()
    return _cached(str(root.resolve()))


def record_digest(record: Mapping[str, Any]) -> str:
    """The content a reviewer stamps: the record without its ``reviews``."""
    from homelabnext.reviews import content_digest

    return content_digest({k: v for k, v in record.items() if k != "reviews"})


def file_digest(path: str | Path) -> str:
    doc = _read(Path(path))
    if not isinstance(doc, Mapping):
        raise CatalogError(f"{path}: a record must be a mapping")
    return record_digest(doc)


# ------------------------------------------------------------------------------------ check
#: the ``oneOf`` branches of the schema, chosen by a discriminating field so a mismatch is
#: reported against the branch the record meant, not as "not valid under any of the given schemas"
_BRANCHES = {
    "origin": ("kind", {"first-party": "origin_first_party", "package": "origin_package",
                        "image": "origin_image", "git": "origin_git", "unknown": "origin_unknown"}),
    "transport": ("type", {"stdio": "transport_stdio", "streamable-http": "transport_http",
                           "sse": "transport_http"}),
}  # fmt: skip
#: the record-level ``not required`` rules (headers only on a remote server, env and settings
#: only on a stdio one)
_NOT_REQUIRED = {
    "headers": "headers are for a remote (http/sse) server; a stdio server takes env",
    "env": "env is for a stdio server; a remote server's credentials go in headers",
    "settings": "settings are for a stdio server; a remote server takes none",
}


@cache
def _validator() -> Any:
    from jsonschema import Draft202012Validator

    from homelabnext import paths
    from homelabnext.agent.schemas import _registry

    schema = json.loads(paths.schema_file(*SCHEMA[:1], f"{SCHEMA[1]}.schema.json").read_text())
    return Draft202012Validator(schema, registry=_registry())


def _message(e: Any) -> str:
    """One readable message for a schema error: for a ``oneOf`` (a version that is null or exact,
    a digest that is null or sha256), the alternative that is not a type mismatch."""
    if e.validator == "oneOf" and e.context:
        useful = [c for c in e.context if c.validator != "type"] or list(e.context)
        return useful[0].message
    return e.message


def _schema_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    v = _validator()
    doc = json.loads(json.dumps(rec))
    out: list[str] = []
    for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path))):
        path = "/".join(map(str, e.absolute_path)) or "$"
        if e.validator == "oneOf" and path in _BRANCHES and isinstance(e.instance, Mapping):
            key, branches = _BRANCHES[path]
            got = e.instance.get(key)
            if got not in branches:
                out.append(f"{where}: {path}.{key} must be one of {sorted(branches)}, not {got!r}")
                continue
            sub = v.evolve(schema={"$ref": f"#/$defs/{branches[got]}", "$defs": v.schema["$defs"]})
            for se in sorted(sub.iter_errors(e.instance), key=lambda x: list(map(str, x.path))):
                spath = "/".join(map(str, se.absolute_path))
                out.append(f"{where}: {path}{'/' + spath if spath else ''}: {_message(se)}")
            continue
        if e.validator == "not" and isinstance(e.validator_value, Mapping):
            field = (e.validator_value.get("required") or [""])[0]
            if field in _NOT_REQUIRED:
                out.append(f"{where}: {_NOT_REQUIRED[field]}")
                continue
        out.append(f"{where}: {path}: {_message(e)}")
    return out


def origin_problems(
    origin: Any, where: str, source_root: Path | None = None, catalog_root: Path | None = None
) -> list[str]:
    """A third-party origin must be pinned; a lock file (relative to the catalog) must exist and
    name the package; a first-party path must exist (in a checkout)."""
    if not isinstance(origin, Mapping):
        return []
    kind = origin.get("kind")
    out: list[str] = []
    if kind == "unknown":
        out.append(
            f"{where}: origin is unknown ({origin.get('hint') or 'no hint'}): name the "
            "first-party path, or the package with its exact version and sha256, the image "
            "digest or the git commit"
        )
    elif kind == "package":
        if not origin.get("version"):
            out.append(f"{where}: package {origin.get('package')} has no exact version (unpinned)")
        if not origin.get("sha256") and not origin.get("lock"):
            out.append(
                f"{where}: package {origin.get('package')} has no sha256 and no lock file "
                "(unpinned: record the release artifact's hash)"
            )
        lock = origin.get("lock")
        if lock and catalog_root is not None:
            f = catalog_root / str(lock)
            if not f.is_file():
                out.append(f"{where}: lock file {lock} does not exist (relative to the catalog)")
            elif str(origin.get("package")) not in f.read_text(encoding="utf-8", errors="replace"):
                out.append(f"{where}: lock file {lock} does not mention {origin.get('package')}")
    elif kind == "image" and not origin.get("digest"):
        out.append(f"{where}: image {origin.get('image')} has no digest (unpinned)")
    elif kind == "git" and not origin.get("commit"):
        out.append(f"{where}: git origin {origin.get('repo')} has no commit (unpinned)")
    elif kind == "first-party" and source_root is not None:
        p = source_root / str(origin.get("path", ""))
        if not p.exists():
            out.append(f"{where}: first-party path {origin.get('path')} is not in the source tree")
    return out


#: an exact npm release: npm resolves 1.2 or 1 as a range
_NPM_EXACT = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
#: origin kind (package: its ecosystem) -> the launchers that can run it pinned (:mod:`.launch`)
LAUNCHERS = {
    "npm": launch.NPM,
    "pypi": launch.PYPI,
    "image": launch.IMAGE,
    "git": launch.NPM + launch.PYPI,
    "first-party": ("hnx", "a path in the checkout"),
}


def launch_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    """The pinned origin is what the launcher runs, read the way the launcher reads its argv
    (:mod:`.launch`): the launch position (the first positional after the launcher's own flags, or
    the value of ``--from``/``--spec``/``--package``) is ``package@version`` for ``npx``/``bunx``,
    ``package==version`` (or ``@version``) for ``uvx``/``uv tool run``/``pipx run``,
    ``image@digest`` for ``docker``/``podman run``, ``git+repo@commit`` (npm: ``#commit``) for a
    git origin; a first-party server starts with ``hnx`` or a path.  Any other launcher, an
    unknown flag before the launch position, and the flags that add or redirect what runs
    (``--with``, an index, ``--registry``, ``--entrypoint`` ...) are refused.  A leading ``v`` in a
    version is not a difference; an npm version is a full ``x.y.z``.  (The sha256 itself is
    declarative: no launcher verifies it.)"""
    origin, t = rec.get("origin") or {}, rec.get("transport") or {}
    if t.get("type") != "stdio" or not isinstance(origin, Mapping):
        return []
    args = [str(a) for a in t.get("args") or ()]
    got = launch.parse(str(t.get("command", "")), args)
    kind = origin.get("kind")
    eco = origin.get("ecosystem") if kind == "package" else kind
    out: list[str] = []
    ver = origin.get("version")
    if kind == "package" and eco == "npm" and ver and not _NPM_EXACT.match(str(ver)):
        out.append(f"{where}: npm version {ver} is not a full x.y.z (npm reads it as a range)")
    if eco not in LAUNCHERS:
        if kind == "package":
            out.append(
                f"{where}: no launcher this check reads runs a pinned {eco} package (the pin "
                "would not control what runs): run it from an image pinned by digest"
            )
        return out
    if got.ecosystem is None or (
        got.ecosystem != eco and not (kind == "git" and got.ecosystem in ("npm", "pypi"))
    ):
        what = {"npm": "an npm package", "pypi": "a pypi package", "image": "an image",
                "git": "a git", "first-party": "a first-party"}[eco]  # fmt: skip
        out.append(
            f"{where}: {what} origin is launched by {' / '.join(LAUNCHERS[eco])}, not "
            f"{got.launcher} (the pin would not control what runs)"
        )
        return out
    out += [f"{where}: {p}" for p in got.problems]
    spec = got.spec or ""
    if kind == "package" and ver:
        pkg = str(origin.get("package"))
        want = f"{pkg}@{ver}" if eco == "npm" else f"{pkg}=={ver}"
        parts = launch.split_spec(eco, spec)
        same = parts is not None and (
            parts[0] == pkg if eco == "npm" else launch.pypi_name(parts[0]) == launch.pypi_name(pkg)
        )
        if not (same and launch.plain_version(parts[1]) == launch.plain_version(ver)):
            out.append(
                f"{where}: {got.launcher} does not launch the pinned {want} (its launch position "
                f"is {spec or 'empty'}: the pin would not control what runs)"
            )
    elif kind == "image" and origin.get("digest"):
        image = str(origin.get("image"))
        repo = image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
        parts = launch.split_image(spec)
        if parts is None or parts[0] != repo or parts[2] != origin["digest"]:
            out.append(
                f"{where}: {got.launcher} does not run the pinned {repo}@{origin['digest']} "
                f"(its image is {spec or 'missing'}: pull by digest)"
            )
    elif kind == "git" and origin.get("commit"):
        sep = "#" if got.ecosystem == "npm" else "@"
        repo = str(origin.get("repo")).removeprefix("git+")
        want = f"git+{repo}{sep}{origin['commit']}"
        if spec != want:
            out.append(
                f"{where}: {got.launcher} does not launch the pinned {want} (its launch position "
                f"is {spec or 'empty'}: a branch or tag moves)"
            )
    return out


def _tool_problems(rec: Mapping[str, Any], where: str, vocabulary: Iterable[str]) -> list[str]:
    tools = rec.get("tools") or []
    out: list[str] = []
    if not tools:
        out.append(f"{where}: lists no tools (classify every tool the server exposes)")
    known = set(vocabulary)
    seen: set[str] = set()
    for t in tools:
        name = str(t.get("name"))
        if name in seen:
            out.append(f"{where}: tool {name} is listed twice")
        seen.add(name)
        unknown = sorted(set(t.get("classes") or ()) - known)
        if not t.get("classes"):
            out.append(f"{where}: tool {name} has no capability class")
        if unknown:
            out.append(f"{where}: tool {name} has undeclared classes {unknown}")
    return out


def _egress_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    egress = rec.get("egress")
    classes = {c for t in rec.get("tools") or () for c in t.get("classes") or ()}
    out: list[str] = []
    if egress == "none" and "egress" in classes:
        out.append(
            f"{where}: a tool is classed egress but the server's egress is none "
            "(say what it reaches)"
        )
    if isinstance(egress, list) and "internet" in egress and "egress" not in classes:
        out.append(
            f"{where}: egress names internet but no tool is classed egress "
            "(a server that sends data out of the lab has an egress tool)"
        )
    return out


def _secret_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    refs: list[str] = []
    for v in (rec.get("env") or {}).values():
        refs.append(str(v))
    for v in (rec.get("headers") or {}).values():
        refs.append(str(v).split(" ")[-1])
    transport = rec.get("transport") or {}
    for a in transport.get("args") or ():
        ref = arg_secret(str(a))
        if ref:
            refs.append(ref)
    out: list[str] = []
    by_var: dict[str, str] = {}
    for ref in sorted(set(refs)):
        var = secret_env_name(ref)
        if var in by_var:
            out.append(
                f"{where}: {by_var[var]} and {ref} are both delivered as {var}; name them so "
                "they stay distinct"
            )
        by_var[var] = ref
    return out


#: a package spec as a launcher takes it (``name==1.2.0``, ``@scope/name@1.2.0``): never a secret
PACKAGE_SPEC = re.compile(
    r"^(@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*(==|@)v?[0-9][A-Za-z0-9._+-]*$"
)


def looks_secret(value: str) -> bool:
    """A value that is probably a credential: a URL with a password, or a long token-like string
    (mixed letters and digits, high entropy, no spaces or path separators).  A package spec with
    its version (``example-notes-mcp==1.2.0``) is not one."""
    if re.search(r"://[^/@\s:]+:[^/@\s]+@", value):
        return True
    v = value.strip()
    if len(v) < 20 or " " in v or "/" in v or v.startswith("$") or PACKAGE_SPEC.match(v):
        return False
    if not (re.search(r"[0-9]", v) and re.search(r"[A-Za-z]", v)):
        return False
    counts = {c: v.count(c) for c in set(v)}
    entropy = -sum(n / len(v) * math.log2(n / len(v)) for n in counts.values())
    return entropy >= 3.5


_SECRET_REF_FULL = re.compile(r"secret:[a-z][a-z0-9_-]*(?:/[a-z][a-z0-9_-]*)*")
#: ``Header-Name: [Scheme ]secret:<name>``, the argument after ``--header`` (mcp-remote and kin)
_HEADER_ARG = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s*(?:[A-Za-z]+ )?(secret:\S+)$")
#: a flag whose value is a credential (``--token``, ``--github-token``, ``--client-secret`` ...)
CREDENTIAL_FLAG = re.compile(
    r"^--?(?:[a-z0-9]+[-_])*(token|api[-_]?key|apikey|key|password|passwd|pass|pwd|passphrase"
    r"|secret|auth|bearer|credentials?|pat)$",
    re.I,
)


def arg_secret(arg: str) -> str | None:
    """The secret ref an argument carries (``secret:x``, ``--flag=secret:x`` or
    ``Header: [Scheme ]secret:x``), else None."""
    m = _HEADER_ARG.match(arg)
    value = m.group(1) if m else arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
    if _SECRET_REF_FULL.fullmatch(value):
        return value
    return None


def _credential_flag(flag: str) -> bool:
    return bool(CREDENTIAL_FLAG.match(flag) or SECRET_KEY.search(flag.lstrip("-")))


def _literal_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    """No literal credential and nothing a client would expand: an argument or a setting never
    holds ``$`` (``${VAR}``, ``$(cmd)``), a ``secret:`` reference only as a whole argument, a
    ``--flag=`` value or a header value, a credential flag's value is a ``secret:`` reference, and
    nothing looks like a token."""
    out: list[str] = []
    args = [str(a) for a in (rec.get("transport") or {}).get("args") or ()]
    for i, a in enumerate(args):
        n, ref = i + 1, arg_secret(a)
        flag, eq, val = a.partition("=")
        prev = args[i - 1] if i else ""
        if "$" in a:
            out.append(
                f"{where}: argument {n} contains $ (a client would expand it from its "
                "environment): use a secret: reference or a parameter"
            )
        elif "secret:" in a and not ref:
            out.append(
                f"{where}: argument {n} carries secret: inside a value; write secret:<name>, "
                "--flag=secret:<name> or Header: [Scheme ]secret:<name>"
            )
        elif not ref and a.startswith("-") and eq and _credential_flag(flag):
            out.append(f"{where}: argument {n}: {flag} takes a credential; give it secret:<name>")
        elif not ref and prev.startswith("-") and "=" not in prev and _credential_flag(prev):
            out.append(f"{where}: argument {n} follows {prev}; give it secret:<name>")
        elif not ref and prev in ("--header", "-H"):
            out.append(
                f"{where}: argument {n} is a header after {prev}; its value is secret:<name>"
            )
        elif not ref and (looks_secret(val if eq else a) or re.search(r"(?i)authorization:", a)):
            out.append(f"{where}: argument {n} looks like a literal credential")
    for k, v in (rec.get("settings") or {}).items():
        v = str(v)
        if "$" in v or "secret:" in v:
            out.append(
                f"{where}: setting {k} holds $ or secret: (a setting is a literal; a credential "
                "goes in env as a secret reference)"
            )
        elif looks_secret(v):
            out.append(f"{where}: setting {k} looks like a literal credential")
    return out


def _template_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    """Parameters and templates: every template names a builtin or a parameter, a parameter's
    env key is not hard-denied and collides with nothing, a default fits its own type, and no
    setting carries a credential."""
    params = rec.get("parameters") or {}
    names = set(BUILTINS) | set(params)
    out: list[str] = []

    def refs(text: str, what: str, extra: Iterable[str] = ()) -> None:
        for name in TEMPLATE.findall(text):
            if name not in names and name not in extra:
                out.append(f"{where}: {what} uses {{{name}}}, which is not a parameter or builtin")

    refs(str(rec.get("instance", "")), "instance")
    for a in (rec.get("transport") or {}).get("args") or ():
        refs(str(a), "an argument", (PROFILE_FILE,))
    settings = rec.get("settings") or {}
    for k, v in settings.items():
        refs(str(v), f"setting {k}")
        if SECRET_KEY.search(k) or CREDENTIAL_FLAG.match("--" + k.lower()):
            out.append(
                f"{where}: setting {k} names a credential; put it in env as a secret reference"
            )
    fixed = set(settings) | set(rec.get("env") or {})
    seen: dict[str, str] = {}
    for name, p in params.items():
        key = p.get("env")
        if p.get("enum") is None and p.get("pattern") is None:
            out.append(
                f"{where}: parameter {name} has no enum or pattern (every value a grant can give "
                "is typed)"
            )
        if key:
            if DENIED_ENV.match(key):
                out.append(f"{where}: parameter {name}: env {key} may never be set by a grant")
            if SECRET_KEY.search(key):
                out.append(
                    f"{where}: parameter {name}: env {key} names a credential (a grant never "
                    "sets one; put it in env as a secret reference)"
                )
            if key in fixed:
                out.append(
                    f"{where}: parameter {name}: env {key} is also a fixed setting or secret"
                )
            if key in seen:
                out.append(f"{where}: parameters {seen[key]} and {name} both set env {key}")
            seen[key] = name
        default = p.get("default")
        if p.get("required") and default is not None:
            out.append(f"{where}: parameter {name} is required and has a default")
        if default is not None and ("$" in default or "secret:" in default):
            out.append(f"{where}: parameter {name}: default holds $ or secret:")
        if default is not None:
            for ref in TEMPLATE.findall(default):
                if ref not in BUILTINS:
                    out.append(f"{where}: parameter {name}: default may use only {list(BUILTINS)}")
        pat = p.get("pattern")
        if pat is not None:
            try:
                re.compile(pat)
            except re.error as exc:
                out.append(f"{where}: parameter {name}: pattern does not compile ({exc})")
                continue
        if default is not None and not TEMPLATE.search(default):
            bad = value_problem(p, default)
            if bad:
                out.append(f"{where}: parameter {name}: default {bad}")
    return out


def value_problem(param: Mapping[str, Any], value: str) -> str | None:
    """Why ``value`` does not fit a parameter's type (enum, pattern), or None."""
    if param.get("enum") is not None and value not in param["enum"]:
        return f"{value!r} is not one of {param['enum']}"
    pat = param.get("pattern")
    if pat is not None and not re.fullmatch(pat, value):
        return f"{value!r} does not match {pat}"
    return None


def _implements_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    from homelabnext.conform.registry import CAPABILITIES, EXTENDED

    known = set(CAPABILITIES) | set(EXTENDED)
    return [
        f"{where}: implements {cap}, which is not a homelab-next capability contract"
        for cap in rec.get("implements") or ()
        if cap.removeprefix("cap:") not in known
    ]


def known_capabilities(registry: Any = None) -> set[str]:
    """``cap:`` ids a record may front: the class table's capabilities, the conformance
    capabilities and (with a registry) every registry service's capability."""
    from homelabnext.agent.readers import table_capabilities
    from homelabnext.conform.registry import CAPABILITIES, EXTENDED

    known = set(table_capabilities()) | {f"cap:{c}" for c in (*CAPABILITIES, *EXTENDED)}
    if registry is not None:
        known |= {f"cap:{s.capability}" for s in registry.services.values() if s.capability}
    return known


def _lifecycle_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    if rec.get("status") in ("deprecated", "retired"):
        return []
    return [
        f"{where}: {k} on a record whose status is {rec.get('status')} (only a deprecated or "
        "retired one says why and what replaces it)"
        for k in ("reason", "replaced_by")
        if rec.get(k) is not None
    ]


def _registry_problems(cat: Catalog, registry: Any, skip: Iterable[str] = ()) -> list[str]:
    """Registry cross-references; ``skip``: records that failed the schema (no follow-on noise)."""
    out: list[str] = []
    skip = set(skip)
    endpoints: dict[str, list[str]] = {}
    known = known_capabilities(registry)
    for sid, rec in cat:
        if sid in skip:
            continue
        where = cat.rel(sid)
        for c in rec.get("capabilities") or ():
            if c not in known:
                out.append(f"{where}: capabilities names {c}, which no registry service, class "
                           "table entry or conformance contract defines")  # fmt: skip
        t = rec.get("transport") or {}
        if t.get("type") in HTTP_TRANSPORTS:
            svc_name = str(t.get("endpoint", "")).removeprefix("svc:")
            svc = registry.services.get(svc_name)
            endpoints.setdefault(svc_name, []).append(sid)
            if svc is None:
                out.append(f"{where}: endpoint svc:{svc_name} is not a registry service")
            elif svc.protocol not in ("http", "https"):
                out.append(f"{where}: endpoint svc:{svc_name} speaks {svc.protocol}, not http(s)")
            elif svc.mcp:
                want = REGISTRY_TRANSPORT.get(svc.mcp.get("transport", "http"))
                if svc.mcp.get("name") != sid:
                    out.append(
                        f"{where}: svc:{svc_name} names its MCP endpoint "
                        f"{svc.mcp.get('name')!r} in the registry, not {sid!r}"
                    )
                if want != t.get("type"):
                    out.append(
                        f"{where}: transport {t.get('type')} but the registry says "
                        f"{svc.mcp.get('transport')} for svc:{svc_name}"
                    )
                if svc.mcp.get("path", "/mcp") != t.get("path", "/mcp"):
                    out.append(
                        f"{where}: path {t.get('path', '/mcp')} but the registry says "
                        f"{svc.mcp.get('path')} for svc:{svc_name}"
                    )
        rt = rec.get("runtime")
        if isinstance(rt, Mapping) and rt.get("host") not in registry.hosts:
            out.append(f"{where}: runtime host {rt.get('host')} is not a registry host")
        egress = rec.get("egress")
        for e in egress if isinstance(egress, list) else ():
            if e.startswith("svc:") and e[4:] not in registry.services:
                out.append(f"{where}: egress {e} is not a registry service")
            if e.startswith("host:") and e[5:] not in registry.hosts:
                out.append(f"{where}: egress {e} is not a registry host")
    for svc in registry.sorted_services():
        if not svc.mcp:
            continue
        name = svc.mcp.get("name")
        if name in skip:
            continue
        if name not in cat.servers:
            out.append(
                f"registry svc:{svc.name}: MCP server {name!r} is not in the MCP catalog "
                f"({cat.root.name}/)"
            )
        elif svc.name not in endpoints:
            out.append(
                f"registry svc:{svc.name}: exposes MCP server {name!r}, whose catalog record "
                "does not name it as its endpoint"
            )
    return out


def _review_problems(cat: Catalog, policy: Any) -> list[str]:
    from homelabnext.reviews import evaluate, missing_message

    out: list[str] = []
    for sid, rec in cat:
        where = cat.rel(sid)
        digest = record_digest(rec)
        ev = evaluate(
            rec.get("reviews"),
            author=rec.get("author"),
            digest=digest,
            artefact=ARTEFACT,
            state=str(rec.get("status")),
            policy=policy,
            who=where,
        )
        out += ev.problems
        if ev.missing:
            out.append(missing_message(where, str(rec.get("status")), ev, digest))
    return out


def integrity_problems(cat: Catalog) -> list[str]:
    """What makes a catalog unfit to judge a grant against: a load problem (two records with one
    id, a record that is not a mapping), an id that is not its file name, a record that fails the
    schema (an unknown status or data tier).  A subset of :func:`check`, computed once per load."""
    if cat._integrity is None:
        out = list(cat.problems)
        for sid, rec in cat:
            where = cat.rel(sid)
            if cat.files[sid].stem != sid:
                out.append(f"{where}: id {sid!r} is not the file name ({cat.files[sid].stem}.yml)")
            out += _schema_problems(rec, where)
        cat._integrity = out
    return list(cat._integrity)


def check(
    cat: Catalog,
    *,
    registry: Any = None,
    vocabulary: Iterable[str] | None = None,
    policy: Any = None,
    source_root: Path | None = None,
) -> list[str]:
    """Every problem with the catalog (empty = valid).  ``registry``: cross-check endpoints,
    hosts, egress and the registry's ``mcp`` entries; ``vocabulary``: the capability classes
    (default: ``tool_classes.yml``'s); ``policy``: the review policy; ``source_root``: the
    checkout first-party paths are relative to."""
    if vocabulary is None:
        from homelabnext.agent.readers import table_vocabulary

        vocabulary = table_vocabulary()
    vocabulary = list(vocabulary)
    out = list(cat.problems)
    invalid: set[str] = set()
    for sid, rec in cat:
        f = cat.files[sid]
        where = cat.rel(sid)
        schema = _schema_problems(rec, where)
        out += schema
        if f.stem != sid:
            out.append(f"{where}: id {sid!r} is not the file name ({f.stem}.yml)")
        if schema:
            invalid.add(sid)
            continue  # the semantic rules assume the shape
        out += origin_problems(rec.get("origin"), where, source_root, cat.root)
        out += launch_problems(rec, where)
        out += _tool_problems(rec, where, vocabulary)
        out += _egress_problems(rec, where)
        out += _secret_problems(rec, where)
        out += _literal_problems(rec, where)
        out += _template_problems(rec, where)
        out += _implements_problems(rec, where)
        out += _lifecycle_problems(rec, where)
        repl = rec.get("replaced_by")
        if repl is not None:
            if repl == sid:
                out.append(f"{where}: replaced_by names itself")
            elif cat.status(repl) != "active":
                out.append(f"{where}: replaced_by {repl!r} is not an active catalog server")
    if registry is not None:
        out += _registry_problems(cat, registry, invalid)
    if policy is not None:
        out += _review_problems(cat, policy)
    return out
