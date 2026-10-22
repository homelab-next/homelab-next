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
40-hex commit) and a stdio record's launch can be generated from it (:func:`launch`: a record
names its origin, ``bin`` and the server's own arguments, never a launcher), every tool is classed with the table's vocabulary, egress agrees with the tools'
classes, credentials are secret names that stay distinct and no setting names one, parameters are
typed, no setting, secret or parameter env key configures the process or its launcher
(:data:`DENIED_ENV`) and no parameter env key is shared, templates name only
builtins and parameters, endpoints and hosts resolve in the registry and every registry ``mcp``
entry resolves to a catalog server, a retired or deprecated server says why, ``replaced_by`` names
an active server, ``implements`` names a capability contract, and an active server carries the
reviews the review policy asks of ``mcp-server.active``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from homelabnext.registry.model import secret_env_name

from . import credentials

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
#: llm-orchestrator's own hard-denied grant keys (internal/grants/grants.go:71, deniedEnvRe),
#: which :func:`homelabnext.mcp.clients.orch_accepts` mirrors
ORCH_DENIED_ENV = re.compile(
    r"^(LD_.*|DYLD_.*|PATH|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONINSPECT|HOME|SHELL|BASH_ENV"
    r"|ENV|NODE_OPTIONS|HERMES_HOME)$"
)
#: environment keys no setting, env secret or parameter may ever set (any case): they change what
#: code runs or how, not what a server is scoped to.  A record's settings and env become the
#: environment of the launcher too (npx, uvx, docker), so its configuration is here as well: the
#: loader (LD_*, DYLD_*), the search path and home, the interpreters (PYTHON*, NODE_*), the
#: package launchers (NPM_CONFIG_*, UV_*, PIP_*, PIPX_*, BUN_*, COREPACK_*, YARN_*, PNPM_*), git
#: (a git origin is fetched with it), the config directories they read (XDG_*), and the container
#: runner's own configuration: an image record's settings and env reach the ``docker`` CLI's
#: environment too (and the container's, by ``-e NAME``), so the variables the docker CLI reads
#: to pick its daemon, credentials, TLS, context, API, platform, plugins and builder
#: (DOCKER_HOST, DOCKER_CONFIG, DOCKER_CERT_PATH, DOCKER_TLS*, DOCKER_CONTEXT,
#: DOCKER_API_VERSION, DOCKER_DEFAULT_PLATFORM, DOCKER_CONTENT_TRUST*, DOCKER_CLI_*,
#: DOCKER_BUILDKIT, DOCKER_CUSTOM_HEADERS, BUILDKIT*, COMPOSE_*) and podman's through its docker
#: alias (CONTAINER*) are refused, while another DOCKER_ name (DOCKER_CONTAINER, which an image
#: reads inside the container) is the server's own setting.  A superset of :data:`ORCH_DENIED_ENV`.
DENIED_ENV = re.compile(
    r"(?:LD_|DYLD_|PYTHON|NODE_|NPM_CONFIG_|UV_|PIP_|PIPX_|BUN_|COREPACK_|YARN_|PNPM_|GIT_"
    r"|CONTAINER|XDG_|BUILDKIT|COMPOSE_|DOCKER_(?:TLS|CONTENT_TRUST|CLI_)).*"
    r"|DOCKER_(?:HOST|CONFIG|CERT_PATH|CONTEXT|API_VERSION|DEFAULT_PLATFORM|BUILDKIT"
    r"|CUSTOM_HEADERS)|PATH|HOME|SHELL|BASH_ENV|ENV|HERMES_HOME|NODE|NPM_TOKEN",
    re.I,
)


def denied_env(key: str) -> bool:
    """``key`` may never be set by a record or a grant (:data:`DENIED_ENV`, any case)."""
    return bool(DENIED_ENV.fullmatch(str(key).strip()))


#: ``{name}`` in an instance name, an argument, a setting or a parameter default
TEMPLATE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
#: template names every instance has: the record id, the profile's bare name, the lane, the
#: render spec output's ``home`` (empty outside one), and (in arguments only) the rendered
#: profile's file
BUILTINS = ("id", "profile", "lane", "home")
PROFILE_FILE = "profile_file"
#: a setting key that names a credential: its value belongs in the secret store (``env``)
SECRET_KEY = credentials.SECRET_KEY


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
#: the launchers a stdio record's origin generates (:func:`launch`): bare names, resolved on PATH
NPX, UVX, DOCKER, HNX = "npx", "uvx", "docker", "hnx"
#: a server entrypoint (``transport.bin``): a bare command name
BIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
#: a git origin a launcher fetches: https, a host, a path, no userinfo, no query
_GIT_REPO = re.compile(r"(?:git\+)?https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)+")
#: commands a package's ``bin`` (and ``bins``) may never be: each runs whatever its arguments say
#: (a shell, an interpreter, a wrapper, a launcher, a network or file tool), so ``npx
#: --package=PIN -- node -e ...`` would run code no pin controls.  Defense in depth: the control
#: is that the bin is one of the reviewed ``origin.bins``.
NOT_A_BIN = frozenset(
    (
        "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "busybox", "env",
        "sudo", "doas", "su", "nohup", "nice", "ionice", "timeout", "xargs", "exec", "eval",
        "command", "chroot", "setsid", "script", "node", "nodejs", "deno", "bun", "bunx", "npx",
        "npm", "pnpm", "pnpx", "yarn", "corepack", "tsx", "ts-node", "python", "pythonw", "pypy",
        "uv", "uvx", "pip", "pipx", "poetry", "conda", "ruby", "irb", "gem", "perl", "php", "lua",
        "luajit", "tclsh", "wish", "expect", "java", "jshell", "go", "cargo", "rustc", "dotnet",
        "pwsh", "powershell", "cmd", "osascript", "r", "rscript", "julia", "awk", "gawk", "mawk",
        "sed", "find", "vim", "vi", "nvim", "emacs", "make", "gcc", "cc", "docker", "podman",
        "nerdctl", "kubectl", "ssh", "scp", "sftp", "rsync", "curl", "wget", "nc", "ncat",
        "netcat", "socat", "telnet", "git", "tar", "dd", "hnx",
    )
)  # fmt: skip
_NOT_A_BIN = re.compile(r"(?:python|pypy|pip|node|perl|ruby|php|lua|java)[0-9.]*", re.I)


def bin_problem(bin_: str) -> str | None:
    """Why ``bin_`` may not be a command a package (or git repo) declares and runs, or None: a
    bare name (a path runs only for a first-party server), never an interpreter, shell, wrapper
    or launcher (:data:`NOT_A_BIN`)."""
    if not BIN.fullmatch(bin_):
        return f"bin {bin_} is not a bare command name (a path runs only for a first-party server)"
    if bin_.lower() in NOT_A_BIN or _NOT_A_BIN.fullmatch(bin_):
        return (
            f"bin {bin_} is an interpreter, shell, wrapper or launcher, not the package's own "
            "command (it would run whatever its arguments say, not the pinned code)"
        )
    return None


def base_name(origin: Mapping[str, Any]) -> str:
    """The package's base name (``@scope/name`` -> ``name``), or a git repo's last segment."""
    if origin.get("kind") == "git":
        return str(origin.get("repo", "")).rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    return str(origin.get("package", "")).rsplit("/", 1)[-1]


def resolve_bin(origin: Mapping[str, Any], bin_: Any) -> tuple[str | None, str | None]:
    """``(bin, None)``: the command a package or git origin runs, one of its reviewed ``bins``
    (``bin_`` when given, else the single declared bin, else the base name when bins lists it);
    or ``(None, why not)``.  npx and uvx run *any* command on PATH under the bin's name (``npx
    --package=PIN -- id`` runs ``id``), so the only bin a record may name is one the review read
    from the package."""
    bins = [str(b) for b in origin.get("bins") or ()]
    if not bins:
        return None, (
            "names no bins: list the bin names the package declares (package.json bin, the "
            "wheel's console_scripts), as the review read them from the released artifact"
        )
    if bin_ is not None:
        if str(bin_) not in bins:
            return None, (
                f"bin {bin_} is not one of the package's reviewed bins {bins} (npx and uvx run "
                "any command on PATH under that name)"
            )
        return str(bin_), None
    if len(bins) == 1:
        return bins[0], None
    if base_name(origin) in bins:
        return base_name(origin), None
    return None, f"declares several bins {bins}: name the one it runs (transport.bin)"


#: the first-party ``hnx`` subcommands that serve MCP on stdio (``transport.entry`` names one),
#: each with the only flags its arguments may hold, every one once and with a value.  Every other
#: hnx subcommand can run code or write files a record must not reach (``invariants run
#: --plugins-dir``, ``--notify-cmd``, ``broker run``, ``workflows run``, ``conform run``,
#: ``--out``), so ``bin: hnx`` with free arguments is refused.  A test holds each entry to its
#: real parser.
HNX_ENTRIES: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {
    # hnx mcp serve: the read-only catalog server (homelabnext/mcp/cli.py)
    "mcp-serve": (("mcp", "serve"), frozenset({"--root", "--registry", "--scope-from-profile"})),
    # hnx broker mcp: the broker's agent-facing tools (homelabnext/broker/cli.py)
    "broker-mcp": (("broker", "mcp"), frozenset({"--socket"})),
}


def hnx_args_problems(entry: Any, args: Iterable[Any]) -> list[str]:
    """Why ``hnx <entry> <args>`` is not an MCP server's launch: an entry outside
    :data:`HNX_ENTRIES`, or an argument that is not one of its flags (``--flag VALUE`` or
    ``--flag=VALUE``, each flag once, the value never another flag)."""
    if entry not in HNX_ENTRIES:
        return [
            f"a first-party hnx server names its entry, one of {sorted(HNX_ENTRIES)} (the hnx "
            "subcommands that serve MCP on stdio)"
        ]
    allowed = HNX_ENTRIES[entry][1]
    out: list[str] = []
    seen: set[str] = set()
    items = [str(a) for a in args]
    i = 0
    while i < len(items):
        flag, eq, value = items[i].partition("=")
        if flag not in allowed:
            out.append(
                f"hnx entry {entry}: argument {i + 1} is not one of its flags {sorted(allowed)}"
            )
            break
        if not eq:
            if i + 1 >= len(items) or items[i + 1].startswith("-"):
                out.append(f"hnx entry {entry}: {flag} has no value")
                break
            value, i = items[i + 1], i + 1
        if not value:
            out.append(f"hnx entry {entry}: {flag} has no value")
        if flag in seen:
            out.append(f"hnx entry {entry}: {flag} is given twice")
        seen.add(flag)
        i += 1
    return out


def _bins_problems(origin: Mapping[str, Any], bin_: Any, where: str) -> list[str]:
    """The reviewed ``bins`` (each a bare name, never an interpreter or shell) and the bin the
    launch runs (:func:`resolve_bin`)."""
    out = [f"{where}: {why}" for b in origin.get("bins") or () if (why := bin_problem(str(b)))]
    if bin_ is not None and (why := bin_problem(str(bin_))):
        out.append(f"{where}: {why}")
    _, why = resolve_bin(origin, bin_)
    if why:
        out.append(f"{where}: {why}")
    return out


def launch_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    """A stdio record has a launch :func:`launch` can generate from its origin: an npm or pypi
    package (an exact npm ``x.y.z``, a valid package name), a git repo with its ecosystem (an
    https URL without credentials, and a bin), an image (no bin: it runs its own entrypoint), or a
    first-party server (``hnx``, or a path under ``origin.path``).  A package's bin is one of the
    reviewed ``origin.bins`` (:func:`resolve_bin`), never an interpreter or shell
    (:func:`bin_problem`).  A record writes no launcher and no launcher flag, so a
    ``--python`` path, an index, ``--with``, ``--privileged`` or another entrypoint cannot be
    expressed.  (The sha256 itself is declarative: no launcher verifies it.)"""
    origin, t = rec.get("origin") or {}, rec.get("transport") or {}
    if t.get("type") != "stdio" or not isinstance(origin, Mapping):
        return []
    kind = origin.get("kind")
    bin_ = t.get("bin")
    out: list[str] = []
    if t.get("entry") is not None and not (kind == "first-party" and bin_ == HNX):
        out.append(f"{where}: entry is for a first-party hnx server (bin: hnx)")
    if kind == "package":
        eco, pkg, ver = origin.get("ecosystem"), str(origin.get("package")), origin.get("version")
        if eco not in ("npm", "pypi"):
            return [
                f"{where}: no generated launch runs a pinned {eco} package (the pin would not "
                "control what runs): run it from an image pinned by digest"
            ]
        if eco == "npm" and ver and not _NPM_EXACT.fullmatch(str(ver)):
            out.append(f"{where}: npm version {ver} is not a full x.y.z (npm reads it as a range)")
        if not (_NPM_NAME if eco == "npm" else _PYPI_NAME).fullmatch(pkg):
            out.append(f"{where}: {pkg} is not an {eco} package name")
        if origin.get("extras") and eco != "pypi":
            out.append(f"{where}: extras are a pypi package's; npm has none")
        out += _bins_problems(origin, bin_, where)
    elif kind == "git":
        repo = str(origin.get("repo"))
        if origin.get("ecosystem") not in ("npm", "pypi"):
            out.append(
                f"{where}: a git origin started on stdio names its ecosystem (npm: npx, pypi: "
                "uvx), which says how it is installed"
            )
        if not _GIT_REPO.fullmatch(repo):
            out.append(f"{where}: git repo {repo} is not an https URL without credentials")
        if origin.get("subdirectory") and origin.get("ecosystem") != "pypi":
            out.append(
                f"{where}: a git subdirectory is installed only by uvx (pypi); npm installs no "
                "subdirectory of a git repo"
            )
        out += _bins_problems(origin, bin_, where)
    elif kind == "image":
        if bin_ is not None:
            out.append(
                f"{where}: an image runs its own reviewed entrypoint; bin is for a package or a "
                "first-party server (the image's arguments go in args)"
            )
    elif kind == "first-party":
        path = str(origin.get("path", "")).rstrip("/")
        if bin_ is None:
            out.append(f"{where}: a first-party server names its bin: hnx, or a path under {path}")
        elif bin_ == HNX:
            out += [f"{where}: {p}" for p in hnx_args_problems(t.get("entry"), t.get("args") or ())]
        elif bin_ != HNX and not (bin_ == path or str(bin_).startswith(path + "/")):
            out.append(
                f"{where}: first-party bin {bin_} is neither hnx nor a path under origin.path "
                f"({path}/): a first-party server runs this checkout's code"
            )
    return out


@dataclass(frozen=True)
class LaunchContext:
    """Where a generated launch is anchored on the host the client runs on (the render spec's
    ``npm_prefix`` and ``checkout_root``, or ``--npm-prefix``/``--checkout-root``): absolute
    paths, never the client's working directory."""

    #: an empty directory npx is started with (``--prefix``): its project config and
    #: ``node_modules`` are read from there, never from the client's working directory
    npm_prefix: str | None = None
    #: the checkout a first-party path bin is resolved under
    checkout_root: str | None = None


#: what an anchor path may not hold: a client would expand ``$``, and a control character splits
#: an argument
_UNSAFE_PATH = re.compile(r"[$\x00-\x1f\x7f]|secret:")


def anchor_problem(value: Any, what: str) -> str | None:
    """Why ``value`` cannot anchor a launch (``npm_prefix``, ``checkout_root``), or None: it is
    an absolute path with no ``..``, ``$``, ``secret:`` or control character."""
    if value is None or value == "":
        return f"{what} is not given (an absolute directory on the client's host)"
    if not isinstance(value, str) or not value.startswith("/"):
        return f"{what} is not an absolute path (a relative one resolves in the client's cwd)"
    if ".." in PurePosixPath(value).parts or _UNSAFE_PATH.search(value):
        return f"{what} holds .., $, secret: or a control character"
    return None


def launch(rec: Mapping[str, Any], ctx: LaunchContext | None = None) -> tuple[str, list[str]]:
    """The launch a stdio record's origin generates: ``(command, launcher arguments)``; the
    server's own ``args`` follow.  Fixed flags only, never one from the record:

    * npm: ``npx -y --prefix=<npm_prefix> --package=<package>@<version> -- <bin>`` (``--``
      ends npx's options; the bin is one of the reviewed ``bins``, :func:`resolve_bin`;
      ``--prefix`` makes npx read its project config and ``node_modules`` from that
      empty directory, so neither a ``node_modules/<package>`` nor an ``.npmrc`` in the client's
      working directory replaces the pinned package);
    * pypi: ``uvx --no-config --from <package>[<extras>]==<version> <bin>`` (``--no-config`` reads no ``uv.toml`` or ``[tool.uv]``, so none can redirect the index);
    * git: the same with ``git+<repo>#<commit>`` (npm) or
      ``git+<repo>@<commit>[#subdirectory=<dir>]`` (pypi);
    * image: ``docker run -i --rm [-e NAME ...] <repository>@<digest>``, one ``-e`` per
      ``env``, ``settings`` and parameter ``env`` key, so the container gets exactly those;
    * first-party: ``hnx <entry's subcommand>`` (:data:`HNX_ENTRIES`), or a path under
      ``origin.path``, written absolute under ``ctx.checkout_root`` (a relative command would be
      resolved in the client's working directory).

    ``ctx`` anchors the launch (:class:`LaunchContext`); an npm launch needs its ``npm_prefix``.
    Raises ValueError for a record :func:`launch_problems` (or the origin rules) refuse, or a
    launch ``ctx`` cannot anchor."""
    ctx = ctx or LaunchContext()
    origin, t = rec.get("origin") or {}, rec.get("transport") or {}
    kind, bin_ = origin.get("kind"), t.get("bin")
    if kind in ("package", "git") and origin.get("ecosystem") in ("npm", "pypi"):
        eco = origin["ecosystem"]
        if kind == "package":
            ver = str(origin.get("version") or "").removeprefix("v")
            extras = f"[{','.join(origin['extras'])}]" if origin.get("extras") else ""
            spec = (
                f"{origin['package']}@{ver}" if eco == "npm"
                else f"{origin['package']}{extras}=={ver}"
            )  # fmt: skip
        else:
            repo = "git+" + str(origin["repo"]).removeprefix("git+")
            spec = f"{repo}{'#' if eco == 'npm' else '@'}{origin.get('commit')}"
            if origin.get("subdirectory"):
                spec += f"#subdirectory={origin['subdirectory']}"
        run, why = resolve_bin(origin, bin_)
        if run is None:
            raise ValueError(f"{why}")
        if eco == "npm":
            bad = anchor_problem(ctx.npm_prefix, "npm_prefix")
            if bad:
                raise ValueError(f"an npm launch needs npm_prefix: {bad}")
            return NPX, ["-y", f"--prefix={ctx.npm_prefix}", f"--package={spec}", "--", run]
        return UVX, ["--no-config", "--from", spec, run]
    if kind == "image" and origin.get("digest"):
        image = str(origin["image"])
        repo = image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
        params = rec.get("parameters") or {}
        names = sorted(
            {*(rec.get("env") or {}), *(rec.get("settings") or {}),
             *(p["env"] for p in params.values() if p.get("env"))}
        )  # fmt: skip
        return DOCKER, ["run", "-i", "--rm", *(x for n in names for x in ("-e", n)),
                        f"{repo}@{origin['digest']}"]  # fmt: skip
    if kind == "first-party" and bin_ == HNX:
        if hnx_args_problems(t.get("entry"), t.get("args") or ()):
            raise ValueError("an hnx launch names an MCP-serving entry and only its flags")
        return HNX, list(HNX_ENTRIES[t["entry"]][0])
    if kind == "first-party" and bin_:
        bad = anchor_problem(ctx.checkout_root, "checkout_root")
        if bad:
            raise ValueError(f"a first-party path bin needs checkout_root: {bad}")
        return f"{str(ctx.checkout_root).rstrip('/')}/{bin_}", []
    raise ValueError(f"{rec.get('id')}: a {kind} origin has no generated launch")


#: a context any launch accepts, for naming the command alone (:func:`launch_command`)
_ANY = LaunchContext(npm_prefix="/", checkout_root="/")


def path_bin(rec: Mapping[str, Any]) -> str | None:
    """A first-party record's path bin (relative to the checkout), or None (hnx, or not one)."""
    origin, t = rec.get("origin") or {}, rec.get("transport") or {}
    if origin.get("kind") == "first-party" and t.get("bin") not in (None, HNX):
        return str(t["bin"])
    return None


def path_bin_problems(rec: Mapping[str, Any], where: str, root: Path | None) -> list[str]:
    """A first-party path bin is a file in the checkout ``root`` (when there is one), not a
    symlink and not outside it once resolved."""
    rel = path_bin(rec)
    if rel is None or root is None:
        return []
    f = Path(root) / rel
    if f.is_symlink():
        return [f"{where}: first-party bin {rel} is a symlink (it runs what the link names)"]
    if not f.is_file() or not f.resolve().is_relative_to(Path(root).resolve()):
        return [f"{where}: first-party bin {rel} is not a file in the checkout"]
    return []


def program(rec: Mapping[str, Any]) -> str:
    """What a stdio record runs, for display (pages, ``list``): the package's bin, the image,
    ``hnx <subcommand>`` or the first-party path; never None (a record with no generated launch
    says so)."""
    origin, t = rec.get("origin") or {}, rec.get("transport") or {}
    kind = origin.get("kind")
    if kind in ("package", "git") and origin.get("ecosystem") in ("npm", "pypi"):
        return resolve_bin(origin, t.get("bin"))[0] or base_name(origin)
    if kind == "image":
        image = str(origin.get("image", ""))
        return image.rsplit(":", 1)[0] if ":" in image.rsplit("/", 1)[-1] else image
    if kind == "first-party" and t.get("bin") == HNX and t.get("entry") in HNX_ENTRIES:
        return " ".join((HNX, *HNX_ENTRIES[t["entry"]][0]))
    if kind == "first-party" and t.get("bin"):
        return str(t["bin"])
    return f"no generated launch: {kind or 'no'} origin"


def launch_command(rec: Mapping[str, Any]) -> str | None:
    """The command a stdio record is started with (``npx``, ``uvx``, ``docker``, ``hnx`` ...), or
    None when it has none (a remote server, an origin with no generated launch)."""
    try:
        return launch(rec, _ANY)[0] if (rec.get("transport") or {}).get("type") == "stdio" else None
    except (ValueError, KeyError, TypeError):
        return None


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


#: the shared credential rules (:mod:`.credentials`), named here for the importer and the tests
PACKAGE_SPEC = credentials.PACKAGE_SPEC
looks_secret = credentials.looks_secret
arg_secret = credentials.arg_secret

_FINDING = {
    "dollar": "contains $ (a client would expand it from its environment): use a secret: "
    "reference or a parameter",
    "inline": "carries secret: inside a value; write secret:<name>, --flag=secret:<name> or "
    "Header: [Scheme ]secret:<name>",
    "flag-value": "{flag} takes a credential; give it secret:<name>",
    "after-flag": "follows {flag}; give it secret:<name>",
    "header": "is a header after {flag}; its value is secret:<name>",
    "env": "{flag} sets a credential (or a value that looks like one): put it in env as a "
    "secret reference",
    "shell": "is a shell line that carries a credential",
    "value": "looks like a literal credential",
}


def _literal_problems(rec: Mapping[str, Any], where: str) -> list[str]:
    """No literal credential and nothing a client would expand (:mod:`.credentials`, the rules
    the importer strips by): an argument or a setting never holds ``$`` (``${VAR}``,
    ``$(cmd)``), a ``secret:`` reference only as a whole argument, a ``--flag=`` value or a header
    value, a credential flag's value is a ``secret:`` reference, and nothing looks like a token or
    carries one (a URL, JSON, a shell line, a container's ``-e``)."""
    t = rec.get("transport") or {}
    out = [
        f"{where}: argument {f.index + 1} " + _FINDING[f.kind].format(flag=f.flag)
        for f in credentials.scan_args(t.get("args") or ())
    ]
    for k, v in (rec.get("settings") or {}).items():
        why = credentials.setting_problem(str(k), str(v))
        if why == "holds $ or secret:":
            out.append(
                f"{where}: setting {k} holds $ or secret: (a setting is a literal; a credential "
                "goes in env as a secret reference)"
            )
        elif why and why != "names a credential":  # that one: _template_problems
            out.append(f"{where}: setting {k} {why}")
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
        if credentials.setting_problem(str(k), str(v)) == "names a credential":
            out.append(
                f"{where}: setting {k} names a credential; put it in env as a secret reference"
            )
    for what, keys in (("setting", settings), ("env", rec.get("env") or {})):
        for key in keys:
            if denied_env(key):
                out.append(
                    f"{where}: {what} {key} configures the process or its launcher (PATH, LD_*, "
                    "NODE_*, NPM_CONFIG_*, UV_*, PIP_*, DOCKER_HOST ...), which no record sets"
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
            if denied_env(key):
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
    for sid, rec in cat:
        if sid in skip:
            continue
        where = cat.rel(sid)
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


def _review_problems(cat: Catalog, policy: Any, only: Iterable[str] | None = None) -> list[str]:
    from homelabnext.reviews import evaluate, missing_message

    out: list[str] = []
    keep = None if only is None else set(only)
    for sid, rec in cat:
        if keep is not None and sid not in keep:
            continue
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


def default_policy(cat: Catalog) -> Any:
    """The review policy ``check`` uses by default: ``review-policy.yml`` beside the catalog
    directory, or None."""
    from homelabnext.reviews import load_policy

    f = cat.root.resolve().parent / "review-policy.yml"
    return load_policy(f) if f.is_file() else None


def record_problems(
    cat: Catalog, sids: Iterable[str], policy: Any = None, source_root: Path | None = None
) -> list[str]:
    """The per-record rules of :func:`check` for the records ``sids`` (what a render is about to
    write into a client file): pinned and launched as pinned, credentials only as secret names
    and no literal one, typed parameters and known templates, and with ``policy`` the reviews
    the record's status needs.  (The schema and id rules: :func:`integrity_problems`.)"""
    out: list[str] = []
    sids = sorted(set(sids))
    for sid in sids:
        rec = cat.get(sid)
        if rec is None:
            continue
        where = cat.rel(sid)
        out += origin_problems(rec.get("origin"), where, source_root, cat.root)
        out += launch_problems(rec, where)
        out += _secret_problems(rec, where)
        out += _literal_problems(rec, where)
        out += _template_problems(rec, where)
    if policy is not None:
        out += _review_problems(cat, policy, sids)
    return out


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
    known = known_capabilities(registry)
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
        out += path_bin_problems(rec, where, source_root)
        out += _tool_problems(rec, where, vocabulary)
        out += _egress_problems(rec, where)
        out += _secret_problems(rec, where)
        out += _literal_problems(rec, where)
        out += _template_problems(rec, where)
        out += _implements_problems(rec, where)
        out += [
            f"{where}: capabilities names {c}, which no registry service, class table entry or "
            "conformance contract defines"
            + ("" if registry is not None else " (no registry given: --registry resolves a "
               "service's capability)")
            for c in rec.get("capabilities") or ()
            if c not in known
        ]  # fmt: skip
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
