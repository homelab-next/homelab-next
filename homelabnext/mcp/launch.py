# SPDX-License-Identifier: Apache-2.0
"""Reading a foreign client config's command line, for ``hnx mcp catalog import`` (ADR-0024).

A catalog record never writes a launcher command line: it names its origin, the server's
entrypoint (``transport.bin``) and the server's own arguments, and the renderer generates the
launch (:func:`homelabnext.mcp.servers.launch`).  So this module is only the importer's: it reads
``command args`` from an existing ``.mcp.json`` (or Hermes, Claude Desktop ...) the way each
launcher reads its argv, and maps it to ``(origin, bin, args)`` (:func:`map_launch`), or says why
it cannot.

* ``npx``/``bunx`` (npm): ``--package``/``-p`` names the package (once) and the next positional is
  the bin, else the first positional is the package;
* ``uvx``, ``uv tool run`` (pypi): ``--from`` names the package and the next positional is the
  bin, else the first positional is the package (and the bin);
* ``pipx run`` (pypi): ``--spec`` names the package, as ``--from``;
* ``docker run``/``podman run`` (image): the first positional after the run flags is the image;
  its ``-e KEY[=VALUE]`` become the record's environment;
* ``hnx``: a first-party server.

Every other launcher flag (``--python``, ``--with``, an index, ``--registry``, ``-v``,
``--privileged`` ...) is dropped and named in the report: a record cannot carry one, so the
rendered launch never has it.  A command line this module cannot read (an unknown flag before the
launch position, a refused one that changes what runs, a shell, ``env``, an interpreter, a path)
is not mapped: the draft keeps no command and none of its arguments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

#: launcher -> what it runs (the origin kinds it can launch)
NPM = ("npx", "bunx")
PYPI = ("uvx", "uv", "pipx")
IMAGE = ("docker", "podman")
FIRST_PARTY = ("hnx",)


@dataclass(frozen=True)
class Flags:
    """One launcher's flags before its launch position."""

    #: flags that take a value (``--flag VALUE`` or ``--flag=VALUE``)
    value: frozenset[str]
    #: switches (no value)
    switch: frozenset[str]
    #: flags whose value is the launched spec
    spec: frozenset[str] = frozenset()
    #: flags refused outright, with why
    refused: dict[str, str] = field(default_factory=dict)
    #: short switches that may be clustered (``-it``)
    cluster: str = ""


def _f(*names: str) -> frozenset[str]:
    return frozenset(names)


_NPM = Flags(
    value=_f("--cache", "--loglevel", "-w", "--workspace", "--prefix"),
    switch=_f("-y", "--yes", "--no", "-q", "--quiet", "-s", "--silent", "--prefer-offline",
              "--prefer-online", "--offline", "--ignore-existing", "--no-install",
              "--legacy-peer-deps", "--bun", "--verbose"),
    spec=_f("-p", "--package"),
    refused={
        "-c": "runs a shell line, not the package", "--call": "runs a shell line, not the package",
        "--registry": "fetches from another registry", "--userconfig": "reads another npm config",
        "--node-options": "changes how node runs the package",
    },
)  # fmt: skip
_UV = Flags(
    value=_f("--python", "-p", "--cache-dir", "--python-preference", "--color", "--directory",
             "--project", "--refresh-package", "--reinstall-package", "--upgrade-package",
             "--resolution", "--prerelease", "--exclude-newer", "--link-mode"),
    switch=_f("-q", "--quiet", "-v", "--verbose", "--offline", "--no-cache", "-n", "--isolated",
              "--refresh", "--native-tls", "--no-progress", "--no-config", "-U", "--upgrade",
              "--reinstall", "--no-python-downloads", "--managed-python", "--no-managed-python"),
    spec=_f("--from"),
    refused={
        **dict.fromkeys(("--with", "--with-editable", "--with-requirements"),
                        "adds packages beside the pinned one"),
        **dict.fromkeys(("--index", "--index-url", "-i", "--extra-index-url", "--default-index",
                         "--find-links", "-f"), "installs from another index"),
        "--config-file": "reads another uv config",
        "--env-file": "loads another environment",
    },
)  # fmt: skip
_PIPX = Flags(
    value=_f("--python"),
    switch=_f("-q", "--quiet", "-v", "--verbose", "--no-cache", "--system-site-packages",
              "--path"),
    spec=_f("--spec"),
    refused={"--pip-args": "passes pip another index or package", "--index-url": "installs from "
             "another index", "-i": "installs from another index", "--editable": "runs a local "
             "checkout", "-e": "runs a local checkout"},
)  # fmt: skip
_RUN = Flags(
    value=_f("--add-host", "--annotation", "-a", "--attach", "--blkio-weight",
             "--blkio-weight-device", "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns",
             "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime",
             "-c", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--device",
             "--device-cgroup-rule", "--device-read-bps", "--device-read-iops",
             "--device-write-bps", "--device-write-iops", "--dns", "--dns-option", "--dns-search",
             "--domainname", "-e", "--env", "--env-file", "--expose", "--gpus", "--group-add",
             "--health-cmd", "--health-interval", "--health-retries", "--health-start-period",
             "--health-timeout", "-h", "--hostname", "--ip", "--ip6", "--ipc", "--isolation",
             "--kernel-memory", "-l", "--label", "--label-file", "--link", "--link-local-ip",
             "--log-driver", "--log-opt", "--mac-address", "-m", "--memory",
             "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name",
             "--network", "--net", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit",
             "--platform", "-p", "--publish", "--pull", "--restart", "--runtime", "--security-opt",
             "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl",
             "--tmpfs", "--ulimit", "-u", "--user", "--userns", "--uts", "-v", "--volume",
             "--volume-driver", "--volumes-from", "-w", "--workdir"),
    switch=_f("-d", "--detach", "--disable-content-trust", "--init", "-i", "--interactive",
              "--no-healthcheck", "--oom-kill-disable", "-P", "--publish-all", "--privileged",
              "-q", "--quiet", "--read-only", "--rm", "-t", "--tty", "--sig-proxy"),
    refused={"--entrypoint": "replaces the image's reviewed entrypoint"},
    cluster="dDiPqt",
)  # fmt: skip


@dataclass
class Launch:
    """A stdio command line as its launcher reads it."""

    #: the launcher's base name (``npx``, ``uvx``, ``docker`` ...)
    launcher: str
    #: what it launches: ``npm``, ``pypi``, ``image``, ``first-party`` (``hnx``), or None (a
    #: launcher this module does not read: an interpreter, a shell, ``env``, a path ...)
    ecosystem: str | None = None
    #: the launched package or image as written, and its argument index
    spec: str | None = None
    spec_index: int | None = None
    #: the index where the server's own arguments start (after the launch position)
    server_args: int = 0
    #: the index of the command named after ``--from``/``--spec``/``--package`` (the bin)
    bin_index: int | None = None
    #: indexes of the launcher's own flag values (``--from X``, ``-e K=V``, ``--python 3.12``)
    flag_values: dict[int, str] = field(default_factory=dict)
    #: the flag each of those values belongs to (``-e``, ``--env``, ``--from`` ...)
    flag_names: dict[int, str] = field(default_factory=dict)
    #: why the launch position cannot be trusted (a refused or unknown flag, a missing subcommand)
    problems: list[str] = field(default_factory=list)


def flag_name(arg: str) -> str:
    """``--flag`` of ``--flag=value``, ``-e`` of ``-eVALUE``."""
    return arg.split("=", 1)[0] if arg.startswith("--") else arg[:2] if arg.startswith("-") else arg


def _read(launch: Launch, args: list[str], start: int, flags: Flags) -> None:
    """Read the flags from ``start`` to the launch position (fills ``launch``)."""
    i = start
    spec_from_flag: list[tuple[int, str]] = []
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        name = flag_name(a)
        long_eq = a.startswith("--") and "=" in a
        attached = not a.startswith("--") and len(a) > 2
        if name in flags.refused:
            launch.problems.append(f"{launch.launcher} {name}: {flags.refused[name]}")
        if name in flags.value or name in flags.spec or name in flags.refused:
            if long_eq or attached:
                value, at = (a.split("=", 1)[1] if long_eq else a[2:]), i
                i += 1
            elif i + 1 < len(args):
                value, at = args[i + 1], i + 1
                i += 2
            else:
                launch.problems.append(f"{launch.launcher} {name}: no value")
                return
            launch.flag_values[at] = value
            launch.flag_names[at] = name
            if name in flags.spec:
                spec_from_flag.append((at, value))
            continue
        if name in flags.switch and not long_eq and (a == name or not attached):
            i += 1
            continue
        if flags.cluster and not a.startswith("--") and set(a[1:]) <= set(flags.cluster):
            i += 1
            continue
        launch.problems.append(
            f"{launch.launcher} {a.split('=', 1)[0]}: an unknown flag before the launch position "
            "(it may take a value, so what runs cannot be read)"
        )
        # never take the next argument as the launch position: it may be this flag's value
        i += 1 if long_eq or attached else 2
    if len(spec_from_flag) > 1:
        launch.problems.append(f"{launch.launcher}: names its package more than once")
    if spec_from_flag:
        launch.spec_index, launch.spec = spec_from_flag[-1]
        launch.server_args = i + 1 if i < len(args) else i  # the command named after --from
        launch.bin_index = i if i < len(args) else None
    elif i < len(args):
        launch.spec_index, launch.spec = i, args[i]
        launch.server_args = i + 1
    else:
        launch.problems.append(f"{launch.launcher}: names nothing to launch")
        launch.server_args = len(args)


def parse(command: str, args: list[str]) -> Launch:
    """``command args`` as its launcher reads it (see the module docstring)."""
    base = PurePosixPath(command).name
    launch = Launch(base)
    if base in NPM:
        launch.ecosystem = "npm"
        _read(launch, args, 0, _NPM)
    elif base == "uvx":
        launch.ecosystem = "pypi"
        _read(launch, args, 0, _UV)
    elif base == "uv":
        launch.ecosystem = "pypi"
        if args[:2] != ["tool", "run"]:
            launch.problems.append("uv: only `uv tool run` launches a pinned package")
            launch.server_args = len(args)
        else:
            _read(launch, args, 2, _UV)
    elif base == "pipx":
        launch.ecosystem = "pypi"
        if args[:1] != ["run"]:
            launch.problems.append("pipx: only `pipx run` launches a pinned package")
            launch.server_args = len(args)
        else:
            _read(launch, args, 1, _PIPX)
    elif base in IMAGE:
        launch.ecosystem = "image"
        if args[:1] != ["run"]:
            launch.problems.append(f"{base}: only `{base} run` launches a pinned image")
            launch.server_args = len(args)
        else:
            _read(launch, args, 1, _RUN)
    elif base in FIRST_PARTY:
        launch.ecosystem = "first-party"
    return launch


# -------------------------------------------------------------------------------- specs
_NPM_SPEC = re.compile(r"^(?P<name>(?:@[^/@\s]+/)?[^@\s]+)(?:@(?P<ver>[^@\s]+))?$")
_PYPI_SPEC = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._-]*\])?"
    r"(?:(?:==|@)(?P<ver>[^\s=<>!~]+))?$"
)
_IMAGE_SPEC = re.compile(
    r"^(?P<repo>[a-z0-9][a-z0-9._/:-]*?)(?::(?P<tag>[A-Za-z0-9._-]+))?(?:@(?P<digest>sha256:"
    r"[0-9a-f]{64}))?$"
)


def plain_version(ver: str | None) -> str | None:
    """A version without its leading ``v`` (``v1.2.0`` and ``1.2.0`` are one release)."""
    return None if ver is None else str(ver).removeprefix("v")


def pypi_name(name: str) -> str:
    """PEP 503 normalised name (``Example_Notes.MCP`` is ``example-notes-mcp``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def split_spec(ecosystem: str, spec: str) -> tuple[str, str | None] | None:
    """``(name, version)`` of a package spec as a launcher takes it, or None (not one)."""
    m = (_NPM_SPEC if ecosystem == "npm" else _PYPI_SPEC).match(spec)
    if not m or spec.startswith(("git+", "file:", "http:", "https:", "./", "/", "~")):
        return None
    return m.group("name"), m.group("ver")


def split_image(spec: str) -> tuple[str, str | None, str | None] | None:
    """``(repository, tag, digest)`` of an image reference, or None."""
    m = _IMAGE_SPEC.match(spec)
    if not m:
        return None
    return m.group("repo"), m.group("tag"), m.group("digest")


# ---------------------------------------------------------------------------- mapping
#: flags that change what runs, so a command line carrying one is not mapped (dropping the flag
#: would make the draft claim a launch that is not the one the config ran)
_UNMAPPABLE = {"--entrypoint", "-c", "--call"}


@dataclass
class Mapped:
    """A foreign command line as a record's ``(origin, bin, args)`` (:func:`map_launch`)."""

    #: the origin the launch position names (never pinned beyond what it says), or unknown
    origin: dict[str, Any]
    #: the server's entrypoint: the command after ``--from``/``--spec``/``--package``, the
    #: first-party ``hnx``, or a bare command run as it is (an unknown origin); None: the
    #: package's own (npm), the package name (pypi), the image's entrypoint
    bin: str | None = None
    #: the server's own arguments (everything after the launch position)
    args: list[str] = field(default_factory=list)
    #: a container runner's ``-e KEY[=VALUE]``, as ``{KEY: VALUE or None}``
    env: dict[str, str | None] = field(default_factory=dict)
    #: the launcher flags that were dropped (names, never values)
    dropped: list[str] = field(default_factory=list)
    #: why the command line was not mapped at all (then bin and args are empty)
    why: str | None = None


_VERSION = re.compile(
    r"v?[0-9]+\.[0-9]+(\.[0-9]+)*(?:[-+][0-9A-Za-z.]+|(?:a|b|rc|\.post|\.dev)[0-9]+)?"
)


def _origin(eco: str, spec: str) -> dict[str, Any] | None:
    """The origin a launch position names: a package, a git repo (no userinfo), or None."""
    if spec.startswith("git+"):
        url = spec.removeprefix("git+")
        url = re.sub(r"(://)[^/@\s]*@", r"\1", url)
        sep = "#" if eco == "npm" and "#" in url else "@"
        head, _, ref = url.rpartition(sep) if sep in url.split("://", 1)[-1] else (url, "", "")
        repo = head if ref else url
        commit = ref if re.fullmatch(r"[0-9a-f]{40}", ref or "") else None
        return {"kind": "git", "ecosystem": eco, "repo": repo, "commit": commit}
    parts = split_spec(eco, spec)
    if parts is None or spec.startswith("secret:"):
        return None
    name, ver = parts
    if eco == "pypi" and "[" in spec.split("==", 1)[0]:
        return None  # extras: a record names one package, nothing beside it
    return {"kind": "package", "ecosystem": eco, "package": name,
            "version": ver if ver and _VERSION.fullmatch(ver) else None, "sha256": None}  # fmt: skip


def map_launch(command: str, args: list[str]) -> Mapped:
    """``command args`` (a foreign client config's) as a record's origin, bin and arguments; see
    the module docstring.  The arguments are returned as written: the importer strips
    credentials from them."""
    args = [str(a) for a in args]
    got = parse(command, args)
    unknown = {"kind": "unknown", "hint": f"launcher {got.launcher or 'none'}"}
    if got.ecosystem is None:
        return Mapped(unknown, why=f"{got.launcher or 'no command'} is not a launcher a record "
                      "generates (a record names its origin; the renderer writes the launch)")  # fmt: skip
    if got.ecosystem == "first-party":
        return Mapped({"kind": "first-party", "path": "homelabnext/"}, bin="hnx", args=args)
    flags = sorted(set(got.flag_names.values()))  # value flags: switches are harmless
    blocking = [p for p in got.problems if "unknown flag" in p or "no value" in p
                or "names nothing" in p or "only `" in p or "more than once" in p]  # fmt: skip
    blocking += [f"{got.launcher} {f}: changes what runs" for f in flags if f in _UNMAPPABLE]
    if blocking or got.spec is None:
        return Mapped(unknown, why="; ".join(blocking) or f"{got.launcher}: names nothing to run")
    spec = got.spec
    env: dict[str, str | None] = {}
    if got.ecosystem == "image":
        parts = split_image(spec)
        if parts is None:
            return Mapped(unknown, why=f"{got.launcher}: {spec!r} is not an image reference")
        repo, tag, digest = parts
        origin = {"kind": "image", "image": repo + (f":{tag}" if tag else ""), "digest": digest}
        for i, name in got.flag_names.items():
            if name in ("-e", "--env"):
                k, eq, v = got.flag_values[i].partition("=")
                env[k] = v if eq else None
        dropped = [f for f in flags if f not in ("-e", "--env")]
        return Mapped(origin, None, args[got.server_args :], env, dropped)
    origin = _origin(got.ecosystem, spec)
    if origin is None:
        return Mapped(unknown, why=f"{got.launcher}: {spec!r} is not a package it can pin")
    bin_ = args[got.bin_index] if got.bin_index is not None else None
    named = (_NPM if got.ecosystem == "npm" else _UV if got.launcher != "pipx" else _PIPX).spec
    dropped = [f for f in flags if f not in named]
    return Mapped(origin, bin_, args[got.server_args :], env, dropped)
