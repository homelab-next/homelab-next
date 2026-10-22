# SPDX-License-Identifier: Apache-2.0
"""``hnx mcp catalog import``: draft catalog records from an existing lab's client configs.

Reads the MCP server entries of the client configuration files a lab already has: Claude Code
(``.mcp.json``, ``~/.claude.json`` with ``mcpServers`` at the top and under ``projects``), Claude
Desktop (``claude_desktop_config.json``), VS Code (``servers``) and Hermes Agent (``mcp_servers``
in YAML).  Each entry becomes a **draft** record (``status: draft``, never grantable):

* **secrets are stripped, failing closed.**  Every environment value is a ``secret:`` reference
  unless it is a path or its key is allowlisted as a mode, level and the like, and nothing in the
  value marks a credential; a ``${VAR}`` (or ``${VAR:-default}``) reference maps to a ``secret:``
  name (a rendered ``${HNX_SECRET_MCP_X}`` back to the ``mcp/x`` name it was rendered from).  In
  the server's arguments, everything check refuses (:mod:`.credentials`, the one rule set both
  use) becomes a reference, and more: an argument carrying a credential marker
  (``Authorization:``, ``password`` ...), and a URL's userinfo, query and any path that is not a
  plain MCP path (in ``*_URL`` settings too).  A container runner's ``-e KEY=VALUE`` that is not
  an allowlisted setting moves to ``env``.  The entry's own description is not copied.  The
  report names each reference (server, key, the name to store the value under); it never prints
  a value, and a config that does not parse is named by file, line and column only.
* **the launch is mapped, never copied.**  A record writes no launcher: the command line is read
  the way its launcher reads it (:func:`.launch.map_launch`) and becomes an origin (the package,
  git repo or image its launch position names; a version only when it is exact; no hash is ever
  invented, so :func:`homelabnext.mcp.servers.check` fails until the maintainer pins it), a bin
  (the command named after ``--from``/``--spec``/``--package``, unless it is the pypi package's
  own name) and the server's own arguments.  Launcher flags are dropped and named in the report;
  a container runner's ``-e KEY[=VALUE]`` becomes the record's environment.  A command line it
  cannot read (a shell, ``env``, an interpreter, a path, an unknown flag before the launch
  position, ``--entrypoint``) or whose bin is not the package's own command (``npx -p PKG node
  -e ...``) is not mapped: the draft is ``origin: {kind: unknown}`` with none of its arguments.
* **endpoints become registry names.**  A remote server's URL is not copied: the record names
  ``svc:<first label of the host>``, and the URL's path only when it is a plain MCP path
  (``/mcp``, ``/sse`` ...); check fails until that is a registry service.  Tools are not known
  from a client config: the record lists none, and check asks for them.
* **lossy by design.**  A ``timeout`` is kept; each rendered instance (``notes-a-real``,
  ``notes-a-shadow``) comes back as its own record: fold them into one record with
  ``parameters`` by hand.

Drafts go to ``--out`` (required); nothing is overwritten unless ``--force``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from homelabnext.registry.model import secret_env_name

from . import credentials, launch, servers

_BARE_FLAG = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_-]*$")
#: text inside an argument or a value that marks it as carrying a credential, whatever its length
_CRED_TEXT = re.compile(
    r"(?i:authorization\s*:|bearer\s|password|passwd|passphrase|pwd=|secret|token|api[-_]?key"
    r"|private[-_ ]?key|BEGIN [A-Z ]*PRIVATE)|(?:^|\s)[A-Z][A-Z0-9_]*=\S"
)
#: environment keys whose values are kept as settings (when nothing else marks them): every other
#: environment value is imported as a secret reference (fail closed)
_SETTING_KEY = re.compile(
    r"(?:^|_)(ROOT|DIR|DIRS|PATH|PATHS|FILE|MODE|LEVEL|DEBUG|VERBOSE|PORT|HOST|REGION|TZ|LANG"
    r"|LOCALE|FORMAT|TIMEOUT|LIMIT|ENABLED|DISABLED|READONLY|READ_ONLY|PREFIX|NAMESPACE"
    r"|WORKSPACE|PROJECT|BASE_URL|URL|ENDPOINT)$"
)
#: remote paths copied into transport.path; anything else may carry a token and is not copied
_PLAIN_PATHS = re.compile(r"^/(?:mcp|sse|messages|v[0-9]+/mcp|api/mcp)?/?$")
_SCHEMES = ("Bearer", "Basic", "Token")


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not s or not s[0].isalpha():
        s = "mcp-" + s if s else "mcp"
    return s[:64].rstrip("-")


def _secret_name(first: str, *rest: str) -> str:
    tail = [re.sub(r"[^a-z0-9]+", "-", p.lower()).strip("-") for p in rest if p]
    return "secret:mcp/" + "-".join([_slug(first), *[t for t in tail if t]])


def looks_secret(value: str) -> bool:
    """A value that is probably a credential (:func:`.credentials.looks_secret`, the rule check
    applies)."""
    return credentials.looks_secret(value)


def _var(value: str) -> str | None:
    """The variable a whole ``$VAR``, ``${VAR}`` or ``${VAR:-default}`` names, else None."""
    m = credentials.VAR.match(value)
    return (m.group("b") or m.group("n")) if m else None


def _plain_url(url: str) -> str:
    """A URL as the importer keeps it: scheme, host and port, and the path only when it is a
    plain MCP path; never userinfo, a query or a fragment."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return ""
    path = parts.path if _PLAIN_PATHS.fullmatch(parts.path or "/") else ""
    return f"{parts.scheme}://{host}{port}{path}"


_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s,]+")


def _urls(text: str) -> bool:
    """``text`` is a URL or a comma-separated list of them (``--allowed-origins a,b``); a URL
    inside other text (a user agent ``Bot/1.0 (+https://...)``) is not, and is kept unless check's
    rules find a credential in it."""
    return all(_URL.fullmatch(u) for u in text.split(","))


def _ref_for_var(var: str, fallback: str) -> str:
    """The secret reference a ``${VAR}`` stands for: a rendered ``${HNX_SECRET_MCP_X_Y}`` maps
    back to the name ``mcp/x-y`` (any name the renderer delivers as that same variable, so a
    re-render is identical), any other variable to the name the importer gives it."""
    if not var.startswith("HNX_SECRET_") or len(var) == len("HNX_SECRET_"):
        return fallback
    first, _, tail = var[len("HNX_SECRET_") :].lower().partition("_")
    ref = f"secret:{first}/{tail.replace('_', '-')}" if tail else f"secret:{first}"
    return ref if secret_env_name(ref) == var else fallback


def _is_setting(key: str, value: Any) -> bool:
    """An environment value kept as a non-secret setting: a path (where a credential is, never
    one), or an allowlisted key (a mode, a level ...) whose scalar value nothing marks as a
    credential; and never what check would refuse as a setting (:mod:`.credentials`)."""
    if isinstance(value, bool | int | float):
        value = str(value)
    if not isinstance(value, str) or credentials.setting_problem(key, value):
        return False
    if credentials.is_path(value):
        return True
    if not _SETTING_KEY.search(key) or credentials.credential_name(key):
        return False
    if "://" in value and urlsplit(value).query:
        return False
    return not _CRED_TEXT.search(value)


def _parse_error(p: Path, exc: Exception) -> ValueError:
    """A config that cannot be parsed, named by file, line and column only: a parser's own
    message quotes the offending line, which may hold a credential."""
    if isinstance(exc, json.JSONDecodeError):
        return ValueError(f"{p}: not valid JSON (line {exc.lineno}, column {exc.colno})")
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else ""
    return ValueError(f"{p}: not valid YAML{where}")


def _shape_problem(name: str, entry: Mapping[str, Any]) -> str | None:
    for key in ("env", "headers"):
        if entry.get(key) is not None and not isinstance(entry[key], Mapping):
            return f"server {name!r}: {key} is not a mapping"
    args = entry.get("args")
    if args is not None and (
        not isinstance(args, list) or not all(isinstance(a, str | int | float) for a in args)
    ):
        return f"server {name!r}: args is not a list of strings"
    return None


def read_entries(path: str | Path) -> dict[str, dict[str, Any]]:
    """``{name: entry}`` of every MCP server one client config declares (empty if none)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    try:
        doc = json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise _parse_error(p, exc) from None
    if not isinstance(doc, Mapping):
        raise ValueError(f"{p}: not a JSON or YAML mapping")
    out: dict[str, dict[str, Any]] = {}

    def take(block: Any) -> None:
        if isinstance(block, Mapping):
            for name, entry in block.items():
                if isinstance(entry, Mapping):
                    bad = _shape_problem(str(name), entry)
                    if bad:
                        raise ValueError(f"{p}: {bad}")
                    out.setdefault(str(name), dict(entry))

    for key in ("mcpServers", "servers", "mcp_servers"):
        take(doc.get(key))
    for proj in (
        (doc.get("projects") or {}).values() if isinstance(doc.get("projects"), Mapping) else ()
    ):
        if isinstance(proj, Mapping):
            take(proj.get("mcpServers"))
    return out


def guess_origin(command: str, args: list[str]) -> dict[str, Any]:
    """The origin a launcher implies (:func:`.launch.map_launch`; unpinned: no hash is ever
    invented)."""
    return launch.map_launch(command, args).origin


@dataclass
class Imported:
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: per record, what the maintainer must do (never a value)
    report: list[str] = field(default_factory=list)


def _clean_args(sid: str, args: list[str], notes: list[str]) -> list[str]:
    """A server's own arguments with every credential replaced by a ``secret:`` reference (fail
    closed): everything check refuses (:func:`.credentials.scan_args`: a credential flag's value,
    a header after ``--header``, a token, a URL, JSON or ``KEY=VALUE`` carrying one, ``$VAR``), and
    more: every argument carrying a credential marker (``Authorization:``, ``password`` ...), and
    a URL's userinfo, query and any path that is not a plain MCP path."""
    found = {f.index: f for f in credentials.scan_args(args)}
    clean: list[str] = []

    def secret(n: int, ref: str, text: str) -> None:
        clean.append(text)
        notes.append(
            f"{sid}: argument {n} carried or may carry a credential; replaced by {ref} (store the "
            "value under that name)"
        )

    for i, a in enumerate(args):
        n, f = i + 1, found.get(i)
        flag, eq, val = a.partition("=")
        if credentials.arg_secret(a):
            clean.append(a)  # already a reference (secret:x, --x=secret:x, Bearer secret:x)
            continue
        if credentials.expands(a):
            var = _var(a) or (_var(val) if eq and flag.startswith("-") else None)
            if var and _var(a):
                clean.append(_ref_for_var(var, _secret_name(var)))
            elif var:
                clean.append(f"{flag}={_ref_for_var(var, _secret_name(sid, flag))}")
            else:
                ref = _secret_name(sid, "arg", str(n))
                secret(n, ref, ref)
            continue
        if f is not None and f.kind == "header":
            name, colon, value = a.partition(":")
            scheme = next((sc + " " for sc in _SCHEMES if value.strip().startswith(sc + " ")), "")
            ref = _secret_name(sid, "header", name if colon else str(n))
            secret(n, ref, f"{name}: {scheme}{ref}" if colon and name.strip() else ref)
        elif f is not None and a.startswith("-") and eq:
            ref = _secret_name(sid, flag.lstrip("-"))
            secret(n, ref, f"{flag}={ref}")
        elif f is not None:
            ref = _secret_name(sid, "arg", str(n))
            secret(n, ref, ref)
        elif not eq and _BARE_FLAG.fullmatch(a):
            clean.append(a)  # a flag's own name
        elif _urls(val if eq and flag.startswith("-") else a):
            url = val if eq and flag.startswith("-") else a
            plain = ",".join(_plain_url(u) for u in url.split(","))
            if plain != url:
                notes.append(
                    f"{sid}: argument {n}: a URL's userinfo, query or path was removed (they may "
                    "hold a credential; keep only what the server needs)"
                )
            clean.append(f"{flag}={plain}" if url is val else plain)
        elif credentials.is_path(val if eq else a):
            clean.append(a)  # a path names where a credential is, never one
        elif eq and flag.startswith("-") and _CRED_TEXT.search(val):
            ref = _secret_name(sid, flag.lstrip("-"))
            secret(n, ref, f"{flag}={ref}")
        elif _CRED_TEXT.search(a):
            ref = _secret_name(sid, "arg", str(n))
            secret(n, ref, ref)
        else:
            clean.append(a)
    return clean


def draft(
    name: str, entry: Mapping[str, Any], source: str, taken: Iterable[str] = ()
) -> tuple[dict, list[str]]:
    """One client entry as a draft record, and the report lines about it."""
    sid = _slug(name)
    n, base = 2, sid
    while sid in set(taken):
        sid, n = f"{base}-{n}", n + 1
    notes: list[str] = []
    rec: dict[str, Any] = {
        "id": sid,
        # never the entry's own description: free text can hold anything, a credential included
        "description": f"Imported from {source} ({sid}); describe it.",
        "owner": "unassigned",
        "status": "draft",
    }
    url = entry.get("url") or entry.get("serverUrl")
    kind = str(entry.get("type") or entry.get("transport") or "")
    if url:
        parts = urlsplit(str(url))
        host = (parts.hostname or "unknown").split(".")[0]
        rec["origin"] = {"kind": "unknown", "hint": "a remote server: name the code it runs"}
        rec["transport"] = {"type": "sse" if kind == "sse" else "streamable-http",
                            "endpoint": f"svc:{_slug(host)}"}  # fmt: skip
        if _PLAIN_PATHS.fullmatch(parts.path or "/"):
            rec["transport"]["path"] = parts.path.rstrip("/") or "/mcp"
        else:
            notes.append(
                f"{sid}: the URL's path was not copied (it may carry a token); set transport.path"
            )
        rec["runtime"] = {"host": _slug(host), "user": "unassigned"}
        notes.append(
            f"{sid}: endpoint guessed as svc:{_slug(host)} from the URL's host; name the registry "
            "service (the URL, its query and any credentials in it were not copied)"
        )
        headers = {}
        for k, v in (entry.get("headers") or {}).items():
            value, scheme = str(v), ""
            for sc in _SCHEMES:
                if value.startswith(sc + " "):
                    scheme, value = sc + " ", value[len(sc) + 1 :]
            var = _var(value)
            fallback = _secret_name(var) if var else _secret_name(sid, k)
            ref = _ref_for_var(var, fallback) if var else fallback
            headers[str(k)] = scheme + ref
            notes.append(
                f"{sid}: header {k}: {'reference' if var else 'literal value'} replaced by {ref} "
                "(store the value under that name)"
            )
        if headers:
            rec["headers"] = headers
    else:
        command = str(entry.get("command") or "")
        env: dict[str, str] = {}
        settings: dict[str, str] = {}
        got = launch.map_launch(command, [str(a) for a in entry.get("args") or ()])
        rec["origin"] = got.origin
        rec["transport"] = {"type": "stdio"}
        if got.why:
            notes.append(
                f"{sid}: its launch was not mapped ({got.why}); none of its arguments were copied: "
                "name the origin, then the bin and the server's own args"
            )
        if got.dropped:
            notes.append(
                f"{sid}: launcher flag(s) {got.dropped} were not carried over (a record names no "
                "launcher flag; the render generates the launch from the origin)"
            )
        third_party = got.origin.get("kind") in ("package", "git")
        bin_problem = third_party and got.bin and servers.bin_problem(got.bin)
        if bin_problem:
            rec["origin"] = {"kind": "unknown", "hint": "its launch runs "
                             f"{got.bin}, not the package's own command"}  # fmt: skip
            notes.append(
                f"{sid}: {bin_problem}; it was not mapped (no origin, bin or argument copied)"
            )
        elif got.bin and not (
            got.origin.get("kind") == "package"
            and (
                launch.pypi_name(got.bin) == launch.pypi_name(got.origin["package"])
                if got.origin.get("ecosystem") == "pypi"
                else got.bin == servers.base_name(got.origin)
            )
        ):  # the bin the origin defaults to is not written
            rec["transport"]["bin"] = got.bin
        if third_party and not bin_problem:
            # what the config ran: the bin it named, else the default npx/uvx picked for it
            seen = got.bin or (
                got.origin["package"] if got.origin.get("ecosystem") == "pypi" and
                got.origin.get("kind") == "package" else servers.base_name(got.origin)
            )  # fmt: skip
            rec["origin"]["bins"] = [seen]
            notes.append(
                f"{sid}: origin.bins {[seen]} is what the config ran, not what the package "
                "declares: review the released artifact's bin names (package.json bin, the "
                "wheel's console_scripts) and list them (check cannot fetch the package)"
            )
        clean = [] if bin_problem else _clean_args(sid, got.args, notes)
        if clean:
            rec["transport"]["args"] = clean
        rec["runtime"] = "agent-local"
        for key, value in got.env.items():  # a container runner's -e KEY[=VALUE]
            if value is not None and _is_setting(key, value):
                settings[key] = value
                notes.append(f"{sid}: -e {key} kept as a setting: confirm it is not a credential")
            elif key not in (entry.get("env") or {}):
                env[key] = _secret_name(sid, key)
                notes.append(
                    f"{sid}: -e {key} moved to env as {env[key]} (store the value under that name)"
                )
        for k, v in (entry.get("env") or {}).items():
            key = str(k)
            var = _var(v) if isinstance(v, str) else None
            if var:
                env[key] = _ref_for_var(var, _secret_name(var))
                notes.append(f"{sid}: env {key}: reference replaced by {env[key]}")
            elif _is_setting(key, v):
                settings[key] = str(v)
                if "://" in settings[key] and _plain_url(settings[key]) != settings[key]:
                    settings[key] = _plain_url(settings[key])
                    notes.append(
                        f"{sid}: env {key}: the URL's path was removed (it may carry a token); "
                        "put back only a path that holds no credential"
                    )
                notes.append(f"{sid}: env {key} kept as a setting: confirm it is not a credential")
            else:
                env[key] = _secret_name(sid, key)
                notes.append(
                    f"{sid}: env {key}: value replaced by {env[key]} (every environment value is "
                    "a secret unless its key names a path, mode or level; store the value under "
                    "that name, or move it to settings if it is not a credential)"
                )
        if env:
            rec["env"] = dict(sorted(env.items()))
        if settings:
            rec["settings"] = settings
    timeout = entry.get("timeout")
    if isinstance(timeout, int) and not isinstance(timeout, bool) and 1 <= timeout <= 86400:
        rec["timeout"] = timeout
    if rec["origin"]["kind"] != "first-party":
        notes.append(
            f"{sid}: origin is not pinned ({rec['origin']['kind']}): add the exact version and "
            "sha256, the image digest or the commit"
        )
    rec.update({"egress": "none", "data_tier": "local-only", "tools": [], "author": "unknown"})
    notes.append(
        f"{sid}: list its tools with their classes, and declare its egress (written as none)"
    )
    return rec, notes


def import_configs(paths: Iterable[str | Path], existing: Iterable[str] = ()) -> Imported:
    """Draft records for every server in ``paths``; a name seen in an earlier file is skipped."""
    res = Imported()
    seen_names: set[str] = set()
    taken = set(existing)
    for p in paths:
        for name, entry in sorted(read_entries(p).items()):
            if name in seen_names:
                res.report.append(f"{_slug(name)}: also in {Path(p).name}; kept the first")
                continue
            seen_names.add(name)
            rec, notes = draft(name, entry, Path(p).name, taken | set(res.records))
            res.records[rec["id"]] = rec
            res.report += notes
    return res


HEAD = (
    "# SPDX-License-Identifier: Apache-2.0\n"
    "# Draft imported by hnx mcp catalog import: secrets are secret: names, the origin is not\n"
    "# pinned and no tools are listed yet. Fix what `hnx mcp catalog check` reports, then review.\n"
)


def write_records(
    records: Mapping[str, Mapping[str, Any]], out: str | Path, force: bool = False
) -> tuple[list[Path], list[str]]:
    """Write each record as ``<out>/<id>.yml``; an existing file is skipped unless ``force``."""
    d = Path(out)
    d.mkdir(parents=True, exist_ok=True)
    written, skipped = [], []
    for sid, rec in sorted(records.items()):
        f = d / f"{sid}.yml"
        if f.exists() and not force:
            skipped.append(f"{f}: exists (use --force to replace it)")
            continue
        f.write_text(HEAD + yaml.safe_dump(dict(rec), sort_keys=False, width=100), encoding="utf-8")
        written.append(f)
    return written, skipped
