# SPDX-License-Identifier: Apache-2.0
"""``hnx mcp catalog import``: draft catalog records from an existing lab's client configs.

Reads the MCP server entries of the client configuration files a lab already has: Claude Code
(``.mcp.json``, ``~/.claude.json`` with ``mcpServers`` at the top and under ``projects``), Claude
Desktop (``claude_desktop_config.json``), VS Code (``servers``) and Hermes Agent (``mcp_servers``
in YAML).  Each entry becomes a **draft** record (``status: draft``, never grantable):

* **secrets are stripped, failing closed.**  Every environment value is a ``secret:`` reference
  unless its key is allowlisted as a path, mode, level and the like and nothing in the value marks
  a credential; a ``${VAR}`` reference maps to a ``secret:`` name (a rendered
  ``${HNX_SECRET_MCP_X}`` back to the ``mcp/x`` name it was rendered from).  In the arguments: the value after a
  credential flag (``--token``, ``--github-token``, ``--client-secret`` ...) or in
  ``--flag=VALUE``, a header after ``--header``/``-H`` (its name kept), a container runner's
  ``-e KEY=VALUE`` (moved to ``env``), a token-like value and an argument carrying a credential
  marker (``Authorization:``, ``KEY=VALUE`` in a shell line ...) become references, and URL
  userinfo and query strings are removed.  A launcher's package spec (``name==1.2.0``,
  ``@scope/name@1.2.0``) is never a secret.  The entry's own description is not copied.  The
  report names each reference (server, key, the name to store the value under); it never prints
  a value, and a config that does not parse is named by file, line and column only.
* **origins are guessed, never pinned.**  ``npx``/``uvx``/``pipx``/``docker run`` launchers
  give a package or image (``git+https://...`` a git origin, without userinfo); a version is kept
  only when it is exact, and no hash is invented, so :func:`homelabnext.mcp.servers.check` fails
  until the maintainer pins it.  Anything else is ``origin: {kind: unknown}``.
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
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from homelabnext.registry.model import secret_env_name

from . import servers

_VERSION = re.compile(
    r"^v?[0-9]+\.[0-9]+(\.[0-9]+)*(?:[-+][0-9A-Za-z.]+|(?:a|b|rc|\.post|\.dev)[0-9]+)?$"
)
_VAR = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
#: a flag whose value is a credential (the value follows as ``=VALUE`` or as the next argument)
_SECRET_FLAG = servers.CREDENTIAL_FLAG
_BARE_FLAG = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_-]*$")
#: a flag whose next argument is an HTTP header (``Name: value``)
_HEADER_FLAG = ("--header", "-H")
#: docker/podman flags whose next argument is ``KEY=VALUE`` (or ``KEY``)
_ENV_FLAG = ("-e", "--env")
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
#: a package spec at a launcher's package position: name==version or name@version (never a secret)
_PACKAGE_SPEC = re.compile(
    r"^(@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*((==|@)[A-Za-z0-9._+-]+)?$"
)
#: remote paths copied into transport.path; anything else may carry a token and is not copied
_PLAIN_PATHS = re.compile(r"^/(?:mcp|sse|messages|v[0-9]+/mcp|api/mcp)?/?$")
_URL_USERINFO = re.compile(r"(://)[^/@\s]*@")
_SCHEMES = ("Bearer", "Basic", "Token")
_RUNNER_FLAGS_WITH_VALUE = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish",
                            "--network", "-u", "--user", "-w", "--workdir", "--env-file",
                            "--mount", "--entrypoint", "--platform"}  # fmt: skip


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if not s or not s[0].isalpha():
        s = "mcp-" + s if s else "mcp"
    return s[:64].rstrip("-")


def _secret_name(first: str, *rest: str) -> str:
    tail = [re.sub(r"[^a-z0-9]+", "-", p.lower()).strip("-") for p in rest if p]
    return "secret:mcp/" + "-".join([_slug(first), *[t for t in tail if t]])


def looks_secret(value: str) -> bool:
    """A value that is probably a credential: a URL with a password, or a long token-like
    string (mixed letters and digits, high entropy, no spaces or path separators).  A package
    spec (``name==1.2.0``, ``@scope/name@1.2.0``) never is."""
    return servers.looks_secret(value)


def _credential(value: str) -> bool:
    """A value that is or carries a credential (a package spec never does)."""
    if _PACKAGE_SPEC.match(value):
        return False
    return looks_secret(value) or bool(_CRED_TEXT.search(value))


def _url_carries(value: str) -> bool:
    """A URL with credentials in it: userinfo, or a query string (``?key=...``)."""
    if "://" not in value:
        return False
    parts = urlsplit(value)
    return bool(parts.username or parts.password or parts.query)


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
    """An environment value kept as a non-secret setting: only an allowlisted key (a path, a
    mode, a level ...) whose scalar value nothing marks as a credential."""
    if isinstance(value, bool | int | float):
        value = str(value)
    if not isinstance(value, str) or not _SETTING_KEY.search(key) or servers.SECRET_KEY.search(key):
        return False
    return not (looks_secret(value) or _CRED_TEXT.search(value) or _url_carries(value))


def _package_positions(command: str, args: list[str]) -> set[int]:
    """Indexes of the arguments that name the package a launcher runs (never secrets)."""
    base = PurePosixPath(command).name
    out: set[int] = set()
    for i in range(1, len(args)):
        if args[i - 1] == "--from":
            out.add(i)
    if base in ("npx", "bunx", "uvx", "pipx", "uv"):
        for i, a in enumerate(args):
            if (
                not a.startswith("-")
                and a not in ("run", "tool")
                and (not i or args[i - 1] != "--from")
            ):
                out.add(i)
                break
    return {i for i in out if _PACKAGE_SPEC.match(args[i])}


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


def _git_origin(spec: str) -> dict[str, Any]:
    """``git+https://host/org/repo[@ref]`` as a git origin (userinfo already removed)."""
    url = spec.removeprefix("git+")
    head, _, ref = url.rpartition("@") if url.count("@") and "://" in url else (url, "", "")
    repo = head if ref else url
    commit = ref if re.fullmatch(r"[0-9a-f]{40}", ref or "") else None
    return {"kind": "git", "repo": repo, "commit": commit}


def guess_origin(command: str, args: list[str]) -> dict[str, Any]:
    """The origin a launcher implies (unpinned: no hash is ever invented).  ``args`` are the
    cleaned arguments: no credential, no URL userinfo."""
    base = PurePosixPath(command).name
    positional = [a for a in args if not a.startswith("-")]
    if base in ("npx", "bunx") and positional:
        spec = positional[0]
        scoped = spec.startswith("@")
        name, _, ver = spec[1:].partition("@") if scoped else spec.partition("@")
        name = "@" + name if scoped else name
        return {"kind": "package", "ecosystem": "npm", "package": name,
                "version": ver if _VERSION.match(ver or "") else None, "sha256": None}  # fmt: skip
    if base in ("uvx", "pipx", "uv"):
        spec = args[args.index("--from") + 1] if "--from" in args[:-1] else (
            [a for a in positional if a not in ("run", "tool")] or [""])[0]  # fmt: skip
        if spec.startswith("git+"):
            return _git_origin(spec)
        name, ver = [*re.split(r"==|@", spec, maxsplit=1), ""][:2]
        if name and _PACKAGE_SPEC.match(spec):
            return {"kind": "package", "ecosystem": "pypi", "package": name,
                    "version": ver if _VERSION.match(ver) else None, "sha256": None}  # fmt: skip
    if base in ("docker", "podman") and "run" in args:
        rest, i = args[args.index("run") + 1 :], 0
        while i < len(rest) and rest[i].startswith("-"):
            i += 2 if rest[i] in _RUNNER_FLAGS_WITH_VALUE else 1
        if i < len(rest):
            image, _, digest = rest[i].partition("@")
            return {"kind": "image", "image": image.lower(),
                    "digest": digest if digest.startswith("sha256:") else None}  # fmt: skip
    if base == "hnx":
        return {"kind": "first-party", "path": "homelabnext/"}
    return {"kind": "unknown", "hint": f"launcher {base}"}


@dataclass
class Imported:
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: per record, what the maintainer must do (never a value)
    report: list[str] = field(default_factory=list)


def _clean_args(
    sid: str, command: str, args: list[str], env: dict[str, str], notes: list[str]
) -> list[str]:
    """The arguments with every credential replaced by a ``secret:`` reference (fail closed):
    a value after a credential flag or in ``--flag=VALUE``, a header after ``--header``, a
    ``-e KEY=VALUE`` of a container runner (moved to ``env``), a token-like value, an argument
    carrying a credential marker (``Authorization:``, ``KEY=VALUE`` in a shell line ...), and URL
    userinfo and query strings.  A launcher's package spec is never a secret."""
    packages = _package_positions(command, args)
    runner = PurePosixPath(command).name in ("docker", "podman")
    clean: list[str] = []
    for i, a in enumerate(args):
        prev = args[i - 1] if i else ""
        n = i + 1
        stripped = _URL_USERINFO.sub(r"\1", a)
        if stripped != a:
            notes.append(
                f"{sid}: argument {n}: credentials in a URL were removed (store them in the "
                "secret store and pass them another way)"
            )
            a = stripped
        if "://" in a and urlsplit(a.split("=", 1)[-1]).query:
            a = a.split("?", 1)[0]
            notes.append(
                f"{sid}: argument {n}: a URL's query string was removed (it may hold a key)"
            )
        m = _VAR.match(a)
        flag, eq, val = a.partition("=")
        if m:
            clean.append(_ref_for_var(m.group(1), _secret_name(m.group(1))))
            continue
        if eq and flag.startswith("-") and _VAR.match(val):
            clean.append(
                f"{flag}={_ref_for_var(_VAR.match(val).group(1), _secret_name(sid, flag))}"
            )
            continue
        if i in packages or (not eq and _BARE_FLAG.match(a)):
            clean.append(a)  # a launcher's package spec, or a flag's own name
            continue
        if runner and prev in _ENV_FLAG and "=" not in a:
            clean.append(a)  # -e KEY: the value comes from the environment (env)
            continue
        if runner and prev in _ENV_FLAG:
            key, _, value = a.partition("=")
            if _is_setting(key, value):
                clean.append(a)
                continue
            env[key] = _secret_name(sid, key)
            clean.append(key)
            notes.append(
                f"{sid}: argument {n}: -e {key}=... moved to env as {env[key]} (store the value "
                "under that name)"
            )
            continue
        if prev in _HEADER_FLAG:
            name, colon, value = a.partition(":")
            scheme = next((sc + " " for sc in _SCHEMES if value.strip().startswith(sc + " ")), "")
            ref = _secret_name(sid, "header", name if colon else str(n))
            clean.append(f"{name}: {scheme}{ref}" if colon and name.strip() else ref)
        elif flag.startswith("-") and eq and (_SECRET_FLAG.match(flag) or _credential(val)):
            ref = _secret_name(sid, flag.lstrip("-"))
            clean.append(f"{flag}={ref}")
        elif _SECRET_FLAG.match(prev) or _credential(a):
            ref = _secret_name(sid, "arg", str(n))
            clean.append(ref)
        else:
            clean.append(a)
            continue
        notes.append(
            f"{sid}: argument {n} carried or may carry a credential; replaced by {ref} (store the "
            "value under that name)"
        )
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
        if _PLAIN_PATHS.match(parts.path or "/"):
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
            m = _VAR.match(value)
            fallback = _secret_name(m.group(1)) if m else _secret_name(sid, k)
            ref = _ref_for_var(m.group(1), fallback) if m else fallback
            headers[str(k)] = scheme + ref
            notes.append(
                f"{sid}: header {k}: {'reference' if m else 'literal value'} replaced by {ref} "
                "(store the value under that name)"
            )
        if headers:
            rec["headers"] = headers
    else:
        command = str(entry.get("command") or "")
        env: dict[str, str] = {}
        settings: dict[str, str] = {}
        clean = _clean_args(sid, command, [str(a) for a in entry.get("args") or ()], env, notes)
        rec["origin"] = guess_origin(command, clean)
        rec["transport"] = {"type": "stdio", "command": command or "unknown", "args": clean}
        rec["runtime"] = "agent-local"
        for k, v in (entry.get("env") or {}).items():
            key = str(k)
            m = _VAR.match(v) if isinstance(v, str) else None
            if m:
                env[key] = _ref_for_var(m.group(1), _secret_name(m.group(1)))
                notes.append(f"{sid}: env {key}: reference replaced by {env[key]}")
            elif _is_setting(key, v):
                settings[key] = str(v)
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
