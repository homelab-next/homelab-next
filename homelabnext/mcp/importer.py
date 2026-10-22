# SPDX-License-Identifier: Apache-2.0
"""``hnx mcp catalog import``: draft catalog records from an existing lab's client configs.

Reads the MCP server entries of the client configuration files a lab already has: Claude Code
(``.mcp.json``, ``~/.claude.json`` with ``mcpServers`` at the top and under ``projects``), Claude
Desktop (``claude_desktop_config.json``), VS Code (``servers``) and Hermes Agent (``mcp_servers``
in YAML).  Each entry becomes a **draft** record (``status: draft``, never grantable):

* **secrets are stripped.**  Every environment value and header that is or may be a credential
  (by its name, or a value that looks like one), every ``${VAR}`` reference and every argument
  that follows a credential flag or looks like a token becomes a ``secret:``
  reference.  The report names each one (server, key, the secret name to store the value
  under); it never prints a value.  Other environment values are kept as ``settings`` and the
  report asks the maintainer to confirm they are not credentials.
* **origins are guessed, never pinned.**  ``npx``/``uvx``/``pipx``/``docker run`` launchers
  give a package or image; a version is kept only when it is exact, and no hash is invented,
  so :func:`homelabnext.mcp.servers.check` fails until the maintainer pins it.  Anything else
  is ``origin: {kind: unknown}``.
* **endpoints become registry names.**  A remote server's URL is not copied: the record names
  ``svc:<first label of the host>`` and the URL path; check fails until that is a registry
  service.  Tools are not known from a client config: the record lists none, and check asks
  for them.

Nothing is overwritten unless ``--force``.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from . import servers

_VERSION = re.compile(
    r"^v?[0-9]+\.[0-9]+(\.[0-9]+)*(?:[-+][0-9A-Za-z.]+|(?:a|b|rc|\.post|\.dev)[0-9]+)?$"
)
_VAR = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_SECRET_FLAG = re.compile(
    r"^--?(token|api[-_]?key|apikey|password|passwd|secret|key|auth|bearer|access[-_]token)$", re.I
)
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
    string (mixed letters and digits, high entropy, no spaces or path separators)."""
    if re.search(r"://[^/@\s:]+:[^/@\s]+@", value):
        return True
    v = value.strip()
    if len(v) < 20 or " " in v or "/" in v or v.startswith("$"):
        return False
    if not (re.search(r"[0-9]", v) and re.search(r"[A-Za-z]", v)):
        return False
    counts = {c: v.count(c) for c in set(v)}
    entropy = -sum(n / len(v) * math.log2(n / len(v)) for n in counts.values())
    return entropy >= 3.5


def read_entries(path: str | Path) -> dict[str, dict[str, Any]]:
    """``{name: entry}`` of every MCP server one client config declares (empty if none)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    doc = json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)
    if not isinstance(doc, Mapping):
        raise ValueError(f"{p}: not a JSON or YAML mapping")
    out: dict[str, dict[str, Any]] = {}

    def take(block: Any) -> None:
        if isinstance(block, Mapping):
            for name, entry in block.items():
                if isinstance(entry, Mapping):
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
    """The origin a launcher implies (unpinned: no hash is ever invented)."""
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
        name, ver = [*re.split(r"==|@", spec, maxsplit=1), ""][:2]
        if name:
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
        "description": str(
            entry.get("description") or f"Imported from {source} ({name}); describe it."
        )[:300],
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
                            "endpoint": f"svc:{_slug(host)}", "path": parts.path or "/mcp"}  # fmt: skip
        rec["runtime"] = {"host": _slug(host), "user": "unassigned"}
        notes.append(
            f"{sid}: endpoint guessed as svc:{_slug(host)} from the URL's host; name the registry service (the URL was not copied)"
        )
        headers = {}
        for k, v in (entry.get("headers") or {}).items():
            value, scheme = str(v), ""
            for sc in _SCHEMES:
                if value.startswith(sc + " "):
                    scheme, value = sc + " ", value[len(sc) + 1 :]
            m = _VAR.match(value)
            ref = _secret_name(m.group(1)) if m else _secret_name(sid, k)
            headers[str(k)] = scheme + ref
            notes.append(
                f"{sid}: header {k}: {'reference' if m else 'literal value'} replaced by {ref} (store the value under that name)"
            )
        if headers:
            rec["headers"] = headers
    else:
        command = str(entry.get("command") or "")
        args = [str(a) for a in entry.get("args") or ()]
        clean: list[str] = []
        for i, a in enumerate(args):
            flag, eq, val = a.partition("=")
            prev = args[i - 1] if i else ""
            if (eq and _SECRET_FLAG.match(flag)) or (eq and looks_secret(val)):
                ref = _secret_name(sid, flag.lstrip("-"))
                clean.append(f"{flag}={ref}")
            elif _SECRET_FLAG.match(prev) or looks_secret(a):
                ref = _secret_name(sid, "arg", str(i))
                clean.append(ref)
            else:
                clean.append(a)
                continue
            notes.append(
                f"{sid}: argument {i + 1} looked like a credential; replaced by {ref} (store the value under that name)"
            )
        rec["origin"] = guess_origin(command, args)
        rec["transport"] = {"type": "stdio", "command": command or "unknown", "args": clean}
        rec["runtime"] = "agent-local"
        env: dict[str, str] = {}
        settings: dict[str, str] = {}
        for k, v in (entry.get("env") or {}).items():
            key, value = str(k), str(v)
            m = _VAR.match(value)
            if m or servers.SECRET_KEY.search(key) or looks_secret(value):
                ref = _secret_name(m.group(1)) if m else _secret_name(sid, key)
                env[key] = ref
                notes.append(
                    f"{sid}: env {key}: {'reference' if m else 'value'} replaced by {ref} (store the value under that name)"
                )
            else:
                settings[key] = value
                notes.append(f"{sid}: env {key} kept as a setting: confirm it is not a credential")
        if env:
            rec["env"] = env
        if settings:
            rec["settings"] = settings
    if rec["origin"]["kind"] != "first-party":
        notes.append(
            f"{sid}: origin is not pinned ({rec['origin']['kind']}): add the exact version and sha256, the image digest or the commit"
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
