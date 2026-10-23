#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: caddy-lint
#   kind: check
#   purpose: Fail when a Caddy config lets a client-sent identity header past forward_auth, or a Caddy pin is below 2.11.2.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:caddy-lint]
#   invariant: [F-23]
#   inputs: the tracked tree (Caddyfiles, templates, markdown caddyfile blocks, registries) and the caddy generator
#   outputs: one line per unprotected forward_auth or vulnerable Caddy pin
#   exit:
#     "0": clean
#     "1": an unprotected forward_auth or a Caddy pin below 2.11.2
#     "2": usage error or a missing dependency
"""Gate: the edge never lets a client name its own identity to a service behind forward-auth.

``forward_auth`` copies the identity provider's answer (``copy_headers``) onto the request, and the
service trusts those headers. Caddy 2.9.0 to 2.11.1 keep a header the *client* sent when the
IdP's answer omits it, and every Caddy up to 2.11.1 passes the underscore spelling
(``X_Authentik_Groups``), which a CGI-style upstream folds into the real header. So two things
must hold, everywhere:

  strip      every ``forward_auth`` sits directly inside a ``route`` block, and earlier in that
             same ``route`` a ``request_header -<name>`` (or a ``-<prefix>*`` / ``-*<suffix>``
             wildcard) deletes every header its ``copy_headers`` sets, in both the dash and the
             underscore spelling. (Outside a ``route``, Caddy's directive order runs
             ``forward_auth`` before ``request_header``, so the strip would delete the IdP's own
             headers instead of the client's.) A ``copy_headers`` that is itself templated
             cannot be checked and fails closed: list the headers literally.
  pin        every Caddy pin is 2.11.2 or later: a registry service with ``impl: caddy`` (its
             ``version``), a ``caddy_version`` key, and a container image ``caddy:<tag>`` (an
             untagged or floating ``caddy`` image is a finding too).

Caddy configs checked: every tracked ``Caddyfile*``, ``*.caddy``, ``*.caddyfile`` and their
``.j2``/``.tmpl`` templates; every ```` ```caddy ```` / ```` ```caddyfile ```` block in markdown;
and the output of the ``caddy`` generator for every registry in the tree that loads (a registry
that does not load, such as a schema negative, is skipped; its pins are still checked). A
reviewed exception is an inline ``caddy-lint: allow <reason>`` comment on the offending line.

Usage: python tools/caddy_lint.py [ROOT] [--json]
Exit: 0 clean, 1 a finding, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

#: the first release whose forward_auth drops a client-sent header the IdP's answer omits
MIN_CADDY = (2, 11, 2)
MIN_CADDY_TEXT = ".".join(map(str, MIN_CADDY))
INLINE_ALLOW = re.compile(r"caddy-lint:\s*allow\s+\S")
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    ".pytest_cache",
    ".ruff_cache",
}
CADDY_NAME = re.compile(r"(^Caddyfile([.-].*)?$)|(\.(caddy|caddyfile)(\.(j2|tmpl))?$)", re.I)
MD_FENCE = re.compile(r"^[ \t]*```(?:caddy|caddyfile)[ \t]*\n(.*?)^[ \t]*```", re.M | re.S | re.I)
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|`[^`]*`|\S+')
VERSION = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?P<pre>-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
#: a container image reference to the Caddy image: ``caddy``, ``library/caddy``,
#: ``docker.io/library/caddy`` (``caddy:<tag>``, ``caddy@sha256:``), but not ``foo/caddy-x``
IMAGE = re.compile(
    r"(?<![\w./-])(?:(?:docker\.io|index\.docker\.io)/)?(?:library/)?caddy"
    r"(?::(?P<tag>[\w.-]+))?(?:@sha256:[0-9a-f]{64})?(?![\w./:-])"
)
TEMPLATED = re.compile(r"\{\{|\{%|\$\{")


class Finding(NamedTuple):
    """One unprotected forward_auth (``strip``), vulnerable pin (``pin``) or unreadable file."""

    path: str
    line: int
    rule: str
    detail: str


@dataclass
class Node:
    tokens: list[str]
    line: int
    children: list[Node] = field(default_factory=list)
    parent: Node | None = None

    @property
    def name(self) -> str:
        return self.tokens[0] if self.tokens else ""


# ---------------------------------------------------------------- Caddyfile


def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in '"`':
        return tok[1:-1]
    return tok


def parse_caddyfile(text: str) -> Node:
    """A block tree of a Caddyfile: one node per directive line, a trailing ``{`` opens its
    children and a lone ``}`` closes them (the Caddyfile's own block rule)."""
    root = Node([], 0)
    cur = root
    for no, raw in enumerate(text.splitlines(), 1):
        toks: list[str] = []
        for t in TOKEN.findall(raw):
            if t.startswith("#"):
                break
            toks.append(t)
        if not toks:
            continue
        if toks == ["}"]:
            cur = cur.parent or root
            continue
        opens = toks[-1] == "{"
        node = Node([_unquote(t) for t in (toks[:-1] if opens else toks)], no, parent=cur)
        cur.children.append(node)
        if opens:
            cur = node
    return root


def _walk(node: Node):
    for c in node.children:
        yield c
        yield from _walk(c)


def _copied(auth: Node) -> tuple[list[str], int | None]:
    """The request headers ``forward_auth`` sets (``A>B`` sets ``B``), and the line of a
    templated ``copy_headers`` (None when every entry is literal)."""
    names: list[str] = []
    templated = None
    for c in auth.children:
        if c.name != "copy_headers":
            continue
        entries = c.tokens[1:] + [t for g in c.children for t in g.tokens[:1]]
        if any(TEMPLATED.search(e) or "{" in e or "}" in e for e in entries):
            templated = templated or c.line  # the real list is only known once rendered
            continue
        names += [e.split(">", 1)[-1] for e in entries]
    return names, templated


def _covers(pattern: str, header: str) -> bool:
    p, h = pattern.lower(), header.lower()
    if p.endswith("*"):
        return h.startswith(p[:-1])
    if p.startswith("*"):
        return h.endswith(p[1:])
    return p == h


def lint_caddy(text: str, path: str = "<text>", line_offset: int = 0) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for node in _walk(parse_caddyfile(text)):
        if node.name != "forward_auth":
            continue
        line = node.line + line_offset
        if INLINE_ALLOW.search(lines[node.line - 1]):
            continue
        route = node.parent
        if route is None or route.name != "route":
            findings.append(
                Finding(path, line, "strip", "forward_auth is not directly inside a route block")
            )
            continue
        before = route.children[: route.children.index(node)]
        deleted = [
            n.tokens[1][1:]
            for n in before
            if n.name == "request_header" and len(n.tokens) >= 2 and n.tokens[1].startswith("-")
        ]
        names, templated = _copied(node)
        if templated is not None:
            findings.append(
                Finding(
                    path,
                    templated + line_offset,
                    "strip",
                    "copy_headers is templated, so its strip cannot be checked: list the headers",
                )
            )
        for h in names:
            for spelling in dict.fromkeys((h, h.replace("-", "_"))):
                if not any(_covers(p, spelling) for p in deleted):
                    findings.append(
                        Finding(
                            path,
                            line,
                            "strip",
                            f"client-sent {spelling} is not deleted before forward_auth "
                            "in the same route",
                        )
                    )
    return findings


# ---------------------------------------------------------------- pins


def version_ok(version: str) -> bool:
    m = VERSION.match(str(version).strip())
    if not m or m.group(3) is None:  # a floating 2.11 is whatever 2.11.x the pull finds
        return False
    v = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return v > MIN_CADDY or (v == MIN_CADDY and not m.group("pre"))


def _line_of(lines: list[str], needle: str, start: int = 0) -> int:
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return 0


def _image_findings(value: str, path: str, lines: list[str]) -> list[Finding]:
    out = []
    for m in IMAGE.finditer(value):
        tag = m.group("tag")
        base, _, variant = (tag or "").partition("-")  # 2.11.7-alpine, 2.11.7-builder
        if version_ok(base) and not re.match(r"(alpha|beta|rc)", variant):
            continue
        ln = _line_of(lines, m.group(0))
        if ln and INLINE_ALLOW.search(lines[ln - 1]):
            continue
        what = f"caddy image tag {tag!r}" if tag else "caddy image without a version tag"
        out.append(Finding(path, ln, "pin", f"{what}: pin {MIN_CADDY_TEXT} or later"))
    return out


def lint_pins(text: str, path: str = "<text>") -> list[Finding]:
    """Caddy pins in a YAML/JSON document (every document, every nesting level)."""
    findings: list[Finding] = []
    lines = text.splitlines()

    def bad(needle: str, detail: str, then: str = "") -> None:
        ln = _line_of(lines, needle)
        if ln and then:  # the pin's own line under its key, when it has one
            ln = _line_of(lines, then, ln - 1) or ln
        if ln and INLINE_ALLOW.search(lines[ln - 1]):
            return
        findings.append(Finding(path, ln, "pin", f"{detail}: pin {MIN_CADDY_TEXT} or later"))

    def walk(o, key: str = "") -> None:
        if isinstance(o, dict):
            if str(o.get("impl", "")).strip().lower() == "caddy":
                v = o.get("version")
                if v is None or not version_ok(str(v)):
                    bad(
                        f"{key}:" if key else "caddy",
                        f"service {key or '?'} caddy {v!r}",
                        "version" if v is not None else "",
                    )
            for k, v in o.items():
                if str(k).lower() == "caddy_version" and not version_ok(str(v)):
                    bad(str(k), f"caddy_version {v!r}")
                walk(v, str(k))
        elif isinstance(o, list):
            for v in o:
                walk(v, key)
        elif isinstance(o, str) and (key == "image" or re.search(r"caddy[:@]", o)):
            findings.extend(_image_findings(o, path, lines))

    for doc in yaml.safe_load_all(text):
        walk(doc)
    return findings


def lint_dockerfile(text: str, path: str = "<text>") -> list[Finding]:
    lines = text.splitlines()
    out = []
    for ln in lines:
        m = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", ln, re.I)
        if m:
            out += _image_findings(m.group(1), path, lines)
    return out


# ---------------------------------------------------------------- the tree


def _generated(text: str) -> str | None:
    """The caddy generator's output for a registry document, or None when it is not one that
    loads (a schema negative, an injection fixture)."""
    from homelabnext.generators import generate
    from homelabnext.generators.safe import UnsafeValueError
    from homelabnext.registry.model import RegistryError, loads

    try:
        out = generate(loads(text), ["caddy"])["caddy"]
    except (RegistryError, UnsafeValueError, KeyError, TypeError, ValueError, AttributeError):
        return None
    return out.get("caddy/sites.caddy")


def _is_registry(doc: object) -> bool:
    return isinstance(doc, dict) and "registry_version" in doc and "services" in doc


def _files(root: Path):
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in rel.split("/")):
            continue
        if p.is_file() and not p.is_symlink():
            yield p, rel


def scan(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    counts = {"files": 0, "caddy_configs": 0, "generated": 0}
    for p, rel in _files(root):
        name = p.name
        try:
            if CADDY_NAME.search(name):
                text = p.read_text(encoding="utf-8")
                counts["files"] += 1
                counts["caddy_configs"] += 1
                findings += lint_caddy(text, rel)
            elif p.suffix == ".md":
                text = p.read_text(encoding="utf-8")
                blocks = list(MD_FENCE.finditer(text))
                if blocks:
                    counts["files"] += 1
                for m in blocks:
                    counts["caddy_configs"] += 1
                    offset = text.count("\n", 0, m.start(1))
                    findings += lint_caddy(m.group(1), rel, offset)
            elif (
                name == "Dockerfile" or name.startswith("Dockerfile.") or p.suffix == ".dockerfile"
            ):
                counts["files"] += 1
                findings += lint_dockerfile(p.read_text(encoding="utf-8"), rel)
            elif p.suffix in (".yml", ".yaml", ".json"):
                text = p.read_text(encoding="utf-8")
                if "caddy" not in text.lower():
                    continue
                counts["files"] += 1
                findings += lint_pins(text, rel)
                docs = list(yaml.safe_load_all(text))
                if len(docs) == 1 and _is_registry(docs[0]):
                    site = _generated(text)
                    if site is not None:
                        counts["generated"] += 1
                        counts["caddy_configs"] += 1
                        findings += lint_caddy(site, f"{rel} (caddy generator)")
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            findings.append(Finding(rel, 0, "parse", f"cannot parse: {exc.__class__.__name__}"))
    return findings, counts


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    parser = argparse.ArgumentParser(prog="caddy_lint", description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=".", help="the tree to check")
    parser.add_argument("--json", action="store_true", help="findings as JSON on stdout")
    try:
        opts = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    root = Path(opts.root).resolve()
    if not root.is_dir():
        print(f"caddy_lint: {root} is not a directory", file=err)
        return 2
    findings, counts = scan(root)
    if opts.json:
        doc = {**counts, "findings": [f._asdict() for f in findings]}
        print(json.dumps(doc, indent=2), file=out)
    else:
        for f in findings:
            print(f"{f.path}:{f.line}: [{f.rule}] {f.detail}", file=err)
        print(
            f"caddy_lint: {len(findings)} finding(s); {counts['caddy_configs']} Caddy configs "
            f"({counts['generated']} generated) in {counts['files']} files",
            file=out,
        )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
