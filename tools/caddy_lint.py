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
             same ``route`` a ``request_header -<name>`` (or a ``-*<part>*``, ``-<prefix>*`` or
             ``-*<suffix>`` wildcard, matched case-insensitively as Caddy does) deletes every
             header its ``copy_headers`` sets, in every spelling with ``-`` or ``_`` at each
             separator (a CGI-style upstream folds both, so ``X-Authentik_Groups`` is the real
             header too). (Outside a ``route``, Caddy's directive order runs
             ``forward_auth`` before ``request_header``, so the strip would delete the IdP's own
             headers instead of the client's.) A ``copy_headers`` that is itself templated
             cannot be checked and fails closed: list the headers literally. A
             ``forward_auth @matcher`` is a finding too: a request it skips is never
             authenticated.
  reset      no directive names an identity header (any name carrying ``authentik``, or any
             header a ``copy_headers`` sets, in any spelling) other than to delete it:
             ``request_header``/``header_up``/``header`` setting, adding or replacing one,
             before or after ``forward_auth``, in any route, or a placeholder copying one into
             another header. Only ``forward_auth``'s own ``copy_headers`` may set it.
  parse      the lint reads a Caddyfile with Caddy's own token rules and fails closed on what
             it cannot vouch for: a heredoc, a quoted token spanning lines, a ``{`` or ``}``
             sharing a line with a directive, a placeholder, ``{$ENV}`` or template in directive
             position, a line ending in ``\\``, unbalanced braces, and an ``import`` it cannot
             follow (a glob, a placeholder, a cycle, a file outside the tree; a snippet defined
             in the config, the generated ``hnx_forward_auth`` and a relative file are expanded
             in place, as Caddy does).
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
class Token:
    text: str
    line: int  # the line the token starts on (1-based, in its file)
    end: int  # the line it ends on (a quoted token or heredoc can span lines)
    quoted: bool = False


@dataclass
class Node:
    tokens: list[str]
    line: int
    path: str = "<text>"
    raw: str = ""  # the source line the node starts on, for an inline allow
    children: list[Node] = field(default_factory=list)
    parent: Node | None = None
    block: bool = False

    @property
    def name(self) -> str:
        return self.tokens[0] if self.tokens else ""

    def copy(self, parent: Node | None) -> Node:
        new = Node(list(self.tokens), self.line, self.path, self.raw, [], parent, self.block)
        new.children = [c.copy(new) for c in self.children]
        return new


# ---------------------------------------------------------------- Caddyfile


class _Lexer:
    """Caddy's own token rules (caddyconfig/caddyfile/lexer.go), so the tree below matches what
    Caddy builds: a quote opens a quoted token only at a token's start, ``#`` starts a comment
    only there, ``<<MARKER`` opens a heredoc, and a quoted token or heredoc may span lines.
    Every construct the line-based reading of a Caddyfile gets wrong is also reported, so the
    lint fails closed on it instead of trusting its own model."""

    def __init__(self, text: str, path: str, line_offset: int, problems: list[Finding]):
        self.text, self.path, self.offset, self.problems = text, path, line_offset, problems

    def problem(self, line: int, detail: str) -> None:
        self.problems.append(Finding(self.path, line, "parse", detail))

    def tokens(self) -> list[Token]:
        text, out, i, line, off = self.text, [], 0, 1, self.offset
        n = len(text)
        while i < n:
            c = text[i]
            if c == "\n":
                line += 1
                i += 1
                continue
            if c.isspace():
                i += 1
                continue
            if c == "#":
                while i < n and text[i] != "\n":
                    i += 1
                continue
            start = line
            if c in '"`':
                j, buf = i + 1, []
                while j < n and text[j] != c:
                    if c == '"' and text[j] == "\\" and j + 1 < n and text[j + 1] in '"\\':
                        buf.append(text[j + 1])
                        j += 2
                        continue
                    if text[j] == "\n":
                        line += 1
                    buf.append(text[j])
                    j += 1
                if j >= n:
                    self.problem(start + off, "a quoted token is never closed")
                elif line != start:
                    self.problem(start + off, "a quoted token spans lines")
                out.append(Token("".join(buf), start + off, line + off, quoted=True))
                i = j + 1
                continue
            j = i
            while j < n and not text[j].isspace():
                j += 2 if text[j] == "\\" and j + 1 < n and not text[j + 1].isspace() else 1
            tok = text[i:j]
            i = j
            if tok.endswith("\\") and (i >= n or text[i] == "\n"):
                self.problem(start + off, "a line ends in \\ (a continued line)")
            if tok.startswith("<<") and len(tok) > 2:
                body, i, line = self._heredoc(tok[2:], i, line)
                out.append(Token(body, start + off, line + off, quoted=True))
                continue
            out.append(Token(tok, start + off, line + off))
        return out

    def _heredoc(self, marker: str, i: int, line: int) -> tuple[str, int, int]:
        start = line
        self.problem(start + self.offset, f"a heredoc (<<{marker}) hides lines from the lint")
        nl = self.text.find("\n", i)
        if nl < 0:
            return "", len(self.text), line
        pos, line = nl + 1, line + 1
        while pos <= len(self.text):
            end = self.text.find("\n", pos)
            end = len(self.text) if end < 0 else end
            if self.text[pos:end].strip() == marker:
                return self.text[nl + 1 : pos], end, line
            pos, line = end + 1, line + 1
        self.problem(start + self.offset, f"the heredoc <<{marker} is never closed")
        return self.text[nl + 1 :], len(self.text), line


def parse_caddyfile(
    text: str, path: str = "<text>", line_offset: int = 0
) -> tuple[Node, list[Finding]]:
    """The block tree Caddy builds from ``text`` (one node per directive line; a ``{`` opens a
    block, a ``}`` closes it) and a ``parse`` finding for every construct the lint cannot vouch
    for: a heredoc, a quoted token spanning lines, a ``{`` or ``}`` that shares its line, a
    placeholder or template in directive position, an unbalanced brace."""
    problems: list[Finding] = []
    raw_lines = text.splitlines()
    toks = _Lexer(text, path, line_offset, problems).tokens()

    def raw(line: int) -> str:
        i = line - line_offset - 1
        return raw_lines[i] if 0 <= i < len(raw_lines) else ""

    def problem(line: int, detail: str) -> None:
        problems.append(Finding(path, line, "parse", detail))

    # one group per directive line: Caddy reads a token as the line's next argument when it
    # starts on the line the previous token ended on
    groups: list[list[Token]] = []
    for t in toks:
        if groups and t.line == groups[-1][-1].end:
            groups[-1].append(t)
        else:
            groups.append([t])

    root = Node([], 0, path)
    cur = root

    def add(pending: list[Token], anchor: Token, opens: bool) -> Node:
        """Append the directive ``pending`` to ``cur``; the node a ``{`` opens is the new cur."""
        node = Node([t.text for t in pending], anchor.line, path, raw(anchor.line), [], cur)
        node.block = opens
        first = pending[0] if pending else None
        hidden = first is not None and not first.quoted and first.text.startswith("{")
        if hidden and not (cur is root and opens):  # a site address may be {$SITE}
            problem(anchor.line, f"{first.text} in directive position hides a directive")
        cur.children.append(node)
        return node if opens else cur

    for g in groups:
        delims = [i for i, t in enumerate(g) if not t.quoted and t.text in "{}"]
        alone_close = len(g) == 1 and g[0].text == "}" and not g[0].quoted
        trailing_open = delims == [len(g) - 1] and g[-1].text == "{"
        if delims and not (alone_close or trailing_open):
            problem(g[0].line, "a { or } shares its line with a directive")
        lone_open = len(g) == 1 and g[0].text == "{" and not g[0].quoted
        if lone_open and (cur is not root or root.children):  # only the global options block
            problem(g[0].line, "a { on a line of its own")
        pending: list[Token] = []
        for t in g:
            if not t.quoted and t.text == "{":
                cur = add(pending, pending[0] if pending else t, True)
                pending = []
            elif not t.quoted and t.text == "}":
                if pending:
                    cur = add(pending, pending[0], False)
                    pending = []
                if cur is root:
                    problem(t.line, "a } closes no block")
                else:
                    cur = cur.parent or root
            else:
                pending.append(t)
        if pending:
            cur = add(pending, pending[0], False)
    if cur is not root:
        problem(cur.line, "a block is never closed")
    return root, problems


def _walk(node: Node):
    for c in node.children:
        yield c
        yield from _walk(c)


SNIPPET = re.compile(r"^\((?P<name>[^()]+)\)$")
GLOB = re.compile(r"[*?\[{]")


@dataclass
class CaddyContext:
    """Where ``import <file>`` may resolve: files under ``tree`` (relative to the importing
    file's directory); ``parsed`` collects every file read, for the coverage check."""

    tree: Path | None = None
    parsed: set[str] = field(default_factory=set)
    depth: int = 0


def _external_snippet(name: str) -> Node | None:
    """A snippet this repository generates, imported by a config that does not define it (a
    documented example importing ``hnx_forward_auth``)."""
    if name != "hnx_forward_auth":
        return None
    from homelabnext.generators.builtin import _forward_auth_snippet

    root, _ = parse_caddyfile(_forward_auth_snippet("idp:9443"), "<generated hnx_forward_auth>")
    return root.children[0]


def _expand(root: Node, base: Path | None, ctx: CaddyContext, problems: list[Finding]) -> None:
    """Replace every ``import`` with what it imports, as Caddy does: a snippet defined in this
    config, a generated snippet, or a file under the tree (no glob). Anything else is a
    ``parse`` finding: the lint cannot see what it would add."""
    snippets = {
        m.group("name"): c for c in root.children if c.block and (m := SNIPPET.match(c.name))
    }

    def resolve(node: Node) -> list[Node] | None:
        target = node.tokens[1] if len(node.tokens) > 1 else ""
        if target in snippets:
            return snippets[target].children
        external = _external_snippet(target)
        if external is not None:
            return external.children
        if not target or GLOB.search(target):
            return None
        if base is None or ctx.tree is None:
            return None
        f = (base / target).resolve()
        try:
            rel = f.relative_to(ctx.tree).as_posix()
        except ValueError:
            return None
        if not f.is_file() or ctx.depth > 8:
            return None
        sub = CaddyContext(ctx.tree, ctx.parsed, ctx.depth + 1)
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        ctx.parsed.add(rel)
        sub_root, sub_problems = parse_caddyfile(text, rel)
        problems.extend(sub_problems)
        _expand(sub_root, f.parent, sub, problems)
        return sub_root.children

    def expand(nodes: list[Node], parent: Node, depth: int) -> list[Node]:
        out: list[Node] = []
        for c in nodes:
            if c.name != "import" or c.block:
                c.children = expand(c.children, c, depth)
                out.append(c)
                continue
            got = resolve(c) if depth < 16 else None
            if got is None:
                target = c.tokens[1] if len(c.tokens) > 1 else ""
                problems.append(
                    Finding(
                        c.path,
                        c.line,
                        "parse",
                        f"import {target} cannot be followed (a glob, a placeholder, a cycle or no "
                        "such file under the tree): the lint cannot see what it adds",
                    )
                )
                continue
            out += expand([g.copy(parent) for g in got], parent, depth + 1)
        return out

    root.children = expand(root.children, root, 0)


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
    """Whether Caddy's ``request_header -<pattern>`` deletes ``header``: case-insensitive, with a
    ``*x*`` (contains), ``x*`` (prefix) or ``*x`` (suffix) wildcard; any other ``*`` is literal."""
    p, h = pattern.lower(), header.lower()
    if len(p) >= 2 and p.startswith("*") and p.endswith("*"):
        return p[1:-1] in h
    if p.endswith("*"):
        return h.startswith(p[:-1])
    if p.startswith("*"):
        return h.endswith(p[1:])
    return p == h


def spellings(header: str) -> list[str]:
    """Every way to spell ``header`` with ``-`` or ``_`` at each separator (2**k for k of them):
    a CGI-style upstream folds both into the same ``HTTP_X_..._...`` variable."""
    parts = re.split(r"[-_]", header)
    out = [parts[0]]
    for part in parts[1:]:
        out = [f"{o}{sep}{part}" for o in out for sep in "-_"]
    return out


#: a header name that carries the identity provider's mark (``X-Authentik-Groups``,
#: ``x_authentik_username``, ``*authentik*``), but not a word that merely contains it
AUTH_NAME = re.compile(r"(?i)(?<![a-z0-9])(?:[a-z0-9]+[-_])*\*?authentik(?:[-_*][a-z0-9*]*)*")
HEADER_WORD = re.compile(r"[A-Za-z0-9_-]+")
#: directives whose ``-<field>`` deletes a header
HEADER_DIRECTIVES = {"request_header", "header", "header_up", "header_down"}


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


def _is_delete(node: Node, tok: str) -> bool:
    owner = node if node.name in HEADER_DIRECTIVES else node.parent
    return tok.startswith("-") and owner is not None and owner.name in HEADER_DIRECTIVES


def _in_forward_auth_copy(node: Node) -> bool:
    """``forward_auth`` itself, or its ``copy_headers`` (the one place the identity is set)."""
    if node.name == "forward_auth":
        return True
    n: Node | None = node
    while n is not None:
        if n.name == "copy_headers" and n.parent is not None and n.parent.name == "forward_auth":
            return True
        n = n.parent
    return False


def _resets(root: Node, copied: set[str]) -> list[Finding]:
    """Every directive that names an identity header other than to delete it: a later
    ``request_header``/``header_up``/``header`` setting, adding or replacing one, or a
    placeholder copying one into another header. Each would let a client choose the value
    the service trusts, whatever the strip before ``forward_auth`` did."""
    out = []
    for node in _walk(root):
        if _in_forward_auth_copy(node) or INLINE_ALLOW.search(node.raw):
            continue
        for tok in node.tokens:
            if _is_delete(node, tok):
                continue
            hits = [m.group(0) for m in AUTH_NAME.finditer(tok)]
            hits += [w for w in HEADER_WORD.findall(tok) if _norm(w.lstrip("-")) in copied]
            if hits:
                parent = node.parent
                label = parent.name if parent and parent.name in HEADER_DIRECTIVES else node.name
                out.append(
                    Finding(
                        node.path,
                        node.line,
                        "reset",
                        f"{label} names the identity header {hits[0]} other than to delete "
                        "it: only forward_auth's copy_headers may set it",
                    )
                )
                break
    return out


def lint_caddy(
    text: str,
    path: str = "<text>",
    line_offset: int = 0,
    base: Path | None = None,
    ctx: CaddyContext | None = None,
) -> list[Finding]:
    ctx = ctx or CaddyContext()
    root, findings = parse_caddyfile(text, path, line_offset)
    _expand(root, base, ctx, findings)
    auths = [n for n in _walk(root) if n.name == "forward_auth"]
    copied: set[str] = set()
    for node in auths:
        copied |= {_norm(h) for h in _copied(node)[0]}
    for node in auths:
        if INLINE_ALLOW.search(node.raw):
            continue
        line, where = node.line, node.path
        if len(node.tokens) > 1 and node.tokens[1].startswith(("@", "/")):
            findings.append(
                Finding(
                    where,
                    line,
                    "strip",
                    f"forward_auth {node.tokens[1]}: a request its matcher skips is never "
                    "authenticated",
                )
            )
        route = node.parent
        if route is None or route.name != "route":
            findings.append(
                Finding(where, line, "strip", "forward_auth is not directly inside a route block")
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
                    where,
                    templated,
                    "strip",
                    "copy_headers is templated, so its strip cannot be checked: list the headers",
                )
            )
        for h in names:
            missed = [sp for sp in spellings(h) if not any(_covers(p, sp) for p in deleted)]
            if missed:
                findings.append(
                    Finding(
                        where,
                        line,
                        "strip",
                        f"client-sent {h} is not deleted before forward_auth in the same route "
                        f"in every spelling (missed: {', '.join(missed)})",
                    )
                )
    findings += _resets(root, copied)
    return list(dict.fromkeys(findings))


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
    ctx = CaddyContext(root)
    for p, rel in _files(root):
        name = p.name
        try:
            if CADDY_NAME.search(name):
                text = p.read_text(encoding="utf-8")
                counts["files"] += 1
                counts["caddy_configs"] += 1
                findings += lint_caddy(text, rel, base=p.parent, ctx=ctx)
            elif p.suffix == ".md":
                text = p.read_text(encoding="utf-8")
                blocks = list(MD_FENCE.finditer(text))
                if blocks:
                    counts["files"] += 1
                for m in blocks:
                    counts["caddy_configs"] += 1
                    offset = text.count("\n", 0, m.start(1))
                    findings += lint_caddy(m.group(1), rel, offset, ctx=ctx)
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
                        findings += lint_caddy(site, f"{rel} (caddy generator)", ctx=ctx)
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
