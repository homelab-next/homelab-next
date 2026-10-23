#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: caddy-lint
#   kind: check
#   purpose: Fail when a Caddy config in the tree could let a client set its own identity header behind forward_auth, cannot be read, or a Caddy pin is below 2.11.2.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:caddy-lint]
#   invariant: [F-23]
#   inputs: the tracked tree (Caddyfiles, templates, markdown caddyfile blocks, registries, Dockerfiles, other pins), the caddy generator and tools/caddy_lint.allow.yml
#   outputs: one line per unprotected forward_auth, identity header set outside copy_headers, construct the lint cannot read, unread config, vulnerable Caddy pin or stale allowlist entry
#   exit:
#     "0": clean
#     "1": a finding (strip, reset, parse, coverage, generate, pin or a stale allowlist entry)
#     "2": usage error, a bad allowlist or a missing dependency
"""Gate: the edge never lets a client name its own identity to a service behind forward-auth.

``forward_auth`` copies the identity provider's answer (``copy_headers``) onto the request, and the
service trusts those headers. Caddy 2.9.0 to 2.11.1 keep a header the *client* sent when the
IdP's answer omits it, and every Caddy up to 2.11.1 passes the underscore and mixed spellings
(``X_Authentik_Groups``, ``X-Authentik_Groups``), which a CGI-style upstream folds into the real
header. (2.11.2's fix deletes only the exact name it copies; 2.11.7's ``reverse_proxy`` was
observed dropping every header with an ``_``, which is not a documented guarantee, so the strip
is what covers those spellings.) So these must hold, everywhere:

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
  pin        every Caddy pin is 2.11.2 or later, by semver (``v2.11.2`` is fine,
             ``2.11.2-rc.1`` is not, a floating ``2.11`` is not); each finding is reported on
             its own line, and an inline allow waives that line only:
             - YAML/JSON: a service with ``impl: caddy`` (its ``version``, missing included); a
               ``caddy_*version``/``_tag``/``_release`` key; a ``caddy_*image`` key; an ``image``
               or any string that is a tagged Caddy image; a split ``repository: caddy`` +
               ``tag``;
             - a Dockerfile: ``FROM`` and ``xcaddy build`` with ``ARG``/``ENV`` defaults
               resolved (an ``ARG`` without a default fails closed, since it could be Caddy);
             - Python: a dict literal with ``"impl": "caddy"`` (its ``version`` a literal);
             - any other text (``.env``, ``go.mod``, templates): an ``image:`` line, a tagged
               Caddy image, a ``caddy_*version`` assignment;
             - everywhere: ``xcaddy build``, a ``caddyserver/caddy/v2`` module requirement and a
               release download.
             A Caddy image is any image whose last path segment is ``caddy``, behind any
             registry or mirror prefix. An image whose last segment only starts with ``caddy``
             (a third-party build) carries its own version, so it needs a reviewed allow. A
             ``${VAR:-default}`` resolves to its default; a variable with none, or a template
             expression, cannot be checked and fails closed.

Which files: inside a git work tree, every file ``git ls-files`` reports (tracked, plus untracked
files that are not ignored); outside one, every file under ROOT but VCS metadata, caches and
virtualenvs, and the run says so. Caddy configs read: every ``Caddyfile*``, ``*.caddyfile*``,
``*.caddy`` and their ``.j2``/``.jinja``/``.tmpl``/``.tpl`` templates; every file one of them
imports; every markdown fence (```, ~~~, any length, any info string) tagged ``caddy`` or
``caddyfile`` or holding a ``forward_auth``; a Caddyfile embedded in a YAML/JSON string; and the
output of the ``caddy`` generator for every registry in the tree that loads (a registry that
does not load, such as a schema negative, is skipped, its pins still checked; a registry that
loads but the generator fails on is a ``generate`` finding).

  coverage   a file with a ``forward_auth`` in directive position (first on a line, in a string
             literal, after an escaped newline or a ``{``) that the lint did not read as a Caddy
             config (a ``.conf`` nothing imports, a ``.tmpl``, a Python string, an indented
             markdown code block) is a finding: the lint cannot vouch for what it does not read.

A reviewed exception is an inline ``caddy-lint: allow <reason>`` comment on the offending line, or
an entry in ``tools/caddy_lint.allow.yml`` (a ``path`` glob and a ``reason``) for a whole file;
an entry that excuses nothing is a finding.

Usage: python tools/caddy_lint.py [ROOT] [--allowlist FILE] [--json]
Exit: 0 clean, 1 a finding, 2 usage error, a bad allowlist or a missing dependency (PyYAML, or the
homelabnext package the generated configs need): could not measure.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

try:
    import yaml
except ImportError:  # reported by main() as exit 2, could not measure
    yaml = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

#: the first release whose forward_auth drops a client-sent header the IdP's answer omits
MIN_CADDY = (2, 11, 2)
MIN_CADDY_TEXT = ".".join(map(str, MIN_CADDY))
DEFAULT_ALLOWLIST = "tools/caddy_lint.allow.yml"
INLINE_ALLOW = re.compile(r"caddy-lint:\s*allow\s+\S")
GIT_LS_FILES = ("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".")
#: outside git: directories that never hold a config of the tree's own
WALK_SKIP = {".git", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
#: a Caddyfile by name: Caddyfile*, *.caddyfile*, *.caddy and its templates
CADDY_NAME = re.compile(r"(?i)((^|\.)caddyfile([.-]|$))|(\.caddy(\.(j2|jinja2?|tmpl|tpl))?$)")
FENCE_OPEN = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
FORWARD_AUTH = re.compile(r"(?<![\w-])forward_auth(?![\w-])")
#: ``forward_auth`` where a Caddyfile directive starts: first on its line, also inside a string
#: literal (``"\tforward_auth``, ``f"forward_auth``), after an escaped newline or after a ``{``
FORWARD_AUTH_LINE = re.compile(
    r"""(?m)(?:^[ \t]*(?:[rbfuRBFU]{0,2}["'`])?(?:\\[tn]|[ \t])*|\\n(?:\\t|[ \t])*|\{[ \t]*)"""
    r"forward_auth(?![\w-])"
)
#: a markdown line outside every fence that starts with the directive (an indented code block)
FORWARD_AUTH_BARE = re.compile(r"[ \t]*forward_auth(?![\w-])")
VERSION = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?P<pre>-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
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
    try:
        from homelabnext.generators.builtin import _forward_auth_snippet
    except ImportError as exc:
        raise MissingDependency(f"homelabnext ({exc})") from None

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


#: a named route (Caddy 2.8+): ``&(name) { ... }``, run by ``invoke name``; its directives run in
#: the order written, as a ``route``'s do
NAMED_ROUTE = re.compile(r"^&\((?P<name>[^()]+)\)$")


def _kind(node: Node) -> str:
    """What a top-level block is: the ``global`` options, a ``snippet`` definition, a ``named``
    route, or a ``site``; ``directive`` for a top-level line without a block."""
    if not node.block:
        return "directive"
    if not node.tokens:
        return "global"
    if len(node.tokens) == 1 and SNIPPET.match(node.name):
        return "snippet"
    if len(node.tokens) == 1 and NAMED_ROUTE.match(node.name):
        return "named"
    return "site"


def _covers_mark(pattern: str) -> bool:
    """Whether ``request_header -<pattern>`` deletes every header whose name contains
    ``authentik``, in any case and spelling: ``*authentik*``, or a shorter contains-wildcard."""
    p = pattern.lower()
    return p == "*" or (len(p) >= 2 and p[0] == p[-1] == "*" and p[1:-1] in "authentik")


def _check_auth(node: Node) -> list[Finding]:
    """One ``forward_auth``: no matcher, directly inside a ``route`` (or a named route), after
    a delete of every spelling of every header its ``copy_headers`` sets."""
    findings = []
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
    if route is None or not (route.name == "route" or _kind(route) == "named"):
        findings.append(
            Finding(where, line, "strip", "forward_auth is not directly inside a route block")
        )
        return findings
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
    return findings


def _site_strip(site: Node, direct: list[Node], names: list[str], label: str) -> list[Finding]:
    """A site that runs ``forward_auth`` anywhere deletes, at site level and with no matcher,
    every header carrying ``authentik`` and every spelling of every header a ``copy_headers``
    in it sets. Caddy sorts a site-level ``request_header`` before every ``handle`` and
    ``route``, so a path that never reaches the auth route (a ``handle /api/*`` beside it, a
    matcher on the route) cannot carry the client's identity headers to the upstream."""
    deletes = [
        n.tokens[1][1:]
        for n in direct
        if n.name == "request_header" and len(n.tokens) >= 2 and n.tokens[1].startswith("-")
    ]
    missing = [] if any(_covers_mark(p) for p in deletes) else ["*authentik*"]
    for h in names:
        if missing[:1] == ["*authentik*"] and "authentik" in h.lower():
            continue  # already named by the missing *authentik*
        missing += [
            sp
            for sp in spellings(h)
            if sp not in missing and not any(_covers(p, sp) for p in deletes)
        ]
    if not missing:
        return []
    return [
        Finding(
            site.path,
            site.line,
            "strip",
            f"site {label} runs forward_auth but has no matcherless site-level request_header "
            f"deleting {', '.join(missing)}: a handle, or a matcher on the auth route, sends a "
            "request past forward_auth with the client's identity headers (put "
            "request_header -*authentik* first in the site, as the generator does)",
        )
    ]


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
    named = {
        m.group("name"): c
        for c in root.children
        if _kind(c) == "named" and (m := NAMED_ROUTE.match(c.name))
    }
    # the sites (and named routes) of the file; top-level directives outside every block are
    # one more site (a Caddyfile with a single site and no braces, or a fragment)
    scopes: list[tuple[Node, str, list[Node], list[Node]]] = []
    loose = [c for c in root.children if _kind(c) == "directive"]
    if loose:
        scopes.append((loose[0], "(top level)", loose, loose))
    for c in root.children:
        if _kind(c) in ("site", "named"):
            label = " ".join(c.tokens) if _kind(c) == "site" else ""
            scopes.append((c, label, list(_walk(c)), c.children))
    copied: set[str] = set()
    auths = [n for n in _walk(root) if n.name == "forward_auth"]
    for node in auths:
        copied |= {_norm(h) for h in _copied(node)[0]}
    for node in auths:
        if not INLINE_ALLOW.search(node.raw):
            findings += _check_auth(node)
    for site, label, nodes, direct in scopes:
        if not label or INLINE_ALLOW.search(site.raw):
            continue  # a named route is checked where it is invoked
        invoked = [
            named[n.tokens[1]]
            for n in nodes
            if n.name == "invoke" and len(n.tokens) > 1 and n.tokens[1] in named
        ]
        site_auths = [n for n in nodes if n.name == "forward_auth"]
        site_auths += [n for r in invoked for n in _walk(r) if n.name == "forward_auth"]
        if not site_auths or all(INLINE_ALLOW.search(n.raw) for n in site_auths):
            continue
        names = list(dict.fromkeys(h for n in site_auths for h in _copied(n)[0]))
        findings += _site_strip(site, direct, names, label)
    findings += _resets(root, copied)
    return list(dict.fromkeys(findings))


# ---------------------------------------------------------------- pins

#: a key that pins a Caddy version: caddy_version, CADDY_VERSION, caddy_image_tag, caddy_release
CADDY_VERSION_KEY = re.compile(r"(?i)^caddy(?:_\w+?)?_(?:version|tag|release)$")
#: a key that names a Caddy image: caddy_image, CADDY_IMAGE, caddy_builder_image
CADDY_IMAGE_KEY = re.compile(r"(?i)^caddy(?:_\w+?)?_image$")
#: an image tag's variant: 2.11.7-alpine, 2.11.7-builder-alpine, 2.11.7-windowsservercore-ltsc2022
VARIANT = re.compile(r"(?i)-(?:alpine|builder|windowsservercore|nanoserver)(?:[-.].*)?$")
#: ``${NAME}``, ``${NAME:-default}`` (and ``-``, ``:=``, ``=``, ``:?``, ``?``, ``:+``, ``+``) or ``$NAME``
VARIABLE = re.compile(r"\$\{(?P<name>\w+)(?:(?P<op>:?[-=?+])(?P<default>[^}]*))?\}|\$(?P<bare>\w+)")
IMAGE_REF = re.compile(
    r"^(?P<name>[a-z0-9][\w.-]*(?::\d+)?(?:/[\w.-]+)*)(?::(?P<tag>\w[\w.-]*))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$",
    re.I,
)
#: a Caddy image reference in free text: the last path segment ``caddy`` or ``caddy-<word>``,
#: followed by a tag or a digest (a bare ``caddy`` in prose is a word, not an image)
TEXT_IMAGE = re.compile(
    r"(?i)(?<![\w./:@$-])(?P<ref>(?:[a-z0-9][\w.-]*(?::\d+)?/)*caddy(?:-[a-z0-9]+)*"
    r"(?::(?:\$\{[^}\s]*\}|\$\w+|\{\{[^}]*\}\}|[\w][\w.${}:-]*)|@sha256:[0-9a-f]{64})+)"
)
#: an ``image:`` line in a template or other text the YAML reader does not parse
TEXT_IMAGE_LINE = re.compile(r"""^\s*-?\s*["']?image["']?\s*:\s*(?P<value>\S.*?)\s*(?:#.*)?$""")
TEXT_KEY = re.compile(
    r"""(?i)(?<![\w.])(?P<key>caddy(?:_\w+?)?_(?:version|tag|release|image))\b["']?\s*[:=]\s*"""
    r"""["']?(?P<value>[^\s"',#]+)"""
)
#: other unambiguous Caddy pins: a build, a module requirement, a release download
TEXT_PINS = (
    # (a backticked `xcaddy build` is markdown prose naming the command, not a run of it)
    re.compile(r"\bxcaddy\s+build(?![`\w])(?:\s+(?P<v>v?\d\S*|\$\S+))?"),
    re.compile(r"github\.com/caddyserver/caddy/v2(?:@|\s+)(?P<v>v\S+)"),
    re.compile(r"caddyserver/caddy/releases/download/(?P<v>[^/\s]+)/"),
    re.compile(r"\bcaddy_(?P<v>\d[\w.+-]*?)_(?:linux|darwin|windows|freebsd|openbsd|netbsd)_"),
)


def version_ok(version: str) -> bool:
    """Whether a Caddy version is ``MIN_CADDY`` or later, by semver precedence: a ``v`` prefix is
    fine, a pre-release sorts before its release (2.11.2-beta.1 < 2.11.2 < 2.12.0-beta.1), and a
    floating 2.11 is whatever 2.11.x the pull finds."""
    m = VERSION.match(str(version).strip())
    if not m or m.group(3) is None:
        return False
    v = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return v > MIN_CADDY or (v == MIN_CADDY and not m.group("pre"))


def tag_ok(tag: str) -> bool:
    """A Caddy image tag: the version with its image variant (``-alpine``, ``-builder``) off."""
    return version_ok(VARIANT.sub("", tag))


def resolve(value: str, env: dict[str, str | None] | None = None) -> str | None:
    """``value`` with its ``${VAR}`` substituted from ``env`` or the expression's own default,
    or None when one cannot be (no value, no default, ``${VAR:?}``, a Jinja expression)."""
    env = env or {}
    missing = False

    def sub(m: re.Match[str]) -> str:
        nonlocal missing
        name = m.group("name") or m.group("bare")
        op, default = m.group("op") or "", m.group("default") or ""
        known = env.get(name)
        if known is not None and not (op.startswith(":") and known == "" and "-" in op):
            return known
        if op in (":-", "-", ":=", "="):
            return default
        missing = True
        return ""

    out = VARIABLE.sub(sub, value)
    return None if missing or "{{" in out or "{%" in out else out


def _tagged_caddy(value: str) -> bool:
    """A string that is, as a whole, a Caddy image reference with a tag or digest."""
    m = IMAGE_REF.match(value.strip())
    return bool(m and (m.group("tag") or m.group("digest")) and _caddy_kind(m.group("name")))


def _caddy_kind(name: str) -> str | None:
    last = name.rsplit("/", 1)[-1].lower()
    if last == "caddy":
        return "caddy"
    return "derived" if last.startswith("caddy") else None


class _Pins:
    """Collects ``pin`` findings for one file, each on its own line and waived only by an
    inline allow on that line."""

    def __init__(self, path: str, text: str):
        self.path, self.lines, self.findings = path, text.splitlines(), []

    def allowed(self, line: int) -> bool:
        return 0 < line <= len(self.lines) and bool(INLINE_ALLOW.search(self.lines[line - 1]))

    def add(self, line: int, detail: str) -> None:
        f = Finding(self.path, line, "pin", detail)
        if not self.allowed(line) and f not in self.findings:
            self.findings.append(f)

    def version(self, line: int, what: str, value: str, env=None) -> None:
        got = resolve(str(value), env)
        if got is None:
            self.add(line, f"{what} {value!r} cannot be resolved: pin {MIN_CADDY_TEXT} or later")
        elif not tag_ok(got):
            self.add(line, f"{what} {got!r}: pin {MIN_CADDY_TEXT} or later")

    def image(self, line: int, value: str, env=None, *, named: bool = False) -> None:
        """A container image reference; ``named`` when its key or position says it runs Caddy
        (an image under ``caddy_image``, a Dockerfile ``FROM``), so an unreadable one fails."""
        got = resolve(value.strip(), env)
        if got is None:
            if named or "caddy" in value.lower():
                self.add(line, f"image {value!r} cannot be resolved: pin a literal Caddy image")
            return
        m = IMAGE_REF.match(got.strip())
        kind = _caddy_kind(m.group("name")) if m else None
        if kind is None:
            if named and got.strip().lower() != "scratch":
                self.add(line, f"image {got!r} under a Caddy key is not the caddy image: "
                         "the lint cannot tell which Caddy it runs")  # fmt: skip
            return
        tag = m.group("tag")
        if kind == "derived":
            self.add(line, f"image {got!r} embeds Caddy and its tag is not Caddy's version: "
                     "check the Caddy it ships and allow it with a reason")  # fmt: skip
        elif tag is None:
            self.add(line, f"caddy image {got!r} without a version tag: pin {MIN_CADDY_TEXT} "
                     "or later")  # fmt: skip
        elif not tag_ok(tag):
            self.add(line, f"caddy image tag {tag!r}: pin {MIN_CADDY_TEXT} or later")

    def text(self, *, images: bool = True, keys: bool = True, xcaddy: bool = True) -> None:
        """The pins free text can carry, line by line: an image reference, a ``caddy_*version``
        style assignment, ``xcaddy build``, a Go module requirement, a release download."""
        for no, ln in enumerate(self.lines, 1):
            self.line(no, ln, images=images, keys=keys, xcaddy=xcaddy)

    def line(self, no: int, ln: str, *, images: bool, keys: bool, xcaddy: bool = True) -> None:
        if images:
            whole = TEXT_IMAGE_LINE.match(ln)
            if whole:
                self.image(no, whole.group("value").strip("\"'"))
            for m in TEXT_IMAGE.finditer(ln):
                self.image(no, m.group("ref"))
        if keys:
            for m in TEXT_KEY.finditer(ln):
                if m.group("key").lower().endswith("image"):
                    self.image(no, m.group("value"), named=True)
                else:
                    self.version(no, m.group("key"), m.group("value"))
        for i, rx in enumerate(TEXT_PINS):
            if i == 0 and not xcaddy:
                continue
            for m in rx.finditer(ln):
                v = m.group("v")
                if v is None:
                    self.add(no, "xcaddy build without a version builds whatever "
                             f"CADDY_VERSION says: pin {MIN_CADDY_TEXT} or later")  # fmt: skip
                else:
                    self.version(no, "caddy", v)


def lint_pins(text: str, path: str = "<text>") -> list[Finding]:
    """Caddy pins in a YAML/JSON document (every document, every nesting level), each reported
    on its own node's line: a registry service with ``impl: caddy`` (its ``version``), a
    ``caddy_*version``/``_tag``/``_release`` key, a ``caddy_*image`` key, an ``image`` (or any
    string that is a tagged Caddy image reference), a split ``repository: caddy`` + ``tag``, and
    in any string the free-text pins (``xcaddy build``, a release download)."""
    pins = _Pins(path, text)

    def line(node: yaml.Node) -> int:
        return node.start_mark.line + 1

    def scalar(node: yaml.Node | None) -> str | None:
        return str(node.value) if isinstance(node, yaml.ScalarNode) else None

    def walk(node: yaml.Node, key: str = "") -> None:
        if isinstance(node, yaml.MappingNode):
            pairs = [(scalar(k), k, v) for k, v in node.value]
            by = {k.lower(): (kn, v) for k, kn, v in pairs if k is not None}
            impl = by.get("impl")
            if impl and (scalar(impl[1]) or "").strip().lower() == "caddy":
                ver = by.get("version")
                if ver is None:
                    pins.add(line(impl[1]), f"service {key or '?'} (impl: caddy) has no version")
                else:
                    pins.version(line(ver[1]), f"service {key or '?'} caddy", scalar(ver[1]) or "")
            repo = by.get("repository")
            if repo and scalar(repo[1]) and _caddy_kind(scalar(repo[1]) or ""):
                tag = by.get("tag")
                ref = f"{scalar(repo[1])}:{scalar(tag[1])}" if tag else scalar(repo[1]) or ""
                pins.image(line(tag[1] if tag else repo[1]), ref, named=True)
            for k, _kn, v in pairs:
                if k is not None and isinstance(v, yaml.ScalarNode):
                    if CADDY_VERSION_KEY.match(k):
                        pins.version(line(v), k, v.value)
                    elif CADDY_IMAGE_KEY.match(k):
                        pins.image(line(v), v.value, named=True)
                        continue
                if k is None or k.lower() not in ("repository", "tag") or not repo:
                    walk(v, k or key)
        elif isinstance(node, yaml.SequenceNode):
            for v in node.value:
                walk(v, key)
        elif isinstance(node, yaml.ScalarNode) and isinstance(node.value, str):
            v = node.value
            if key.lower() == "image" or key.lower().endswith("_image") or _tagged_caddy(v):
                pins.image(line(node), v)

    for doc in yaml.compose_all(text, Loader=yaml.SafeLoader):
        if doc is not None:
            walk(doc)
    pins.text(images=False, keys=False)
    return pins.findings


def lint_dockerfile(text: str, path: str = "<text>") -> list[Finding]:
    """A Dockerfile: ``ARG``/``ENV`` defaults are resolved into ``FROM`` and ``xcaddy build``;
    a ``FROM`` that cannot be resolved (no default) fails closed, since it could be Caddy."""
    pins = _Pins(path, text)
    env: dict[str, str | None] = {}
    stages: set[str] = set()
    builder = False
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    for no, ln in enumerate(pins.lines, 1):
        if not buf:
            start = no
        if ln.rstrip().endswith("\\"):
            buf += ln.rstrip()[:-1] + " "
            continue
        logical.append((start, buf + ln))
        buf = ""
    if buf:
        logical.append((start, buf))
    for no, ln in logical:
        words = ln.split()
        if not words or words[0].startswith("#"):
            continue
        op = words[0].upper()
        if op in ("ARG", "ENV"):
            pairs = [w.split("=", 1) for w in words[1:]] if "=" in ln else [words[1:3]]
            for pair in pairs:
                name, value = pair[0], (pair[1].strip("\"'") if len(pair) > 1 else None)
                env[name] = resolve(value, env) if value is not None else env.get(name)
                if value is not None and CADDY_VERSION_KEY.match(name):
                    pins.version(no, name, value, env)
                elif value is not None and CADDY_IMAGE_KEY.match(name):
                    pins.image(no, value, env, named=True)
        elif op == "FROM":
            args = [w for w in words[1:] if not w.startswith("--")]
            if not args:
                continue
            got = resolve(args[0], env)
            if got is None:
                pins.add(no, f"FROM {args[0]} cannot be resolved (an ARG without a default): it "
                         "could be Caddy; give the ARG a default")  # fmt: skip
            elif got not in stages:
                pins.image(no, got)
            m = IMAGE_REF.match(got or "")
            builder = bool(
                m and _caddy_kind(m.group("name")) and "builder" in (m.group("tag") or "")
            )
            if len(args) >= 3 and args[1].lower() == "as":
                stages.add(args[2])
        elif op == "RUN":
            for m in TEXT_PINS[0].finditer(ln):
                v = m.group("v")
                if v is None:
                    if not (builder or env.get("CADDY_VERSION")):
                        pins.add(no, "xcaddy build without a version or CADDY_VERSION: pin "
                                 f"{MIN_CADDY_TEXT} or later")  # fmt: skip
                else:
                    pins.version(no, "xcaddy build", v, env)
    pins.text(images=False, keys=False, xcaddy=False)
    return pins.findings


def lint_python(text: str, path: str = "<text>") -> list[Finding]:
    """A registry built in Python (a dict literal with ``"impl": "caddy"``: its ``version``
    must be a literal 2.11.2 or later), a string that is a tagged Caddy image, and the
    free-text pins."""
    pins = _Pins(path, text)
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [Finding(path, exc.lineno or 0, "parse", "cannot parse: SyntaxError")]
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            kv = {
                k.value: v
                for k, v in zip(node.keys, node.values, strict=True)
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
            impl = kv.get("impl")
            if isinstance(impl, ast.Constant) and str(impl.value).lower() == "caddy":
                ver = kv.get("version")
                if isinstance(ver, ast.Constant) and isinstance(ver.value, str):
                    pins.version(ver.lineno, "a caddy service", ver.value)
                else:
                    pins.add(node.lineno, "a caddy service whose version is not a literal: pin "
                             f"{MIN_CADDY_TEXT} or later")  # fmt: skip
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _tagged_caddy(node.value):
                pins.image(node.lineno, node.value)
            for i, ln in enumerate(node.value.splitlines()):
                pins.line(node.lineno + i, ln, images=False, keys=False)
    return pins.findings


# ---------------------------------------------------------------- the tree


class MissingDependency(Exception):
    """PyYAML or the homelabnext package cannot be imported (exit 2: could not measure)."""


def _generated(text: str, rel: str) -> tuple[str | None, list[Finding]]:
    """The caddy generator's output for a registry document. A registry that does not load (a
    schema negative, an injection fixture) is skipped; a registry that loads but the generator
    fails on, or that yields no Caddy sites file, is a ``generate`` finding, never a quiet
    loss of coverage."""
    try:
        from homelabnext.generators import generate
        from homelabnext.registry.model import RegistryError, loads
    except ImportError as exc:
        raise MissingDependency(f"homelabnext ({exc})") from None
    try:
        reg = loads(text)
    except RegistryError:
        return None, []
    try:
        site = generate(reg, ["caddy"])["caddy"].get("caddy/sites.caddy")
    except Exception as exc:  # any failure of the generator is reported, not skipped
        return None, [
            Finding(rel, 0, "generate", f"the caddy generator failed: {exc.__class__.__name__}")
        ]
    if site is None:
        return None, [Finding(rel, 0, "generate", "the caddy generator wrote no sites.caddy")]
    return site, []


def _is_registry(text: str) -> bool:
    """One YAML document whose top level has ``registry_version`` and ``services``."""
    docs = [d for d in yaml.compose_all(text, Loader=yaml.SafeLoader) if d is not None]
    if len(docs) != 1 or not isinstance(docs[0], yaml.MappingNode):
        return False
    keys = {k.value for k, _ in docs[0].value if isinstance(k, yaml.ScalarNode)}
    return {"registry_version", "services"} <= keys


def _git_files(root: Path) -> list[str] | None:
    """The files under ``root`` git tracks or would track (``.gitignore`` respected), relative
    to ``root``; None outside a work tree or without git."""
    try:
        inside = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            check=False,
        )
        if inside.returncode != 0 or inside.stdout.strip() != b"true":
            return None
        out = subprocess.run(
            ["git", "-C", str(root), *GIT_LS_FILES],
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return sorted({n for n in out.stdout.decode("utf-8", "surrogateescape").split("\0") if n})


def _walk_files(root: Path) -> list[str]:
    """Outside git: every file under ``root`` but VCS metadata, caches and virtualenvs."""
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        parents = [root / Path(*rel.parts[: i + 1]) for i in range(len(rel.parts) - 1)]
        if any(part in WALK_SKIP for part in rel.parts) or any(
            (d / "pyvenv.cfg").is_file() for d in parents
        ):
            continue
        out.append(rel.as_posix())
    return out


def files(root: Path) -> tuple[list[tuple[Path, str]], str]:
    """The files to check and how they were found: ``git`` (tracked plus untracked-but-not-
    ignored) inside a work tree, else ``walk`` (every file; no ``.gitignore`` to honour)."""
    names = _git_files(root)
    how = "git"
    if names is None:
        names, how = _walk_files(root), "walk"
    out = []
    for rel in names:
        p = root / rel
        if p.is_file() and not p.is_symlink():
            out.append((p, rel))
    return out, how


def md_blocks(text: str) -> tuple[list[tuple[str, str, int]], list[tuple[int, str]]]:
    """Fenced blocks of a markdown file as ``(info, body, line offset)`` (``` and ~~~ fences of
    any length and indent, any info string), and the lines outside every fence."""
    lines = text.split("\n")
    blocks: list[tuple[str, str, int]] = []
    outside: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        m = FENCE_OPEN.match(lines[i])
        if m and not (m.group("fence")[0] == "`" and "`" in m.group("info")):
            fence, indent = m.group("fence"), len(m.group("indent"))
            close = re.compile(rf"^[ \t]*{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$")
            j = i + 1
            while j < len(lines) and not close.match(lines[j]):
                j += 1
            body = [re.sub(rf"^[ \t]{{0,{indent}}}", "", ln) for ln in lines[i + 1 : j]]
            blocks.append((m.group("info").strip(), "\n".join(body) + "\n", i + 1))
            i = j + 1
            continue
        outside.append((i + 1, lines[i]))
        i += 1
    return blocks, outside


def _yaml_caddy(text: str, rel: str, ctx: CaddyContext) -> tuple[list[Finding], int]:
    """A Caddyfile embedded in a YAML/JSON string (an Ansible ``copy: content:``): any string
    with a ``forward_auth`` that reads as a directive is linted as one."""
    findings: list[Finding] = []
    n = 0
    stack = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    while stack:
        node = stack.pop()
        if isinstance(node, yaml.MappingNode):
            stack += [v for _, v in node.value]
        elif isinstance(node, yaml.SequenceNode):
            stack += node.value
        elif isinstance(node, yaml.ScalarNode) and isinstance(node.value, str):
            v = node.value
            if FORWARD_AUTH_LINE.search(v) and ("{" in v or "\n" in v.strip()):
                n += 1
                offset = node.start_mark.line + (1 if node.style in ("|", ">") else 0)
                findings += lint_caddy(v, rel, offset, ctx=ctx)
    return findings, n


def scan(
    root: Path, allow: list[tuple[str, str]] | None = None
) -> tuple[list[Finding], dict[str, int | str]]:
    findings: list[Finding] = []
    counts: dict[str, int | str] = {"files": 0, "caddy_configs": 0, "generated": 0}
    ctx = CaddyContext(root)
    unread: list[tuple[str, int]] = []  # files with a forward_auth the lint did not read
    listed, counts["discovery"] = files(root)
    for p, rel in listed:
        name = p.name
        try:
            if CADDY_NAME.search(name):
                text = p.read_text(encoding="utf-8")
                counts["files"] += 1
                counts["caddy_configs"] += 1
                ctx.parsed.add(rel)
                findings += lint_caddy(text, rel, base=p.parent, ctx=ctx)
                continue
            if name == "Dockerfile" or name.startswith("Dockerfile.") or p.suffix == ".dockerfile":
                counts["files"] += 1
                findings += lint_dockerfile(p.read_text(encoding="utf-8"), rel)
                continue
            text = p.read_text(encoding="utf-8")
            low = text.lower()
            if "caddy" not in low and "forward_auth" not in low:
                continue
            counts["files"] += 1
            if p.suffix == ".md":
                blocks, outside = md_blocks(text)
                for info, body, offset in blocks:
                    lang = (info.split() or [""])[0].lower()
                    if lang in ("caddy", "caddyfile") or FORWARD_AUTH.search(body):
                        counts["caddy_configs"] += 1
                        findings += lint_caddy(body, rel, offset, ctx=ctx)
                unread += [(rel, no) for no, ln in outside if FORWARD_AUTH_BARE.match(ln)]
                pins = _Pins(rel, text)
                pins.text()
                findings += pins.findings
            elif p.suffix in (".yml", ".yaml", ".json"):
                findings += lint_pins(text, rel)
                found, n = _yaml_caddy(text, rel, ctx)
                findings += found
                counts["caddy_configs"] += n
                if _is_registry(text):
                    site, problems = _generated(text, rel)
                    findings += problems
                    if site is not None:
                        counts["generated"] += 1
                        counts["caddy_configs"] += 1
                        findings += lint_caddy(site, f"{rel} (caddy generator)", ctx=ctx)
            else:
                if p.suffix == ".py":
                    findings += lint_python(text, rel)
                else:
                    pins = _Pins(rel, text)
                    pins.text()
                    findings += pins.findings
                directive = FORWARD_AUTH_LINE.search(text)
                if directive:
                    unread.append((rel, text.count("\n", 0, directive.start()) + 1))
        except UnicodeDecodeError:
            if CADDY_NAME.search(name):
                findings.append(Finding(rel, 0, "parse", "cannot parse: UnicodeDecodeError"))
        except yaml.YAMLError as exc:
            findings.append(Finding(rel, 0, "parse", f"cannot parse: {exc.__class__.__name__}"))
    for rel, line in unread:
        if rel not in ctx.parsed:
            findings.append(
                Finding(
                    rel,
                    line,
                    "coverage",
                    "forward_auth in a file the lint does not read as a Caddy config: name it "
                    "Caddyfile or *.caddy, fence it in markdown, import it from a linted "
                    f"Caddyfile, or list it in {DEFAULT_ALLOWLIST} with the reason it is covered",
                )
            )
    return apply_allowlist(findings, allow or []), counts


class AllowlistError(Exception):
    """The allowlist file is malformed (exit 2)."""


def load_allowlist(path: Path | None) -> list[tuple[str, str]]:
    """``(path glob, reason)`` entries from ``tools/caddy_lint.allow.yml``."""
    if path is None or not path.is_file():
        return []
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AllowlistError(f"{path}: {exc.__class__.__name__}") from None
    entries = doc.get("allow", []) if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise AllowlistError(f"{path}: 'allow' must be a list")
    out = []
    for i, e in enumerate(entries):
        fields = e if isinstance(e, dict) else {}
        glob, why = (str(fields.get(k) or "").strip() for k in ("path", "reason"))
        problem = "needs a 'path' glob" if not glob else "has no 'reason'" if not why else ""
        if problem:
            raise AllowlistError(f"{path}: entry {i} {problem}")
        out.append((glob, why))
    return out


def apply_allowlist(findings: list[Finding], allow: list[tuple[str, str]]) -> list[Finding]:
    """The findings no entry excuses, plus one ``allowlist`` finding per entry that excuses
    nothing (a stale entry would silently waive the next real finding in that file)."""
    used: set[int] = set()
    kept = []
    for f in findings:
        rel = f.path.split(" (", 1)[0]
        hit = [i for i, (g, _) in enumerate(allow) if fnmatch.fnmatchcase(rel, g)]
        used.update(hit)
        if not hit:
            kept.append(f)
    for i, (g, _) in enumerate(allow):
        if i not in used:
            kept.append(Finding(DEFAULT_ALLOWLIST, 0, "allowlist", f"entry {g!r} excuses nothing"))
    return kept


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    parser = argparse.ArgumentParser(prog="caddy_lint", description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=".", help="the tree to check")
    parser.add_argument("--json", action="store_true", help="findings as JSON on stdout")
    parser.add_argument("--allowlist", help=f"default: <root>/{DEFAULT_ALLOWLIST}")
    try:
        opts = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    root = Path(opts.root).resolve()
    if not root.is_dir():
        print(f"caddy_lint: {root} is not a directory", file=err)
        return 2
    if yaml is None:
        print("caddy_lint: missing dependency: PyYAML", file=err)
        return 2
    allow_path = Path(opts.allowlist) if opts.allowlist else root / DEFAULT_ALLOWLIST
    if opts.allowlist and not allow_path.is_file():
        print(f"caddy_lint: allowlist {allow_path} not found", file=err)
        return 2
    try:
        allow = load_allowlist(allow_path)
    except AllowlistError as exc:
        print(f"caddy_lint: bad allowlist: {exc}", file=err)
        return 2
    try:
        findings, counts = scan(root, allow)
    except MissingDependency as exc:
        print(f"caddy_lint: missing dependency: {exc}", file=err)
        return 2
    if counts["discovery"] == "walk":
        print(
            f"caddy_lint: {root} is not a git work tree: reading every file under it "
            "(no .gitignore)",
            file=err,
        )
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
