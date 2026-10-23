#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: caddy-lint
#   kind: check
#   purpose: Fail when a Caddy config in the tree could let a client set its own identity header behind forward_auth (judged on the Caddyfile text and, with a caddy binary, on Caddy's own adapted JSON), cannot be read, or a Caddy pin is below 2.11.2.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:caddy-lint]
#   invariant: [F-23]
#   inputs: the tracked tree (Caddyfiles, templates, markdown caddyfile blocks, Caddy JSON/YAML, registries, Dockerfiles, other pins), the caddy generator, tools/caddy_lint.allow.yml and a caddy binary when one is available (required in CI)
#   outputs: one line per unprotected forward_auth or site, identity header set outside copy_headers, construct the lint cannot read, unread config, path Caddy's own JSON shows reaching an upstream unstripped, vulnerable Caddy pin or stale allowlist rule
#   exit:
#     "0": clean
#     "1": a finding (strip, reset, dial, exposure, parse, coverage, generate, semantic, pin or allowlist)
#     "2": usage error, a bad allowlist or a missing dependency (a caddy binary when HNX_CADDY_REQUIRED is set)
"""Gate: the edge never lets a client name its own identity to a service behind forward-auth.

``forward_auth`` copies the identity provider's answer (``copy_headers``) onto the request, and the
service trusts those headers. Caddy 2.9.0 to 2.11.1 keep a header the *client* sent when the
IdP's answer omits it, and every Caddy up to 2.11.1 passes the underscore and mixed spellings
(``X_Authentik_Groups``, ``X-Authentik_Groups``), which a CGI-style upstream folds into the real
header. (2.11.2's fix deletes only the exact name it copies; 2.11.7's ``reverse_proxy`` was
observed dropping every header with an ``_``, which is not a documented guarantee, so the strip
is what covers those spellings.)

Threat model. The lint stops ACCIDENTAL misconfiguration that lets a client set its own identity:
a config, in the Caddyfiles and Caddy JSON/YAML of the tree, that Caddy accepts and that delivers
a client-chosen identity (or the IdP's identity to a client-chosen host) to an upstream. The
authors of Caddy configs are trusted and their changes reviewed; a deliberate bypass written to
evade the lint (a directive name assembled from pieces, a value smuggled through the deploy
environment) is out of scope and left to review. Where a construct is risky, the lint refuses
it rather than modelling it. Known non-goals: the operator's environment (``{$VAR}``, read as
unset by the semantic check and assumed to expand to one token, so a value that opens a block
is not seen), plugins the lint does not know (refused in a forward-auth server when Caddy's own
JSON is judged), a config deployed from outside the tree, services published by another proxy
or port than this Caddy (the registry-driven front-door guarantee, that every human-facing
service is reachable only through the authed front door, is the front-door work's job, Rule 1,
not this lint's), and the pin forms listed under ``pin`` as not read.

So these must hold, everywhere:

  strip      every site that runs ``forward_auth`` (directly, or through ``invoke`` of a named
             route) deletes at site level, with no matcher, every header carrying ``authentik``
             and every header its ``copy_headers`` set, in every spelling
             (``request_header -*authentik*`` first in the site, as the generator writes it):
             Caddy sorts a site-level ``request_header`` before every ``handle`` and ``route``,
             so a path that never reaches the auth route (a ``handle /api/*`` beside it, a
             matcher on the route) cannot carry the client's identity headers either. And every
             ``forward_auth`` sits directly inside a ``route`` block, and earlier in that same
             ``route`` a ``request_header -<name>`` (or a ``-*<part>*``, ``-<prefix>*`` or
             ``-*<suffix>`` wildcard, matched case-insensitively as Caddy does; any other ``*``
             is literal) deletes every header its ``copy_headers`` sets, in every spelling with
             ``-`` or ``_`` at each separator. (Outside a ``route``, Caddy's directive order runs
             ``forward_auth`` before ``request_header``, so the strip would delete the IdP's own
             headers instead of the client's; a named route ``&(name)`` is not a route: Caddy
             2.11.1 and 2.11.7 adapt only its first directive.) A templated ``copy_headers``
             fails closed, and so does a ``forward_auth @matcher``: a request it skips is never
             authenticated.
  reset      no header directive sets, adds or replaces an identity header (a field name carrying
             ``authentik``, or one a ``copy_headers`` of the same site sets, in any spelling),
             and none copies one into another header through a header placeholder
             (``{http.request.header.*}``, ``{header.*}``, ``{http.reverse_proxy.header.*}``,
             ``{rp.header.*}``): ``request_header``/``header`` after an optional matcher,
             ``header_up``/``header_down``, a ``header`` block line. Only ``forward_auth``'s own
             ``copy_headers`` may set it. Only header field names and header placeholders are
             judged: a site address, an upstream host or a matcher named after the IdP is not a
             header. A snippet definition is judged where it is imported, never where it is
             defined. A field name with a ``*`` (Caddy's every-header ``*``, a wildcard) that can
             match an identity header, set or replaced from a placeholder value
             (``header_up * alice {http.request.header.X-Evil}``), rewrites the IdP's own
             headers and is a ``reset`` too, and so is a FastCGI ``env`` (``transport fastcgi``,
             ``php_fastcgi``) that sets an identity variable (``HTTP_<identity header>``,
             ``REMOTE_USER``, ``AUTH_*`` and the other CGI user variables) or sets any variable
             from a value the client chooses: Caddy builds the CGI environment from ``env``
             first, so a name no request header carries keeps the ``env`` value.
  dial       a ``forward_auth`` whose upstream is a placeholder the request chooses (the client
             picks the IdP that vouches for it), and any proxy of a site that runs
             ``forward_auth`` whose upstream (argument, ``to``, ``dynamic``) is one (the IdP's
             identity headers go to a host the client picks). An operator's ``{$VAR}`` or
             ``{env.VAR}`` is not the client's.
  exposure   an upstream that a site proxies behind ``forward_auth``, proxied again by a site
             with no ``forward_auth`` (another host, another listener, a path-scoped block of
             the same host, which Caddy orders first): a client reaches the same service there
             with its own identity headers. The IdP's own upstream (a ``forward_auth`` dial) is
             exempt. Meant-to-be-public cases take an allowlist entry with
             ``rules: [exposure]`` and a reason.
  parse      the lint reads a Caddyfile with Caddy's own token rules and fails closed on what
             it cannot vouch for: a heredoc, a quoted token spanning lines, a ``{`` or ``}``
             sharing a line with a directive, a placeholder, ``{$ENV}`` or template in directive
             position, a header field name that is not literal (a placeholder, an environment
             variable, a request value: it could name an identity header), a line ending in
             ``\\``, unbalanced braces, a global ``order`` option moving a directive these rules
             rely on, and an ``import`` it cannot follow (a glob, a placeholder, a cycle, a
             snippet not defined above it, a file outside the tree, an argument that is itself a
             placeholder, an argument range or an index past the arguments given). A snippet, the
             generated ``hnx_forward_auth`` and a relative file are expanded in place, as Caddy
             does: arguments substituted (``{args[N]}``), and an import's block put where the
             snippet says ``{block}``.
  semantic   Caddy's own reading, when a ``caddy`` binary is available (``--caddy``,
             ``$HNX_CADDY`` or PATH; CI pins one and sets ``HNX_CADDY_REQUIRED=1``, which makes
             a run without it exit 2): every Caddyfile read (but a template, which Caddy reads
             once rendered) goes through ``caddy adapt`` with an empty environment, and its JSON
             is judged in the order Caddy runs it. In a server with a forward-auth (a
             ``reverse_proxy`` with ``handle_response``), every ``reverse_proxy`` a request
             reaches, the auth one included, is reached with every header carrying ``authentik``
             and every spelling of every copied header deleted on every path (a route with a
             matcher, or in a ``handle`` group, may not run; an upstream's own ``header_up``
             delete counts for it; ``handle_errors`` starts from what its site deleted first;
             ``invoke`` follows a named route; ``handle_response`` bodies, the subroutes and
             named routes they run, and ``intercept``'s are judged, ``intercept`` being no
             pass-through); a host-matched site with no forward-auth of its own is not held to
             it, but serving a forward-auth site's upstream there is ``exposure``. A
             forward-auth is a ``reverse_proxy`` whose ``handle_response`` copies a header of
             the answer onto the request; a ``handle_response`` that serves a file
             (X-Accel-Redirect) is not one. A wildcard field, a placeholder dial and a FastCGI
             ``env`` are judged in the JSON as in the text. Anywhere, a header set, added or replaced whose
             name is not literal, carries ``authentik`` or is a copied one, or that copies one
             through a placeholder, is a finding (``reset`` or ``semantic``), but in the auth
             answer's own ``handle_response``, from the answer's headers. An unknown handler in
             a forward-auth server fails closed. Caddy refusing a Caddyfile is a finding; a
             markdown example it refuses is left to the text rules. With the check required, a
             Caddyfile it cannot read (a template: ``{{``, ``{%`` or ``${`` outside comments, or
             a template file name) is a finding. Caddy JSON in the tree (and
             the same structure in YAML) is judged the same way with no binary needed.
             Without a binary the run says so and the text rules alone judge the Caddyfiles:
             they do not see the handler order Caddy builds beyond the default directive order
             they model, nor what a plugin directive does to headers.
  pin        every Caddy pin is 2.11.2 or later, by semver (``v2.11.2`` is fine,
             ``2.11.2-rc.1`` is not, a floating ``2.11`` is not); each finding is reported on
             its own line, and an inline allow waives that line only:
             - YAML/JSON: a service with ``impl: caddy`` (its ``version``, missing included); a
               ``caddy_*version``/``_tag``/``_release`` key; a ``caddy_*image`` key; an ``image``
               or any string that is a tagged Caddy image; a split ``repository: caddy`` +
               ``tag``;
             - a Dockerfile: ``FROM``, ``COPY``/``ADD --from`` and ``RUN --mount=from=`` images,
               and ``xcaddy build`` (shell or exec form, quoted, with a ``CADDY_VERSION=`` set
               on the command; a branch name is not a version), with ``ARG``/``ENV`` defaults
               resolved and the ``# escape=`` directive honoured (an ``ARG`` without a default
               fails closed, since it could be Caddy); ``caddy=<version>`` package pins;
             - Python: a dict literal with ``"impl": "caddy"`` (its ``version`` a literal);
             - any other text (``.env``, ``go.mod``, templates): an ``image:`` line, a tagged
               Caddy image, a ``caddy_*version`` assignment;
             - everywhere: ``xcaddy build``, a ``caddyserver/caddy/v2`` module requirement, a
               release download and a ``caddy=<version>`` package.
             A Caddy image is any image whose last path segment is ``caddy``, behind any
             registry or mirror prefix. An image whose last segment only starts with ``caddy``
             (a third-party build) carries its own version, so it needs a reviewed allow. A
             ``${VAR:-default}`` resolves to its default, nested defaults included; a variable
             with none, a template expression or a ``$`` left over cannot be checked and fails
             closed. Not read: a compose ``build.args`` override of a generically named ``ARG``,
             and a tag paired with a digest of another release (the digest is not resolvable
             offline).

Which files: inside a git work tree, every file ``git ls-files`` reports (tracked, plus untracked
files that are not ignored); outside one, every file under ROOT but VCS metadata, caches and
virtualenvs, and the run says so. Caddy configs read: every ``Caddyfile*``, ``*.caddyfile*``,
``*.caddy`` and their ``.j2``/``.jinja``/``.tmpl``/``.tpl`` templates; every file one of them
imports; every markdown fence (```, ~~~, any length, any info string) tagged ``caddy`` or
``caddyfile`` or holding a ``forward_auth``; a Caddyfile embedded in a YAML/JSON string; Caddy
JSON/YAML (``apps.http.servers``); and the output of the ``caddy`` generator for every registry
in the tree that loads (a registry that does not load, such as a schema negative, is skipped,
its pins still checked; a registry that loads but the generator fails on is a ``generate``
finding).

  coverage   a file with a ``forward_auth`` in directive position (first on a line, in a string
             literal, a list item or argument with the directive's argument, after an escaped
             newline or a ``{``) that the lint did not read as a Caddy config (a ``.conf``
             nothing imports, a ``.tmpl``, a Python string, an indented markdown code block), and
             a Caddy JSON handler outside a full config, are findings: the lint cannot vouch for
             what it does not read.

A reviewed exception is an inline ``caddy-lint: allow <reason>`` comment on the offending line, or
an entry in ``tools/caddy_lint.allow.yml``: a ``path`` (one file, or a glob that names no Caddy
config; never bare ``*``/``**``), the ``rules`` it excuses there and a ``reason``. A rule of an
entry that excuses nothing is a finding.

Usage: python tools/caddy_lint.py [ROOT] [--allowlist FILE] [--caddy BINARY] [--json]
Exit: 0 clean, 1 a finding, 2 usage error, a bad allowlist or a missing dependency (PyYAML, the
homelabnext package the generated configs need, or a caddy binary when ``HNX_CADDY_REQUIRED``
is set): could not measure.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
#: the caddy binary for the semantic check (``caddy adapt``), and the flag CI sets to require it
CADDY_ENV, CADDY_REQUIRED_ENV = "HNX_CADDY", "HNX_CADDY_REQUIRED"
INLINE_ALLOW = re.compile(r"caddy-lint:\s*allow\s+\S")
GIT_LS_FILES = ("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".")
#: outside git: directories that never hold a config of the tree's own
WALK_SKIP = {".git", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
#: a Caddyfile by name: Caddyfile*, *.caddyfile*, *.caddy and its templates
CADDY_NAME = re.compile(r"(?i)((^|\.)caddyfile([.-]|$))|(\.caddy(\.(j2|jinja2?|tmpl|tpl))?$)")
FENCE_OPEN = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
FORWARD_AUTH = re.compile(r"(?<![\w-])forward_auth(?![\w-])")
#: ``forward_auth`` where a Caddyfile directive starts: first on its line, also inside a string
#: literal (``"\tforward_auth``, ``f"forward_auth``), a string that is an item of a list or an
#: argument with the directive's own argument (``[..., "forward_auth idp:9443 {"``, not a
#: ``startswith("forward_auth ")``), after an escaped newline or after a ``{``
FORWARD_AUTH_LINE = re.compile(
    r"""(?m)(?:(?:^[ \t]*(?:[rbfuRBFU]{0,2}["'`])?(?:\\[tn]|[ \t])*|\\n(?:\\t|[ \t])*|\{[ \t]*)"""
    r"forward_auth(?![\w-]))"
    r"""|(?:[,(\[][ \t]*[rbfuRBFU]{0,2}["'`](?:\\[tn]|[ \t])*forward_auth[ \t]+[^\s"'`])"""
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
        if hidden and first.text == "{block}" and len(pending) == 1 and not opens:
            top = cur
            while top.parent is not None and top.parent is not root:
                top = top.parent
            hidden = not SNIPPET.match(top.name)  # an import's block lands here (Caddy 2.9+)
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
    imported: set[str] = field(default_factory=set)  # files only ever read through an import


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


#: an import argument in a snippet or imported file: ``{args[0]}`` (and the older ``{args.0}``)
ARG_REF = re.compile(r"\{args(?:\[(?P<i>\d+)\]|\.(?P<j>\d+))\}")


class _Refused(Exception):
    """An import the lint will not expand: what it would add cannot be known."""


def _substitute(nodes: list[Node], imp: Node) -> list[Node]:
    """``nodes`` (copies of what ``imp`` imports) with its arguments substituted and ``{block}``
    replaced by the import's own block, as Caddy does. An argument that is itself a placeholder,
    an index past the arguments given, or an argument range is refused: the expanded tokens (a
    header name, say) would not be literal."""
    args = imp.tokens[2:]

    def tok(t: str) -> str:
        def one(m: re.Match[str]) -> str:
            k = int(m.group("i") or m.group("j"))
            if k >= len(args):
                raise _Refused(f"{m.group(0)} is past the {len(args)} argument(s) given")
            if "{" in args[k] or "}" in args[k]:
                raise _Refused(f"argument {args[k]} is a placeholder, not a literal")
            return args[k]

        out = ARG_REF.sub(one, t)
        if "{args" in out:
            raise _Refused(f"{t} cannot be substituted (an argument range)")
        return out

    def walk(level: list[Node], parent: Node) -> list[Node]:
        out: list[Node] = []
        for n in level:
            if n.tokens == ["{block}"] and not n.block:
                out += [b.copy(parent) for b in imp.children]
                continue
            n.tokens = [tok(t) for t in n.tokens]
            n.children = walk(n.children, n)
            out.append(n)
        return out

    return walk(nodes, nodes[0].parent if nodes else imp)


def _expand(root: Node, base: Path | None, ctx: CaddyContext, problems: list[Finding]) -> None:
    """Replace every ``import`` with what it imports, as Caddy does: a snippet defined earlier
    in this config (Caddy refuses one used before its definition), a generated snippet, or a
    file under the tree (no glob), with its arguments substituted and its block put where the
    snippet says ``{block}``. Anything else is a ``parse`` finding: the lint cannot see what it
    would add."""
    snippets: dict[str, Node] = {}

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
        sub = CaddyContext(ctx.tree, ctx.parsed, ctx.depth + 1, ctx.imported)
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        ctx.parsed.add(rel)
        ctx.imported.add(rel)
        sub_root, sub_problems = parse_caddyfile(text, rel)
        problems.extend(sub_problems)
        _expand(sub_root, f.parent, sub, problems)
        return sub_root.children

    def expand(nodes: list[Node], parent: Node, depth: int) -> list[Node]:
        out: list[Node] = []
        for c in nodes:
            if parent is root and _kind(c) == "snippet":
                snippets[SNIPPET.match(c.name).group("name")] = c  # type: ignore[union-attr]
                out.append(c)  # judged where it is imported, so not expanded here
                continue
            if c.name != "import":
                c.children = expand(c.children, c, depth)
                out.append(c)
                continue
            target = c.tokens[1] if len(c.tokens) > 1 else ""
            got = resolve(c) if depth < 16 else None
            if got is None:
                problems.append(
                    Finding(
                        c.path,
                        c.line,
                        "parse",
                        f"import {target} cannot be followed (a glob, a placeholder, a cycle, a "
                        "snippet not defined above it, or no such file under the tree): the lint "
                        "cannot see what it adds",
                    )
                )
                continue
            try:
                copies = _substitute([g.copy(parent) for g in got], c)
            except _Refused as exc:
                problems.append(Finding(c.path, c.line, "parse", f"import {target}: {exc}"))
                continue
            out += expand(copies, parent, depth + 1)
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


#: a placeholder that reads a request header: ``{http.request.header.X}``, its ``{header.X}``
#: shorthand, and the ``{http.reverse_proxy.header.X}`` / ``{rp.header.X}`` of a proxied answer
HEADER_PLACEHOLDER = re.compile(
    r"(?i)\{(?:http\.request\.header|header|http\.reverse_proxy\.header|rp\.header)\.(?P<name>[^{}]+)\}"
)
#: directives whose arguments name a header field (and ``-<field>`` deletes it)
HEADER_DIRECTIVES = {"request_header", "header", "header_up", "header_down"}


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


#: a placeholder whose value the request (and so the client) can choose: any but the operator's
#: environment (``{$VAR}`` at load time, ``{env.VAR}`` at run time)
CLIENT_PLACEHOLDER = re.compile(r"\{(?!\$|env\.)[^{}]*\}")
#: the CGI variables an upstream reads as the authenticated user, besides ``HTTP_<header>``
CGI_IDENTITY = {
    "REMOTE_USER", "REMOTE_IDENT", "AUTH_TYPE", "AUTH_USER", "AUTH_PASSWORD", "LOGON_USER",
    "PHP_AUTH_USER", "PHP_AUTH_PW", "PHP_AUTH_DIGEST", "REDIRECT_REMOTE_USER",
}  # fmt: skip
#: a sample identity header, to ask whether a wildcard field name matches one
SAMPLE_IDENTITY = "X-Authentik-Username"


def _wild_identity(field_: str, copied: set[str]) -> bool:
    """Whether a field name with a ``*`` (Caddy's every-header ``*``, or a wildcard) can name an
    identity header: the IdP's, or one a ``copy_headers`` of the scope sets."""
    return "*" in field_ and (
        _covers(field_, SAMPLE_IDENTITY) or any(_covers(field_, c) for c in copied)
    )


def cgi_identity(name: str, copied: set[str]) -> bool:
    """Whether a FastCGI ``env`` name is an identity variable: ``HTTP_<header>`` for an identity
    header (``_`` read as a separator), ``REMOTE_USER`` and the other CGI user variables, or
    any ``AUTH_*``."""
    n = name.upper()
    if n.startswith("HTTP_"):
        h = n[5:]
        return "AUTHENTIK" in h or _norm(h) in copied
    return n in CGI_IDENTITY or n.startswith("AUTH_")


def _dial(token: str) -> str:
    """An upstream as Caddy dials it: no scheme, no trailing slash, lower case."""
    return re.sub(r"^[a-z0-9+.-]+://", "", token.lower()).rstrip("/")


def _upstreams(node: Node) -> list[str]:
    """The upstream tokens of a ``reverse_proxy``/``forward_auth``/``php_fastcgi``: its
    arguments after an optional matcher, its ``to`` lines and its ``dynamic`` block."""
    args = node.tokens[1:]
    if args and (args[0].startswith(("@", "/")) or args[0] == "*"):
        args = args[1:]
    out = list(args)
    for c in node.children:
        if c.name == "to":
            out += c.tokens[1:]
        elif c.name == "dynamic":
            out += c.tokens[1:] + [t for g in c.children for t in g.tokens]
    return out


PROXIES = ("reverse_proxy", "php_fastcgi")


def _in_matcher(node: Node) -> bool:
    """Inside a named matcher (``@name ...`` or its block): a ``header`` there matches a
    request, it does not set one."""
    n: Node | None = node
    while n is not None:
        if n.name.startswith("@"):
            return True
        n = n.parent
    return False


def _header_args(node: Node) -> tuple[str, list[str]] | None:
    """``(directive, [field, value...])`` when ``node`` sets, adds, replaces or deletes a header:
    ``request_header``/``header`` after an optional matcher, ``header_up``/``header_down``, or a
    line of a ``header`` block. None for anything else (a site address, an upstream, a
    matcher), which never names a header the upstream receives."""
    if _in_matcher(node):
        return None
    if node.name in ("request_header", "header"):
        args = node.tokens[1:]
        if args and (args[0].startswith(("@", "/")) or args[0] == "*"):
            args = args[1:]
        return node.name, args
    if node.name in ("header_up", "header_down"):
        return node.name, node.tokens[1:]
    parent = node.parent
    if parent is not None and parent.name == "header" and node.name not in ("defer", "match"):
        return "header", node.tokens
    return None


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


def _resets(nodes: list[Node], copied: set[str]) -> list[Finding]:
    """Every header directive that sets, adds or replaces an identity header (a field name
    carrying ``authentik`` or one a ``copy_headers`` of the same site sets, in any spelling), or
    copies one into another header through a placeholder. Each would let a client choose the
    value the service trusts, whatever the strip before ``forward_auth`` did. Only header field
    names and header placeholders are judged: a site address, an upstream host or a matcher
    named after the IdP is not a header."""

    def identity(name: str) -> bool:
        return "authentik" in name.lower() or _norm(name) in copied

    out = []
    for node in nodes:
        if _in_forward_auth_copy(node) or INLINE_ALLOW.search(node.raw):
            continue
        got = _header_args(node)
        if not got or not got[1] or got[1][0].startswith("-"):
            continue  # nothing named, or a delete
        label, (field, *values) = got[0], got[1]
        bare = field.lstrip("+?>")
        if "{" in bare or "}" in bare:
            out.append(
                Finding(
                    node.path,
                    node.line,
                    "parse",
                    f"{label} {field}: a header name taken from a placeholder (an environment "
                    "variable, an import argument, a request value) can name an identity header, "
                    "and the lint cannot tell which: write the name literally",
                )
            )
            continue
        if (
            label in ("request_header", "header_up")
            and _wild_identity(bare, copied)
            and any("{" in v for v in values)
        ):
            out.append(
                Finding(
                    node.path,
                    node.line,
                    "reset",
                    f"{label} {field} with a placeholder value rewrites every header the field "
                    "matches, the identity headers the IdP set included: name the header",
                )
            )
            continue
        hits = [bare] if identity(bare) else []
        hits += [
            m.group("name")
            for v in values
            for m in HEADER_PLACEHOLDER.finditer(v)
            if identity(m.group("name"))
        ]
        if hits:
            out.append(
                Finding(
                    node.path,
                    node.line,
                    "reset",
                    f"{label} names the identity header {hits[0]} other than to delete "
                    "it: only forward_auth's copy_headers may set it",
                )
            )
    return out


#: a named route (Caddy 2.8+): ``&(name) { ... }``, run by ``invoke name``. It is not a ``route``:
#: Caddy 2.11.1 and 2.11.7 adapt only its first directive (observed), so a strip and a
#: ``forward_auth`` belong in a ``route`` block inside it
NAMED_ROUTE = re.compile(r"^&\((?P<name>[^()]+)\)$")


#: the directives whose default order the strip rules rely on
ORDER_MODELED = {"request_header", "forward_auth", "route", "handle", "handle_path", "header"}


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
    """One ``forward_auth``: no matcher, directly inside a ``route``, after
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
    if route is None or route.name != "route":
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


def _fastcgi_env(nodes: list[Node], copied: set[str]) -> list[Finding]:
    """A FastCGI ``env`` (``transport fastcgi``, ``php_fastcgi``) is the CGI environment the
    upstream reads, where an identity header arrives as ``HTTP_<NAME>`` and the user as
    ``REMOTE_USER``. Caddy sets ``env`` first and the request headers after, so a name no
    header of the request carries keeps its ``env`` value: an identity variable set here, or
    any variable set from a value the client chooses, is a ``reset``."""
    out = []
    for n in nodes:
        p = n.parent
        fastcgi = p is not None and (
            p.name == "php_fastcgi" or (p.name == "transport" and p.tokens[1:2] == ["fastcgi"])
        )
        if n.name != "env" or not fastcgi or len(n.tokens) < 2 or INLINE_ALLOW.search(n.raw):
            continue
        name, values = n.tokens[1], n.tokens[2:]
        if cgi_identity(name, copied) or any(CLIENT_PLACEHOLDER.search(v) for v in values):
            out.append(
                Finding(
                    n.path,
                    n.line,
                    "reset",
                    f"fastcgi env {name}: an identity variable, or one set from a value the client "
                    "chooses, reaches the upstream as if the edge had set it",
                )
            )
    return out


def _dials(nodes: list[Node], auth_site: bool) -> list[Finding]:
    """An upstream the client can choose: a request placeholder in a ``forward_auth`` dial (the
    client picks the IdP that vouches for it), or in any proxy of a site that runs
    ``forward_auth`` (the IdP's identity headers go to a host the client picks)."""
    out = []
    for n in nodes:
        if n.name != "forward_auth" and not (auth_site and n.name in PROXIES):
            continue
        if INLINE_ALLOW.search(n.raw):
            continue
        bad = [t for t in _upstreams(n) if CLIENT_PLACEHOLDER.search(t)]
        if bad:
            out.append(
                Finding(
                    n.path,
                    n.line,
                    "dial",
                    f"{n.name} dials {bad[0]}, a value the request chooses: the client picks "
                    + (
                        "the identity provider"
                        if n.name == "forward_auth"
                        else "where the identity headers go"
                    )
                    + "; dial a fixed host (an operator {$VAR} is fine)",
                )
            )
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
    named = {
        m.group("name"): c
        for c in root.children
        if _kind(c) == "named" and (m := NAMED_ROUTE.match(c.name))
    }
    # what is judged: each site, each named route, and the top-level directives outside every
    # block (a Caddyfile with one site and no braces, or a fragment). A snippet definition is
    # judged where it is imported (its expanded copy), never where it is defined: Caddy
    # ignores an unused snippet, and a definition has no site around it.
    scopes: list[tuple[Node, str, list[Node], list[Node]]] = []
    loose = [c for c in root.children if _kind(c) == "directive"]
    if loose:
        scopes.append((loose[0], "(top level)", loose, loose))
    for c in root.children:
        if _kind(c) in ("site", "named"):
            label = " ".join(c.tokens) if _kind(c) == "site" else ""
            scopes.append((c, label, list(_walk(c)), c.children))
    for c in root.children:
        if _kind(c) != "global":
            continue
        for n in _walk(c):
            moved = [t for t in n.tokens[1:] if t in ORDER_MODELED]
            if n.name == "order" and moved:
                findings.append(
                    Finding(
                        n.path,
                        n.line,
                        "parse",
                        f"the global order option moves {moved[0]}: the lint reads directives in "
                        "Caddy's default order",
                    )
                )
    for site, label, nodes, direct in scopes:
        invoked = [
            named[n.tokens[1]]
            for n in nodes
            if n.name == "invoke" and len(n.tokens) > 1 and n.tokens[1] in named
        ]
        own = [n for n in nodes if n.name == "forward_auth"]
        site_auths = own + [n for r in invoked for n in _walk(r) if n.name == "forward_auth"]
        # the headers this site's forward_auth sets: identity headers here, not in other sites
        names = list(dict.fromkeys(h for n in site_auths for h in _copied(n)[0]))
        for node in own:
            if not INLINE_ALLOW.search(node.raw):
                findings += _check_auth(node)
        if (
            label  # a named route is checked where it is invoked
            and site_auths
            and not INLINE_ALLOW.search(site.raw)
            and not all(INLINE_ALLOW.search(n.raw) for n in site_auths)
        ):
            findings += _site_strip(site, direct, names, label)
        copied = {_norm(h) for h in names}
        findings += _resets(nodes, copied)
        findings += _fastcgi_env(nodes, copied)
        findings += _dials(nodes, bool(site_auths))
    findings += _exposure(scopes, named)
    return list(dict.fromkeys(findings))


def _exposure(scopes: list, named: dict) -> list[Finding]:
    """An upstream a site serves behind ``forward_auth``, served again by a site (another host,
    or another listener) with no ``forward_auth``: a client reaches the same service there with
    its own identity headers. The IdP's own dials (a ``forward_auth`` upstream) are exempt,
    since the IdP's site and the outpost passthrough serve them without auth by design."""
    protected: dict[str, str] = {}
    idp: set[str] = set()
    plain: list[tuple[Node, str]] = []
    for _site, label, nodes, _direct in scopes:
        if not label:
            continue  # a named route counts where it is invoked
        invoked = [
            named[n.tokens[1]]
            for n in nodes
            if n.name == "invoke" and len(n.tokens) > 1 and n.tokens[1] in named
        ]
        reach = nodes + [n for r in invoked for n in _walk(r)]
        authed = any(n.name == "forward_auth" for n in reach)
        for n in reach:
            if n.name == "forward_auth":
                idp |= {_dial(t) for t in _upstreams(n)}
            elif n.name in PROXIES:
                for t in _upstreams(n):
                    if authed:
                        protected.setdefault(_dial(t), label)
                    else:
                        plain.append((n, _dial(t)))
    out = []
    for n, dial in plain:
        # a path-scoped block of the auth site's own host counts too: Caddy 2.11.7 orders it
        # before the host's site (it is more specific), so its paths never reach forward_auth
        if dial in protected and dial not in idp and not INLINE_ALLOW.search(n.raw):
            out.append(
                Finding(
                    n.path,
                    n.line,
                    "exposure",
                    f"{n.name} {dial} serves, with no forward_auth, the upstream site "
                    f"{protected[dial]} puts behind forward_auth: a client reaches it here with "
                    "its own identity headers (list it with rules: [exposure] and a reason if it "
                    "is meant to be public)",
                )
            )
    return out


# ---------------------------------------------------------------- Caddy's own JSON

#: handlers that pass the request on with its headers as they are
JSON_PASS = {
    "vars", "rewrite", "encode", "request_body", "map", "templates", "push", "tracing",
    "metrics", "log_append", "authentication", "copy_response_headers",
}  # fmt: skip
#: handlers that answer the request themselves: nothing after them runs
JSON_END = {"static_response", "file_server", "error", "copy_response", "acme_server"}
#: a forward-auth copy: a header set to exactly the auth answer's own header
RP_HEADER_VALUE = re.compile(r"(?i)^\{(?:http\.reverse_proxy|rp)\.header\.[^{}]+\}$")
MARK = "*authentik*"  # the requirement "every header carrying authentik is deleted"


def _covers_key(pattern: str, key: str) -> bool:
    return _covers_mark(pattern) if key == MARK else _covers(pattern, key)


def _copies(rp: dict) -> list[str]:
    """The request headers a reverse_proxy's ``handle_response`` sets from the proxied answer's
    own headers: what Caddy's ``forward_auth`` ``copy_headers`` adapts to."""
    out: list[str] = []
    stack: list = [rp.get("handle_response")]
    while stack:
        x = stack.pop()
        if isinstance(x, list):
            stack += x
        elif isinstance(x, dict):
            if x.get("handler") == "headers" and isinstance(x.get("request"), dict):
                for f, vals in (x["request"].get("set") or {}).items():
                    if (
                        isinstance(vals, list)
                        and vals
                        and all(RP_HEADER_VALUE.match(str(v)) for v in vals)
                    ):
                        out.append(f)
            stack += [v for v in x.values() if isinstance(v, (list, dict))]
    return out


def _is_auth(h: object) -> bool:
    """A forward-auth: a ``reverse_proxy`` whose ``handle_response`` copies a header of the
    proxied answer onto the request (what ``copy_headers`` adapts to). A ``handle_response``
    that serves a file (X-Accel-Redirect) or rewrites the answer is not one."""
    return (
        isinstance(h, dict)
        and h.get("handler") == "reverse_proxy"
        and bool(h.get("handle_response"))
        and bool(_copies(h))
    )


def _proxy_dials(h: dict) -> list[str]:
    """Every string a ``reverse_proxy`` dials: its static upstreams and its dynamic ones."""
    out = [str(u.get("dial", "")).lower() for u in h.get("upstreams") or [] if isinstance(u, dict)]
    dyn = h.get("dynamic_upstreams")
    if isinstance(dyn, dict):
        out += [str(v) for v in dyn.values() if isinstance(v, (str, int))]
    return out


def _contains_auth(x: object, named: dict) -> bool:
    if _is_auth(x):
        return True
    if isinstance(x, dict):
        if x.get("handler") == "invoke" and x.get("name") in named:
            return _contains_auth(named[x["name"]], {})
        return any(_contains_auth(v, named) for v in x.values())
    if isinstance(x, list):
        return any(_contains_auth(v, named) for v in x)
    return False


class _Judge:
    """Caddy's own JSON for one server, judged in the order Caddy runs it. A request walks the
    routes in order; a route with a matcher (or in a ``handle`` group) may or may not run, so a
    header is known deleted after it only when it is deleted on both ways. In a server with a
    ``forward_auth`` (a ``reverse_proxy`` with ``handle_response``), every ``reverse_proxy`` a
    request reaches, the auth one included, must be reached with every header carrying
    ``authentik`` and every spelling of every copied header deleted first; a host-matched
    terminal site with no auth in it (the IdP's own site) is not held to that. Anywhere, a
    header set, added or replaced whose name is not literal, carries ``authentik`` or is a
    copied one, or that copies such a header through a placeholder, is a finding; only the auth
    answer's own ``handle_response`` may set those, from the answer's headers."""

    def __init__(self, server: str, srv: dict, protected: frozenset = frozenset()):
        self.server, self.srv, self.out = server, srv, []
        self.protected = protected  # upstreams some site of the config puts behind forward_auth
        self.named = srv.get("named_routes") if isinstance(srv.get("named_routes"), dict) else {}
        everything = [srv.get("routes"), (srv.get("errors") or {}).get("routes"), self.named]
        self.everything = everything
        self.auth = _contains_auth(everything, self.named)
        self.depth = 0
        self.use(everything)

    def use(self, scope: object) -> None:
        """The identity headers of ``scope``: what its forward_auths copy (a site's own, or the
        whole server's for routes no host matcher keeps apart)."""
        copied: list[str] = []
        stack: list = [scope]
        while stack:
            x = stack.pop()
            if _is_auth(x):
                copied += _copies(x)
            if isinstance(x, dict):
                if x.get("handler") == "invoke" and x.get("name") in self.named:
                    stack.append(self.named[x["name"]])
                stack += [v for v in x.values() if isinstance(v, (list, dict))]
            elif isinstance(x, list):
                stack += x
        copied = list(dict.fromkeys(copied))
        self.idents = {_norm(c) for c in copied}
        self.keys = {MARK} | {sp.lower() for c in copied for sp in spellings(c)}

    def site(self, r: dict) -> None:
        self.use(r if r.get("match") and r.get("terminal") else self.everything)

    def add(self, rule: str, where: str, detail: str) -> None:
        self.out.append((rule, f"{self.server} {where}: {detail}"))

    def run(self) -> list[tuple[str, str]]:
        primary = self.srv.get("routes") if isinstance(self.srv.get("routes"), list) else []
        st: frozenset | None = frozenset()
        for i, r in enumerate(primary):
            if st is None:
                break
            if isinstance(r, dict):
                self.site(r)
                st = self.route(r, st, self.in_scope(r), f"routes[{i}]")
        # handle_errors runs on the same request after the site's own routes failed: whatever
        # the site deleted before anything else (its site-level strip) is already gone
        errors = (self.srv.get("errors") or {}).get("routes")
        for i, r in enumerate(errors if isinstance(errors, list) else []):
            if isinstance(r, dict):
                same = [
                    p for p in primary if isinstance(p, dict) and p.get("match") == r.get("match")
                ]
                starts = [self.prefix(p) for p in (same or primary) if isinstance(p, dict)]
                start = frozenset.intersection(*starts) if starts else frozenset()
                scope = (
                    self.auth and any(_contains_auth(p, self.named) for p in same)
                    if same
                    else self.in_scope(r)
                )
                self.site(same[0] if same else r)
                self.route(r, start, scope, f"errors[{i}]")
        return self.out

    def in_scope(self, r: dict) -> bool:
        """A site with no forward_auth of its own beside one that has it (the IdP's site)."""
        other_site = r.get("match") and r.get("terminal") and not _contains_auth(r, self.named)
        return self.auth and not other_site

    def prefix(self, r: dict) -> frozenset:
        """What a route deletes before anything else it does (headers handlers first in it,
        or first in its subroute's first unconditional route)."""
        st: frozenset = frozenset()
        for h in r.get("handle") or []:
            if not isinstance(h, dict):
                break
            if h.get("handler") == "headers":
                st = self.deleted(h.get("request"), st)
            elif h.get("handler") == "subroute":
                for sub in h.get("routes") or []:
                    if (
                        not isinstance(sub, dict)
                        or sub.get("match")
                        or sub.get("group") is not None
                    ):
                        break
                    got = self.prefix(sub)
                    st |= got
                    if any(not isinstance(x, dict) or x.get("handler") != "headers"
                           for x in sub.get("handle") or []):  # fmt: skip
                        break
                break
            else:
                break
        return st

    def routes(self, rs: object, st: frozenset, scope: bool, loc: str) -> frozenset | None:
        cur: frozenset | None = st
        for i, r in enumerate(rs if isinstance(rs, list) else []):
            if cur is None:
                return None
            if isinstance(r, dict):
                cur = self.route(r, cur, scope, f"{loc}/routes[{i}]")
        return cur

    def route(self, r: dict, st: frozenset, scope: bool, loc: str) -> frozenset | None:
        out: frozenset | None = st
        for j, h in enumerate(r.get("handle") or []):
            if out is None:
                break
            out = self.handler(h, out, scope, f"{loc}/handle[{j}]")
        maybe = bool(r.get("match")) or r.get("group") is not None
        if r.get("terminal"):
            return st if maybe else None
        if not maybe:
            return out
        return st if out is None else st & out

    def handler(self, h: object, st: frozenset, scope: bool, loc: str) -> frozenset | None:
        if not isinstance(h, dict):
            return st
        kind = h.get("handler")
        if kind == "subroute":
            errors = (h.get("errors") or {}).get("routes")
            if errors:
                self.routes(errors, st, scope, f"{loc}/errors")
            return self.routes(h.get("routes"), st, scope, loc)
        if kind == "headers":
            return self.headers(h.get("request"), st, loc, copy=False)
        if kind == "intercept":
            # its handle_response routes run on the request as it is here, after the upstream
            # answered: judged like any other routes; the request then goes on unchanged
            for k, resp in enumerate(h.get("handle_response") or []):
                if isinstance(resp, dict):
                    self.routes(resp.get("routes"), st, scope, f"{loc}/handle_response[{k}]")
            return st
        if kind == "reverse_proxy":
            request = (h.get("headers") or {}).get("request")
            self.fastcgi(h, loc)
            bad = [d for d in _proxy_dials(h) if CLIENT_PLACEHOLDER.search(d)]
            if bad and (scope or _is_auth(h)):
                self.add("dial", loc, f"reverse_proxy dials {bad[0]}, a value the request "
                         "chooses: the client picks " + ("the identity provider" if _is_auth(h)
                         else "where the identity headers go"))  # fmt: skip
            if _is_auth(h):
                copied = {sp.lower() for c in _copies(h) for sp in spellings(c)}
                if scope:
                    self.require(st, {MARK} | copied, loc, "forward_auth")
                self.headers(request, None, loc, copy=False)  # the auth request's own header_up
                for k, resp in enumerate(h.get("handle_response") or []):
                    if isinstance(resp, dict):
                        self.depth += 1
                        self.copy_routes(resp.get("routes"), f"{loc}/handle_response[{k}]")
                        self.depth -= 1
                return st
            local = self.headers(request, st, loc, copy=False)
            if scope:
                self.require(local, self.keys, loc, "the upstream")
            if not scope and self.protected:
                for d in _proxy_dials(h):
                    if d in self.protected:
                        self.add("exposure", loc, f"reverse_proxy {d} serves, with no "
                                 "forward_auth, an upstream another site puts behind "
                                 "forward_auth: a client reaches it here with its own identity "
                                 "headers")  # fmt: skip
            # a handle_response that is not a forward-auth runs after the upstream answered
            for k, resp in enumerate(h.get("handle_response") or []):
                if isinstance(resp, dict):
                    self.routes(resp.get("routes"), local or st, scope,
                                f"{loc}/handle_response[{k}]")  # fmt: skip
            return None
        if kind == "invoke":
            name = h.get("name")
            if name not in self.named or self.depth > 16:
                self.add("semantic", loc, f"invoke {name!r}: no such named route")
                return st
            self.depth += 1
            got = self.route(self.named[name], st, scope, f"named_routes[{name}]")
            self.depth -= 1
            return got
        if kind in JSON_PASS:
            return st
        if kind in JSON_END:
            return None
        if scope:
            self.add("semantic", loc, f"handler {kind!r} is not one the lint knows: it cannot "
                     "tell what it does to the request's headers")  # fmt: skip
        return st

    def copy_routes(self, rs: object, loc: str) -> None:
        """A forward_auth's ``handle_response``: the one place an identity header is set, and
        only from the auth answer's own headers. Every handler in it is judged, through
        ``subroute`` and ``invoke`` too."""
        if self.depth > 16:
            self.add("semantic", loc, "handle_response nests too deep (a cycle)")
            return
        for i, r in enumerate(rs if isinstance(rs, list) else []):
            for j, h in enumerate((r.get("handle") or []) if isinstance(r, dict) else []):
                here = f"{loc}/routes[{i}]/handle[{j}]"
                if not isinstance(h, dict):
                    continue
                kind = h.get("handler")
                self.depth += 1
                if kind == "headers":
                    self.headers(h.get("request"), None, here, True)
                elif kind == "subroute":
                    self.copy_routes(h.get("routes"), here)
                elif kind == "invoke" and h.get("name") in self.named:
                    self.copy_routes([self.named[h["name"]]], f"named_routes[{h['name']}]")
                elif kind not in JSON_PASS and kind not in JSON_END and kind != "vars":
                    self.handler(h, frozenset(), True, here)
                self.depth -= 1

    def headers(self, ops: object, st: frozenset | None, loc: str, copy: bool) -> frozenset | None:
        if not isinstance(ops, dict):
            return st
        for kind in ("add", "set", "replace"):
            for field_, vals in (ops.get(kind) or {}).items():
                values = [v.get("replace", "") if isinstance(v, dict) else str(v)
                          for v in (vals if isinstance(vals, list) else [vals])]  # fmt: skip
                self.judge_set(kind, str(field_), values, loc, copy and kind == "set")
        return None if st is None else self.deleted(ops, st)

    def deleted(self, ops: object, st: frozenset) -> frozenset:
        """``st`` plus what a headers handler's request ``delete`` covers."""
        deletes = [str(d) for d in ((ops.get("delete") if isinstance(ops, dict) else None) or [])]
        return st | {k for k in self.keys if any(_covers_key(p, k) for p in deletes)}

    def judge_set(self, kind: str, field_: str, values: list[str], loc: str, copy: bool) -> None:
        if "{" in field_ or "}" in field_:
            self.add("semantic", loc, f"headers {kind} {field_}: a header name taken from a "
                     "placeholder can name an identity header")  # fmt: skip
            return

        def identity(name: str) -> bool:
            return "authentik" in name.lower() or _norm(name) in self.idents

        if _wild_identity(field_, self.idents) and any("{" in v for v in values):
            self.add("reset", loc, f"headers {kind} {field_} with a placeholder value rewrites "
                     "every header it matches, the identity headers the IdP set included")  # fmt: skip
            return
        if identity(field_) and not (
            copy and values and all(RP_HEADER_VALUE.match(v) for v in values)
        ):
            self.add("reset", loc, f"headers {kind} sets the identity header {field_}: only "
                     "forward_auth's copy_headers may set it")  # fmt: skip
            return
        for v in values:
            for m in HEADER_PLACEHOLDER.finditer(v):
                if identity(m.group("name")) and not (copy and RP_HEADER_VALUE.match(v)):
                    self.add("reset", loc, f"headers {kind} {field_} copies the identity header "
                             f"{m.group('name')}")  # fmt: skip
                    return

    def fastcgi(self, h: dict, loc: str) -> None:
        """A FastCGI transport's ``env`` is the CGI environment; see ``_fastcgi_env``."""
        t = h.get("transport")
        if not isinstance(t, dict) or t.get("protocol") != "fastcgi":
            return
        for name, value in (t.get("env") or {}).items():
            if cgi_identity(str(name), self.idents) or CLIENT_PLACEHOLDER.search(str(value)):
                self.add("reset", f"{loc}/transport", f"fastcgi env {name}: an identity variable, "
                         "or one set from a value the client chooses")  # fmt: skip

    def require(self, st: frozenset | None, needed: set[str], loc: str, what: str) -> None:
        missing = sorted(needed - (st or frozenset()), key=lambda k: (k != MARK, k))
        if MARK in missing:  # the names carrying authentik go with it
            missing = [k for k in missing if k == MARK or "authentik" not in k]
        if missing:
            self.add("semantic", loc, f"{what} is reached on a path where client-sent "
                     f"{', '.join(missing)} is not deleted first (a matcherless "
                     "request_header -*authentik* first in the site covers every path)")  # fmt: skip


def _protected(servers: dict) -> frozenset:
    """The upstreams a top-level route with a forward-auth proxies to (but the forward-auth
    dials themselves, the IdP's): served elsewhere without auth, they are exposed."""
    behind: set[str] = set()
    idp: set[str] = set()

    def walk(x: object, authed: bool, named: dict) -> None:
        if isinstance(x, dict):
            if x.get("handler") == "reverse_proxy":
                (idp if _is_auth(x) else behind if authed else set()).update(_proxy_dials(x))
            if x.get("handler") == "invoke" and x.get("name") in named:
                walk(named[x["name"]], authed, {})
            for v in x.values():
                walk(v, authed, named)
        elif isinstance(x, list):
            for v in x:
                walk(v, authed, named)

    for srv in servers.values():
        if not isinstance(srv, dict):
            continue
        named = srv.get("named_routes") if isinstance(srv.get("named_routes"), dict) else {}
        for r in srv.get("routes") or []:
            if _contains_auth(r, named):
                walk(r, True, named)
    return frozenset(behind - idp)


def caddy_shape(doc: object) -> bool:
    """Whether ``doc`` is a Caddy JSON config: ``apps.http.servers`` is an object."""
    apps = doc.get("apps") if isinstance(doc, dict) else None
    http = apps.get("http") if isinstance(apps, dict) else None
    return isinstance(http, dict) and isinstance(http.get("servers"), dict)


def judge_json(doc: object) -> list[tuple[str, str]]:
    """``(rule, detail)`` for each problem in a Caddy JSON config (see ``_Judge``)."""
    if not caddy_shape(doc):
        return [("semantic", "not a Caddy config: no apps.http.servers")]
    out: list[tuple[str, str]] = []
    servers = doc["apps"]["http"]["servers"]  # type: ignore[index]
    protected = _protected(servers)
    for name, srv in servers.items():
        if isinstance(srv, dict):
            out += _Judge(str(name), srv, protected).run()
    return list(dict.fromkeys(out))


#: a Caddy JSON handler outside a full config (a route posted to the admin API, say)
JSON_FRAGMENT = {"reverse_proxy": ("upstreams", "handle_response"), "headers": ("request",),
                 "subroute": ("routes",)}  # fmt: skip


def caddy_fragment(x: object) -> str | None:
    """The first Caddy handler in ``x`` that is not inside a full config: a ``reverse_proxy``
    with ``upstreams``, a ``headers`` with ``request``, a ``subroute`` with ``routes``."""
    if isinstance(x, dict):
        keys = JSON_FRAGMENT.get(str(x.get("handler")))
        if keys and any(k in x for k in keys):
            return str(x["handler"])
        x = list(x.values())
    if isinstance(x, list):
        for v in x:
            got = caddy_fragment(v)
            if got:
                return got
    return None


class Adapter:
    """``caddy adapt`` run on a Caddyfile: Caddy's own reading of it, as JSON."""

    def __init__(self, binary: str):
        self.binary = binary
        try:
            got = subprocess.run([binary, "version"], capture_output=True, timeout=60, check=False)
            self.version = (got.stdout.decode("utf-8", "replace").split() or ["?"])[0]
        except (OSError, subprocess.SubprocessError) as exc:
            raise MissingDependency(f"caddy binary {binary} does not run ({exc})") from None

    def adapt(self, text: str | None, file: Path | None) -> tuple[object | None, str]:
        """The JSON Caddy builds from ``file`` (or ``text``, written to a scratch file), or None
        and Caddy's own error. The environment is empty: a ``{$VAR}`` reads as unset. Each input
        is adapted once per process (a file by its path and content: its imports are read
        relative to it)."""
        key = (str(file.resolve()), file.read_bytes()) if file is not None else (None, text)
        cache = self.__dict__.setdefault("_cache", {})
        if key not in cache:
            cache[key] = self._adapt(text, file)
        doc, err = cache[key]
        return (json.loads(json.dumps(doc)) if doc is not None else None), err

    def _adapt(self, text: str | None, file: Path | None) -> tuple[object | None, str]:
        with tempfile.TemporaryDirectory() as tmp:
            if file is not None:
                file = file.resolve()
            else:
                file = Path(tmp) / "Caddyfile"
                file.write_text(text or "", encoding="utf-8")
            try:
                got = subprocess.run(
                    [self.binary, "adapt", "--adapter", "caddyfile", "--config", str(file)],
                    capture_output=True,
                    timeout=120,
                    check=False,
                    cwd=tmp,
                    env={"HOME": tmp, "XDG_CONFIG_HOME": tmp, "XDG_DATA_HOME": tmp},
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return None, f"caddy adapt did not run ({exc.__class__.__name__})"
            err = got.stderr.decode("utf-8", "replace").replace(f"{file.parent}/", "")
        if got.returncode != 0:
            msgs = []
            for ln in err.splitlines():
                try:
                    rec = json.loads(ln)
                except ValueError:
                    rec = None
                if isinstance(rec, dict):
                    if rec.get("level") in ("error", "fatal"):
                        msgs.append(str(rec.get("msg") or rec.get("error") or ""))
                elif ln.strip():
                    msgs.append(ln.strip())
            return None, (msgs[-1] if msgs else f"exit {got.returncode}")[:240]
        try:
            return json.loads(got.stdout), ""
        except ValueError:
            return None, "caddy adapt printed no JSON"


def find_caddy(explicit: str | None) -> str | None:
    """The ``caddy`` binary: ``--caddy``, else ``$HNX_CADDY``, else ``caddy`` on PATH."""
    if explicit:
        return explicit
    if os.environ.get(CADDY_ENV):
        return os.environ[CADDY_ENV]
    return shutil.which("caddy")


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
    re.compile(r"\bxcaddy\s+build(?![`\w])(?:\s+(?P<v>v?\d\S*|\$\S+|master|main|latest|HEAD)\b)?"),
    re.compile(r"github\.com/caddyserver/caddy/v2(?:@|\s+)(?P<v>v\S+)"),
    re.compile(r"caddyserver/caddy/releases/download/(?P<v>[^/\s]+)/"),
    re.compile(r"\bcaddy_(?P<v>\d[\w.+-]*?)_(?:linux|darwin|windows|freebsd|openbsd|netbsd)_"),
    # a distro package pin (apk add caddy=2.8.4-r0, apt-get install caddy=2.8.4-1): its upstream
    # version; the distro's own revision after it is not a pre-release
    re.compile(r"(?<![\w.-])caddy=(?:\d+:)?(?P<v>\d+\.\d+(?:\.\d+)?)"),
)


@functools.lru_cache(maxsize=4)
def _compose(text: str) -> tuple:
    """Every YAML document of ``text`` as nodes, composed once per file however many checks read
    it (libyaml's loader when it is there)."""
    return tuple(yaml.compose_all(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)))


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


def _substitute_vars(value: str, env: dict[str, str | None]) -> tuple[str, bool]:
    """``value`` with each ``${NAME...}`` and ``$NAME`` replaced, nested defaults included
    (``${A:-${B:-2.11.7}}``), and whether one could not be (no value and no default)."""
    out: list[str] = []
    missing = False
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c == "$" and value.startswith("${", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if value.startswith("${", j):
                    depth, j = depth + 1, j + 2
                    continue
                depth -= value[j] == "}"
                j += 1
            if depth:
                return value, True  # never closed
            m = re.match(r"(\w+)(?:(:?[-=?+])(.*))?$", value[i + 2 : j - 1], re.S)
            i = j
            if not m:
                missing = True
                continue
            name, op, default = m.group(1), m.group(2) or "", m.group(3) or ""
            known = env.get(name)
            if known is not None and not (op.startswith(":") and known == "" and "-" in op):
                out.append(known)
            elif op in (":-", "-", ":=", "="):
                got, miss = _substitute_vars(default, env)
                out.append(got)
                missing |= miss
            else:
                missing = True
            continue
        if c == "$" and (m := re.match(r"\$(\w+)", value[i:])):
            known = env.get(m.group(1))
            if known is None:
                missing = True
            else:
                out.append(known)
            i += len(m.group(0))
            continue
        out.append(c)
        i += 1
    return "".join(out), missing


def resolve(value: str, env: dict[str, str | None] | None = None) -> str | None:
    """``value`` with its ``${VAR}`` substituted from ``env`` or the expression's own default
    (nested defaults to any depth), or None when one cannot be (no value, no default,
    ``${VAR:?}``, a Jinja expression) or a ``$`` is left over."""
    out, missing = _substitute_vars(value, env or {})
    if missing or "{{" in out or "{%" in out or "$" in out:
        return None
    return out


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

    for doc in _compose(text):
        if doc is not None:
            walk(doc)
    pins.text(images=False, keys=False)
    return pins.findings


#: an ``xcaddy build`` in a Dockerfile ``RUN``, shell or exec form (``"xcaddy", "build"``); its
#: version is the first argument that is not a flag
XCADDY_RUN = re.compile(
    r"""\bxcaddy["']?\s*,?\s*["']?build\b["']?(?:[\s,]+(?P<v>["']?[^\s,"'\]]+["']?))?"""
)
#: ``CADDY_VERSION=...`` set for the command that follows it (``RUN CADDY_VERSION=v2.8.4 xcaddy``)
INLINE_CADDY_VERSION = re.compile(r"""(?<![\w-])CADDY_VERSION=(?P<v>"[^"]*"|'[^']*'|[^\s;&|]+)""")


def _dockerfile_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Logical instructions as ``(first line, text)``: continuation lines joined with the escape
    character the ``# escape=`` parser directive names (default ``\\``)."""
    escape = "\\"
    for ln in lines:
        m = re.match(r"^#\s*(\w+)\s*=\s*(\S+)\s*$", ln)
        if not m:
            break
        if m.group(1).lower() == "escape":
            escape = m.group(2)
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for no, ln in enumerate(lines, 1):
        if not buf:
            start = no
        if ln.rstrip().endswith(escape) and not ln.lstrip().startswith("#"):
            buf += ln.rstrip()[: -len(escape)] + " "
            continue
        out.append((start, buf + ln))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def lint_dockerfile(text: str, path: str = "<text>") -> list[Finding]:
    """A Dockerfile: ``ARG``/``ENV`` defaults are resolved into ``FROM``, ``COPY --from``,
    ``RUN --mount=from=`` and ``xcaddy build`` (shell or exec form, quoted or not, a
    ``CADDY_VERSION=`` set on the command itself included); a ``FROM`` that cannot be resolved
    (no default) fails closed, since it could be Caddy; ``caddy=<version>`` package pins
    (``apk add``, ``apt-get install``) are read as Caddy versions."""
    pins = _Pins(path, text)
    env: dict[str, str | None] = {}
    stages: set[str] = set()
    builder = False

    def other_image(no: int, ref: str) -> None:
        """An image a ``COPY --from`` or ``RUN --mount`` reads from: unless it is a stage."""
        got = resolve(ref.strip("\"'"), env)
        if got is None:
            pins.add(no, f"--from {ref} cannot be resolved: it could be Caddy; give the ARG a "
                     "default")  # fmt: skip
        elif got not in stages and not got.isdigit():
            pins.image(no, got)

    for no, ln in _dockerfile_lines(pins.lines):
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
        elif op in ("COPY", "ADD"):
            for w in words[1:]:
                if w.startswith("--from="):
                    other_image(no, w.split("=", 1)[1])
        elif op == "RUN":
            flags = []
            rest = ln.split(None, 1)[1] if len(words) > 1 else ""
            while rest.startswith("--"):
                flag, _, rest = rest.partition(" ")
                flags.append(flag)
                rest = rest.lstrip()
            for flag in flags:
                for m in re.finditer(r"(?:^--mount=|,)from=([^,\s]+)", flag):
                    other_image(no, m.group(1))
            if rest.startswith("["):
                try:
                    argv = json.loads(rest)
                except ValueError:
                    argv = None
                if isinstance(argv, list):
                    rest = " ".join(str(a) for a in argv)
            inline = [m.group("v").strip("\"'") for m in INLINE_CADDY_VERSION.finditer(rest)]
            for v in inline:
                pins.version(no, "CADDY_VERSION", v, env)
            for m in XCADDY_RUN.finditer(rest):
                v = (m.group("v") or "").strip("\"'")
                if not v or v.startswith("-") or v in ("&&", "||", ";", "|"):
                    if not (builder or env.get("CADDY_VERSION") or inline):
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
        from homelabnext.registry.model import RegistryError, build_registry, loads
    except ImportError as exc:
        raise MissingDependency(f"homelabnext ({exc})") from None
    # most registries in a tree are schema negatives that never load: refuse those with the
    # model's own validation on a libyaml parse first (the same document the registry's loader
    # builds, so a refusal here is a refusal there), and pay for the loader's pure-Python
    # duplicate-key parse only for the ones that pass
    try:
        build_registry(yaml.load(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)))
    except (RegistryError, yaml.YAMLError):
        return None, []
    except Exception:  # anything else is decided by the real loader below
        pass
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
    docs = [d for d in _compose(text) if d is not None]
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


def _yaml_caddy(text: str, rel: str, ctx: CaddyContext) -> tuple[list[Finding], list[Pending]]:
    """A Caddyfile embedded in a YAML/JSON string (an Ansible ``copy: content:``): any string
    with a ``forward_auth`` that reads as a directive is linted as one."""
    findings: list[Finding] = []
    found: list[Pending] = []
    stack = list(_compose(text))
    while stack:
        node = stack.pop()
        if isinstance(node, yaml.MappingNode):
            stack += [v for _, v in node.value]
        elif isinstance(node, yaml.SequenceNode):
            stack += node.value
        elif isinstance(node, yaml.ScalarNode) and isinstance(node.value, str):
            v = node.value
            if FORWARD_AUTH_LINE.search(v) and ("{" in v or "\n" in v.strip()):
                offset = node.start_mark.line + (1 if node.style in ("|", ">") else 0)
                findings += lint_caddy(v, rel, offset, ctx=ctx)
                found.append(Pending(rel, offset + 1, v, None, template=_templated(v)))
    return findings, found


def _plain(node: yaml.Node) -> object:
    """A composed YAML node as plain data, unknown tags (``!vault``) read as their value."""
    if isinstance(node, yaml.MappingNode):
        return {str(_plain(k)): _plain(v) for k, v in node.value}
    if isinstance(node, yaml.SequenceNode):
        return [_plain(v) for v in node.value]
    tag, value = node.tag.rsplit(":", 1)[-1], node.value
    if tag == "bool":
        return str(value).lower() in ("true", "yes", "on")
    if tag == "int":
        try:
            return int(value)
        except ValueError:
            return value
    return None if tag == "null" else value


def _json_configs(text: str, rel: str, json_file: bool) -> tuple[list[Finding], int]:
    """Caddy JSON (or the same structure in YAML) judged as Caddy runs it, and a coverage
    finding for a Caddy handler outside a full config (the lint cannot tell where it runs)."""
    if json_file:
        try:
            docs = [json.loads(text)]
        except ValueError:
            return [], 0  # the YAML reader already reported what it could not parse
    else:
        docs = [_plain(d) for d in _compose(text) if d is not None]
    findings: list[Finding] = []
    n = 0
    for doc in docs:
        if caddy_shape(doc):
            n += 1
            findings += [Finding(rel, 0, rule, detail) for rule, detail in judge_json(doc)]
        elif (handler := caddy_fragment(doc)) is not None:
            findings.append(
                Finding(
                    rel,
                    0,
                    "coverage",
                    f"a Caddy {handler} handler outside a full Caddy config (apps.http.servers): "
                    "the lint cannot tell which requests reach it; keep Caddy JSON whole, or list "
                    f"it in {DEFAULT_ALLOWLIST} with the reason it is covered",
                )
            )
    return findings, n


#: a Caddyfile that is a template still to be rendered: Caddy cannot read it yet
TEMPLATE_NAME = re.compile(r"(?i)\.(j2|jinja2?|tmpl|tpl)$")
TEMPLATE_TEXT = re.compile(r"\{\{|\{%|\$\{")
#: a Caddyfile comment: ``#`` at the start of a token, to the end of the line
CADDY_COMMENT = re.compile(r"(?m)(^|[ \t])#.*$")


def _templated(text: str) -> bool:
    """Template syntax outside comments (a ``${DOCS}`` in a comment does not make a template)."""
    return bool(TEMPLATE_TEXT.search(CADDY_COMMENT.sub(r"\1", text)))


#: an import of the generated snippet by a config that does not define it
IMPORTS_GENERATED = re.compile(r"(?m)^[ \t]*import[ \t]+hnx_forward_auth[ \t]*$")


@dataclass
class Pending:
    """A Caddyfile for the semantic check: its file (when Caddy can read it in place) or its
    text, and whether Caddy refusing it is a finding (``strict``) or leaves it to the text lint
    (a markdown example)."""

    rel: str
    line: int
    text: str | None
    file: Path | None
    strict: bool = True
    template: bool = False  # rendered before Caddy reads it: text rules only


def _semantic(item: Pending, adapter: Adapter) -> tuple[list[Finding], bool]:
    """The ``semantic`` findings for one Caddyfile, from Caddy's own JSON of it, and whether it
    was judged."""
    text, file = item.text, item.file
    if file is not None:
        text = file.read_text(encoding="utf-8")
    if text is not None and IMPORTS_GENERATED.search(text) and "(hnx_forward_auth)" not in text:
        try:
            from homelabnext.generators.builtin import _forward_auth_snippet
        except ImportError as exc:
            raise MissingDependency(f"homelabnext ({exc})") from None
        text, file = _forward_auth_snippet("idp:9443") + text, None
    doc, err = adapter.adapt(text, file)
    if doc is None:
        if not item.strict:
            return [], False
        return [
            Finding(
                item.rel,
                item.line,
                "semantic",
                f"caddy adapt refuses it ({err}): the semantic check cannot judge it",
            )
        ], False
    if not caddy_shape(doc):
        return [], True  # no site at all (only snippets, or nothing): nothing reaches anything
    return [Finding(item.rel, item.line, r, d) for r, d in judge_json(doc)], True


def scan(
    root: Path,
    allow: list[AllowEntry] | None = None,
    adapter: Adapter | None = None,
    required: bool = False,
) -> tuple[list[Finding], dict[str, int | str]]:
    findings: list[Finding] = []
    counts: dict[str, int | str] = {
        "files": 0,
        "caddy_configs": 0,
        "generated": 0,
        "json_configs": 0,
        "adapted": 0,
        "text_only": 0,
        "caddy": adapter.version if adapter else "none",
    }
    ctx = CaddyContext(root)
    unread: list[tuple[str, int]] = []  # files with a forward_auth the lint did not read
    pending: list[Pending] = []  # Caddyfiles for the semantic check
    json_files: set[str] = set()  # Caddy JSON/YAML configs
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
                template = bool(TEMPLATE_NAME.search(name)) or _templated(text)
                pending.append(Pending(rel, 0, None, p, template=template))
                continue
            if name == "Dockerfile" or name.startswith("Dockerfile.") or p.suffix == ".dockerfile":
                counts["files"] += 1
                findings += lint_dockerfile(p.read_text(encoding="utf-8"), rel)
                continue
            text = p.read_text(encoding="utf-8")
            low = text.lower()
            structured = p.suffix in (".yml", ".yaml", ".json")
            if (
                "caddy" not in low
                and "forward_auth" not in low
                and not (structured and "handler" in low)
            ):
                continue
            counts["files"] += 1
            if p.suffix == ".md":
                blocks, outside = md_blocks(text)
                for info, body, offset in blocks:
                    lang = (info.split() or [""])[0].lower()
                    if lang in ("caddy", "caddyfile") or FORWARD_AUTH.search(body):
                        counts["caddy_configs"] += 1
                        findings += lint_caddy(body, rel, offset, ctx=ctx)
                        pending.append(Pending(rel, offset + 1, body, None, strict=False))
                unread += [(rel, no) for no, ln in outside if FORWARD_AUTH_BARE.match(ln)]
                pins = _Pins(rel, text)
                pins.text()
                findings += pins.findings
            elif structured:
                findings += lint_pins(text, rel)
                found, embedded = _yaml_caddy(text, rel, ctx)
                findings += found
                pending += embedded
                counts["caddy_configs"] += len(embedded)
                judged, n = _json_configs(text, rel, p.suffix == ".json")
                findings += judged
                if n:
                    json_files.add(rel)
                counts["caddy_configs"] += n
                counts["json_configs"] += n
                if _is_registry(text):
                    site, problems = _generated(text, rel)
                    findings += problems
                    if site is not None:
                        counts["generated"] += 1
                        counts["caddy_configs"] += 1
                        label = f"{rel} (caddy generator)"
                        findings += lint_caddy(site, label, ctx=ctx)
                        pending.append(Pending(label, 0, site, None))
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
    for item in pending:
        if item.rel in ctx.imported:
            continue  # Caddy reads it through the config that imports it
        if adapter is None or item.template:
            counts["text_only"] += 1
            if adapter is not None and required:
                findings.append(
                    Finding(
                        item.rel,
                        item.line,
                        "semantic",
                        "a template (or text with {{, {% or ${ outside comments): caddy adapt "
                        "cannot read it until it is rendered, and the semantic check is required; "
                        "lint the rendered config, or list it with rules: [semantic] and a reason",
                    )
                )
            continue
        got, judged = _semantic(item, adapter)
        findings += got
        counts["adapted" if judged else "text_only"] += 1
    configs = set(ctx.parsed) | {i.rel.split(" (", 1)[0] for i in pending} | json_files
    return apply_allowlist(findings, allow or [], configs), counts


class AllowlistError(Exception):
    """The allowlist file is malformed (exit 2)."""


#: the rules an allowlist entry may excuse
RULES = ("strip", "reset", "parse", "coverage", "generate", "pin", "semantic", "dial", "exposure")


class AllowEntry(NamedTuple):
    """One reviewed exception: the findings of ``rules`` in the file(s) ``path`` names."""

    path: str
    reason: str
    rules: tuple[str, ...]


def load_allowlist(path: Path | None) -> list[AllowEntry]:
    """The entries of ``tools/caddy_lint.allow.yml``: each a ``path`` (a file, or a glob that
    names no Caddy config; never bare ``*``/``**``), a ``reason`` and the ``rules`` it excuses."""
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
        rules = fields.get("rules")
        problem = ""
        if not glob:
            problem = "needs a 'path'"
        elif not glob.replace("*", "").replace("/", ""):
            problem = f"path {glob!r} matches every file: name the file"
        elif not why:
            problem = "has no 'reason'"
        elif not isinstance(rules, list) or not rules:
            problem = f"needs 'rules': a list of the rules it excuses ({', '.join(RULES)})"
        elif unknown := [r for r in rules if r not in RULES]:
            problem = f"names unknown rules {unknown} (known: {', '.join(RULES)})"
        if problem:
            raise AllowlistError(f"{path}: entry {i} {problem}")
        out.append(AllowEntry(glob, why, tuple(dict.fromkeys(str(r) for r in rules))))
    return out


def apply_allowlist(
    findings: list[Finding], allow: list[AllowEntry], configs: set[str] | None = None
) -> list[Finding]:
    """The findings no entry excuses (an entry excuses only its own rules), plus an
    ``allowlist`` finding for each rule of an entry that excuses nothing (a stale entry would
    silently waive the next real finding in that file) and for each glob entry that names a
    file the lint reads as a Caddy config (a config is excused file by file, by name)."""
    used: set[tuple[int, str]] = set()
    kept = []
    for f in findings:
        rel = f.path.split(" (", 1)[0]
        hit = [
            i for i, e in enumerate(allow) if f.rule in e.rules and fnmatch.fnmatchcase(rel, e.path)
        ]
        used.update((i, f.rule) for i in hit)
        if not hit:
            kept.append(f)
    for i, e in enumerate(allow):
        for rule in e.rules:
            if (i, rule) not in used:
                kept.append(
                    Finding(
                        DEFAULT_ALLOWLIST, 0, "allowlist", f"entry {e.path!r} excuses no {rule}"
                    )
                )
        if GLOB.search(e.path):
            named = sorted(c for c in configs or () if fnmatch.fnmatchcase(c, e.path))
            if named:
                kept.append(
                    Finding(
                        DEFAULT_ALLOWLIST,
                        0,
                        "allowlist",
                        f"entry {e.path!r} is a glob that names the Caddy config {named[0]}: "
                        "list a config by its own path",
                    )
                )
    return kept


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    parser = argparse.ArgumentParser(prog="caddy_lint", description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=".", help="the tree to check")
    parser.add_argument("--json", action="store_true", help="findings as JSON on stdout")
    parser.add_argument("--allowlist", help=f"default: <root>/{DEFAULT_ALLOWLIST}")
    parser.add_argument(
        "--caddy", help=f"the caddy binary for the semantic check (default: ${CADDY_ENV}, PATH)"
    )
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
    binary = find_caddy(opts.caddy)
    required = os.environ.get(CADDY_REQUIRED_ENV, "") not in ("", "0")
    try:
        if binary is None and required:
            raise MissingDependency(
                f"caddy ({CADDY_REQUIRED_ENV} is set and no caddy binary was found: "
                f"--caddy, ${CADDY_ENV} or PATH)"
            )
        adapter = Adapter(binary) if binary else None
        findings, counts = scan(root, allow, adapter, required)
    except MissingDependency as exc:
        print(f"caddy_lint: missing dependency: {exc}", file=err)
        return 2
    if adapter is None:
        print(
            f"caddy_lint: no caddy binary (--caddy, ${CADDY_ENV} or PATH): the semantic check "
            f"(caddy adapt) did not run, so the text lint alone judged {counts['text_only']} "
            "Caddyfile(s); it does not see what Caddy's own reading shows (the handler order "
            "after Caddy sorts the directives, a plugin directive's effect on headers). CI runs "
            f"it with a pinned Caddy and {CADDY_REQUIRED_ENV}=1",
            file=err,
        )
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
        semantic = (
            f"caddy adapt ({counts['caddy']}) judged {counts['adapted']}"
            if adapter
            else "caddy adapt not run"
        )
        print(
            f"caddy_lint: {len(findings)} finding(s); {counts['caddy_configs']} Caddy configs "
            f"({counts['generated']} generated, {counts['json_configs']} JSON) in "
            f"{counts['files']} files; {semantic}, {counts['text_only']} text only",
            file=out,
        )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
