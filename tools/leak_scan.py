#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: leak-scan
#   kind: check
#   purpose: Fail when the tree, a commit range or stdin carries a private identifier or a secret shape.
#   owner: maintainers
#   trigger: [ci:ci/leak-scan, ci:ci/packaging, ci:release/build, make:leak-scan, make:leak-scan-history, make:secret-scan, pre-commit:leak-scan, pre-commit:secret-scan, script:coverage-floor, script:private-leak-check]
#   invariant: [F-05, F-18, Q-06]
#   inputs: paths, --history RANGE, --stdin or --check-authors RANGE; optional HNX_DENYLIST file
#   outputs: one line per hit
#   exit:
#     "0": clean
#     "1": at least one hit or an unscannable file
#     "2": misconfiguration
"""Generic public-repository leak scanner.

Scans text files for *shapes* of data that must never be published: private, carrier-grade-NAT
and public IPv4 addresses, non-documentation IPv6 (full and compressed), MAC addresses, e-mail
addresses outside documentation domains, private TLDs, workstation paths, secret-looking variable
names and keyed values, cloud keys, PEM blocks, API tokens and high-entropy strings.  It knows no
real identifiers: a project's or a person's own names (host names, domains, paths) belong in a
deny-list file given at run time (env ``HNX_DENYLIST`` or ``--denylist``, never committed) of
literal terms or ``re:`` regexes; terms from it are never echoed back, only their line number in
the file.

What is scanned: inside a git work tree, the files ``git ls-files`` reports (tracked plus untracked
files that are not ignored); elsewhere, a directory walk that skips ``build``, ``dist`` and virtual
environments only at the top of the scanned directory.  A file that cannot be scanned (binary,
larger than 5 MB, unreadable) is reported and fails the run unless ``--allow-skip GLOB`` names it.
A symbolic link is never followed: its target path is scanned as text.

``--history RANGE`` scans the lines each commit in ``RANGE`` added (``git log -p``), by default
with the network and identity groups and the deny-list, so a value that was committed and later
deleted is still found.  ``--check-authors RANGE`` fails on an author or committer e-mail that is
not a GitHub noreply address.

Exit codes: 0 clean, 1 at least one hit (or an unscannable file), 2 misconfiguration.

Suppress one reviewed line with an end-of-line marker ``scrub-allow: <reason>`` (any comment
syntax; the reason is a few plain words).  Only hits *before* the marker are suppressed, a hit in
the ``secret`` group is never suppressed, and the note printed for CI logs names the patterns and
the reason, never the line.

Usage::

    python3 tools/leak_scan.py [PATH ...]           # default: current directory
    git log -5 --format=%B | python3 tools/leak_scan.py --stdin
    python3 tools/leak_scan.py --history origin/main..HEAD
    python3 tools/leak_scan.py --list               # show the built-in patterns
    python3 tools/leak_scan.py --groups secret .    # only one group of patterns
"""

from __future__ import annotations

import argparse
import bisect
import fnmatch
import ipaddress
import math
import os
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Shapes shared with the prompt screener (homelabnext.agent.screen); stdlib only.
from homelabnext import shapes  # noqa: E402

EXIT_CLEAN = 0
EXIT_HIT = 1
EXIT_CONFIG = 2

# Never useful to scan, at any depth.
SKIP_DIRS_ANYWHERE = {
    ".git",
    "node_modules",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".mypy_cache",
}
# Build output and environments: skipped only directly under the scanned directory, so a source
# directory that happens to be called ``build`` deeper in the tree is still scanned.
SKIP_DIRS_AT_ROOT = {".venv", "venv", "dist", "build", ".tox"}
MAX_BYTES = 5 * 1024 * 1024
# The marker must end the line; the reason is a few plain words (so a value cannot hide in it).
SUPPRESS_RE = re.compile(
    r"scrub-allow:[ \t]*(?P<reason>[A-Za-z][A-Za-z0-9 ,;()'_-]{2,79}?)[ \t]*(?:-->|\*/)?[ \t]*$"
)
DEFAULT_HISTORY_GROUPS = ("network", "identity")

# Documentation / reserved values that are always acceptable.
DOC_MAC_PREFIX = "00:00:5e:00:53:"
ALLOWED_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "example.internal",
    # reserved top-level names (RFC 2606, RFC 6761): no real mailbox can exist under them
    "example",
    "invalid",
    "test",
    "users.noreply.github.com",
)
# Exact addresses (not domains) that are public by construction, e.g. co-author trailers.
# Fixed service addresses that tools write into commits (a co-author trailer, Dependabot's
# sign-off); other addresses at the same domains still count.
ALLOWED_EMAIL_ADDRESSES = ("noreply@anthropic.com", "support@github.com")
# Commit identities that are public by construction.
NOREPLY_COMMIT_RE = re.compile(
    r"(?i)^(?:[\w.+-]+(?:\[bot\])?@users\.noreply\.github\.com|noreply@github\.com)$"
)
# Well-known public anycast resolvers: public, but not anybody's infrastructure.
PUBLIC_RESOLVERS = frozenset(
    {
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "149.112.112.112",
        "208.67.222.222",
        "208.67.220.220",
    }
)
# Words that mark a value as an obvious placeholder rather than a credential.
PLACEHOLDER_RE = re.compile(
    r"(?i)fake|example|dummy|placeholder|changeme|change-me|redacted|sample|not-a-real|xxxx"
)


@dataclass(frozen=True)
class Pattern:
    name: str
    group: str  # network | identity | path | secret
    regex: re.Pattern[str]
    why: str
    redact: bool = False
    # (match, line, path) -> True when it IS a hit; path is the scanned file's ('' for stdin)
    accept: Callable[[re.Match[str], str, str], bool] | None = None


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    pattern: str
    shown: str


@dataclass(frozen=True)
class Skipped:
    path: str
    reason: str


def _entropy(token: str) -> float:
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


KEYED_RE = re.compile(r"(?i)(secret|token|passw|api[_-]?key|credential|auth|private)")


def _is_hit_mac(m: re.Match[str], _line: str, _path: str = "") -> bool:
    text = m.group(0).lower().replace("-", ":")
    return not text.startswith(DOC_MAC_PREFIX)


def _is_hit_email(m: re.Match[str], _line: str, _path: str = "") -> bool:
    if m.group(0).lower() in ALLOWED_EMAIL_ADDRESSES:
        return False
    domain = m.group("domain").lower()
    return not any(domain == d or domain.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS)


def _is_hit_tld(m: re.Match[str], _line: str, _path: str = "") -> bool:
    # example.internal (and anything beneath it) is the documented placeholder.
    return not (m.group("tld") == "internal" and m.group("label").lower() == "example")


def _is_hit_aws_account(m: re.Match[str], _line: str, _path: str = "") -> bool:
    return m.group("num") != "123456789012"


def _is_hit_rule_number(m: re.Match[str], _line: str, _path: str = "") -> bool:
    return not m.group("num").startswith("9000")


VERSION_CONTEXT_RE = shapes.VERSION_CONTEXT_RE


def _is_hit_public_ipv4(m: re.Match[str], line: str, _path: str = "") -> bool:
    text = m.group(0)
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return False  # 999.1.2.3: not an address at all
    if not addr.is_global or text in PUBLIC_RESOLVERS:
        return False  # private / documentation / special-purpose (RFC 6890) or a public resolver
    if any(len(o) > 1 and o.startswith("0") for o in text.split(".")):
        return False  # zero-padded octets: a date or version, not an address
    return not VERSION_CONTEXT_RE.search(line[: m.start()])


def _is_hit_ipv6_compressed(m: re.Match[str], _line: str, _path: str = "") -> bool:
    text = m.group(0)
    groups = [g for g in text.split(":") if g]
    if len(groups) < 2 or all(g.isalpha() for g in groups):
        return False  # ``ab::cd`` or ``Foo::Bar`` style text, not an address
    try:
        addr = ipaddress.IPv6Address(text)
    except ValueError:
        return False
    if any(addr in ipaddress.IPv6Network(n) for n in ("2001:db8::/32", "3fff::/20")):
        return False  # documentation (RFC 3849, RFC 9637)
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return False
    return not addr.exploded.startswith(("fc", "fd"))  # unique-local has its own rule


# The one commit-trailer shape that is public by construction: a session link, nothing else on
# the line.  Anchored on both ends so it cannot be used to smuggle other content past the scan.
SESSION_TRAILER_RE = re.compile(
    r"^Claude-Session: https://claude\.ai/code/session_[A-Za-z0-9]+\s*$"
)


# A go.sum line: ``<module> <version>[/go.mod] h1:<base64 SHA-256>=``.  The hash is a digest of
# public module content, not a credential.  Only the whole-line shape in a file named go.sum
# counts, so the same value anywhere else (another file, or a go.sum-looking line with anything
# appended) is still scanned.
GO_SUM_LINE_RE = re.compile(r"^\S+ v\S+ h1:(?P<hash>[A-Za-z0-9+/]{43}=)$")
# A Go test, benchmark, fuzz or example function name (``TestSubmit_ReplayIs422``): CamelCase
# words, so long and mixed-case enough to read as random.  A name is told from a token by its
# lowercase runs (``ubmit``, ``eplay``): at least three letters on average, which random base64
# of this length essentially never has; see GO_TEST_NAME_MIN_RUN.
GO_TEST_NAME_RE = re.compile(r"^(?:Test|Benchmark|Fuzz|Example)[A-Z0-9_][A-Za-z0-9_]*$")
GO_TEST_NAME_MIN_RUN = 3.0


def _is_go_test_name(token: str) -> bool:
    if not GO_TEST_NAME_RE.match(token):
        return False
    runs = re.findall(r"[a-z]+", token)
    return bool(runs) and sum(map(len, runs)) / len(runs) >= GO_TEST_NAME_MIN_RUN


def _is_hit_entropy(m: re.Match[str], line: str, path: str = "") -> bool:
    if SESSION_TRAILER_RE.match(line):
        return False
    go_sum = GO_SUM_LINE_RE.match(line) if path.rsplit("/", 1)[-1] == "go.sum" else None
    if go_sum and go_sum.start("hash") == m.start("tok") and go_sum.end("hash") == m.end("tok"):
        return False
    token = m.group("tok")
    if _is_go_test_name(token):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", token):  # hex digests: see hex-secret
        return False
    if token.startswith(("http", "www.")) or token.count("/") > 2:
        return False
    if PLACEHOLDER_RE.search(token):
        return False
    if not (re.search(r"[a-z]", token) and re.search(r"[A-Z]", token) and re.search(r"\d", token)):
        return False
    return _entropy(token) >= (4.0 if KEYED_RE.search(line) else 4.5)


def _is_hit_lower_entropy(m: re.Match[str], line: str, _path: str = "") -> bool:
    token = m.group("tok")
    if re.fullmatch(r"[0-9a-f]+", token):  # hex digests: see hex-secret
        return False
    if PLACEHOLDER_RE.search(token):
        return False
    if len(re.findall(r"\d", token)) < 4 or len(re.findall(r"[a-z]", token)) < 4:
        return False
    return _entropy(token) >= (3.8 if KEYED_RE.search(line) else 4.2)


# A hex run is a credential only next to a credential word and never next to a digest word.
DIGEST_CONTEXT_RE = re.compile(r"(?i)sha\d*|digest|checksum|commit|hash|\bref\b|@|fingerprint")


def _is_hit_hex_secret(m: re.Match[str], line: str, _path: str = "") -> bool:
    if not KEYED_RE.search(line) or DIGEST_CONTEXT_RE.search(line):
        return False
    return _entropy(m.group("tok")) >= 3.0  # rules out 000..., fade/face fillers


# An unquoted value made only of a name, attribute path or call is code (``token = self.token``).
CODE_REFERENCE_RE = re.compile(r"^[A-Za-z_][A-Za-z_.]*(?:[\[(].*)?$")
# References and indirections, not values: templates, env vars, secret-store refs, paths, URLs.
REFERENCE_RE = re.compile(
    r"^(?:\$|\{|\[|\(|<|%\(|\*{3}|\.{3}|!vault|lookup\(|/|\./|~/|[a-z][a-z0-9+.-]*:)"
    r"|^[A-Z][A-Z0-9_]+$|^[\d.]+$"
)
# A secret-store reference (``secret:<area>/<name>``), written bare or as a keyed value.  The
# keyed pattern takes the reference's own scheme word as the key when it is bare.  A lower-case
# store name with an area path is a name to look up, never the value - but only when every
# segment reads as words: a random-looking or hex segment after the prefix is a value wearing a
# ``secret:`` prefix, and stays a finding (tools/tests/test_leak_scan.py has the examples).
SECRET_STORE_REF_RE = re.compile(r"^secret:[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*)+`?$")
# one word of a store-reference segment: letters with at most a 2-digit suffix (key2, v1, s3)
STORE_WORD_RE = re.compile(r"[a-z]+\d{0,2}|\d{1,2}")
# A number, scientific notation included (a per-token cost such as 2e-6), is not a credential -
# when its mantissa is short: ``1.23456789e+99`` carries as many digits as a PIN-sized secret.
NUMBER_RE = re.compile(r"^[+-]?(?P<int>\d+)(?:\.(?P<frac>\d+))?(?:[eE][+-]?\d{1,3})?$")
NUMBER_MAX_DIGITS = 6
# a keyed value that is a concrete store reference (not a ``secret:<name>`` template or a path)
SECRET_VALUE_RE = re.compile(r"^secret:[A-Za-z0-9][A-Za-z0-9/_.-]*`?$")


def _is_store_ref(text: str) -> bool:
    """A word-like ``secret:<area>/<name>`` reference (see SECRET_STORE_REF_RE)."""
    if not SECRET_STORE_REF_RE.match(text):
        return False
    for part in re.split(r"[/_.-]", text.removeprefix("secret:").rstrip("`")):
        if not part:
            continue
        if not STORE_WORD_RE.fullmatch(part) or (len(part) >= 8 and _entropy(part) >= 3.5):
            return False
    return True


# A numeric conversion (Go ``float64(435783``, the closing parenthesis ends the match) of a short
# number, and Go's integer and float limit constants, are numbers too.
NUMBER_CAST_RE = re.compile(r"^(?:u?int|float|complex)(?:8|16|32|64|128)?\((?P<num>[^()]*)$")
GO_MATH_LIMIT_RE = re.compile(
    r"^math\.(?:Max|Min|SmallestNonzero)(?:Int|Uint|Float)(?:8|16|32|64)?$"
)
# An escape sequence separates values inside a Go string literal (``"key: v\nnext: w"``): each
# segment is scanned on its own, so a value on either side of an escape is still found, and so is
# the value with the escapes and next keys taken out (pieces each too short to judge).  Only in a
# Go source's interpreted string; any other file keeps the value whole.
GO_ESCAPE_RE = re.compile(r"\\[nrt]")
# a segment that is the next key of the literal (``\nnext_key:``), not a value
NEXT_KEY_RE = re.compile(r"^[a-z][a-z0-9_.-]*:$")


def _is_short_number(value: str) -> bool:
    cast = NUMBER_CAST_RE.match(value)
    if cast:
        value = cast.group("num")
    elif GO_MATH_LIMIT_RE.match(value):
        return True
    m = NUMBER_RE.match(value)
    if not m:
        return False
    digits = (m.group("int") + (m.group("frac") or "")).lstrip("0").rstrip("0")
    return len(digits) <= NUMBER_MAX_DIGITS


# Classic stand-in values (and values that name their own key) read as placeholders.
KEYED_PLACEHOLDER_RE = re.compile(r"(?i)secret|passw|token|hunter2|abc123|letmein|qwerty|123456")


# a Go expression assigned in code: an identifier with a selector, a call or an index after it
# (base64.StdEncoding.EncodeToString(buf), sha256.Sum256([]byte(tok))); Go has no bare literals
GO_CODE_VALUE_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\.[A-Za-z_]\w*|[\[(].*)$")
# A string literal on the right-hand side that is text, not a value: words with spaces or
# punctuation between them ("Bearer ", "/oauth/token", "-suffix-v2"; a word of at most three
# letters may end in a digit or two, so "Battery-Staple42" is no word), once its format verbs
# ("%s-%s-tls") and, in a time layout, its layout elements ("2006-01-02") are taken out.  Taken
# out, not matched anywhere: "%2F" or "2006" inside a random value leaves the rest to be judged.
GO_WORDS_RE = re.compile(
    r"\s*[-_.:/ ]*(?:[A-Za-z]{1,3}\d{1,2}|[A-Za-z]+)(?:[-_. :/]+(?:[A-Za-z]{1,3}\d{1,2}|[A-Za-z]+))*"
    r"[-_.:/ ]*\s*"
)
GO_PUNCTUATION_RE = re.compile(r"[\s\-_.:/,;=()\[\]{}@#|<>'\"]*")
GO_FMT_VERB_RE = re.compile(r"%[-+# 0-9.*\[\]]*[a-zA-Z%]")
GO_TIME_LAYOUT_RE = re.compile(r"2006|15:04|(?<!\d)3:04|Jan _?2|Mon Jan")
GO_LAYOUT_ELEMENT_RE = re.compile(
    r"2006|January|Jan|Monday|Mon|MST|PM|pm|Z07:?00|-07:?00|15|0[1-6]|_2|\.[09]+"
    r"|(?<!\d)[1-5](?!\d)"  # unpadded month, day, hour, minute and second: "January 2, 2006"
)


def _is_go_text_literal(body: str) -> bool:
    text = GO_FMT_VERB_RE.sub(" ", body)
    if GO_TIME_LAYOUT_RE.search(text):
        text = GO_LAYOUT_ELEMENT_RE.sub(" ", text)
    return bool(GO_WORDS_RE.fullmatch(text) or GO_PUNCTUATION_RE.fullmatch(text))


class GoSource:
    """A Go file's tokens, so a position on a line can be told code, a literal or a comment from
    the whole file: a line inside a multi-line raw string is text, not code."""

    def __init__(self, text: str) -> None:
        from tools.go_test_policy import go_tokens  # the same lexer as --check-sources

        self.lines = text.splitlines(keepends=True)  # as scan_text numbers them
        self.starts = [0]
        for line in self.lines:
            self.starts.append(self.starts[-1] + len(line))
        self.tokens = go_tokens(text)
        self.offsets = [t.pos for t in self.tokens]

    def _index(self, lineno: int, col: int) -> int:
        """The index of the first token that ends after this position."""
        at = self.starts[lineno - 1] + col
        i = bisect.bisect_right(self.offsets, at) - 1
        return i if i >= 0 and at < self.offsets[i] + len(self.tokens[i].text) else i + 1

    def kind_at(self, lineno: int, col: int) -> str:
        """The kind of token at this position: ``code`` for an identifier, operator, number or
        white space; ``string``, ``raw``, ``rune`` or ``comment`` for the rest."""
        at = self.starts[lineno - 1] + col
        i = self._index(lineno, col)
        if i < len(self.tokens) and self.offsets[i] <= at:
            kind = self.tokens[i].kind
            return kind if kind in ("string", "raw", "rune", "comment") else "code"
        return "code"

    def literals_after(self, lineno: int, col: int) -> Iterator[str]:
        """The bodies of the string literals that start after this position on its line, up to a
        comment."""
        end = self.starts[lineno]
        for i in range(self._index(lineno, col), len(self.tokens)):  # no slice: linear per file
            tok = self.tokens[i]
            if tok.pos >= end or tok.kind == "comment":
                return
            if tok.kind in ("string", "raw") and tok.pos >= self.starts[lineno - 1] + col:
                yield tok.text[1:-1]


# the Go file scan_text is on, and the line: (source, lineno), for the keyed-value judgement
_GO_CONTEXT: list[tuple[GoSource, int]] = []


def _go_where(line: str) -> tuple[GoSource, int]:
    """The current Go file and line number, or this line alone outside scan_text."""
    if _GO_CONTEXT:
        src, lineno = _GO_CONTEXT[-1]
        # splitlines() as scan_text: a line may end at \f, \x85 or \u2028 as well as \n
        if (src.lines[lineno - 1].splitlines() or [""])[0] == line:
            return src, lineno
    return GoSource(line), 1


class _Quoted:
    """A keyed match stand-in for a string literal on the right-hand side: quoted, the literal
    itself the whole match."""

    def __init__(self, text: str) -> None:
        self.text = text

    def group(self, name: str | int = 0) -> str:
        return '"' if name == "q" else self.text


def _is_hit_keyed_value(m: re.Match[str], line: str, path: str = "") -> bool:
    value = m.group("val")
    if not path.endswith(".go"):
        return _keyed_value_is_hit(m, value)
    src, lineno = _go_where(line)
    kind = src.kind_at(lineno, m.start("val"))
    if kind == "string":
        segments = GO_ESCAPE_RE.split(value)
        kept = [seg for n, seg in enumerate(segments) if not (n and NEXT_KEY_RE.match(seg))]
        # each segment, and the value with its escapes (and next keys) taken out: short pieces
        # split by escapes are still the value they make together, as in any other file
        return any(_keyed_value_is_hit(m, seg) for seg in kept) or _keyed_value_is_hit(
            m, "".join(kept)
        )
    if kind != "code" or m.group("q"):
        return _keyed_value_is_hit(m, value)  # a raw string, a comment: text, as in any file
    # an unquoted value in code, after =, := or a key's ":" alike: an expression such as
    # base64.StdEncoding.EncodeToString(buf) is never a literal, Go having no bare ones, except a
    # numeric cast, judged as before (a long number cast to uint64 stays a finding); and every
    # string literal after it in the statement that is not text is judged as a quoted value
    # (prefix + "<literal>", fromHex("<literal>"), map[string]string{"k": "<literal>"})
    code = GO_CODE_VALUE_RE.match(value) and not NUMBER_CAST_RE.match(value)
    if not code and _keyed_value_is_hit(m, value):
        return True
    return any(
        not _is_go_text_literal(body) and _keyed_value_is_hit(_Quoted(body), body)
        for body in src.literals_after(lineno, m.start("val"))
    )


def _keyed_value_is_hit(m: re.Match[str], value: str) -> bool:
    if len(value) < 6:  # the pattern's own minimum, for a segment of a Go string literal
        return False
    quoted = bool(m.group("q"))
    if _is_store_ref(m.group(0)) or _is_short_number(value):
        return False
    if SECRET_VALUE_RE.match(value):  # a store reference as the value: word-like, or a finding
        return not _is_store_ref(value)
    if REFERENCE_RE.match(value) or PLACEHOLDER_RE.search(value):
        return False
    if KEYED_PLACEHOLDER_RE.search(value):
        return False
    if not quoted and CODE_REFERENCE_RE.match(value):
        return False
    if re.fullmatch(r"[a-z]+(?:[-_][a-z]+)*", value):
        return False  # a word or kebab-case name: an option value, not a secret
    if re.fullmatch(r"[A-Z(),:=]+", value):
        return False  # an all-caps rule such as a sudoers spec (ALL=(ALL)), not a secret
    return len(set(value)) > 3  # 'xxxxxx', '000000' are fillers


# Variable names a product itself defines and the roles must set or reserve: naming them says
# nothing about this lab.  Each entry is reviewed; a lab's own API-key variable names stay findings.
PRODUCT_SECRET_NAMES = frozenset(
    {
        "VLLM_API_KEY",  # vLLM's server key, written by the vllm_server role
        "IMAGES_OPENAI_API_KEY",  # an Open WebUI setting the open_webui role reserves
    }
)


def _is_hit_secret_name(m: re.Match[str], _line: str, _path: str = "") -> bool:
    return m.group(0) not in PRODUCT_SECRET_NAMES


def _p(
    name: str,
    group: str,
    rx: str,
    why: str,
    *,
    redact: bool = False,
    accept: Callable[[re.Match[str], str, str], bool] | None = None,
    flags: int = 0,
) -> Pattern:
    return Pattern(name, group, re.compile(rx, flags), why, redact, accept)


# NOTE: regexes are written so that this file does not match itself (character classes
# break up the literal tokens).  tools/tests/test_leak_scan.py asserts a clean self-scan.
PATTERNS: tuple[Pattern, ...] = (
    _p(
        "private-ipv4",
        "network",
        r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\d])",
        "RFC 1918 address; use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24",
    ),
    _p(
        "cgnat-tailnet-ipv4",
        "network",
        r"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}(?![\d])",
        "carrier-grade NAT / tailnet address",
    ),
    _p(
        "public-ipv4",
        "network",
        r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d|\w)",
        "public IPv4 address; use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24",
        accept=_is_hit_public_ipv4,
    ),
    _p(
        "ipv6-nondoc",
        "network",
        r"(?<![0-9A-Fa-f:])(?!2001:0?db8:)(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])",
        "full IPv6 address outside 2001:db8::/32",
    ),
    _p(
        "ipv6-compressed",
        "network",
        r"(?<![\w:.])(?=[0-9A-Fa-f:]*::)[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:.])",
        "compressed IPv6 address outside 2001:db8::/32, 3fff::/20, ::1 and ::",
        accept=_is_hit_ipv6_compressed,
    ),
    _p(
        "ipv6-ula",
        "network",
        r"(?<![0-9A-Fa-f:])f[cd][0-9A-Fa-f]{2}:[0-9A-Fa-f:]{2,}",
        "IPv6 unique-local address",
    ),
    _p(
        "mac-address",
        "network",
        r"(?<![0-9A-Fa-f:.-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])",
        "MAC address; documentation range is 00:00:5e:00:53:xx",
        accept=_is_hit_mac,
    ),
    _p(
        "email",
        "identity",
        shapes.EMAIL,
        "e-mail outside example domains / users.noreply.github.com",
        accept=_is_hit_email,
    ),
    _p(
        "private-tld",
        "network",
        r"(?<![\w-])(?P<label>[\w-]+)\.(?P<tld>lan|home|local|internal|corp|localdomain|home\.arpa|ts\.net|cloudflareaccess\.com|pages\.dev)"
        r"(?![\w-]|\.(?:json|ya?ml|toml|py|md|txt|cfg|conf|env|sh|j2)\b)",
        "private or lab-specific TLD; use example.internal",
        accept=_is_hit_tld,
    ),
    _p(
        "workstation-path",
        "path",
        r"/mnt/[a-z]/User[s]/|\b[A-Z]:\\User[s]\\|(?<![\w.])/User[s]/[\w.-]+|\bid_(?:rsa|ecdsa|ed2551[9])\b(?!\.pub)",
        "personal workstation path or private-key file name",
    ),
    _p(
        "secret-name",
        "secret",
        r"\bvault_[a-z0-9_]+\b|\bANTHROPIC_[A-Z_]+\b|\b[A-Z0-9_]*_API_KE[Y]\b",
        "secret variable name (Ansible vault_ convention, provider keys)",
        accept=_is_hit_secret_name,
    ),
    _p(
        "keyed-secret",
        "secret",
        r"(?i)(?<![\w.:/-])[\w-]*(?:passw|secret|token(?!iz))[\w-]*(?P<q1>[\"']?)\s*(?::=|[:=])\s*(?P<q>[\"']?)(?P<val>[^\s\"',;)}\]]{6,})",
        "literal value assigned to a password/secret/token key",
        redact=True,
        accept=_is_hit_keyed_value,
    ),
    _p(
        "aws-access-key",
        "secret",
        shapes.AWS_ACCESS_KEY,
        "AWS access key id",
        redact=True,
    ),
    _p(
        "aws-secret-key",
        "secret",
        r"(?i)aws_?secret_?access_?key\W{1,4}[A-Za-z0-9/+=]{40}\b",
        "AWS secret access key",
        redact=True,
    ),
    _p(
        "aws-account-id",
        "identity",
        r"(?i)account\W{0,12}(?P<num>\d{12})\b",
        "12-digit account id next to the word 'account' (documentation id is 123456789012)",
        accept=_is_hit_aws_account,
    ),
    _p(
        "private-key-block",
        "secret",
        shapes.PRIVATE_KEY_HEADER,
        "PEM private key",
        redact=True,
    ),
    _p("vault-blob", "secret", r"[$]ANSIBLE_VAUL[T]", "encrypted vault blob", redact=True),
    _p(
        "age-secret-key",
        "secret",
        r"AGE-SECRET-KE[Y]-1[0-9A-Z]{58}",
        "age identity (private key): it decrypts every SOPS file sealed to it",
        redact=True,
    ),
    _p(
        "github-token",
        "secret",
        shapes.GITHUB_TOKEN,
        "GitHub token",
        redact=True,
    ),
    _p("slack-token", "secret", shapes.SLACK_TOKEN, "Slack token", redact=True),
    _p("google-api-key", "secret", shapes.GOOGLE_KEY, "Google API key", redact=True),
    _p(
        "jwt",
        "secret",
        shapes.JWT,
        "JSON web token",
        redact=True,
    ),
    _p(
        "gpu-uuid",
        "identity",
        r"\bGPU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "GPU UUID fingerprints hardware",
    ),
    _p(
        "detection-rule-number",
        "identity",
        r"(?i)\b(?:rule|sid|id)\b\W.{0,40}?\b(?P<num>1\d{5})\b",
        "engine rule number; cite a logical det: id (examples use 9000xx)",
        accept=_is_hit_rule_number,
    ),
    _p(
        "employer-term",
        "identity",
        r"(?i)\b(?:[t]ax clients?|[p]ayroll|my [e]mployer|day [j]ob)\b",
        "personal/employer context",
    ),
    _p(
        "high-entropy-string",
        "secret",
        r"(?<![\w/+=-])(?P<tok>[A-Za-z0-9+/_=-]{24,})(?![\w/+=-])",
        "high-entropy string that looks like a credential",
        redact=True,
        accept=_is_hit_entropy,
    ),
    _p(
        "lowercase-entropy-string",
        "secret",
        r"(?<![\w/+=.-])(?P<tok>[a-z0-9]{20,})(?![\w/+=-])",
        "random-looking lowercase/digit token (many API keys use this alphabet)",
        redact=True,
        accept=_is_hit_lower_entropy,
    ),
    _p(
        "hex-secret",
        "secret",
        r"(?<![\w/+=-])(?P<tok>[0-9a-fA-F]{32,})(?![\w/+=-])",
        "long hex value next to a credential word (not a digest or commit)",
        redact=True,
        accept=_is_hit_hex_secret,
    ),
)


class ConfigError(Exception):
    """Misconfiguration (exit 2)."""


def load_denylist(path: str | None) -> list[tuple[int, re.Pattern[str]]]:
    """Return ``[(line_number, regex)]``; raises ConfigError when unusable."""
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"deny-list not found: {path}")
    try:
        terms = shapes.compile_denylist(p.read_text(encoding="utf-8").splitlines())
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if not terms:
        raise ConfigError(f"deny-list is empty: {path} (an empty list would pass everything)")
    return terms


def _display(p: Pattern, text: str) -> str:
    if p.redact:
        return text[:4] + "..." + f"({len(text)} chars)"
    return text if len(text) <= 80 else text[:77] + "..."


def scan_text(
    text: str,
    label: str,
    patterns: Iterable[Pattern] = PATTERNS,
    denylist: list[tuple[int, re.Pattern[str]]] | None = None,
    suppressed: list[str] | None = None,
    path: str | None = None,
) -> list[Hit]:
    """Hits in ``text``; ``path`` (default: ``label``) is the file name some patterns read."""
    hits: list[Hit] = []
    pats = list(patterns)
    path = label if path is None else path
    if path.startswith("<"):  # <stdin>: not a file
        path = ""
    go_src = GoSource(text) if path.endswith(".go") else None
    try:
        for lineno, line in enumerate(text.splitlines(), 1):
            _GO_CONTEXT[:] = [(go_src, lineno)] if go_src else []
            _scan_line(hits, label, lineno, line, pats, denylist, suppressed, path)
    finally:
        _GO_CONTEXT.clear()
    return hits


def _scan_line(
    hits: list[Hit],
    label: str,
    lineno: int,
    line: str,
    pats: list[Pattern],
    denylist: list[tuple[int, re.Pattern[str]]] | None,
    suppressed: list[str] | None,
    path: str,
) -> None:
    """The hits of one line of ``scan_text``, appended to ``hits``."""
    sup = SUPPRESS_RE.search(line)
    cut = sup.start() if sup else len(line)
    allowed: list[str] = []
    for pat in pats:
        for m in pat.regex.finditer(line):
            if pat.accept is not None and not pat.accept(m, line, path):
                continue
            hit = Hit(label, lineno, pat.name, _display(pat, m.group(0)))
            # a reviewed line may waive what lies before its marker, never a credential
            if sup and pat.group != "secret" and m.end() <= cut:
                allowed.append(pat.name)
            else:
                hits.append(hit)
    for idx, rx in denylist or []:
        m = rx.search(line)
        if m:
            # deny-list terms are never waived: the list exists because they must not ship
            hits.append(Hit(label, lineno, "denylist", f"term on deny-list line {idx}"))
    if allowed and suppressed is not None:
        names = ", ".join(sorted(set(allowed)))
        suppressed.append(
            f"{label}:{lineno}: suppressed {len(allowed)} hit(s) [{names}]: "
            f"{sup.group('reason').strip()}"
        )


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, check=False)


def _git_files(directory: Path) -> list[Path] | None:
    """Files under ``directory`` that git tracks or would track; None outside a work tree."""
    try:
        inside = _git(directory, "rev-parse", "--is-inside-work-tree")
    except OSError:  # git is not installed
        return None
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        return None
    out = _git(directory, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".")
    if out.returncode != 0:
        return None
    names = sorted({n for n in out.stdout.decode("utf-8", "surrogateescape").split("\0") if n})
    return [directory / n for n in names]


def iter_files(paths: Iterable[str]) -> Iterator[Path]:
    for raw in paths:
        p = Path(raw)
        if not p.exists() and not p.is_symlink():
            raise ConfigError(f"path does not exist: {raw}")
        if not p.is_dir() or p.is_symlink():
            yield p
            continue
        tracked = _git_files(p)
        if tracked is not None:
            for f in tracked:
                if f.exists() or f.is_symlink():  # deleted-but-tracked files are skipped
                    yield f
            continue
        for root, dirs, files in os.walk(p):
            at_root = Path(root) == p
            dirs[:] = sorted(
                d
                for d in dirs
                if d not in SKIP_DIRS_ANYWHERE and not (at_root and d in SKIP_DIRS_AT_ROOT)
            )
            for name in sorted(files):
                if name == ".git":  # worktree pointer file
                    continue
                yield Path(root) / name


def decode(data: bytes) -> str | None:
    """Text of ``data``, or None when it is binary.  UTF-16/32 need their byte-order mark."""
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return data.decode("utf-32", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8-sig", errors="replace")


def read_text_file(path: Path) -> str | Skipped:
    """Text to scan, or why the file could not be scanned."""
    try:
        if path.is_symlink():
            return os.readlink(path)  # never follow: the target path itself is the content
        if path.stat().st_size > MAX_BYTES:
            return Skipped(str(path), f"larger than {MAX_BYTES // (1024 * 1024)} MB")
        data = path.read_bytes()
    except OSError as exc:
        return Skipped(str(path), f"unreadable ({exc.__class__.__name__})")
    text = decode(data)
    if text is None:
        return Skipped(str(path), "binary (NUL byte)")
    return text


def _allowed_skip(path: str, globs: Iterable[str]) -> bool:
    posix = Path(path).as_posix()
    return any(fnmatch.fnmatch(posix, g) or fnmatch.fnmatch(Path(path).name, g) for g in globs)


def scan_paths(
    paths: Iterable[str],
    patterns: Iterable[Pattern] = PATTERNS,
    denylist: list[tuple[int, re.Pattern[str]]] | None = None,
    suppressed: list[str] | None = None,
    skipped: list[Skipped] | None = None,
    allow_skip: Iterable[str] = (),
) -> list[Hit]:
    hits: list[Hit] = []
    pats = list(patterns)
    globs = list(allow_skip)
    for f in iter_files(paths):
        text = read_text_file(f)
        if isinstance(text, Skipped):
            if skipped is not None and not _allowed_skip(text.path, globs):
                skipped.append(text)
            continue
        hits.extend(scan_text(text, str(f), pats, denylist, suppressed))
    return hits


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")


def scan_history(
    rev_range: str,
    patterns: Iterable[Pattern],
    denylist: list[tuple[int, re.Pattern[str]]] | None = None,
    cwd: Path | None = None,
) -> list[Hit]:
    """Scan the lines every commit in ``rev_range`` added.  Labels are ``<sha>:<path>``.

    Suppression markers are not honoured here: history cannot be reviewed line by line, and a
    marker that hid a value then hides nothing now that the value is permanent.
    """
    out = _git(
        cwd or Path.cwd(),
        "log",
        "-p",
        "--no-color",
        "--no-ext-diff",
        "--no-renames",
        "--format=commit %H",
        rev_range,
    )
    if out.returncode != 0:
        raise ConfigError(f"git log {rev_range!r} failed: {out.stderr.decode(errors='replace')}")
    pats = list(patterns)
    hits: list[Hit] = []
    sha, path, lineno = "?", "?", 0
    for raw in out.stdout.decode("utf-8", "replace").splitlines():
        if raw.startswith("commit ") and len(raw) == 47:
            sha = raw[7:19]
        elif raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else raw[4:]
        elif raw.startswith("@@ "):
            m = HUNK_RE.match(raw)
            lineno = int(m.group(1)) if m else 0
        elif raw.startswith("+"):
            for h in scan_text(raw[1:], f"{sha}:{path}", pats, denylist, path=path):
                hits.append(Hit(h.path, lineno, h.pattern, h.shown))
            lineno += 1
        elif raw.startswith(" "):
            lineno += 1
    return hits


def check_authors(rev_range: str, cwd: Path | None = None) -> list[str]:
    """Author and committer e-mails in ``rev_range`` that are not GitHub noreply addresses."""
    out = _git(cwd or Path.cwd(), "log", "--format=%h %ae%n%h %ce", rev_range)
    if out.returncode != 0:
        raise ConfigError(f"git log {rev_range!r} failed: {out.stderr.decode(errors='replace')}")
    bad: list[str] = []
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        sha, _, email = line.partition(" ")
        if email and not (
            NOREPLY_COMMIT_RE.match(email) or email.lower() in ALLOWED_EMAIL_ADDRESSES
        ):
            bad.append(f"{sha}: identity is not a noreply address ({email.split('@')[-1]})")
    return sorted(set(bad))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generic public-repo leak scanner")
    ap.add_argument("paths", nargs="*", help="files or directories (default: .)")
    ap.add_argument("--stdin", action="store_true", help="scan standard input (commit messages)")
    ap.add_argument(
        "--history",
        metavar="RANGE",
        help="scan lines added by the commits in RANGE (default groups: network,identity)",
    )
    ap.add_argument(
        "--check-authors",
        metavar="RANGE",
        help="fail on author/committer e-mails in RANGE that are not GitHub noreply addresses",
    )
    ap.add_argument(
        "--denylist",
        default=os.environ.get("HNX_DENYLIST"),
        help="file of extra terms (default: env HNX_DENYLIST)",
    )
    ap.add_argument("--groups", default="", help="comma list: network,identity,path,secret")
    ap.add_argument(
        "--allow-skip",
        action="append",
        default=[],
        metavar="GLOB",
        help="a file matching GLOB may be skipped (binary/large) without failing the run",
    )
    ap.add_argument("--list", action="store_true", help="print the built-in patterns and exit")
    args = ap.parse_args(argv)

    if args.list:
        for p in PATTERNS:
            print(f"{p.name:24} [{p.group}] {p.why}")
        return EXIT_CLEAN

    patterns: list[Pattern] = list(PATTERNS)
    groups = args.groups or (",".join(DEFAULT_HISTORY_GROUPS) if args.history else "")
    if groups:
        wanted = {g.strip() for g in groups.split(",") if g.strip()}
        known = {p.group for p in PATTERNS}
        if not wanted <= known:
            print(f"leak_scan: unknown group(s): {sorted(wanted - known)}", file=sys.stderr)
            return EXIT_CONFIG
        patterns = [p for p in patterns if p.group in wanted]

    suppressed: list[str] = []
    skipped: list[Skipped] = []
    problems: list[str] = []
    try:
        denylist = load_denylist(args.denylist)
        if args.check_authors:
            problems = check_authors(args.check_authors)
            hits = []
        elif args.history:
            hits = scan_history(args.history, patterns, denylist)
        elif args.stdin:
            hits = scan_text(sys.stdin.read(), "<stdin>", patterns, denylist, suppressed)
        else:
            hits = scan_paths(
                args.paths or ["."], patterns, denylist, suppressed, skipped, args.allow_skip
            )
    except ConfigError as exc:
        print(f"leak_scan: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    for s in suppressed:
        print(f"note: {s}")
    for h in hits:
        print(f"{h.path}:{h.line}: [{h.pattern}] {h.shown}")
    for sk in skipped:
        print(f"{sk.path}: [not-scanned] {sk.reason} (allow it with --allow-skip if intended)")
    for msg in problems:
        print(msg)
    failures = len(hits) + len(skipped) + len(problems)
    if failures:
        print(
            f"leak_scan: {len(hits)} hit(s), {len(skipped)} unscanned file(s), "
            f"{len(problems)} commit identity problem(s)",
            file=sys.stderr,
        )
        return EXIT_HIT
    print("leak_scan: clean")
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
