#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generic public-repository leak scanner.

Scans text files for *shapes* of data that must never be published: private and
carrier-grade-NAT IPv4 addresses, non-documentation IPv6, MAC addresses, e-mail
addresses outside documentation domains, private TLDs, hypervisor-style host names,
workstation paths, secret-looking variable names, cloud keys, PEM blocks, API tokens
and high-entropy strings.  It knows no real identifiers.  An optional deny-list file
(env ``HNX_DENYLIST`` or ``--denylist``) adds literal terms or ``re:`` regexes at run
time; terms from it are never echoed back, only their line number in the file.

Exit codes: 0 clean, 1 at least one hit, 2 misconfiguration (bad path, bad deny-list).

Suppress one reviewed line with an end-of-line marker ``scrub-allow: <reason>`` (any
comment syntax).  Every suppression is printed so reviewers see it in CI logs.

Usage::

    python3 tools/leak_scan.py [PATH ...]           # default: current directory
    git log -5 --format=%B | python3 tools/leak_scan.py --stdin
    python3 tools/leak_scan.py --list               # show the built-in patterns
    python3 tools/leak_scan.py --groups secret .    # only one group of patterns
"""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

EXIT_CLEAN = 0
EXIT_HIT = 1
EXIT_CONFIG = 2

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".tox",
}
MAX_BYTES = 5 * 1024 * 1024
SUPPRESS_RE = re.compile(r"scrub-allow:\s*(\S.*)$")

# Documentation / reserved values that are always acceptable.
DOC_MAC_PREFIX = "00:00:5e:00:53:"
ALLOWED_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "example.internal",
    "users.noreply.github.com",
)
# Exact addresses (not domains) that are public by construction, e.g. co-author trailers.
ALLOWED_EMAIL_ADDRESSES = ("noreply@anthropic.com",)


@dataclass(frozen=True)
class Pattern:
    name: str
    group: str  # network | identity | path | secret
    regex: re.Pattern[str]
    why: str
    redact: bool = False
    accept: Callable[[re.Match[str], str], bool] | None = None  # True => it IS a hit


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    pattern: str
    shown: str


def _entropy(token: str) -> float:
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_hit_mac(m: re.Match[str], _line: str) -> bool:
    text = m.group(0).lower().replace("-", ":")
    return not text.startswith(DOC_MAC_PREFIX)


def _is_hit_email(m: re.Match[str], _line: str) -> bool:
    if m.group(0).lower() in ALLOWED_EMAIL_ADDRESSES:
        return False
    domain = m.group("domain").lower()
    return not any(domain == d or domain.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS)


def _is_hit_tld(m: re.Match[str], _line: str) -> bool:
    # example.internal (and anything beneath it) is the documented placeholder.
    return not (m.group("tld") == "internal" and m.group("label").lower() == "example")


def _is_hit_aws_account(m: re.Match[str], _line: str) -> bool:
    return m.group("num") != "123456789012"


def _is_hit_rule_number(m: re.Match[str], _line: str) -> bool:
    return not m.group("num").startswith("9000")


# The one commit-trailer shape that is public by construction: a session link, nothing else on
# the line.  Anchored on both ends so it cannot be used to smuggle other content past the scan.
SESSION_TRAILER_RE = re.compile(
    r"^Claude-Session: https://claude\.ai/code/session_[A-Za-z0-9]+\s*$"
)


def _is_hit_entropy(m: re.Match[str], line: str) -> bool:
    if SESSION_TRAILER_RE.match(line):
        return False
    token = m.group("tok")
    if re.fullmatch(r"[0-9a-fA-F]+", token):  # hex digests / commit SHAs
        return False
    if token.startswith(("http", "www.")) or token.count("/") > 2:
        return False
    if not (re.search(r"[a-z]", token) and re.search(r"[A-Z]", token) and re.search(r"\d", token)):
        return False
    ent = _entropy(token)
    keyed = re.search(r"(?i)(secret|token|passw|api[_-]?key|credential|auth|private)", line)
    return ent >= (4.0 if keyed else 4.5)


def _p(
    name: str,
    group: str,
    rx: str,
    why: str,
    *,
    redact: bool = False,
    accept: Callable[[re.Match[str], str], bool] | None = None,
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
        "ipv6-nondoc",
        "network",
        r"(?<![0-9A-Fa-f:])(?!2001:0?db8:)(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])",
        "full IPv6 address outside 2001:db8::/32",
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
        r"[\w.+-]+@(?P<domain>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b",
        "e-mail outside example domains / users.noreply.github.com",
        accept=_is_hit_email,
    ),
    _p(
        "private-tld",
        "network",
        r"(?<![\w-])(?P<label>[\w-]+)\.(?P<tld>cas[a]|lan|home|local|internal|ts\.net|cloudflareaccess\.com|pages\.dev)"
        r"(?![\w-]|\.(?:json|ya?ml|toml|py|md|txt|cfg|conf|env|sh|j2)\b)",
        "private or lab-specific TLD; use example.internal",
        accept=_is_hit_tld,
    ),
    _p(
        "hypervisor-name",
        "network",
        r"\bpm2\d{2}\b|\bproxmox-\d{3}\b",
        "instance-style hypervisor name; use hv-01",
    ),
    _p(
        "lab-path",
        "path",
        r"/opt/herme[s]\b|/home/ansibl[e]\b|/mnt/c/User[s]|\.vault[_]pass\b|\bid_ed2551[9]\b",
        "workstation or credential path",
    ),
    _p(
        "secret-name",
        "secret",
        r"\bvault_[a-z0-9_]+\b|\bANTHROPIC_[A-Z_]+\b|\b[A-Z0-9_]*_API_KE[Y]\b",
        "secret variable name",
    ),
    _p(
        "aws-access-key",
        "secret",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
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
        r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----",
        "PEM private key",
        redact=True,
    ),
    _p("vault-blob", "secret", r"[$]ANSIBLE_VAUL[T]", "encrypted vault blob", redact=True),
    _p(
        "github-token",
        "secret",
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b",
        "GitHub token",
        redact=True,
    ),
    _p("slack-token", "secret", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", "Slack token", redact=True),
    _p("google-api-key", "secret", r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API key", redact=True),
    _p(
        "jwt",
        "secret",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
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
    terms: list[tuple[int, re.Pattern[str]]] = []
    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            if raw.startswith("re:"):
                rx = re.compile(raw[3:], re.IGNORECASE)
            else:
                rx = re.compile(r"(?<![\w-])" + re.escape(raw) + r"(?![\w-])", re.IGNORECASE)
        except re.error as exc:
            raise ConfigError(f"deny-list line {lineno}: bad regex ({exc})") from exc
        terms.append((lineno, rx))
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
) -> list[Hit]:
    hits: list[Hit] = []
    pats = list(patterns)
    for lineno, line in enumerate(text.splitlines(), 1):
        sup = SUPPRESS_RE.search(line)
        found: list[Hit] = []
        for pat in pats:
            for m in pat.regex.finditer(line):
                if pat.accept is not None and not pat.accept(m, line):
                    continue
                found.append(Hit(label, lineno, pat.name, _display(pat, m.group(0))))
        for idx, rx in denylist or []:
            if rx.search(line):
                found.append(Hit(label, lineno, "denylist", f"term on deny-list line {idx}"))
        if found and sup:
            if suppressed is not None:
                suppressed.append(
                    f"{label}:{lineno}: suppressed {len(found)} hit(s): {sup.group(1).strip()}"
                )
            continue
        hits.extend(found)
    return hits


def iter_files(paths: Iterable[str]) -> Iterator[Path]:
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            raise ConfigError(f"path does not exist: {raw}")
        if p.is_file():
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                if name == ".git":  # worktree pointer file
                    continue
                yield Path(root) / name


def read_text_file(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_paths(
    paths: Iterable[str],
    patterns: Iterable[Pattern] = PATTERNS,
    denylist: list[tuple[int, re.Pattern[str]]] | None = None,
    suppressed: list[str] | None = None,
) -> list[Hit]:
    hits: list[Hit] = []
    pats = list(patterns)
    for f in iter_files(paths):
        text = read_text_file(f)
        if text is None:
            continue
        hits.extend(scan_text(text, str(f), pats, denylist, suppressed))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generic public-repo leak scanner")
    ap.add_argument("paths", nargs="*", help="files or directories (default: .)")
    ap.add_argument("--stdin", action="store_true", help="scan standard input (commit messages)")
    ap.add_argument(
        "--denylist",
        default=os.environ.get("HNX_DENYLIST"),
        help="file of extra terms (default: env HNX_DENYLIST)",
    )
    ap.add_argument("--groups", default="", help="comma list: network,identity,path,secret")
    ap.add_argument("--list", action="store_true", help="print the built-in patterns and exit")
    args = ap.parse_args(argv)

    if args.list:
        for p in PATTERNS:
            print(f"{p.name:24} [{p.group}] {p.why}")
        return EXIT_CLEAN

    patterns: list[Pattern] = list(PATTERNS)
    if args.groups:
        wanted = {g.strip() for g in args.groups.split(",") if g.strip()}
        known = {p.group for p in PATTERNS}
        if not wanted <= known:
            print(f"leak_scan: unknown group(s): {sorted(wanted - known)}", file=sys.stderr)
            return EXIT_CONFIG
        patterns = [p for p in patterns if p.group in wanted]

    suppressed: list[str] = []
    try:
        denylist = load_denylist(args.denylist)
        if args.stdin:
            hits = scan_text(sys.stdin.read(), "<stdin>", patterns, denylist, suppressed)
        else:
            hits = scan_paths(args.paths or ["."], patterns, denylist, suppressed)
    except ConfigError as exc:
        print(f"leak_scan: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    for s in suppressed:
        print(f"note: {s}")
    for h in hits:
        print(f"{h.path}:{h.line}: [{h.pattern}] {h.shown}")
    if hits:
        print(f"leak_scan: {len(hits)} hit(s)", file=sys.stderr)
        return EXIT_HIT
    print("leak_scan: clean")
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
