# SPDX-License-Identifier: Apache-2.0
"""Raw-endpoint detection, the one copy (ADR-0002): endpoints are looked up through the service
registry (capability alias), never written as literals.

Rules (:func:`scan_text`):

  ipv4        any IPv4 address literal (0.0.0.0 bind-all, a version and a record's display
              number such as ``TT 1.1.1.1`` are exempt; see RECORD_NUMBER for what counts)
  localhost   ``localhost:<port>`` / ``localhost`` inside a URL with a port
  url-port    ``scheme://host:port`` with a literal host and explicit port
  host-port   ``name.<internal-ish tld>:<port>`` outside a URL

A finding is suppressed only by (a) a path glob in the allowlist file, each with a mandatory
``reason``, or (b) an inline ``no-raw-endpoint: allow <reason>`` comment on the same line.

The CI gate ``tools/no_raw_endpoints.py`` is a command line over this module; the customization
lint and the agent home check (invariant A-14) call it directly, so an installed package checks
what CI checks.  Standard library only, except :func:`load_allowlist`, which reads YAML.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from .allowlist import entries

__all__ = [
    "DEFAULT_ALLOWLIST",
    "FOUR_PART_TYPES",
    "AllowlistError",
    "Finding",
    "iter_files",
    "load_allowlist",
    "scan_text",
    "scan_tree",
]

DEFAULT_ALLOWLIST = "tools/no_raw_endpoints.allow.yml"
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "build",  # generated output (make registers, wheels); never source
    "dist",
}
MAX_BYTES = 2_000_000
INLINE_ALLOW = re.compile(r"no-raw-endpoint:\s*allow\s+\S")

_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = re.compile(rf"(?<![\w.]){_OCT}(?:\.{_OCT}){{3}}(?![\w]|\.\d)")
# a version-ish context: "==1.2.3.4", "version 1.2.3.4", "v1.2.3.4"
VERSIONISH = re.compile(r"(?:==|>=|<=|~=|!=|\bversion\b\W{0,3}|\bv)\s*$", re.IGNORECASE)
# A record's computed display number (ADR-0019) looks like an address only with four components:
# "TT 1.1.1.1".  It is exempt only when (a) the word before it is the display prefix of a record
# type whose number can have four components -- TT (SO > OO > TO > TT), a MOE or MOP under a TO,
# a PIR three sub-PIRs deep and its SIRs; SO, OO, TO, CCIR, FFIR and RFI numbers have at most
# three, a lesson's (LL) and a runbook's (RB) one, so a dotted quad after RB, or after the word
# TO ("FORWARD TO <address>"), is an address -- and (b) every component is a sibling position,
# 1..50 (a number starts at 1; an address's 0 or 192 is no position).  tests/gates keeps FOUR_PART_TYPES equal to what the
# strategy doctrine's hierarchy allows.
FOUR_PART_TYPES = ("TT", "MOE", "MOP", "PIR", "SIR")
RECORD_NUMBER = re.compile(rf"(?<![\w-])(?:{'|'.join(FOUR_PART_TYPES)}) $")
_POSITION = re.compile(r"(?:[1-9]|[1-4]\d|50)")


def _record_number(line: str, m: re.Match) -> bool:
    """The IPv4-shaped match ``m`` is a record's display number (see RECORD_NUMBER)."""
    return bool(RECORD_NUMBER.search(line[: m.start()])) and all(
        _POSITION.fullmatch(p) for p in m.group(0).split(".")
    )


URL_PORT = re.compile(
    r"\b[a-z][a-z0-9+.-]*://(?:[^\s/@:'\"<>]+@)?(\[[0-9a-f:]+\]|[A-Za-z0-9_.-]+):(\d{1,5})\b"
)
LOCALHOST = re.compile(r"\blocalhost:(\d{1,5})\b", re.IGNORECASE)
HOST_PORT = re.compile(
    r"(?<![\w./@-])([A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*\.(?:internal|local|lan|home|corp|lab|svc|intranet)):(\d{1,5})\b"
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    text: str

    def as_dict(self) -> dict:
        return {"path": self.path, "line": self.line, "rule": self.rule, "text": self.text}


class AllowlistError(ValueError):
    pass


def load_allowlist(path: Path | None) -> list[tuple[str, str]]:
    """Return [(glob, reason)]. Every entry must carry a non-empty reason."""
    why = "; every exemption must say why"
    return [(str(e["path"]), str(e["reason"]).strip()) for e in entries(path, AllowlistError, why)]


def _allowed(rel: str, allow: list[tuple[str, str]]) -> bool:
    for glob, _ in allow:
        if fnmatch.fnmatchcase(rel, glob) or (glob.endswith("/**") and rel.startswith(glob[:-2])):
            return True
        if "**" in glob and fnmatch.fnmatchcase(rel, glob.replace("**/", "").replace("**", "*")):
            return True
    return False


def scan_text(rel: str, text: str) -> list[Finding]:
    found: list[Finding] = []
    for n, line in enumerate(text.splitlines(), 1):
        if INLINE_ALLOW.search(line):
            continue
        spans: list[tuple[int, int]] = []

        def add(rule: str, m: re.Match, spans=spans, n=n) -> None:
            spans.append(m.span())
            found.append(Finding(rel, n, rule, m.group(0)))

        for m in URL_PORT.finditer(line):
            add("url-port", m)
        for m in LOCALHOST.finditer(line):
            if not any(s <= m.start() < e for s, e in spans):
                add("localhost", m)
        for m in HOST_PORT.finditer(line):
            if not any(s <= m.start() < e for s, e in spans):
                add("host-port", m)
        for m in IPV4.finditer(line):
            if m.group(0) == "0.0.0.0":
                continue
            if VERSIONISH.search(line[: m.start()]) or _record_number(line, m):
                continue
            if any(s <= m.start() < e for s, e in spans):
                # already reported as part of a URL; still an ipv4 literal, report once under url-port
                continue
            add("ipv4", m)
    return found


def iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if any(
            part in SKIP_DIRS or part.endswith(".egg-info") for part in p.relative_to(root).parts
        ):
            continue
        if p.is_file() and not p.is_symlink():
            yield p


def scan_tree(root: Path, allow: list[tuple[str, str]]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    scanned = 0
    for p in iter_files(root):
        rel = p.relative_to(root).as_posix()
        if _allowed(rel, allow):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:4096]:
            continue
        text = data.decode("utf-8", errors="replace")
        scanned += 1
        findings.extend(scan_text(rel, text))
    return findings, scanned
