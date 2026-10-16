#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CI gate: no raw endpoints in code or config.

Endpoints are looked up through the service registry (capability alias), never
written as literals. This scans a tree for:

  ipv4        any IPv4 address literal (0.0.0.0 bind-all is exempt)
  localhost   ``localhost:<port>`` / ``localhost`` inside a URL with a port
  url-port    ``scheme://host:port`` with a literal host and explicit port
  host-port   ``name.<internal-ish tld>:<port>`` outside a URL

A finding is suppressed only by (a) a path glob in the allowlist file, each with
a mandatory ``reason``, or (b) an inline ``no-raw-endpoint: allow <reason>``
comment on the same line. Census mode prints counts instead of failing.

Usage:
  python tools/no_raw_endpoints.py [ROOT] [--allowlist FILE] [--census] [--json]
Exit: 0 clean (or census), 1 violations, 2 usage / bad allowlist.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

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
    if path is None or not path.is_file():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = doc.get("allow", [])
    out = []
    if not isinstance(entries, list):
        raise AllowlistError(f"{path}: 'allow' must be a list")
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not str(e.get("path", "")).strip():
            raise AllowlistError(f"{path}: entry {i} needs a 'path' glob")
        if not str(e.get("reason", "")).strip():
            raise AllowlistError(
                f"{path}: entry {i} ({e['path']}) has no 'reason'; every exemption must say why"
            )
        out.append((str(e["path"]), str(e["reason"]).strip()))
    return out


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
            if VERSIONISH.search(line[: m.start()]):
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


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    ap = argparse.ArgumentParser(
        description="Fail on raw IP/host:port literals outside the allowlist."
    )
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument(
        "--allowlist", default=None, help=f"allowlist file (default: <root>/{DEFAULT_ALLOWLIST})"
    )
    ap.add_argument("--census", action="store_true", help="print counts, always exit 0")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"no_raw_endpoints: {root} is not a directory", file=err)
        return 2
    al_path = Path(args.allowlist) if args.allowlist else root / DEFAULT_ALLOWLIST
    if args.allowlist and not al_path.is_file():
        print(f"no_raw_endpoints: allowlist {al_path} not found", file=err)
        return 2
    try:
        allow = load_allowlist(al_path)
    except (AllowlistError, yaml.YAMLError) as exc:
        print(f"no_raw_endpoints: bad allowlist: {exc}", file=err)
        return 2
    findings, scanned = scan_tree(root, allow)
    if args.census:
        by_rule = Counter(f.rule for f in findings)
        by_file = Counter(f.path for f in findings)
        doc = {
            "scanned_files": scanned,
            "total": len(findings),
            "by_rule": dict(sorted(by_rule.items())),
            "by_file": dict(sorted(by_file.items())),
        }
        print(
            json.dumps(doc, indent=2, sort_keys=True)
            if args.json
            else f"raw endpoints: {len(findings)} in {len(by_file)} files ({scanned} files scanned) "
            + " ".join(f"{k}={v}" for k, v in sorted(by_rule.items())),
            file=out,
        )
        return 0
    if args.json:
        print(
            json.dumps(
                {"scanned_files": scanned, "findings": [f.as_dict() for f in findings]}, indent=2
            ),
            file=out,
        )
    else:
        for f in findings:
            print(
                f"{f.path}:{f.line}: [{f.rule}] raw endpoint {f.text!r}; use a registry capability or add an allowlist entry with a reason",
                file=err,
            )
        print(f"no_raw_endpoints: {len(findings)} violation(s), {scanned} files scanned", file=out)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
