#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: workstation-refs
#   kind: check
#   purpose: Fail when a runtime config, role, compose file, example or golden output points at the admin workstation.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:workstation-lint]
#   invariant: [F-17]
#   inputs: runtime configs (ansible, compose, examples, generators, conformance targets, goldens)
#   outputs: one line per workstation-shaped reference or stale allowlist entry
#   exit:
#     "0": clean
#     "1": a workstation reference or a stale allowlist entry
#     "2": usage error or a missing dependency
"""Gate (checklist F-17): nothing at runtime points at the admin workstation.

The fleet must keep running with the workstation switched off (F-16), so no runtime
configuration may depend on it. This scans what ends up running on the fleet -- Ansible roles,
playbooks and inventory, compose stacks, the example lab and the orchestrator's examples, the
generator manifest and templates,
conformance targets and the generated golden outputs under ``tests/**/golden/`` -- for:

  home-path         a personal home directory: ``/home/<user>``, ``~/``, ``~user/``, ``$HOME``,
                    ``${HOME}``, ``%USERPROFILE%`` (a service has a state directory, not a login)
  workstation-path  the leak scanner's workstation shapes (``/Users/<name>``, ``C:\\Users\\``,
                    ``/mnt/<drive>/Users/``, a private-key file name such as ``id_<keytype>``)
  workstation-host  a host named like a person's machine (``*workstation*``, ``*laptop*``,
                    ``*desktop*``)
  control-node      a role step that runs on whatever machine ran Ansible: ``delegate_to:
                    localhost`` (or the loopback address), ``local_action``, ``connection: local``, and
                    ``hosts: localhost`` in a playbook

Comments (``#`` to end of line) are not configuration and are skipped; ``localhost:<port>``
endpoints are X-01's job (the no-raw-endpoints gate), which this gate runs beside. A reviewed
exception is an entry in ``tools/workstation_refs.allow.yml`` (``path`` glob, optional ``match``
regex limiting it to the lines it excuses, ``reason``) or an inline ``workstation-ref: allow
<reason>`` comment on the line. An allowlist entry that excuses nothing is reported as stale.

Usage: python tools/workstation_refs.py [ROOT] [--allowlist FILE] [--json]
Exit: 0 clean, 1 workstation references (or a stale allowlist entry), 2 usage / bad allowlist.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leak_scan  # the scanner's workstation-path shape is reused, not copied

DEFAULT_ALLOWLIST = "tools/workstation_refs.allow.yml"
INLINE_ALLOW = re.compile(r"workstation-ref:\s*allow\s+\S")
# what runs on the fleet (generated output included); docs and library code are not runtime config
SCOPE = (
    "ansible/**",
    "compose/**",
    "examples/**",
    # the orchestration controller's example config, profiles and prompts (installed as-is)
    "orchestrator/examples/**",
    "generators/**",
    "homelabnext/generators/templates/**",
    "conformance/targets/**",
    "tests/**/golden/**",
)
SKIP_SUFFIXES = (".md", ".pyc")
MAX_BYTES = 2_000_000

_WS_PATH = next(p.regex for p in leak_scan.PATTERNS if p.name == "workstation-path")
RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "home-path",
        re.compile(
            r"(?<![\w.~-])/home/[A-Za-z_][\w.-]*"
            r"|(?<![\w~/])~[A-Za-z_][\w-]*/|(?<![\w~/$])~/"
            r"|\$HOME\b|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%"
        ),
        "personal home directory; give the service its own state directory",
    ),
    ("workstation-path", _WS_PATH, "workstation path or private-key file name"),
    (
        "workstation-host",
        re.compile(r"(?i)(?<![\w-])[\w-]*(?:workstation|laptop|desktop)[\w-]*(?:\.[\w-]+)*"),
        "names a person's machine; runtime may only name fleet hosts and registry aliases",
    ),
)
CONTROL_NODE = re.compile(
    r"^\s*(?:-\s+)?(?:"
    r"delegate_to\s*:\s*[\"']?(?:localhost|127\.0\.0\.1)[\"']?\s*$"
    r"|local_action\s*:"
    r"|(?:ansible_)?connection\s*:\s*[\"']?local[\"']?\s*$"
    r"|hosts\s*:\s*[\"']?(?:localhost|127\.0\.0\.1)[\"']?\s*$"
    r")"
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


def _strip_comment(line: str) -> str:
    """Drop a ``#`` comment (whole line, or after whitespace); keep ``#`` inside a token."""
    if line.lstrip().startswith("#"):
        return ""
    m = re.search(r"\s#", line)
    return line[: m.start()] if m else line


def scan_text(rel: str, text: str) -> list[Finding]:
    found: list[Finding] = []
    ansible = rel.startswith("ansible/") and rel.endswith((".yml", ".yaml"))
    for n, raw in enumerate(text.splitlines(), 1):
        if INLINE_ALLOW.search(raw):
            continue
        line = _strip_comment(raw)
        if not line.strip():
            continue
        for rule, rx, _ in RULES:
            for m in rx.finditer(line):
                found.append(Finding(rel, n, rule, m.group(0)))
        if ansible and CONTROL_NODE.search(line):
            found.append(Finding(rel, n, "control-node", line.strip()))
    return found


def load_allowlist(path: Path | None) -> list[tuple[str, re.Pattern[str] | None, str]]:
    if path is None or not path.is_file():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = doc.get("allow", [])
    if not isinstance(entries, list):
        raise AllowlistError(f"{path}: 'allow' must be a list")
    out = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not str(e.get("path", "")).strip():
            raise AllowlistError(f"{path}: entry {i} needs a 'path' glob")
        if not str(e.get("reason", "")).strip():
            raise AllowlistError(f"{path}: entry {i} ({e['path']}) has no 'reason'")
        try:
            match = re.compile(str(e["match"])) if e.get("match") else None
        except re.error as exc:
            raise AllowlistError(f"{path}: entry {i} has a bad 'match' regex: {exc}") from None
        out.append((str(e["path"]), match, str(e["reason"]).strip()))
    return out


def _glob(rel: str, g: str) -> bool:
    if fnmatch.fnmatchcase(rel, g):
        return True
    return g.endswith("/**") and rel.startswith(g[:-2])


def in_scope(rel: str) -> bool:
    if rel.endswith(SKIP_SUFFIXES) or "/__pycache__/" in f"/{rel}":
        return False
    return any(_glob(rel, g) for g in SCOPE)


def scan(root: Path, allow) -> tuple[list[Finding], list[str], int]:
    findings: list[Finding] = []
    used: set[int] = set()
    n = 0
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or p.is_symlink() or not in_scope(rel):
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:4096]:
            continue
        n += 1
        lines = data.decode("utf-8", errors="replace").splitlines()
        for f in scan_text(rel, "\n".join(lines)):
            hit = [
                i
                for i, (g, match, _) in enumerate(allow)
                if _glob(rel, g) and (match is None or match.search(lines[f.line - 1]))
            ]
            if hit:
                used.update(hit)
            else:
                findings.append(f)
    stale = [g for i, (g, _, _) in enumerate(allow) if i not in used]
    return findings, stale, n


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--allowlist", help=f"default: <root>/{DEFAULT_ALLOWLIST}")
    ap.add_argument("--json", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    root = Path(args.root).resolve()
    al = Path(args.allowlist) if args.allowlist else root / DEFAULT_ALLOWLIST
    if args.allowlist and not al.is_file():
        print(f"workstation_refs: allowlist {al} not found", file=err)
        return 2
    try:
        allow = load_allowlist(al)
    except (AllowlistError, yaml.YAMLError) as exc:
        print(f"workstation_refs: bad allowlist: {exc}", file=err)
        return 2
    findings, stale, n = scan(root, allow)
    why = {rule: text for rule, _, text in RULES}
    why["control-node"] = "runs on the machine that ran Ansible; target a fleet host"
    if args.json:
        doc = {"scanned_files": n, "findings": [f.as_dict() for f in findings], "stale": stale}
        print(json.dumps(doc, indent=2), file=out)
    else:
        for f in findings:
            print(f"{f.path}:{f.line}: [{f.rule}] {f.text!r}: {why[f.rule]}", file=err)
        for s in stale:
            print(f"workstation_refs: stale allowlist entry {s}: excuses nothing", file=err)
        print(
            f"workstation_refs: {len(findings)} workstation reference(s), {len(stale)} stale "
            f"allowlist entr{'y' if len(stale) == 1 else 'ies'}, {n} runtime files scanned",
            file=out,
        )
    return 1 if findings or stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
