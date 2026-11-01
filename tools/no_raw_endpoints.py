#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: no-raw-endpoints
#   kind: check
#   purpose: Fail when code or config writes an endpoint literal instead of a registry lookup.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:gates]
#   invariant: [X-01]
#   inputs: the tree; tools/no_raw_endpoints.allow.yml
#   outputs: one line per violation (or a census)
#   exit:
#     "0": clean
#     "1": violations
#     "2": usage error or bad allowlist
"""CI gate: no raw endpoints in code or config.

Endpoints are looked up through the service registry (capability alias), never
written as literals. The detection is ``homelabnext.endpoints_scan`` (this is its command
line; the package's own checks call the module). It scans a tree for:

  ipv4        any IPv4 address literal (0.0.0.0 bind-all, a version and a record's display
              number such as ``TT 1.1.1.1`` are exempt; see RECORD_NUMBER for what counts)
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
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from homelabnext.endpoints_scan import (  # noqa: E402,F401  (re-exported for callers and tests)
    DEFAULT_ALLOWLIST,
    FOUR_PART_TYPES,
    AllowlistError,
    Finding,
    iter_files,
    load_allowlist,
    scan_text,
    scan_tree,
)


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
