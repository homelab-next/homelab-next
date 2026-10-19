# SPDX-License-Identifier: Apache-2.0
"""Id allocation and loss detection for YAML registers.

  hnx ids alloc REGISTER [--prefix LL] [-n N]
  hnx ids resolve PATH...        rewrite XX-NEW placeholders (exit 3 if it changed anything)
  hnx ids check-lost PATH... [--base REV]
                                 fail if a parent commit's (or REV's) id vanished (exit 1)
  hnx ids check-dupes PATH...    fail if an allocated id occurs twice (exit 1)

Contributors commit `XX-NEW`; `check-lost` and `check-dupes` run in the pre-commit hook and in CI
against the pull request's base.  A maintainer runs `resolve` once, at merge time, on the target
branch (`make ids-resolve`), so two pull requests never claim the same number.
tools/register_ids.py is a thin wrapper.
"""

import argparse
import pathlib
import sys

from . import ids

EXPLAIN = """An id a parent commit HAD is missing from {path}: {lost}.
Ids are append-only here, so this is not an edit. Likely a merge conflict resolved inside an
entry body, producing one record with one entry's head and another's tail. Recover with
`git show MERGE_HEAD:{path}` (or HEAD) and re-append the entry whole; never renumber to
silence this. A deliberate consolidation: REGISTER_IDS_ALLOW_DROP={lost} git commit ...
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hnx ids", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("alloc")
    a.add_argument("register")
    a.add_argument("--prefix")
    a.add_argument("-n", type=int, default=1)
    r = sub.add_parser("resolve")
    r.add_argument("paths", nargs="+")
    r.add_argument("--dry-run", action="store_true")
    c = sub.add_parser("check-lost")
    c.add_argument("paths", nargs="+")
    c.add_argument("--base", help="compare with this revision only (CI: the PR base commit)")
    d = sub.add_parser("check-dupes")
    d.add_argument("paths", nargs="+")
    ns = ap.parse_args(argv)
    try:
        root = ids.repo_root()
        if ns.cmd == "alloc":
            spec = ids.spec_for(ns.register)
            if spec is None:
                raise ids.IdError(f"{ns.register}: unknown register kind")
            prefix = ns.prefix or (spec.prefixes[0] if len(spec.prefixes) == 1 else None)
            if prefix is None:
                raise ids.IdError(f"{ns.register} has several prefixes; pass --prefix")
            print("\n".join(ids.allocate(root, ns.register, prefix, ns.n)))
            return 0
        rels = [pathlib.Path(p).resolve().relative_to(root).as_posix() for p in ns.paths]
        if ns.cmd == "resolve":
            changed = False
            for rel in rels:
                for old, new in ids.resolve_file(root, rel, ns.dry_run):
                    changed = True
                    print(f"[register-ids] {rel}: {old} -> {new}")
            return 3 if changed else 0
        bad = False
        if ns.cmd == "check-dupes":
            for rel in rels:
                spec = ids.spec_for(rel)
                if spec is None:
                    continue
                dupes = ids.duplicates((root / rel).read_text(), spec)
                if dupes:
                    bad = True
                    print(
                        f"[register-ids] FATAL: {rel} repeats {', '.join(dupes)}", file=sys.stderr
                    )
            return 1 if bad else 0
        for rel in rels:
            lost = ids.check_lost(root, rel, base=ns.base)
            if lost:
                bad = True
                print(f"[register-ids] FATAL: {rel} lost {', '.join(lost)}", file=sys.stderr)
                print(EXPLAIN.format(path=rel, lost=",".join(lost)), file=sys.stderr)
        return 1 if bad else 0
    except ids.IdError as ex:
        print(f"[register-ids] FATAL: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
