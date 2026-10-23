# SPDX-License-Identifier: Apache-2.0
"""Loss and duplicate detection for registers (record directories and the invariants file).

  hnx ids check-lost [PATH...] [--base REV]
                                 fail if a parent commit's (or REV's) record vanished (exit 1)
  hnx ids check-dupes [PATH...]  fail if a key occurs twice, an invariant id is live and retired,
                                 or a record file is not named for its uid (exit 1)
  hnx ids check-uids [PATH...]   fail if a record file carries no canonical uid: a legacy
                                 numbered id or an XX-NEW placeholder (exit 1); check-dupes
                                 leaves such a file to it, so each defect is reported once

A PATH is a register file (invariants.yml), a record directory (lessons/, objectives/) or a
record file inside one (lessons/<uid>.md, which stands for its directory).  Without PATHs every
register git tracks or HEAD (and --base) has is checked, so a commit that only deletes a record
file is still seen.

Records are identified by uids (ADR-0019): nothing is allocated, so there is no placeholder to
resolve and no merge-time step.  `check-lost`, `check-dupes` and `check-uids` each run as a
pre-commit hook (.pre-commit-config.yaml) and in `make ids-check` (CI, with check-lost against
the pull request's base).  tools/register_ids.py is a thin wrapper.
"""

import argparse
import pathlib
import sys

from . import ids

EXPLAIN = """A record a parent commit HAD is missing from {path}: {lost}.
Records are never deleted, so this is not an edit. Likely a merge conflict resolved by keeping
one side's directory, or a rename gone wrong. Recover with `git show MERGE_HEAD:{path}` (or
HEAD) and restore the record whole. A record that was wrong is retired through its lifecycle
(a register-transition or strategy-transition intent), never deleted. A deliberate removal in a
local commit: REGISTER_IDS_ALLOW_DROP={lost} git commit ...
"""

EXPLAIN_FILE = """{path} is a single-file register: an id that was wrong is retired, not deleted --
move it to the register's top-level `retired:` block with `reason:` (and `replaced_by:`), a
tombstone check-lost counts as present.
"""

EXPLAIN_DIR = """{path} is a record directory: a deleted record file is restored with
`git checkout HEAD -- {path}/<uid>.md` (or MERGE_HEAD), with its <uid>.events/ directory.
A lost <uid>.events/<file> is an event (a review, a recurrence, a verified run, a transition):
events are append-only and never deleted; restore it with `git checkout HEAD -- {path}/<file>`.
"""

UIDS_HELP = """Every record is identified by a UUIDv7 in its front-matter `uid:` and lives in
<uid>.md. A record written before uids (a numbered `id:` such as LL-001, or an XX-NEW
placeholder) is migrated with `hnx records assign-uids <tree>`, which also rewrites every
reference to it and records the old code in the tree's aliases.yml.
"""


def _registers(root: pathlib.Path, paths: list[str], base: str | None) -> list[str]:
    """Register paths relative to ``root``: a record file stands for its directory; none given
    means every register tracked now or present at HEAD (and ``base``)."""
    if not paths:
        return ids.discover(root, ("HEAD", base) if base else ("HEAD",))
    out: list[str] = []
    for p in paths:
        rel = pathlib.Path(p).resolve().relative_to(root.resolve()).as_posix()
        parent = rel.rpartition("/")[0]
        if rel.endswith(ids.RECORD_SUFFIX) and ids.spec_for(parent or "."):
            rel = parent
        if rel not in out:
            out.append(rel)
    return out


def _texts(d: pathlib.Path) -> dict[str, str]:
    return {p.name: p.read_text() for p in sorted(d.glob("*.md"))}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hnx ids", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check-lost")
    c.add_argument("paths", nargs="*")
    c.add_argument("--base", help="compare with this revision only (CI: the PR base commit)")
    d = sub.add_parser("check-dupes")
    d.add_argument("paths", nargs="*")
    u = sub.add_parser("check-uids")
    u.add_argument("paths", nargs="*")
    ns = ap.parse_args(argv)
    try:
        root = ids.repo_root()
        rels = _registers(root, ns.paths, getattr(ns, "base", None))
        bad = False
        if ns.cmd == "check-uids":
            for rel in rels:
                spec = ids.spec_for(rel)
                if spec is None or spec.key != "uid" or not (root / rel).is_dir():
                    continue
                for problem in ids.missing_uids(_texts(root / rel), spec):
                    bad = True
                    print(f"[register-ids] FATAL: {rel}/{problem}", file=sys.stderr)
            if bad:
                print(UIDS_HELP, file=sys.stderr)
            return 1 if bad else 0
        if ns.cmd == "check-dupes":
            for rel in rels:
                spec = ids.spec_for(rel)
                if spec is None or not (root / rel).exists():
                    continue
                if ids.is_record_dir(root / rel):
                    for problem in ids.dir_problems(_texts(root / rel), spec):
                        bad = True
                        print(f"[register-ids] FATAL: {rel}/{problem}", file=sys.stderr)
                    continue
                text = (root / rel).read_text()
                dupes = ids.duplicates(text, spec)
                if dupes:
                    bad = True
                    print(
                        f"[register-ids] FATAL: {rel} repeats {', '.join(dupes)}", file=sys.stderr
                    )
                    reused = sorted(set(dupes) & set(ids.retired_in(text, spec)))
                    if reused:
                        print(
                            f"[register-ids] {', '.join(reused)} retired; a live entry may not "
                            "reuse it unless the same change deletes its tombstone",
                            file=sys.stderr,
                        )
            return 1 if bad else 0
        for rel in rels:
            lost = ids.check_lost(root, rel, base=ns.base)
            if lost:
                bad = True
                print(f"[register-ids] FATAL: {rel} lost {', '.join(lost)}", file=sys.stderr)
                print(EXPLAIN.format(path=rel, lost=",".join(lost)), file=sys.stderr)
                if ids.is_record_dir(root / rel):
                    print(EXPLAIN_DIR.format(path=rel), file=sys.stderr)
                else:
                    print(EXPLAIN_FILE.format(path=rel), file=sys.stderr)
        return 1 if bad else 0
    except ids.IdError as ex:
        print(f"[register-ids] FATAL: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
