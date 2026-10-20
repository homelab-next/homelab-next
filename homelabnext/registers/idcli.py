# SPDX-License-Identifier: Apache-2.0
"""Id allocation and loss detection for registers (single YAML files or record directories).

  hnx ids alloc REGISTER [--prefix LL] [-n N]
  hnx ids resolve [PATH...]      rewrite XX-NEW placeholders (exit 3 if it changed anything);
                                 in a record directory also renames LL-NEW-<slug>.md to LL-NNN.md
  hnx ids check-lost [PATH...] [--base REV]
                                 fail if a parent commit's (or REV's) id vanished (exit 1)
  hnx ids check-dupes [PATH...]  fail if an allocated id occurs twice, is live and retired, or a
                                 record file's name disagrees with its id (exit 1)
  hnx ids check-placeholders [PATH...]
                                 fail if any entry id is still an XX-NEW placeholder (exit 1);
                                 CI runs it on every push to main, never on a pull request

A PATH is a register file (lessons.yml), a record directory (lessons/) or a record file inside
one (lessons/LL-001.md, which stands for its directory).  Without PATHs every register git tracks
or HEAD (and --base) has is checked, so a commit that only deletes a record file is still seen.

Contributors commit `XX-NEW`; `check-lost` and `check-dupes` run in the pre-commit hook and in CI
against the pull request's base.  A maintainer runs `resolve` once, at merge time, on the target
branch (`make ids-resolve`), so two pull requests never claim the same number; a push to main
that still carries a placeholder fails CI (`make ids-placeholders`) until that step is done.
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
silence this. An id that was wrong on purpose is retired, not deleted: move it to the
register's top-level `retired:` block with `reason:` (and `replaced_by:`), a tombstone that
check-lost counts as present. A one-off consolidation in a local commit:
REGISTER_IDS_ALLOW_DROP={lost} git commit ...
"""

EXPLAIN_DIR = """{path} is a record directory: a deleted record file is restored with
`git checkout HEAD -- {path}/<ID>.md` (or MERGE_HEAD); a wrong id is retired by replacing the
file's front-matter with `id:` and a `retired:` mapping (`reason:`, `replaced_by:`).
"""

PLACEHOLDER_HELP = """XX-NEW is fine on a pull request branch, never on main. Maintainer step: on an
up-to-date main, run `make ids-resolve`, review the diff and push it (resolve allocates under the
per-repository lock, so the numbers cannot collide with another merge).
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hnx ids", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("alloc")
    a.add_argument("register")
    a.add_argument("--prefix")
    a.add_argument("-n", type=int, default=1)
    r = sub.add_parser("resolve")
    r.add_argument("paths", nargs="*")
    r.add_argument("--dry-run", action="store_true")
    c = sub.add_parser("check-lost")
    c.add_argument("paths", nargs="*")
    c.add_argument("--base", help="compare with this revision only (CI: the PR base commit)")
    d = sub.add_parser("check-dupes")
    d.add_argument("paths", nargs="*")
    pl = sub.add_parser("check-placeholders")
    pl.add_argument("paths", nargs="*")
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
        rels = _registers(root, ns.paths, getattr(ns, "base", None))
        if ns.cmd == "resolve":
            changed = False
            for rel in rels:
                if not (root / rel).exists():
                    continue
                for old, new in ids.resolve_file(root, rel, ns.dry_run):
                    changed = True
                    print(f"[register-ids] {rel}: {old} -> {new}")
            return 3 if changed else 0
        bad = False
        if ns.cmd == "check-placeholders":
            for rel in rels:
                spec = ids.spec_for(rel)
                if spec is None:
                    continue
                left = [i for i in ids.entry_ids(root, rel, spec) if i.endswith("-NEW")]
                if left:
                    bad = True
                    print(
                        f"[register-ids] FATAL: {rel} still has {len(left)} placeholder id(s): "
                        f"{', '.join(sorted(set(left)))}",
                        file=sys.stderr,
                    )
            if bad:
                print(PLACEHOLDER_HELP, file=sys.stderr)
            return 1 if bad else 0
        if ns.cmd == "check-dupes":
            for rel in rels:
                spec = ids.spec_for(rel)
                if spec is None or not (root / rel).exists():
                    continue
                if ids.is_record_dir(root / rel):
                    texts = {p.name: p.read_text() for p in sorted((root / rel).glob("*.md"))}
                    for problem in ids.dir_problems(texts, spec):
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
        return 1 if bad else 0
    except ids.IdError as ex:
        print(f"[register-ids] FATAL: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
