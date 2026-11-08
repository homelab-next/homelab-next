#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: allowlist-ratchet
#   kind: check
#   purpose: Fail when a gate's allowlist or inline suppression markers outgrow the reviewed counts in tools/allowlist_counts.yml.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:gates, make:allowlist-counts]
#   inputs: the tracked tree; tools/allowlist_counts.yml; CODEOWNERS; the base commit's counts and CODEOWNERS (--base, --ci-base)
#   outputs: one line per list that grew or shrank against its count (or against the base); --update rewrites the counts
#   exit:
#     "0": every list is at its count (and no count rose against the base without a human-tier code owner)
#     "1": a list above or below its count, a counts file outside CODEOWNERS' human tier, or a count raised against the base with none
#     "2": usage error, a malformed counts file or allowlist, an unusable base, or an update that would raise a count without --grow
#     "100": the check itself failed (could not measure)
"""The allowlist ratchet: the gates' suppression lists only grow by a reviewed change.

Several gates take a reviewed list of exemptions, and each of them only ever grew: nothing capped
them while the debt they excuse was being paid down elsewhere.  This check counts each list
(:data:`LISTS`) and holds the count to ``tools/allowlist_counts.yml``:

* ``product-names-allow``: the ``allow:`` globs of ``tools/product_names.yml``;
* ``no-raw-endpoints-allow``: every entry of ``tools/no_raw_endpoints.allow.yml``;
* ``scripts-allow``: every entry of every section of ``tools/scripts.allow.yml``;
* ``scrub-allow-markers``: the lines carrying a leak-scan suppression marker, as
  ``tools/leak_scan.py`` reads them (its own ``SUPPRESS_RE``, its own file walk);
* ``no-raw-endpoint-markers``: the lines carrying an inline raw-endpoint allow marker
  (``homelabnext.endpoints_scan.INLINE_ALLOW``), over the same files.

**A count above what is committed fails**: the change that adds an exemption must raise the count
in the same change.  **A count below what is there also fails**, telling you the number to lower
it to (``--update`` does it): shrinking is always allowed, and the count follows it down, so the
slack a removal frees cannot be spent later without review.

**Why the counts file, and why CODEOWNERS.**  Raising a count is an edit of
``tools/allowlist_counts.yml``, which must sit under a *human-tier* rule of CODEOWNERS: the last
rule matching it is an explicit path rule (``/tools/``), not the catch-all ``*``.  So every growth
of any list, wherever its entries live (a marker in a test file, a glob in a gate's list), touches
one file whose review is the code owner's.  A label (``tools/experimental.yml``'s
``experimental-growth``) was the alternative; it approves one head and needs the operator to act
on every growth, which suits a list that should almost never grow but not lists that legitimately
grow by a reviewed line most weeks.  The code-owner review is advisory until GitHub can require it
(the header of CODEOWNERS says why); the counts file is what makes the growth visible in one place
and the check is what makes it impossible to land silently.

``--base REV`` / ``--ci-base`` also compare the committed counts with the base commit's: a count
that rose is printed, and fails unless the base's own CODEOWNERS puts the counts file under a
human-tier rule (read at the base, so a change cannot drop the rule and raise a count at once).  A
base with no counts file is the adoption commit and has nothing to compare.

Usage:
  python tools/allowlist_ratchet.py [ROOT] [--json] [--update [--grow]] [--base REV | --ci-base]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "tools"), str(REPO)):  # this checkout's own scanners, never another's
    if _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)

import yaml  # noqa: E402

COUNTS = "tools/allowlist_counts.yml"
#: where GitHub reads CODEOWNERS from, first found wins (homelabnext.modules.review_tier)
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
#: patterns that own everything: a path they alone own is not in the human tier
CATCH_ALL = {"*", "/*", "**", "/**", "/"}
HEADER = """\
# SPDX-License-Identifier: Apache-2.0
# The reviewed size of each gate's suppression list (tools/allowlist_ratchet.py, which says what
# each one counts).  A list above its count fails: the change that adds an exemption raises the
# count here, and this file's code owner reviews it.  A list below its count fails too, with the
# number to lower it to: `make allowlist-counts` (tools/allowlist_ratchet.py --update) lowers
# every count to what is there; raising one needs --grow, or a hand edit, and that review.
"""


class RatchetError(Exception):
    """A malformed counts file or allowlist, or an unusable base (exit 2)."""


def _yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RatchetError(f"{path}: {exc}") from None


def _entries(value: Any, where: str) -> int:
    if value is None:
        return 0
    if isinstance(value, (list, dict)):
        return len(value)
    raise RatchetError(f"{where}: expected a list or a mapping, not {type(value).__name__}")


def _section(rel: str, key: str) -> Callable[[Path, Markers], int]:
    def count(root: Path, _markers: Markers) -> int:
        doc = _yaml(root / rel) or {}
        if not isinstance(doc, dict):
            raise RatchetError(f"{rel}: not a mapping")
        return _entries(doc.get(key), f"{rel}: {key}")

    return count


def _every_section(rel: str) -> Callable[[Path, Markers], int]:
    def count(root: Path, _markers: Markers) -> int:
        doc = _yaml(root / rel) or {}
        if not isinstance(doc, dict):
            raise RatchetError(f"{rel}: not a mapping")
        return sum(_entries(v, f"{rel}: {k}") for k, v in doc.items())

    return count


@dataclass
class Markers:
    """The suppression-marker lines of the tree, counted once for both marker kinds."""

    scrub_allow: int
    no_raw_endpoint: int


def markers(root: Path) -> Markers:
    import leak_scan  # tools/leak_scan.py: its own walk and its own marker

    from homelabnext.endpoints_scan import INLINE_ALLOW

    scrub = endpoint = 0
    for f in leak_scan.iter_files([str(root)]):
        if isinstance(f, leak_scan.Skipped):
            continue
        text = leak_scan.read_text_file(f)
        if isinstance(text, leak_scan.Skipped):
            continue
        for line in text.splitlines():
            scrub += bool(leak_scan.SUPPRESS_RE.search(line))
            endpoint += bool(INLINE_ALLOW.search(line))
    return Markers(scrub, endpoint)


#: each ratcheted list and how it is counted; a new list is added here and to the counts file
LISTS: dict[str, Callable[[Path, Markers], int]] = {
    "product-names-allow": _section("tools/product_names.yml", "allow"),
    "no-raw-endpoints-allow": _every_section("tools/no_raw_endpoints.allow.yml"),
    "scripts-allow": _every_section("tools/scripts.allow.yml"),
    "scrub-allow-markers": lambda _root, m: m.scrub_allow,
    "no-raw-endpoint-markers": lambda _root, m: m.no_raw_endpoint,
}


def measure(root: Path) -> dict[str, int]:
    m = markers(root)
    return {name: count(root, m) for name, count in LISTS.items()}


def parse_counts(text: str, where: str) -> dict[str, int]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RatchetError(f"{where}: {exc}") from None
    if not isinstance(doc, dict) or set(doc) != {"counts"} or not isinstance(doc["counts"], dict):
        raise RatchetError(f"{where}: expected one mapping, counts: {{list: count}}")
    counts = doc["counts"]
    for name, n in counts.items():
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            raise RatchetError(f"{where}: {name}: the count must be a whole number >= 0")
    return {str(k): v for k, v in counts.items()}


def load_counts(path: Path) -> dict[str, int]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RatchetError(f"{path}: {exc}") from None
    counts = parse_counts(text, str(path))
    unknown, missing = sorted(set(counts) - set(LISTS)), sorted(set(LISTS) - set(counts))
    if unknown or missing:
        raise RatchetError(
            f"{path}: lists {unknown or '-'} are not ratcheted here, lists {missing or '-'} have "
            "no count (tools/allowlist_ratchet.py LISTS names each list once)"
        )
    return counts


def write_counts(path: Path, counts: dict[str, int]) -> None:
    body = "".join(f"  {name}: {counts[name]}\n" for name in LISTS)
    path.write_text(f"{HEADER}counts:\n{body}", encoding="utf-8")


def compare(have: dict[str, int], counts: dict[str, int]) -> list[str]:
    out = []
    for name in LISTS:
        n, c = have[name], counts[name]
        if n > c:
            out.append(
                f"{name}: {n} entries, the reviewed count is {c}: remove the exemption, or raise "
                f"the count in {COUNTS} in this change for its code owner to review"
            )
        elif n < c:
            out.append(
                f"{name}: {n} entries, the count is {c}: lower it to {n} in {COUNTS} "
                "(make allowlist-counts); a count only follows its list down"
            )
    return out


# ----------------------------------------------------------------------------- CODEOWNERS


def human_tier(codeowners: str | None, rel: str) -> bool:
    """Whether the last CODEOWNERS rule matching ``rel`` is an explicit path rule with a valid
    owner (not the catch-all), as GitHub reads it (homelabnext.modules.review_tier)."""
    if codeowners is None:
        return False
    from homelabnext.modules.review_tier import codeowners_for, parse_codeowners

    rules = parse_codeowners(codeowners)
    # each rule "owned" by its own index, so codeowners_for names the last rule that matches
    last = codeowners_for([(p, [str(i)]) for i, (p, _) in enumerate(rules)], rel)
    if not last:
        return False
    pattern, owners = rules[int(last[0])]
    return pattern not in CATCH_ALL and bool(owners)


def _codeowners_in_tree(root: Path) -> str | None:
    for rel in CODEOWNERS_PATHS:
        with contextlib.suppress(OSError, UnicodeDecodeError):
            return (root / rel).read_text(encoding="utf-8")
    return None


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)


def _show(root: Path, rev: str, rel: str) -> str | None:
    r = _git(root, "show", f"{rev}:{rel}")
    if r.returncode:
        return None
    try:
        return r.stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise RatchetError(f"--base {rev[:12]}: {rel} is not UTF-8") from None


def against_base(root: Path, rev: str, counts: dict[str, int], out) -> list[str]:
    """Counts that rose against ``rev``'s: each is printed, and fails unless ``rev``'s own
    CODEOWNERS puts the counts file under a human-tier rule."""
    if _git(root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").returncode:
        raise RatchetError(f"--base {rev}: not a commit here")
    text = _show(root, rev, COUNTS)
    if text is None:
        print(f"allowlist_ratchet: no {COUNTS} at {rev[:12]} (its adoption)", file=out)
        return []
    then = parse_counts(text, f"{COUNTS}@{rev[:12]}")
    rose = [(n, then[n], counts[n]) for n in LISTS if n in then and counts[n] > then[n]]
    if not rose:
        return []
    owners = next((t for p in CODEOWNERS_PATHS if (t := _show(root, rev, p)) is not None), None)
    owned = human_tier(owners, COUNTS)
    problems = []
    for name, was, now in rose:
        line = f"{name}: the count rises {was} -> {now} against {rev[:12]}"
        if owned:
            print(f"allowlist_ratchet: {line}: for the code owner of {COUNTS} to review", file=out)
        else:
            problems.append(
                f"{line}, and {COUNTS} has no human-tier CODEOWNERS rule at the base, so nobody "
                "reviews the growth"
            )
    return problems


# ----------------------------------------------------------------------------- the command line


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    try:
        return _main(argv, out, err)
    except RatchetError as exc:
        print(f"allowlist_ratchet: {exc}", file=err)
        return 2
    except Exception as exc:  # an internal failure: "could not measure", never a pass or a fail
        print(f"allowlist_ratchet: internal error: {type(exc).__name__}: {exc}", file=err)
        return 100


def _pick_base(root: Path, args, out) -> str | None:
    if args.base is not None and not args.base.strip():
        raise RatchetError("--base needs a commit (an empty value would skip the check)")
    if not args.ci_base:
        return args.base
    from homelabnext.gitbase import ci_base_from_env  # the one --ci-base rule

    try:
        rev, why = ci_base_from_env(root)
    except ValueError as exc:
        raise RatchetError(str(exc)) from None
    print(f"allowlist_ratchet: base {rev or '-'} ({why})", file=out)
    return rev


def _main(argv: list[str] | None, out, err) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--update", action="store_true", help=f"rewrite {COUNTS} to what is there")
    ap.add_argument(
        "--grow", action="store_true", help="with --update: allow a count to rise (for review)"
    )
    base = ap.add_mutually_exclusive_group()
    base.add_argument("--base", help="a commit whose counts may not be raised without review")
    base.add_argument(
        "--ci-base",
        action="store_true",
        help="pick --base from the CI event (GITHUB_EVENT_NAME, HNX_PR_BASE, HNX_PUSH_BEFORE)",
    )
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.grow and not args.update:
        raise RatchetError("--grow only goes with --update")
    root = Path(args.root).resolve()
    if not root.is_dir():
        raise RatchetError(f"{root}: not a directory")
    path = root / COUNTS
    have = measure(root)
    if args.update:
        counts = load_counts(path) if path.exists() else dict.fromkeys(LISTS, 0)
        rises = [n for n in LISTS if have[n] > counts[n]]
        if rises and not args.grow:
            for n in rises:
                print(f"allowlist_ratchet: {n} would rise {counts[n]} -> {have[n]}", file=err)
            raise RatchetError("refusing to raise a count without --grow (the raise is reviewed)")
        write_counts(path, have)
        changed = [f"{n} {counts[n]} -> {have[n]}" for n in LISTS if have[n] != counts[n]]
        print(
            f"allowlist_ratchet: {COUNTS} updated ({', '.join(changed) or 'no change'})", file=out
        )
        return 0
    counts = load_counts(path)
    problems = compare(have, counts)
    if not human_tier(_codeowners_in_tree(root), COUNTS):
        problems.append(
            f"{COUNTS}: no human-tier CODEOWNERS rule owns it (an explicit path rule, not the "
            "catch-all), so a raised count would land unreviewed"
        )
    rev = _pick_base(root, args, out)
    problems += against_base(root, rev, counts, out) if rev else []
    if args.json:
        print(json.dumps({"counts": counts, "measured": have, "problems": problems}, indent=2))
    else:
        for line in problems:
            print(line, file=out)
        summary = ", ".join(f"{n} {have[n]}" for n in LISTS)
        print(f"allowlist_ratchet: {len(problems)} problem(s); {summary}", file=out)
    return 1 if problems else 0


if __name__ == "__main__":
    for _stream in (sys.stdout, sys.stderr):  # a path that is not UTF-8 prints, never crashes
        with contextlib.suppress(AttributeError, ValueError):
            _stream.reconfigure(errors="backslashreplace")
    raise SystemExit(main())
