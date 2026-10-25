# SPDX-License-Identifier: Apache-2.0
"""The test run split across CI jobs, and the proof that the parts add up (checklist Q-02).

``pytest --shard I/N`` (``tests/suite_policy.py``) keeps the collected tests whose node id hashes
(SHA-256) to ``I-1`` modulo ``N``: every file and every suite is spread over all the shards, so
they come out about even with no table of timings to keep up to date, and the choice does not
depend on collection order, which may differ between runners.  The cost is that a module- or
session-scoped fixture runs once in each shard that needs it -- and its time counts once per
shard in the summed budget below, so a suite with a heavy shared fixture needs the headroom.

``--shard-report FILE`` writes what the shard collected (the count and a digest of every node id,
after ``-m`` and ``--deselect``), the node ids it kept and those it actually ran (a setup
report), the time it spent per suite, the budgets it applied and its exit status.  A shard still enforces the budgets on its own share of each
suite (a share over the budget means the whole suite is too); only the merge sees the whole::

    python -m tests.shard_report [--groups 3.11,3.12] PATH...

reads every ``*.json`` report under the PATHs (files or directories), groups them by the Python
version that wrote them, and fails (exit 1) unless, in every group: shards 1..N each reported
once, all collected the same tests, each ran exactly the tests it kept, together they ran
each of them exactly once, every shard exited 0, and each suite's time summed over the shards is within its budget.  ``--groups`` names
the groups that must all be there.  Exit 2: no report, or one that cannot be read.

Standard library only: the CI job that merges installs nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable
from pathlib import Path

FORMAT = 1


def parse_shard(text: str) -> tuple[int, int]:
    """``"I/N"`` -> ``(I, N)``, with ``1 <= I <= N``; ValueError otherwise."""
    index, sep, count = text.partition("/")
    try:
        i, n = int(index), int(count)
    except ValueError:
        i = n = 0
    if not sep or not 1 <= i <= n:
        raise ValueError(f"--shard: expected I/N with 1 <= I <= N, got {text!r}")
    return i, n


def shard_of(nodeid: str, count: int) -> int:
    """The shard (1..count) that runs ``nodeid``."""
    return int(hashlib.sha256(nodeid.encode()).hexdigest(), 16) % count + 1


def select(nodeids: list[str], index: int, count: int) -> list[bool]:
    """Which of the collected tests shard ``index`` of ``count`` keeps."""
    return [shard_of(n, count) == index for n in nodeids]


def digest(nodeids: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(nodeids)).encode()).hexdigest()


def report(
    *,
    group: str,
    index: int,
    count: int,
    collected: list[str] | None,
    selected: list[str],
    ran: list[str],
    times: dict[str, float],
    budgets: dict[str, float],
    default_budget: float,
    exitstatus: int,
) -> dict:
    """One shard's report; ``collected`` is None when the session never got as far."""
    return {
        "format": FORMAT,
        "group": group,
        "shard": index,
        "of": count,
        "collected": None if collected is None else len(collected),
        "collected_sha256": None if collected is None else digest(collected),
        "selected": sorted(selected),
        "ran": sorted(ran),
        "times": dict(sorted(times.items())),
        "budgets": dict(sorted(budgets.items())),
        "default_budget": default_budget,
        "exitstatus": exitstatus,
    }


def _check_group(group: str, reports: list[dict]) -> tuple[list[str], dict[str, float]]:
    problems: list[str] = []
    counts = {r["of"] for r in reports}
    if len(counts) != 1:
        return [f"{group}: the shards disagree on how many there are: {sorted(counts)}"], {}
    (n,) = counts
    seen = sorted(r["shard"] for r in reports)
    if seen != list(range(1, n + 1)):
        missing = sorted(set(range(1, n + 1)) - set(seen))
        twice = sorted({s for s in seen if seen.count(s) > 1})
        problems.append(f"{group}: shards of {n}: missing {missing}, reported twice {twice}")
    for r in reports:
        if r["exitstatus"] != 0 or type(r["exitstatus"]) is not int:
            problems.append(f"{group}: shard {r['shard']}/{n} exited {r['exitstatus']}")
        if r["collected"] is None:
            problems.append(f"{group}: shard {r['shard']}/{n} never finished collecting")
        elif sorted(r["ran"]) != sorted(r["selected"]):
            problems.append(
                f"{group}: shard {r['shard']}/{n} ran {len(r['ran'])} of the "
                f"{len(r['selected'])} tests it kept"
            )
    if any(r["collected"] is None for r in reports):
        return problems, {}
    if len({(r["collected"], r["collected_sha256"]) for r in reports}) != 1:
        problems.append(f"{group}: the shards did not collect the same tests")
        return problems, {}
    ran = [nodeid for r in reports for nodeid in r["selected"]]
    if not ran:
        problems.append(f"{group}: no test ran")
    if len(ran) != reports[0]["collected"] or digest(ran) != reports[0]["collected_sha256"]:
        problems.append(
            f"{group}: the shards ran {len(ran)} tests ({len(set(ran))} distinct), not each of "
            f"the {reports[0]['collected']} collected exactly once"
        )
    if len({json.dumps([r["budgets"], r["default_budget"]]) for r in reports}) != 1:
        problems.append(f"{group}: the shards applied different budgets")
        return problems, {}
    totals: dict[str, float] = {}
    for r in reports:
        for suite, secs in r["times"].items():
            totals[suite] = totals.get(suite, 0.0) + secs
    budgets, default = reports[0]["budgets"], reports[0]["default_budget"]
    for suite, secs in sorted(totals.items()):
        budget = budgets.get(suite, default)
        if not secs <= budget:  # a NaN is over too
            problems.append(
                f"{group}: {suite}: {secs:.1f}s over all shards > budget {budget:.1f}s "
                "(suite_budgets in pyproject.toml)"
            )
    return problems, totals


def merge(reports: list[dict], groups: list[str] | None = None) -> list[str]:
    """Every problem with the reports, as lines; the per-suite table goes to stdout."""
    by_group: dict[str, list[dict]] = {}
    problems: list[str] = []
    for r in reports:
        if r.get("format") != FORMAT:
            problems.append(f"a report in format {r.get('format')!r}, not {FORMAT}")
            continue
        by_group.setdefault(r["group"], []).append(r)
    if groups is not None and sorted(by_group) != sorted(groups):
        problems.append(f"groups reported {sorted(by_group)}, expected {sorted(groups)}")
    for group, rs in sorted(by_group.items()):
        found, totals = _check_group(group, rs)
        problems += found
        print(f"{group}: {len(rs)} shards, seconds per shard:", end="")
        for r in sorted(rs, key=lambda r: r["shard"]):
            print(f" {sum(r['times'].values()):.0f}", end="")
        print()
        for suite, secs in sorted(totals.items(), key=lambda kv: -kv[1]):
            budget = rs[0]["budgets"].get(suite, rs[0]["default_budget"])
            print(f"  {secs:8.1f}s / {budget:6.0f}s  {suite}")
    return problems


def _load(paths: list[str]) -> list[dict]:
    files: list[Path] = []
    for p in map(Path, paths):
        files += sorted(p.rglob("*.json")) if p.is_dir() else [p]
    return [json.loads(f.read_text(encoding="utf-8")) for f in files]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="+", help="shard reports, or directories holding them")
    ap.add_argument("--groups", help="the groups (Python versions) that must all report, a,b")
    args = ap.parse_args(argv)
    try:
        reports = _load(args.paths)
    except (OSError, ValueError) as exc:
        print(f"shard_report: {exc}", file=sys.stderr)
        return 2
    if not reports:
        print("shard_report: no shard report found", file=sys.stderr)
        return 2
    groups = [g.strip() for g in args.groups.split(",") if g.strip()] if args.groups else None
    try:
        problems = merge(reports, groups)
    except (KeyError, TypeError, AttributeError) as exc:
        print(f"shard_report: a malformed report: {exc!r}", file=sys.stderr)
        return 2
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
