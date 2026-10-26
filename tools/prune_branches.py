# SPDX-License-Identifier: Apache-2.0
"""Which branches the prune-branches workflow deletes: the ones whose work is over.

    python tools/prune_branches.py BRANCHES.json PULLS.json --default main

``BRANCHES.json`` is the GitHub API's branch list (``repos/{repo}/branches``) and ``PULLS.json``
its pull requests (``repos/{repo}/pulls?state=all``), each a JSON array (``gh api --paginate
--slurp`` gives an array of pages, which is flattened).  It prints one branch name per line to
delete; ``--keep FILE`` writes the kept ones with the reason, for the run summary.

A branch is deleted only when every one of these holds:

* it is not the default branch and not protected;
* no open pull request has it as its head or as its base (a stacked pull request: deleting its
  base would close it);
* its tip is exactly the head commit of a merged or closed pull request from this repository, so
  a branch that got new commits after its pull request closed, or never had one, is kept.

A deleted branch of a pull request can be restored from the pull request's page.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any


def _flat(doc: Any) -> list[dict]:
    """A list of objects, or a list of pages (lists) of them (``--paginate --slurp``)."""
    if not isinstance(doc, list):
        raise ValueError("expected a JSON array")
    out: list[dict] = []
    for item in doc:
        out.extend(item if isinstance(item, list) else [item])
    return out


def decide(
    branches: Iterable[dict], pulls: Iterable[dict], *, default: str, repo: str | None = None
) -> tuple[list[str], dict[str, str]]:
    """``(to_delete, kept)``: names to delete, and every other branch with why it stays."""
    pulls = list(pulls)
    # any open pull request's base, a fork's included: deleting it would close that pull request
    open_bases = {p["base"]["ref"] for p in pulls if p.get("state") == "open" and p.get("base")}
    pulls = [
        p
        for p in pulls
        if repo is None or (p.get("head", {}).get("repo") or {}).get("full_name") == repo
    ]
    open_heads = {p["head"]["ref"] for p in pulls if p.get("state") == "open"}
    finished = {(p["head"]["ref"], p["head"]["sha"]) for p in pulls if p.get("state") == "closed"}
    with_pr = {p["head"]["ref"] for p in pulls}
    delete, kept = [], {}
    for b in sorted(branches, key=lambda b: b["name"]):
        name, tip = b["name"], (b.get("commit") or {}).get("sha")
        if name == default:
            kept[name] = "the default branch"
        elif b.get("protected"):
            kept[name] = "protected"
        elif name in open_heads:
            kept[name] = "an open pull request"
        elif name in open_bases:
            kept[name] = "the base of an open pull request"
        elif (name, tip) in finished:
            delete.append(name)
        elif name in with_pr:
            kept[name] = "commits after its pull request closed"
        else:
            kept[name] = "no pull request"
    return delete, kept


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prune_branches", description=__doc__.split("\n\n")[0])
    ap.add_argument("branches", type=Path)
    ap.add_argument("pulls", type=Path)
    ap.add_argument("--default", required=True, help="the repository's default branch")
    ap.add_argument("--repo", help="owner/name: only pull requests from this repository count")
    ap.add_argument("--keep", type=Path, help="write the kept branches and why, one per line")
    args = ap.parse_args(argv)
    if not args.default.strip():
        # an empty default would match no branch, and the default branch would lose its guard
        print("prune_branches: --default is empty", file=sys.stderr)
        return 2
    try:
        branches = _flat(json.loads(args.branches.read_text(encoding="utf-8")))
        pulls = _flat(json.loads(args.pulls.read_text(encoding="utf-8")))
        delete, kept = decide(branches, pulls, default=args.default, repo=args.repo)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"prune_branches: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2
    if args.keep:
        args.keep.write_text("".join(f"{n}\t{why}\n" for n, why in kept.items()), encoding="utf-8")
    sys.stdout.write("".join(f"{n}\n" for n in delete))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
