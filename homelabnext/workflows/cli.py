# SPDX-License-Identifier: Apache-2.0
"""``hnx workflows``: validate (every pack in git, offline), run (one pack's fixtures), digest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pack import WorkflowError, expand, load_doc, pack_digest
from .validate import Universe, load_universe, validate_repo


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="hnx workflows", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    va = sub.add_parser("validate", help="validate every pack in the git tree, or PATHS")
    va.add_argument("paths", nargs="*", type=Path, help="pack files or directories")
    va.add_argument("--root", type=Path, default=None, help="git tree (default: cwd)")
    va.add_argument(
        "--deploy", type=Path, default=None, help="deploy manifest (default: workflows/deploy.yml)"
    )
    ru = sub.add_parser("run", help="run a pack's fixtures offline and print the action calls")
    ru.add_argument("pack", type=Path)
    ru.add_argument("--fixture", default=None, help="only this fixture")
    ru.add_argument("--root", type=Path, default=None, help="git tree (default: cwd)")
    di = sub.add_parser("digest", help="print '<pack> <digest>' for the deploy manifest's pins")
    di.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "validate":
            return _validate(args)
        if args.cmd == "run":
            return _run(args)
        for f in expand(args.paths):
            doc = load_doc(f)
            print(f"{doc.get('pack')} {pack_digest(doc)}")
        return 0
    except WorkflowError as exc:
        print(f"hnx workflows: {exc}", file=sys.stderr)
        return exc.code


def _validate(args) -> int:
    rep = validate_repo(args.paths, root=args.root, deploy=args.deploy)
    for p in rep.problems:
        print(p)
    print(f"workflows validate: {len(rep.packs)} pack(s), {len(rep.problems)} problem(s)")
    return 1 if rep.problems else 0


def _run(args) -> int:
    from .runner import run_fixture

    uni: Universe = load_universe((args.root or Path.cwd()).resolve())
    doc = load_doc(args.pack)
    manifest, problems = uni.manifest(doc["broker_manifest"])
    if manifest is None:
        print("\n".join(problems), file=sys.stderr)
        return 2
    out = []
    for fx in doc["fixtures"]:
        if args.fixture and fx["name"] != args.fixture:
            continue
        res = run_fixture(doc, fx, manifest=manifest, spec_labels=uni.spec_labels)
        out.append(
            {
                "fixture": fx["name"],
                "triggered": res.triggered,
                "calls": [c.to_dict() for c in res.calls],
                "skipped": res.skipped,
                "problems": res.problems,
            }
        )
    print(json.dumps(out, indent=2, sort_keys=True))
    return 1 if any(r["problems"] for r in out) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
