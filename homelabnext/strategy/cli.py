# SPDX-License-Identifier: Apache-2.0
"""``hnx strategy``: the strategy-to-task records (docs/strategy.md).

    hnx strategy check [ROOT] [--invariants FILE] [--registry FILE]   validate (fatal) + warnings
    hnx strategy links [ROOT] [--check]           regenerate / check the records' Links blocks
    hnx strategy measure [ROOT] [--results FILE] [--state FILE] [--registry FILE]
                         [--records DIR] [--now TIME] [--by ID] [--dry-run] [--json]
    hnx strategy rollup [ROOT] [--now TIME] [--json]           the cascade, graded
    hnx strategy rfis [ROOT] [--today DATE] [--json]           open RFIs, expiring, gaps
    hnx strategy rfis [ROOT] --raise --records DIR --as profile:NAME [--today DATE]
    hnx strategy rfis [ROOT] --sweep --records DIR --as ISSUER:NAME [--today DATE]
    hnx strategy decide [ROOT] RECORDS --as ISSUER:NAME [--dry-run] [--json]
    hnx strategy index [ROOT] [--out FILE] [--check]          the Markdown index (docs/strategy/)

ROOT defaults to ``examples/strategy``; a lab keeps its real strategy in a private repository
and passes its path (the same loader, ADR-0011).  Records are printed with their computed
display numbers (``OO 1.2``) and their uids; the JSON keys records by uid and carries each
one's ``label`` (ADR-0019).  ``--now`` / ``--today`` inject the clock
(default: the real one).  Exit codes: 0 ok, 1 a check failed (invalid records, a stale Links
block or index, a denied or invalid intent), 2 usage or input error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from collections.abc import Callable

from homelabnext.registers.schema import RegisterError

DEFAULT_ROOT = "examples/strategy"
DEFAULT_RESULTS = "examples/registers/invariants.results.json"
DEFAULT_REGISTRY = "examples/services.yml"
DEFAULT_INDEX = "docs/strategy/README.md"


def _now(value: str | None, clock: Callable[[], dt.datetime]) -> dt.datetime:
    if not value:
        return clock()
    t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def _today(value: str | None, clock: Callable[[], dt.datetime]) -> dt.date:
    return dt.date.fromisoformat(value) if value else clock().astimezone(dt.UTC).date()


def _snapshot(state: str | None, registry: str, now: dt.datetime):
    if not state:
        return None
    from homelabnext.registry.model import load
    from homelabnext.state import StateStore
    from homelabnext.status.hub import StatusHub
    from homelabnext.status.model import sources_from_registry

    specs = sources_from_registry(load(registry))
    ts = now.timestamp()
    return StatusHub(specs, StateStore(state, clock=lambda: ts), clock=lambda: ts).snapshot(ts)


def _grade_line(k: str, g) -> str:
    v = "-" if g.value is None else f"{g.value:g}"
    extra = [x for x in (g.trend and f"trend {g.trend}", g.thin and f"thin: {g.thin}") if x]
    extra += ["capped (self-measured)"] if g.capped else []
    extra += [f"finding: {g.finding}"] if g.finding else []
    at = g.observed_at or "-"
    return (
        f"  {g.label or k:<10} {g.state:<10} {v:>8} at {at}  {g.confidence or ''}  "
        f"{'; '.join(extra)}  [{k}]"
    )


def main(argv: list[str] | None = None, *, clock: Callable[[], dt.datetime] | None = None) -> int:
    clock = clock or (lambda: dt.datetime.now(dt.UTC))
    ap = argparse.ArgumentParser(prog="hnx strategy", description="strategy-to-task records")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def root(p):
        p.add_argument("root", nargs="?", default=DEFAULT_ROOT, help="the strategy directory")

    p = sub.add_parser("check", help="validate the tree (fatal) and print doctrine warnings")
    root(p)
    p = sub.add_parser("links", help="regenerate the records' Links blocks")
    root(p)
    p.add_argument("--check", action="store_true", help="fail when one is stale")
    p = sub.add_parser("measure", help="read every bound measure; record value events")
    root(p)
    p.add_argument("--results", default=DEFAULT_RESULTS, help="invariants results JSON")
    p.add_argument("--state", help="the status hub's state file (status: bindings)")
    p.add_argument("--registry", default=DEFAULT_REGISTRY, help="services.yml (with --state)")
    p.add_argument("--records", help="records root (records: bindings)")
    p.add_argument("--now", help="RFC 3339 time to measure at (default: now)")
    p.add_argument("--by", default="profile:strategy-measure", help="the writer of the events")
    p.add_argument("--dry-run", action="store_true", help="read and grade; write nothing")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("rollup", help="the cascade graded from the recorded readings")
    root(p)
    p.add_argument("--now", help="RFC 3339 time to grade at (thinness ages; default: now)")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("rfis", help="RFIs: list, raise intents from gaps, LTIOV sweep")
    root(p)
    p.add_argument("--today", help="YYYY-MM-DD (default: today, UTC)")
    p.add_argument("--raise", dest="raise_", action="store_true", help="file intents for gaps")
    p.add_argument("--sweep", action="store_true", help="expire what is past its LTIOV")
    p.add_argument("--records", help="records root (with --raise or --sweep)")
    p.add_argument("--as", dest="who", help="profile:NAME (--raise) or the decider (--sweep)")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("decide", help="decide strategy-transition and strategy-rfi intents")
    root(p)
    p.add_argument("records", help="the records root (inbox/, decided/)")
    p.add_argument("--as", dest="who", required=True, help="the decider (human:operator)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("index", help="write or check the Markdown index")
    root(p)
    p.add_argument("--out", default=DEFAULT_INDEX)
    p.add_argument("--check", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if not pathlib.Path(args.root).is_dir():
        print(f"hnx strategy: {args.root}: no such directory", file=sys.stderr)
        return 2
    try:
        return _run(args, clock)
    except RegisterError as ex:
        print(f"[strategy] FATAL: {ex}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as ex:
        print(f"hnx strategy: {ex}", file=sys.stderr)
        return 2


def _run(args, clock) -> int:
    from .doctrine import load_doctrine
    from .records import load_tree
    from .rules import validate

    if args.cmd == "check":
        tree = load_tree(args.root)
        rep = validate(tree)
        for w in rep.warnings:
            print(f"[strategy] warning: {w}")
        for e in rep.errors:
            print(f"[strategy] {e}")
        n = sum(1 for _ in tree.items())
        state = "FAIL" if rep.errors else "ok"
        print(f"[strategy] {args.root}: {n} record(s), {len(rep.errors)} problem(s): {state}")
        return 1 if rep.errors else 0
    if args.cmd == "links":
        from homelabnext.registers.records import stale_links

        from .records import DIRS

        stale = []
        for d in DIRS:
            if (pathlib.Path(args.root) / d).is_dir():
                stale += stale_links(pathlib.Path(args.root) / d, write=not args.check)
        for p in stale:
            print(f"[strategy] {'stale' if args.check else 'rewrote'} Links block: {p}")
        return 1 if stale and args.check else 0
    if args.cmd == "index":
        from .index import render_index

        text = render_index(load_tree(args.root), args.root, args.out)
        out = pathlib.Path(args.out)
        if args.check:
            ok = out.is_file() and out.read_text(encoding="utf-8") == text
            print(f"[strategy] index {out}: {'ok' if ok else 'STALE (run hnx strategy index)'}")
            return 0 if ok else 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"[strategy] wrote {out}")
        return 0
    doctrine = load_doctrine(args.root)
    if args.cmd == "measure":
        return _measure(args, clock, doctrine)
    if args.cmd == "rollup":
        return _rollup(args, clock, doctrine)
    if args.cmd == "rfis":
        return _rfis(args, clock, doctrine)
    return _decide(args, clock)


def _measure(args, clock, doctrine) -> int:
    from .measure import Context, grade_all, load_results, measure_all

    now = _now(args.now, clock)
    results, name = load_results(args.results)
    ctx = Context(
        now=now,
        results=results,
        results_name=name,
        snapshot=_snapshot(args.state, args.registry, now),
        records_root=pathlib.Path(args.records) if args.records else None,
    )
    written, tree = measure_all(args.root, ctx, by=args.by, write=not args.dry_run)
    grades = grade_all(tree, doctrine, now)
    if args.json:
        out = {
            k: {"recorded": written.get(k) is not None, **g.as_json()} for k, g in grades.items()
        }
        print(json.dumps(out, indent=1, sort_keys=True, default=str))
        return 0
    verb = "would record" if args.dry_run else "recorded"
    for k, g in grades.items():
        print(_grade_line(k, g) + (f"  [{verb}]" if written.get(k) else ""))
    n = sum(1 for e in written.values() if e)
    print(f"[strategy] {verb} {n} reading(s) at {now.isoformat()}")
    return 0


def _tree_lines(tree, states, grades) -> list[str]:
    lines: list[str] = []

    def walk(k: str, depth: int) -> None:
        o, s = tree.of("objectives")[k], states[k]
        lines.append(f"{'  ' * depth}{tree.label(k)} [{s['state']}] {o.get('title')}  [{k}]")
        for m in s["measures"]:
            g = grades[m]
            v = "-" if g.value is None else f"{g.value:g}"
            lines.append(f"{'  ' * (depth + 1)}- {tree.label(m)} {g.state} {v}  [{m}]")
        for c in s["children"]:
            walk(c, depth + 1)

    for k in [k for k in tree.ordered("objectives") if k in states]:
        if tree.of("objectives")[k].get("type") == "SO":
            walk(k, 0)
    return lines


def _rollup(args, clock, doctrine) -> int:
    from .measure import grade_all, rollup
    from .records import load_tree

    tree = load_tree(args.root)
    now = _now(args.now, clock)
    grades = grade_all(tree, doctrine, now)
    states = rollup(tree, grades)
    if args.json:
        doc = {"objectives": states, "measures": {k: g.as_json() for k, g in grades.items()}}
        print(json.dumps(doc, indent=1, sort_keys=True, default=str))
        return 0
    print("\n".join(_tree_lines(tree, states, grades)))
    return 0


def _rfis(args, clock, doctrine) -> int:
    from .measure import grade_all
    from .records import load_tree
    from .rfis import expiring, gaps, raise_intents, sweep

    today = _today(args.today, clock)
    at = dt.datetime(today.year, today.month, today.day, tzinfo=dt.UTC) if args.today else None
    now_fn = (lambda: at) if at else clock
    if (args.raise_ or args.sweep) and not (args.records and args.who):
        print("hnx strategy rfis: --raise and --sweep need --records and --as", file=sys.stderr)
        return 2
    if args.sweep:
        filed, outcomes = sweep(
            args.root, args.records, today=today, decided_by=args.who, clock=now_fn
        )
        for o in outcomes:
            print(f"[strategy] {o.line()}")
        print(f"[strategy] LTIOV sweep {today}: {len(filed)} expiry intent(s) filed")
        return 1 if any(o.result in ("denied", "invalid", "error") for o in outcomes) else 0
    tree = load_tree(args.root)
    grades = grade_all(tree, doctrine, now_fn())
    found = gaps(tree, grades, today, args.records)
    if args.raise_:
        paths = raise_intents(found, args.records, agent=args.who, clock=now_fn)
        for p in paths:
            print(f"[strategy] filed {p}")
        print(f"[strategy] {len(paths)} strategy-rfi intent(s) in {args.records}/inbox")
        return 0
    soon = expiring(tree, today, doctrine.expiring_soon_days)
    open_ = {k: r for k, r in tree.of("rfis").items() if r.get("status") == "open"}
    if args.json:
        doc = {
            "open": {
                k: {"label": tree.label(k), "triage": r.get("triage"), "ltiov": str(r.get("ltiov"))}
                for k, r in open_.items()
            },
            "expiring": [k for k, _ in soon],
            "gaps": [g.__dict__ for g in found],
        }
        print(json.dumps(doc, indent=1, sort_keys=True))
        return 0
    for triage in ("collection", "production"):
        rows = [
            tree.label(k) for k in tree.ordered("rfis", open_) if open_[k].get("triage") == triage
        ]
        print(f"{triage} requirements: {', '.join(rows) or 'none'}")
    print("expiring soon: " + (", ".join(f"{tree.label(k)} ({d})" for k, d in soon) or "none"))
    for g in found:
        print(f"gap: {g.label or g.raised_by} -> {g.triage}: {g.why}  [{g.raised_by}]")
    return 0


def _decide(args, clock) -> int:
    from .rfis import StrategyDecider

    decider = StrategyDecider(args.root, args.records, decided_by=args.who, clock=clock)
    outcomes = decider.decide_all(dry_run=args.dry_run)
    if args.json:
        print(json.dumps([o.as_json() for o in outcomes], indent=1, sort_keys=True))
    else:
        for o in outcomes:
            print(f"[strategy] {o.line()}")
        print(f"[strategy] {len(outcomes)} intent(s) decided")
    return 1 if any(o.result in ("denied", "invalid", "error") for o in outcomes) else 0
