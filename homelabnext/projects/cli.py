# SPDX-License-Identifier: Apache-2.0
"""``hnx projects``: projects, steps and tasks as Markdown files (docs/projects.md).

    hnx projects new KIND TITLE [--project REF] [--parent REF] [--key KEY] [--assignee ID]
                     [--due DATE] [--description TEXT]
    hnx projects list [--kind K] [--status S] [--project REF] [--assignee ID] [--linked-to REF]
    hnx projects show REF
    hnx projects move REF STATUS [--result TEXT] [--version N]
    hnx projects close REF RESULT [--version N]
    hnx projects link REF TARGET RELATION [--unlink] [--version N]
    hnx projects check
    hnx projects feed [--cursor C]               homelabnext.project.changed events, JSON lines
    hnx projects doctor --target openproject --config FILE
    hnx projects sync-strategy --target openproject --config FILE (--dry-run | --apply)

Common options: ``--dir DIR`` (the projects directory, default ``examples/projects``),
``--strategy DIR`` (the strategy records links may name, default ``examples/strategy``),
``--json``.  A REF is a uid or a unique prefix or suffix of one (at least 6 hex digits); a link
TARGET may also be a strategy record's display number (``"OO 1.1"``, computed by
``homelabnext.identity``) or a legacy code from ``aliases.yml``, resolved to its uid.  ``move``
and ``close`` read the current version when ``--version`` is not given (a version given is
checked: a stale one is a conflict, exit 1).  OpenProject's API token is read by its secret name
from the environment (``HNX_SECRET_OPENPROJECT_API_TOKEN`` for ``secret:openproject/api-token``).

Exit codes: 0 ok, 1 a rule refused the change or ``check``/``doctor`` found problems, 2 usage or
input error (a ``--dir`` that does not exist, for any command but ``new``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict

from .model import KINDS, RELATIONS, STATUSES, NotFound, ProjectsError, WorkItem

DEFAULT_DIR = "examples/projects"
DEFAULT_STRATEGY = "examples/strategy"


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dir", default=DEFAULT_DIR, help="the projects directory")
    common.add_argument("--strategy", default=DEFAULT_STRATEGY, help="the strategy records")
    common.add_argument("--json", action="store_true")
    p = argparse.ArgumentParser(prog="hnx projects", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new", parents=[common], help="create a project, step or task")
    n.add_argument("kind", choices=KINDS)
    n.add_argument("title")
    n.add_argument("--project")
    n.add_argument("--parent")
    n.add_argument("--key", help="external key: a second new with it returns the first item")
    n.add_argument("--assignee")
    n.add_argument("--due")
    n.add_argument("--description", default="")
    ls = sub.add_parser("list", parents=[common], help="list items")
    ls.add_argument("--kind", choices=KINDS)
    ls.add_argument("--status", choices=STATUSES)
    ls.add_argument("--project")
    ls.add_argument("--assignee")
    ls.add_argument("--linked-to")
    s = sub.add_parser("show", parents=[common], help="one item (a project with its steps)")
    s.add_argument("ref")
    m = sub.add_parser("move", parents=[common], help="change an item's status")
    m.add_argument("ref")
    m.add_argument("status", choices=STATUSES)
    m.add_argument("--result")
    m.add_argument("--version", type=int)
    c = sub.add_parser("close", parents=[common], help="finish an item with a one-line result")
    c.add_argument("ref")
    c.add_argument("result")
    c.add_argument("--version", type=int)
    lk = sub.add_parser("link", parents=[common], help="link an item to a record or an item")
    lk.add_argument("ref")
    lk.add_argument("target")
    lk.add_argument("relation", choices=RELATIONS)
    lk.add_argument("--unlink", action="store_true")
    lk.add_argument("--version", type=int)
    sub.add_parser("check", parents=[common], help="the board rules over every file")
    f = sub.add_parser("feed", parents=[common], help="change events (JSON lines)")
    f.add_argument("--cursor", help="from this cursor (default: a snapshot of every item)")
    for name, what in (
        ("doctor", "check the one-time OpenProject setup"),
        ("sync-strategy", "mirror the strategy records into OpenProject"),
    ):
        o = sub.add_parser(name, parents=[common], help=what)
        o.add_argument("--target", choices=["openproject"], required=True)
        o.add_argument("--config", required=True, help="openproject.yml (docs/projects.md)")
        if name == "sync-strategy":
            g = o.add_mutually_exclusive_group(required=True)
            g.add_argument("--dry-run", action="store_true")
            g.add_argument("--apply", action="store_true")
    return p


def _store(a):
    """The store over ``--dir``; only ``new`` creates a missing directory (every other command
    needs items to act on, and a read must not pass vacuously over a directory that is not
    there: exit 2)."""
    from . import markdown_store

    return markdown_store(a.dir, strategy=a.strategy, create=a.cmd == "new")


def _resolve(store, ref: str, items: Sequence[WorkItem] | None = None) -> str:
    """A uid from a uid, or a unique prefix/suffix of one (6+ hex digits)."""
    items = list(items if items is not None else store.list())
    if any(i.uid == ref for i in items):
        return ref
    bare = ref.lower().replace("-", "")
    if len(bare) < 6:
        raise NotFound(f"{ref!r}: give a uid or at least 6 of its hex digits")
    hits = [
        i.uid
        for i in items
        if i.uid.replace("-", "").startswith(bare) or i.uid.replace("-", "").endswith(bare)
    ]
    if len(hits) != 1:
        raise NotFound(f"{ref!r} matches {len(hits)} items")
    return hits[0]


def _target(store, a, ref: str) -> str:
    from .strategy import resolve_record

    if a.relation in ("blocks", "precedes"):
        return _resolve(store, ref)
    return resolve_record(ref, a.strategy)  # refused by the store when it resolves to nothing


def _line(i: WorkItem) -> str:
    tail = f"  [{i.result}]" if i.result else ""
    order = f"#{i.order} " if i.order else ""
    return f"{i.uid}  {i.kind:<7} {i.status:<11} {order}{i.title}{tail}"


def _out(a, items: Sequence[WorkItem]) -> None:
    if a.json:
        print(json.dumps([_doc(i) for i in items], indent=2, sort_keys=True))
    else:
        for i in items:
            print(_line(i))


def _doc(i: WorkItem) -> dict:
    d = asdict(i)
    d.pop("extra", None)
    return d


def _openproject(a):
    from .openproject import load_config

    cfg = load_config(a.config)
    return cfg, cfg.client()


def _run(a) -> int:
    if a.cmd == "doctor":
        from .openproject import doctor

        cfg, client = _openproject(a)
        findings = doctor(client, cfg)
        if a.json:
            print(json.dumps([asdict(f) for f in findings], indent=2))
        else:
            for f in findings:
                print(
                    f"{'ok  ' if f.ok else 'MISS'}  {f.what}"
                    + (f"\n      -> {f.step}" if f.step else "")
                )
        return 0 if all(f.ok for f in findings) else 1
    if a.cmd == "sync-strategy":
        from .openproject import discover, sync_strategy
        from .strategy import strategy_records

        cfg, client = _openproject(a)
        rep = sync_strategy(
            client, cfg, discover(client, cfg), list(strategy_records(a.strategy)), apply=a.apply
        )
        print(json.dumps(rep.as_dict(), indent=2) if a.json else "\n".join(rep.lines()))
        return 1 if rep.problems else 0
    store = _store(a)
    if a.cmd == "new":
        items = store.list()
        it = store.create(
            a.kind,
            a.title,
            project=_resolve(store, a.project, items) if a.project else None,
            parent=_resolve(store, a.parent, items) if a.parent else None,
            external_key=a.key,
            assignee=a.assignee,
            due=a.due,
            description=a.description,
        )
        _out(a, [it])
    elif a.cmd == "list":
        items = store.list()
        _out(
            a,
            store.list(
                kind=a.kind,
                status=a.status,
                project=_resolve(store, a.project, items) if a.project else None,
                assignee=a.assignee,
                linked_to=_target_ref(store, a, a.linked_to) if a.linked_to else None,
            ),
        )
    elif a.cmd == "show":
        it = store.get(_resolve(store, a.ref))
        steps = store.list(kind="step", project=it.uid) if it.kind == "project" else []
        if a.json:
            print(json.dumps({**_doc(it), "steps": [_doc(s) for s in steps]}, indent=2, sort_keys=True))  # fmt: skip
        else:
            print(_line(it))
            for k in ("project", "parent", "assignee", "due", "closed_on", "external_key"):
                if getattr(it, k):
                    print(f"  {k}: {getattr(it, k)}")
            for lk in it.links:
                print(f"  {lk.relation} -> {lk.target}")
            for s in sorted(steps, key=lambda s: s.order or 0):
                print("    " + _line(s))
            if it.description:
                print("\n" + it.description)
    elif a.cmd == "move":
        uid = _resolve(store, a.ref)
        version = a.version if a.version is not None else store.get(uid).version
        fields = {"status": a.status}
        if a.result is not None:
            fields["result"] = a.result
        _out(a, [store.update(uid, version, **fields)])
    elif a.cmd == "close":
        _out(a, [store.close(_resolve(store, a.ref), a.result, version=a.version)])
    elif a.cmd == "link":
        uid = _resolve(store, a.ref)
        target = _target(store, a, a.target)
        op = store.unlink if a.unlink else store.link
        _out(a, [op(uid, target, a.relation, version=a.version)])
    elif a.cmd == "check":
        found = store.check()  # loads the files: unreadable ones land in backend.problems
        problems = [*store.backend.problems, *found]
        if a.json:
            print(json.dumps(problems, indent=2))
        else:
            for p in problems:
                print(p)
        n = len(store.list())
        print(
            f"hnx projects check: {len(problems)} problem(s) in {n} item(s) of {a.dir}",
            file=sys.stderr,
        )
        return 1 if problems else 0
    elif a.cmd == "feed":
        from .events import change_events

        cs = store.changes_since(a.cursor)
        items = {i.uid: i for i in store.list()}
        for ev in change_events(cs.changes, items=items):
            print(json.dumps(ev, sort_keys=True))
        print(f"cursor: {cs.cursor}", file=sys.stderr)
    return 0


def _target_ref(store, a, ref: str) -> str:
    from homelabnext.identity import is_uid

    from .strategy import resolve_record

    uid = resolve_record(ref, a.strategy)
    return uid if is_uid(uid) else _resolve(store, ref)


def main(argv: Sequence[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
        return _run(a)
    except ProjectsError as exc:
        print(f"hnx projects {a.cmd}: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"hnx projects {a.cmd}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
