# SPDX-License-Identifier: Apache-2.0
"""``hnx status``: the status hub's command line (read-only; ADR-0013, ``docs/status.md``).

    hnx status sources [--registry FILE] [--json]          the menu: every registered source
    hnx status catalog generate|check [--registry FILE] [--out FILE]   docs/status/sources.md
    hnx status views check [VIEWS] [--registry FILE]        views.yml against schema + registry
    hnx status collect [--registry FILE] [--root DIR] [--state FILE] [--all | --source ID ...]
                       [--notify-topic T]
    hnx status render --out DIR [--state FILE] [--views FILE] [--registry FILE] [--now TIME]
    hnx status serve [--state FILE] [--views FILE] [--registry FILE] [--bind HOST] [--port N]

``collect`` runs one pass over the due sources (``--all``: every polled source) and writes the
state file; ``render`` and ``serve`` only read it, so they never wait on a source.  Exit codes:
0 ok, 1 a check failed (stale catalog, invalid views), 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

from homelabnext.registry.model import RegistryError, load

from . import catalog
from .model import parse_iso, sources_from_registry
from .views import ViewsError, build_status, load_views

DEFAULT_REGISTRY = "examples/services.yml"
DEFAULT_VIEWS = "examples/status/views.yml"
DEFAULT_STATE = "build/status/state.json"


def _hub(args, reg, specs, clock):
    from homelabnext.state import StateStore

    from .hub import StatusHub

    return StatusHub(specs, StateStore(args.state, clock=clock), clock=clock)


def _document(args, reg, specs, views, clock):
    hub = _hub(args, reg, specs, clock)
    return build_status(hub.snapshot(clock()), views, reg, specs)


def main(argv: list[str] | None = None, *, clock: Callable[[], float] = time.time) -> int:
    """Entry point; ``clock`` is the process edge's real clock (injectable for tests)."""
    ap = argparse.ArgumentParser(prog="hnx status", description="the read-only status hub")
    sub = ap.add_subparsers(
        dest="cmd", required=True, metavar="{sources,catalog,views,collect,render,serve}"
    )

    def common(p, *, views=False, state=False):
        p.add_argument(
            "--registry", default=DEFAULT_REGISTRY, help="service registry (services.yml)"
        )
        if views:
            p.add_argument("--views", default=DEFAULT_VIEWS, help="views.yml (shell and menu)")
        if state:
            p.add_argument("--state", default=DEFAULT_STATE, help="the hub's state file")

    p = sub.add_parser("sources", help="list every registered status source (the menu)")
    common(p)
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("catalog", help="generate or check docs/status/sources.md")
    p.add_argument("action", choices=["generate", "check"])
    p.add_argument("--out", default=str(catalog.PAGE))
    common(p)
    p = sub.add_parser("views", help="check a views.yml against its schema and the registry")
    p.add_argument("action", choices=["check"])
    p.add_argument("file", nargs="?", default=DEFAULT_VIEWS)
    common(p)
    p = sub.add_parser("collect", help="one collection pass over the due sources")
    common(p, state=True)
    p.add_argument("--root", default=".", help="what poll-file targets are relative to")
    p.add_argument("--all", action="store_true", help="every polled source, due or not")
    p.add_argument(
        "--source", action="append", help="only this source (repeatable; implies due or not)"
    )
    p.add_argument("--notify-topic", help="page transitions through the registry's notify service")
    p = sub.add_parser("render", help="write the static page and status.json")
    common(p, views=True, state=True)
    p.add_argument("--out", required=True)
    p.add_argument("--now", help="RFC 3339 time to render at (default: now)")
    p.add_argument("--docs-base", default="docs")
    p = sub.add_parser("serve", help="serve the page and status.json live (GET only)")
    common(p, views=True, state=True)
    p.add_argument("--bind", default=None, help="address to bind (default: loopback)")
    p.add_argument("--port", type=int, default=8099)
    p.add_argument("--allow-remote", action="store_true", help="permit a non-loopback --bind")
    p.add_argument("--docs-base", default="docs")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        reg = load(args.registry)
    except RegistryError as exc:
        print(f"hnx status: {exc}", file=sys.stderr)
        return 2
    specs = sources_from_registry(reg)
    if args.cmd == "sources":
        rows = [s.describe() for s in specs]
        if args.json:
            print(json.dumps({"sources": rows}, indent=1, sort_keys=True))
        else:
            for r in rows:
                flag = " (reserved)" if r["reserved"] else ""
                print(
                    f"{r['id']:<22} {r['kind']:<15} {r['module']:<14} every {r['interval_s']:g}s, "
                    f"stale after {r['stale_after_s']:g}s{flag}  {r['what']}"
                )
            print(f"{len(rows)} status source(s)")
        return 0
    if args.cmd == "catalog":
        if args.action == "generate":
            print(f"wrote {catalog.generate(args.out, specs)}")
            return 0
        problems = catalog.check(args.out, specs)
        for line in problems:
            print(line)
        print(f"status catalog: {'FAIL' if problems else 'ok'} ({args.out})")
        return 1 if problems else 0
    if args.cmd == "views":
        try:
            doc = load_views(args.file, reg, specs)
        except ViewsError as exc:
            print(f"hnx status views: {exc}", file=sys.stderr)
            return 1
        print(f"views: ok ({args.file}: {len(doc['menu'])} menu entries)")
        return 0
    if args.cmd == "collect":
        return _collect(args, reg, specs, clock)
    try:
        views = load_views(args.views, reg, specs)
    except ViewsError as exc:
        print(f"hnx status: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "render":
        from .render import write

        at = clock
        if args.now:
            fixed = parse_iso(args.now)
            at = lambda: fixed  # noqa: E731
        paths = write(args.out, _document(args, reg, specs, views, at), docs_base=args.docs_base)
        print("wrote " + ", ".join(str(p) for p in paths))
        return 0
    from .serve import LOOPBACK, make_server

    try:
        srv = make_server(
            lambda: _document(args, reg, specs, views, clock),
            host=args.bind or LOOPBACK,
            port=args.port,
            allow_remote=args.allow_remote,
            docs_base=args.docs_base,
        )
    except (ValueError, OSError) as exc:
        print(f"hnx status serve: {exc}", file=sys.stderr)
        return 2
    host, port = srv.server_address[:2]
    print(f"status hub (read-only) on http://{host}:{port}/  (Ctrl-C stops)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def _collect(args, reg, specs, clock: Callable[[], float]) -> int:
    from .collectors import CollectContext, UrllibClient, registry_endpoint
    from .scheduler import Scheduler, due

    hub = _hub(args, reg, specs, clock)
    ctx = CollectContext(
        clock=clock, http=UrllibClient(), endpoint=registry_endpoint(reg), root=Path(args.root)
    )
    if args.source:
        unknown = sorted(set(args.source) - {s.id for s in specs})
        if unknown:
            print(f"hnx status collect: unknown source(s) {unknown}", file=sys.stderr)
            return 2
        todo = [s for s in specs if s.id in args.source and s.polled]
    elif args.all:
        todo = [s for s in specs if s.polled]
    else:
        todo = due(specs, hub.last_attempts(), clock())
    results = Scheduler().run(todo, ctx)
    for r in results:
        hub.record(r)
        print(
            f"{r.source:<22} {'ok' if r.ok else 'error'}  {len(r.drafts)} item(s)  {r.error or ''}"
        )
    if args.notify_topic:
        from homelabnext.notify import Notifier, NtfySender
        from homelabnext.registry.resolver import Resolver

        sender = NtfySender(default_topic=args.notify_topic, resolver=Resolver(reg))
        sent = hub.notify(Notifier(sender, hub.store, clock=clock))
        print(f"notifications sent: {len(sent)}")
    print(f"collected {len(results)} source(s) into {args.state}")
    return 0
