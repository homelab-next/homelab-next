# SPDX-License-Identifier: Apache-2.0
"""``hnx status``: the status hub's command line (read-only; ADR-0013, ``docs/status.md``).

    hnx status sources [--registry FILE] [--json]          the menu: every registered source
    hnx status catalog generate|check [--registry FILE] [--out FILE]   docs/status/sources.md
    hnx status views check [VIEWS] [--registry FILE]        views.yml against schema + registry
    hnx status collect [--registry FILE] [--root DIR] [--state FILE] [--all | --source ID ...]
                       [--notify-topic T] [--secrets-dir DIR] [--site SITE [--site-guests DIR]]
    hnx status render --out DIR [--state FILE] [--views FILE] [--registry FILE] [--now TIME]
                      [--guests DIR --guests-site SITE [--guests-registry FILE]] [--maps ROOT]
                      [--invariants-results FILE] [--roster FILE] [--mcp-catalog DIR]
    hnx status serve [--state FILE] [--views FILE] [--registry FILE] [--bind HOST] [--port N]
                     [--allow-remote --allowed-host NAME ...] [--agents FILE] [--secrets-dir DIR]
                     [--strategy DIR] [--projects DIR] [--orchestration DB]
                     [--guests DIR --guests-site SITE [--guests-registry FILE]]
                     [--maps ROOT] [--invariants-results FILE] [--roster FILE]
                     [--mcp-catalog DIR]
    hnx status ingest --agents FILE [--registry FILE] [--bind HOST] [--port N] [--publish-to URL]
                      [--allow-remote --allowed-host NAME ...] [--secrets-dir DIR]

``--agents`` (``examples/status/agents.yml``) turns on agent activity (stage 1b): ``collect``
drains the agent-activity sources into the activity store, ``render``/``serve`` add the agent
sessions to ``status.json`` and ``serve`` the agent pages (the private tier only behind the
trusted front door); ``ingest`` is the separate push listener (``POST /ingest/agent-activity``).
An ``approvals:`` block there has ``serve`` add the broker Approvals page (``/approvals``, behind
the same front door; the hub's one ``POST``: ``homelabnext.status.approvals``).
``--strategy`` (``examples/strategy``) has ``serve`` add the strategy pages (Strategy,
Requirements, Objectives, RFIs; ``docs/strategy.md``); ``--projects`` (``examples/projects``)
adds the Projects page (open projects and their steps, blocked work, work by strategy record;
``docs/projects.md``); ``--orchestration DB`` (the store ``hnx orchestration`` fills) adds the
Orchestration page (agent jobs per profile and backend, and one job's gateway turns;
``docs/orchestration-telemetry.md``); ``--guests`` (``examples/minimal/guests``
with ``--guests-site examples/minimal/site.yml``) adds the Baselines page, the guest x
defense-layer coverage matrix (``docs/compute-model.md``).
The generated maps (ADR-0018, ``homelabnext.status.maps``): ``--guests``/``--guests-site`` also
give the Topology page; ``--maps ROOT`` (a checkout, e.g. ``.``) the Dataflow, Architecture and
Roadmap pages, the roadmap reading ``--invariants-results`` (``build/invariants/results.json``
from ``make invariants``) for each criterion's state.  ``--maps`` also gives the directory pages:
Links (the registry's services), Schedule (every timer, CI schedule, workflow pack and collector
with its cadence and last/next run), Agent roster (``--roster FILE``, default
``ROOT/examples/status/roster.yml``) and MCP servers (``--mcp-catalog DIR``, default
``ROOT/examples/mcp``).  ``render`` writes each available page as ``<panel>.html``
beside ``index.html``.

``--site`` (every subcommand but ``catalog``) adds one ``poll-nut`` source per UPS the site
monitors by nut, from the registry's upsd template (``homelabnext.status.power``), with what
each UPS feeds from ``--site-guests``; ``render`` and ``serve`` default them to ``--guests-site``
and ``--guests``.  Give ``collect`` and ``render``/``serve`` the same site, or the generated
sources' readings are not shown.

``collect`` runs one pass over the due sources (``--all``: every polled source) and writes the
state file; ``render`` and ``serve`` only read it, so they never wait on a source.  Exit codes:
0 ok, 1 a check failed (stale catalog, invalid views), 2 usage or input error.
"""

from __future__ import annotations

import argparse
import contextlib
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


def _agents(args, reg, clock):
    """The agents config and its store, or (None, None) without ``--agents``."""
    if not getattr(args, "agents", None):
        return None, None
    from .agents.config import load_config, secret_lookup

    cfg = load_config(args.agents, reg, secret_lookup(secrets_dir=args.secrets_dir))
    for w in cfg.warnings:
        print(f"hnx status: {w}", file=sys.stderr)
    return cfg, cfg.open_store(clock)


def _hub(args, reg, specs, clock):
    from homelabnext.state import StateStore

    from .hub import StatusHub

    return StatusHub(specs, StateStore(args.state, clock=clock), clock=clock)


def _document(args, reg, specs, views, clock, site=None, *, approvals=False, maps=None):
    hub = _hub(args, reg, specs, clock)
    now = clock()
    agents = site.summary(now) if site is not None else None
    strategy = bool(getattr(args, "strategy", None))
    projects = bool(getattr(args, "projects", None))
    orchestration = bool(getattr(args, "orchestration", None))
    baselines = getattr(args, "cmd", "serve") == "serve" and bool(getattr(args, "guests", None))
    return build_status(
        hub.snapshot(now),
        views,
        reg,
        specs,
        agents=agents,
        strategy=strategy,
        baselines=baselines,
        approvals=approvals,
        maps=maps.available() if maps is not None else (),
        projects=projects,
        orchestration=orchestration,
    )


def main(argv: list[str] | None = None, *, clock: Callable[[], float] = time.time) -> int:
    """Entry point; ``clock`` is the process edge's real clock (injectable for tests)."""
    ap = argparse.ArgumentParser(prog="hnx status", description="the read-only status hub")
    sub = ap.add_subparsers(
        dest="cmd", required=True, metavar="{sources,catalog,views,collect,render,serve,ingest}"
    )

    def agents_opt(p, *, required=False):
        p.add_argument(
            "--agents", required=required, help="agents.yml: turn on agent activity (stage 1b)"
        )
        p.add_argument("--secrets-dir", help="files named after secret references (else env)")

    def remote_opts(p, port):
        p.add_argument("--bind", default=None, help="address to bind (default: loopback)")
        p.add_argument("--port", type=int, default=port)
        p.add_argument("--allow-remote", action="store_true", help="permit a non-loopback --bind")
        p.add_argument(
            "--allowed-host",
            action="append",
            default=[],
            help="hostname clients use besides loopback (repeatable; required with --allow-remote)",
        )

    def map_opts(p):
        p.add_argument("--guests", help="a guest directory: the Baselines and Topology pages")
        p.add_argument("--guests-site", help="the site model the guest directory's zones come from")
        p.add_argument(
            "--guests-registry",
            metavar="FILE",
            help="the registry that places services on those guests (Topology, Dataflow; "
            "default: --registry)",
        )
        p.add_argument(
            "--maps",
            metavar="ROOT",
            help="a checkout: the Dataflow, Architecture, Roadmap maps and the Links, Schedule, Roster pages",
        )
        p.add_argument(
            "--invariants-results", metavar="FILE", help="invariants results for the Roadmap"
        )
        p.add_argument(
            "--roster",
            metavar="FILE",
            help="roster.yml for the Agent roster (default: ROOT/examples/status/roster.yml)",
        )
        p.add_argument(
            "--mcp-catalog",
            metavar="DIR",
            help="the MCP catalog for the MCP servers page (default: ROOT/examples/mcp)",
        )

    def common(p, *, views=False, state=False, site=True):
        p.add_argument(
            "--registry", default=DEFAULT_REGISTRY, help="service registry (services.yml)"
        )
        if site:
            p.add_argument(
                "--site",
                help="site model: one poll-nut source per UPS it monitors by nut "
                "(render/serve default: --guests-site)",
            )
            p.add_argument(
                "--site-guests",
                metavar="DIR",
                help="guest directory: what each UPS feeds (render/serve default: --guests)",
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
    p.add_argument(
        "--power-lab",
        default=catalog.POWER_LAB,
        metavar="DIR",
        help="a lab (services.yml, site.yml, guests/) whose generated UPS sources the page "
        "also lists ('' for none)",
    )
    common(p, site=False)
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
    agents_opt(p)
    p = sub.add_parser("render", help="write the static page and status.json")
    common(p, views=True, state=True)
    p.add_argument("--out", required=True)
    p.add_argument("--now", help="RFC 3339 time to render at (default: now)")
    p.add_argument("--docs-base", default="docs")
    map_opts(p)
    agents_opt(p)
    p = sub.add_parser("serve", help="serve the page and status.json live (GET only)")
    common(p, views=True, state=True)
    remote_opts(p, 8099)
    p.add_argument("--docs-base", default="docs")
    p.add_argument("--strategy", help="a strategy directory: serve its pages (docs/strategy.md)")
    p.add_argument(
        "--projects", help="a projects directory: serve the Projects page (docs/projects.md)"
    )
    p.add_argument(
        "--orchestration",
        help="the orchestration telemetry store: serve the Orchestration page "
        "(docs/orchestration-telemetry.md)",
    )
    map_opts(p)
    agents_opt(p)
    p = sub.add_parser("ingest", help="the agent-activity push listener (POST only)")
    common(p)
    remote_opts(p, 8098)
    agents_opt(p, required=True)
    p.add_argument(
        "--publish-to",
        metavar="URL",
        help="events forwarder URL: also publish each stored summary as homelabnext.agent.activity",
    )
    p.add_argument(
        "--publish-state", help="the publisher's state file (default: STORE.publish.json)"
    )
    p.add_argument("--publish-source", default="svc:status-hub", help="the events' source")
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
    try:
        specs = _power_specs(args, specs)
    except ValueError as exc:
        print(f"hnx status: {exc}", file=sys.stderr)
        return 2
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
        try:
            ups = catalog.power_lab(args.power_lab) if args.power_lab else []
        except (ValueError, RegistryError) as exc:
            print(f"hnx status catalog: --power-lab {args.power_lab}: {exc}", file=sys.stderr)
            return 2
        if args.action == "generate":
            print(f"wrote {catalog.generate(args.out, specs, ups)}")
            return 0
        problems = catalog.check(args.out, specs, ups)
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
    from .agents.config import AgentsConfigError

    try:
        agents_cfg, store = _agents(args, reg, clock)
    except AgentsConfigError as exc:
        print(f"hnx status: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "collect":
        return _collect(args, reg, specs, clock, store)
    if args.cmd == "ingest":
        return _ingest(args, agents_cfg, store, clock)
    site = None
    if store is not None:
        from .agents.pages import AgentSite

        site = AgentSite(store, front_door=agents_cfg.front_door, clock=clock)
    try:
        views = load_views(args.views, reg, specs)
    except ViewsError as exc:
        print(f"hnx status: {exc}", file=sys.stderr)
        return 2
    try:
        maps = _map_site(args, reg)
    except ValueError as exc:
        print(f"hnx status {args.cmd}: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "render":
        from .render import write

        at = clock
        if args.now:
            fixed = parse_iso(args.now)
            at = lambda: fixed  # noqa: E731
        doc = _document(args, reg, specs, views, at, site, maps=maps)
        paths = write(args.out, doc, docs_base=args.docs_base)
        if maps is not None:
            paths += maps.write(args.out, doc)
        print("wrote " + ", ".join(str(p) for p in paths))
        return 0
    from .serve import LOOPBACK, make_server

    approvals = _approvals_site(agents_cfg, clock)
    served = approvals is not None
    try:
        srv = make_server(
            lambda: _document(args, reg, specs, views, clock, site, approvals=served, maps=maps),
            host=args.bind or LOOPBACK,
            port=args.port,
            allow_remote=args.allow_remote,
            allowed_hosts=args.allowed_host,
            docs_base=args.docs_base,
            agents=site,
            strategy=_strategy_site(args, clock),
            projects=_projects_site(args, clock),
            orchestration=_orchestration_site(args, clock),
            baselines=_baseline_site(args),
            approvals=approvals,
            maps=maps,
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


def _power_specs(args, specs):
    """The registry's sources plus one per site UPS monitored by nut (``--site``, else on
    render/serve ``--guests-site``), with what each feeds from ``--site-guests`` (``--guests``)."""
    site = getattr(args, "site", None) or getattr(args, "guests_site", None)
    if site and not any(s.kind == "poll-nut" for s in specs):
        return specs  # no upsd registered: nothing to generate
    if not site:
        if getattr(args, "site_guests", None):
            raise ValueError("--site-guests needs --site")
        return specs
    guests = getattr(args, "site_guests", None)
    if guests is None and not getattr(args, "site", None):
        guests = getattr(args, "guests", None)
    from .power import load as load_power

    return load_power(specs, site, guests)


def _baseline_site(args):
    """The Baselines page for ``--guests DIR --guests-site SITE``, or None."""
    if not getattr(args, "guests", None):
        return None
    if not args.guests_site:
        raise ValueError("--guests needs --guests-site (the site model that defines the zones)")
    from homelabnext.compute.pages import BaselineSite

    return BaselineSite(args.guests, args.guests_site)


def _map_site(args, reg):
    """The generated maps for ``--guests``/``--guests-site``, ``--maps`` and
    ``--invariants-results``, or None when none of them is given."""
    guests, root = getattr(args, "guests", None), getattr(args, "maps", None)
    results = getattr(args, "invariants_results", None)
    if guests and not args.guests_site:
        raise ValueError("--guests needs --guests-site (the site model that defines the zones)")
    if root and not Path(root).is_dir():
        raise ValueError(f"--maps {root}: not a directory")
    if results and not root:
        raise ValueError("--invariants-results needs --maps (the checkout the roadmap reads)")
    roster = getattr(args, "roster", None)
    if roster and not root:
        raise ValueError("--roster needs --maps (the checkout the directory pages read)")
    if roster and not Path(roster).is_file():
        raise ValueError(f"--roster {roster}: not a file")
    mcp_catalog = getattr(args, "mcp_catalog", None)
    if mcp_catalog and not root:
        raise ValueError("--mcp-catalog needs --maps (the checkout the directory pages read)")
    if mcp_catalog and not Path(mcp_catalog).is_dir():
        raise ValueError(f"--mcp-catalog {mcp_catalog}: not a directory")
    lab_file = getattr(args, "guests_registry", None)
    if lab_file and not guests:
        raise ValueError("--guests-registry needs --guests (the guests its services run on)")
    if not guests and not root:
        return None
    from .maps import MapSite

    try:
        lab = load(lab_file) if lab_file else None
    except RegistryError as exc:
        raise ValueError(f"--guests-registry {lab_file}: {exc}") from None
    return MapSite(
        root=root,
        registry=reg,
        guests=guests,
        guests_site=args.guests_site,
        results=results,
        lab_registry=lab,
        roster=roster,
        mcp_catalog=mcp_catalog,
    )


def _strategy_site(args, clock: Callable[[], float]):
    """The strategy pages for ``--strategy DIR``, or None."""
    if not getattr(args, "strategy", None):
        return None
    from homelabnext.strategy.pages import StrategySite

    return StrategySite(args.strategy, clock=clock)


def _orchestration_site(args, clock: Callable[[], float]):
    """The Orchestration page for ``--orchestration DB``, or None."""
    if not getattr(args, "orchestration", None):
        return None
    from homelabnext.orchestration.pages import OrchestrationSite
    from homelabnext.orchestration.store import TelemetryStore

    return OrchestrationSite(TelemetryStore(args.orchestration, clock=clock), clock=clock)


def _projects_site(args, clock: Callable[[], float]):
    """The Projects page for ``--projects DIR`` (linking to ``--strategy DIR``), or None."""
    if not getattr(args, "projects", None):
        return None
    from homelabnext.projects.pages import ProjectsSite

    return ProjectsSite(args.projects, strategy=getattr(args, "strategy", None), clock=clock)


def _approvals_site(cfg, clock: Callable[[], float]):
    """The Approvals page when ``agents.yml`` configures it (and its front door is on)."""
    if cfg is None or cfg.approvals is None or cfg.front_door is None:
        return None
    from .approvals import ApprovalsSite

    return ApprovalsSite.from_settings(cfg.approvals, cfg.front_door, clock=clock)


def _ingest(args, cfg, store, clock: Callable[[], float]) -> int:
    from .agents.ingest import make_ingest_server
    from .serve import LOOPBACK

    if cfg.ingest is None or not cfg.ingest.senders:
        print("hnx status ingest: no sender with a resolvable token in --agents", file=sys.stderr)
        return 2
    try:
        srv = make_ingest_server(
            store,
            cfg.ingest,
            host=args.bind or LOOPBACK,
            port=args.port,
            allow_remote=args.allow_remote,
            allowed_hosts=args.allowed_host,
            clock=clock,
            publish=_publisher(args, cfg),
        )
    except (ValueError, OSError) as exc:
        print(f"hnx status ingest: {exc}", file=sys.stderr)
        return 2
    host, port = srv.server_address[:2]
    print(f"agent-activity ingest on http://{host}:{port}/ingest/agent-activity  (Ctrl-C stops)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def _publisher(args, cfg):
    """The ingest's bus hook for ``--publish-to``, or None.  One send attempt per event inside
    the request (the sender is not kept waiting on retries); what did not go stays pending in
    the state file and is flushed when the listener next starts."""
    if not getattr(args, "publish_to", None):
        return None
    from homelabnext.events.forwarder import HttpForwarder
    from homelabnext.events.publisher import Publisher, RetryPolicy
    from homelabnext.state import StateStore

    from .agents.ingest import bus_publisher

    state = args.publish_state or f"{cfg.store}.publish.json"
    pub = Publisher(
        HttpForwarder(args.publish_to), StateStore(state), policy=RetryPolicy(max_attempts=1)
    )
    with contextlib.suppress(Exception):  # an unreachable bus never stops the ingest
        pub.flush()
    return bus_publisher(pub, args.publish_source)


def _collect(args, reg, specs, clock: Callable[[], float], store=None) -> int:
    from .agents.config import secret_lookup
    from .collectors import CollectContext, UrllibClient, registry_endpoint
    from .scheduler import Scheduler, due

    hub = _hub(args, reg, specs, clock)
    ctx = CollectContext(
        clock=clock,
        http=UrllibClient(),
        endpoint=registry_endpoint(reg),
        root=Path(args.root),
        activity=store,
        secret=secret_lookup(secrets_dir=args.secrets_dir),  # a source's auth, by name
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
