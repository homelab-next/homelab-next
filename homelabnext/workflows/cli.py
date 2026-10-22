# SPDX-License-Identifier: Apache-2.0
"""``hnx workflows``: validate (every pack in git, offline), run (one pack's fixtures), digest,
st2 render|check (the pinned packs as a StackStorm pack, docs/stackstorm.md), st2 bridge (the event
bridge from the bus to StackStorm's webhook)."""

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
    st = sub.add_parser(
        "st2", help="render or check the StackStorm pack of the bound packs; run the event bridge"
    )
    st.add_argument("action", choices=("render", "check", "bridge"))
    st.add_argument("--root", type=Path, default=None, help="git tree (default: cwd)")
    st.add_argument("--binding", type=Path, default=None, help="default: workflows/stackstorm.yml")
    st.add_argument("--out", type=Path, default=None, help="default: workflows/stackstorm")
    st.add_argument("--check", action="store_true", help="render: fail on drift, write nothing")
    br = st.add_argument_group("bridge (docs/stackstorm.md, the event bridge)")
    br.add_argument("--bridge-file", type=Path, default=None, help="the rendered bridge.json")
    br.add_argument("--st2-url", default=None, help="StackStorm's base URL (https)")
    br.add_argument("--ca-file", type=Path, default=None, help="CA bundle for StackStorm's TLS")
    br.add_argument(
        "--allow-plaintext",
        action="store_true",
        help="allow http to a host that is not loopback (the key would cross in clear)",
    )
    br.add_argument("--stream", default=None, help="the JetStream stream the events are in")
    br.add_argument("--subject-prefix", default=None, help="the stream's subject prefix")
    br.add_argument("--max-in-flight", type=int, default=8)
    br.add_argument("--max-deliver", type=int, default=100)
    br.add_argument("--stats-file", type=Path, default=None, help="JSON counters, for status")
    br.add_argument("--events-user", default=None, help="the bridge's NATS user")
    br.add_argument(
        "--events-password-secret",
        default=None,
        help="the NATS password by secret name (secret:<name>), never a value",
    )
    br.add_argument("--events-ca-file", default=None, help="CA bundle for a tls:// events endpoint")
    br.add_argument(
        "--events-allow-plaintext",
        action="store_true",
        help="allow the NATS password over nats:// to a host that is not loopback (the lab only)",
    )
    args = ap.parse_args(argv)
    try:
        if args.cmd == "st2":
            return _st2(args)
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


def _st2(args) -> int:
    from . import st2

    if args.action == "bridge":
        return _st2_bridge(args)

    root = (args.root or Path.cwd()).resolve()
    res, _binding = st2.render_repo(root, args.binding)
    out = args.out if args.out is not None else st2.DEFAULT_OUT
    out_dir = out if out.is_absolute() else root / out
    base = out.as_posix()
    problems = list(res.problems)
    check = args.check or args.action == "check"
    if not problems:
        if check:
            problems += st2.drift(res.files, out_dir, base)
        else:
            written = st2.write(res.files, out_dir)
            print(f"workflows st2: wrote {len(written)} file(s) under {base}")
    for p in problems:
        print(p)
    print(f"workflows st2: {len(res.files)} file(s), {len(problems)} problem(s)")
    return 1 if problems else 0


def _st2_bridge(args) -> int:
    """The event bridge: the bus (``HNX_ENDPOINT_EVENTS``, nats:// or tls://) to the webhook,
    until SIGTERM.  Exit 2 on a configuration error."""
    import contextlib
    import logging
    import signal
    import threading

    from homelabnext.conform.adapters import nats_jetstream

    from . import st2_bridge as sb

    if not (args.bridge_file and args.st2_url and args.stream and args.subject_prefix):
        print(
            "hnx workflows st2 bridge: --bridge-file, --st2-url, --stream and --subject-prefix "
            "are required",
            file=sys.stderr,
        )
        return 2
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        config = sb.load_bridge(args.bridge_file)
        hook = sb.Webhook(
            args.st2_url,
            config.webhook,
            config.api_key,
            ca_file=args.ca_file,
            allow_plaintext=args.allow_plaintext,
        )

        def connect():
            return nats_jetstream.make(
                scratch=False,
                provision=False,  # read the stream, manage durables, nothing else
                stream=args.stream,
                subject_prefix=args.subject_prefix,
                ack_wait=sb.ACK_WAIT_S,
                user=args.events_user,
                password_secret=args.events_password_secret,
                ca_file=args.events_ca_file,
                allow_plaintext=args.events_allow_plaintext,
                client_name="hnx-st2-bridge",
            )

        bus = connect()  # the first connect is checked here; later ones are the bridge's
    except Exception as exc:  # configuration, the endpoint variable, the first connect
        print(f"hnx workflows st2 bridge: {exc}", file=sys.stderr)
        return 2
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_a: stop.set())
    bridge = sb.Bridge(
        bus,
        config,
        hook,
        max_in_flight=args.max_in_flight,
        max_deliver=args.max_deliver,
        stats_file=args.stats_file,
        connect=connect,  # a transport failure reconnects instead of ending the process
    )
    try:
        bridge.run(stop)
    except sb.BridgeError as exc:  # a durable the bridge cannot use as it stands
        print(f"hnx workflows st2 bridge: {exc}", file=sys.stderr)
        return 2
    finally:
        with contextlib.suppress(Exception):
            bridge.bus.close()  # the bus it holds now (a reconnect replaces the first)
    return 0


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
