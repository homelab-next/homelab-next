# SPDX-License-Identifier: Apache-2.0
"""``hnx broker``: validate a manifest, serve the broker, and talk to it from a shell.

``validate MANIFEST`` checks the manifest schema, every handler document and its pinned digest,
the lane configuration and the transport peers.  With ``--data-root DIR`` (or
``$HNX_BROKER_DATA_ROOT``) it also prints what each lane directory holds against its quota and
warns at 80% (:func:`homelabnext.broker.lanes.usage`); ``serve`` logs the same at start.  A
warning does not fail validation: an agent writing there is about to be refused
``lane-quota-exceeded``, and this is how the operator hears it first.

``serve --socket PATH`` runs the broker on a Unix socket whose callers are authenticated by their
peer credentials (:mod:`homelabnext.broker.server`); with ``--notify-topic T`` (its access
token given by secret reference, ``--notify-token``) it pages approval requests and lane-quota
notices through ntfy (:func:`notifier_from_args`); ``mcp --socket PATH`` runs the agent-facing
MCP tool server (stdio) against it (:mod:`homelabnext.broker.mcp_tools`).

``relay --state DIR --events-target FILE --stream S --subject-prefix P`` publishes the state
directory's outbox to the event bus, at least once and in order (:mod:`homelabnext.broker.relay`);
``--once`` publishes what is pending and exits (1 when something is still pending); ``--skip ID``
marks one event undeliverable by hand (the operator's escape for an event the bus will not take;
it takes the relay lock, so stop the relay first).

The request commands work two ways:

* with ``--socket PATH`` (or ``$HNX_BROKER_SOCKET``) they ask a running broker, which knows who
  this process is: no ``--as`` for an agent's commands, and ``approve``/``deny`` need this
  process to be an approval relay, with ``--as ISSUER:SUBJECT`` naming the human it vouches for;
* without it they open the state directory directly (``--manifest`` / ``$HNX_BROKER_MANIFEST``,
  ``--state`` / ``$HNX_BROKER_STATE``; lanes under ``--data-root`` / ``$HNX_BROKER_DATA_ROOT``,
  default ``<state>/lanes``) with an **asserted** ``--as`` identity.  That is the development
  path: it is refused unless the manifest sets ``dev_identity: true``.

    actions [--as ACTOR]
    call|submit ACTION [--as ACTOR] [--params JSON | --params-file FILE] [--target svc:NAME]
    status|run|cancel REQUEST_ID [--as ACTOR]
    approve|deny REQUEST_ID --as ISSUER:SUBJECT [--note TEXT]
    pending [--mine [--as ACTOR]]
    audit [--action A] [--caller C] [--request R] [--outcome O] [--operation P] [--tail N]
    agents
    import-proposals DIR [--apply] [--action proposal.file] [--default-risk R]
                     [--default-rollback TEXT] [--as ACTOR]

``import-proposals`` reads a directory of vault-style proposal Markdown files (front-matter) and
files each as a ``proposal.file`` lane record through the broker (dry run unless ``--apply``),
reporting what it could not map (:mod:`homelabnext.broker.importer`).

``agents`` (the operator's: root on the broker's host, over ``--socket``) prints the agent keys
the running broker serves, one per line; without a socket it reads them from the manifest.

``--json`` prints machine-readable output.

Exit: 0 ok, 1 refused or failed (the reason is printed), 2 usage error or an invalid manifest.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sys
import threading
from pathlib import Path
from typing import Any

from conformance.protocols.broker import BrokerError

from .service import BrokerService, ManifestError, _reasoned, load_manifest, validate_manifest

_AGENT_CMDS = ("actions", "call", "submit", "status", "run", "cancel")


def _service_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--manifest", default=os.environ.get("HNX_BROKER_MANIFEST"))
    p.add_argument("--state", default=os.environ.get("HNX_BROKER_STATE"))
    p.add_argument("--data-root", default=os.environ.get("HNX_BROKER_DATA_ROOT"))
    p.add_argument(
        "--approvals-url",
        default=os.environ.get("HNX_BROKER_APPROVALS_URL"),
        help="the hub's Approvals page (https://.../approvals): linked from decision.requested",
    )


def _common(p: argparse.ArgumentParser) -> None:
    _service_opts(p)
    p.add_argument(
        "--socket",
        default=os.environ.get("HNX_BROKER_SOCKET"),
        help="talk to the broker serving this socket instead of opening the state directly",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")


def _params_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--params", help="params as a JSON object")
    g.add_argument("--params-file", help="params from a JSON file")
    p.add_argument("--target", help="svc:NAME the action is about")


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx broker", description="the reference broker service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check a manifest, its handler digests, lanes and peers")
    v.add_argument("path")
    v.add_argument("--json", action="store_true")
    v.add_argument(
        "--data-root",
        default=os.environ.get("HNX_BROKER_DATA_ROOT"),
        help="also show each lane directory's usage against its quota (warn at 80%%)",
    )
    v.add_argument(
        "--state",
        default=os.environ.get("HNX_BROKER_STATE"),
        help="with --data-root: the broker's state directory, read for a shared files lane's "
        "owner index (each actor's share); never written",
    )
    srv = sub.add_parser("serve", help="serve the broker on a Unix socket (peer-authenticated)")
    _service_opts(srv)
    srv.add_argument(
        "--socket", required=True, help="socket path, e.g. /run/hnx-broker/broker.sock"
    )
    srv.add_argument(
        "--socket-mode", default="600", help="octal socket mode (default 600; 660 with a group)"
    )
    srv.add_argument("--socket-group", help="group owning the socket (the agents' group)")
    srv.add_argument("--max-request-bytes", type=int, default=None)
    srv.add_argument("--timeout", type=float, default=None, help="seconds to read one request")
    srv.add_argument(
        "--notify-topic",
        help="page the approver (approval requests) and the operator (lane quotas) on this ntfy "
        "topic (visible in ps: prefer $HNX_BROKER_NOTIFY_TOPIC or --notify-topic-file); the "
        "endpoint is the notify capability (--registry, else HNX_ENDPOINT_NOTIFY)",
    )
    srv.add_argument("--notify-topic-file", help="read the ntfy topic from this file's first line")
    srv.add_argument(
        "--notify-token",
        default=os.environ.get("HNX_BROKER_NOTIFY_TOKEN"),
        metavar="secret:NAME",
        help="the ntfy access token, as a secret reference: its value is read at send time "
        "from the environment variable it names (secret:broker/ntfy-token -> "
        "HNX_SECRET_BROKER_NTFY_TOKEN), never from the command line",
    )
    srv.add_argument("--registry", help="services.yml: resolve the notify capability through it")
    rel = sub.add_parser("relay", help="publish the outbox to the event bus (at least once)")
    rel.add_argument("--state", default=os.environ.get("HNX_BROKER_STATE"))
    rel.add_argument(
        "--events-target",
        help="a target file binding the events capability (adapter, config; no URL, no secret)",
    )
    rel.add_argument("--stream", help="the standing JetStream stream")
    rel.add_argument("--subject-prefix", help="the stream's subject prefix")
    rel.add_argument("--once", action="store_true", help="publish what is pending, then exit")
    rel.add_argument(
        "--skip",
        metavar="EVENT_ID",
        action="append",
        help="mark this outbox event undeliverable (never published) and exit; repeatable "
        "(takes the relay lock: stop the relay first)",
    )
    rel.add_argument(
        "--since",
        help="first start only: outbox events from before the relay older than this ISO time "
        "are marked superseded, never published",
    )
    rel.add_argument(
        "--max-attempts",
        type=int,
        default=5,
        help="permanent refusals of one event before it is undeliverable (default 5)",
    )
    rel.add_argument(
        "--retain-days",
        type=float,
        default=30.0,
        help="keep delivered markers this long after the broker pruned the event (default 30)",
    )
    rel.add_argument("--batch", type=int, default=100, help="events per pass (default 100)")
    rel.add_argument("--idle", type=float, default=1.0, help="seconds between idle passes")
    rel.add_argument("--backoff-max", type=float, default=60.0, help="longest retry wait (s)")
    rel.add_argument("--stats-file", help="write the relay's stats here (a poll-file source)")
    m = sub.add_parser("mcp", help="the agent-facing MCP tool server (stdio) for a broker socket")
    m.add_argument("--socket", default=os.environ.get("HNX_BROKER_SOCKET"))
    for name in _AGENT_CMDS:
        p = sub.add_parser(name, help=f"{name} (as the authenticated caller)")
        if name in ("call", "submit"):
            p.add_argument("action")
            _params_opts(p)
        elif name != "actions":
            p.add_argument("request_id")
        p.add_argument("--as", dest="who", help="the actor, profile:NAME (dev identity only)")
    for name in ("approve", "deny"):
        p = sub.add_parser(name, help=f"{name} a request")
        p.add_argument("request_id")
        p.add_argument("--as", dest="who", required=True, help="the approver, issuer:subject")
        p.add_argument("--note")
    pend = sub.add_parser("pending", help="requests awaiting approval (--mine: your own pending)")
    pend.add_argument("--mine", action="store_true")
    pend.add_argument("--as", dest="who", help="with --mine and no socket: the actor (dev only)")
    a = sub.add_parser("audit", help="print audit records (oldest first)")
    for f in ("action", "caller", "outcome", "operation"):
        a.add_argument(f"--{f}")
    a.add_argument("--request", dest="request_id")
    a.add_argument("--tail", type=int, help="only the last N records")
    sub.add_parser(
        "agents", help="the agent keys the broker serves (operator: root, over --socket)"
    )
    imp = sub.add_parser(
        "import-proposals", help="file a directory of vault-style proposals through the broker"
    )
    imp.add_argument("directory")
    imp.add_argument("--apply", action="store_true", help="file them (default: dry run)")
    imp.add_argument("--action", default="proposal.file", help="the records-inbox lane action")
    imp.add_argument("--default-risk", choices=("low", "medium", "high"))
    imp.add_argument("--default-rollback", help="rollback text for proposals that have none")
    imp.add_argument("--as", dest="who", help="the importing actor (dev identity only)")
    for p in sub.choices.values():
        if p.prog.split()[-1] not in ("validate", "serve", "mcp", "relay"):
            _common(p)
    return ap


def _out(args, payload: Any, text: str) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else text)


def _validate(args) -> int:
    path = Path(args.path)
    from .service import _parse_errors, _read_doc

    try:
        manifest = _read_doc(path)
    except _parse_errors() as exc:  # malformed YAML too: a usage error, never a traceback
        print(f"hnx broker validate: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        problems = [f"{path}: not a mapping"]
    else:
        _, problems = validate_manifest(manifest, path.parent)
    rows = []
    if args.data_root and not problems:
        ledger = Path(args.state) / "lanes-ledger" if args.state else None
        rows = lane_usage(manifest, args.data_root, ledger=ledger)
    if args.json:
        doc = {"manifest": str(path), "ok": not problems, "problems": problems}
        if args.data_root:
            doc["lane_usage"] = rows
        print(json.dumps(doc, indent=2))
    elif problems:
        print("\n".join(f"{path}: {p}" for p in problems))
    else:
        actions = len(manifest["actions"])
        print(f"{path}: ok ({actions} actions, {len(manifest.get('lanes', []))} lanes)")
        for row in rows:
            print(_usage_line(row))
    return 1 if problems else 0


def lane_usage(
    manifest: dict[str, Any], data_root: str | os.PathLike[str], *, ledger: Any = None
) -> list[dict]:
    """Every lane directory's usage row (:func:`homelabnext.broker.lanes.usage`); a shared
    inbox's files are attributed to the manifest's granted profiles by name (the broker's own
    ``serve`` verifies each name's tag)."""
    from . import lanes

    actors = tuple(sorted({g["profile"] for g in manifest.get("grants", [])}))
    return [
        r
        for ld in manifest.get("lanes", [])
        for r in lanes.usage(lanes.Lane.from_doc(ld), data_root, actors=actors, ledger=ledger)
    ]


def _usage_line(row: dict[str, Any]) -> str:
    files = (
        f"{row['files']}/{row['max_files']}" if row["max_files"] is not None else str(row["files"])
    )
    line = (
        f"lane {row['lane']} {row['dir']}: {files} files, "
        f"{row['bytes']}/{row['max_total_bytes']} bytes ({row['used']:.0%} of its quota)"
    )
    lines = [line + ("  WARNING: over 80% of its quota" if row["warn"] else "")]
    for actor, share in (row.get("actors") or {}).items():
        files = f"{share['files']}/{row['max_files_per_actor']}"
        lines.append(
            f"  {actor}: {files} files, {share['bytes']}/{row['max_bytes_per_actor']} bytes "
            f"({share['used']:.0%} of its share)"
            + ("  WARNING: over 80% of its share" if share["warn"] else "")
        )
    return "\n".join(lines)


#: what serve's notifier may send: per agent, and over all agents together (a loose backstop)
NOTIFY_PER_AGENT_PER_HOUR = 20
NOTIFY_ALL_AGENTS_PER_HOUR = 60


def _notify_topic(args) -> str | None:
    """The topic from ``--notify-topic`` (visible in ``ps``), else ``$HNX_BROKER_NOTIFY_TOPIC``,
    else the first line of ``--notify-topic-file`` (or ``$HNX_BROKER_NOTIFY_TOPIC_FILE``): the
    file keeps a topic that anonymous readers could subscribe to out of the process list."""
    topic = getattr(args, "notify_topic", None) or os.environ.get("HNX_BROKER_NOTIFY_TOPIC")
    path = getattr(args, "notify_topic_file", None) or os.environ.get(
        "HNX_BROKER_NOTIFY_TOPIC_FILE"
    )
    if not topic and path:
        try:
            topic = Path(path).read_text(encoding="utf-8").strip().splitlines()[0].strip()
        except (OSError, IndexError, UnicodeDecodeError):
            raise ValueError(f"--notify-topic-file {path}: no topic can be read") from None
    return topic or None


def notifier_from_args(args) -> Any:
    """The ntfy notifier ``serve`` pages through, or None without a topic: state-diffed
    (``<state>/notify.json``), :data:`NOTIFY_PER_AGENT_PER_HOUR` sends an hour per agent and
    :data:`NOTIFY_ALL_AGENTS_PER_HOUR` over all of them.  The token is a ``secret:`` reference
    resolved at send time; a literal is refused, so no token ever sits in a unit file, a shell
    history or ``ps``.  The endpoint is resolved now, and a plaintext one refused when a token
    would cross it, so a misconfigured notifier stops ``serve`` instead of failing every send."""
    topic = _notify_topic(args)
    if not topic:
        return None
    from homelabnext._http import check_plaintext
    from homelabnext.notify import Notifier, NtfySender, RateLimit
    from homelabnext.registry.model import secret_env_name
    from homelabnext.state import StateStore

    ref = getattr(args, "notify_token", None)
    auth = None
    if ref:
        if not ref.startswith("secret:") or len(ref) <= len("secret:"):
            raise ValueError("--notify-token takes a secret reference (secret:NAME), not a token")
        var = secret_env_name(ref)
        if not os.environ.get(var, "").strip():
            raise ValueError(f"--notify-token {ref}: {var} is not set")

        def auth() -> str | None:
            value = os.environ.get(var, "").strip()
            return f"Bearer {value}" if value else None

    resolver = None
    if getattr(args, "registry", None):
        from homelabnext.registry import load
        from homelabnext.registry.resolver import Resolver

        resolver = Resolver(load(args.registry))
    sender = NtfySender(default_topic=topic, auth=auth, resolver=resolver)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", topic):
        raise ValueError("the ntfy topic is 1 to 64 letters, digits, '_' or '-'")
    try:
        base = sender.base_url()
    except Exception as exc:
        raise ValueError(f"notify endpoint: {exc}") from None
    if auth is not None:
        check_plaintext(base, credentials=True, allow_plaintext=False)
    store = StateStore(Path(args.state) / "notify.json")
    limit = RateLimit(
        max_sends=NOTIFY_PER_AGENT_PER_HOUR,
        window_s=3600.0,
        max_sends_all_scopes=NOTIFY_ALL_AGENTS_PER_HOUR,
    )
    return Notifier(sender, store, rate_limit=limit)


def _service(args) -> BrokerService:
    if not args.manifest or not args.state:
        raise SystemExit(
            "hnx broker: --manifest and --state (or HNX_BROKER_MANIFEST and HNX_BROKER_STATE) are required"
        )
    manifest, docs = load_manifest(args.manifest)
    data_root = args.data_root or Path(args.state) / "lanes"
    return BrokerService(
        args.state,
        manifest,
        handler_docs=docs,
        base_dir=Path(args.manifest).parent,
        data_root=data_root,
        approvals_url=args.approvals_url,
        # only the long-running server pages: a local CLI command (pending, approve, audit, ...)
        # with the topic exported beside HNX_BROKER_STATE must neither page nor fail on it
        notifier=notifier_from_args(args) if getattr(args, "cmd", None) == "serve" else None,
    )


def _params(args) -> dict[str, Any]:
    raw = args.params
    if args.params_file:
        raw = Path(args.params_file).read_text(encoding="utf-8")
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict):
        raise ValueError("params must be a JSON object")
    return value


class _Local:
    """The request commands against the state directory, with the asserted ``--as``."""

    def __init__(self, args) -> None:
        self.svc = _service(args)
        self.args = args

    def _dev_only(self, message: str) -> None:
        """Refuse an asserted identity unless the manifest sets ``dev_identity: true``."""
        if self.svc.manifest.get("dev_identity") is not True:
            raise _reasoned(message, "dev-identity-disabled")

    def _who(self) -> str:
        self._dev_only(
            "this manifest does not accept an asserted --as identity (dev_identity is not "
            "true); use --socket against a running broker"
        )
        if not self.args.who:
            raise ValueError("--as is required without --socket")
        return self.args.who

    def actions(self):
        who = self._who()
        return {"caller": who, "actions": self.svc.actions_for(who)}

    def call(self, action, params, target):
        return self.svc.call(self._who(), action, params, target=target)

    def submit(self, action, params, target):
        rid = self.svc.submit(self._who(), action, params, target=target)
        waiting = self.svc.state.get_request(rid)["verdict"] == "needs-approval"
        return {"request_id": rid, "state": "pending", "awaiting_approval": waiting}

    def status(self, rid):
        return self.svc.detail(self._who(), rid)

    def run(self, rid):
        return self.svc.run(self._who(), rid)

    def cancel(self, rid):
        self.svc.cancel(self._who(), rid)

    def decide(self, cmd, rid, who, note):
        self._dev_only(
            "this manifest does not accept an asserted approver; approvals come from an "
            "approval relay over the socket"
        )
        fn = self.svc.approve if cmd == "approve" else self.svc.deny
        return fn(rid, who, note=note)

    def pending(self, mine):
        return self.svc.pending_for(self._who()) if mine else self.svc.pending()

    def audit(self, **match):
        return self.svc.audit_documents(**match)

    def agents(self):
        return self.svc.served_agents()


class _Remote:
    """The request commands against a running broker; the broker knows who this process is."""

    def __init__(self, args) -> None:
        from .client import BrokerClient

        if getattr(args, "who", None) and args.cmd in (*_AGENT_CMDS, "pending", "import-proposals"):
            raise ValueError("--as is not accepted with --socket: the broker authenticates you")
        self.c = BrokerClient(args.socket)

    def actions(self):
        return self.c.actions()

    def call(self, action, params, target):
        return self.c.call(action, params, target=target)

    def submit(self, action, params, target):
        return self.c.submit(action, params, target=target)

    def status(self, rid):
        return self.c.status(rid)

    def run(self, rid):
        return self.c.run(rid)

    def cancel(self, rid):
        self.c.cancel(rid)

    def decide(self, cmd, rid, who, note):
        issuer, sep, subject = who.partition(":")
        if not sep:
            raise ValueError("--as is the approver, issuer:subject")
        fn = self.c.approve if cmd == "approve" else self.c.deny
        return fn(rid, issuer, subject, note=note)

    def pending(self, mine):
        return self.c.pending_for_me() if mine else self.c.pending()

    def audit(self, **match):
        return self.c.audit(tail=500, **match)

    def agents(self):
        return self.c.agents()


def _run(args) -> int:
    b = _Remote(args) if args.socket else _Local(args)
    if args.cmd == "actions":
        doc = b.actions()
        text = "\n".join(
            f"{r['action']}  {r['tier']}  {r['kind']}"
            + ("  [needs approval]" if r["needs_approval"] else "")
            for r in doc["actions"]
        )
        _out(args, doc, text or f"{doc['caller']} may do nothing")
    elif args.cmd == "call":
        result = b.call(args.action, _params(args), args.target)
        _out(args, {"result": result}, json.dumps(result, default=repr))
    elif args.cmd == "submit":
        doc = b.submit(args.action, _params(args), args.target)
        note = " (awaiting approval)" if doc["awaiting_approval"] else ""
        _out(args, doc, doc["request_id"] + note)
    elif args.cmd == "status":
        d = b.status(args.request_id)
        _out(args, d, f"{args.request_id}: {d['state']} ({d['request']['action']})")
    elif args.cmd == "run":
        result = b.run(args.request_id)
        _out(
            args,
            {"request_id": args.request_id, "result": result},
            json.dumps(result, default=repr),
        )
    elif args.cmd == "cancel":
        b.cancel(args.request_id)
        _out(
            args,
            {"request_id": args.request_id, "state": "cancelled"},
            f"{args.request_id}: cancelled",
        )
    elif args.cmd in ("approve", "deny"):
        doc = b.decide(args.cmd, args.request_id, args.who, args.note)
        _out(args, doc, f"{args.request_id}: {doc['decision']} ({doc['approval_id']})")
    elif args.cmd == "pending":
        rows = b.pending(args.mine)
        text = "\n".join(
            f"{r['request_id']}  {r.get('actor', '')}  {r['action']}  "
            + json.dumps(r.get("params", {}), sort_keys=True)
            + ("  [approved, not yet run]" if r["approved"] else "")
            + (
                f"  [approval {r['approval_state']}: approve again]"
                if r.get("approval_state") in ("expired", "consumed", "invalid")
                else ""
            )
            for r in rows
        )
        _out(args, rows, text or ("nothing pending" if args.mine else "nothing awaiting approval"))
    elif args.cmd == "agents":
        keys = b.agents()
        _out(args, {"agents": keys}, "\n".join(keys))
    else:  # audit
        match = {
            k: getattr(args, k) for k in ("action", "caller", "outcome", "operation", "request_id")
        }
        rows = b.audit(**match)
        if args.tail is not None:
            rows = rows[-args.tail :] if args.tail > 0 else []
        text = "\n".join(
            f"{r['at']}  {r['operation']:<7} {r['outcome']:<7} {r['caller']}  {r['action']}"
            + (f"  {r['reason']}" if r["reason"] else "")
            + (f"  {r['request_id']}" if r.get("request_id") else "")
            for r in rows
        )
        _out(args, rows, text or "no audit records")
    return 0


def _import(args) -> int:
    from . import importer

    rows = importer.read_dir(
        args.directory, default_risk=args.default_risk, default_rollback=args.default_rollback
    )
    if args.apply:
        b = _Remote(args) if args.socket else _Local(args)
        source = b.actions()["caller"]
        importer.apply(rows, lambda params: b.call(args.action, params, None), source)
    lines = []
    for r in rows:
        line = f"{r.outcome:<10} {r.source}"
        if r.params is not None and r.outcome == "mapped":
            line += f"  -> {r.params['note']['title']!r} (risk {r.params['note']['risk']})"
        if r.result:
            line += f"  {r.result}"
        if r.problem:
            line += f"  ({r.problem})"
        if r.unmapped:
            line += "  unmapped: " + ", ".join(r.unmapped)
        lines.append(line)
    mode = "applied" if args.apply else "dry run (use --apply to file)"
    lines.append(f"{len(rows)} files, {mode}")
    _out(args, {"apply": args.apply, "files": [r.as_dict() for r in rows]}, "\n".join(lines))
    return 1 if any(r.outcome in ("unmappable", "refused", "conflict") for r in rows) else 0


def _serve(args) -> int:
    from .server import DEFAULT_MAX_REQUEST_BYTES, DEFAULT_TIMEOUT_S, BrokerServer

    logging.basicConfig(level=logging.INFO, format="hnx-broker %(levelname)s %(message)s")
    try:
        mode = int(args.socket_mode, 8)
    except ValueError:
        raise ValueError("--socket-mode is an octal mode such as 660") from None
    svc = _service(args)
    log = logging.getLogger("homelabnext.broker.cli")
    for row in svc.lane_usage():
        (log.warning if row["warn"] else log.info)("%s", _usage_line(row))
    server = BrokerServer(
        svc,
        args.socket,
        mode=mode,
        group=args.socket_group,
        max_request_bytes=args.max_request_bytes or DEFAULT_MAX_REQUEST_BYTES,
        timeout_s=args.timeout or DEFAULT_TIMEOUT_S,
    )
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    server.start()
    try:
        stop.wait()
    finally:
        server.close()
    return 0


def events_connector(target: str, *, stream: str, subject_prefix: str) -> Any:
    """A zero-argument factory for the bus the target file's ``events`` binding names, on the
    standing ``stream`` / ``subject_prefix`` (never a scratch stream), which it never creates:
    the stream and its DLQ must be provisioned, each with a ``max_bytes`` limit (a relay with
    ``STREAM.CREATE`` could make an unbounded one; its bus user is granted lookups only)."""
    from dataclasses import replace

    from homelabnext.conform.target import load_target, make_factory

    binding = load_target(target).binding("events")
    if binding.builtin or not binding.adapter:
        raise ValueError(f"{target}: the events binding must name an adapter")
    config = {
        **binding.config,
        "scratch": False,
        "provision": False,
        "stream": stream,
        "subject_prefix": subject_prefix,
    }
    return make_factory(replace(binding, config=config))


def _relay(args) -> int:
    from .relay import OutboxRelay, RelayBusy, RelayFirstStart, RelayStore

    logging.basicConfig(level=logging.INFO, format="hnx-broker-relay %(levelname)s %(message)s")
    if not args.state:
        print("hnx broker relay: --state (or HNX_BROKER_STATE) is required", file=sys.stderr)
        return 2
    if args.skip:
        try:
            store = RelayStore(args.state)
            fd = store.lock()  # a running relay could publish the event while it is skipped
        except RelayBusy as exc:
            print(f"hnx broker relay: {exc}: stop the relay, --skip, start it", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"hnx broker relay: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        try:
            for eid in args.skip:
                done = store.skip(eid)
                print(f"hnx broker relay: {eid[:80]} {'skipped' if done else 'already done'}")
        except Exception as exc:
            print(f"hnx broker relay: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        finally:
            os.close(fd)
        return 0
    if not (args.events_target and args.stream and args.subject_prefix):
        print(
            "hnx broker relay: --events-target, --stream and --subject-prefix are required",
            file=sys.stderr,
        )
        return 2
    try:
        connect = events_connector(
            args.events_target, stream=args.stream, subject_prefix=args.subject_prefix
        )
        relay = OutboxRelay(
            args.state,
            connect,
            batch=args.batch,
            backoff_max_s=args.backoff_max,
            max_attempts=args.max_attempts,
            retain_s=args.retain_days * 86400.0,
            since=args.since,
            stats_file=args.stats_file,
        )
        relay.acquire()
    except (RelayBusy, RelayFirstStart) as exc:
        print(f"hnx broker relay: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # the target file, the adapter, the state directory
        print(f"hnx broker relay: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.once:
        try:
            published = relay.drain()
            left = relay.pending()
        finally:
            relay.close()
        print(f"hnx broker relay: published {published}, {left} pending")
        return 1 if left else 0
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    relay.run(stop, idle_s=args.idle)
    return 0


def _mcp(args) -> int:
    from homelabnext.mcp.server import sdk_missing

    from .client import BrokerClient
    from .mcp_tools import serve

    if not args.socket:
        print("hnx broker mcp: --socket (or HNX_BROKER_SOCKET) is required", file=sys.stderr)
        return 2
    if sdk_missing():
        print(
            "hnx broker mcp: the MCP SDK is not installed (pip install 'homelabnext[mcp]')",
            file=sys.stderr,
        )
        return 2
    serve(BrokerClient(args.socket))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cmd == "validate":
        return _validate(args)
    if args.cmd == "mcp":
        return _mcp(args)
    if args.cmd == "relay":
        return _relay(args)
    try:
        if args.cmd == "import-proposals":
            return _import(args)
        return _serve(args) if args.cmd == "serve" else _run(args)
    except ManifestError as exc:
        print(f"hnx broker: {exc}", file=sys.stderr)
        return 2
    except BrokerError as exc:
        reason = getattr(exc, "reason", "") or type(exc).__name__
        if getattr(args, "json", False):
            print(json.dumps({"error": reason, "message": str(exc)}, indent=2))
        print(f"hnx broker {args.cmd}: refused ({reason}): {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"hnx broker {args.cmd}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
