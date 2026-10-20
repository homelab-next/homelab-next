# SPDX-License-Identifier: Apache-2.0
"""``hnx broker``: validate a manifest, serve the broker, and talk to it from a shell.

``validate MANIFEST`` checks the manifest schema, every handler document and its pinned digest,
the lane configuration and the transport peers.

``serve --socket PATH`` runs the broker on a Unix socket whose callers are authenticated by their
peer credentials (:mod:`homelabnext.broker.server`); ``mcp --socket PATH`` runs the agent-facing
MCP tool server (stdio) against it (:mod:`homelabnext.broker.mcp_tools`).

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

``--json`` prints machine-readable output.

Exit: 0 ok, 1 refused or failed (the reason is printed), 2 usage error or an invalid manifest.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any

from conformance.protocols.broker import BrokerError

from .service import BrokerService, ManifestError, load_manifest, validate_manifest

_AGENT_CMDS = ("actions", "call", "submit", "status", "run", "cancel")


def _service_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--manifest", default=os.environ.get("HNX_BROKER_MANIFEST"))
    p.add_argument("--state", default=os.environ.get("HNX_BROKER_STATE"))
    p.add_argument("--data-root", default=os.environ.get("HNX_BROKER_DATA_ROOT"))


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
    for p in sub.choices.values():
        if p.prog.split()[-1] not in ("validate", "serve", "mcp"):
            _common(p)
    return ap


def _out(args, payload: Any, text: str) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else text)


def _validate(args) -> int:
    path = Path(args.path)
    try:
        from .service import _read_doc

        manifest = _read_doc(path)
    except (OSError, ValueError) as exc:
        print(f"hnx broker validate: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        problems = [f"{path}: not a mapping"]
    else:
        _, problems = validate_manifest(manifest, path.parent)
    if args.json:
        print(
            json.dumps({"manifest": str(path), "ok": not problems, "problems": problems}, indent=2)
        )
    elif problems:
        print("\n".join(f"{path}: {p}" for p in problems))
    else:
        actions = len(manifest["actions"])
        print(f"{path}: ok ({actions} actions, {len(manifest.get('lanes', []))} lanes)")
    return 1 if problems else 0


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
    )


def _params(args) -> dict[str, Any]:
    raw = args.params
    if args.params_file:
        raw = Path(args.params_file).read_text(encoding="utf-8")
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict):
        raise ValueError("params must be a JSON object")
    return value


def _refused(reason: str, message: str) -> BrokerError:
    err = BrokerError(message)
    err.reason = reason  # type: ignore[attr-defined]
    return err


class _Local:
    """The request commands against the state directory, with the asserted ``--as``."""

    def __init__(self, args) -> None:
        self.svc = _service(args)
        self.args = args

    def _who(self) -> str:
        if self.svc.manifest.get("dev_identity") is not True:
            raise _refused(
                "dev-identity-disabled",
                "this manifest does not accept an asserted --as identity (dev_identity is not "
                "true); use --socket against a running broker",
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
        self._who_is_dev()
        fn = self.svc.approve if cmd == "approve" else self.svc.deny
        return fn(rid, who, note=note)

    def _who_is_dev(self):
        if self.svc.manifest.get("dev_identity") is not True:
            raise _refused(
                "dev-identity-disabled",
                "this manifest does not accept an asserted approver; approvals come from an "
                "approval relay over the socket",
            )

    def pending(self, mine):
        return self.svc.pending_for(self._who()) if mine else self.svc.pending()

    def audit(self, **match):
        return self.svc.audit_documents(**match)


class _Remote:
    """The request commands against a running broker; the broker knows who this process is."""

    def __init__(self, args) -> None:
        from .client import BrokerClient

        if getattr(args, "who", None) and args.cmd in (*_AGENT_CMDS, "pending"):
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
            for r in rows
        )
        _out(args, rows, text or ("nothing pending" if args.mine else "nothing awaiting approval"))
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


def _serve(args) -> int:
    from .server import DEFAULT_MAX_REQUEST_BYTES, DEFAULT_TIMEOUT_S, BrokerServer

    logging.basicConfig(level=logging.INFO, format="hnx-broker %(levelname)s %(message)s")
    try:
        mode = int(args.socket_mode, 8)
    except ValueError:
        raise ValueError("--socket-mode is an octal mode such as 660") from None
    server = BrokerServer(
        _service(args),
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
    try:
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
