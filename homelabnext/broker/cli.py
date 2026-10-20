# SPDX-License-Identifier: Apache-2.0
"""``hnx broker``: validate a manifest and drive the reference broker service from a shell.

``validate MANIFEST`` checks the manifest schema, every handler document and its pinned digest,
and the lane configuration.  The other commands act on one state directory with one manifest
(``--manifest`` / ``$HNX_BROKER_MANIFEST``, ``--state`` / ``$HNX_BROKER_STATE``; lanes write under
``--data-root`` / ``$HNX_BROKER_DATA_ROOT``, default ``<state>/lanes``):

    submit ACTION --as ACTOR [--params JSON | --params-file FILE] [--target svc:NAME]
    status|run|cancel REQUEST_ID --as ACTOR
    approve|deny REQUEST_ID --as ISSUER:SUBJECT [--note TEXT]
    pending
    audit [--action A] [--caller C] [--request R] [--outcome O] [--operation P] [--tail N]

``--as`` is an asserted identity: this CLI is the local and development path.  In production the
caller is authenticated by the transport and approvals come through the front door (ADR-0017,
stage 2).  ``--json`` prints machine-readable output.

Exit: 0 ok, 1 refused or failed (the reason is printed), 2 usage error or an invalid manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from conformance.protocols.broker import BrokerError

from .service import BrokerService, ManifestError, load_manifest, validate_manifest


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--manifest", default=os.environ.get("HNX_BROKER_MANIFEST"))
    p.add_argument("--state", default=os.environ.get("HNX_BROKER_STATE"))
    p.add_argument("--data-root", default=os.environ.get("HNX_BROKER_DATA_ROOT"))
    p.add_argument("--json", action="store_true", help="machine-readable output")


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx broker", description="the reference broker service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check a manifest, its handler digests and lanes")
    v.add_argument("path")
    v.add_argument("--json", action="store_true")
    s = sub.add_parser("submit", help="submit a request for ACTION")
    s.add_argument("action")
    s.add_argument("--as", dest="who", required=True, help="the actor (profile:NAME)")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--params", help="params as a JSON object")
    g.add_argument("--params-file", help="params from a JSON file")
    s.add_argument("--target", help="svc:NAME the action is about")
    for name, who_help in (
        ("status", "the request's owner"),
        ("run", "the request's owner"),
        ("cancel", "the request's owner"),
        ("approve", "the approver, issuer:subject"),
        ("deny", "the approver, issuer:subject"),
    ):
        p = sub.add_parser(name, help=f"{name} a request")
        p.add_argument("request_id")
        p.add_argument("--as", dest="who", required=True, help=who_help)
        if name in ("approve", "deny"):
            p.add_argument("--note")
    sub.add_parser("pending", help="list requests awaiting approval")
    a = sub.add_parser("audit", help="print audit records (oldest first)")
    for f in ("action", "caller", "outcome", "operation"):
        a.add_argument(f"--{f}")
    a.add_argument("--request", dest="request_id")
    a.add_argument("--tail", type=int, help="only the last N records")
    for p in sub.choices.values():
        if p.prog.split()[-1] != "validate":
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


def _run(args) -> int:
    svc = _service(args)
    if args.cmd == "submit":
        rid = svc.submit(args.who, args.action, _params(args), target=args.target)
        verdict = svc.state.get_request(rid)["verdict"]
        waiting = verdict == "needs-approval"
        note = " (awaiting approval)" if waiting else ""
        _out(
            args, {"request_id": rid, "state": "pending", "awaiting_approval": waiting}, rid + note
        )
    elif args.cmd == "status":
        d = svc.detail(args.who, args.request_id)
        _out(args, d, f"{args.request_id}: {d['state']} ({d['request']['action']})")
    elif args.cmd == "run":
        result = svc.run(args.who, args.request_id)
        _out(
            args,
            {"request_id": args.request_id, "result": result},
            json.dumps(result, default=repr),
        )
    elif args.cmd == "cancel":
        svc.cancel(args.who, args.request_id)
        _out(
            args,
            {"request_id": args.request_id, "state": "cancelled"},
            f"{args.request_id}: cancelled",
        )
    elif args.cmd in ("approve", "deny"):
        fn = svc.approve if args.cmd == "approve" else svc.deny
        doc = fn(args.request_id, args.who, note=args.note)
        _out(args, doc, f"{args.request_id}: {doc['decision']} ({doc['approval_id']})")
    elif args.cmd == "pending":
        rows = svc.pending()
        text = "\n".join(
            f"{r['request_id']}  {r['actor']}  {r['action']}  {json.dumps(r['params'], sort_keys=True)}"
            + ("  [approved, not yet run]" if r["approved"] else "")
            for r in rows
        )
        _out(args, rows, text or "nothing awaiting approval")
    else:  # audit
        match = {
            k: getattr(args, k) for k in ("action", "caller", "outcome", "operation", "request_id")
        }
        rows = svc.audit_documents(**match)
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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cmd == "validate":
        return _validate(args)
    try:
        return _run(args)
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
