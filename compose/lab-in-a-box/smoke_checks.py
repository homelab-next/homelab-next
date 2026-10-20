#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lab-smoke-checks
#   kind: tool
#   purpose: One real round trip against every lab-in-a-box service, as a JSON report.
#   owner: lab-in-a-box
#   trigger: [script:lab-smoke]
#   inputs: endpoints from the environment or --base capability=url
#   outputs: the --report JSON file
#   exit:
#     "0": every check passed
#     "1": some check failed
"""Direct, product-neutral checks of every lab-in-a-box service (stdlib only).

Each check hits a published endpoint and does one real round trip (not just "port open").  The
result is a JSON report; the exit code is 0 only when every check passed.  Endpoints come from
the environment (the same variables as ``.env.example``) or ``--base capability=url`` options;
there are no defaults, so a missing endpoint is a failed check, not a silent skip.

The metrics and uptime checks poll their service through the status hub's real collectors
(``homelabnext.status``: ``poll-prometheus``, ``poll-uptime-kuma``), so they need the project
importable; without it they fail with that reason.

The broker check runs the broker end-to-end scenario (``broker_e2e.py run --json``) through the
command in ``LAB_BROKER_E2E`` (a JSON argv; the smoke script sets it to a ``docker compose exec``
into the ``broker-edge`` container) and passes only when every step of it did.

    smoke_checks.py --report build/lab-smoke/checks.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

TIMEOUT = 20
USER = {"X-Trino-User": "lab-smoke"}


class CheckError(Exception):
    pass


def http(
    method: str,
    url: str,
    body: Any = None,
    headers: Mapping[str, str] | None = None,
    raw: bytes | None = None,
) -> tuple[int, Any]:
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        payload, status = exc.read(), exc.code
    try:
        return status, json.loads(payload) if payload else None
    except ValueError:
        return status, payload.decode(errors="replace")


def expect(status: int, ok: tuple[int, ...], what: str, out: Any = None) -> None:
    if status not in ok:
        raise CheckError(f"{what}: HTTP {status} {str(out)[:200]}")


def trino_run(base: str, sql: str) -> list[list[Any]]:
    """Run one statement to completion through the REST protocol and return its rows."""
    status, doc = http("POST", f"{base}/v1/statement", raw=sql.encode(), headers=USER)
    expect(status, (200,), f"trino submit {sql[:40]!r}", doc)
    rows: list[list[Any]] = []
    deadline = time.monotonic() + 120
    while True:
        rows.extend(doc.get("data") or [])
        if doc.get("error"):
            raise CheckError(f"trino {sql[:40]!r}: {doc['error'].get('message')}")
        nxt = doc.get("nextUri")
        if not nxt:
            return rows
        if time.monotonic() > deadline:
            raise CheckError(f"trino {sql[:40]!r}: timed out")
        time.sleep(0.2)
        status, doc = http("GET", nxt, headers=USER)
        expect(status, (200,), "trino poll", doc)


def check_object_store(b: Mapping[str, str]) -> str:
    status, out = http("GET", f"{b['object-store-admin']}/health")
    expect(status, (200,), "object-store admin health", out)
    return "admin health 200"


def check_lake_catalog(b: Mapping[str, str]) -> str:
    status, out = http("GET", f"{b['lake-catalog']}/health")
    expect(status, (200,), "catalog health", out)
    status, out = http("GET", f"{b['lake-catalog']}/catalog/v1/config?warehouse={b['warehouse']}")
    expect(status, (200,), "catalog config for the warehouse", out)
    return "health 200, warehouse config served"


def check_lake_query(b: Mapping[str, str]) -> str:
    base = b["lake-query"]
    if trino_run(base, "SELECT 1") != [[1]]:
        raise CheckError("SELECT 1 did not return 1")
    # end to end: engine -> REST catalog -> object store, then clean up
    trino_run(base, "CREATE SCHEMA IF NOT EXISTS iceberg.smoke")
    try:
        trino_run(base, "DROP TABLE IF EXISTS iceberg.smoke.t")
        trino_run(base, "CREATE TABLE iceberg.smoke.t (id integer, label varchar)")
        trino_run(base, "INSERT INTO iceberg.smoke.t VALUES (1, 'a'), (2, 'b')")
        got = trino_run(base, "SELECT count(*) FROM iceberg.smoke.t")
        if got != [[2]]:
            raise CheckError(f"round trip returned {got}, expected [[2]]")
    finally:
        trino_run(base, "DROP TABLE IF EXISTS iceberg.smoke.t")
        trino_run(base, "DROP SCHEMA IF EXISTS iceberg.smoke")
    return "SELECT 1 and an Iceberg create/insert/count round trip"


def check_events(b: Mapping[str, str]) -> str:
    status, out = http("GET", f"{b['events-monitor']}/healthz")
    expect(status, (200,), "events health", out)
    status, out = http("GET", f"{b['events-monitor']}/jsz")
    expect(status, (200,), "events jetstream status", out)
    if not isinstance(out, dict) or "config" not in out:
        raise CheckError("JetStream is not enabled")
    return "health 200, JetStream enabled"


def check_secrets(b: Mapping[str, str]) -> str:
    auth = {"X-Vault-Token": b["secrets-token"]}
    status, out = http("GET", f"{b['secrets']}/v1/sys/health")
    expect(status, (200,), "secrets health", out)
    status, out = http(
        "POST", f"{b['secrets']}/v1/secret/data/smoke", {"data": {"k": "v"}}, headers=auth
    )
    expect(status, (200, 204), "secrets write", out)
    status, out = http("GET", f"{b['secrets']}/v1/secret/data/smoke", headers=auth)
    expect(status, (200,), "secrets read", out)
    if out["data"]["data"] != {"k": "v"}:
        raise CheckError("secrets read-back mismatch")
    return "health 200, KV write/read-back"


def check_notify(b: Mapping[str, str]) -> str:
    status, out = http("GET", f"{b['notify']}/v1/health")
    expect(status, (200,), "notify health", out)
    status, out = http("POST", f"{b['notify']}/lab-smoke", raw=b"lab smoke test message")
    expect(status, (200,), "notify publish", out)
    if not isinstance(out, dict) or not out.get("id"):
        raise CheckError("notify did not return a message id")
    return "health 200, message accepted"


def check_inference(b: Mapping[str, str]) -> str:
    status, out = http("GET", f"{b['inference']}/v1/models")
    expect(status, (200,), "inference models", out)
    model = out["data"][0]["id"]
    status, out = http(
        "POST",
        f"{b['inference']}/v1/chat/completions",
        {"model": model, "messages": [{"role": "user", "content": "ping"}]},
    )
    expect(status, (200,), "inference chat", out)
    if not out["choices"][0]["message"]["content"]:
        raise CheckError("empty completion")
    return f"models listed, chat completion from {model}"


def check_cases(b: Mapping[str, str]) -> str:
    base = f"{b['cases']}/api/cases"
    doc = {"title": "smoke", "severity": "low", "dedup_key": "lab-smoke"}
    status, first = http("POST", base, doc)
    expect(status, (200, 201), "case create", first)
    status, again = http("POST", base, doc)
    expect(status, (200,), "case dedup", again)
    if again["id"] != first["id"]:
        raise CheckError("dedup_key did not return the same case")
    status, got = http("GET", f"{base}/{first['id']}")
    expect(status, (200,), "case read", got)
    return f"create/dedup/read ({first['id']})"


def collect(kind: str, base: str, path: str, mapping: Mapping[str, Any]) -> dict[str, str]:
    """One poll through the status hub's collector for ``kind``: ``{item: state}``."""
    try:
        from homelabnext.status import CollectContext, SourceSpec, UrllibClient
        from homelabnext.status.collectors import COLLECTORS
    except ImportError as exc:
        raise CheckError(f"the status hub is not importable ({exc})") from None
    spec = SourceSpec(
        id=f"lab-{kind}",
        kind=kind,
        service="lab",
        capability="lab",
        interval_s=60,
        what="lab smoke",
        path=path,
        timeout_s=TIMEOUT,
        mapping=dict(mapping),
    )
    ctx = CollectContext(http=UrllibClient(), endpoint=lambda _service: base)
    try:
        drafts = COLLECTORS[kind].collect(spec, ctx)
    except Exception as exc:  # the collector's own error (transport, shape) fails this check
        raise CheckError(f"{kind}: {type(exc).__name__}: {exc}") from None
    return {d.item: d.state for d in drafts}


def check_metrics(b: Mapping[str, str]) -> str:
    alerts = collect(
        "poll-prometheus", b["metrics"], "/api/v1/alerts", {"builtin": "prometheus-alerts"}
    )
    want = {"LabSmokeWarning": "warn", "LabSmokeCritical": "fail"}
    if alerts != want:
        raise CheckError(f"alerts read {alerts}, expected {want} (rules evaluated yet?)")
    up = collect(
        "poll-prometheus",
        b["metrics"],
        "/api/v1/query",
        {"query": "up", "item": "job", "thresholds": {"fail": 0, "direction": "below"}},
    )
    if up.get("prometheus") != "ok":
        raise CheckError(f"self-scrape read {up}, expected prometheus ok")
    return "collector: firing alerts warn+fail by severity, self-scrape target up"


def check_uptime(b: Mapping[str, str]) -> str:
    monitors = collect("poll-uptime-kuma", b["uptime"], "/api/status-page/lab", {})
    want = {"metrics": "ok", "unreachable": "fail"}
    if monitors != want:
        raise CheckError(f"status page read {monitors}, expected {want}")
    return "collector: public status page, up monitor ok, down monitor fail"


def check_broker(b: Mapping[str, str]) -> str:
    argv = json.loads(b["broker-e2e"])
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    lines = proc.stdout.strip().splitlines()
    try:
        doc = json.loads(lines[-1])
        steps = doc["steps"]
    except (IndexError, KeyError, TypeError, ValueError):
        raise CheckError(
            f"no scenario report (rc={proc.returncode}): {proc.stderr[-300:]}"
        ) from None
    failed = [s for s in steps if not s.get("ok")]
    if failed or not doc.get("ok") or proc.returncode != 0:
        first = failed[0] if failed else {"step": "?", "detail": "incomplete"}
        passed = ", ".join(s["step"] for s in steps if s.get("ok"))
        raise CheckError(f"step {first['step']}: {first['detail']} (passed: {passed or 'none'})")
    return f"{len(steps)} steps passed: " + ", ".join(s["step"] for s in steps)


CHECKS: dict[str, Callable[[Mapping[str, str]], str]] = {
    "object-store": check_object_store,
    "lake-catalog": check_lake_catalog,
    "lake-query": check_lake_query,
    "events": check_events,
    "secrets": check_secrets,
    "notify": check_notify,
    "inference": check_inference,
    "cases": check_cases,
    "metrics": check_metrics,
    "uptime": check_uptime,
    "broker": check_broker,
}


def bases_from_env(environ: Mapping[str, str]) -> dict[str, str]:
    """Published endpoints and the few inputs the checks need, from the .env.example names."""
    bind = environ.get("LAB_BIND", "")
    ports = {
        "object-store-admin": "LAB_PORT_OBJECT_STORE_ADMIN",
        "lake-catalog": "LAB_PORT_CATALOG",
        "lake-query": "LAB_PORT_QUERY",
        "events-monitor": "LAB_PORT_EVENTS_MONITOR",
        "secrets": "LAB_PORT_SECRETS",
        "notify": "LAB_PORT_NOTIFY",
        "inference": "LAB_PORT_INFERENCE",
        "cases": "LAB_PORT_CASES",
        "metrics": "LAB_PORT_METRICS",
        "uptime": "LAB_PORT_UPTIME",
    }
    out = {k: f"http://{bind}:{environ[v]}" for k, v in ports.items() if bind and v in environ}
    out["warehouse"] = environ.get("LAB_WAREHOUSE", "")
    out["secrets-token"] = environ.get("LAB_SECRETS_DEV_TOKEN", "")
    if environ.get("LAB_BROKER_E2E"):  # set by the smoke script, not a setting
        out["broker-e2e"] = environ["LAB_BROKER_E2E"]
    return out


def run_checks(
    bases: Mapping[str, str], only: list[str] | None = None, retries: int = 3
) -> list[dict[str, Any]]:
    results = []
    for name, fn in CHECKS.items():
        if only and name not in only:
            continue
        started = time.monotonic()
        detail, ok = "", False
        for attempt in range(retries):
            try:
                detail, ok = fn(bases), True
                break
            except (CheckError, KeyError, OSError, urllib.error.URLError, ValueError) as exc:
                detail = f"{type(exc).__name__}: {exc}"
                if attempt + 1 < retries:
                    time.sleep(3)
        results.append(
            {
                "capability": name,
                "status": "pass" if ok else "fail",
                "detail": detail,
                "seconds": round(time.monotonic() - started, 2),
            }
        )
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--report", type=Path, help="write the JSON report here")
    ap.add_argument("--only", action="append", help="run only this capability (repeatable)")
    ap.add_argument("--retries", type=int, default=3)
    args = ap.parse_args(argv)
    results = run_checks(bases_from_env(os.environ), args.only, args.retries)
    for r in results:
        print(f"{r['status'].upper():4} {r['capability']:<13} {r['detail']}")
    report = {"checks": results, "ok": all(r["status"] == "pass" for r in results)}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
