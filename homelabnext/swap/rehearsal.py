# SPDX-License-Identifier: Apache-2.0
"""P9.2: rehearse the swap procedure on the lab-in-a-box - the built-in fake lake replaced by the
real query engine, through the swap kit, then rolled back.

``run(report_dir, incumbent, candidate)`` drives :class:`~homelabnext.swap.SwapRunner` with the
reference :class:`~homelabnext.swap.LakeBackend`:

1. a registry (``examples/services.yml`` plus two hosts) whose ``lake-query`` row points at the
   incumbent, produced by the kit's own flip so it validates;
2. ``declare`` (incumbent conformance), ``shadow-start`` (candidate conformance, backfill of the
   seeded dataset), ``dual-write`` (live batches mirrored through the ``DualWriter``),
   ``parity-compare`` (whole tables plus aggregate queries, every row), ``soak`` (a zero-hour window:
   this is a rehearsal), ``cutover`` (the registry row flips; the canary is the alias answering from
   the candidate; the incumbent is stopped, not destroyed);
3. after the flip, the parity queries are asked *through the route* and must answer from the
   candidate with the incumbent's results;
4. ``rollback``: the registry text is back byte for byte, the incumbent runs again, the route
   answers from it, and the record validates (schema, hash chain, evidence hashes) with status
   ``rolled_back``.

Everything lands in ``report_dir``: the record, its evidence directory, the registry and
``rehearsal.json`` (the verdict and every check).  The real run is
``compose/lab-in-a-box/rehearsals/swap-lake-query.sh`` (incumbent: an in-process ``FakeLake``;
candidate: Trino + Lakekeeper through ``homelabnext.conform.adapters.lake``); the unit tests run
the same function on two in-memory lakes.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from homelabnext import paths, tlp
from homelabnext.lake.base import normalize_rows
from homelabnext.parity import ParityQuery, RowRules, compare_queries

from . import record as rec
from .flip import flip_text, load_doc, plan_flip
from .lakebackend import LakeBackend
from .machine import GateFailed, SwapError, SwapRunner

__all__ = ["PARITY_QUERIES", "TABLES", "Router", "rehearsal_registry", "run", "seed_rows"]

SWAP_ID = "swap-lake-query-rehearsal"
SERVICE = "lake-query"
INCUMBENT = {"host": "lab-fake-lake", "impl": "fake-lake", "version": "0.0"}
CANDIDATE = {"host": "lab-lake-query", "impl": "trino", "version": "470.0"}
TABLES = ("authentication", "dns_activity")
FROM_ADAPTER = "fake-lake"
TO_ADAPTER = "trino-lakekeeper-lake"  # homelabnext.conform.adapters.lake:make_lake
PARITY_QUERIES = (
    ParityQuery(
        "auth-by-user",
        sql="SELECT user_name, count(*) AS n, min(time) AS first_seen FROM authentication "
        "GROUP BY user_name",
        rules=RowRules(key=("user_name",)),
        min_rows=3,
    ),
    ParityQuery(
        "failed-logons-since",
        sql="SELECT uid, user_name, src_endpoint FROM authentication "
        "WHERE status_id = :status AND time >= :since",
        params={"status": 2, "since": datetime(2026, 3, 1, 12, 0, tzinfo=UTC)},
        rules=RowRules(key=("uid",)),
        min_rows=1,
    ),
    ParityQuery(
        "dns-by-type",
        sql="SELECT query_type, count(*) AS n FROM dns_activity GROUP BY query_type",
        rules=RowRules(key=("query_type",)),
        min_rows=2,
    ),
)


# ---------------------------------------------------------------- the seeded dataset
def _addr(net: str, host: int) -> str:
    return f"{net}.{host}"


def seed_rows(n_auth: int = 36, n_dns: int = 12) -> dict[str, list[dict[str, Any]]]:
    """A deterministic dataset (documentation addresses only) covering every column type."""
    t0 = datetime(2026, 3, 1, 8, 0, tzinfo=UTC)
    users = ("alice", "bob", "carol", "dave")
    auth = []
    for i in range(n_auth):
        auth.append(
            {
                "uid": f"rh-auth-{i:03d}",
                "time": t0 + timedelta(minutes=17 * i),
                "class_uid": 3002,
                "category_uid": 3,
                "activity_id": 1,
                "type_uid": 300201,
                "severity_id": 1 + i % 3,
                "status_id": 2 if i % 5 == 0 else 1,
                "message": "login failed" if i % 5 == 0 else "login ok",
                "metadata": {"version": "1.3.0", "product": "example-sensor", "log_source": "a"},
                "user_name": users[i % len(users)],
                "src_endpoint": {
                    "ip": _addr("192.0.2", 10 + i),
                    "port": 40000 + i,
                    "hostname": None if i % 4 else f"ws-{i:02d}.example.internal",
                },
                "dst_endpoint": {"ip": _addr("198.51.100", 20), "port": 22, "hostname": None},
                "logon_type_id": 3,
                "auth_protocol": "ssh",
                "is_mfa": i % 2 == 0,
                "tlp": tlp.LABELS[i % len(tlp.LABELS)],
            }
        )
    dns = []
    for i in range(n_dns):
        dns.append(
            {
                "uid": f"rh-dns-{i:03d}",
                "time": t0 + timedelta(minutes=29 * i),
                "class_uid": 4003,
                "category_uid": 4,
                "activity_id": 1,
                "severity_id": 1,
                "metadata": {"version": "1.3.0", "product": "example-resolver", "log_source": "b"},
                "src_endpoint": {"ip": _addr("192.0.2", 100 + i), "port": 53000 + i},
                "query_hostname": f"host-{i % 5}.example.internal",
                "query_type": ("A", "AAAA", "TXT")[i % 3],
                "rcode_id": 0,
                "answers": [_addr("203.0.113", i + 1)] if i % 3 != 2 else [],
                "tlp": tlp.LABELS[i % len(tlp.LABELS)],
            }
        )
    return {"authentication": auth, "dns_activity": dns}


def live_rows() -> list[dict[str, Any]]:
    """Batches written while the mirror runs (they must reach both sides)."""
    base = seed_rows(0, 3)["dns_activity"]
    return [dict(r, uid=f"rh-live-{i}") for i, r in enumerate(base)]


# ---------------------------------------------------------------- registry and route
def rehearsal_registry() -> str:
    """``examples/services.yml`` plus the incumbent's and candidate's hosts, with the
    ``lake-query`` row pointing at the incumbent (made with the kit's flip, so it validates)."""
    text = paths.example_file("services.yml").read_text(encoding="utf-8")
    m = re.search(r"^  lake-core: .*address: ([0-9.]+),.*$", text, re.M)
    if not m:
        raise SwapError("examples/services.yml has no lake-core host line")
    line, base = m.group(0), ipaddress.ip_address(m.group(1))
    extra = [
        line.replace("lake-core:", f"{h}:").replace(m.group(1), str(base + k))
        for k, h in ((1, INCUMBENT["host"]), (2, CANDIDATE["host"]))
    ]
    text = text.replace(line, "\n".join([line, *extra]), 1)
    plan = plan_flip(load_doc(text), SERVICE, **INCUMBENT)
    return flip_text(text, plan)


class Router:
    """What a consumer resolves: the client behind the registry row's host."""

    def __init__(self, registry: Path, clients: dict[str, Any]):
        self.registry, self.clients = registry, clients

    def host(self) -> str:
        return load_doc(self.registry.read_text(encoding="utf-8"))["services"][SERVICE]["host"]

    def client(self) -> Any:
        return self.clients[self.host()]


# ---------------------------------------------------------------- the rehearsal
def _answers(client: Any) -> dict[str, list[dict[str, Any]]]:
    out = {}
    for q in PARITY_QUERIES:
        rows = normalize_rows(client.query(q.sql, q.params or None))
        out[q.name] = sorted(rows, key=lambda r: json.dumps(r, sort_keys=True, default=str))
    return out


def run(
    report_dir: str | Path,
    incumbent: Any,
    candidate: Any,
    *,
    clock: Callable[[], datetime] | None = None,
    actor: str = "lab-smoke",
) -> dict[str, Any]:
    """Run the rehearsal; return (and write to ``rehearsal.json``) the verdict and its checks."""
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)
    clock = clock or (lambda: datetime.now(UTC))
    registry = out / "services.yml"
    original = rehearsal_registry()
    registry.write_text(original, encoding="utf-8")
    record_path = out / f"{SWAP_ID}.swap.json"
    if record_path.exists():
        raise SwapError(f"{record_path} exists; a rehearsal writes a fresh record")
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append({"check": name, "ok": bool(ok), "detail": detail[:500]})
        return bool(ok)

    seed = seed_rows()
    for table, rows in seed.items():
        incumbent.write_batch(table, rows, idempotency_key=f"seed-{table}")
    total = sum(len(r) for r in seed.values()) + len(live_rows())

    backend = LakeBackend(
        incumbent,
        candidate,
        tables=TABLES,
        registry_path=registry,
        service=SERVICE,
        new_host=CANDIDATE["host"],
        queries=PARITY_QUERIES,
    )
    router = Router(registry, {INCUMBENT["host"]: backend.old, CANDIDATE["host"]: candidate})
    before = {"host": INCUMBENT["host"], "port": 8443, **INCUMBENT}
    after = {"host": CANDIDATE["host"], "port": 8443, **CANDIDATE}
    runner = SwapRunner.create(
        record_path,
        backend,
        swap_id=SWAP_ID,
        capability=f"cap:{SERVICE}",
        from_adapter=FROM_ADAPTER,
        to_adapter=TO_ADAPTER,
        service=SERVICE,
        before=before,
        after=after,
        plan={
            "soak_hours": 0,
            "rollback_window_hours": 0,
            "max_divergences": 0,
            "min_parity_rows": total,
        },
        registry=registry.name,
        clock=clock,
        actor=actor,
    )
    flipped = False
    try:
        for step in ("declare", "shadow-start", "dual-write"):
            check(f"step:{step}", runner.advance().passed)
        for i, row in enumerate(live_rows()):
            backend.writer.write_batch("dns_activity", [row], idempotency_key=f"live-{i}")
        for step in ("parity-compare", "soak"):
            check(f"step:{step}", runner.advance().passed)
        expected = _answers(incumbent)  # what consumers saw before the flip
        check("step:cutover", runner.advance().passed)
        flipped = True
        check(
            "route-answers-from-candidate",
            router.host() == CANDIDATE["host"] and router.client() is candidate,
            f"registry row host: {router.host()}",
        )
        got = compare_queries(_Fixed(expected), router.client(), PARITY_QUERIES)
        check("candidate-answers-like-incumbent", got.ok, got.summary())
    except GateFailed as exc:
        check(f"step:{exc.result.step}", False, str(exc))
    except SwapError as exc:
        check("swap", False, str(exc))

    reason = "P9.2 rehearsal: prove that rollback restores the incumbent"
    try:
        doc = runner.rollback(reason)
        check("rollback", doc["status"] == "rolled_back", f"from {doc['rollback']['from_step']}")
        check(
            "rollback-restored-route",
            doc["rollback"]["restored_route"] == flipped,
            f"cutover had passed: {flipped}; route restored: {doc['rollback']['restored_route']}",
        )
    except SwapError as exc:
        check("rollback", False, str(exc))
    check(
        "registry-restored-byte-for-byte",
        registry.read_text(encoding="utf-8") == original,
        "the registry file equals the pre-swap text",
    )
    check("route-answers-from-incumbent", router.host() == INCUMBENT["host"], router.host())
    try:
        back = compare_queries(_Fixed(_answers(backend.old)), router.client(), PARITY_QUERIES)
        check("incumbent-serves-after-rollback", back.ok and not backend.old.down, back.summary())
        mirror = compare_queries(router.client(), candidate, PARITY_QUERIES)
        check("incumbent-kept-every-mirrored-batch", mirror.ok, mirror.summary())
    except Exception as exc:  # the incumbent must answer; anything else is a failed rehearsal
        check("incumbent-serves-after-rollback", False, f"{type(exc).__name__}: {exc}")
    try:
        final = rec.load(record_path)
        bad = rec.verify_evidence(final, out / f"{SWAP_ID}.evidence")
        check("record-validates", not bad, "; ".join(bad) or "schema, chain and evidence hashes ok")
        check("record-status-rolled-back", final["status"] == "rolled_back", final["status"])
    except rec.RecordError as exc:
        check("record-validates", False, str(exc))
    summary = {
        "ok": all(c["ok"] for c in checks),
        "swap_id": SWAP_ID,
        "record": record_path.name,
        "registry": registry.name,
        "from": FROM_ADAPTER,
        "to": TO_ADAPTER,
        "rows": total,
        "checks": checks,
    }
    (out / "rehearsal.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


class _Fixed:
    """A recorded answer set that ``compare_queries`` can query like a lake."""

    def __init__(self, answers: dict[str, list[dict[str, Any]]]):
        self._by_sql = {q.sql: answers[q.name] for q in PARITY_QUERIES}

    def query(self, sql: str, params: Any = None) -> list[dict[str, Any]]:
        return self._by_sql[sql]


# ---------------------------------------------------------------- command line
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m homelabnext.swap.rehearsal",
        description="P9.2: swap the built-in fake lake for the lab's query engine, then roll back.",
    )
    ap.add_argument("--report-dir", required=True)
    ap.add_argument("--domain", default="example.internal")
    ap.add_argument("--namespace", default="auto", help="candidate scratch namespace")
    args = ap.parse_args(argv)
    from homelabnext.conform.adapters._env import run_token
    from homelabnext.conform.adapters.lake import make_lake
    from homelabnext.lake import FakeLake

    ns = f"hnx_rehearsal_{run_token()}" if args.namespace == "auto" else args.namespace
    try:
        candidate = make_lake(domain=args.domain, namespace=ns)
    except Exception as exc:  # cannot build the candidate: not a rehearsal result
        print(f"rehearsal: cannot reach the candidate lake: {type(exc).__name__}: {exc}")
        return 2
    summary = run(args.report_dir, FakeLake(), candidate)
    for c in summary["checks"]:
        print(
            f"  [{'ok' if c['ok'] else 'FAIL'}] {c['check']}"
            + (f" - {c['detail']}" if c["detail"] else "")
        )
    print(f"rehearsal: {'PASS' if summary['ok'] else 'FAIL'} ({summary['record']})")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
