#!/opt/hnx/current/bin/python
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lake-writer
#   kind: job
#   purpose: Commit the log pipeline's staged OCSF batches to the fresh tables of the soc lake namespace, one writer per table, commit then checkpoint, refusing any namespace but soc and any event without its pipeline TLP label.
#   owner: platform
#   trigger: [timer:lake_writer/commit, role:lake_writer]
#   inputs: "commit [--table T] | ensure-tables | schema-check | status [--max-pending N] [--max-age-s S]; environment HNX_LW_*, the endpoints HNX_ENDPOINT_LAKE_QUERY, HNX_ENDPOINT_LAKE_CATALOG and HNX_ENDPOINT_OBJECT_STORE, the lake login and the object store key pair in the root-only credentials file; staged batches in the staging bucket; runs under the hnx runtime release python"
#   outputs: rows committed through LakeClient.write_batch; per table a checkpoint and a last-run record under the state directory; staged objects deleted once committed; refused rows under <prefix><table>/_rejected/ in the staging bucket; one JSON line per table on stdout
#   installs_to: /usr/local/libexec/homelabnext/hnx-lake-writer
#   exit:
#     "0": every table committed (or had nothing new), or the check passed
#     "1": a table failed (the lake or the store refused, a batch could not be read), or a run in which every row was refused, or status found a problem
#     "2": refused before anything was read or written (a namespace that is not soc, an unknown table, a missing setting)
"""The lake writer: staged OCSF batches into the ``soc`` namespace, one writer per table.

The log pipeline (the ``log-pipeline`` slot) stages batches of events in the object store, one
newline-delimited JSON object per batch under ``<prefix><table>/<name>``. Every event already carries its
TLP label in ``labels.hnx_tlp``, set by the pipeline from the route's declaration and never from
the event. This script, run once per table by its own unit, lists the table's staged objects,
turns every event into a row with :func:`homelabnext.lake.rows.row_from_event` (the row's ``tlp``
is that label and nothing else; an event without a canonical one is **refused**, never given a
label here), and commits each object through :class:`homelabnext.lake.checkpoint.Ingestor`:

1. the batch is committed with its object key as the idempotency key (``write_batch``), then
2. the checkpoint is saved, then
3. the staged object is deleted.

A crash between any two of these leaves the staged object in place, and the next run replays it:
the lake's batch ledger answers ``replayed`` (nothing is written), and where the ledger has been
expired the rows' content key (``uid``) skips every row already stored. A replay after a crash adds
no row (tests/modules/test_lake_writer_script.py).

Two guards stand before everything else:

* **Only the ``soc`` namespace.** ``require_namespace`` refuses any other, and names the lake's
  protected ones. The old lab's imported and migrated namespaces (the CTI, risk, sandbox,
  honeypot, archive, OCSF and observability ones) hold data that cannot be re-created; this writer
  does not take their names as input, builds no client for them, and checks the namespace the
  client reports about itself. The tables are the module's own: ``require_table`` refuses any name
  outside them (never a dotted, qualified one).
* **One writer per table.** A per-table lock is taken without waiting; a run that finds it held
  exits 0 having done nothing (the timer's next run continues), so two units can never write one
  table at once. The checkpoint's source is ``lake-writer/<table>``.

A row the lake would refuse (a field outside the pinned schema, a bad type, no label) is written to
``<prefix><table>/_rejected/`` beside its reason, counted, and never blocks the rest of its batch; a run in
which every row was refused exits 1, so a pipeline shipping unlabelled events is loud and not a
green unit with an empty table (LL-008's shape). A lake that is down is retried a bounded number of
times (the write is replay-safe, so a retry cannot duplicate), then the table's run stops and exits
1 with the objects still staged.
"""

import argparse
import contextlib
import gzip
import io
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from homelabnext.lake.checkpoint import Checkpoint, Ingestor
from homelabnext.lake.errors import (
    BatchSourceMismatch,
    CheckpointError,
    LakeError,
    RowRejected,
    SchemaMismatch,
    UnknownTable,
)
from homelabnext.lake.rows import row_from_event
from homelabnext.lake.tables import load_schemas
from homelabnext.lake.validate import normalize_rows
from homelabnext.state import StateStore
from homelabnext.state.store import StateLockBusy, file_lock

#: the one namespace this writer writes
NAMESPACE = "soc"
#: namespaces that hold imported or migrated data (or the core's own tables): named in the refusal so
#: the reader sees which kind of mistake it was; every namespace but NAMESPACE is refused alike
PROTECTED = ("cti", "rba", "cape", "honeypot", "archive", "ocsf", "obs")
#: the OCSF classes pinned in the core's schemas/ocsf, and the ones this module pins itself
CORE_TABLES = (
    "authentication",
    "detection_finding",
    "dns_activity",
    "network_activity",
    "vulnerability_finding",
)
OWN_TABLES = (
    "compliance_finding",
    "file_activity",
    "http_activity",
    "process_activity",
    "raw_archive",
)
ALL_TABLES = tuple(sorted(CORE_TABLES + OWN_TABLES))
REJECTED = "_rejected"
#: THE staging layout, the contract with the log pipeline (one definition: build keys with
#: :func:`staging_key`). Objects are gzip (or plain) newline-delimited JSON, one flat OCSF event per
#: line with ``labels.hnx_tlp``; the writer lists everything under ``<prefix><table>/`` recursively.
STAGING_LAYOUT = "<prefix><table>/dt=YYYY-MM-DD/hour=HH/<id>.ndjson.gz"
#: a staged object that inflates past this many bytes is refused whole (a decompression bomb)
MAX_INFLATED = 256 * 1024 * 1024


def staging_key(prefix, table, when, name, gz=True):
    """The key of a staged object in :data:`STAGING_LAYOUT` (``when``: its write time, UTC)."""
    stamp = when.strftime("dt=%Y-%m-%d/hour=%H")
    return f"{prefix}{table}/{stamp}/{name}.ndjson" + (".gz" if gz else "")


EXIT_OK, EXIT_FAILED, EXIT_REFUSED = 0, 1, 2
#: a reason or an original line is cut to this many characters in a rejected record
CUT = 4000


class Refused(Exception):
    """Something this writer will not do: nothing was read or written."""


class NamespaceRefused(Refused):
    """A namespace that is not the writer's own."""


class TableRefused(Refused):
    """A table that is not one of the writer's own."""


def require_namespace(namespace):
    """``namespace`` when it is exactly ``soc``; anything else (a protected namespace, another
    case, padded, qualified, not text) raises :class:`NamespaceRefused`."""
    if namespace == NAMESPACE and isinstance(namespace, str):
        return namespace
    shown = repr(namespace)[:60]
    kind = (
        "a protected namespace: imported or migrated data, never this writer's"
        if isinstance(namespace, str) and namespace in PROTECTED
        else f"not {NAMESPACE!r}"
    )
    raise NamespaceRefused(
        f"namespace {shown} refused ({kind}): lake-writer writes only the fresh {NAMESPACE!r} "
        "tables and never takes another namespace as input"
    )


def table_schemas(schema_dir=None, core=None):
    """``{table: TableSchema}`` for every table this writer owns: the core's pinned classes and
    the module's own (``schema_dir``). A pinned schema that is missing is an error, not a smaller
    set of tables."""
    core_all = load_schemas() if core is None else core
    own_all = load_schemas(schema_dir) if schema_dir else {}
    out = {}
    for name in ALL_TABLES:
        schema = (core_all if name in CORE_TABLES else own_all).get(name)
        if schema is None:
            raise Refused(f"the pinned schema of table {name!r} is not installed")
        out[name] = schema
    return out


def require_table(name, schemas):
    """``name`` when it is one of the writer's own tables (a bare name, never ``ns.table``)."""
    if not isinstance(name, str) or name not in schemas:
        raise TableRefused(
            f"table {str(name)[:60]!r} refused: lake-writer's tables are {', '.join(sorted(schemas))}"
        )
    return name


def lake_namespace(lake):
    """The namespace a lake client reports it works in (the adapters keep it as ``_ns``), or None
    when it reports none (the in-memory fake has no namespaces)."""
    return getattr(lake, "_ns", None)


# ----------------------------------------------------------------------------- batches


def _cut(text, n=CUT):
    text = str(text)
    return text if len(text) <= n else text[: n - 1] + "…"


def prepare(schema, data):
    """``(rows, rejects)`` of one staged object: a row for every event the lake would take, and a
    ``{"line", "reason", "text"}`` for every line it would not (not UTF-8, not JSON, not an object,
    no canonical pipeline label, a field the pinned schema does not hold). Nothing here writes."""
    rows, rejects = [], []
    if data[:2] == b"\x1f\x8b":  # gzip
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as fh:
                data = fh.read(MAX_INFLATED + 1)
        except (OSError, EOFError):
            return [], [{"line": 0, "reason": "the object is not valid gzip", "text": ""}]
        if len(data) > MAX_INFLATED:
            return [], [{"line": 0, "reason": "the object inflates past the limit", "text": ""}]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [], [{"line": 0, "reason": "the object is not UTF-8 text", "text": ""}]
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            rejects.append({"line": n, "reason": "not JSON", "text": _cut(line)})
            continue
        try:
            row = row_from_event(event, schema)
            normalize_rows(schema, [row])  # exactly what write_batch will check, for this row alone
        except RowRejected as exc:
            rejects.append({"line": n, "reason": _cut("; ".join(exc.problems)), "text": _cut(line)})
            continue
        rows.append(row)
    return rows, rejects


def list_keys(store, bucket, prefix):
    """Every key under ``prefix`` (all pages)."""
    keys, token = [], None
    while True:
        page = store.list(bucket, prefix, limit=1000, after=token)
        keys.extend(page.keys)
        token = page.next
        if token is None:
            return keys


def pending_keys(store, bucket, prefix, table):
    """The table's staged object keys (``<prefix><table>/<name>``), oldest name first, never the
    rejected ones."""
    head = f"{prefix}{table}/"
    return sorted(
        k for k in list_keys(store, bucket, head) if not k[len(head) :].startswith(REJECTED + "/")
    )


def rejected_keys(store, bucket, prefix, table):
    return list_keys(store, bucket, f"{prefix}{table}/{REJECTED}/")


def last_run(state_dir, table):
    """The table's last-run record, or None; reads only, and creates nothing."""
    path = Path(state_dir) / table / "last-run.json"
    return StateStore(path).get("last") if path.is_file() else None


# ----------------------------------------------------------------------------- the writer


class Writer:
    """One table's writer: the staged objects of ``<prefix><table>/`` into ``<namespace>.<table>``."""

    def __init__(
        self,
        lake,
        store,
        schema,
        *,
        namespace,
        bucket,
        state_dir,
        prefix="",
        max_attempts=5,
        max_batches=0,
        sleep=time.sleep,
        before_checkpoint=None,
        before_delete=None,
        clock=lambda: datetime.now(UTC),
    ):
        require_namespace(namespace)
        reported = lake_namespace(lake)
        if reported is not None:
            require_namespace(reported)  # a client built for another namespace is refused too
        self.lake, self.store, self.schema = lake, store, schema
        self.table = schema.name
        self.bucket, self.prefix = bucket, prefix
        self.dir = Path(state_dir) / self.table
        self.source = f"lake-writer/{self.table}"
        self.max_attempts, self.max_batches = max_attempts, max_batches
        self._sleep, self._clock = sleep, clock
        self._before_delete = before_delete
        self.checkpoint = Checkpoint(self.dir / "checkpoint.json")
        self.ingestor = Ingestor(
            lake,
            self.checkpoint,
            table=self.table,
            source=self.source,
            before_checkpoint=before_checkpoint,
        )
        self.record = StateStore(self.dir / "last-run.json")

    def pending(self):
        return pending_keys(self.store, self.bucket, self.prefix, self.table)

    def rejected(self):
        return rejected_keys(self.store, self.bucket, self.prefix, self.table)

    def _rejected_key(self, key):
        rest = key[len(self.prefix) + len(self.table) + 1 :]
        return f"{self.prefix}{self.table}/{REJECTED}/{rest.replace('/', '__')}"

    # -- one object
    def _commit(self, rows, key):
        """Commit ``rows`` under ``key``, retrying only what a retry cannot duplicate."""
        last = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                return self.ingestor.ingest(rows, batch_id=key, position=key)
            except (
                RowRejected,
                SchemaMismatch,
                BatchSourceMismatch,
                UnknownTable,
                CheckpointError,
            ):
                raise
            except LakeError as exc:  # a commit conflict or a lake that is away: replay-safe
                last = exc
                if attempt < self.max_attempts:
                    self._sleep(min(2**attempt, 60))
        raise last

    def _one(self, key, res):
        data = self.store.get(self.bucket, key)
        rows, rejects = prepare(self.schema, data)
        if rejects:
            body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rejects)
            self.store.put(self.bucket, self._rejected_key(key), body.encode("utf-8"))
        res["rows_rejected"] += len(rejects)
        if rows:
            out = self._commit(rows, key)
            res["rows_written"] += out.rows_written
            res["rows_skipped"] += out.rows_skipped
            res["replayed"] += 1 if out.replayed else 0
        if self._before_delete is not None:
            self._before_delete()  # test seam: raise here to simulate a crash after the checkpoint
        self.store.delete(self.bucket, key)
        res["batches"] += 1

    def run(self):
        """Commit every staged object (up to ``max_batches``), then record the run."""
        res = {
            "table": self.table,
            "at": self._clock().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ok": True,
            "batches": 0,
            "rows_written": 0,
            "rows_skipped": 0,
            "rows_rejected": 0,
            "replayed": 0,
            "failed": [],
            "error": None,
        }
        try:
            self.ingestor.start()  # a crash window: the lake is ahead of the checkpoint
            keys = self.pending()
            if self.max_batches:
                keys = keys[: self.max_batches]
            for key in keys:
                try:
                    self._one(key, res)
                except LakeError as exc:
                    # the lake refused after its retries, or the batch cannot be accepted as is:
                    # stop this table, the object stays staged
                    res["failed"].append(key)
                    res["error"] = _cut(f"{type(exc).__name__}: {exc}", 400)
                    break
                except Exception as exc:  # the store: this object only
                    res["failed"].append(key)
                    res["error"] = _cut(f"{type(exc).__name__}: {exc}", 400)
        except LakeError as exc:
            res["error"] = _cut(f"{type(exc).__name__}: {exc}", 400)
        res["pending_after"] = len(self.pending()) if res["error"] is None else None
        res["ok"] = res["error"] is None and not (
            res["rows_rejected"] and not (res["rows_written"] or res["rows_skipped"])
        )
        self.dir.mkdir(parents=True, exist_ok=True)
        self.record.put("last", res)
        return res


def run_table(lake, store, schema, **kw):
    """:meth:`Writer.run` under the table's own lock; None when another run holds it."""
    w = Writer(lake, store, schema, **kw)
    w.dir.mkdir(parents=True, exist_ok=True)
    try:
        with file_lock(w.dir / "lock", timeout=0):
            return w.run()
    except StateLockBusy:
        return None


# ----------------------------------------------------------------------------- status


def status(
    lake_store, schemas, tables, *, bucket, state_dir, max_pending, max_age_s, prefix="", now=None
):
    """``{"tables": {...}, "problems": [...]}``: per table the staged and rejected counts and the
    last run; a problem for a table that never ran, whose last run failed or is too old, or whose
    backlog is over ``max_pending``."""
    now = now or datetime.now(UTC)
    out, problems = {}, []
    for t in tables:
        last = last_run(state_dir, t)
        pending = len(pending_keys(lake_store, bucket, prefix, t))
        rejected = len(rejected_keys(lake_store, bucket, prefix, t))
        out[t] = {"pending": pending, "rejected_objects": rejected, "last": last}
        if last is None:
            problems.append(f"{t}: has never run")
            continue
        if not last.get("ok"):
            problems.append(
                f"{t}: the last run failed ({last.get('error') or 'every row refused'})"
            )
        age = (
            now - datetime.strptime(last["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        ).total_seconds()
        if max_age_s and age > max_age_s:
            problems.append(f"{t}: the last run was {int(age)} s ago (over {max_age_s})")
        if max_pending and pending > max_pending:
            problems.append(f"{t}: {pending} staged objects wait (over {max_pending})")
    return {"tables": out, "problems": problems}


# ----------------------------------------------------------------------------- environment


class Config:
    def __init__(self, env=None):
        e = os.environ if env is None else env

        def get(name, default=None):
            v = e.get(name, default)
            if v is None or v == "":
                raise Refused(f"{name} is not set")
            return v

        self.namespace = require_namespace(e.get("HNX_LW_NAMESPACE", NAMESPACE))
        self.bucket = get("HNX_LW_STAGING_BUCKET")
        self.prefix = e.get("HNX_LW_STAGING_PREFIX", "")
        if self.prefix and not (self.prefix.endswith("/") and not self.prefix.startswith("/")):
            raise Refused("HNX_LW_STAGING_PREFIX is empty or a relative prefix ending in /")
        self.state_dir = get("HNX_LW_STATE_DIR")
        self.schema_dir = get("HNX_LW_SCHEMA_DIR")
        listed = [t for t in e.get("HNX_LW_TABLES", "").split(",") if t.strip()]
        self.tables = [t.strip() for t in listed] or list(ALL_TABLES)
        self.user = get("HNX_LW_LAKE_USER")
        self.warehouse = get("HNX_LW_LAKE_WAREHOUSE")
        self.credential = get("HNX_LW_LAKE_CREDENTIAL")
        self.catalog_credential = e.get("HNX_LW_CATALOG_CREDENTIAL") or None
        self.ca_file = e.get("HNX_LW_LAKE_CA_FILE") or None
        self.domain = e.get("HNX_LW_DOMAIN") or "unused"
        self.max_attempts = int(e.get("HNX_LW_MAX_ATTEMPTS", "5"))
        self.max_batches = int(e.get("HNX_LW_MAX_BATCHES", "0"))
        self.s3_region_env = e.get("HNX_LW_S3_REGION_VAR", "HNX_LW_S3_REGION")
        self.s3_access_env = e.get("HNX_LW_S3_ACCESS_VAR", "HNX_LW_S3_ACCESS_KEY")
        self.s3_secret_env = e.get("HNX_LW_S3_SECRET_VAR", "HNX_LW_S3_SECRET_KEY")


def open_lake(cfg, schemas, *, ensure):
    """The soc lake: the platform's lake client for the query service and the catalog, signed in as
    the writer's account. ``ensure`` creates the namespace and any missing table (and refuses one
    that differs); without it nothing is created or altered."""
    require_namespace(cfg.namespace)
    from homelabnext.conform.adapters.lake import make_lake

    lake = make_lake(
        namespace=cfg.namespace,
        schemas=[schemas[t] for t in cfg.tables],
        ensure=ensure,
        domain=cfg.domain,
        warehouse=cfg.warehouse,
        user=cfg.user,
        credential=cfg.credential,
        catalog_credential=cfg.catalog_credential,
        ca_file=cfg.ca_file,
    )
    require_namespace(lake_namespace(lake))
    return lake


def open_store(cfg):
    from homelabnext.conform.adapters.s3 import make_object_store

    return make_object_store(
        domain=cfg.domain,
        bucket_prefix="",
        access_key_env=cfg.s3_access_env,
        secret_key_env=cfg.s3_secret_env,
        region_env=cfg.s3_region_env,
    )


# ----------------------------------------------------------------------------- commands


def _say(doc):
    print(json.dumps(doc, sort_keys=True))


def cmd_commit(cfg, tables, schemas, lake=None, store=None):
    tables = [require_table(t, schemas) for t in (tables or cfg.tables)]
    lake = lake or open_lake(cfg, schemas, ensure=False)
    store = store or open_store(cfg)
    code = EXIT_OK
    for t in tables:  # one table's failure never stops the others' turn, but fails the run (LL-008)
        res = run_table(
            lake,
            store,
            schemas[t],
            namespace=cfg.namespace,
            bucket=cfg.bucket,
            prefix=cfg.prefix,
            state_dir=cfg.state_dir,
            max_attempts=cfg.max_attempts,
            max_batches=cfg.max_batches,
        )
        if res is None:
            _say({"table": t, "skipped": "another run holds the table's lock"})
            continue
        _say(res)
        if not res["ok"]:
            code = EXIT_FAILED
    return code


def cmd_ensure(cfg, schemas):
    lake = open_lake(cfg, schemas, ensure=True)
    _say({"namespace": cfg.namespace, "tables": sorted(lake.list_tables())})
    return EXIT_OK


def cmd_schema_check(cfg, schemas, lake=None):
    lake = lake or open_lake(cfg, schemas, ensure=False)
    bad = 0
    for t in cfg.tables:
        try:
            lake.describe(t)  # the table exists and its columns are the pinned ones, or it raises
            ok, why = True, None
        except (LakeError, KeyError) as exc:
            ok, why = False, _cut(f"{type(exc).__name__}: {exc}", 300)
        _say({"table": t, "ok": ok, "problem": None if ok else why})
        bad += 0 if ok else 1
    return EXIT_FAILED if bad else EXIT_OK


def cmd_status(cfg, schemas, max_pending, max_age_s, store=None):
    store = store or open_store(cfg)
    doc = status(
        store,
        schemas,
        [require_table(t, schemas) for t in cfg.tables],
        bucket=cfg.bucket,
        prefix=cfg.prefix,
        state_dir=cfg.state_dir,
        max_pending=max_pending,
        max_age_s=max_age_s,
    )
    _say(doc)
    for p in doc["problems"]:
        print(p, file=sys.stderr)
    return EXIT_FAILED if doc["problems"] else EXIT_OK


def main(argv=None, env=None):
    ap = argparse.ArgumentParser(prog="hnx-lake-writer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("commit")
    c.add_argument("--table", action="append", default=[])
    sub.add_parser("ensure-tables")
    sub.add_parser("schema-check")
    s = sub.add_parser("status")
    s.add_argument("--max-pending", type=int, default=0)
    s.add_argument("--max-age-s", type=int, default=0)
    args = ap.parse_args(argv)
    try:
        cfg = Config(env)
        schemas = table_schemas(cfg.schema_dir)
        for t in cfg.tables:
            require_table(t, schemas)
        if args.cmd == "commit":
            return cmd_commit(cfg, args.table, schemas)
        if args.cmd == "ensure-tables":
            return cmd_ensure(cfg, schemas)
        if args.cmd == "schema-check":
            return cmd_schema_check(cfg, schemas)
        return cmd_status(cfg, schemas, args.max_pending, args.max_age_s)
    except Refused as exc:
        print(f"lake-writer: refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except LakeError as exc:
        print(f"lake-writer: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        sys.exit(main())
