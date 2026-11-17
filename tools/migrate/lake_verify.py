#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lake-verify
#   kind: tool
#   purpose: Compare each lake table's row count at a fixed snapshot with a reference TSV, to prove a copied lake (catalog and bucket) equals its source.
#   owner: maintainers
#   trigger: [manual]
#   inputs: a reference TSV (one row per table - the schema, table, snapshot id and row count the source answered); the query engine's URL, a sign-in and its CA
#   outputs: one line per table (ok, MISMATCH, ERROR, HISTORY), with --all-catalog-tables a separate section for catalog tables the reference does not list, and a summary, or the same as JSON
#   exit:
#     "0": every table's count at its snapshot equals the reference, every table's whole snapshot history is readable (and the table count is the expected one)
#     "1": a count differs, a snapshot cannot be read, a table's history ($all_manifests) is unreadable, a reference table is missing, or the table count is not the expected one
#     "2": usage error or an unreadable reference file
"""Verify a copied lake against the counts its source reported.

    python tools/migrate/lake_verify.py --expected trino_reference_counts.tsv \\
        --url https://<engine>:8443 --user <login> --password-env HNX_LAKE_VERIFY_PASSWORD \\
        [--ca-file lab-ca.pem] [--expect-tables 37] [--cross-check] [--json]

For each reference row, ``SELECT count(*) FROM <catalog>."<schema>"."<table>" FOR VERSION AS OF
<snapshot_id>`` is run on the engine under test and compared with the reference. A count at a
snapshot id is immutable, so a writer cannot make it drift: a difference is the copy's. Nothing
here checks that the reference was taken after the source's writers were frozen and their final
delta copied: the cutover (Task 3.4) must freeze the writers of the kept tables, take the final
delta, and only then produce the reference TSV this tool is given. A snapshot
the copy does not hold (the old lake's archive keeps the CURRENT snapshot only; older ones are
intentionally not restorable) is an ERROR naming the engine's message, never a pass.

The reference TSV has no header and one row per table, tab-separated, in either of two shapes:

* ``schema.table <TAB> rows <TAB> snapshot_id``      (the old lake's archive: trino_reference_counts.tsv)
* ``schema <TAB> table <TAB> snapshot_id <TAB> rows``

A first line whose count column is not a number is a header and is skipped. ``#`` lines and blank
lines are ignored.

``--cross-check`` also reads the count the snapshot's own summary recorded (``total-records`` in
the ``$snapshots`` metadata table) and notes a disagreement with the reference: a scan and the
metadata are independent readings of the same snapshot (LL-014: verify with the table's own
metadata where a convenient reader can disagree). The summary counts data records and ignores
delete files, so it is a note, not a failure.

**All-catalog mode (``--all-catalog-tables``).** The checks above cover only the tables the reference
TSV lists. With this flag the tool also lists the catalog's own base tables (``information_schema.tables``,
without the engine's system schemas) and runs the history check on every one the reference does not
list (for example registrations of tables that were dropped on purpose and never copied). They are
reported in their own section, ``catalog tables not in the reference``; one whose history is unreadable
(or the listing itself failing) makes the run fail, a readable one is only counted.

**All-history check (on by default, ``--no-all-history`` to skip).** The count above reads only the
current snapshot, so a copy that holds the current snapshot but whose catalog still lists thousands of
older snapshots with no manifest lists passes it, and then every maintenance procedure that has to read
the whole history (``remove_orphan_files``, ``expire_snapshots`` cleanup) fails or hangs (the 2026-11-17
first maintenance run on a restored lake). So for every table the tool also runs ``SELECT count(*) FROM
<catalog>."<schema>"."<table>$all_manifests"``, which reads the manifest list of every retained
snapshot, and a table where it fails is reported as ``HISTORY`` with the table name and the engine's
message. The fix for a ``HISTORY`` table is metadata-side (expire the snapshots whose files were never
copied, or restore their files), never a retry. A table the engine answers with no row is an ERROR, not ok.

The password is read from the environment variable ``--password-env`` names, never from argv. The
connection is HTTPS verified against ``--ca-file``, follows no redirect and uses no proxy.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from homelabnext._http import credential_opener, is_loopback  # noqa: E402
from homelabnext.lake.errors import LakeError  # noqa: E402
from homelabnext.lake.trino_http import TrinoHTTP, password_auth  # noqa: E402

_NAME = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
_NUM = re.compile(r"[0-9]{1,19}\Z")


@dataclass(frozen=True)
class Expected:
    schema: str
    table: str
    snapshot_id: int
    rows: int

    @property
    def name(self) -> str:
        return f"{self.schema}.{self.table}"


@dataclass
class Result:
    name: str
    status: str  # ok | MISMATCH | ERROR | HISTORY
    expected: int
    snapshot_id: int
    got: int | None = None
    detail: str = ""
    notes: list[str] = field(default_factory=list)
    history: str = (
        ""  # why the table's whole history ($all_manifests) cannot be read; empty when it can
    )


class ReferenceError(ValueError):
    pass


def parse_reference(text: str) -> list[Expected]:
    """The reference rows of ``text``, in file order; a malformed row, an unsafe name or a table
    listed twice is a ReferenceError naming the line."""
    out: list[Expected] = []
    seen: set[str] = set()
    first = True
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.rstrip("\r\n").split("\t")
        if len(cols) == 3:
            name, rows, snap = cols
            schema, _, table = name.partition(".")
        elif len(cols) == 4:
            schema, table, snap, rows = cols
        else:
            raise ReferenceError(
                f"line {n}: expected 3 or 4 tab-separated columns, got {len(cols)}"
            )
        if first and not _NUM.match(rows.strip()):
            first = False
            continue  # a header
        first = False
        schema, table, rows, snap = schema.strip(), table.strip(), rows.strip(), snap.strip()
        if not (_NAME.match(schema) and _NAME.match(table)):
            raise ReferenceError(f"line {n}: {schema!r}.{table!r} is not a plain schema.table name")
        if not (_NUM.match(rows) and _NUM.match(snap)):
            raise ReferenceError(f"line {n}: the row count and the snapshot id are whole numbers")
        e = Expected(schema, table, int(snap), int(rows))
        if e.name in seen:
            raise ReferenceError(f"line {n}: {e.name} is listed twice")
        seen.add(e.name)
        out.append(e)
    return out


def count_sql(catalog: str, e: Expected) -> str:
    return f'SELECT count(*) AS n FROM {catalog}."{e.schema}"."{e.table}" FOR VERSION AS OF CAST({e.snapshot_id} AS BIGINT)'


def summary_sql(catalog: str, e: Expected) -> str:
    return (
        f'SELECT summary[\'total-records\'] AS n FROM {catalog}."{e.schema}"."{e.table}$snapshots" '
        f"WHERE snapshot_id = {e.snapshot_id}"
    )


def history_sql(catalog: str, e: Expected) -> str:
    return f'SELECT count(*) AS n FROM {catalog}."{e.schema}"."{e.table}$all_manifests"'


def check_history(engine: TrinoHTTP, catalog: str, e: Expected) -> str:
    """ "" when every retained snapshot's manifest list of the table reads, else the reason."""
    try:
        rows = engine.execute(history_sql(catalog, e)).rows
        int(rows[0]["n"])
    except (LakeError, KeyError, IndexError, ValueError, TypeError) as exc:
        return " ".join(str(exc).split())[:300] or type(exc).__name__
    return ""


def verify(
    engine: TrinoHTTP,
    catalog: str,
    expected: Sequence[Expected],
    cross_check: bool = False,
    all_history: bool = True,
) -> list[Result]:
    results: list[Result] = []
    for e in expected:
        r = Result(e.name, "ok", e.rows, e.snapshot_id)
        try:
            rows = engine.execute(count_sql(catalog, e)).rows
            r.got = int(rows[0]["n"])
            if r.got != e.rows:
                r.status = "MISMATCH"
                r.detail = f"count {r.got} != reference {e.rows}"
        except (LakeError, KeyError, IndexError, ValueError) as exc:
            r.status, r.detail = "ERROR", " ".join(str(exc).split())[:300]
        if cross_check and r.status != "ERROR":
            try:
                rec = engine.execute(summary_sql(catalog, e)).rows
                if not rec:
                    r.notes.append("cross-check: the snapshot is not in the table's $snapshots")
                elif rec[0]["n"] is not None and int(rec[0]["n"]) != e.rows:
                    r.notes.append(
                        f"cross-check: the snapshot summary says {rec[0]['n']} records, the reference {e.rows}"
                    )
            except (LakeError, KeyError, IndexError, ValueError) as exc:
                r.notes.append("cross-check unavailable: " + " ".join(str(exc).split())[:120])
        if all_history:
            r.history = check_history(engine, catalog, e)
            if r.history and r.status == "ok":
                r.status = "HISTORY"
                r.detail = f"all-history unreadable: {r.history}"
            elif r.history:
                r.notes.append(f"all-history unreadable: {r.history}")
        results.append(r)
    return results


def listing_sql(catalog: str) -> str:
    return (
        f"SELECT table_schema, table_name FROM {catalog}.information_schema.tables "
        "WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('information_schema', 'system') "
        "ORDER BY table_schema, table_name"
    )


def verify_extras(
    engine: TrinoHTTP, catalog: str, reference: Sequence[Expected]
) -> tuple[list[Result], int]:
    """History-check every catalog base table the reference does not list. Returns the failures (a
    listing that fails is one ERROR row) and the number of extras that read cleanly."""
    known = {e.name for e in reference}
    try:
        rows = engine.execute(listing_sql(catalog)).rows
        found = [(str(r["table_schema"]), str(r["table_name"])) for r in rows]
    except (LakeError, KeyError, ValueError) as exc:
        detail = " ".join(str(exc).split())[:300]
        return [Result("<catalog listing>", "ERROR", 0, 0, detail=detail)], 0
    bad: list[Result] = []
    clean = 0
    for schema, table in found:
        if f"{schema}.{table}" in known:
            continue
        if not (_NAME.match(schema) and _NAME.match(table)):
            bad.append(
                Result(f"{schema}.{table}", "ERROR", 0, 0, detail="not a plain schema.table name")
            )
            continue
        e = Expected(schema, table, 0, 0)
        why = check_history(engine, catalog, e)
        if why:
            bad.append(
                Result(
                    e.name, "HISTORY", 0, 0, detail=f"all-history unreadable: {why}", history=why
                )
            )
        else:
            clean += 1
    return bad, clean


def render(
    results: Sequence[Result],
    expect_tables: int | None,
    extras: tuple[list[Result], int] | None = None,
) -> tuple[str, bool]:
    lines = []
    for r in results:
        got = "-" if r.got is None else str(r.got)
        lines.append(
            f"{r.status:8} {r.name:40} snapshot {r.snapshot_id} reference {r.expected} got {got}"
            + (f"  {r.detail}" if r.detail else "")
        )
        lines += [f"           note: {n}" for n in r.notes]
    bad = [r for r in results if r.status != "ok"]
    ok = not bad
    tail = f"{len(results) - len(bad)} of {len(results)} table(s) equal the reference"
    if expect_tables is not None and len(results) != expect_tables:
        ok = False
        tail += f"; the reference lists {len(results)} table(s), {expect_tables} expected"
    if extras is not None:
        bad_extras, clean = extras
        lines.append("catalog tables not in the reference:")
        lines += [f"{r.status:8} {r.name:40} {r.detail}" for r in bad_extras]
        lines.append(f"  {clean} readable, {len(bad_extras)} failing")
        if bad_extras:
            ok = False
    lines.append(tail + ("" if ok else "  -> NOT EQUAL"))
    return "\n".join(lines), ok


def _args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--expected", required=True, help="the reference TSV")
    p.add_argument(
        "--url",
        default=os.environ.get("HNX_ENDPOINT_LAKE_QUERY", ""),
        help="the engine, scheme://host:port (default $HNX_ENDPOINT_LAKE_QUERY)",
    )
    p.add_argument("--user", required=True, help="the engine login")
    p.add_argument(
        "--password-env",
        default="HNX_LAKE_VERIFY_PASSWORD",
        help="the environment variable holding the password",
    )
    p.add_argument(
        "--ca-file", default=None, help="the CA certificate that issued the engine's certificate"
    )
    p.add_argument("--catalog", default="iceberg")
    p.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="SCHEMA.TABLE",
        help="verify only these tables",
    )
    p.add_argument(
        "--expect-tables",
        type=int,
        default=None,
        help="fail unless the reference lists exactly this many tables",
    )
    p.add_argument(
        "--cross-check",
        action="store_true",
        help="also compare the snapshot summary's total-records",
    )
    p.add_argument(
        "--no-all-history",
        action="store_true",
        help="skip the check that every table's whole snapshot history ($all_manifests) reads",
    )
    p.add_argument(
        "--all-catalog-tables",
        action="store_true",
        help="also history-check every catalog table the reference does not list (reported separately)",
    )
    p.add_argument("--timeout", type=float, default=900.0, help="seconds one count may take")
    p.add_argument("--json", action="store_true")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    a = _args(argv)
    if not a.url:
        print("lake_verify: no engine URL (--url or HNX_ENDPOINT_LAKE_QUERY)", file=sys.stderr)
        return 2
    if not _NAME.match(a.catalog):
        print("lake_verify: --catalog is a plain name", file=sys.stderr)
        return 2
    try:
        expected = parse_reference(Path(a.expected).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ReferenceError) as exc:
        print(f"lake_verify: {a.expected}: {exc}", file=sys.stderr)
        return 2
    full_reference = list(expected)
    if a.only:
        want = set(a.only)
        unknown = want - {e.name for e in expected}
        if unknown:
            print(f"lake_verify: not in the reference: {sorted(unknown)}", file=sys.stderr)
            return 2
        expected = [e for e in expected if e.name in want]
    if not expected:
        print("lake_verify: the reference lists no table", file=sys.stderr)
        return 2
    if a.password_env not in os.environ or not os.environ[a.password_env]:
        print(
            "lake_verify: the variable named by --password-env is not set or is empty",
            file=sys.stderr,
        )
        return 2
    parts = urllib.parse.urlsplit(a.url)
    if parts.scheme != "https" and not (parts.scheme == "http" and is_loopback(parts.hostname)):
        print(
            "lake_verify: a sign-in goes over https only (plain http is for loopback)",
            file=sys.stderr,
        )
        return 2
    name = a.password_env
    try:
        engine = TrinoHTTP(
            a.url,
            user=a.user,
            source="lake-verify",
            timeout=a.timeout,
            auth=password_auth(a.user, lambda: os.environ[name]),
            opener=credential_opener(a.ca_file),
        )
    except LakeError as exc:
        print(f"lake_verify: {exc}", file=sys.stderr)
        return 2
    results = verify(engine, a.catalog, expected, a.cross_check, not a.no_all_history)
    extras = None
    if a.all_catalog_tables:
        # the reference as read, before --only narrowed it: a table the reference lists is not an extra
        extras = verify_extras(engine, a.catalog, full_reference)
    text, ok = render(results, a.expect_tables, extras)
    if a.json:
        print(
            json.dumps(
                {
                    "ok": ok,
                    "tables": [r.__dict__ for r in results],
                    **(
                        {
                            "extras": {
                                "failing": [r.__dict__ for r in extras[0]],
                                "readable": extras[1],
                            }
                        }
                        if extras is not None
                        else {}
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
