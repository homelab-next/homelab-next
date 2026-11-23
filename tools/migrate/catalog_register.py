#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: catalog-register
#   kind: tool
#   purpose: Register every table of one lake catalog (a copy of its SQLite file) into another Iceberg REST catalog at its current metadata file, without copying, rewriting or deleting any file, and verify the target against the source.
#   owner: maintainers
#   trigger: [manual]
#   inputs: a COPY of the source catalog's SQLite file (the lake-catalog export), the target catalog's URL and warehouse name, for verify the source catalog's URL and a listing of the object store's keys
#   outputs: one line per table (planned, registered, exists, ok, MISMATCH, MISSING, ERROR) and a summary, or the same as JSON
#   exit:
#     "0": plan found no problem, or every table is registered (register) or equals its source and every object its metadata names exists (verify)
#     "1": a table could not be registered, differs from the source, or a file its metadata names is not in the listing
#     "2": usage error, an unusable source file, an unknown schema, or zero tables (a vacuous run is an error)
"""Move a lake's table pointers between two Iceberg REST catalogs. Nothing else moves.

The catalog holds only ``(namespace, table) -> metadata_location``: the data, the manifests and the
metadata JSON live in the object store and stay exactly where they are. The target catalog takes
over by *registering* each table at that current metadata file (the REST ``register`` call), so no
data or metadata file is copied, rewritten or deleted::

    # 1. what would be registered (default; reads the file, asks the target nothing destructive)
    python tools/migrate/catalog_register.py plan   --source-db catalog.db --url <target url> --warehouse lake
    # 2. register (creates the namespaces, then registers each table; existing equal entries are fine)
    python tools/migrate/catalog_register.py register --source-db catalog.db --url ... --warehouse lake --apply
    # 3. prove it: same metadata location, same current snapshot id and history length as the
    #    source catalog, and every object the metadata names exists in the key listing
    python tools/migrate/catalog_register.py verify --source-db catalog.db --url ... --warehouse lake \\
        --reference-url <source url> --listing keys.txt --expect-tables 59

What it refuses, each with a test:

* **The live file.** ``--source-db`` must be a copy: a regular file (not a link) with no ``-wal``,
  ``-shm`` or ``-journal`` beside it (a live database has them while it is written). It is opened
  read-only and immutable and read through SQLite's online backup into memory; it is never written.
* **A vacuous run.** An unknown schema (no ``iceberg_tables`` with the pointer columns), zero tables,
  or zero tables left by ``--only`` is an error, never an "ok".
* **A location outside the warehouse.** The target warehouse's bucket (and key prefix) is read from
  its management API, and a table whose metadata file is outside it is refused before any call.
* **Any destructive request.** The only methods used are GET and POST, and the only POSTs are
  namespace create, register and the table-protection flag (which can only be set to true by this
  tool). There is no DROP, no purge, no ``overwrite`` and no table procedure; ``_call`` refuses
  anything else, so a later edit cannot add one without failing its test.
* **Overwriting.** A table already registered at a different metadata location is an ERROR and is
  left as it is; the tool never repoints an entry.

The bearer token for a target that has authentication is read from the environment variable
``--token-env`` names (never argv). ``--listing`` is the object store's key listing: a file of
``aws s3 ls --recursive`` lines (date, time, size, key) or JSON lines with a ``key``; an empty one
is refused (the check must not pass vacuously, LL-586).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

_NAME = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
_META = re.compile(r"s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/(.+\.metadata\.json)\Z")
_COLUMNS = {"table_namespace", "table_name", "metadata_location"}
# the only requests this tool may make: (method, shape of the path after the base URL)
_ALLOWED = (
    ("GET", re.compile(r"/(management/v1/warehouse|catalog/v1/|v1/)")),
    ("POST", re.compile(r"/(catalog/)?v1/([^/]+/)?namespaces(/[A-Za-z0-9_]+/register)?\Z")),
    ("POST", re.compile(r"/management/v1/warehouse/[0-9a-f-]+/table/[0-9a-f-]+/protection\Z")),
)


class SourceError(ValueError):
    """The source file is unusable (exit 2)."""


@dataclass(frozen=True)
class Entry:
    namespace: str
    table: str
    location: str

    @property
    def name(self) -> str:
        return f"{self.namespace}.{self.table}"


@dataclass
class Row:
    name: str
    status: str
    detail: str = ""
    notes: list[str] = field(default_factory=list)


def read_source(path: str) -> list[Entry]:
    """The (namespace, table, metadata_location) rows of a COPY of the source catalog, sorted."""
    p = Path(path)
    try:
        st = p.lstat()
    except OSError as exc:
        raise SourceError(f"{path}: {exc.strerror}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise SourceError(f"{path}: not a regular file (a link or a directory is refused)")
    for suffix in ("-wal", "-shm", "-journal"):
        if Path(str(p) + suffix).exists():
            raise SourceError(
                f"{path}: {p.name}{suffix} exists beside it, so this looks like a live database; "
                "give the export hook's copy (an online backup), never the live file"
            )
    try:
        src = sqlite3.connect(f"{p.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
        mem = sqlite3.connect(":memory:")
        try:
            src.backup(mem)
        finally:
            src.close()
        cols = {r[1] for r in mem.execute("PRAGMA table_info(iceberg_tables)")}
        if not cols >= _COLUMNS:
            raise SourceError(
                f"{path}: no iceberg_tables with columns {sorted(_COLUMNS)} (unknown schema)"
            )
        rows = mem.execute(
            "SELECT table_namespace, table_name, metadata_location, "
            + ("record_type" if "record_type" in cols else "'TABLE'")
            + " FROM iceberg_tables"
        ).fetchall()
        mem.close()
    except sqlite3.Error as exc:
        raise SourceError(f"{path}: not a readable SQLite catalog ({exc})") from exc
    out: list[Entry] = []
    for ns, table, loc, kind in rows:
        if kind not in (None, "TABLE"):
            raise SourceError(
                f"{path}: {ns}.{table} is a {kind}, which this tool does not register"
            )
        if not (
            isinstance(ns, str)
            and _NAME.match(ns)
            and isinstance(table, str)
            and _NAME.match(table)
        ):
            raise SourceError(f"{path}: an unsafe namespace or table name {ns!r}.{table!r}")
        if not (isinstance(loc, str) and _META.match(loc)):
            raise SourceError(f"{path}: {ns}.{table} has no usable metadata location ({loc!r})")
        out.append(Entry(ns, table, loc))
    if not out:
        raise SourceError(f"{path}: the catalog lists no table (refusing a vacuous run)")
    return sorted(out, key=lambda e: (e.namespace, e.table))


def read_pointers(cat: Catalog, warehouse: str) -> list[Entry]:
    """Every table of a running catalog as an Entry (the rollback's source: Lakekeeper's own
    current metadata locations, read with GET only)."""
    api = cat.api_base(warehouse)
    code, doc = cat._call("GET", f"{api}/namespaces")
    if code != 200:
        raise SourceError(f"namespaces: HTTP {code}")
    out: list[Entry] = []
    for ns in [n[0] for n in (doc or {}).get("namespaces", [])]:
        code, doc = cat._call("GET", f"{api}/namespaces/{ns}/tables")
        if code != 200:
            raise SourceError(f"tables of {ns}: HTTP {code}")
        for ident in (doc or {}).get("identifiers", []):
            code, t = cat._call("GET", f"{api}/namespaces/{ns}/tables/{ident['name']}")
            loc = (t or {}).get("metadata-location")
            if code != 200 or not (isinstance(loc, str) and _META.match(loc)):
                raise SourceError(f"{ns}.{ident['name']}: no metadata location (HTTP {code})")
            if not (_NAME.match(ns) and _NAME.match(ident["name"])):
                raise SourceError(f"an unsafe name {ns!r}.{ident['name']!r}")
            out.append(Entry(ns, ident["name"], loc))
    if not out:
        raise SourceError("the catalog lists no table (refusing a vacuous run)")
    return sorted(out, key=lambda e: (e.namespace, e.table))


class Catalog:
    """A small Iceberg REST client that can only make the requests of ``_ALLOWED``."""

    def __init__(self, base: str, token: str | None = None, timeout: float = 60.0):
        parts = urllib.parse.urlsplit(base)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.query
            or parts.fragment
        ):
            raise ValueError(f"not a catalog URL: {base!r}")
        self.base = base.rstrip("/")
        self.token, self.timeout = token, timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict | None]:
        if not any(method == m and rx.match(path) for m, rx in _ALLOWED):
            raise PermissionError(f"refused: {method} {path} is not a request this tool makes")
        if method == "POST" and path.endswith("/protection") and body != {"protected": True}:
            raise PermissionError("refused: protection may only be set to true")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                code = resp.status
        except urllib.error.HTTPError as exc:
            raw, code = exc.read(), exc.code
        except (urllib.error.URLError, OSError) as exc:
            raise ConnectionError(f"{method} {path}: {exc}") from exc
        try:
            return code, (json.loads(raw) if raw else None)
        except ValueError:
            return code, None

    def api_base(self, warehouse: str) -> str:
        """The path the table API is served under: ``/catalog/v1/<prefix>`` (the catalog under a
        warehouse prefix) or, for a catalog that serves its API at the root, ``/v1``."""
        code, doc = self._call(
            "GET", f"/catalog/v1/config?warehouse={urllib.parse.quote(warehouse)}"
        )
        if code == 200:
            pfx = ((doc or {}).get("defaults") or {}).get("prefix")
            if not pfx:
                raise ConnectionError(f"the catalog gave no prefix for warehouse {warehouse!r}")
            return f"/catalog/v1/{pfx}"
        code, doc = self._call("GET", "/v1/config")
        if code != 200:
            raise ConnectionError(f"no catalog config answered (HTTP {code})")
        pfx = ((doc or {}).get("defaults") or {}).get("prefix")
        return f"/v1/{pfx}" if pfx else "/v1"

    def warehouse(self, name: str) -> dict | None:
        """The named warehouse from the management API; None for a catalog that has none (the
        Apache fixture: one fixed warehouse, nothing to check a location against)."""
        code, doc = self._call("GET", "/management/v1/warehouse")
        if code in (400, 404, 405):
            return None
        for w in (doc or {}).get("warehouses", []) if code == 200 else []:
            if w.get("name") == name:
                return w
        raise ConnectionError(f"no warehouse {name!r} on the target (HTTP {code})")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # a redirect would carry the token elsewhere
        return None


def inside_warehouse(wh: dict, entries: Sequence[Entry]) -> list[str]:
    """The entries whose metadata file is not under the warehouse's bucket (and key prefix)."""
    prof = wh.get("storage-profile") or {}
    bucket, key_prefix = prof.get("bucket"), (prof.get("key-prefix") or "").strip("/")
    bad = []
    for e in entries:
        m = _META.match(e.location)
        key = m.group(2) if m else ""
        if not m or m.group(1) != bucket or (key_prefix and not key.startswith(key_prefix + "/")):
            bad.append(f"{e.name}: {e.location}")
    return bad


def plan(entries: Sequence[Entry], wh: dict | None) -> list[Row]:
    rows = [Row(e.name, "planned", e.location) for e in entries]
    if wh is not None:
        for line in inside_warehouse(wh, entries):
            name, _, loc = line.partition(": ")
            for r in rows:
                if r.name == name:
                    r.status, r.detail = (
                        "ERROR",
                        f"outside the warehouse's bucket or key prefix: {loc}",
                    )
    return rows


def register(cat: Catalog, warehouse: str, entries: Sequence[Entry]) -> list[Row]:
    api = cat.api_base(warehouse)
    wh = cat.warehouse(warehouse)
    out = plan(entries, wh)
    if any(r.status == "ERROR" for r in out):
        return out  # nothing is created when any table cannot be registered
    made: set[str] = set()
    base = f"{api}/namespaces"
    for r, e in zip(out, entries, strict=True):
        if e.namespace not in made:
            code, doc = cat._call("POST", base, {"namespace": [e.namespace], "properties": {}})
            if code not in (200, 409):
                r.status, r.detail = "ERROR", f"namespace create: HTTP {code} {_msg(doc)}"
                continue
            made.add(e.namespace)
        code, doc = cat._call("POST", f"{base}/{e.namespace}/register",
                              {"name": e.table, "metadata-location": e.location})  # fmt: skip
        if code == 200:
            got = (doc or {}).get("metadata-location")
            if got != e.location:
                r.status, r.detail = "ERROR", f"registered, but the target reports {got!r}"
                continue
            r.status, r.detail = "registered", e.location
            _protect(cat, wh, doc or {}, r)
        elif code == 409:
            code, doc = cat._call("GET", f"{base}/{e.namespace}/tables/{e.table}")
            got = (doc or {}).get("metadata-location")
            if code == 200 and got == e.location:
                r.status, r.detail = "exists", e.location
                _protect(cat, wh, doc or {}, r)
            else:
                r.status, r.detail = (
                    "ERROR",
                    f"already registered at another location ({got!r}); left as is",
                )
        else:
            r.status, r.detail = "ERROR", f"register: HTTP {code} {_msg(doc)}"
    return out


def _protect(cat: Catalog, wh: dict | None, loaded: dict, r: Row) -> None:
    if wh is None:
        return
    tid = ((loaded.get("metadata") or {}).get("table-uuid")) or ""
    wid = wh.get("id") or wh.get("warehouse-id") or ""
    if not (tid and wid):
        r.notes.append("not protected (no table id or warehouse id)")
        return
    code, _ = cat._call(
        "POST", f"/management/v1/warehouse/{wid}/table/{tid}/protection", {"protected": True}
    )
    if code not in (200, 204):
        r.notes.append(f"not protected (HTTP {code})")


def _msg(doc: dict | None) -> str:
    return str(((doc or {}).get("error") or {}).get("message", ""))[:200]


def read_listing(path: str) -> set[str]:
    """The object keys of a listing (aws ``s3 ls --recursive`` lines or JSON lines); empty is refused."""
    keys: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            k = json.loads(line).get("key")
            if isinstance(k, str):
                keys.add(k)
            continue
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[2].isdigit():
            keys.add(parts[3])
    if not keys:
        raise SourceError(f"{path}: the listing names no object (refusing a vacuous check)")
    return keys


def named_objects(metadata: dict, location: str) -> tuple[list[str], list[str]]:
    """The objects a table's metadata JSON names, as (required, history).

    Required, because a writer or a reader of the CURRENT state opens them (LL-586): the metadata
    file itself, the current snapshot's manifest list, and every statistics and partition-statistics
    file (the engine reads the existing one on INSERT). History: earlier metadata files and the
    manifest lists of earlier snapshots, which only a time-travel query or a maintenance procedure
    over the whole history opens (an import that copied the current snapshot only does not hold
    them, in the source catalog either, so their absence is not something the move caused).
    Data files and manifests are read by the query engine's row counts, not named here."""
    current = metadata.get("current-snapshot-id")
    required = [location]
    history = [
        m["metadata-file"] for m in metadata.get("metadata-log", []) if m.get("metadata-file")
    ]
    for s in metadata.get("snapshots", []):
        if s.get("manifest-list"):
            (required if s.get("snapshot-id") == current else history).append(s["manifest-list"])
    for key in ("statistics", "partition-statistics"):
        required += [
            s["statistics-path"] for s in metadata.get(key, []) if s.get("statistics-path")
        ]
    return sorted(set(required)), sorted(set(history) - set(required))


def _key(uri: str) -> str:
    m = re.match(r"s3a?://[^/]+/(.+)\Z", uri)
    return m.group(1) if m else ""


def verify(cat: Catalog, warehouse: str, ref: Catalog, ref_warehouse: str,
           entries: Sequence[Entry], keys: set[str]) -> list[Row]:  # fmt: skip
    api_t, api_r = cat.api_base(warehouse), ref.api_base(ref_warehouse)
    out = []
    for e in entries:
        tail = f"/namespaces/{e.namespace}/tables/{e.table}"
        t_code, t = cat._call("GET", api_t + tail)
        r_code, r = ref._call("GET", api_r + tail)
        row = Row(e.name, "ok")
        out.append(row)
        if t_code != 200 or r_code != 200:
            row.status, row.detail = "ERROR", f"load: target HTTP {t_code}, source HTTP {r_code}"
            continue
        tm, rm = (t or {}).get("metadata") or {}, (r or {}).get("metadata") or {}
        problems = []
        if (t or {}).get("metadata-location") != e.location:
            problems.append(
                f"metadata_location {(t or {}).get('metadata-location')!r} != {e.location!r}"
            )
        for field_name in ("current-snapshot-id", "table-uuid", "location", "current-schema-id"):
            if tm.get(field_name) != rm.get(field_name):
                problems.append(
                    f"{field_name} {tm.get(field_name)!r} != source {rm.get(field_name)!r}"
                )
        if len(tm.get("snapshots", [])) != len(rm.get("snapshots", [])):
            problems.append("snapshot count differs")
        if problems:
            row.status, row.detail = "MISMATCH", "; ".join(problems)
            continue
        required, history = named_objects(tm, e.location)
        missing = [o for o in required if _key(o) not in keys]
        if missing:
            row.status = "MISSING"
            row.detail = (
                f"{len(missing)} required object(s) not in the listing, first: {missing[0]}"
            )
        gone = sum(1 for o in history if _key(o) not in keys)
        if gone:
            row.notes.append(
                f"history: {gone} of {len(history)} older objects absent from the object store"
            )
    return out


def render(rows: Sequence[Row], expect: int | None) -> tuple[str, bool]:
    ok = all(r.status in ("planned", "registered", "exists", "ok") for r in rows)
    lines = [f"{r.status:10} {r.name}" + (f"  {r.detail}" if r.status not in ("ok", "planned") or r.detail else "")
             + "".join(f"  [{n}]" for n in r.notes) for r in rows]  # fmt: skip
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.status] = counts.get(r.status, 0) + 1
    if expect is not None and len(rows) != expect:
        ok = False
        lines.append(f"ERROR: {len(rows)} tables, expected {expect}")
    lines.append("summary: " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))
    return "\n".join(lines), ok


def _args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("command", choices=["plan", "register", "verify"])
    p.add_argument("--source-db", default=None, help="a COPY of the source catalog's SQLite file")
    p.add_argument(
        "--source-url",
        default=None,
        help="instead of --source-db (rollback): a running catalog whose current pointers are the source",
    )
    p.add_argument("--source-warehouse", default="", help="with --source-url: its warehouse name")
    p.add_argument("--url", required=True, help="the target catalog, scheme://host:port")
    p.add_argument("--warehouse", required=True, help="the target warehouse's name")
    p.add_argument("--reference-url", default=None, help="verify: the source catalog (read only)")
    p.add_argument(
        "--reference-warehouse",
        default="",
        help="verify: the source's warehouse name, if it has one",
    )
    p.add_argument("--listing", default=None, help="verify: the object store's key listing")
    p.add_argument(
        "--token-env", default=None, help="the variable holding the target's bearer token"
    )
    p.add_argument("--only", action="append", default=[], metavar="NS.TABLE")
    p.add_argument("--expect-tables", type=int, default=None)
    p.add_argument(
        "--apply",
        action="store_true",
        help="register: actually do it (without it, register is a plan)",
    )
    p.add_argument("--json", action="store_true")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    a = _args(argv)
    if bool(a.source_db) == bool(a.source_url):
        print("catalog_register: give exactly one of --source-db and --source-url", file=sys.stderr)
        return 2
    try:
        entries = read_source(a.source_db) if a.source_db else read_pointers(
            Catalog(a.source_url), a.source_warehouse)  # fmt: skip
    except (SourceError, ConnectionError, ValueError) as exc:
        print(f"catalog_register: {exc}", file=sys.stderr)
        return 2
    if a.only:
        unknown = set(a.only) - {e.name for e in entries}
        if unknown:
            print(f"catalog_register: not in the source: {sorted(unknown)}", file=sys.stderr)
            return 2
        entries = [e for e in entries if e.name in set(a.only)]
        if not entries:
            print("catalog_register: --only left no table", file=sys.stderr)
            return 2
    token = None
    if a.token_env:
        token = os.environ.get(a.token_env)
        if not token:
            print("catalog_register: the variable named by --token-env is not set", file=sys.stderr)
            return 2
    try:
        cat = Catalog(a.url, token)
        if a.command == "plan" or (a.command == "register" and not a.apply):
            rows = plan(entries, cat.warehouse(a.warehouse))
        elif a.command == "register":
            rows = register(cat, a.warehouse, entries)
        else:
            if not a.reference_url or not a.listing:
                print(
                    "catalog_register: verify needs --reference-url and --listing", file=sys.stderr
                )
                return 2
            rows = verify(cat, a.warehouse, Catalog(a.reference_url), a.reference_warehouse,
                          entries, read_listing(a.listing))  # fmt: skip
    except SourceError as exc:
        print(f"catalog_register: {exc}", file=sys.stderr)
        return 2
    except (ConnectionError, ValueError) as exc:
        print(f"catalog_register: {exc}", file=sys.stderr)
        return 2
    text, ok = render(rows, a.expect_tables)
    if a.json:
        print(
            json.dumps({"ok": ok, "tables": [r.__dict__ for r in rows]}, indent=2, sort_keys=True)
        )
    else:
        print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
