#!/opt/hnx/current/bin/python
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: honeypot-lake
#   kind: job
#   purpose: Land the receiver's spooled honeypot events into the lake's honeypot events table through the query service (offset-tracked, schema-checked first), and judge the table's freshness.
#   owner: platform
#   trigger: [timer:honeypot/lake, role:honeypot, script:honeypot-report]
#   inputs: "land | freshness MAX_AGE_HOURS | ensure-table | schema-check; environment HNX_HP_*, HNX_ENDPOINT_LAKE_QUERY and the lake login in HNX_SECRET_HONEYPOT_LAKE_LOGIN (honeypot.env and the credentials env file); runs under the hnx runtime release python"
#   outputs: rows INSERTed into the events table; the state file (offset) and last-run.json under the state directory; one JSON or text line on stdout
#   installs_to: /usr/local/libexec/homelabnext/hnx-honeypot-lake
#   exit:
#     "0": landed (or nothing new), or the table is fresh, or the schema is as expected
#     "1": failed (the lake refused, a total parse failure, a stale or empty table; the reason on stderr)
#     "2": refused before any write (the table is missing or its schema differs from the contract) or a usage error
"""Land the honeypot's spooled events into ``<catalog>.<schema>.<table>`` (the events table).

The receiver appends newline-delimited JSON to the spool; ``land`` reads it from a saved byte
offset, maps each event onto the table's 26 columns (``to_row``: Suricata EVE lines, the HTTP
bait's captures and the SSH decoys' sessions), and INSERTs them through the lake's query service in
statements of bounded size, saving the offset after every statement that succeeded. It never
creates, alters or drops anything: before the first write it reads the table's columns and refuses
unless they are exactly the contract (``COLUMNS``), because a writer that quietly landed into a
different shape would be the lake's next silent defect. ``ensure-table`` is the one explicit
creation, for a fresh lake. A line that cannot be parsed is counted and reported, never dropped
silently, and a run in which every line failed exits 1.

A crash between a statement finishing and the offset being saved lands that statement's rows
again on the next run (at-least-once); the window is one statement wide.
"""

import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from homelabnext.lake.errors import LakeError

# the contract: the existing table's columns, in order
COLUMNS = [
    ("event_time", "timestamp(6) with time zone"),
    ("ingested_at", "timestamp(6) with time zone"),
    ("source", "varchar"),
    ("honeypot_host", "varchar"),
    ("peer_ip", "varchar"),
    ("event_type", "varchar"),
    ("src_ip", "varchar"),
    ("dest_ip", "varchar"),
    ("src_port", "bigint"),
    ("dest_port", "bigint"),
    ("proto", "varchar"),
    ("alert_signature", "varchar"),
    ("alert_category", "varchar"),
    ("alert_severity", "bigint"),
    ("http_hostname", "varchar"),
    ("http_url", "varchar"),
    ("http_method", "varchar"),
    ("http_status", "bigint"),
    ("http_user_agent", "varchar"),
    ("dns_query", "varchar"),
    ("raw", "varchar"),
    ("http_content_type", "varchar"),
    ("payload", "varchar"),
    ("payload_len", "bigint"),
    ("cred_username", "varchar"),
    ("cred_password", "varchar"),
]
CREATE_WITH = (
    "compression_codec = 'ZSTD', format = 'PARQUET', format_version = 2, "
    "partitioning = ARRAY['day(event_time)']"
)
MAX_STATEMENT_CHARS = 500_000  # under the query service's default 1,000,000-character query limit
RAW_LIMIT = 8000


def _env(name, default=""):
    return os.environ.get(name, default)


_IDENT = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")


def _table():
    """catalog.schema.table from the environment; every part must be a plain identifier (they are
    written into SQL), and the catalog has no default: it is the site's name for its lake."""
    parts = [
        _env("HNX_HP_LAKE_CATALOG"),
        _env("HNX_HP_LAKE_SCHEMA", "honeypot"),
        _env("HNX_HP_LAKE_TABLE", "events"),
    ]
    if not all(_IDENT.match(p) for p in parts):
        raise ValueError("HNX_HP_LAKE_CATALOG, _SCHEMA and _TABLE must each be a plain identifier")
    return ".".join(parts)


def _state_dir() -> Path:
    return Path(_env("HNX_HP_STATE_DIR", "state"))


# ----------------------------------------------------------------------------- the query service


class Lake:
    """The lake's query service as this script uses it: statements in, rows out. The engine client
    is the platform's own (homelabnext.conform.adapters.lake): HTTPS only with a credential, the
    certificate always verified, no redirect followed, no proxy, an INSERT retried only when the
    service says it has not taken it (never after a gateway error, which could write twice)."""

    def __init__(self, engine):
        self.engine = engine

    def query(self, sql):
        """Run one statement to its end: (column names, rows as lists), or a LakeError."""
        res = self.engine.execute(sql, client_tags=("honeypot",))
        cols = [c["name"] for c in res.columns]
        return cols, [[r[c] for c in cols] for r in res.rows]

    def run(self, sql, timeout=None):
        """The rows of one statement."""
        return self.query(sql)[1]


def lake_from_env() -> Lake:
    """The lake from the unit's environment: HNX_ENDPOINT_LAKE_QUERY (and, because the platform's
    client factory builds both lake clients, HNX_ENDPOINT_LAKE_CATALOG, which this script never
    calls), HNX_SECRET_HONEYPOT_LAKE_LOGIN, HNX_HP_LAKE_USER and optionally HNX_HP_LAKE_CA_FILE.
    The endpoint override outranks the resolver's domain, which is only its fallback."""
    from homelabnext.conform.adapters.lake import make_clients

    engine, _catalog_client = make_clients(
        domain=_env("HNX_HP_DOMAIN", "unused"),
        warehouse="unused",
        user=_env("HNX_HP_LAKE_USER"),
        credential="secret:honeypot/lake-login",
        ca_file=_env("HNX_HP_LAKE_CA_FILE") or None,
    )
    return Lake(engine)


def check_schema(rows) -> str:
    """'' when the DESCRIBE rows are exactly the contract, else what differs."""
    got = [(r[0], str(r[1]).lower()) for r in rows]  # (column, type); the rest are extras
    if not got:
        return "no columns (the table does not exist)"
    if got == COLUMNS:
        return ""
    want, have = dict(COLUMNS), dict(got)
    parts = [
        f"missing {sorted(set(want) - set(have))}" if set(want) - set(have) else "",
        f"unexpected {sorted(set(have) - set(want))}" if set(have) - set(want) else "",
        f"changed type {sorted(k for k in want if k in have and want[k] != have[k])}"
        if any(want[k] != have[k] for k in want if k in have)
        else "",
        "column order differs" if set(want) == set(have) and got != COLUMNS else "",
    ]
    return "; ".join(p for p in parts if p)


# ----------------------------------------------------------------------------- SQL literals


def lit(v) -> str:
    """One SQL literal. Strings are quoted with '' (no other escape exists in the dialect), NUL is
    replaced, lone surrogates (valid in a JSON \\ud800 escape) cannot be encoded and are replaced."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        raise TypeError("no boolean column")
    if isinstance(v, int):
        return str(v)
    if isinstance(v, datetime):
        return "TIMESTAMP '" + v.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f") + " UTC'"
    s = str(v).replace("\x00", "\ufffd").encode("utf-8", "replace").decode("utf-8")
    return "'" + s.replace("'", "''") + "'"


def tuple_sql(row: dict) -> str:
    return "(" + ",".join(lit(row[c]) for c, _t in COLUMNS) + ")"


def statements(rows, table, max_chars=MAX_STATEMENT_CHARS):
    """INSERT statements covering the rows, each at most max_chars (a single oversize row still
    goes alone). Yields (statement, rows_in_it)."""
    head = f"INSERT INTO {table} VALUES "
    parts, size = [], len(head)
    for row in rows:
        t = tuple_sql(row)
        if parts and size + len(t) + 1 > max_chars:
            yield head + ",".join(parts), len(parts)
            parts, size = [], len(head)
        parts.append(t)
        size += len(t) + 1
    if parts:
        yield head + ",".join(parts), len(parts)


# ----------------------------------------------------------------------------- event mapping


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _ts(raw):
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(raw, fmt).astimezone(UTC)
        except (ValueError, TypeError):
            pass
    return None


def to_row(outer: dict, ingested_at: datetime) -> dict:
    # Vector's file source wraps the raw EVE line in .message; parse it if present so the
    # Suricata fields are addressable. WP docker_logs / anything else falls back to the outer dict.
    eve = outer
    msg = outer.get("message")
    if isinstance(msg, str) and msg.lstrip().startswith("{"):
        try:
            eve = json.loads(msg)
        except json.JSONDecodeError:
            eve = outer
    alert = eve.get("alert") or {}
    http = eve.get("http") or {}
    dns = eve.get("dns") or {}
    # LLM-shell decoy events: SSH/TCP land as {"event": {DateTime,RemoteAddr,SourceIp,User,
    # Password,Command,Protocol,...}} -- capitalised fields NESTED under .event; HTTP-ish are flatter.
    # UNWRAP the nested .event so SSH creds/commands/time are not dropped (they would all read
    # NULL and land as event_type='event').
    bz = eve.get("event") if isinstance(eve.get("event"), dict) else {}
    bz_ip = (
        str(
            eve.get("SourceIp")
            or eve.get("RemoteAddr")
            or bz.get("SourceIp")
            or bz.get("RemoteAddr")
            or ""
        ).rsplit(":", 1)[0]
        or None
    )
    protocol = str(eve.get("Protocol") or bz.get("Protocol") or "").lower()
    # The interactive SSH decoy names its event kind `eventid` (cowrie.login.success,
    # cowrie.command.input, cowrie.session.file_upload) and has neither `event_type` nor `Protocol`;
    # `input` is its executed-command field, the most valuable thing it produces. Purely additive:
    # no other source emits `eventid` or `input`.
    cowrie_id = eve.get("eventid")
    # The LLM-shell decoy's SSH events get their own `beelzebub.*` event types, parallel to the other
    # decoy's `cowrie.*`: without them they fall through to the generic protocol branch and land as
    # event_type='ssh', indistinguishable from the network sensor's own SSH protocol events.
    bz_msg = bz.get("Msg") if bz else None
    bz_event_type = (
        "beelzebub.command"
        if bz_msg == "SSH Raw Command"
        else "beelzebub.login"
        if bz_msg == "New SSH Login Attempt"
        else "beelzebub.event"
        if bz
        else None
    )
    et = (
        eve.get("event_type")
        or cowrie_id
        or bz_event_type
        or (protocol or None)
        or ("wp_access" if "message" in outer and eve is outer else "event")
    )
    dest_port = _int(eve.get("dest_port"))
    if dest_port is None and cowrie_id:
        # the interactive decoy binds :22 itself and emits no dest_port.
        dest_port = 22
    elif dest_port is None and protocol == "ssh":
        # the LLM-shell decoy's SSH persona listens on :2222 (the other decoy owns :22)
        dest_port = 2222
    return {
        "event_time": _ts(eve.get("timestamp") or bz.get("DateTime") or outer.get("timestamp")),
        "ingested_at": ingested_at,
        "source": outer.get("source") or "honeypot",
        "honeypot_host": outer.get("honeypot_host"),
        "peer_ip": outer.get("peer_ip"),
        "event_type": et,
        "src_ip": eve.get("src_ip") or bz_ip,
        "dest_ip": eve.get("dest_ip"),
        "src_port": _int(eve.get("src_port")),
        "dest_port": dest_port,
        "proto": eve.get("proto") or (protocol or None),
        "alert_signature": alert.get("signature"),
        "alert_category": alert.get("category"),
        "alert_severity": _int(alert.get("severity")),
        "http_hostname": http.get("hostname"),
        "http_url": http.get("url") or eve.get("RequestURI") or bz.get("RequestURI"),
        "http_method": http.get("http_method") or eve.get("HTTPMethod") or bz.get("HTTPMethod"),
        "http_status": _int(http.get("status")),
        "http_user_agent": http.get("http_user_agent"),
        "dns_query": dns.get("rrname"),
        "raw": json.dumps(eve)[:8000],
        "http_content_type": http.get("content_type"),
        # `input` is Cowrie's executed-command field (eventid=cowrie.command.input).
        "payload": (
            eve.get("payload")
            or eve.get("Command")
            or eve.get("Body")
            or eve.get("input")
            or bz.get("Command")
            or bz.get("Body")
        ),
        "payload_len": _int(eve.get("payload_len")),
        "cred_username": eve.get("username") or eve.get("User") or bz.get("User"),
        "cred_password": eve.get("password") or eve.get("Password") or bz.get("Password"),
    }


# ----------------------------------------------------------------------------- state


OFFSET_WIDTH = 20


def load_offset(state: Path) -> int:
    """The saved byte offset, or 0 (no file, or anything that is not exactly the saved form)."""
    try:
        text = state.read_text()
    except OSError:
        return 0
    return int(text) if re.fullmatch(rf"[0-9]{{{OFFSET_WIDTH}}}\n?", text) else 0


def save_offset(state: Path, offset: int) -> None:
    """Save the offset as one fixed-width record written in place with a single write: it is never
    seen half-written (a torn offset would read as 0 and land the whole spool a second time)."""
    state.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(state, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        os.pwrite(fd, f"{offset:0{OFFSET_WIDTH}d}\n".encode(), 0)
    finally:
        os.close(fd)


def save_run(path: Path, doc: dict) -> None:
    """The last-run record the health hook reads (a torn one reads as not ok until the next run)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))


def now() -> datetime:
    return datetime.now(UTC)


def read_batches(spool: Path, offset: int, ingested_at: datetime, batch_rows: int):
    """Yield (rows, end_offset, skipped) over the spool from offset. Binary mode with a
    per-line decode (errors="replace"): a spliced line must never kill the run, which would leave the
    offset stuck on the same byte forever. Only whole lines (ending in a newline) are consumed."""
    rows, skipped, pos = [], 0, offset
    with spool.open("rb") as fh:
        fh.seek(offset)
        for raw_line in fh:
            if not raw_line.endswith(b"\n"):
                break  # the receiver is mid-write: leave it for the next run
            pos += len(raw_line)
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                outer = json.loads(line)
                if not isinstance(outer, dict):
                    raise ValueError("not an object")
                rows.append(to_row(outer, ingested_at))
            except ValueError:
                skipped += 1
                continue
            if len(rows) >= batch_rows:
                yield rows, pos, skipped
                rows, skipped = [], 0
    yield rows, pos, skipped


def land(
    lake,
    spool: Path,
    state_dir: Path,
    table: str,
    batch_rows: int = 5000,
    max_chars: int = MAX_STATEMENT_CHARS,
) -> dict:
    result = {"at": now().isoformat(), "landed": 0, "skipped": 0, "ok": False}
    state_file = state_dir / "lake-offset"
    if not spool.exists():
        print("no honeypot spool yet")
        result["ok"] = True
        return result
    size = spool.stat().st_size
    offset = load_offset(state_file)
    if offset > size:  # rotated or truncated
        offset = 0
    if offset == size:
        print("no new honeypot events")
        result["ok"] = True
        return result
    problem = check_schema(lake.run(f"DESCRIBE {table}"))
    if problem:
        raise SystemExit(f"refused: {table} is not the honeypot events contract: {problem}")
    ingested_at = now()
    total = skipped_total = 0
    for rows, end, skipped in read_batches(spool, offset, ingested_at, batch_rows):
        skipped_total += skipped
        for sql, n in statements(rows, table, max_chars):
            lake.run(sql)
            total += n
        save_offset(state_file, end)
        result["landed"], result["skipped"] = total, skipped_total
    print(f"landed {total} honeypot event(s) -> {table}")
    if skipped_total:
        print(f"skipped {skipped_total} malformed line(s) (landed {total})", file=sys.stderr)
        if total == 0:
            result["ok"] = False
            save_run(state_dir / "last-run.json", result)
            sys.exit(1)  # every line failed: a total failure must not read as a normal run
    result["ok"] = True
    return result


def freshness(lake, table: str, max_age_hours: float) -> dict:
    rows = lake.run(f"SELECT max(event_time) AS newest, count(*) AS n FROM {table}")
    newest, count = rows[0] if rows else (None, 0)
    if not newest or not count:
        return {
            "ok": False,
            "reason": "the table is empty (a freshness check never passes on no data)",
            "rows": count,
        }
    ts = newest
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace(" UTC", "+00:00").replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    age_h = (now() - ts).total_seconds() / 3600
    return {
        "ok": age_h <= max_age_hours,
        "newest": ts.isoformat(),
        "age_hours": round(age_h, 2),
        "max_age_hours": max_age_hours,
        "reason": "" if age_h <= max_age_hours else f"newest event is {age_h:.1f} h old",
    }


def ensure_table(lake, table: str) -> None:
    schema = table.rsplit(".", 1)[0]
    lake.run(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    cols = ", ".join(f"{c} {t}" for c, t in COLUMNS)
    lake.run(f"CREATE TABLE IF NOT EXISTS {table} ({cols}) WITH ({CREATE_WITH})")


def main(argv) -> int:
    if len(argv) < 2 or argv[1] not in ("land", "freshness", "ensure-table", "schema-check"):
        print(
            "usage: hnx_honeypot_lake.py land | freshness MAX_AGE_HOURS | ensure-table | schema-check",
            file=sys.stderr,
        )
        return 2
    table = _table()
    try:
        lake = lake_from_env()
        if argv[1] == "ensure-table":
            ensure_table(lake, table)
            print(f"ensured {table}")
        elif argv[1] == "schema-check":
            problem = check_schema(lake.run(f"DESCRIBE {table}"))
            print(json.dumps({"ok": not problem, "table": table, "problem": problem}))
            return 0 if not problem else 2
        elif argv[1] == "freshness":
            verdict = freshness(lake, table, float(argv[2]))
            print(json.dumps(verdict))
            return 0 if verdict["ok"] else 1
        else:
            state_dir = _state_dir()
            result = land(
                lake,
                Path(_env("HNX_HP_SPOOL")),
                state_dir,
                table,
                int(_env("HNX_HP_BATCH_ROWS", "5000")),
            )
            save_run(state_dir / "last-run.json", result)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 2
        return int(exc.code or 0)
    except (OSError, LakeError, ValueError) as exc:
        print(f"honeypot-lake: FAILED: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
