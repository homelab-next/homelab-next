#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: intel-ingest
#   kind: job
#   purpose: Pull the threat-intel platform's actionable indicators per type and write them as graph nodes, resuming from an atomically saved per-page checkpoint.
#   owner: operator
#   trigger: [timer:intel_ingest/intel-ingest, role:intel_ingest]
#   inputs: the platform's attribute search and the graph store's query API over HTTPS (credentials and URLs from the environment), the state file
#   outputs: graph nodes, the state file, and journal lines
#   installs_to: /usr/local/libexec/homelabnext/hnx-intel-ingest
#   exit:
#     "0": walked every type to the end
#     "1": a type failed (its checkpoint is saved; the next run resumes)
#     "2": paused at the wall-clock cap or on a signal (progress, not failure)
"""Pulls actionable MISP indicators (attributes with to_ids=1) and ingests
them into Synapse Cortex (the graph store of the module's site) as real Storm graph nodes, tagged #rep.misp -- the first leg
of making Cortex an actual CTI system of record instead of an empty graph.
A second leg (Wazuh alerts, via Trino/Iceberg) is tracked separately -- see
generate_topology.py's DATAFLOWS.

Run by the intel-ingest module's daily timer (modules/intel-ingest). Incremental via a per-type
"highest attribute id already ingested" state file (STATE_FILE) -- NOT a
`last:Xh` time-window filter. Confirmed live (2026-07-18) that several
feeds (fixed_event + delta_merge:false, e.g. Blocklist.de/URLhaus/
firehol_level1) re-touch every one of their attributes' `timestamp` on
MISP's own daily feed refetch even when the value hasn't changed at all --
a `last`-based filter would therefore re-match the ENTIRE historical feed
set every single day forever (confirmed: unpaginated single-type pulls for
"url"/"md5"/"sha256" alone returned 100-300MB each and OOM-killed this
script before pagination was added; even paginated, a `last`-based version
of this script took ~40+ minutes on its very first run and would keep
paying that cost daily). MISP's attribute `id` is a genuine immutable
auto-increment primary key, so instead: page through each type sorted
`id desc` and stop as soon as an id <= the last-seen state value is hit --
only genuinely NEW attribute rows ever get fetched on subsequent runs.

RESUMABILITY + CPU CAP + WATERMARK (LL-504, 2026-10-15). The id-desc +
hit_known_territory shape above is correct for warm steady-state (next-day
runs do one page per type and stop). It is NOT cheap when state.json has
no entry for a type -- a cold walk pages id-desc through the entire table,
and MISP's restSearch translates `page=N, limit=1000` to a MariaDB
`LIMIT 1000 OFFSET N*1000`, which rescans N*1000 rows per page. For the
'domain' type (315k rows) that regresses to O(N^2) scan work and pins the
MISP MariaDB container at 100% of a core for hours. The fix is three-layer
and all three are needed:
  (1) Minimal-payload restSearch body: MISP_LEAN_PARAMS below drops the
      AttributeTag + Event JOIN and other per-row context nested fetches
      wherever restSearch lets us, so each returned page costs the DB less.
  (2) Per-page intra-type checkpoint + atomic state write. A SIGTERM, DB
      restart, or deadline mid-walk now saves `in_progress.page` /
      `in_progress.newest_id` after each page's successful Cortex ingest,
      and the next invocation resumes at the saved page instead of
      re-paging from 1.
  (3) A per-run wall-clock cap (INGEST_MAX_RUNTIME_SECONDS, default 7200)
      so a pathological run pauses cleanly at deadline and the next
      schedule continues -- a runaway can never pin the DB indefinitely.
Plus a hard CPU cgroup cap on misp-docker-db-1 itself in the
misp_core role (cpus=2, cpu_shares=512) so this script's worst case still
cannot starve the fleet. LL-504 records the three-layer control.

Talks to both MISP's REST API and Cortex's Storm HTTP API via stdlib only
(urllib) -- no pymisp/requests, matching this repo's other scheduled
scripts (see roles/vuln_core/files/export_openvas_findings.py), which is
also where the STATE_FILE pattern itself is borrowed from.
"""

import argparse
import json
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

# MISP attribute type -> Synapse node form. Anything not in this map is
# skipped -- deliberately conservative, only types with an obvious 1:1
# Synapse core-model form.
TYPE_MAP = {
    "ip-src": "inet:ipv4",
    "ip-dst": "inet:ipv4",
    "domain": "inet:fqdn",
    "hostname": "inet:fqdn",
    "url": "inet:url",
    "md5": "hash:md5",
    "sha1": "hash:sha1",
    "sha256": "hash:sha256",
    "email-src": "inet:email",
    "email-dst": "inet:email",
}

STATE_FILE = Path(
    os.environ.get("INGEST_STATE_FILE", "/var/lib/hnx-modules/intel-ingest/state/state.json")
)
PAGE_SIZE = 1000  # bounds how much verbose per-attribute JSON (nested Event/Tag/Object data) is ever held in memory at once

# Chained `[...]` edit statements per Storm ingest call. Confirmed live
# (2026-07-18) Cortex's own "Maximum Storm pipeline depth exceeded" ceiling
# sits somewhere between 300 (succeeded outright) and 500 (RecursionLimitHit)
# -- 250 keeps a real margin below the confirmed-working point. REDUCED to
# 100 on 2026-10-15 (LL-504): a 250-node inet:ipv4 batch reproducibly hit the
# per-call 180s HardTimeout under contention with Cortex's own background
# work, even though the same query ran in ~5-28s standalone. 100 both widens
# the margin below the recursion ceiling and divides each page's Cortex wait
# into shorter checkpointable chunks, so a slow Cortex pauses the walk at a
# page-boundary within one HardTimeout window.
BATCH_SIZE = 100

# Retry policy for the HTTP calls below. 5xx and connection/timeout errors
# are retried with exponential backoff (10s, 30s, 90s), everything else
# fails fast so a 4xx (bad authkey, malformed body) does not get retried
# into an outage. The retry budget deliberately fits inside the per-call
# `hard_timeout` ceiling + a tolerable overall slowdown for a flaky link.
MAX_RETRIES = 3
RETRY_BACKOFF_BASE_S = 10

# Per-run wall-clock cap. Checked between pages and between types; the
# current page is always allowed to finish so the resume checkpoint lines
# up with a real page boundary. 2h matches the OnCalendar=*:0/N granularity
# the timer could land on -- a run that cannot finish in 2h is a resync in
# progress, not a steady-state tick, and should pause for the next schedule
# rather than keep the DB pinned.
DEFAULT_MAX_RUNTIME_S = 7200

# MISP restSearch body knobs that drop joins and extra per-row context
# fetches whenever MISP lets us. Each one measurably reduces the "Sending
# data" wait per page (confirmed live on 2026-10-15 against the live MISP:
# the 'domain' page time with these flags set drops from ~34s to <5s). We
# only need (type, value, id) -- no Event info, no AttributeTag, no
# correlations, no decay scoring, no sightings, no analyst metadata, no
# attachments. Set every known switch explicitly so a future MISP default
# flip (any of these turning ON upstream) does not silently re-break this.
MISP_LEAN_PARAMS = {
    "includeContext": 0,
    "includeEventUuid": 0,
    "metadata": 0,
    "enforceWarninglist": 0,
    "includeCorrelations": 0,
    "includeSightingdb": 0,
    "includeFullModel": 0,
    "includeDecayScore": 0,
    "excludeDecayed": 0,
    "includeAnalystData": 0,
    "withAttachments": 0,
    "includeTag": 0,
}

# TLS to the two services: ordinary verification, hostname checking on, against INGEST_CA_FILE (a
# bundle of the certificates to trust: the lab CA for the platform, and for the graph store either
# the CA that signed its certificate or, when it keeps its own self-signed one, that exact
# certificate). No pin, no unverified fallback: without a CA file the call is refused. The URL's
# host must be a name the certificate carries.
_PINNED_CTX_CACHE: dict[tuple[str, int], ssl.SSLContext] = {}


def _pinned_ctx_for(url: str, timeout: int = 10) -> ssl.SSLContext:
    parsed = urlparse(url)
    cache_key = (parsed.hostname, parsed.port or 443)
    if cache_key in _PINNED_CTX_CACHE:
        return _PINNED_CTX_CACHE[cache_key]
    ca_file = os.environ.get("INGEST_CA_FILE", "")
    if not ca_file:
        raise RuntimeError(
            f"no CA file (INGEST_CA_FILE) for {parsed.hostname!r} -- refusing to connect without verifying"
        )
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    _PINNED_CTX_CACHE[cache_key] = ctx
    return ctx


class HardTimeout(Exception):
    pass


@contextmanager
def hard_timeout(seconds: int, what: str):
    """A wall-clock deadline that fires regardless of WHY a call is stuck.

    WHY THIS EXISTS (2026-08-06, 2nd wedge in one day). Both HTTP calls below already
    pass urlopen(timeout=120) -- but that is a PER-READ socket timeout, not a call
    duration cap: a stream that keeps delivering bytes (even one byte every 100s) or a
    hang that never reaches the socket layer at all (DNS resolution, a half-closed
    connection urllib doesn't recognize as dead) never trips it. The second wedge this
    day showed zero open TCP sockets when checked -- inconsistent with "blocked inside
    a live read", which is exactly the class this per-read timeout cannot catch.
    signal.alarm() fires on the wall clock alone, independent of what the process is
    doing, so it is the backstop underneath the socket-level timeout rather than a
    replacement for it.
    """

    def _on_alarm(signum, frame):
        raise HardTimeout(f"{what} exceeded hard wall-clock timeout of {seconds}s")

    previous = signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


# ---------------------------------------------------------------------------
# Graceful-exit + deadline tracking. SIGTERM/SIGINT request shutdown; the
# main loop checks `shutdown_requested()` between pages and types and bails
# cleanly with state saved. This replaces the previous behaviour where a
# `systemctl stop` or a DB-restart-driven kill dropped the whole run.
# ---------------------------------------------------------------------------
_deadline_t: float | None = None
_exit_requested = False


def _request_graceful_exit(signum, frame):
    global _exit_requested
    _exit_requested = True


def shutdown_requested() -> bool:
    """True if either the wall-clock cap or a termination signal says to stop."""
    return _exit_requested or (_deadline_t is not None and time.monotonic() >= _deadline_t)


# ---------------------------------------------------------------------------
# State I/O. The schema is nested per-type to carry the in-progress cursor;
# a legacy flat `{"<type>": <int watermark>}` state file (written by the
# pre-LL-504 script) is migrated transparently in `_normalise_state`.
# Writes are atomic (tmp + rename) so a kill mid-write cannot corrupt the
# file -- the state is now written O(pages) times per run, not O(types),
# so the previous `write_text` approach was no longer safe.
# ---------------------------------------------------------------------------
def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except json.JSONDecodeError:
        corrupt = STATE_FILE.with_suffix(".json.corrupt")
        STATE_FILE.rename(corrupt)
        print(f"[!] state file was corrupt, moved to {corrupt}; starting fresh", file=sys.stderr)
        return {}


def save_state(state: dict) -> None:
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(STATE_FILE)


def _normalise_state(state: dict) -> dict:
    """Accept both legacy (`{type: int}`) and new (`{type: {watermark_id, in_progress}}`) shapes
    and return the new shape. Pure function, no I/O, so main() and the tests share it."""
    out: dict = {}
    for t, v in state.items():
        if isinstance(v, int):
            out[t] = {"watermark_id": v, "in_progress": None}
        elif isinstance(v, dict):
            out[t] = {
                "watermark_id": int(v.get("watermark_id") or 0),
                "in_progress": v.get("in_progress") or None,
            }
        else:
            # Unknown shape -- drop rather than crash; worst case is a cold walk for this type.
            out[t] = {"watermark_id": 0, "in_progress": None}
    return out


# ---------------------------------------------------------------------------
# HTTP helpers with retry/backoff for transient 5xx + timeout classes.
# A 4xx fails fast -- a bad authkey or malformed body is not a transient.
# ---------------------------------------------------------------------------
def _request_with_retry(fn, *, what: str):
    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            return fn()
        except urllib.error.HTTPError as e:
            if 500 <= e.code < 600 and attempt < MAX_RETRIES:
                last_err = e
                delay = RETRY_BACKOFF_BASE_S * (3**attempt)
                print(
                    f"[.] {what} -> HTTP {e.code}; retry {attempt + 1}/{MAX_RETRIES} in {delay}s",
                    file=sys.stderr,
                )
                time.sleep(delay)
                continue
            raise
        except (urllib.error.URLError, HardTimeout, TimeoutError) as e:
            last_err = e
            if attempt == MAX_RETRIES:
                raise
            delay = RETRY_BACKOFF_BASE_S * (3**attempt)
            print(
                f"[.] {what} failed ({e!r}); retry {attempt + 1}/{MAX_RETRIES} in {delay}s",
                file=sys.stderr,
            )
            time.sleep(delay)
    # Unreachable in practice: either return or raise above.
    raise last_err if last_err else RuntimeError(f"{what}: retry loop ended abnormally")


def http_json(url: str, headers: dict, body: dict) -> dict:
    def _one():
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with (
                hard_timeout(180, f"POST {url}"),
                urllib.request.urlopen(req, context=_pinned_ctx_for(url), timeout=120) as resp,
            ):
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            # 5xx is retryable; 4xx is a hard error -- surface the body for diagnosis then stop.
            if 500 <= e.code < 600:
                raise
            detail = e.read().decode(errors="replace")
            raise RuntimeError(f"POST {url} -> HTTP {e.code}: {detail[:2000]}") from None

    return _request_with_retry(_one, what=f"POST {url}")


# ---------------------------------------------------------------------------
# Fetch + Cortex ingest.
# ---------------------------------------------------------------------------
def fetch_page(misp_url: str, authkey: str, misp_type: str, page: int) -> list:
    """Fetch ONE page of ONE type with the lean body. Returns the raw Attribute list
    (empty when the page is past the end). restSearch per-type (not list of types) because
    MISP's own controller 500s whenever `url` + any hash type share one `type` filter
    array (confirmed live) -- isolated per type is the sidestep."""
    headers = {
        "Authorization": authkey,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    body = dict(MISP_LEAN_PARAMS)
    body.update(
        {
            "returnFormat": "json",
            "to_ids": 1,
            "type": misp_type,
            "limit": PAGE_SIZE,
            "page": page,
            "sort": "id",
            "direction": "desc",
        }
    )
    data = http_json(f"{misp_url}/attributes/restSearch", headers, body)
    return data.get("response", {}).get("Attribute", [])


def storm_quote(value: str) -> str:
    # Storm's own string literal does NOT accept raw newlines; a value with an embedded \n
    # splits the chained `[...]` edit statement across lines and corrupts the whole batch,
    # so collapse any CR/LF to a space in the quoted form rather than passing it through.
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")
    return f'"{escaped}"'


def attribute_to_form(misp_type: str, value: str) -> str | None:
    """Pick the Storm form for a given MISP attribute (type, value) pair, or None to skip.

    MISP's `ip-src`/`ip-dst` columns are documented as individual addresses in theory, but
    in practice the live feeds mix in CIDR ranges (a whole block of addresses, not one), bare
    IPv6 addresses, and the occasional malformed value. Storm's `inet:ipv4` form rejects
    non-dotted-quad input, and a reject that lands inside a 100-stmt chained edit batch
    turns the WHOLE batch into a long error-emitting storm run that pins Cortex's response
    stream (LL-504, 2026-10-15: this is the exact shape that made 100-node batches hit the
    180s HardTimeout even though an idle Cortex benchmarks at <1s/100-nodes). So:
      - value contains ':' AND form is inet:ipv4 -> route to inet:ipv6
      - value contains '/' AND form is inet:ipv4 -> route to inet:cidr4 / inet:cidr6
      - otherwise return the mapped form unchanged
    """
    form = TYPE_MAP[misp_type]
    if form == "inet:ipv4":
        if "/" in value:
            return "inet:cidr6" if ":" in value else "inet:cidr4"
        if ":" in value:
            return "inet:ipv6"
    return form


def attribute_to_storm_line(misp_type: str, value: str) -> str | None:
    form = attribute_to_form(misp_type, value)
    if form is None:
        return None
    return f"[{form}={storm_quote(value)} +#rep.misp]"


# Kept for test backward compatibility.
def ipv4_or_ipv6(value: str) -> str:
    return "inet:ipv6" if ":" in value else "inet:ipv4"


def chunked(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def cortex_storm_ingest(cortex_url: str, user: str, password: str, query: str) -> None:
    """Uses the plain streaming /api/v1/storm endpoint, NOT /api/v1/storm/call.
    Confirmed live (2026-07-18) that /storm/call combined with a trailing
    `return(...)` -- the originally-planned approach -- silently only
    creates the FIRST node in a multi-statement bulk-ingest query and then
    reports {"status":"ok"} regardless, since `return()` halts the entire
    query the first time any node reaches it rather than after all of
    them do. No trailing return() is used here at all; success is judged
    by consuming the whole jsonlines stream and confirming zero "err"
    messages appear.

    Also confirmed live: Cortex enforces a real "Maximum Storm pipeline
    depth exceeded" ceiling somewhere between 300 and 500 chained `[...]`
    edit statements in one query (300 succeeded outright, 500 hit
    RecursionLimitHit) -- see BATCH_SIZE's own comment for the margin
    kept below that. Idempotent: `[form=val +#rep.misp]` is set-semantics,
    so a re-ingest of the same (type, value) is a no-op in Cortex."""
    import base64

    basic = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/json"}

    def _one():
        req = urllib.request.Request(
            f"{cortex_url}/api/v1/storm",
            data=json.dumps({"query": query, "stream": "jsonlines"}).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with (
                hard_timeout(
                    180,
                    f"POST {cortex_url}/api/v1/storm (batch of {query.count(chr(10)) + 1} node(s))",
                ),
                urllib.request.urlopen(
                    req, context=_pinned_ctx_for(cortex_url), timeout=120
                ) as resp,
            ):
                for line in resp:
                    line = line.strip()
                    if not line:
                        continue
                    msg = json.loads(line)
                    if msg[0] == "err":
                        raise RuntimeError(f"Cortex storm ingest failed: {msg[1]}")
        except urllib.error.HTTPError as e:
            if 500 <= e.code < 600:
                raise
            detail = e.read().decode(errors="replace")
            raise RuntimeError(
                f"POST {cortex_url}/api/v1/storm -> HTTP {e.code}: {detail[:2000]}"
            ) from None

    _request_with_retry(_one, what=f"POST {cortex_url}/api/v1/storm")


# ---------------------------------------------------------------------------
# Per-type walk with intra-type checkpointing. Returns (ingested_count, complete)
# where `complete` is False iff we bailed early (deadline or signal).
# ---------------------------------------------------------------------------
def walk_type(
    misp_url: str,
    misp_authkey: str,
    misp_type: str,
    cortex_url: str,
    cortex_user: str,
    cortex_password: str,
    state: dict,
    *,
    fetch_page_fn=fetch_page,
    cortex_ingest_fn=cortex_storm_ingest,
    save_state_fn=save_state,
) -> tuple[int, bool]:
    """Walk one type id-desc, ingesting each page to Cortex immediately and checkpointing
    after each successful page ingest. On restart, resume from the saved in_progress page.
    Watermark advances only when the walk reaches known territory (end of fetch).

    The injected `fetch_page_fn` / `cortex_ingest_fn` / `save_state_fn` arguments are the
    seam the tests substitute to drive this against a fake MISP + a fake Cortex + an
    in-memory state dict, without touching the network or the real STATE_FILE path.
    """
    entry = state.get(misp_type) or {"watermark_id": 0, "in_progress": None}
    watermark_id = int(entry.get("watermark_id") or 0)
    in_progress = entry.get("in_progress") or {}
    page = int(in_progress.get("page") or 1)
    newest_id_seen = int(in_progress.get("newest_id") or watermark_id)
    total_this_type = 0

    if page > 1:
        print(
            f"[+] {misp_type}: resuming at page {page} (watermark={watermark_id}, "
            f"in_progress.newest_id={newest_id_seen})",
            file=sys.stderr,
        )

    while True:
        if shutdown_requested():
            state[misp_type] = {
                "watermark_id": watermark_id,
                "in_progress": {"page": page, "newest_id": newest_id_seen},
            }
            save_state_fn(state)
            why = "deadline" if (_deadline_t and time.monotonic() >= _deadline_t) else "signal"
            print(
                f"[!] {misp_type}: paused on page {page} due to {why}; state saved for resume",
                file=sys.stderr,
            )
            return total_this_type, False

        batch = fetch_page_fn(misp_url, misp_authkey, misp_type, page)
        if not batch:
            break

        pairs: list[tuple[str, str]] = []
        hit_known_territory = False
        for attr in batch:
            attr_id = int(attr["id"])
            if attr_id <= watermark_id:
                hit_known_territory = True
                break
            if attr.get("value"):
                pairs.append((misp_type, attr["value"]))
            newest_id_seen = max(newest_id_seen, attr_id)

        if pairs:
            batches = list(chunked(pairs, BATCH_SIZE))
            n_batches = len(batches)
            for i, b in enumerate(batches, 1):
                lines = [attribute_to_storm_line(t, v) for t, v in b]
                lines = [ln for ln in lines if ln is not None]
                if not lines:
                    continue
                query = "\n".join(lines)
                cortex_ingest_fn(cortex_url, cortex_user, cortex_password, query)
                print(
                    f"[.] {misp_type}: page {page}, batch {i}/{n_batches} ingested ({len(lines)}/{len(b)} rows this batch, {len(pairs)} total this page)",
                    file=sys.stderr,
                )
            total_this_type += len(pairs)

        # Intra-type checkpoint: next invocation resumes at page+1 if we die here.
        state[misp_type] = {
            "watermark_id": watermark_id,
            "in_progress": {"page": page + 1, "newest_id": newest_id_seen},
        }
        save_state_fn(state)

        if hit_known_territory or len(batch) < PAGE_SIZE:
            break
        page += 1

    # Walk complete for this type: advance watermark, clear in_progress.
    state[misp_type] = {
        "watermark_id": max(watermark_id, newest_id_seen),
        "in_progress": None,
    }
    save_state_fn(state)
    return total_this_type, True


# ---------------------------------------------------------------------------
# Entrypoint.
# ---------------------------------------------------------------------------
def main(argv: list | None = None) -> int:
    global _deadline_t
    parser = argparse.ArgumentParser(description="MISP -> Synapse Cortex indicator ingest")
    parser.add_argument(
        "--full-resync",
        action="store_true",
        help="Discard existing state.json and walk every type from id=0. Default is incremental.",
    )
    args = parser.parse_args(argv)

    misp_url = os.environ["INGEST_SOURCE_URL"]
    misp_authkey = os.environ["INGEST_SOURCE_KEY"]
    cortex_url = os.environ["INGEST_GRAPH_URL"]
    cortex_user = os.environ["INGEST_GRAPH_USER"]
    cortex_password = os.environ["INGEST_GRAPH_PASSWORD"]

    max_runtime = int(os.environ.get("INGEST_MAX_RUNTIME_SECONDS", DEFAULT_MAX_RUNTIME_S))
    _deadline_t = time.monotonic() + max_runtime

    signal.signal(signal.SIGTERM, _request_graceful_exit)
    signal.signal(signal.SIGINT, _request_graceful_exit)

    if args.full_resync:
        print("[!] --full-resync: discarding existing state", file=sys.stderr)
        if STATE_FILE.exists():
            STATE_FILE.unlink()

    state = _normalise_state(load_state())
    total = 0
    failed_type = None
    bailed_early = False
    t_start = time.monotonic()

    for misp_type in TYPE_MAP:
        if shutdown_requested():
            bailed_early = True
            break
        try:
            n, complete = walk_type(
                misp_url,
                misp_authkey,
                misp_type,
                cortex_url,
                cortex_user,
                cortex_password,
                state,
            )
            total += n
            if n:
                print(
                    f"[+] {misp_type}: ingested {n} node(s), watermark -> {state[misp_type]['watermark_id']}"
                )
            if not complete:
                bailed_early = True
                break
        except Exception as e:
            # Keep going on remaining types -- same blast-radius discipline as LL-059.
            print(f"[!] {misp_type}: {e}", file=sys.stderr)
            failed_type = failed_type or misp_type
            continue

    duration = time.monotonic() - t_start
    if bailed_early:
        print(
            f"[+] ingested {total} new node(s) in {duration:.1f}s; paused for next invocation (deadline or signal)"
        )
        return 2
    if failed_type:
        raise RuntimeError(
            f"ingested {total} node(s) in {duration:.1f}s; at least one type failed (first: {failed_type}). "
            "Per-page checkpoints were saved, so the next run resumes rather than restarting."
        )
    print(f"[+] ingested {total} new node(s) into Cortex in {duration:.1f}s")
    return 0


if __name__ == "__main__":
    try:
        rc = main()
        sys.exit(rc)
    except Exception as e:
        print(f"misp-cortex-ingest failed: {e}", file=sys.stderr)
        sys.exit(1)
