#!/opt/hnx/current/bin/python
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: honeypot-report
#   kind: job
#   purpose: Render the daily honeypot intel report from the lake's honeypot events (enriched attacker IPs, high-value commands and samples, an LLM analyst brief) as one self-contained HTML file.
#   owner: platform
#   trigger: [timer:honeypot/report, role:honeypot]
#   inputs: environment HNX_HP_*, HNX_ENDPOINT_LAKE_QUERY and the lake login in HNX_SECRET_HONEYPOT_LAKE_LOGIN (honeypot.env and the credentials env file), the gateway key in $CREDENTIALS_DIRECTORY; runs under the hnx runtime release python
#   outputs: <reports dir>/honeypot-report.html and a dated copy; one summary line on stdout
#   installs_to: /usr/local/libexec/homelabnext/hnx-honeypot-report
#   exit:
#     "0": the report was written (the brief may say the model tier did not answer; the data below it is complete)
#     "1": the lake could not be queried or the report could not be written
"""Daily honeypot intel report. Queries the honeypot events table for the last 24h, enriches every
attacker IP (geo/ASN, a scanner-vs-malicious classification, Tor exit), has the model tier analyse
the payloads, optionally cross-references a threat-intelligence table, and renders a styled HTML
report. Standard library only. Every site value (the lake, the gateway, the model, the output
directory, the friendly addresses) comes from the environment the role writes."""

import contextlib
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, datetime


def _env(name, default=""):
    return os.environ.get(name, default)


def _cred(name):
    """A secret the unit loaded as a systemd credential (or a file the environment names)."""
    path = _env("HNX_HP_" + name.upper().replace("-", "_") + "_FILE")
    if not path:
        d = _env("CREDENTIALS_DIRECTORY")
        path = os.path.join(d, name) if d else ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


LAKE_CATALOG = _env("HNX_HP_LAKE_CATALOG")
LAKE_SCHEMA = _env("HNX_HP_LAKE_SCHEMA", "honeypot")
EVENTS = f"{LAKE_CATALOG}.{LAKE_SCHEMA}.{_env('HNX_HP_LAKE_TABLE', 'events')}"
# optional: a threat-intel table (catalog.schema.table with an `iocs` array column) to cross-reference
CTI_TABLE = _env("HNX_HP_CTI_TABLE")
# The model tier: any OpenAI-compatible chat-completions endpoint (the lab's gateway).
LLM_URL = _env("HNX_HP_LLM_URL")
LLM_MODEL = _env("HNX_HP_LLM_MODEL")
LLM_BEARER = _cred("gateway-key")
# A REASONING model spends the token budget on thought before it writes: a small max_tokens returns
# reasoning only and an empty answer (measured: a 12-sample prompt used its whole 350 tokens
# thinking). Leave the budget generous, the timeout long (a shared model tier is often busy) and
# retry; do not try to switch the thinking off, which the serving stacks in use ignore.
LLM_MAX_TOKENS = int(_env("HNX_HP_LLM_MAX_TOKENS", "4000"))
LLM_TIMEOUT = int(_env("HNX_HP_LLM_TIMEOUT_S", "240"))
LLM_ATTEMPTS = int(_env("HNX_HP_LLM_ATTEMPTS", "3"))
LLM_RETRY_SLEEP = int(_env("HNX_HP_LLM_RETRY_SLEEP_S", "20"))
LLM_TEMPERATURE = float(_env("HNX_HP_LLM_TEMPERATURE", "0.2"))
OUT_DIR = _env("HNX_HP_REPORT_DIR", "reports")
OUT = os.path.join(OUT_DIR, "honeypot-report.html")
SITE_LABEL = _env("HNX_HP_SITE_LABEL", "decoy")
ENRICH = _env("HNX_HP_ENRICH", "1") not in ("0", "false", "no", "")
UA = {"User-Agent": "honeypot-report/1.0"}


def _get(url, timeout=15, headers=None):
    req = urllib.request.Request(url, headers=headers or UA)
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")


def _load_lake_client():
    """The lake client the lake writer ships beside this script (one client, one place that speaks
    the query service's protocol); loaded by path because the scripts run isolated."""
    import importlib.machinery
    import importlib.util

    here = os.path.dirname(os.path.abspath(__file__))
    # installed beside this script as hnx-honeypot-lake, in a checkout as hnx_honeypot_lake.py
    for name in ("hnx-honeypot-lake", "hnx_honeypot_lake.py"):
        path = os.path.join(here, name)
        if os.path.exists(path):
            break
    loader = importlib.machinery.SourceFileLoader("hnx_honeypot_lake", path)
    spec = importlib.util.spec_from_loader("hnx_honeypot_lake", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


_LAKE = None


def lake_query(sql):
    """(column names, rows) of one read statement; the certificate is always verified."""
    global _LAKE
    if _LAKE is None:
        _LAKE = _load_lake_client().lake_from_env()
    return _LAKE.query(sql)


# The AWS Instance Metadata Service. Traffic to/from it is the instance talking to its own
# control plane -- but an ATTACKER reaching it (SSRF, or hands-on-keyboard inside the honeypot)
# is a credential-theft attempt and one of the highest-value signals this sensor can produce.
# So it is excluded from the attacker rankings and surfaced SEPARATELY, never silently dropped.


def is_metadata(ip):
    """The instance-metadata service lives at a link-local address (169.254/16): link-local is the
    test, never a literal."""
    try:
        return ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return False


# The overlay network's documented default port. The honeypot host is on the overlay, and the network IDS sniffs
# the whole interface, so NAT-traversal keepalives to a rotating pool of DERP/STUN relays are
# captured as inbound "alerts". They are PUBLICLY ROUTABLE, which is why an is_global check alone
# does not remove them -- and they are voluminous enough to own the whole table.
OVERLAY_PORT = 41641

# The fleet's own egress address. Our own verification probes are not catch. Keep this list in
# sync with the analyst's attribution; a new egress IP silently becomes a "top attacker".
FRIENDLY = {ip.strip() for ip in _env("HNX_HP_FRIENDLY_IPS").split(",") if ip.strip()}


def bucket(e: dict) -> str:
    """Attribute one event. Only 'external' is attacker traffic.

    This mirrors the buckets an analyst derives in their own pass —
    deliberately, because the report and the analyst disagreeing about who the attackers are is
    worse than either being wrong alone.
    """
    ip = e.get("ip") or ""
    if not ip:
        return "noip"
    if is_metadata(ip):
        return "imds"
    if ip in FRIENDLY:
        return "friendly"
    if not is_external(ip):
        return "internal"
    port = e.get("dport")
    sig = e.get("sig") or ""
    if port == OVERLAY_PORT or "STUN Binding" in sig:
        return "overlay"
    return "external"


def is_external(ip: str) -> bool:
    """True only for a globally-routable source address.

    Use ipaddress, NEVER string prefixes. RFC1918 is 10/8, 172.16/12 and 192.168/16 -- and
    that middle range is the trap: a `172.` prefix filter also swallows 172.105.x and
    172.237.x, which are public Linode/Akamai space and were among this honeypot's REAL
    attackers (238 alerts each, observed 2026-08-02). Filtering them would have blinded the
    sensor to genuine traffic while looking like it was cleaning noise.

    `is_global` covers private, loopback, link-local (169.254/16, incl. IMDS), multicast,
    reserved, unspecified and CGNAT in one predicate, so no range has to be enumerated here.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def fetch_events():
    sql = (
        "SELECT event_type, src_ip, dest_port, alert_signature, raw, cast(event_time as varchar) t "
        f"FROM {EVENTS} "
        "WHERE event_time > current_timestamp - interval '24' hour"
    )
    cols, rows = lake_query(sql)
    i = {c: n for n, c in enumerate(cols)}
    ev, excluded = [], []
    for r in rows:
        raw = {}
        with contextlib.suppress(Exception):
            raw = json.loads(r[i["raw"]]) if r[i["raw"]] else {}
        try:
            dport = int(r[i["dest_port"]]) if r[i["dest_port"]] not in (None, "") else None
        except (ValueError, TypeError):
            dport = None
        e = {
            "type": r[i["event_type"]],
            "ip": r[i["src_ip"]],
            "t": r[i["t"]],
            "raw": raw,
            "dport": dport,
            "sig": r[i["alert_signature"]],
        }
        e["bucket"] = bucket(e)
        (ev if e["bucket"] == "external" else excluded).append(e)
    return ev, excluded


# Operator priority, 2026-08-02: "actual malware or internal commands over the mass url payload".
# A URL probe has a short shelf life -- once the network IDS has seen the pattern once and a rule exists,
# the 500th identical curl adds nothing. A captured binary or a typed command is irreducible: it is
# what the attacker DID after getting in, it cannot be signatured away, and there is usually only
# one of it. So these lead the report and the probe volume is demoted to a count.
#
# They need their OWN, LONGER window. Measured 2026-08-02: 146 http_payload events in 48h against
# 9 cowrie.command.input and 2 sample_manifest. On a 24h window the highest-value sections would
# routinely render empty and look like "nothing happened" -- which is exactly backwards.
HIGHVALUE_DAYS = 7
HIGHVALUE_TYPES = (
    "cowrie.command.input",
    "cowrie.login.success",
    "sample_manifest",
    "file_upload",
    "cowrie.session.file_upload",
)

# Wider than HIGHVALUE_DAYS: command-fingerprint clustering benefits from more history before
# "no shared hash yet" means something, and command volume is much lower than SSH KEX volume.
FINGERPRINT_DAYS = 30


def fetch_highvalue():
    """Samples, typed commands and successful logins over a 7-day window.

    Friendly/fleet-egress traffic is dropped here too: our own verification probes upload an ELF
    named CLAUDE-P2-VERIFY-*.elf and run nvidia-smi, and presenting that as captured malware would
    be a self-inflicted false positive of the worst kind -- the report crying wolf about itself.
    """
    types = ",".join("'" + t + "'" for t in HIGHVALUE_TYPES)
    sql = (
        f"SELECT event_type, src_ip, raw, cast(event_time as varchar) t "
        f"FROM {EVENTS} "
        f"WHERE event_time > current_timestamp - interval '{HIGHVALUE_DAYS}' day "
        f"AND event_type IN ({types}) ORDER BY event_time DESC LIMIT 400"
    )
    try:
        cols, rows = lake_query(sql)
    except Exception as e:
        print("highvalue:", e)
        return {"samples": [], "cmds": [], "logins": [], "friendly_skipped": 0}
    i = {c: n for n, c in enumerate(cols)}
    samples, cmds, logins, skipped = [], [], [], 0
    for r in rows:
        ip = r[i["src_ip"]] or ""
        try:
            raw = json.loads(r[i["raw"]]) if r[i["raw"]] else {}
        except Exception:
            raw = {}
        if ip in FRIENDLY:
            skipped += 1
            continue
        et, t = r[i["event_type"]], r[i["t"]]
        rec = {"ip": ip, "t": t, "raw": raw, "session": raw.get("session", "")}
        if et in ("sample_manifest", "file_upload", "cowrie.session.file_upload"):
            samples.append(rec)
        elif et == "cowrie.command.input":
            rec["input"] = raw.get("input") or raw.get("message") or ""
            cmds.append(rec)
        elif et == "cowrie.login.success":
            rec["user"] = raw.get("username", "")
            rec["pw"] = raw.get("password", "")
            logins.append(rec)
    return {"samples": samples, "cmds": cmds, "logins": logins, "friendly_skipped": skipped}


# rDNS naming schemes of legitimate internet-measurement projects. These are NOT attackers, and
# separating them is most of the day-to-day value of a PTR lookup -- some scanner
# addresses resolve to research-scanner names (binaryedge, deepfield), which would otherwise sit in the
# attacker table looking like scanning adversaries.
RESEARCH_PTR = (
    "binaryedge",
    "shodan",
    "censys",
    "deepfield",
    "shadowserver",
    "zgrab",
    "internet-measurement",
    "onyphe",
    "leakix",
    "stretchoid",
    "alphastrike",
    "projectdiscovery",
    "netsystemsresearch",
    "driftnet",
    "rwth-aachen",
    "bufferover",
)


def rdns(ips):
    """Best-effort PTR. Cheap, keyless, stdlib -- but do not over-trust it.

    Measured against a honeypot's own attackers: only 3 of 9 resolved. PTR is
    therefore WEAK as an identity pivot (most attacker infrastructure has no PTR at all), but
    STRONG as a classifier for the subset that does -- research scanners advertise themselves in
    their rDNS, and a name is also the one attribute that survives an IP change within a provider.
    For actually tracking an actor across IP swaps, use HASSH (see hassh_pivots) -- that is a
    property of the client, not of the address.
    """
    out = {}
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    try:
        for ip in ips:
            try:
                name = socket.gethostbyaddr(ip)[0]
            except Exception:
                continue
            low = name.lower()
            out[ip] = {"ptr": name, "research": next((r for r in RESEARCH_PTR if r in low), None)}
    finally:
        socket.setdefaulttimeout(old)
    return out


def hassh_pivots(days=14):
    """SSH client fingerprints seen from MORE THAN ONE address = the same tooling, new IP.

    This is the answer to "how do we know when they swap IPs". HASSH is a hash of the client's
    KEX/cipher/MAC/compression algorithm lists -- the SSH analogue of JA3 -- and Cowrie already
    emits it on every `cowrie.client.kex`, so no new collection is needed. It is a property of the
    ATTACKER'S TOOLING, so it survives changing address, ASN, and country.

    Observed on a real sensor: one hassh arriving from two unrelated addresses. Caveat worth keeping in view: a hassh shared by a very common
    stock client (e.g. plain libssh/Go) groups TOOLING, not necessarily one operator -- so treat a
    match as a lead, and corroborate with credential sets, command sequences or sample hashes.
    """
    sql = (
        f"SELECT json_extract_scalar(raw,'$.hassh') AS hassh, "
        f"cardinality(array_agg(DISTINCT src_ip)) AS n_ips, count(*) AS sessions, "
        f"array_join(array_agg(DISTINCT src_ip), ', ') AS ips, "
        f"array_join(array_agg(DISTINCT json_extract_scalar(raw,'$.version')), ', ') AS vers, "
        f"cast(max(event_time) as varchar) AS latest "
        f"FROM {EVENTS} "
        f"WHERE event_time > current_timestamp - interval '{days}' day "
        f"AND event_type = 'cowrie.client.kex' GROUP BY 1 ORDER BY 2 DESC LIMIT 40"
    )
    try:
        cols, rows = lake_query(sql)
    except Exception as e:
        print("hassh:", e)
        return []
    i = {c: n for n, c in enumerate(cols)}
    out = []
    for r in rows:
        h = r[i["hassh"]]
        if not h:
            continue
        try:
            n_ips = int(r[i["n_ips"]])
        except (TypeError, ValueError):
            n_ips = 0
        out.append(
            {
                "hassh": h,
                "n_ips": n_ips,
                "sessions": r[i["sessions"]],
                "ips": r[i["ips"]],
                "latest": r[i["latest"]],
            }
        )
    # Group significance (n_ips DESC, from the SQL) stays primary; stable-resort newest-first
    # so a truncated table subset favors the more recently active pivot among equal n_ips.
    out.sort(key=lambda h: h.get("latest") or "", reverse=True)
    out.sort(key=lambda h: -h["n_ips"])
    return out


# Operator observation, 2026-08-05, reading the raw catch: "i am looking at these honeypot
# commands and a bunch are identical.. either it is same person or it is same bot using same
# command and it looks like something we can hash and group by for some form of identification
# and pivoting in the future." Byte-identical command strings are not how humans type -- they
# are how a SCRIPT runs, so the repetition fingerprints the TOOLKIT, which is far more durable
# than the IP that delivered it (IPs rotate hourly; a hardcoded command sequence survives
# across campaigns, hosting providers and months).
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 5+ digit runs -- random dir/nonce names observed on this sensor are 19 digits
# (`./.6620093613290270919/sshd`); small literals like `head -c 250` are deliberately left
# alone, since they are part of the command's actual behaviour, not per-session noise.
_NUM_RE = re.compile(r"\d{5,}")


def normalize_command(cmd: str) -> str:
    """Strip the volatile parts BEFORE hashing, or every session hashes uniquely and the
    clustering silently yields nothing -- a normaliser bug looks exactly like "no pattern".
    Order matters: IPs first (else the digit-run regex would half-eat them), then long
    digit runs, then whitespace/case folding last so the regexes above see the original text.
    """
    if not cmd:
        return ""
    c = _IP_RE.sub("<IP>", cmd)
    c = _NUM_RE.sub("<NUM>", c)
    return re.sub(r"\s+", " ", c).strip().lower()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def command_fingerprints(days=FINGERPRINT_DAYS):
    """Two hashes, because they answer different questions (see the kanban card this closes).

    (1) sha256(normalised single command) -- groups reuse of one command across otherwise
        unrelated sessions. A single `uname -a` is near-worthless (everything runs it); this
        is the weaker of the two but catches partial reuse (e.g. one stock recon one-liner
        embedded in several different attack chains).
    (2) sha256(normalised ORDERED command sequence for a session) -- the stronger identifier.
        An ordered playbook is close to a tool signature.

    30-day window (vs hassh_pivots' 14d) because command volume is much lower than SSH KEX
    volume -- more history is needed before "no shared hash yet" means something.

    Do NOT let a fingerprint become an identity: identical commands prove shared TOOLING, not
    a shared operator -- a public exploit script gives thousands of unrelated actors the same
    hash. Report it as "same toolkit/script"; attribution to an actor needs corroboration
    beyond the hash (credential sets, sample hashes, HASSH -- see hassh_pivots above).
    """
    sql = (
        f"SELECT json_extract_scalar(raw,'$.session') AS session, src_ip, "
        f"json_extract_scalar(raw,'$.input') AS input, cast(event_time as varchar) t "
        f"FROM {EVENTS} WHERE event_type = 'cowrie.command.input' "
        f"AND event_time > current_timestamp - interval '{days}' day ORDER BY session, t"
    )
    try:
        cols, rows = lake_query(sql)
    except Exception as e:
        print("command_fingerprints:", e)
        return {"singles": [], "sequences": []}
    i = {c: n for n, c in enumerate(cols)}

    # Rows arrive ordered by (session, t), so a single pass builds each session's ordered
    # command list without a second query. `last_t` ends up as that session's newest command
    # time, since rows for a session arrive ascending -- feeds each group's "latest" below
    # (2026-08-17: this report had no timestamps anywhere, individual or group-latest).
    sessions = defaultdict(lambda: {"ip": None, "cmds": [], "last_t": ""})
    for r in rows:
        sess, ip, raw_input, t = r[i["session"]], r[i["src_ip"]], r[i["input"]], r[i["t"]]
        if not sess or raw_input is None:
            continue
        sessions[sess]["ip"] = ip
        sessions[sess]["cmds"].append(raw_input)
        if t:
            sessions[sess]["last_t"] = t

    single_groups = defaultdict(
        lambda: {"count": 0, "sessions": set(), "ips": set(), "example": None, "latest": ""}
    )
    seq_groups = defaultdict(
        lambda: {"sessions": set(), "ips": set(), "example": None, "n_cmds": 0, "latest": ""}
    )

    for sess, d in sessions.items():
        norm_cmds = [normalize_command(c) for c in d["cmds"]]
        for raw_c, norm_c in zip(d["cmds"], norm_cmds, strict=True):
            if not norm_c:
                continue
            g = single_groups[_sha256(norm_c)]
            g["count"] += 1
            g["sessions"].add(sess)
            if d["ip"]:
                g["ips"].add(d["ip"])
            if g["example"] is None:
                g["example"] = raw_c
            g["latest"] = max(g["latest"], d["last_t"])

        seq_norm = "\n".join(c for c in norm_cmds if c)
        if not seq_norm:
            continue
        sg = seq_groups[_sha256(seq_norm)]
        sg["sessions"].add(sess)
        if d["ip"]:
            sg["ips"].add(d["ip"])
        sg["n_cmds"] = len(norm_cmds)
        if sg["example"] is None:
            sg["example"] = d["cmds"]
        sg["latest"] = max(sg["latest"], d["last_t"])

    singles = [
        {
            "hash": h,
            "count": g["count"],
            "n_sessions": len(g["sessions"]),
            "n_ips": len(g["ips"]),
            "ips": sorted(g["ips"]),
            "example": g["example"],
            "latest": g["latest"],
        }
        for h, g in single_groups.items()
    ]
    singles.sort(key=lambda x: x["latest"], reverse=True)
    singles.sort(key=lambda x: (-x["n_ips"], -x["count"]))

    sequences = [
        {
            "hash": h,
            "n_sessions": len(g["sessions"]),
            "n_ips": len(g["ips"]),
            "ips": sorted(g["ips"]),
            "n_cmds": g["n_cmds"],
            "example": g["example"],
            "latest": g["latest"],
        }
        for h, g in seq_groups.items()
    ]
    sequences.sort(key=lambda x: x["latest"], reverse=True)
    sequences.sort(key=lambda x: (-x["n_ips"], -x["n_sessions"]))
    return {"singles": singles, "sequences": sequences}


# The report carries no agent-written assessment card: the data, the enrichment and the brief only.
def analyst_note(domain="honeypot", max_chars=2600):
    return None


def enrich_ips(ips):
    ips = [ip for ip in ips if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)]
    enr = {ip: {} for ip in ips}
    if not ENRICH:
        return enr
    # ip-api batch geo/ASN (keyless, 100/req)
    try:
        for i in range(0, len(ips), 100):
            chunk = ips[i : i + 100]
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=query,country,countryCode,as,org,proxy,hosting",
                data=json.dumps(chunk).encode(),
                headers={"Content-Type": "application/json"},
            )
            for row in json.loads(urllib.request.urlopen(req, timeout=20).read()):
                enr.get(row.get("query"), {}).update(
                    country=row.get("country"),
                    cc=row.get("countryCode"),
                    asn=row.get("as"),
                    org=row.get("org"),
                    proxy=row.get("proxy"),
                    hosting=row.get("hosting"),
                )
    except Exception as e:
        print("ip-api:", e)
    # GreyNoise community (keyless): benign scanner vs malicious
    for ip in ips:
        try:
            g = json.loads(_get(f"https://api.greynoise.io/v3/community/{ip}", timeout=8))
            enr[ip].update(
                gn=g.get("classification"), gn_name=g.get("name"), gn_noise=g.get("noise")
            )
        except Exception:
            pass
    # Tor exit list
    try:
        tor = set(_get("https://check.torproject.org/torbulkexitlist", timeout=15).split())
        for ip in ips:
            if ip in tor:
                enr[ip]["tor"] = True
    except Exception:
        pass
    # Reverse DNS — last, because it is the slowest leg and the most optional.
    for ip, d in rdns(ips).items():
        enr.get(ip, {}).update(ptr=d["ptr"], research=d["research"])
    return enr


def cti_crossref(ips):
    if not ips or not CTI_TABLE:
        return {}
    # src_ip comes from the sender: only a real IP address may reach the statement (no quote, no text)
    valid = []
    for ip in ips:
        try:
            text = str(ipaddress.ip_address(ip))
            if re.fullmatch(r"[0-9a-f.:]+", text):  # no scope id, nothing but address characters
                valid.append(text)
        except (ValueError, TypeError):
            continue
    if not valid:
        return {}
    arr = "ARRAY[" + ",".join("'" + ip + "'" for ip in sorted(set(valid))) + "]"
    hits = {}
    try:
        _, rows = lake_query(
            f"SELECT DISTINCT i.value FROM {CTI_TABLE} r CROSS JOIN UNNEST(r.iocs) AS t(i) "
            f"WHERE i.type='ip' AND contains({arr}, i.value)"
        )
        for r in rows:
            hits[r[0]] = "in CTI reporting"
    except Exception as e:
        print("cti xref:", e)
    return hits


# Deterministic MITRE ATT&CK tactic/technique tagging for typed commands. Substring-matched
# against real command text rather than left to the LLM: a model can miss a step, invent one, or
# tag inconsistently between runs on identical input -- the "attack path" the operator wants
# needs to be an auditable, reproducible fact, not a paraphrase. Ordered most-specific-first;
# first match wins per command. Kept intentionally small and precise (false-tag is worse than
# untagged -- an unmapped command still renders plainly rather than being forced into a guess).
ATTCK_RULES = [
    (
        "TA0006",
        "Credential Access",
        "T1552.001",
        "Unsecured Credentials",
        ("/etc/shadow", "/etc/passwd", ".ssh/id_", ".ssh/authorized_keys"),
    ),
    (
        "TA0007",
        "Discovery",
        "T1082",
        "System Information Discovery",
        ("uname", "/proc/cpuinfo", "/proc/meminfo", "lscpu", "/etc/issue", "/etc/os-release"),
    ),
    (
        "TA0007",
        "Discovery",
        "T1016",
        "System Network Config Discovery",
        ("ifconfig", "ip a", "ip addr", "netstat", "route -n"),
    ),
    ("TA0007", "Discovery", "T1057", "Process Discovery", ("ps ", "ps-e", "top -", "pgrep")),
    ("TA0007", "Discovery", "T1083", "File and Directory Discovery", ("ls -", "find /", "locate ")),
    (
        "TA0007",
        "Discovery",
        "T1033",
        "System Owner/User Discovery",
        ("whoami", "who ", " id;", " id\n"),
    ),
    (
        "TA0011",
        "Command and Control",
        "T1105",
        "Ingress Tool Transfer",
        ("wget ", "curl ", "tftp ", "scp "),
    ),
    ("TA0003", "Persistence", "T1053.003", "Scheduled Task/Job: Cron", ("crontab", "/etc/cron")),
    (
        "TA0003",
        "Persistence",
        "T1546.004",
        "Unix Shell Config Modification",
        (".bashrc", ".bash_profile", ".profile"),
    ),
    ("TA0003", "Persistence", "T1098.004", "SSH Authorized Keys", ("authorized_keys",)),
    ("TA0003", "Persistence", "T1136", "Create Account", ("useradd", "adduser")),
    (
        "TA0002",
        "Execution",
        "T1059.004",
        "Unix Shell",
        ("sh -c", "bash -c", "/bin/sh", "/bin/bash"),
    ),
    (
        "TA0002",
        "Execution",
        "T1204.002",
        "Malicious File Execution",
        ("chmod +x", "chmod 777", "./"),
    ),
    (
        "TA0005",
        "Defense Evasion",
        "T1070.003",
        "Clear Command History",
        ("history -c", "histfile", "bash_history"),
    ),
    (
        "TA0005",
        "Defense Evasion",
        "T1027",
        "Obfuscated Files or Information",
        ("base64 -d", "base64 --decode"),
    ),
    (
        "TA0040",
        "Impact",
        "T1496",
        "Resource Hijacking",
        ("xmrig", "stratum+tcp", "minerd", "cpuminer"),
    ),
    ("TA0040", "Impact", "T1485", "Data Destruction", ("rm -rf /", "rm -rf *")),
]


def tag_command(cmd: str):
    low = (cmd or "").lower()
    for tactic_id, tactic, tech_id, tech, subs in ATTCK_RULES:
        if any(s in low for s in subs):
            return tactic_id, tactic, tech_id, tech
    return None


BRIEF_OBSERVATION_LIMIT = 12
# Per-kind floor so a plain prefix slice can never decide what the brief may say (LL-049: with
# >=12 commands, `[:12]` silently dropped EVERY kind=sample -- the highest-value observation --
# and the model was then judged "weak" for not discussing samples it was never shown).
BRIEF_KIND_QUOTAS = (("sample", 4), ("command", 6))


def select_observations(items, limit=BRIEF_OBSERVATION_LIMIT, quotas=BRIEF_KIND_QUOTAS):
    """Pick at most `limit` observations, guaranteeing each kind in `quotas` its floor (if it has
    that many), then filling the rest in the caller's priority order. Output keeps input order."""

    def kind(it):
        return (it.get("raw") or {}).get("kind")

    chosen: set[int] = set()
    for k, q in quotas:
        idx = [i for i, it in enumerate(items) if kind(it) == k][:q]
        chosen.update(idx)
    for i in range(len(items)):
        if len(chosen) >= limit:
            break
        chosen.add(i)
    return [items[i] for i in sorted(chosen)][:limit]


def llm_analyze(payload_events, stats):
    samples = [json.dumps(e["raw"])[:300] for e in select_observations(payload_events)]
    # Bullets, not a paragraph -- the operator's own feedback 2026-08-09: a freeform prose block
    # reads as raw analyst thought process, not a report. The factual kill-chain (which command
    # did what) now lives in the deterministic ATT&CK-tagged attack-path section below instead of
    # being asked of the model, so this prompt is narrowed to the judgment calls an LLM is
    # actually suited for: tooling/family guess, scanning-vs-hands-on-keyboard, the standout, and
    # a recommendation -- four bullets, not a recap of data already tabulated elsewhere.
    prompt = (
        "You are a SOC analyst writing a daily honeypot intel brief for a decoy service ("
        + SITE_LABEL
        + "). "
        f"Stats: {stats}. Below are observations, each tagged with a `kind`. "
        "**PRIORITISE `kind=command` and `kind=sample` — post-compromise behaviour and captured binaries. "
        "Those show what the attacker DID once inside and cannot be signatured away. `kind` entries that "
        "are URL probes are low value: once a rule exists the volume adds nothing, so mention them only if "
        "something is genuinely novel.**\n\n"
        "Write your answer as exactly 4 markdown bullet points (each line starting with '- '), NOT a "
        "paragraph. One topic per bullet, in this order: (1) what family/tooling the samples suggest, or "
        "'no samples to assess' if none; (2) mass-scanning noise or hands-on-keyboard, and why; "
        "(3) the single most notable thing in this window; (4) one concrete recommendation. "
        "Ground only in the data; if unsure, say so. Do not restate raw command text -- the exact "
        "commands are already shown elsewhere in this report, tagged by ATT&CK tactic.\n\n"
        "OBSERVATIONS:\n" + "\n".join(samples)
    )
    import time as _t

    # a reasoning model and the token budget is shared with its thinking. Measured
    # 2026-08-01 against this exact endpoint: a trivial "say CONFIRMED" prompt spent 164 of 170
    # completion tokens on reasoning_tokens and returned 9 characters of content. At the old
    # max_tokens=350, a real prompt (12 payload samples, asking for 3-5 sentences) spends the
    # WHOLE budget thinking and returns content="" -- which rendered as a silently blank
    # "Analyst brief" card.
    #
    # The fix is purely BUDGET. Two things that do NOT work, tested against this endpoint so
    # nobody retries them: `chat_template_kwargs: {"enable_thinking": false}` is ignored by this
    # serving build, and appending the model's `/no_think` directive still burned 749 reasoning
    # tokens. At 1500 the model returned reasoning only; at 2500 it thought for 749 tokens and
    # then produced 427 characters of actual brief. So give it room rather than trying to stop
    # it thinking.
    #
    # Raised 2500 -> 4000 on 2026-08-09: even at 2500 the reasoning-only fallback still fired
    # intermittently (confirmed live -- a run whose reasoning content happened to be formatted as
    # "- bulleted" scratchpad lines rendered as though it were the finished brief before
    # render_brief() was hardened to always show the fallback warning). 2500 was never a durable
    # budget, just the number that happened to clear on the one run it was measured against.
    body = {
        "model": LLM_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": LLM_MAX_TOKENS,
        "temperature": LLM_TEMPERATURE,
    }
    last = None
    # the model tier can be busy: retry with a generous timeout
    for _attempt in range(LLM_ATTEMPTS):
        try:
            headers = {"Content-Type": "application/json"}
            if LLM_BEARER:
                headers["Authorization"] = f"Bearer {LLM_BEARER}"
            req = urllib.request.Request(LLM_URL, data=json.dumps(body).encode(), headers=headers)
            msg = json.loads(urllib.request.urlopen(req, timeout=LLM_TIMEOUT).read())["choices"][0][
                "message"
            ]
            text = (msg.get("content") or "").strip()
            if text:
                return text
            # Content empty but the model did think: surface the reasoning rather than a blank
            # card. Messy prose beats an empty box that looks like "nothing happened today".
            reasoning = (msg.get("reasoning_content") or "").strip()
            if reasoning:
                return ("(model returned reasoning only -- shown as-is)\n\n" + reasoning)[:2000]
            last = "empty completion"
        except Exception as e:
            last = e
        _t.sleep(LLM_RETRY_SLEEP)
    # NEVER leak a raw exception into a published page. It reached the operator as
    # "<urlopen error [Errno 113] No route to host>" on the 2026-08-01 report, which is a stack
    # detail, not an analyst brief. Say what happened in words a reader can act on.
    return (
        "Analyst brief unavailable for this run -- the local model tier did not answer "
        f"(last: {type(last).__name__ if isinstance(last, Exception) else last}). "
        "The event data below is unaffected and complete."
    )


def render_brief(text: str) -> str:
    """Render the LLM's markdown-ish answer as HTML: consecutive '- '/'* ' lines become a <ul>,
    everything else (including the "(model returned reasoning only...)" fallback label, and any
    stray non-bullet line the model emits) becomes its own paragraph, IN ORDER.

    Deliberately does not collect bullets globally and drop non-bullet lines: an earlier version
    did exactly that, and when the model fell back to leaking its raw reasoning_content (which
    itself often reads as a bulleted scratchpad, e.g. "- *Stats:* ...", "- *Observation Analysis:*"),
    the '(model returned reasoning only -- shown as-is)' warning line -- which does NOT start with
    '- ' -- was silently dropped, so the leaked reasoning rendered as if it were the intended
    finished brief with no indication anything had gone wrong. Order-preserving mixed rendering
    fixes that: the warning always survives as its own paragraph ahead of whatever follows it.
    """
    parts, bullets = [], []

    def flush():
        if bullets:
            parts.append(
                "<ul class=briefList>"
                + "".join(f"<li>{html.escape(b)}</li>" for b in bullets)
                + "</ul>"
            )
            bullets.clear()

    for raw_ln in (text or "").split("\n"):
        ln = raw_ln.strip()
        if not ln:
            continue
        if ln.startswith(("- ", "* ")):
            bullets.append(ln[2:].strip())
        else:
            flush()
            parts.append(f"<p>{html.escape(ln)}</p>")
    flush()
    return "".join(parts) if parts else html.escape(text or "")


def render(ev, enr, xref, brief, internal=(), imds=0, hv=None, pivots=None, note=None, fp=None):
    hv = hv or {"samples": [], "cmds": [], "logins": [], "friendly_skipped": 0}
    fp = fp or {"singles": [], "sequences": []}
    now = datetime.now(UTC)
    ips = Counter(e["ip"] for e in ev if e["ip"])
    types = Counter(e["type"] for e in ev)
    paths = Counter(
        e["raw"].get("path") or e["raw"].get("url")
        for e in ev
        if e["raw"].get("path") or e["raw"].get("url")
    )
    uas = Counter(
        e["raw"].get("user_agent") or e["raw"].get("ua")
        for e in ev
        if e["raw"].get("user_agent") or e["raw"].get("ua")
    )
    countries = Counter(
        enr.get(ip, {}).get("country") for ip in ips if enr.get(ip, {}).get("country")
    )
    # fetch_events()'s own SQL has no ORDER BY (Counters below don't care), but `plist` shows only
    # a [:6] SUBSET of payloads -- sort newest-first here or that subset is an arbitrary Trino
    # ordering, not "the 6 most recent" (2026-08-17 operator feedback: any subset must be
    # newest-first).
    payloads = sorted(
        (e for e in ev if e["type"] == "http_payload"), key=lambda e: e.get("t") or "", reverse=True
    )
    E = html.escape

    def _fmt_t(t):
        """Trino gives `cast(event_time as varchar)` as 'YYYY-MM-DD HH:MM:SS.ffffff UTC' --
        take just the date+minute prefix, matching the page's own compact style (see the
        page header's own `{now:%H:%M UTC}`). Never raises: an unparseable/missing value
        renders as '?' rather than breaking the page."""
        if not t or len(t) < 16:
            return "?"
        return t[5:16].replace(" ", " ") + "Z"  # 'MM-DD HH:MM' + Z

    # Per-IP LATEST event time -- the "group of items -> latest timestamp" case (2026-08-17
    # operator feedback: the report had NO timestamps anywhere, individual or aggregate).
    last_seen = {}
    for e in ev:
        if e["ip"] and e.get("t") and (e["ip"] not in last_seen or e["t"] > last_seen[e["ip"]]):
            last_seen[e["ip"]] = e["t"]

    def iprow(ip, n):
        d = enr.get(ip, {})
        gn = d.get("gn") or "-"
        gncls = {"malicious": "bad", "benign": "ok", "unknown": "warn"}.get(gn, "")
        flags = " ".join(
            f'<span class="tag {c}">{t}</span>'
            for t, c in [
                (gn, gncls),
                ("TOR", "bad") if d.get("tor") else ("", ""),
                ("proxy", "warn") if d.get("proxy") else ("", ""),
                ("hosting", "") if d.get("hosting") else ("", ""),
                (f"RESEARCH:{d['research']}", "ok") if d.get("research") else ("", ""),
                ("CTI-HIT", "bad") if ip in xref else ("", ""),
            ]
            if t
        )
        ptr = d.get("ptr")
        ipcell = (
            f'{E(ip)}<div class="sm" style="color:var(--dim)">{E(ptr[:44])}</div>' if ptr else E(ip)
        )
        return (
            f'<tr><td class="mono">{ipcell}</td><td>{n}</td>'
            f'<td class="mono sm">{E(_fmt_t(last_seen.get(ip)))}</td>'
            f"<td>{E(d.get('cc') or '?')} {E(d.get('country') or '')}</td>"
            f'<td class="mono sm">{E((d.get("asn") or d.get("org") or "")[:38])}</td><td>{flags}</td></tr>'
        )

    rows = "".join(iprow(ip, n) for ip, n in ips.most_common(25))
    plist = "".join(
        f'<div class="pl"><span class="mono sm">{E(str(e["raw"].get("src_ip") or e["ip"]))}</span> '
        f'<span class="mono sm" style="color:var(--dim)">{E(_fmt_t(e.get("t")))}</span> '
        f"<code>{E((e['raw'].get('path') or e['raw'].get('url') or '')[:80])}</code>"
        f'<div class="plbody mono sm">{E(json.dumps(e["raw"])[:220])}</div></div>'
        for e in payloads[:6]
    )
    # IMDS is excluded from the attacker table but never silently dropped: an attacker reaching
    # the metadata address from inside the honeypot is attempting to steal the instance's role
    # credentials, which is the single most consequential thing that can happen on this sensor.
    # Volume alone is not an alarm -- the instance polls its own metadata routinely -- so this
    # reports the count and says plainly what would make it an incident.
    imds_card = (
        (
            f"<div class=card><h2>IMDS contact ({imds})</h2><div class=sub>"
            f"<b>{imds}</b> event(s) involving a link-local address (the instance metadata service) in the window. "
            "Excluded from the attacker ranking because it is link-local, <b>not</b> because it is uninteresting. "
            "Routine instance self-polling looks exactly like this. <b>It becomes an incident if IMDS contact "
            "correlates with an inbound session</b> — i.e. an attacker inside the honeypot reaching for the "
            "instance role credentials (SSRF or hands-on-keyboard). Cross-check against session start times "
            "before dismissing.</div></div>"
        )
        if imds
        else ""
    )

    # ---- the three high-value sections, in operator-priority order ----
    # A sample manifest the capture side stamped `sample_truncation_candidate` carries its own
    # verdict (a byte-exact truncated prefix of another sample is not a distinct build); an older
    # manifest without the stamp is shown unjudged rather than re-derived here.
    _leg1 = None

    def _truncation_flag(r):
        flag = r.get("sample_truncation_candidate")
        if flag is not None:
            return bool(flag)
        if _leg1 is None:
            return None
        ln = r.get("sample_len")
        if not isinstance(ln, int):
            return None
        fired, _reason = _leg1(
            ln, sample_origin=r.get("sample_origin"), cowrie_event=r.get("cowrie_event")
        )
        return bool(fired)

    def _sample_row(s):
        r = s["raw"]
        sha = r.get("sample_sha256") or ""
        ln = r.get("sample_len")
        magic = (r.get("sample_magic") or "").lower()
        kind = (
            "ELF binary"
            if magic.startswith("7f454c46")
            else "PE/EXE"
            if magic.startswith("4d5a")
            else "script/text"
            if magic and magic.startswith(("2321", "2a0a"))
            else (r.get("content_type") or r.get("http", {}).get("content_type") or "unknown")
        )
        name = r.get("attacker_filename") or r.get("filename") or r.get("http", {}).get("url") or ""
        size = f"{ln:,} B" if isinstance(ln, int) else "?"
        truncated = _truncation_flag(r)
        sha_cell = E(sha[:20]) + ("…" if sha else "")
        if truncated:
            sha_cell = (
                f'<span title="LL-233: exact multiple of the SFTP chunk size or '
                f"ELF section table runs past EOF -- NOT ISSUABLE as a file-hash "
                f'IOC, likely a truncated prefix of a larger capture" '
                f'style="color:#b33;font-weight:600">&#9888; TRUNCATED CANDIDATE</span> '
                f"<span class=mono>{sha_cell}</span>"
            )
        return (
            f'<tr><td class="mono sm">{E(s["ip"] or "-")}</td>'
            f'<td class="mono sm">{E(_fmt_t(s.get("t")))}</td>'
            f"<td class=sm>{E(kind)}</td>"
            f'<td class=sm>{size}</td><td class="mono sm">{E(str(name)[:46])}</td>'
            f'<td class="mono sm" title="{E(sha)}">{sha_cell}</td>'
            f'<td class="mono sm">{E(str(s.get("session") or "")[:12])}</td></tr>'
        )

    # hv["samples"]/["cmds"]/["logins"] all come from fetch_highvalue()'s `ORDER BY event_time
    # DESC` -- already newest-first. Kept explicit here (not just assumed) since a truncated
    # subset (samples[:12], logins[:24], per-session items[:6] below) that quietly wasn't
    # newest-first would show stale entries and hide the actual latest activity (2026-08-17
    # operator feedback: any subset display must keep the newest items up front).
    samples, cmds, logins = hv["samples"], hv["cmds"], hv["logins"]
    samples_card = (
        f"<div class=card><h2>&#9888; Malware / uploads captured ({len(samples)})</h2>"
        f"<div class=sub>The payoff. A captured binary cannot be signatured away — it is the one artifact "
        f"that survives the attacker changing tooling. Window: {HIGHVALUE_DAYS}d, newest first.</div>"
        f"<table><tr><th>source</th><th>when</th><th>type</th><th>size</th><th>filename</th><th>sha256</th><th>session</th></tr>"
        f"{''.join(_sample_row(s) for s in samples[:12])}</table></div>"
        if samples
        else f"<div class=card><h2>Malware / uploads captured (0)</h2><div class=sub>Nothing captured in "
        f"{HIGHVALUE_DAYS}d. <b>This is the metric that matters most</b> — a honeypot drawing scans but no "
        f"payloads is being fingerprinted and rejected, or the bait is not tempting enough to act on.</div></div>"
    )

    # bysess groups `cmds` (already DESC/newest-first, see the note above) preserving that
    # relative order, so both `items[:6]` (commands within a session) and dict-iteration order
    # over `bysess.items()` (sessions, ordered by when each session's MOST RECENT command was
    # hit in the DESC scan) end up newest-first without a separate sort.
    bysess = defaultdict(list)
    for c in cmds:
        bysess[(c["ip"], c["session"])].append(c)
    session_latest = {k: (items[0].get("t") or "") for k, items in bysess.items()}
    cmd_blocks = "".join(
        f'<div class=pl><span class="mono sm">{E(ip)}</span> '
        f"<span class=sub>session {E(str(sess)[:12])} · {len(items)} cmd(s) · last {E(_fmt_t(session_latest.get((ip, sess))))} · newest first</span>"
        + "".join(
            f'<div class="plbody mono sm"><span style="color:var(--dim)">{E(_fmt_t(c.get("t")))}</span> $ {E((c["input"] or "")[:300])}</div>'
            for c in items[:6]
        )
        + "</div>"
        for (ip, sess), items in list(bysess.items())[:8]
    )
    cmds_card = (
        f"<div class=card><h2>&#128187; Hands-on-keyboard — commands run ({len(cmds)})</h2>"
        f"<div class=sub>What the attacker did <b>after</b> getting in. Irreducible intel: this is behaviour, "
        f"not a signature. Window: {HIGHVALUE_DAYS}d.</div>{cmd_blocks}</div>"
        if cmds
        else ""
    )

    logins_card = (
        f"<div class=card><h2>&#128273; Credentials that WORKED ({len(logins)})</h2>"
        f"<div class=sub>Accepted by the bait — these are the pairs being sprayed at real estates right now. "
        f"Newest first; hover a pair for its exact time.</div>"
        + "".join(
            f'<span class="tag bad" title="{E(_fmt_t(l.get("t")))}">{E(l["user"])} / {E(l["pw"])} '
            f'<span style="opacity:.65">{E(_fmt_t(l.get("t")))}</span></span> '
            for l in logins[:24]
        )
        + "</div>"
        if logins
        else ""
    )

    # ---- Attack path — MITRE ATT&CK, deterministic per-session kill chain ----
    # Operator feedback 2026-08-09: the report needed sections / a structured attack path, not a
    # freeform paragraph. This is built from the SAME per-session command groups as cmds_card
    # above, tagged against ATTCK_RULES -- reproducible and auditable, unlike an LLM's guess.
    login_by_session = {(l["ip"], l.get("session") or ""): l for l in logins}
    path_sessions = []
    for (ip, sess), items in bysess.items():
        steps = []
        lg = login_by_session.get((ip, sess))
        if lg:
            steps.append(
                {
                    "tactic_id": "TA0001",
                    "tactic": "Initial Access",
                    "tech_id": "T1078",
                    "tech": "Valid Accounts",
                    "cmd": f"login {lg['user']}/{lg['pw']}",
                    "t": lg.get("t"),
                }
            )
        for c in items:
            tag = tag_command(c["input"])
            step = {"cmd": (c["input"] or "")[:160], "t": c.get("t")}
            if tag:
                step["tactic_id"], step["tactic"], step["tech_id"], step["tech"] = tag
            steps.append(step)
        n_tactics = len({s["tactic_id"] for s in steps if "tactic_id" in s})
        latest = max((s.get("t") or "" for s in steps), default="")
        path_sessions.append(
            {"ip": ip, "session": sess, "steps": steps, "n_tactics": n_tactics, "latest": latest}
        )
    # Primary sort stays significance (most ATT&CK tactics first, an intentional editorial
    # ranking, not a chronological one) -- ties broken by recency (two stable sorts: sort
    # newest-first, then stable-resort by tactic count so equal-tactic sessions keep their
    # newest-first relative order) so the subset kept by [:8] below favors the newer of two
    # equally-notable sessions.
    path_sessions.sort(key=lambda s: s["latest"], reverse=True)
    path_sessions.sort(key=lambda s: -s["n_tactics"])

    TACTIC_CLASS = {
        "TA0001": "warn",
        "TA0006": "bad",
        "TA0011": "bad",
        "TA0003": "bad",
        "TA0005": "bad",
        "TA0040": "bad",
    }  # unlisted (Discovery, Execution) = neutral

    def _step_html(s):
        if "tactic_id" in s:
            cls = TACTIC_CLASS.get(s["tactic_id"], "")
            badge = f'<span class="tag {cls}">{E(s["tactic"])} &middot; {E(s["tech_id"])}</span>'
        else:
            badge = '<span class="tag">unmapped</span>'
        return (
            f'<div class=pathstep><span class="mono sm" style="color:var(--dim)">{E(_fmt_t(s.get("t")))}</span> '
            f"{badge} <code>{E(s['cmd'])}</code></div>"
        )

    def _session_html(ps):
        tactics = sorted({s["tactic"] for s in ps["steps"] if "tactic_id" in s})
        return (
            f'<div class=pl><span class="mono sm">{E(ps["ip"])}</span> '
            f"<span class=sub>session {E(str(ps['session'])[:12])} &middot; last activity {E(_fmt_t(ps['latest']))} &middot; "
            f"{ps['n_tactics']} ATT&amp;CK tactic(s): {E(', '.join(tactics)) or 'none mapped'}</span>"
            + "".join(_step_html(s) for s in ps["steps"][:15])
            + "</div>"
        )

    attack_path_card = (
        (
            f"<div class=card><h2>&#128737; Attack path — MITRE ATT&amp;CK ({len(path_sessions)} session(s))</h2>"
            f"<div class=sub>Deterministic, substring-matched against the real typed commands above — not an LLM guess. "
            f"Kill-chain order per session: login (Initial Access, if captured) then each command tagged with its "
            f"tactic/technique where the mapping is unambiguous. An unmapped command is shown plainly rather than "
            f"forced into a tactic that does not fit. Ranked by tactic breadth, ties broken newest-first.</div>"
            + "".join(_session_html(ps) for ps in path_sessions[:8])
            + "</div>"
        )
        if path_sessions
        else "<div class=card><h2>Attack path — MITRE ATT&CK (0)</h2>"
        "<div class=sub>No sessions with typed commands in this window.</div></div>"
    )

    # ---- infrastructure tracking: same tooling, new address ----
    shared = [h for h in (pivots or []) if h["n_ips"] > 1]
    pivot_card = (
        f"<div class=card><h2>&#128225; Same actor, new IP — HASSH pivots ({len(shared)})</h2>"
        f"<div class=sub>HASSH is a hash of the SSH client's KEX/cipher/MAC algorithm lists — the SSH analogue of JA3 — "
        f"and Cowrie already emits it, so this needs no new collection. It is a property of the attacker's <b>tooling</b>, "
        f"so it survives a change of address, ASN and country. <b>rDNS cannot do this</b> (only 3 of 9 attacker IPs here "
        f"even have a PTR). Treat a match as a lead and corroborate with credential sets or sample hashes — a very common "
        f"stock client groups tooling, not necessarily one operator.</div>"
        f"<table><tr><th>hassh</th><th>IPs</th><th>sessions</th><th>last seen</th><th>addresses seen</th></tr>"
        + "".join(
            f'<tr><td class="mono sm">{E(h["hassh"][:20])}…</td><td><b>{h["n_ips"]}</b></td>'
            f'<td>{h["sessions"]}</td><td class="mono sm">{E(_fmt_t(h.get("latest")))}</td>'
            f'<td class="mono sm">{E(str(h["ips"])[:70])}</td></tr>'
            for h in shared[:10]
        )
        + "</table></div>"
        if shared
        else f"<div class=card><h2>Same actor, new IP — HASSH pivots (0)</h2><div class=sub>No SSH client "
        f"fingerprint seen from more than one address in the window. {len(pivots or [])} distinct fingerprint(s) "
        f"tracked — the pivot arms itself automatically the first time one reappears from a new IP.</div></div>"
    )

    singles, sequences = fp.get("singles") or [], fp.get("sequences") or []
    shared_singles = [s for s in singles if s["n_ips"] > 1]
    shared_seqs = [s for s in sequences if s["n_ips"] > 1]

    def _fprow(s, cmd_text):
        return (
            f'<tr><td class="mono sm" title="{E(s["hash"])}">{E(s["hash"][:16])}…</td>'
            f"<td><b>{s['n_ips']}</b></td><td>{s['n_sessions']}</td>"
            f'<td class="mono sm">{E(_fmt_t(s.get("latest")))}</td>'
            f'<td class="mono sm">{E(str(s["ips"])[:60])}</td>'
            f'<td class="mono sm">{E(cmd_text[:90])}</td></tr>'
        )

    seq_rows = "".join(
        _fprow(s, " ; ".join((c or "")[:40] for c in (s["example"] or [])[:3]))
        for s in shared_seqs[:10]
    )
    single_rows = "".join(_fprow(s, s["example"] or "") for s in shared_singles[:10])
    fingerprint_card = (
        f"<div class=card><h2>&#128269; Command fingerprinting — shared tooling across sessions "
        f"({len(singles)} single-command, {len(sequences)} session-sequence, {FINGERPRINT_DAYS}d window)</h2>"
        f"<div class=sub>Operator observation 2026-08-05: identical command strings across sessions are not how humans "
        f"type — they are how a <b>script</b> runs, so the repetition fingerprints the TOOLKIT rather than the IP that "
        f"delivered it. A toolkit survives IP rotation; the attacker address does not. Normalization folds whitespace/case "
        f"and strips IPs + long digit runs (random dir names, nonces) before hashing. "
        f"<b>&#9888; A shared hash proves shared TOOLING, not a shared operator</b> — a public exploit script gives "
        f'thousands of unrelated actors the same hash; treat a match as "same toolkit", corroborate before calling it '
        f"one actor.</div>"
        f'<div class=sub style="margin-top:10px"><b>Session-sequence hashes seen from &gt;1 IP ({len(shared_seqs)})'
        f"</b> — the stronger pivot, an ordered playbook rather than one command.</div>"
        + (
            f"<table><tr><th>hash</th><th>IPs</th><th>sessions</th><th>last seen</th><th>addresses</th><th>first commands</th></tr>"
            f"{seq_rows}</table>"
            if shared_seqs
            else "<div class=sub>None yet — every session-sequence so far is unique to one IP.</div>"
        )
        + f'<div class=sub style="margin-top:10px"><b>Single-command hashes seen from &gt;1 IP ({len(shared_singles)})'
        f"</b> — weaker alone (a lone <code>uname -a</code> is near-worthless), useful for partial reuse.</div>"
        + (
            f"<table><tr><th>hash</th><th>IPs</th><th>sessions</th><th>last seen</th><th>addresses</th><th>command</th></tr>"
            f"{single_rows}</table>"
            if shared_singles
            else "<div class=sub>None yet.</div>"
        )
        + "</div>"
    )

    note_card = ""

    BUCKET_WHY = {
        "internal": (
            "honeypot's own containers / host chatter",
            "RFC1918 — the network IDS sniffing the local interface",
        ),
        "overlay": (
            "overlay-network DERP/STUN relays",
            f"publicly routable, but :{OVERLAY_PORT} NAT-traversal keepalives — <b>not</b> caught by routability",
        ),
        "imds": ("AWS Instance Metadata Service", "link-local; see the IMDS card"),
        "friendly": (
            "our own egress / verification probes",
            "fleet IP — our own traffic is not catch",
        ),
        "noip": ("no source address", "excluded from every IP-keyed figure"),
    }
    bcount = Counter(e["bucket"] for e in internal)
    bucket_latest = {}
    for e in internal:
        if e.get("t") and (e["bucket"] not in bucket_latest or e["t"] > bucket_latest[e["bucket"]]):
            bucket_latest[e["bucket"]] = e["t"]
    buckets_rows = "".join(
        f'<tr><td class=mono>{E(b)}</td><td>{n}</td><td class="mono sm">{E(_fmt_t(bucket_latest.get(b)))}</td>'
        f"<td class=sm>{BUCKET_WHY.get(b, ('?', ''))[0]} — "
        f'<span style="color:var(--dim)">{BUCKET_WHY.get(b, ("", "?"))[1]}</span></td></tr>'
        for b, n in bcount.most_common()
    )

    def bars(counter, top=8):
        mx = max(counter.values()) if counter else 1
        return "".join(
            f'<div class="bar"><span class="bl">{E(str(k)[:40])}</span>'
            f'<span class="bb" style="width:{max(6, int(100 * v / mx))}%"></span><span class="bn">{v}</span></div>'
            for k, v in counter.most_common(top)
        )

    return f"""<!doctype html><html><head><meta charset=utf-8><title>Honeypot Intel — {now:%Y-%m-%d}</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>
:root{{--bg:#0b0e14;--card:#141925;--edge:#26304a;--tx:#c7d0e0;--dim:#7d89a3;--acc:#5aa2ff;--bad:#ff5c6c;--ok:#3fb950;--warn:#e3b341}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;padding:22px;max-width:1150px;margin:auto}}
h1{{font-size:23px;margin:0}}.sub{{color:var(--dim);margin:2px 0 18px;font-size:13px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}}
.kpi{{background:var(--card);border:1px solid var(--edge);border-radius:10px;padding:12px 14px}}.kpi .n{{font-size:26px;font-weight:700;color:#fff}}.kpi .l{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.05em}}
.card{{background:var(--card);border:1px solid var(--edge);border-radius:10px;padding:16px;margin-bottom:16px}}
h2{{font-size:15px;margin:0 0 12px;color:#fff}}.brief{{border-left:3px solid var(--acc);padding-left:12px;color:#dfe6f2}}
table{{width:100%;border-collapse:collapse;font-size:13px}}td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--edge)}}th{{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase}}
.mono{{font-family:ui-monospace,Menlo,monospace}}.sm{{font-size:12px}}.tag{{display:inline-block;background:#5aa2ff22;color:var(--acc);border-radius:9px;padding:0 7px;font-size:11px;font-weight:600;margin:0 2px 2px 0}}.tag.bad{{background:#ff5c6c22;color:var(--bad)}}.tag.ok{{background:#3fb95022;color:var(--ok)}}.tag.warn{{background:#e3b34122;color:var(--warn)}}
.bar{{display:flex;align-items:center;gap:8px;margin:3px 0}}.bl{{width:44%;color:var(--dim);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,monospace}}.bb{{height:9px;background:var(--acc);border-radius:5px}}.bn{{font-size:12px;color:var(--tx)}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}@media(max-width:720px){{.cols{{grid-template-columns:1fr}}}}
.pl{{border-bottom:1px solid var(--edge);padding:8px 0}}.pl code{{background:#010409;padding:1px 6px;border-radius:4px;color:var(--warn)}}.plbody{{color:var(--dim);margin-top:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.pathstep{{margin:4px 0 4px 8px;font-size:12.5px}}.pathstep code{{background:#010409;padding:1px 6px;border-radius:4px;color:var(--tx)}}
.briefList{{margin:0;padding-left:20px}}.briefList li{{margin:5px 0}}
</style></head><body>
<h1>🍯 Honeypot Intel — {now:%Y-%m-%d}</h1>
<div class=sub>{html.escape(SITE_LABEL)} · last 24h · generated {now:%H:%M UTC}</div>
<div class=grid>
 <div class=kpi><div class=n>{len(ev)}</div><div class=l>events</div></div>
 <div class=kpi><div class=n>{len(ips)}</div><div class=l>unique IPs</div></div>
 <div class=kpi><div class=n>{types.get("http_payload", 0)}</div><div class=l>payload attempts</div></div>
 <div class=kpi><div class=n>{len(countries)}</div><div class=l>countries</div></div>
 <div class=kpi><div class=n>{sum(1 for ip in ips if enr.get(ip, {}).get("gn") == "malicious")}</div><div class=l>GreyNoise-malicious</div></div>
 <div class=kpi><div class=n>{len(xref)}</div><div class=l>CTI-lake hits</div></div>
</div>
<div class=card><h2>Analyst brief</h2><div class=brief>{render_brief(brief)}</div></div>
{note_card}
{samples_card}
{cmds_card}
{attack_path_card}
{logins_card}
{pivot_card}
{fingerprint_card}
<div class=card><h2>Top source IPs (enriched)</h2>
<div class=sub>External, globally-routable sources only — RFC1918/link-local/loopback are excluded from the ranking (see below).</div><table>
<tr><th>IP</th><th>events</th><th>last seen</th><th>geo</th><th>ASN / org</th><th>flags</th></tr>{rows}</table></div>
{imds_card}
<div class=card><h2>Excluded from the attacker ranking ({len(internal)})</h2>
<div class=sub>the network IDS sniffs the whole host interface, so most of what lands in this table is <b>not inbound attack traffic</b>. Buckets mirror an analyst's own attribution so the report and the analyst cannot disagree about who the attackers are.</div>
<table><tr><th>bucket</th><th>events</th><th>last seen</th><th>what it is</th></tr>{buckets_rows}</table>
<div class=sub style="margin-top:10px"><b>Routability is judged by CIDR (<code>ipaddress.is_global</code>), never by string prefix.</b> RFC1918 is only <code>172.16/12</code>, so a <code>172.</code> prefix filter would also discard <code>172.105.x</code>/<code>172.237.x</code> — public Akamai/Linode space. Note those particular addresses are <i>still</i> not attackers here: they are overlay-network relays, caught by the <code>:41641</code> rule rather than by routability.</div></div>
<div class=cols>
 <div class=card><h2>Event types</h2>{bars(types)}</div>
 <div class=card><h2>Countries</h2>{bars(countries)}</div>
 <div class=card><h2>Top paths hit</h2>{bars(paths)}</div>
 <div class=card><h2>User agents / tools</h2>{bars(uas)}</div>
</div>
<div class=card><h2>URL probe payloads ({len(payloads)}) — low priority</h2>
<div class=sub>Deliberately below the sections above. A mass URL probe is worth <b>one</b> look: once the network IDS has the pattern and a rule exists, the next thousand identical curls add nothing. Kept for novelty-spotting, not for volume. Newest {min(len(payloads), 6)} of {len(payloads)}:</div>
{plist or "<span class=sub>none in window</span>"}</div>
</body></html>"""


_DATED = re.compile(r"\Ahoneypot-report-[0-9]{4}-[0-9]{2}-[0-9]{2}\.html\Z", re.ASCII)


def prune_old(directory, keep_days, now=None):
    """Remove dated report copies older than keep_days: regular files directly inside `directory`
    whose names are exactly the dated pattern (never a link, never anything else). Returns the names."""
    import stat as _stat

    now = now if now is not None else datetime.now(UTC).timestamp()
    removed = []
    if keep_days < 1 or not os.path.isdir(directory):
        return removed
    for name in sorted(os.listdir(directory)):
        if not _DATED.match(name):
            continue
        path = os.path.join(directory, name)
        try:
            st = os.lstat(path)
            if _stat.S_ISREG(st.st_mode) and now - st.st_mtime > keep_days * 86400:
                os.unlink(path)
                removed.append(name)
        except OSError:
            continue
    return removed


def main():
    if not LAKE_CATALOG:
        raise RuntimeError("HNX_HP_LAKE_CATALOG is not set (the site's name for its lake)")
    ev, internal = fetch_events()
    # Only routable sources are enriched. Besides being the correct population, this stops us
    # spending ip-api/GreyNoise/Tor lookups on RFC1918 addresses that can only ever return "?" --
    # which is exactly what the pre-2026-08-02 report showed at the top of its attacker table.
    ips = list({e["ip"] for e in ev if e["ip"]})
    enr = enrich_ips(ips)
    xref = cti_crossref(ips)
    types = Counter(e["type"] for e in ev)
    imds = sum(1 for e in internal if is_metadata(e["ip"]))
    hv = fetch_highvalue()
    stats = {
        "events": len(ev),
        "ips": len(ips),
        "payloads": types.get("http_payload", 0),
        "samples": len(hv["samples"]),
        "commands": len(hv["cmds"]),
        "logins": len(hv["logins"]),
        "malicious_ips": sum(1 for ip in ips if enr.get(ip, {}).get("gn") == "malicious"),
    }
    # Analyse behaviour first. A typed command tells you what the attacker WANTED; a URL probe
    # tells you what scanner they rented. Probes are passed only as a thin tail for novelty.
    brief_input = (
        [
            {"raw": {"kind": "command", "src_ip": c["ip"], "input": c["input"]}}
            for c in hv["cmds"][:25]
        ]
        + [
            {
                "raw": {
                    "kind": "sample",
                    "src_ip": s["ip"],
                    "sha256": s["raw"].get("sample_sha256"),
                    "len": s["raw"].get("sample_len"),
                    "filename": s["raw"].get("attacker_filename"),
                }
            }
            for s in hv["samples"][:10]
        ]
        + [e for e in ev if e["type"] == "http_payload"][:8]
    )
    brief = llm_analyze(brief_input, stats)
    pivots = hassh_pivots()
    note = analyst_note()
    fp = command_fingerprints()
    page = render(ev, enr, xref, brief, internal, imds, hv, pivots, note, fp)
    os.makedirs(OUT_DIR, exist_ok=True)
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    for dest in (OUT, os.path.join(OUT_DIR, f"honeypot-report-{day}.html")):
        # write beside, then rename: a reader never sees a half-written page
        tmp = dest + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(page)
        os.replace(tmp, dest)
    prune_old(OUT_DIR, int(_env("HNX_HP_REPORT_KEEP_DAYS", "30")))
    print(
        f"wrote {OUT} — {len(ev)} external events, {len(ips)} IPs, {len(xref)} CTI hits; "
        f"HIGH-VALUE({HIGHVALUE_DAYS}d): {len(hv['samples'])} sample(s), {len(hv['cmds'])} command(s), "
        f"{len(hv['logins'])} login(s), {hv['friendly_skipped']} friendly skipped; "
        f"filtered {len(internal)} non-attacker ({imds} IMDS); "
        f"{sum(1 for h in pivots if h['n_ips'] > 1)} hassh pivot(s) across multiple IPs; "
        f"command fingerprints({FINGERPRINT_DAYS}d): {len(fp['singles'])} single/{len(fp['sequences'])} sequence, "
        f"{sum(1 for s in fp['sequences'] if s['n_ips'] > 1)} sequence pivot(s) across multiple IPs"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # the lake could not be queried, or the page not written
        print(f"honeypot-report: FAILED: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        sys.exit(1)
