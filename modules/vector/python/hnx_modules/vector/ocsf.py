# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: vector-ocsf
#   kind: tool
#   purpose: Remap one labelled event into the rows of its OCSF classes for the sidecar.
#   owner: platform
#   trigger: [manual]
#   inputs: a labelled event, its kind and a seed
#   outputs: rows per OCSF table
#   exit:
#     "0": imported
"""The OCSF remap: one labelled event in, the rows of its OCSF classes out (standard library only).

``map_event(event, kind, uid_seed, now)`` returns ``[(table, row), ...]``.  The event is what the
enrichment stage produced: its ``labels`` hold the pipeline's labels (``hnx_tlp``,
``hnx_runtime``), which every row keeps so the lake writer can set the row's ``tlp`` column from
``labels.hnx_tlp`` (``homelabnext.lake.rows.row_from_event``) and never from the event's own word.

Severity.  ``severity_id`` is OCSF's own scale (0 unknown, 1 informational, 2 low, 3 medium,
4 high, 5 critical, 6 fatal) and is derived from the severity the SOURCE itself grades, through a
documented band table, never copied from a rule level (the old pipeline wrote Wazuh's 0-15
``rule_level`` into the column, so a level 12 read as "severity 12" to a reader and sorted
against a Suricata 3):

* Wazuh ``rule.level`` 0-3 informational, 4-6 low, 7-11 medium, 12-14 high, 15 critical
  (:func:`siem_severity`; level 12 is Wazuh's own "high importance" line and the paging line,
  ``severity_id >= 4``, is therefore the same events as the old level >= 12 integration);
* Suricata: the signature's own ``signature_severity`` grade when it has one, else the numeric
  ``alert.severity`` (1 high, 2 medium, 3 low) (:func:`ids_severity`);
* CEF (UniFi): the header's 0-10 severity (:func:`cef_severity`);
* a source with no severity of its own (a Zeek connection record, an access log) is informational.

The pinned lake classes (``schemas/ocsf``: authentication, detection_finding, dns_activity,
network_activity, vulnerability_finding) are written in exactly the columns of their schemas.
compliance_finding, file_activity, http_activity and process_activity have no pinned schema yet:
their rows follow the same flat conventions (docs/modules vector README, "OCSF classes") and are
staged under their own table names for the lake writer to take once a schema is pinned.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

OCSF_VERSION = "1.3.0"
PRODUCT = "hnx-vector"

#: table -> (class_uid, category_uid)
CLASSES: dict[str, tuple[int, int]] = {
    "authentication": (3002, 3),
    "compliance_finding": (2003, 2),
    "detection_finding": (2004, 2),
    "dns_activity": (4003, 4),
    "file_activity": (1001, 1),
    "http_activity": (4002, 4),
    "network_activity": (4001, 4),
    "process_activity": (1007, 1),
    "vulnerability_finding": (2002, 2),
}
#: the staging layout, one definition: ``<prefix><table>/dt=%Y-%m-%d/hour=%H/`` (strftime of the write
#: time, UTC); the object store key is this plus ``<id>.ndjson.gz``.  The aggregator's sink renders
#: the same text (a test pins it) and the lake writer reads it.
STAGING_LAYOUT = "{prefix}{table}/dt=%Y-%m-%d/hour=%H/"


def staging_prefix(prefix: str, table: str) -> str:
    """The key prefix under which ``table``'s staged batches are written."""
    return STAGING_LAYOUT.format(prefix=prefix, table=table)


#: the table of the labelled raw event (every event, whatever its class)
RAW_TABLE = "raw_archive"
#: the classes the lake pins today (the rest are staged unpinned)
PINNED = frozenset(
    {"authentication", "detection_finding", "dns_activity", "network_activity",
     "vulnerability_finding"}
)  # fmt: skip

_TECHNIQUE = re.compile(r"T[0-9]{4}(\.[0-9]{3})?\Z")
_DETECTION = re.compile(r"det:[a-z0-9][a-z0-9-]{0,62}\Z")
#: the logical detection id of a Wazuh alert no mapping names (never an engine rule number)
UNMAPPED_DETECTION = "det:siem-unmapped"


# ------------------------------------------------------------------------------- severity
def siem_severity(level: Any) -> int:
    """OCSF ``severity_id`` of a Wazuh rule level (see the module doc); 0 when unreadable."""
    try:
        n = int(level)
    except (TypeError, ValueError):
        return 0
    if isinstance(level, bool) or n < 0:
        return 0
    for ceiling, sev in ((3, 1), (6, 2), (11, 3), (14, 4)):
        if n <= ceiling:
            return sev
    return 5


_SIG_GRADES = {"informational": 2, "minor": 3, "major": 4, "critical": 5}


def ids_severity(alert: Mapping[str, Any]) -> int:
    """The signature's own author grade (``alert.metadata.signature_severity``) when it has a
    known one (many informational rules ship numeric severity 1), else numeric ``alert.severity``
    (1 high, 2 medium, 3 low); an unreadable one is low."""
    meta = alert.get("metadata")
    grade = meta.get("signature_severity") if isinstance(meta, Mapping) else None
    if isinstance(grade, list) and grade:
        grade = grade[0]
    if isinstance(grade, str) and grade.strip().lower() in _SIG_GRADES:
        return _SIG_GRADES[grade.strip().lower()]
    sev = alert.get("severity")
    if isinstance(sev, bool) or not isinstance(sev, (int, str)):
        return 2
    try:
        return {1: 4, 2: 3}.get(int(sev), 2)
    except ValueError:
        return 2


def cef_severity(value: Any) -> int:
    """OCSF ``severity_id`` of a CEF 0-10 severity (or its Low/Medium/High/Very-High names)."""
    names = {"unknown": 1, "low": 2, "medium": 3, "high": 4, "very-high": 5, "very high": 5}
    if isinstance(value, str) and value.strip().lower() in names:
        return names[value.strip().lower()]
    try:
        n = int(str(value).strip())
    except ValueError:
        return 0
    if n < 0 or n > 10:
        return 0
    return 1 if n == 0 else 2 if n <= 3 else 3 if n <= 6 else 4 if n <= 8 else 5


# ------------------------------------------------------------------------------- helpers
def _get(obj: Any, *path: str) -> Any:
    for p in path:
        if not isinstance(obj, Mapping):
            return None
        obj = obj.get(p)
    return obj


def _s(value: Any, limit: int = 256) -> str | None:
    if value is None or isinstance(value, (Mapping, list)):
        return None
    out = str(value).strip()
    return out[:limit] if out else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _first(*values: Any) -> Any:
    return next((v for v in values if v not in (None, "")), None)


def parse_time(value: Any, fallback: datetime) -> str:
    """RFC 3339 UTC (``...Z``) of a timestamp: ISO 8601 (Wazuh's ``+0000``, Suricata's
    ``+0000``, ``Z``), epoch seconds (Zeek's ``ts``) or CEF's ``rt`` epoch milliseconds; the
    collector's receive time when the event has none (never a time from the future of that)."""
    when: datetime | None = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        secs = float(value) / 1000.0 if value > 1e11 else float(value)
        try:
            when = datetime.fromtimestamp(secs, UTC)
        except (OverflowError, OSError, ValueError):
            when = None
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            if re.fullmatch(r"[0-9]+(\.[0-9]+)?", text):
                return parse_time(float(text), fallback)
            when = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
        except ValueError:
            when = None
    return (when or fallback).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def uid_for(seed: str, table: str) -> str:
    """The row's stable content id: the same event always gives the same id (the lake's replay
    key), and one event gives each of its classes a different one."""
    return hashlib.sha256(f"{table}\0{seed}".encode()).hexdigest()[:40]


def seed_of(route: str, event: Any) -> str:
    return route + "\0" + json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)


def _labels(event: Mapping[str, Any]) -> dict[str, Any]:
    lab = event.get("labels")
    return (
        {k: v for k, v in lab.items() if k in ("hnx_tlp", "hnx_runtime")}
        if isinstance(lab, Mapping)
        else {}
    )


def _row(
    table: str,
    event,
    seed,
    now,
    activity,
    severity,
    status=0,
    message=None,
    log_source=None,
    product=None,
):
    cls, cat = CLASSES[table]
    row: dict[str, Any] = {
        "uid": uid_for(seed, table),
        "time": event["_time"],
        "class_uid": cls,
        "category_uid": cat,
        "activity_id": activity,
        "type_uid": cls * 100 + activity,
        "severity_id": severity,
        "status_id": status,
        "metadata": {
            "version": OCSF_VERSION,
            "product": product or PRODUCT,
            "log_source": _s(log_source, 128) or "unknown",
        },
    }
    msg = _s(message, 4096)
    if msg:
        row["message"] = msg
    row["labels"] = _labels(event)
    return row


def _endpoint(ip: Any = None, port: Any = None, hostname: Any = None) -> dict[str, Any] | None:
    out: dict[str, Any] = {}
    if _s(ip, 64):
        out["ip"] = _s(ip, 64)
    p = _int(port)
    if p is not None and 0 <= p <= 65535:
        out["port"] = p
    if _s(hostname):
        out["hostname"] = _s(hostname)
    return out or None


def _detection_id(ids: Mapping[str, str], key: str, default: str) -> str:
    """The logical detection id a mapping gives ``key`` when it is a valid ``det:`` id, else ``default``."""
    value = ids.get(key)
    return value if isinstance(value, str) and _DETECTION.fullmatch(value) else default


def _direction(ext: Mapping[str, str]) -> str:
    """A CEF extension's vendor direction field (a key ending ``direction``), lower case, or ''."""
    for key, value in ext.items():
        if key.lower().endswith("direction"):
            return str(value).lower()
    return ""


def _drop_none(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v is not None}


# ------------------------------------------------------------------------------- the mappers
def siem(
    event: Mapping[str, Any], seed: str, now: datetime, ids: Mapping[str, str]
) -> list[tuple[str, dict[str, Any]]]:
    """A Wazuh alerts.json / archives.json record."""
    out: list[tuple[str, dict[str, Any]]] = []
    rule = event.get("rule") if isinstance(event.get("rule"), Mapping) else {}
    agent_name = _first(_get(event, "agent", "name"), _get(event, "manager", "name"))
    groups = [str(g) for g in (rule.get("groups") or []) if isinstance(g, str)]
    data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
    decoder = _s(_get(event, "decoder", "name"), 64) or ""
    sev = siem_severity(rule.get("level")) if rule else 1
    log_source = _first(agent_name, event.get("location"))
    full = _s(event.get("full_log"), 4096)

    if rule.get("id") is not None:
        rid = str(rule.get("id"))
        det = _detection_id(ids, rid, UNMAPPED_DETECTION)
        mitre = _get(rule, "mitre", "id")
        techs = [
            t
            for t in (mitre if isinstance(mitre, list) else [])
            if isinstance(t, str) and _TECHNIQUE.fullmatch(t)
        ]
        row = _row(
            "detection_finding",
            event,
            seed,
            now,
            1,
            sev,
            1,
            _first(rule.get("description"), full),
            log_source,
            "siem",
        )
        row.update(
            finding_uid=rid[:128],
            finding_title=_s(rule.get("description")),
            detection_id=det,
            attack_techniques=techs or None,
            host_name=_s(agent_name),
            risk_score=min(100, sev * 20) if sev else None,
        )
        out.append(("detection_finding", _drop_none(row)))

    gset = set(groups)
    if gset & {
        "authentication_success",
        "authentication_failed",
        "authentication_failures",
        "invalid_login",
    } or decoder in {"sshd", "pam"}:
        user = _first(
            data.get("dstuser"),
            data.get("srcuser"),
            _get(data, "win", "eventdata", "targetUserName"),
        )
        ok = "authentication_success" in gset or "accepted" in (full or "").lower()
        fail = bool(gset & {"authentication_failed", "authentication_failures", "invalid_login"})
        if _s(user):
            row = _row(
                "authentication",
                event,
                seed,
                now,
                1,
                1 if ok and not fail else 2,
                1 if ok and not fail else 2,
                _first(rule.get("description"), full),
                log_source,
                "siem",
            )
            row.update(
                user_name=_s(user, 128),
                src_endpoint=_endpoint(data.get("srcip"), data.get("srcport")),
                auth_protocol=decoder or None,
            )
            out.append(("authentication", _drop_none(row)))

    vuln = data.get("vulnerability") if isinstance(data.get("vulnerability"), Mapping) else None
    if vuln and _s(vuln.get("cve")):
        score = _get(vuln, "cvss", "cvss3", "base_score")
        row = _row(
            "vulnerability_finding",
            event,
            seed,
            now,
            1,
            {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(
                str(vuln.get("severity", "")).lower(), 1
            ),
            1,
            _s(vuln.get("title")),
            log_source,
            "siem",
        )
        row.update(
            finding_uid=_s(vuln.get("cve"), 128), cve_uid=_s(vuln.get("cve"), 64),
            cvss_score=float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
            package_name=_s(_get(vuln, "package", "name")), package_version=_s(_get(vuln, "package", "version")),
            host_name=_s(agent_name),
        )  # fmt: skip
        out.append(("vulnerability_finding", _drop_none(row)))

    sca = data.get("sca") if isinstance(data.get("sca"), Mapping) else None
    if sca and (_s(_get(sca, "check", "id")) or _s(_get(sca, "check", "title"))):
        result = str(_get(sca, "check", "result") or "").lower()
        row = _row(
            "compliance_finding",
            event,
            seed,
            now,
            1,
            2 if result == "failed" else 1,
            {"passed": 1, "failed": 2}.get(result, 0),
            _s(_get(sca, "check", "title")),
            log_source,
            "siem",
        )
        row.update(
            finding_uid=_s(_get(sca, "check", "id"), 128), finding_title=_s(_get(sca, "check", "title")),
            compliance_status=result or None, standard=_s(_get(sca, "policy")), host_name=_s(agent_name),
        )  # fmt: skip
        out.append(("compliance_finding", _drop_none(row)))

    sc = event.get("syscheck") if isinstance(event.get("syscheck"), Mapping) else None
    if sc and _s(sc.get("path")):
        act = {"added": 1, "modified": 3, "deleted": 4}.get(str(sc.get("event")), 0)
        row = _row(
            "file_activity",
            event,
            seed,
            now,
            act,
            sev if rule else 1,
            1,
            _first(rule.get("description")),
            log_source,
            "siem",
        )
        row.update(
            file_path=_s(sc.get("path"), 1024), file_hash_sha256=_s(sc.get("sha256_after")),
            user_name=_s(sc.get("uname_after")), host_name=_s(agent_name),
        )  # fmt: skip
        out.append(("file_activity", _drop_none(row)))

    audit = data.get("audit") if isinstance(data.get("audit"), Mapping) else None
    win = _get(data, "win", "eventdata")
    cmd = _first(
        _get(audit, "execve", "a0")
        and " ".join(str(v) for k, v in sorted(audit["execve"].items()) if k != "argc"),
        _get(win, "commandLine"),
    )
    exe = _first(_get(audit, "exe"), _get(win, "image"))
    if _s(exe) or _s(cmd):
        row = _row(
            "process_activity",
            event,
            seed,
            now,
            1,
            sev if rule else 1,
            1,
            _first(rule.get("description")),
            log_source,
            "siem",
        )
        row.update(
            process_name=_s(str(exe).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]) if exe else None,
            process_path=_s(exe, 1024), process_cmd_line=_s(cmd, 4096),
            process_pid=_int(_first(_get(audit, "pid"), _get(win, "processId"))),
            user_name=_s(_first(_get(audit, "auid"), _get(win, "user"))), host_name=_s(agent_name),
        )  # fmt: skip
        out.append(("process_activity", _drop_none(row)))

    if (
        decoder in {"web-accesslog", "json"}
        and (data.get("url") or data.get("protocol"))
        and (data.get("srcip") or data.get("remote_ip"))
    ):
        status = _int(data.get("id"))
        row = _row("http_activity", event, seed, now, 0, 1, 0, full, log_source, "siem")
        row.update(
            http_method=_s(data.get("protocol"), 16) if str(data.get("protocol", "")).isalpha() else None,
            url=_s(data.get("url"), 2048), http_status=status if status and 100 <= status <= 599 else None,
            src_endpoint=_endpoint(_first(data.get("srcip"), data.get("remote_ip"))), host_name=_s(agent_name),
        )  # fmt: skip
        out.append(("http_activity", _drop_none(row)))
    return out


_CEF_HEADER = re.compile(
    r"CEF:(\d+)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|(.*)\Z",
    re.S,
)
_CEF_KEY = re.compile(r"(?:(?<=\s)|^)([A-Za-z][A-Za-z0-9_.]*)=")


def parse_cef(line: str) -> dict[str, Any] | None:
    """The CEF record inside a syslog line (``<PRI>... CEF:0|vendor|product|version|id|name|sev|ext``),
    or None.  Extension values run to the next `` key=``; ``\\|``, ``\\=`` and ``\\\\`` unescape."""
    at = line.find("CEF:")
    m = _CEF_HEADER.match(line, at) if at >= 0 else None
    if not m:
        return None

    def unesc(s: str) -> str:
        return re.sub(r"\\([|\\=])", r"\1", s)

    ext_text = m.group(8)
    keys = list(_CEF_KEY.finditer(ext_text))
    ext: dict[str, str] = {}
    for i, k in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(ext_text)
        ext[k.group(1)] = unesc(ext_text[k.end() : end].strip())
    return {
        "version": m.group(1), "vendor": unesc(m.group(2)), "product": unesc(m.group(3)),
        "product_version": unesc(m.group(4)), "signature_id": unesc(m.group(5)),
        "name": unesc(m.group(6)), "severity": unesc(m.group(7)), "ext": ext,
    }  # fmt: skip


def cef_client(line: str) -> str | None:
    """The client address a CEF record names as its source (``src``), for the collector's
    observed-address rule when the sender is a trusted recorder."""
    cef = parse_cef(line)
    src = cef["ext"].get("src") if cef else None
    return src.strip() if isinstance(src, str) and src.strip() else None


def syslog(
    event: Mapping[str, Any], seed: str, now: datetime, ids: Mapping[str, str]
) -> list[tuple[str, dict[str, Any]]]:
    """A syslog line: CEF (UniFi) becomes a network activity record; a CEF record that carries
    no flow (no ``src``/``dst``) becomes none (the raw archive still holds it)."""
    cef = parse_cef(str(event.get("full_log") or ""))
    if not cef:
        return []
    ext = cef["ext"]
    sev = cef_severity(cef["severity"])
    src = _endpoint(ext.get("src"), ext.get("spt"), ext.get("shost"))
    dst = _endpoint(ext.get("dst"), ext.get("dpt"), ext.get("dhost"))
    if not src or not dst:
        return []
    row = _row(
        "network_activity",
        event,
        seed,
        now,
        6,
        sev,
        1,
        cef["name"],
        _first(ext.get("dvchost"), cef["product"]),
        cef["vendor"] + " " + cef["product"],
    )
    row.update(
        src_endpoint=src, dst_endpoint=dst, protocol_name=_s(ext.get("proto"), 32),
        direction_id={"in": 1, "out": 2}.get(_direction(ext), 0),
        bytes_in=_int(ext.get("in")), bytes_out=_int(ext.get("out")),
    )  # fmt: skip
    return [("network_activity", _drop_none(row))]


def sensor(
    event: Mapping[str, Any], seed: str, now: datetime, ids: Mapping[str, str]
) -> list[tuple[str, dict[str, Any]]]:
    """A Suricata EVE record or a Zeek JSON record."""
    et = event.get("event_type")
    if isinstance(et, str):  # Suricata
        src = _endpoint(event.get("src_ip"), event.get("src_port"))
        dst = _endpoint(event.get("dest_ip"), event.get("dest_port"))
        if et == "alert" and isinstance(event.get("alert"), Mapping):
            alert = event["alert"]
            sig = _s(alert.get("signature_id"), 128) or "0"
            row = _row(
                "detection_finding",
                event,
                seed,
                now,
                1,
                ids_severity(alert),
                1,
                alert.get("signature"),
                "ids-sensor",
                "ids-sensor",
            )
            row.update(
                finding_uid=sig, finding_title=_s(alert.get("signature")),
                detection_id=_detection_id(ids, "ids:" + sig, "det:ids-signature"),
                host_name=None,
            )  # fmt: skip
            return [("detection_finding", _drop_none(row))]
        if et == "http" and src and dst and isinstance(event.get("http"), Mapping):
            h = event["http"]
            row = _row("http_activity", event, seed, now, 0, 1, 0, None, "ids-sensor", "ids-sensor")
            row.update(
                http_method=_s(h.get("http_method"), 16),
                url=_s(h.get("url"), 2048),
                http_status=_int(h.get("status")),
                user_agent=_s(h.get("http_user_agent"), 512),
                src_endpoint=src,
                dst_endpoint=dst,
            )
            return [("http_activity", _drop_none(row))]
        if et == "flow" and src and dst:
            f = event.get("flow") if isinstance(event.get("flow"), Mapping) else {}
            row = _row(
                "network_activity", event, seed, now, 6, 1, 1, None, "ids-sensor", "ids-sensor"
            )
            row.update(
                src_endpoint=src,
                dst_endpoint=dst,
                protocol_name=_s(event.get("proto"), 32),
                bytes_in=_int(f.get("bytes_toclient")),
                bytes_out=_int(f.get("bytes_toserver")),
            )
            return [("network_activity", _drop_none(row))]
        return []
    # Zeek (JSON logs)
    orig, resp = event.get("id.orig_h"), event.get("id.resp_h")
    if orig is None and isinstance(event.get("id"), Mapping):
        orig, resp = _get(event, "id", "orig_h"), _get(event, "id", "resp_h")
        oport, rport = _get(event, "id", "orig_p"), _get(event, "id", "resp_p")
    else:
        oport, rport = event.get("id.orig_p"), event.get("id.resp_p")
    src, dst = _endpoint(orig, oport), _endpoint(resp, rport)
    if not src or not dst:
        return []
    if "query" in event and ("qtype_name" in event or "rcode" in event):
        q = _s(event.get("query"), 253)
        if not q:
            return []
        answers = event.get("answers")
        row = _row(
            "dns_activity", event, seed, now, 1, 1, 1, None, "network-monitor", "network-monitor"
        )
        row.update(
            src_endpoint=src, query_hostname=q, query_type=_s(event.get("qtype_name"), 16),
            rcode_id=_int(event.get("rcode")),
            answers=[str(a)[:256] for a in answers if isinstance(a, (str, int))] if isinstance(answers, list) else None,
        )  # fmt: skip
        return [("dns_activity", _drop_none(row))]
    if "method" in event and ("uri" in event or "host" in event):
        row = _row(
            "http_activity", event, seed, now, 0, 1, 0, None, "network-monitor", "network-monitor"
        )
        row.update(
            http_method=_s(event.get("method"), 16), url=_s(event.get("uri"), 2048), http_status=_int(event.get("status_code")),
            user_agent=_s(event.get("user_agent"), 512), src_endpoint=src, dst_endpoint=dst, host_name=_s(event.get("host")),
        )  # fmt: skip
        return [("http_activity", _drop_none(row))]
    if "proto" in event and ("conn_state" in event or "orig_bytes" in event or "duration" in event):
        row = _row(
            "network_activity",
            event,
            seed,
            now,
            6,
            1,
            1,
            None,
            "network-monitor",
            "network-monitor",
        )
        row.update(
            src_endpoint=src, dst_endpoint=dst, protocol_name=_s(event.get("proto"), 32), connection_uid=_s(event.get("uid"), 128),
            direction_id=0, bytes_out=_int(event.get("orig_bytes")), bytes_in=_int(event.get("resp_bytes")),
        )  # fmt: skip
        return [("network_activity", _drop_none(row))]
    return []


MAPPERS = {"siem": siem, "syslog": syslog, "sensor": sensor}


def event_time(event: Mapping[str, Any], kind: str, now: datetime) -> str:
    """The event's own time (its field for its kind), else the receive time."""
    if kind == "siem":
        raw = event.get("timestamp")
    elif kind == "syslog":
        cef = parse_cef(str(event.get("full_log") or ""))
        raw = cef["ext"].get("rt") if cef else None
        raw = raw or event.get("timestamp")
    else:
        raw = _first(event.get("timestamp"), event.get("ts"))
    return parse_time(raw, now)


def map_event(
    event: Mapping[str, Any],
    kind: str,
    route: str,
    now: datetime,
    ids: Mapping[str, str] | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """The rows (table, row) for one enriched event of ``kind``.  The raw archive row comes
    first; a mapper that fails on an odd record never costs the raw row (the caller counts it)."""
    ev = dict(event)
    ev["_time"] = event_time(event, kind, now)
    seed = seed_of(route, {k: v for k, v in event.items() if k != "labels"})
    loc = event.get("location")
    raw = _drop_none({
        "uid": uid_for(seed, RAW_TABLE),
        "time": ev["_time"],
        "route": route,
        "source_kind": kind,
        "location": _s(loc, 512),
        "decoder_name": _s(_get(event, "decoder", "name"), 128),
        "agent_id": _s(_get(event, "agent", "id"), 64),
        "agent_name": _s(_get(event, "agent", "name"), 256),
        "rule_id": _s(_get(event, "rule", "id"), 64),
        "full_log": _s(event.get("full_log"), 8192),
        "raw": json.dumps({k: v for k, v in event.items() if k != "labels"}, sort_keys=True, separators=(",", ":"), default=str)[:65536],
        "labels": _labels(event),
    })  # fmt: skip
    rows = [(RAW_TABLE, raw)]
    rows += MAPPERS[kind](ev, seed, now, ids or {})
    return rows
