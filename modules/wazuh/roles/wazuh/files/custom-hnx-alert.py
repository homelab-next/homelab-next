#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: wazuh-alert-forward
#   kind: tool
#   purpose: Post each SIEM alert at or above the integration's level to the events forwarder as a homelabnext.alert.created event, and keep what could not be delivered for the next run.
#   owner: platform
#   trigger: [role:wazuh]
#   inputs: "ALERT_FILE API_KEY HOOK_URL (the integration daemon's arguments); hnx-alert.json (source, tlp, detections) and hnx-alert.auth (the Authorization header value) beside the script"
#   outputs: one CloudEvents JSON POST to HOOK_URL; undelivered events in the outbox directory; a line on stderr per outcome
#   exit:
#     "0": delivered, held for the next run, or refused as permanent (the reason on stderr)
#     "2": usage error or an unreadable alert
"""The alert webhook of the wazuh module (modules/wazuh/README.md, "The alert webhook").

Runs inside the manager container under the product's own Python (standard library only).  The
event id is ``evt-`` and the first 32 hex digits of the SHA-256 of the JSON array
[type, source, subject or "", alert id], the same function as ``homelabnext.events.derive_event_id``
(a test holds the two together), so a re-run of the same alert is the same event and the forwarder
answers *duplicate*.  The credential is read from ``hnx-alert.auth`` and goes only in the
Authorization header; the TLP label is the SIEM source's declaration (``hnx-alert.json``), never
the event's.  Redirects are never followed (a POST resent as a GET would read as delivered).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

_UTC = timezone(timedelta(0))  # the product's own Python is 3.10: no UTC alias
TYPE = "homelabnext.alert.created"
SCHEMA = "https://schemas.example.internal/homelabnext/events/alert.created/1.2"
HERE = os.path.dirname(os.path.abspath(__file__))
OUTBOX = os.environ.get("HNX_ALERT_OUTBOX", "/var/ossec/logs/hnx-alert-outbox")
OUTBOX_MAX = 500
RETRY = {
    408,
    425,
    429,
    401,
    403,
    404,
    421,
}  # transient or fixable by configuration: held, not dropped
ENTITY_FIELDS = (
    ("host", ("agent", "name")),
    ("ip", ("data", "srcip")),
    ("ip", ("data", "dstip")),
    ("user", ("data", "srcuser")),
    ("user", ("data", "dstuser")),
    ("domain", ("data", "query")),
    ("hash", ("syscheck", "sha256_after")),
    ("process", ("data", "win", "eventdata", "image")),
)


def derive_id(source: str, dedupe_key: str) -> str:
    material = json.dumps([TYPE, source, "", dedupe_key], separators=(",", ":"), ensure_ascii=True)
    return "evt-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def severity(level: int) -> str:
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 8:
        return "medium"
    if level >= 5:
        return "low"
    return "info"


def _timestamp(value: str | None) -> str:
    if value and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{4}", value):
        return value[:-2] + ":" + value[-2:]
    if value and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})", value
    ):
        return value
    return datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dig(obj: dict, path: tuple[str, ...]):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj if isinstance(obj, str) and obj else None


def entities(alert: dict) -> list[dict]:
    seen, out = set(), []
    for kind, path in ENTITY_FIELDS:
        value = _dig(alert, path)
        if value and (kind, value) not in seen:
            seen.add((kind, value))
            out.append({"kind": kind, "value": value[:256]})
    return out[:50]


def build(alert: dict, cfg: dict) -> dict:
    rule = alert.get("rule") or {}
    rid = str(rule.get("id", ""))
    alert_id = re.sub(r"[^A-Za-z0-9._-]", "-", str(alert.get("id") or rid or "unknown"))[:64]
    source = cfg["source"]
    det = (cfg.get("detections") or {}).get(
        rid
    ) or f"det:wazuh-rule-{re.sub(r'[^0-9a-z]', '', rid) or 'unknown'}"
    sev = severity(int(rule.get("level", 0) or 0))
    data = {
        "alert_id": alert_id,
        "detection": det,
        "title": (str(rule.get("description") or f"Wazuh rule {rid}")[:200]) or "Wazuh alert",
        "severity": sev,
        "observed_at": _timestamp(alert.get("timestamp")),
    }
    ents = entities(alert)
    if ents:
        data["entities"] = ents
    return {
        "specversion": "1.0",
        "id": derive_id(source, alert_id),
        "source": source,
        "type": TYPE,
        "time": datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "severity": sev,
        "datacontenttype": "application/json",
        "dataschema": SCHEMA,
        "tlp": cfg.get("tlp", "red"),
        "data": data,
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a 3xx is an HTTPError for the caller to hold
        return None


def post(url: str, auth: str, event: dict, timeout: float = 10.0) -> str:
    """'sent', 'held' (retry later) or 'dropped' (permanent), never raises on a refusal."""
    req = urllib.request.Request(
        url,
        data=json.dumps(event, sort_keys=True).encode(),
        method="POST",
        headers={
            "Content-Type": "application/cloudevents+json",
            "Idempotency-Key": event["id"],
            "Authorization": auth,
        },
    )
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return "sent" if resp.status in (200, 201, 202, 204) else "held"
    except urllib.error.HTTPError as exc:
        if exc.code in RETRY or exc.code >= 500 or 300 <= exc.code < 400:
            return "held"
        return "dropped"
    except (urllib.error.URLError, OSError, TimeoutError):
        return "held"


def _spool(event: dict) -> None:
    os.makedirs(OUTBOX, mode=0o750, exist_ok=True)
    held = sorted(os.listdir(OUTBOX))
    for old in held[: max(0, len(held) - OUTBOX_MAX + 1)]:  # bounded: the oldest give way
        os.unlink(os.path.join(OUTBOX, old))
    path = os.path.join(OUTBOX, event["id"] + ".json")
    with open(path + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(event, fh, sort_keys=True)
    os.replace(path + ".tmp", path)


def flush(url: str, auth: str) -> None:
    if not os.path.isdir(OUTBOX):
        return
    for name in sorted(os.listdir(OUTBOX)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(OUTBOX, name)
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)
        outcome = post(url, auth, event)
        if outcome == "held":
            return  # the forwarder is unreachable: keep order, try again next run
        os.unlink(path)


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: custom-hnx-alert ALERT_FILE API_KEY HOOK_URL", file=sys.stderr)
        return 2
    alert_file, _api_key, url = argv[1], argv[2], argv[3]
    try:
        with open(alert_file, encoding="utf-8") as fh:
            alert = json.load(fh)
        with open(os.path.join(HERE, "hnx-alert.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
        with open(os.path.join(HERE, "hnx-alert.auth"), encoding="utf-8") as fh:
            auth = fh.read().strip()
    except (OSError, ValueError) as exc:
        print(f"hnx-alert: cannot read an input ({type(exc).__name__})", file=sys.stderr)
        return 2
    event = build(alert, cfg)
    flush(url, auth)
    outcome = post(url, auth, event)
    if outcome == "held":
        _spool(event)
    print(f"hnx-alert: {event['id']} {outcome}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
