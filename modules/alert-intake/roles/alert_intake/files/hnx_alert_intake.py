#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: alert-intake
#   kind: service
#   purpose: Receive the SIEM's alert events over an authenticated webhook, deduplicate them, record each as an alert in the case-management provider through the cases contract, and page for high severity.
#   owner: operator
#   trigger: [role:alert_intake]
#   inputs: alert.created events posted to /v1/alerts (bearer token), the cases adapter named by the environment, the state file
#   outputs: alerts (and, by the promotion policy, cases) through the cases contract, notifications, the state file, and journal lines
#   installs_to: /usr/local/libexec/homelabnext/hnx-alert-intake
#   exit:
#     "0": stopped on SIGTERM
#     "2": refused to start (an input is missing or malformed)
"""alert-intake: the SIEM's alerts become alerts in the case store (ADR-0049 decision 5).

One event is one ``homelabnext.alert.created`` document (CloudEvents structured JSON, schema
``events/alert.created`` 1.2) posted to ``/v1/alerts`` with ``Authorization: Bearer <token>``.

* **Only the SIEM may raise an alert**: the event's ``source`` must equal the configured source,
  or it is refused (403), however valid the token.
* **Idempotent by event id**: a redelivery of an id already handled is answered from the state
  file and runs nothing again; the same id with a different body is refused (409).  The
  progress of each event (alert recorded, promoted, paged) is saved as it happens, so a retry
  after a downstream failure (502) resumes where it stopped and never double-counts or re-pages.
* **Deduplicated** on ``detection`` plus the sorted ``entities`` (the key the ADR names): a repeat
  while the alert is still new collapses into it and raises its count (the contract's rule, done by
  the case store).  A repeat never pages.
* **Alerts, not cases**: the alert is recorded with ``create_alert``; ``promote`` runs only when
  the overlay's promotion policy names a severity and the alert reaches it (default: never).
* **Paging is conservative**: a NEW alert (count 1) at or above the paging severity (default
  ``high``) is sent once through the shared notification sender (``homelabnext.notify``).  Canary alerts (a detection id under the
  canary prefix) are recorded, dismissed with the reason ``canary`` and never page.

The cases adapter is the site's: ``ALERT_INTAKE_CASES_ADAPTER`` is ``package.module:factory`` and
its settings are the JSON object in ``ALERT_INTAKE_CASES_CONFIG_FILE``; the directory the adapter is
installed in is ``ALERT_INTAKE_ADAPTER_PATH`` and the one holding the shared libraries ``ALERT_INTAKE_LIB_PATH``.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import importlib
import json
import logging
import os
import re
import signal
import ssl
import sys
import threading
import time
import urllib.request
from typing import Any

# the shared libraries (notify, state) are installed beside the adapter by the role
_LIB = os.environ.get("ALERT_INTAKE_LIB_PATH", "")
if _LIB:
    sys.path.insert(0, _LIB)
from homelabnext._http import send_json  # noqa: E402
from homelabnext.notify import Message, default_sender  # noqa: E402
from homelabnext.state import StateStore  # noqa: E402

LOG = logging.getLogger("alert-intake")
EVENT_TYPE = "homelabnext.alert.created"
SEVERITY_RANK = {"info": 0, "low": 0, "medium": 1, "high": 2, "critical": 3}
CASE_SEVERITY = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
MAX_BODY = 256 * 1024
MAX_SEEN = 5000
_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_DET = re.compile(r"det:[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_ALERT_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
_ENTITY_KINDS = ("host", "user", "ip", "domain", "hash", "process")


class Refused(Exception):
    """The event is refused; ``status`` is the HTTP answer (400, 403 or 409)."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Downstream(Exception):
    """A dependency failed; the sender should retry (HTTP 502)."""


def validate(event: Any, allowed_source: str) -> dict[str, Any]:
    """The event as a dict, or :class:`Refused`.  The checks are the schema's, spelled out."""

    def bad(why: str) -> Refused:
        return Refused(400, why)

    if not isinstance(event, dict):
        raise bad("the body is not a JSON object")
    if event.get("specversion") != "1.0":
        raise bad("specversion must be 1.0")
    if event.get("type") != EVENT_TYPE:
        raise bad(f"type must be {EVENT_TYPE}")
    if not isinstance(event.get("id"), str) or not _ID.fullmatch(event["id"]):
        raise bad("id is missing or malformed")
    if not isinstance(event.get("time"), str) or not _TIME.fullmatch(event["time"]):
        raise bad("time is missing or malformed")
    data = event.get("data")
    if not isinstance(data, dict):
        raise bad("data is missing")
    if not isinstance(data.get("alert_id"), str) or not _ALERT_ID.fullmatch(data["alert_id"]):
        raise bad("data.alert_id is missing or malformed")
    if not isinstance(data.get("detection"), str) or not _DET.fullmatch(data["detection"]):
        raise bad("data.detection must be a det: id")
    title = data.get("title")
    if not isinstance(title, str) or not 1 <= len(title) <= 200:
        raise bad("data.title must be 1 to 200 characters")
    if data.get("severity") not in SEVERITY_RANK:
        raise bad("data.severity is not one of info, low, medium, high, critical")
    if not isinstance(data.get("observed_at"), str) or not _TIME.fullmatch(data["observed_at"]):
        raise bad("data.observed_at is missing or malformed")
    entities = data.get("entities", [])
    if not isinstance(entities, list) or len(entities) > 50:
        raise bad("data.entities must be a list of at most 50")
    for e in entities:
        if (
            not isinstance(e, dict)
            or e.get("kind") not in _ENTITY_KINDS
            or not isinstance(e.get("value"), str)
            or not 1 <= len(e["value"]) <= 256
        ):
            raise bad("data.entities holds a malformed entity")
    # the source rule comes after the shape, but a foreign source never reaches the case store
    if event.get("source") != allowed_source:
        raise Refused(403, "the event's source is not the SIEM's")
    return event


def dedup_key(data: dict[str, Any]) -> str:
    """``detection`` plus the sorted entities, hashed (ADR-0049 decision 5)."""
    ents = sorted(f"{e['kind']}:{e['value']}" for e in data.get("entities", []))
    text = "\n".join([data["detection"], *ents])
    return "hnx-" + hashlib.sha256(text.encode()).hexdigest()[:40]


def _digest(event: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class State:
    """Per-event progress in the shared state store (crash-safe, locked); bounded to the newest
    MAX_SEEN events.  A corrupt file is refused (the service does not start), never started empty:
    an empty state would let a redelivered event be counted twice."""

    def __init__(self, path: str):
        self.store = StateStore(path, quarantine=False)

    def get(self, event_id: str) -> dict[str, Any] | None:
        return self.store.get(event_id)

    def put(self, event_id: str, rec: dict[str, Any]) -> None:
        self.store.put(event_id, rec)
        if len(self.store.keys()) > MAX_SEEN + 100:
            self.store.rewrite(_prune)


def _prune(data: dict[str, Any]) -> bool:
    drop = sorted(data, key=lambda k: data[k].get("at", 0))[: max(0, len(data) - MAX_SEEN)]
    for k in drop:
        del data[k]
    return bool(drop)


class Intake:
    """The event handler: a case store, a pager and the policy, with no network of its own."""

    def __init__(
        self,
        store: Any,
        pager: Any,
        state: State,
        *,
        allowed_source: str,
        page_min: str = "high",
        promote_min: str = "",
        canary_prefix: str = "det:canary",
    ):
        self.store, self.pager, self.state = store, pager, state
        self.allowed_source = allowed_source
        if page_min not in SEVERITY_RANK or (promote_min and promote_min not in SEVERITY_RANK):
            raise ValueError("severity threshold is not one of info, low, medium, high, critical")
        self.page_min, self.promote_min, self.canary_prefix = page_min, promote_min, canary_prefix
        self._lock = threading.Lock()  # one event at a time: the dedup read-then-bump is not atomic

    def handle(self, body: Any) -> dict[str, Any]:
        event = validate(body, self.allowed_source)
        data, digest = event["data"], _digest(event)
        with self._lock:
            rec = self.state.get(event["id"])
            if rec and rec["digest"] != digest:
                raise Refused(409, "this event id was handled with a different body")
            duplicate = bool(rec and rec.get("done"))
            if rec is None:
                rec = {"digest": digest, "done": False, "at": time.time()}
            canary = data["detection"].startswith(self.canary_prefix)
            if not duplicate:
                self._run(event, rec, canary)
            return {
                "alert": rec["alert"], "count": rec.get("count", 1), "paged": rec.get("paged", False),
                "case": rec.get("case"), "duplicate": duplicate,
            }  # fmt: skip

    def _run(self, event: dict[str, Any], rec: dict[str, Any], canary: bool) -> None:
        data, eid = event["data"], event["id"]
        try:
            if "alert" not in rec:
                alert = self.store.create_alert(
                    event["source"], data["title"], CASE_SEVERITY[data["severity"]],
                    dedup_key=dedup_key(data),
                )  # fmt: skip
                rec.update(alert=alert.id, count=alert.count)
                self.state.put(eid, rec)
            if canary:
                if not rec.get("dismissed"):
                    self.store.dismiss(rec["alert"], "canary")
                    rec["dismissed"] = True
            else:
                self._policy(eid, data, rec)
            rec["done"] = True
        except Refused:
            raise
        except Exception as exc:
            # whatever the case store or the pager raised: progress is kept, the sender retries
            self.state.put(eid, rec)
            raise Downstream(f"{type(exc).__name__}: {str(exc)[:160]}") from None
        self.state.put(eid, rec)

    def _policy(self, eid: str, data: dict[str, Any], rec: dict[str, Any]) -> None:
        rank = SEVERITY_RANK[data["severity"]]
        if self.promote_min and rank >= SEVERITY_RANK[self.promote_min] and "case" not in rec:
            rec["case"] = self.store.promote(rec["alert"]).id
            self.state.put(eid, rec)
        if (
            rec.get("count", 1) == 1
            and rank >= SEVERITY_RANK[self.page_min]
            and not rec.get("paged")
        ):
            self.pager(data, rec["alert"])
            rec["paged"] = True
            self.state.put(eid, rec)


def make_pager(base_url: str, topic: str, token: str, ca_file: str | None, plaintext: bool) -> Any:
    """The page: one message through the shared notification sender (bearer-authenticated, no
    redirect, a private CA for https), a failure raised as :class:`SendError`."""
    opener = None
    if ca_file:
        ctx = ssl.create_default_context(cafile=ca_file)
        op = urllib.request.build_opener(
            _NoRedirect, urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx)
        )
        opener = lambda req, timeout=None: op.open(req, timeout=timeout)  # noqa: E731
    sender = default_sender(
        endpoint=base_url,
        default_topic=topic,
        auth=(lambda: f"Bearer {token}") if token else None,
        opener=opener,
        allow_plaintext=plaintext,
    )

    def page(data: dict[str, Any], alert_id: str) -> None:
        ents = ", ".join(f"{e['kind']}={e['value']}" for e in data.get("entities", [])[:5])
        text = f"{data['detection']} ({data['severity']}): {data['title']}"
        if ents:
            text += f"\n{ents}"
        text += f"\ncase store alert {alert_id}"
        sender.send(
            Message(
                key=f"alert-{alert_id}",
                title=f"alert: {data['title']}",
                body=text,
                level="crit" if data["severity"] == "critical" else "warn",
                tags=("rotating_light", data["severity"]),
            )
        )

    return page


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # a 3xx is the answer, never followed
        return None


def _handler(intake: Intake, token: str) -> type[http.server.BaseHTTPRequestHandler]:
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "alert-intake"
        sys_version = ""

        def _send(self, status: int, doc: dict[str, Any]) -> None:
            send_json(self, status, doc)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/v1/alerts":
                self._send(404, {"error": "not found"})
                return
            given = self.headers.get("Authorization", "")
            if not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
                self._send(401, {"error": "unauthorised"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if not 0 < length <= MAX_BODY:
                self._send(413 if length > MAX_BODY else 400, {"error": "bad length"})
                return
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError:
                self._send(400, {"error": "not JSON"})
                return
            try:
                self._send(202, intake.handle(body))
            except Refused as exc:
                self._send(exc.status, {"error": str(exc)})
            except Downstream as exc:
                LOG.error("downstream failure: %s", exc)
                self._send(502, {"error": "downstream failure, retry"})

        def log_message(self, fmt: str, *args: Any) -> None:
            LOG.info("%s %s", self.address_string(), fmt % args)

    return H


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise SystemExit(f"alert-intake: {name} is not set")
    return value


def build() -> tuple[Intake, http.server.ThreadingHTTPServer]:
    adapter_path = os.environ.get("ALERT_INTAKE_ADAPTER_PATH", "")
    if adapter_path:
        sys.path.insert(0, adapter_path)
    module, _, attr = _env("ALERT_INTAKE_CASES_ADAPTER").partition(":")
    with open(_env("ALERT_INTAKE_CASES_CONFIG_FILE"), encoding="utf-8") as f:
        config = json.load(f)
    store = getattr(importlib.import_module(module), attr)(**config)
    pager = make_pager(
        _env("ALERT_INTAKE_NOTIFY_URL"),
        _env("ALERT_INTAKE_NOTIFY_TOPIC"),
        os.environ.get("ALERT_INTAKE_NOTIFY_TOKEN", ""),
        os.environ.get("ALERT_INTAKE_NOTIFY_CA_FILE") or None,
        os.environ.get("ALERT_INTAKE_NOTIFY_PLAINTEXT", "") == "true",
    )
    intake = Intake(
        store, pager, State(_env("ALERT_INTAKE_STATE_FILE")),
        allowed_source=_env("ALERT_INTAKE_ALLOWED_SOURCE"),
        page_min=os.environ.get("ALERT_INTAKE_PAGE_MIN", "high"),
        promote_min=os.environ.get("ALERT_INTAKE_PROMOTE_MIN", ""),
        canary_prefix=os.environ.get("ALERT_INTAKE_CANARY_PREFIX", "det:canary"),
    )  # fmt: skip
    server = http.server.ThreadingHTTPServer(
        (_env("ALERT_INTAKE_LISTEN_HOST"), int(_env("ALERT_INTAKE_LISTEN_PORT"))),
        _handler(intake, _env("ALERT_INTAKE_TOKEN")),
    )
    return intake, server


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    try:
        _, server = build()
    except (
        SystemExit,
        ValueError,
        OSError,
        ImportError,
        AttributeError,
        KeyError,
        TypeError,
    ) as exc:
        LOG.error("cannot start: %s", exc if isinstance(exc, SystemExit) else type(exc).__name__)
        return 2
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown).start())
    LOG.info("listening on %s:%s", *server.server_address[:2])
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
