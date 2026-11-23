# SPDX-License-Identifier: Apache-2.0
"""The ``cases`` contract on DFIR-IRIS (pinned: 2.4.29), stdlib HTTP.

``make(**config)`` returns an :class:`IrisCases`, a :class:`conformance.protocols.cases.CaseStore`
over the product's REST API (the one its web interface and its own tools use), shapes recorded from
a live 2.4.29 instance (``conformance/fakes/iris_api.py`` is the loopback stand-in built from them).

Mapping (the contract's words -> the product's):

* an *alert* is a product alert.  ``new`` is the product's New, Assigned, In progress and Pending
  (no human has dispositioned it); ``promoted`` is Escalated (a case exists); ``dismissed`` is
  Closed or Merged.  The dedup key is the alert's ``alert_source_ref`` (a tag of its hash lets the
  product's tag filter find it) and the collapse count is ``alert_context.hnx_count``.  A dismissal
  reason is ``alert_context.hnx_reason`` and the alert's note.
* promotion is the product's *escalate* call; a *case* is the product's case.  ``open`` is its state
  Open, ``in_progress`` its state In progress, ``closed`` its state Closed.
* notes live in the case's note directory ``hnx`` (title = author, content = text, oldest first by
  note id); the resolution of a closed case is the last note of the directory ``hnx-resolution``
  (the product's close call takes no text and its closing-note field is not writable by the API).
* severities are resolved by NAME from the instance's own list, never by number: this product's
  numbers are not in severity order (Medium is 1, Low is 4).

Limits of the product, not of this adapter: the dedup read-then-bump is not atomic, so two writers
that open the same new key within one round trip can leave two alerts (one writer, the
alert-intake service, is the supported shape); an alert changed by a person in the web interface is
read back by its product status; a closed case rejects a note here, not in the product.

Settings: ``base_url`` (else ``HNX_ENDPOINT_CASE_MANAGEMENT``, never a default), ``credential`` (``secret:<name>``,
read from ``HNX_SECRET_<NAME>`` at every request), ``ca_file`` (the lab CA), ``customer_id``
(default 1), ``timeout``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from conformance.protocols.cases import (
    SEVERITIES,
    Alert,
    Case,
    CaseClosed,
    CasesError,
    InvalidTransition,
    NotFound,
)

__all__ = ["IrisCases", "make", "make_recorded"]

# stdlib and the contract file only: alert-intake runs this on a guest that has no homelabnext
# package (its role installs conformance/protocols/cases.py beside the adapter)
DEFAULT_MAX_BYTES = 1 << 20  # 1 MiB
_SECRET_REF = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # a 3xx is the answer, never followed
        return None


def _opener(ca_file: str | None) -> urllib.request.OpenerDirector:
    """Verified https (``ca_file`` for the lab CA), no redirect, no proxy: the request carries the key."""
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    return urllib.request.build_opener(
        _NoRedirect, urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx)
    )


def _read_bounded(resp: Any, limit: int) -> bytes:
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"response larger than {limit} bytes")
    return data


def _credential_reader(ref: Any) -> Callable[[], str]:
    """The reader of a ``secret:<name>`` setting: the key is in ``HNX_SECRET_<NAME>``, read at
    every request so the adapter never holds it."""
    if not isinstance(ref, str) or not _SECRET_REF.fullmatch(ref):
        raise ValueError("credential is a secret name (secret:<name>), never a value")
    var = "HNX_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", ref.removeprefix("secret:")).upper()
    if not os.environ.get(var):
        raise ValueError(f"credential variable {var} is not set")
    return lambda: os.environ.get(var, "")


NOTE_DIR = "hnx"
RESOLUTION_DIR = "hnx-resolution"
_NEW_STATUSES = ("New", "Assigned", "In progress", "Pending")
_DISMISSED_STATUSES = ("Closed", "Merged")
_NAME_PREFIX = re.compile(r"^#\d+\s+-\s+")
_NEXT = {"open": ("in_progress", "closed"), "in_progress": ("closed",), "closed": ("open",)}
_STATE_TO_STATUS = {"In progress": "in_progress", "Closed": "closed"}
_STATUS_TO_STATE = {"open": "Open", "in_progress": "In progress"}


class IrisCases:
    """A ``CaseStore`` on one DFIR-IRIS instance."""

    features = frozenset()

    def __init__(
        self,
        base_url: str,
        *,
        token: Callable[[], str] | None,
        ca_file: str | None = None,
        customer_id: int = 1,
        timeout: float = 20.0,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        if token is None:
            raise ValueError("a credential (secret:<name>) is required")
        self._base = f"{parts.scheme}://{parts.netloc}"
        self._token = token
        self._opener = _opener(ca_file)
        self._customer = int(customer_id)
        self._limits = (timeout, max_bytes)
        self._lookups: dict[str, dict[str, int]] = {}

    def __repr__(self) -> str:
        return f"IrisCases({self._base!r})"

    def close(self) -> None:  # the harness's teardown; nothing is held
        return None

    # -- transport ---------------------------------------------------------------------------

    def _call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        key = self._token()
        if not key or any(c in key for c in "\r\n\0"):
            raise CasesError("no credential that can be sent as a header")
        data = None if body is None else json.dumps(body).encode()
        headers = {
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(self._base + path, data=data, headers=headers, method=method)
        timeout, max_bytes = self._limits
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw, status = _read_bounded(resp, max_bytes), resp.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(DEFAULT_MAX_BYTES), exc.code
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise CasesError(f"{method} {path.split('?')[0]}: {type(exc).__name__}") from None
        try:
            return status, json.loads(raw.decode("utf-8"))
        except ValueError:
            return status, None

    def _ok(self, method: str, path: str, body: Any = None) -> Any:
        status, doc = self._call(method, path, body)
        if status != 200 or not isinstance(doc, dict) or doc.get("status") != "success":
            msg = doc.get("message") if isinstance(doc, dict) else ""
            raise CasesError(f"{method} {path.split('?')[0]}: HTTP {status} {str(msg)[:120]}")
        return doc.get("data")

    def _lookup(self, kind: str, path: str, id_key: str, name_key: str) -> dict[str, int]:
        if kind not in self._lookups:
            rows = self._ok("GET", path) or []
            self._lookups[kind] = {str(r[name_key]): int(r[id_key]) for r in rows}
        return self._lookups[kind]

    def _severity_id(self, name: str) -> int:
        ids = self._lookup("sev", "/manage/severities/list", "severity_id", "severity_name")
        return ids[name.capitalize()]

    def _alert_status_id(self, name: str) -> int:
        ids = self._lookup("ast", "/manage/alert-status/list", "status_id", "status_name")
        return ids[name]

    def _state_id(self, name: str) -> int:
        ids = self._lookup("cst", "/manage/case-states/list", "state_id", "state_name")
        return ids[name]

    # -- alerts ------------------------------------------------------------------------------

    @staticmethod
    def _num(value: str, what: str) -> int:
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,12}", value):
            raise NotFound(f"{what} {str(value)[:40]!r}")
        return int(value)

    @staticmethod
    def _tag(dedup_key: str) -> str:
        return "hnx-dk-" + hashlib.sha256(dedup_key.encode()).hexdigest()[:32]

    def _alert(self, doc: dict) -> Alert:
        status_name = (doc.get("status") or {}).get("status_name", "")
        context = doc.get("alert_context") if isinstance(doc.get("alert_context"), dict) else {}
        cases = doc.get("cases") or []
        if status_name == "Escalated":
            status = "promoted"
        elif status_name in _DISMISSED_STATUSES:
            status = "dismissed"
        else:
            status = "new"
        sev = (doc.get("severity") or {}).get("severity_name", "").lower()
        return Alert(
            id=str(doc["alert_id"]),
            source=str(doc.get("alert_source") or ""),
            title=str(doc.get("alert_title") or ""),
            severity=sev if sev in SEVERITIES else "medium",
            status=status,
            count=int(context.get("hnx_count", 1)),
            case_id=str(cases[0]) if cases else None,
            reason=context.get("hnx_reason") if status == "dismissed" else None,
        )

    def _raw_alert(self, alert_id: str) -> dict:
        n = self._num(alert_id, "alert")
        status, doc = self._call("GET", f"/alerts/{n}")
        if status in (400, 404) or (isinstance(doc, dict) and doc.get("status") == "error"):
            raise NotFound(f"alert {alert_id}")
        if status != 200 or not isinstance(doc, dict):
            raise CasesError(f"GET /alerts/{n}: HTTP {status}")
        return doc["data"]

    def create_alert(
        self, source: str, title: str, severity: str, *, dedup_key: str | None = None
    ) -> Alert:
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if not source or not title:
            raise ValueError("source and title are required")
        if dedup_key:
            found = self._find_open(dedup_key)
            if found is not None:
                ctx = dict(found.get("alert_context") or {})
                ctx["hnx_count"] = int(ctx.get("hnx_count", 1)) + 1
                data = self._ok(
                    "POST", f"/alerts/update/{found['alert_id']}", {"alert_context": ctx}
                )
                return self._alert(data)
        body = {
            "alert_title": title[:250],
            "alert_description": title,
            "alert_severity_id": self._severity_id(severity),
            "alert_status_id": self._alert_status_id("New"),
            "alert_source": source[:250],
            "alert_source_ref": dedup_key or "",
            "alert_customer_id": self._customer,
            "alert_tags": self._tag(dedup_key) if dedup_key else "",
            "alert_context": {"hnx_count": 1},
        }
        return self._alert(self._ok("POST", "/alerts/add", body))

    def _find_open(self, dedup_key: str) -> dict | None:
        q = urllib.parse.urlencode(
            {"alert_tags": self._tag(dedup_key), "alert_status_id": self._alert_status_id("New")}
        )
        data = self._ok("GET", f"/alerts/filter?{q}") or {}
        for doc in data.get("alerts", []):  # the tag filter is a substring match: confirm exactly
            if doc.get("alert_source_ref") == dedup_key:
                return doc
        return None

    def get_alert(self, alert_id: str) -> Alert:
        return self._alert(self._raw_alert(alert_id))

    def list_alerts(self, status: str | None = None) -> list[Alert]:
        if status is None:
            names: tuple[str, ...] | None = None
        elif status == "new":
            names = _NEW_STATUSES
        elif status == "promoted":
            names = ("Escalated",)
        elif status == "dismissed":
            names = _DISMISSED_STATUSES
        else:
            return []
        out: dict[str, Alert] = {}
        for name in names or (None,):
            page = 1
            while True:
                params = {"page": page, "per_page": 100, "sort": "asc"}
                if name:
                    params["alert_status_id"] = self._alert_status_id(name)
                data = self._ok("GET", "/alerts/filter?" + urllib.parse.urlencode(params)) or {}
                for doc in data.get("alerts", []):
                    out[str(doc["alert_id"])] = self._alert(doc)
                if not data.get("next_page"):
                    break
                page = int(data["next_page"])
        return sorted(out.values(), key=lambda a: int(a.id))

    def promote(self, alert_id: str, title: str | None = None) -> Case:
        doc = self._raw_alert(alert_id)
        alert = self._alert(doc)
        if alert.status == "promoted" and alert.case_id:
            return self.get_case(alert.case_id)
        if alert.status == "dismissed":
            raise InvalidTransition("a dismissed alert cannot be promoted")
        body = {
            "iocs_import_list": [],
            "assets_import_list": [],
            "escalation_note": "",
            "case_title": (title or alert.title)[:250],
            "import_as_event": False,
            "case_tags": "",
        }
        case = self._ok("POST", f"/alerts/escalate/{int(alert.id)}", body)
        return self.get_case(str(case["case_id"]))

    def dismiss(self, alert_id: str, reason: str) -> Alert:
        doc = self._raw_alert(alert_id)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a dismissal needs a reason")
        alert = self._alert(doc)
        if alert.status == "promoted":
            raise InvalidTransition("a promoted alert cannot be dismissed")
        ctx = dict(doc.get("alert_context") or {})
        ctx["hnx_reason"] = reason.strip()
        body = {
            "alert_status_id": self._alert_status_id("Closed"),
            "alert_note": f"Dismissed: {reason.strip()}"[:2000],
            "alert_context": ctx,
        }
        return self._alert(self._ok("POST", f"/alerts/update/{int(alert.id)}", body))

    # -- cases -------------------------------------------------------------------------------

    def _raw_case(self, case_id: str) -> dict:
        n = self._num(case_id, "case")
        status, doc = self._call("GET", f"/manage/cases/{n}")
        if status in (400, 404) or (isinstance(doc, dict) and doc.get("status") == "error"):
            raise NotFound(f"case {case_id}")
        if status != 200 or not isinstance(doc, dict):
            raise CasesError(f"GET /manage/cases/{n}: HTTP {status}")
        return doc["data"]

    def _directories(self, n: int) -> list[dict]:
        return self._ok("GET", f"/case/notes/directories/filter?cid={n}") or []

    def _notes(self, n: int, directory: str) -> list[tuple[int, str, str]]:
        rows: list[tuple[int, str, str]] = []
        for d in self._directories(n):
            if d.get("name") != directory:
                continue
            for note in d.get("notes", []):
                full = self._ok("GET", f"/case/notes/{int(note['id'])}?cid={n}")
                rows.append(
                    (
                        int(note["id"]),
                        str(full.get("note_title", "")),
                        str(full.get("note_content", "")),
                    )
                )
        return sorted(rows)

    def _case_status(self, doc: dict) -> str:
        name = doc.get("state_name") or ""
        if name in _STATE_TO_STATUS:
            return _STATE_TO_STATUS[name]
        return "closed" if doc.get("close_date") else "open"

    def get_case(self, case_id: str) -> Case:
        doc = self._raw_case(case_id)
        n = int(doc["case_id"])
        status = self._case_status(doc)
        linked = self._ok("GET", "/alerts/filter?" + urllib.parse.urlencode({"case_id": n})) or {}
        resolution = None
        if status == "closed":
            last = self._notes(n, RESOLUTION_DIR)
            resolution = last[-1][2] if last else None
        return Case(
            id=str(n),
            title=_NAME_PREFIX.sub("", str(doc.get("case_name") or "")).strip(),
            status=status,
            alert_ids=tuple(
                sorted((str(a["alert_id"]) for a in linked.get("alerts", [])), key=int)
            ),
            notes=tuple((t, c) for _, t, c in self._notes(n, NOTE_DIR)),
            resolution=resolution,
            extra={"state": doc.get("state_name")},
        )

    def _directory_id(self, n: int, name: str) -> int:
        for d in self._directories(n):
            if d.get("name") == name:
                return int(d["id"])
        made = self._ok("POST", f"/case/notes/directories/add?cid={n}", {"name": name})
        return int(made["id"])

    def _add_note(self, n: int, directory: str, title: str, text: str) -> None:
        body = {
            "note_title": title[:250],
            "note_content": text,
            "directory_id": self._directory_id(n, directory),
        }
        self._ok("POST", f"/case/notes/add?cid={n}", body)

    def add_note(self, case_id: str, author: str, text: str) -> Case:
        doc = self._raw_case(case_id)
        if self._case_status(doc) == "closed":
            raise CaseClosed(case_id)
        if not author or not text:
            raise ValueError("author and text are required")
        self._add_note(int(doc["case_id"]), NOTE_DIR, author, text)
        return self.get_case(case_id)

    def set_status(self, case_id: str, status: str, *, resolution: str | None = None) -> Case:
        doc = self._raw_case(case_id)
        n = int(doc["case_id"])
        current = self._case_status(doc)
        if status not in _NEXT.get(current, ()):
            raise InvalidTransition(f"{current} -> {status} is not allowed")
        if status == "closed":
            if not (isinstance(resolution, str) and resolution.strip()):
                raise ValueError("closing a case needs a resolution")
            self._add_note(n, RESOLUTION_DIR, "resolution", resolution.strip())
            self._ok("POST", f"/manage/cases/close/{n}")
        elif current == "closed":
            self._ok("POST", f"/manage/cases/reopen/{n}")
        else:
            self._ok(
                "POST",
                f"/manage/cases/update/{n}",
                {"state_id": self._state_id(_STATUS_TO_STATE[status])},
            )
        return self.get_case(case_id)


def make(**config: Any) -> IrisCases:
    """An :class:`IrisCases` from the settings in the module doc (``recorded_fake: true``: a fresh
    loopback instance of the recorded API, for the target file and the tests)."""
    if config.pop("recorded_fake", False):
        return make_recorded()
    unknown = sorted(set(config) - {"base_url", "credential", "ca_file", "customer_id", "timeout"})
    if unknown:
        raise ValueError(f"cases adapter: unknown setting(s) {', '.join(unknown)}")
    base = config.get("base_url") or os.environ.get("HNX_ENDPOINT_CASE_MANAGEMENT", "")
    if not base:
        raise ValueError(
            "no endpoint: base_url, or HNX_ENDPOINT_CASE_MANAGEMENT (there is no default)"
        )
    return IrisCases(
        base,
        token=_credential_reader(config.get("credential")),
        ca_file=config.get("ca_file"),
        customer_id=int(config.get("customer_id", 1)),
        timeout=float(config.get("timeout", 20.0)),
    )


def make_recorded(**_: Any) -> IrisCases:
    """The adapter on a fresh loopback instance of the recorded API (``conformance.fakes.iris_api``), stopped when the
    harness closes the subject: what the module's conformance run and its tests use."""
    try:
        from conformance.fakes.iris_api import TOKEN, FakeIris
    except ImportError as exc:  # checkout-only: conformance/fakes is not in the wheel
        raise ValueError(
            "the recorded cases fake needs a source checkout (conformance/fakes)"
        ) from exc

    fake = FakeIris().start()
    store = IrisCases(fake.url, token=lambda: TOKEN)
    store.close = fake.stop  # type: ignore[method-assign]
    return store
