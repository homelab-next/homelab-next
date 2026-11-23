# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the part of the DFIR-IRIS 2.4.29 API the ``cases`` adapter uses.

Shapes and quirks are recorded from a live 2.4.29 instance (2026-11-22), with fictional data:
the severities' ids are not in severity order (Medium is 1, Low is 4); a missing alert or case is
HTTP 400 with ``status: error``, not 404; an alert's escalation makes the alert Escalated and links
a case that starts in state Open; closing sets state Closed and a close date, reopening state Open;
the case's closing note is NOT writable through ``/manage/cases/update``; a note needs a
``directory_id``; the alert filter's tag match is a substring match; every call needs the bearer
key (401 otherwise).  ``requests`` records each request's path (and ``method`` for a POST) for a test.
"""

from __future__ import annotations

import copy
import itertools
import threading
from typing import Any

from ._loopback import LoopbackAPI

TOKEN = "fake-api-key-for-the-stand-in"
SEVERITIES = {"Medium": 1, "Unspecified": 2, "Informational": 3, "Low": 4, "High": 5, "Critical": 6}
ALERT_STATUS = {
    "Unspecified": 1, "New": 2, "Assigned": 3, "In progress": 4, "Pending": 5, "Closed": 6,
    "Merged": 7, "Escalated": 8,
}  # fmt: skip
CASE_STATES = {
    "Unspecified": 1, "In progress": 2, "Open": 3, "Containment": 4, "Eradication": 5,
    "Recovery": 6, "Post-Incident": 7, "Reporting": 8, "Closed": 9,
}  # fmt: skip


class _Error(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


def _ok(data: Any, message: str = "") -> tuple[int, dict]:
    return 200, {"status": "success", "message": message, "data": data}


class FakeIris(LoopbackAPI):
    def __init__(self) -> None:
        super().__init__()
        self._alerts: dict[int, dict] = {}
        self._cases: dict[int, dict] = {}
        self._dirs: dict[int, dict] = {}
        self._notes: dict[int, dict] = {}
        self._ids = {k: itertools.count(1) for k in ("alert", "case", "dir", "note")}
        self._lock = threading.Lock()

    def answer(self, path: str, query: dict[str, str], headers: Any) -> tuple[int, Any]:
        return self._serve("GET", path, query, headers, None)

    def answer_post(
        self, path: str, query: dict[str, str], headers: Any, body: Any
    ) -> tuple[int, Any]:
        return self._serve("POST", path, query, headers, body)

    def _serve(self, method: str, path: str, q: dict, headers: Any, body: Any) -> tuple[int, Any]:
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 401, {"status": "error", "message": "Unauthorized", "data": []}
        with self._lock:
            try:
                return self._route(method, path, q, body)
            except _Error as exc:
                return exc.status, {"status": "error", "message": exc.message, "data": []}

    # -- the API -----------------------------------------------------------------------------

    @staticmethod
    def _by_id(table: dict[int, dict], raw: str, what: str) -> dict:
        try:
            return table[int(raw)]
        except (KeyError, ValueError):
            raise _Error(400, f"{what} not found") from None

    def _alert_view(self, a: dict) -> dict:
        view = copy.deepcopy(a)
        sid = view.pop("_status")
        view["status"] = {"status_id": sid, "status_name": _name(ALERT_STATUS, sid)}
        sev = view.pop("_severity")
        view["severity"] = {"severity_id": sev, "severity_name": _name(SEVERITIES, sev)}
        view["cases"] = [c for c, case in self._cases.items() if case["_alert"] == a["alert_id"]]
        return view

    def _case_view(self, c: dict) -> dict:
        return {
            "case_id": c["case_id"],
            "case_name": f"#{c['case_id']} - {c['_title']}",
            "state_id": c["state_id"],
            "state_name": _name(CASE_STATES, c["state_id"]),
            "close_date": c["close_date"],
            "closing_note": None,
        }

    def _route(self, method: str, path: str, q: dict, body: Any) -> tuple[int, dict]:
        parts = [p for p in path.split("/") if p]
        if method == "GET" and path == "/manage/severities/list":
            return _ok([{"severity_id": i, "severity_name": n} for n, i in SEVERITIES.items()])
        if method == "GET" and path == "/manage/alert-status/list":
            return _ok([{"status_id": i, "status_name": n} for n, i in ALERT_STATUS.items()])
        if method == "GET" and path == "/manage/case-states/list":
            return _ok([{"state_id": i, "state_name": n} for n, i in CASE_STATES.items()])
        if method == "POST" and path == "/alerts/add":
            n = next(self._ids["alert"])
            b = body or {}
            if not b.get("alert_title") or not b.get("alert_customer_id"):
                raise _Error(400, "Data error")
            self._alerts[n] = {
                "alert_id": n, "alert_title": b["alert_title"], "alert_description": b.get("alert_description"),
                "alert_source": b.get("alert_source"), "alert_source_ref": b.get("alert_source_ref"),
                "alert_tags": b.get("alert_tags", ""), "alert_context": b.get("alert_context"),
                "alert_note": b.get("alert_note"), "_status": b["alert_status_id"],
                "_severity": b["alert_severity_id"],
            }  # fmt: skip
            return _ok(self._alert_view(self._alerts[n]))
        if method == "GET" and path == "/alerts/filter":
            rows = list(self._alerts.values())
            if "alert_tags" in q:
                rows = [a for a in rows if q["alert_tags"] in (a["alert_tags"] or "")]
            if "alert_status_id" in q:
                rows = [a for a in rows if str(a["_status"]) == q["alert_status_id"]]
            if "case_id" in q:
                linked = {
                    c["_alert"] for c in self._cases.values() if str(c["case_id"]) == q["case_id"]
                }
                rows = [a for a in rows if a["alert_id"] in linked]
            per, page = int(q.get("per_page", 10)), int(q.get("page", 1))
            rows.sort(key=lambda a: a["alert_id"], reverse=q.get("sort") != "asc")
            chunk = rows[(page - 1) * per : page * per]
            more = page * per < len(rows)
            return _ok({
                "total": len(rows), "alerts": [self._alert_view(a) for a in chunk],
                "current_page": page, "next_page": page + 1 if more else None,
            })  # fmt: skip
        if len(parts) == 2 and parts[0] == "alerts" and method == "GET":
            return _ok(self._alert_view(self._by_id(self._alerts, parts[1], "Alert")))
        if len(parts) == 3 and parts[:2] == ["alerts", "update"] and method == "POST":
            a = self._by_id(self._alerts, parts[2], "Alert")
            for key, value in (body or {}).items():
                if key == "alert_status_id":
                    a["_status"] = value
                else:
                    a[key] = value
            return _ok(self._alert_view(a))
        if len(parts) == 3 and parts[:2] == ["alerts", "escalate"] and method == "POST":
            a = self._by_id(self._alerts, parts[2], "Alert")
            n = next(self._ids["case"])
            self._cases[n] = {
                "case_id": n, "_title": (body or {}).get("case_title") or a["alert_title"],
                "state_id": CASE_STATES["Open"], "close_date": None, "_alert": a["alert_id"],
            }  # fmt: skip
            a["_status"] = ALERT_STATUS["Escalated"]
            return _ok(
                {
                    **self._case_view(self._cases[n]),
                    "case_name": f"#{n} -  {self._cases[n]['_title']}",
                }
            )
        if len(parts) == 3 and parts[:2] == ["alerts", "delete"] and method == "POST":
            a = self._by_id(self._alerts, parts[2], "Alert")
            del self._alerts[a["alert_id"]]
            return _ok({"alert_id": a["alert_id"]})
        if len(parts) == 3 and parts[:2] == ["manage", "cases"] and method == "GET":
            return _ok(self._case_view(self._by_id(self._cases, parts[2], f"Case ID {parts[2]}")))
        if len(parts) == 4 and parts[:2] == ["manage", "cases"] and method == "POST":
            c = self._by_id(self._cases, parts[3], f"Case ID {parts[3]}")
            if parts[2] == "close":
                c["state_id"], c["close_date"] = CASE_STATES["Closed"], "2026-11-22"
            elif parts[2] == "reopen":
                c["state_id"], c["close_date"] = CASE_STATES["Open"], None
            elif parts[2] == "update":
                if "state_id" in (body or {}):
                    c["state_id"] = body["state_id"]
            else:
                raise _Error(404, "Resource not found")
            return _ok(self._case_view(c), "updated")
        if path.startswith("/case/notes/"):
            return self._notes_route(method, parts, q, body)
        raise _Error(404, "Resource not found")

    def _notes_route(self, method: str, parts: list[str], q: dict, body: Any) -> tuple[int, dict]:
        cid = self._by_id(self._cases, q.get("cid", ""), "Case ID")["case_id"]
        if parts[2:] == ["directories", "filter"] and method == "GET":
            out = []
            for d in self._dirs.values():
                if d["case_id"] != cid:
                    continue
                notes = [n for n in self._notes.values() if n["directory_id"] == d["id"]]
                out.append({
                    "id": d["id"], "name": d["name"], "note_count": len(notes),
                    "subdirectories": [], "notes": [{"id": n["note_id"], "title": n["note_title"]} for n in notes],
                })  # fmt: skip
            return _ok(out)
        if parts[2:] == ["directories", "add"] and method == "POST":
            n = next(self._ids["dir"])
            self._dirs[n] = {
                "id": n,
                "name": (body or {}).get("name"),
                "parent_id": None,
                "case_id": cid,
            }
            return _ok(self._dirs[n], "Directory added")
        if parts[2:] == ["add"] and method == "POST":
            b = body or {}
            if b.get("directory_id") is None or not b.get("note_title"):
                raise _Error(400, "Data error")
            n = next(self._ids["note"])
            self._notes[n] = {
                "note_id": n, "note_title": b["note_title"], "note_content": b.get("note_content", ""),
                "directory_id": b["directory_id"], "note_case_id": cid,
            }  # fmt: skip
            return _ok(self._notes[n], f"Note ID {n} created")
        if len(parts) == 3 and method == "GET":
            return _ok(self._by_id(self._notes, parts[2], "Note ID"))
        raise _Error(404, "Resource not found")


def _name(table: dict[str, int], ident: int) -> str:
    return next(n for n, i in table.items() if i == ident)
