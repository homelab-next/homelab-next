# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the part of the OpenProject 17.9 API v3 the projects adapter uses.

The read-only setup (the user, types, statuses, the two projects, the forms' custom fields and the
Strategy project's memberships) is :func:`recorded_setup`: responses shaped after OpenProject
17.9's HAL+JSON (``docs/api/apiv3`` at tag ``v17.9.2``), with fictional names and ids.  A test
removes or alters an entry to stand for an instance an administrator has not finished setting up.

Work packages and relations are stateful: ``POST``/``PATCH``/``GET`` work packages (``PATCH``
needs the current ``lockVersion``, else 409), the collection filters the adapter sends
(``type``, ``status``, ``customFieldN`` -- only on a field marked filterable, else 400 --
``updatedAt <>d``) with ``sortBy`` and ``offset``/``pageSize`` paging, and relations (create,
list by ``involved``, delete).  Times have second precision, like OpenProject; ``tick`` seconds
pass per write (``tick=0`` keeps every write in one second, for cursor tests).  Requests need
``Authorization: Basic apikey:<token>`` (401 otherwise).  ``fail_next(n, status)`` answers the
next ``n`` requests with ``status`` (retry tests); ``fail_after_next(n, status)`` applies the next
``n`` requests and then answers ``status`` (a write that landed before the error).
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import itertools
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow fake server binds loopback only
TOKEN = "fake-openproject-token"
API = "/api/v3"
STRATEGY_TYPES = ("SO", "OO", "TO", "TT", "CCIR", "FFIR", "PIR", "RFI", "MOP", "MOE")
WORK_TYPES = ("Project", "Step", "Task")
STATUSES = (
    ("Open", False), ("Closed", True), ("Blocked", False), ("To do", False),
    ("In progress", False), ("Done", True), ("Cancelled", True), ("Active", False),
    ("Achieved", True), ("Retired", True), ("Answered", True), ("Expired", True),
    ("No-find", True),
)  # fmt: skip
EXT_CF, STATE_CF = "customField3", "customField7"
_EPOCH = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def recorded_setup() -> dict[str, Any]:
    """The instance as an administrator left it after the checklist in docs/projects.md."""
    types = [{"_type": "Type", "id": 10 + n, "name": t} for n, t in enumerate((*STRATEGY_TYPES, *WORK_TYPES))]  # fmt: skip
    statuses = [
        {"_type": "Status", "id": 1 + n, "name": name, "isClosed": closed}
        for n, (name, closed) in enumerate(STATUSES)
    ]
    fields = {
        EXT_CF: {"type": "String", "name": "External key", "filterable": True},
        STATE_CF: {"type": "Formattable", "name": "hnx state", "filterable": False},
    }
    projects = {
        "strategy": {
            "_type": "Project", "id": 2, "identifier": "strategy", "name": "Strategy",
            "_links": {"createWorkPackage": {"href": f"{API}/projects/2/work_packages/form"}},
            "types": list(STRATEGY_TYPES),
        },
        "lab": {
            "_type": "Project", "id": 3, "identifier": "lab", "name": "Lab",
            "_links": {"createWorkPackage": {"href": f"{API}/projects/3/work_packages/form"}},
            "types": list(WORK_TYPES),
        },
    }  # fmt: skip
    memberships = [
        {"_type": "Membership", "id": 1, "_links": {
            "project": {"href": f"{API}/projects/2"},
            "principal": {"href": f"{API}/users/5", "title": "hnx sync"},
            "roles": [{"href": f"{API}/roles/4", "title": "Strategy sync"}]}},
        {"_type": "Membership", "id": 2, "_links": {
            "project": {"href": f"{API}/projects/2"},
            "principal": {"href": f"{API}/users/6", "title": "Example Operator"},
            "roles": [{"href": f"{API}/roles/3", "title": "Reader"}]}},
    ]  # fmt: skip
    return {
        "me": {"_type": "User", "id": 5, "login": "hnx-sync", "name": "hnx sync"},
        "types": types,
        "statuses": statuses,
        "projects": projects,
        "fields": fields,  # every enabled type of every project shows these on its form
        "memberships": memberships,
    }


class _Error(Exception):
    def __init__(self, status: int, ident: str, message: str) -> None:
        self.status, self.ident, self.message = status, ident, message


class FakeOpenProject:
    def __init__(self, *, setup: dict[str, Any] | None = None, tick: int = 1, max_page: int = 1000):
        self.setup = setup if setup is not None else recorded_setup()
        self.tick, self.max_page = tick, max_page
        self.wps: dict[int, dict[str, Any]] = {}
        self.relations: dict[int, dict[str, Any]] = {}
        self.log: list[tuple[str, str]] = []
        self._ids = itertools.count(100)
        self._rel_ids = itertools.count(500)
        self._seconds = 0
        self._fail: list[int] = []
        self._fail_after: list[int] = []
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer((LOOPBACK, 0), self._handler())
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ lifecycle
    @property
    def url(self) -> str:
        return f"http://{LOOPBACK}:{self._httpd.server_address[1]}"

    def start(self) -> FakeOpenProject:
        self._thread = threading.Thread(target=self._httpd.serve_forever, args=(0.02,), daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def __enter__(self) -> FakeOpenProject:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def fail_next(self, n: int, status: int = 503) -> None:
        self._fail += [status] * n

    def fail_after_next(self, n: int, status: int = 503) -> None:
        self._fail_after += [status] * n

    def writes(self) -> int:
        return sum(1 for m, _ in self.log if m in ("POST", "PATCH", "DELETE"))

    # ------------------------------------------------------------------ helpers
    def _now(self) -> str:
        self._seconds += self.tick
        return (_EPOCH + dt.timedelta(seconds=self._seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _project(self, key: str) -> dict[str, Any]:
        for p in self.setup["projects"].values():
            if key in (str(p["id"]), p["identifier"]):
                return p
        raise _Error(404, "NotFound", "The requested resource could not be found.")

    def _type_names(self) -> dict[int, str]:
        return {t["id"]: t["name"] for t in self.setup["types"]}

    def _collection(self, elements: list[Any], q: dict[str, str]) -> dict[str, Any]:
        size = min(int(q.get("pageSize", 20)), self.max_page)
        page = max(int(q.get("offset", 1)), 1)
        part = elements[(page - 1) * size : page * size]
        return {
            "_type": "Collection", "total": len(elements), "count": len(part),
            "pageSize": size, "offset": page, "_embedded": {"elements": part},
        }  # fmt: skip

    def _filters(self, q: dict[str, str]) -> list[tuple[str, str, list[str]]]:
        try:
            raw = json.loads(q.get("filters", "[]"))
            return [(k, v["operator"], [str(x) for x in v["values"]]) for f in raw for k, v in f.items()]  # fmt: skip
        except (ValueError, KeyError, TypeError, AttributeError):
            raise _Error(400, "InvalidQuery", "filters is not valid") from None

    def _match(self, wp: dict[str, Any], name: str, op: str, vals: list[str]) -> bool:
        if name.startswith("customField"):
            spec = self.setup["fields"].get(name)
            if spec is None or not spec.get("filterable"):
                raise _Error(400, "InvalidQuery", f"Filter {name} does not exist.")
            return op == "=" and str(wp.get(name) or "") in vals
        if name in ("type", "status"):
            href = wp["_links"][name]["href"]
            return op == "=" and href.rsplit("/", 1)[-1] in vals
        if name == "updatedAt" and op == "<>d":
            lo, hi = ([*vals, "", ""])[:2]
            return (not lo or wp["updatedAt"] >= lo) and (not hi or wp["updatedAt"] <= hi)
        raise _Error(400, "InvalidQuery", f"unsupported filter {name} {op}")

    def _apply(self, wp: dict[str, Any], body: dict[str, Any]) -> None:
        for k in ("subject", "dueDate"):
            if k in body:
                wp[k] = body[k]
        if "description" in body:
            wp["description"] = {"format": "markdown", "raw": (body["description"] or {}).get("raw", ""), "html": ""}  # fmt: skip
        for k, v in body.items():
            if k.startswith("customField"):
                if k not in self.setup["fields"]:
                    raise _Error(422, "PropertyIsReadOnly", f"{k} is not available")
                wp[k] = v
        links = body.get("_links") or {}
        for name in ("type", "status", "parent"):
            if name in links:
                href = (links[name] or {}).get("href")
                if name == "parent" and href:
                    pid = int(href.rsplit("/", 1)[-1])
                    if pid not in self.wps or pid == wp["id"]:
                        raise _Error(422, "PropertyConstraintViolation", "Parent is invalid.")
                wp["_links"][name] = {"href": href}
        if not wp.get("subject"):
            raise _Error(422, "PropertyConstraintViolation", "Subject can't be blank.")

    def _view(self, wp: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(wp)

    # ------------------------------------------------------------------ routes
    def handle(self, method: str, path: str, q: dict[str, str], body: Any) -> tuple[int, Any]:
        s = self.setup
        parts = path.removeprefix(API).strip("/").split("/")
        if method == "GET" and parts == ["users", "me"]:
            return 200, s["me"]
        if method == "GET" and parts == ["types"]:
            return 200, self._collection(s["types"], q)
        if method == "GET" and parts == ["statuses"]:
            return 200, self._collection(s["statuses"], q)
        if method == "GET" and parts[0] == "projects" and len(parts) == 2:
            p = self._project(parts[1])
            return 200, {k: v for k, v in p.items() if k != "types"}
        if method == "GET" and parts[0] == "projects" and len(parts) == 3 and parts[2] == "types":
            names = self._project(parts[1])["types"]
            return 200, self._collection([t for t in s["types"] if t["name"] in names], q)
        if method == "GET" and parts[:2] == ["work_packages", "schemas"] and len(parts) == 3:
            pid, tid = parts[2].split("-")
            p = self._project(pid)
            if self._type_names().get(int(tid)) not in p["types"]:
                raise _Error(404, "NotFound", "no such form")
            return 200, {"_type": "Schema", **{k: {"type": v["type"], "name": v["name"]} for k, v in s["fields"].items()}}  # fmt: skip
        if method == "GET" and parts == ["memberships"]:
            want = {v for k, _op, vals in self._filters(q) if k == "project" for v in vals}
            ms = [m for m in s["memberships"] if m["_links"]["project"]["href"].rsplit("/", 1)[-1] in want]  # fmt: skip
            return 200, self._collection(ms, q)
        if parts[0] == "projects" and len(parts) == 3 and parts[2] == "work_packages":
            p = self._project(parts[1])
            if method == "POST":
                return 201, self._create(p, body)
            fl = self._filters(q)
            for name, _op, _vals in fl:  # an unusable filter is refused even on no rows
                spec = (
                    s["fields"].get(name)
                    if name.startswith("customField")
                    else {"filterable": True}
                )
                if spec is None or not spec.get("filterable"):
                    raise _Error(400, "InvalidQuery", f"Filter {name} does not exist.")
            rows = [w for w in self.wps.values() if w["_links"]["project"]["href"].endswith(f"/{p['id']}")]  # fmt: skip
            rows = [w for w in rows if all(self._match(w, *f) for f in fl)]
            sort = json.loads(q.get("sortBy", '[["id","asc"]]'))
            key = sort[0][0] if sort else "id"
            rows.sort(key=lambda w: (w.get(key), w["id"]))
            return 200, self._collection([self._view(w) for w in rows], q)
        if parts[0] == "work_packages" and len(parts) == 2:
            wp = self.wps.get(int(parts[1])) if parts[1].isdigit() else None
            if wp is None:
                raise _Error(404, "NotFound", "The requested resource could not be found.")
            if method == "GET":
                return 200, self._view(wp)
            if method == "PATCH":
                if body.get("lockVersion") != wp["lockVersion"]:
                    raise _Error(409, "UpdateConflict", "Information has been updated by at least one other user in the meantime.")  # fmt: skip
                new = copy.deepcopy(wp)
                self._apply(new, body)
                new["lockVersion"] += 1
                new["updatedAt"] = self._now()
                self.wps[wp["id"]] = new
                return 200, self._view(new)
        if parts[0] == "work_packages" and len(parts) == 3 and parts[2] == "relations" and method == "POST":  # fmt: skip
            return 201, self._relate(int(parts[1]), body)
        if parts == ["relations"] and method == "GET":
            ids = {v for k, _op, vals in self._filters(q) if k == "involved" for v in vals}
            rels = [r for r in self.relations.values() if {r["_links"]["from"]["href"].rsplit("/", 1)[-1], r["_links"]["to"]["href"].rsplit("/", 1)[-1]} & ids]  # fmt: skip
            return 200, self._collection(sorted(rels, key=lambda r: r["id"]), q)
        if parts[0] == "relations" and len(parts) == 2 and method == "DELETE":
            if self.relations.pop(int(parts[1]), None) is None:
                raise _Error(404, "NotFound", "no such relation")
            return 204, None
        raise _Error(404, "NotFound", f"no route {method} {path}")

    def _create(self, p: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        tid = int(str(((body.get("_links") or {}).get("type") or {}).get("href", "/0")).rsplit("/", 1)[-1])  # fmt: skip
        if self._type_names().get(tid) not in p["types"]:
            raise _Error(422, "PropertyConstraintViolation", "Type is not set to one of the allowed values.")  # fmt: skip
        now = self._now()
        wp = {
            "_type": "WorkPackage", "id": next(self._ids), "lockVersion": 0, "subject": "",
            "description": {"format": "markdown", "raw": "", "html": ""}, "dueDate": None,
            "createdAt": now, "updatedAt": now,
            "_links": {"project": {"href": f"{API}/projects/{p['id']}"}, "parent": {"href": None}},
        }  # fmt: skip
        self._apply(wp, body)
        self.wps[wp["id"]] = wp
        return self._view(wp)

    def _relate(self, src: int, body: dict[str, Any]) -> dict[str, Any]:
        to = str(((body.get("_links") or {}).get("to") or {}).get("href", "")).rsplit("/", 1)[-1]
        if src not in self.wps or not to.isdigit() or int(to) not in self.wps or int(to) == src:
            raise _Error(422, "PropertyConstraintViolation", "Related work package is invalid.")
        rel = {
            "_type": "Relation", "id": next(self._rel_ids), "type": body.get("type", "relates"),
            "description": body.get("description") or "",
            "_links": {"from": {"href": f"{API}/work_packages/{src}"}, "to": {"href": f"{API}/work_packages/{to}"}},
        }  # fmt: skip
        self.relations[rel["id"]] = rel
        return rel

    # ------------------------------------------------------------------ HTTP
    def _handler(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _send(self, status: int, doc: Any) -> None:
                data = b"" if doc is None else json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/hal+json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _do(self, method: str) -> None:
                url = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(url.query))
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                want = "Basic " + base64.b64encode(f"apikey:{TOKEN}".encode()).decode()
                with fake._lock:
                    fake.log.append((method, url.path))
                    if fake._fail:
                        status = fake._fail.pop(0)
                        self._send(status, _err(status, "ServiceUnavailable", "try again"))
                        return
                    if self.headers.get("Authorization") != want:
                        self._send(401, _err(401, "Unauthenticated", "You did not provide the correct credentials."))  # fmt: skip
                        return
                    try:
                        body = json.loads(raw) if raw else None
                        status, doc = fake.handle(method, url.path, q, body)
                    except _Error as e:
                        status, doc = e.status, _err(e.status, e.ident, e.message)
                    if fake._fail_after:
                        status = fake._fail_after.pop(0)
                        doc = _err(status, "ServiceUnavailable", "try again")
                self._send(status, doc)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

            def do_PATCH(self):
                self._do("PATCH")

            def do_DELETE(self):
                self._do("DELETE")

        return Handler


def _err(status: int, ident: str, message: str) -> dict[str, Any]:
    return {
        "_type": "Error",
        "errorIdentifier": f"urn:openproject-org:api:v3:errors:{ident}",
        "message": message,
    }
