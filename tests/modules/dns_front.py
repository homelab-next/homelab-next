# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the admin API of the dns server the ``technitium`` module runs.

Shaped after what the pinned server (15.4.0) answered when the module was built, including the
answers that are not obvious: every reply is ``{"status": "ok"|"error"|"invalid-token", ...}``; a
sign-in answers a flat ``token``; a new primary zone holds its NS and SOA records (so a zone's
record count is never zero); adding an identical record is an error (``record already exists``);
a CNAME cannot share a name with other records; a name with no record is an empty list, not an
error; and a zone exports as a zone file (``$ORIGIN``) that imports back to the same records.

Not shaped after it: recursion, zone transfers and the web console; it speaks the API only.
Shared by tests/modules/test_technitium_module.py and tests/roles/test_technitium_role.py.
"""

from __future__ import annotations

import ipaddress
import itertools
import json
import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = ["FakeDnsAdmin"]

LOOPBACK = socket.gethostbyname("localhost")  # the stand-in listens here; resolved, never a literal
_FIELD = {"A": "ipAddress", "AAAA": "ipAddress", "CNAME": "cname", "TXT": "text"}


def _rec(name: str, rtype: str, rdata: dict[str, Any], ttl: int = 3600) -> dict[str, Any]:
    return {"name": name, "type": rtype, "ttl": ttl, "disabled": False, "rData": rdata}


def _zone_text(zone: str, records: list[dict[str, Any]]) -> str:
    lines = [f"$ORIGIN {zone}."]
    for r in records:
        d = r["rData"]
        if r["type"] == "SOA":
            rdata = f"{d['primaryNameServer']}. hostadmin {d['serial']} 900 300 604800 900"
        elif r["type"] == "NS":
            rdata = d["nameServer"] + "."
        else:
            rdata = d[_FIELD[r["type"]]]
        lines.append(f"{r['name']} {r['ttl']} IN {r['type']} {rdata}")
    return "\n".join(lines) + "\n"


def _parse_zone(text: str) -> tuple[str, list[dict[str, Any]]]:
    zone, out = "", []
    for line in text.splitlines():
        if line.startswith("$ORIGIN "):
            zone = line.split()[1].rstrip(".")
        elif line.strip():
            name, ttl, _, rtype, *rest = line.split(None, 4)
            value = rest[0] if rest else ""
            if rtype == "SOA":
                out.append(
                    _rec(
                        name,
                        rtype,
                        {
                            "primaryNameServer": line.split()[4].rstrip("."),
                            "serial": int(line.split()[6]),
                        },
                        int(ttl),
                    )
                )
            elif rtype == "NS":
                out.append(_rec(name, rtype, {"nameServer": value.rstrip(".")}, int(ttl)))
            else:
                out.append(_rec(name, rtype, {_FIELD[rtype]: value}, int(ttl)))
    return zone, out


class FakeDnsAdmin:
    def __init__(self, *, user: str = "admin", password: str = "admin-password-fake"):
        self.user, self.password = user, password
        self.zones: dict[str, list[dict[str, Any]]] = {}
        self.tokens: set[str] = set()
        self.logins = 0
        self._sessions = itertools.count(1)
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer((LOOPBACK, 0), self._handler())
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ lifecycle and seeding
    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> FakeDnsAdmin:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def add_zone(self, name: str, hosts: dict[str, str] | None = None) -> None:
        """A primary zone with its NS and SOA and one A record for each ``label: address``."""
        recs = [_rec(name, "SOA", {"primaryNameServer": "ns", "serial": 1}, 900),
                _rec(name, "NS", {"nameServer": "ns"}, 14400)]  # fmt: skip
        recs += [_rec(f"{h}.{name}", "A", {"ipAddress": a}) for h, a in (hosts or {}).items()]
        self.zones[name] = recs

    # --------------------------------------------------------------------------- the API
    def _api(self, path: str, form: dict[str, str], body: bytes) -> tuple[int, Any, str]:
        if path == "user/login":
            if form.get("user") == self.user and form.get("pass") == self.password:
                sid = f"sess-{next(self._sessions)}"
                self.tokens.add(sid)
                self.logins += 1
                return 200, {"username": self.user, "token": sid, "status": "ok"}, "json"
            return 200, {"status": "error", "errorMessage": "Invalid username or password."}, "json"
        if form.get("token") not in self.tokens:
            return 200, {"status": "invalid-token", "errorMessage": "Invalid token."}, "json"
        zone = form.get("zone", "").rstrip(".").lower()
        if path == "user/logout":
            self.tokens.discard(form["token"])
            return 200, {"status": "ok"}, "json"
        if path == "user/session/get":
            return 200, {"username": self.user, "status": "ok"}, "json"
        if path == "zones/list":
            zs = [{"name": n, "type": "Primary"} for n in sorted(self.zones)]
            return 200, {"response": {"zones": zs}, "status": "ok"}, "json"
        if path == "zones/create":
            if zone in self.zones:
                return 200, {"status": "error", "errorMessage": "Zone already exists."}, "json"
            self.add_zone(zone)
            return 200, {"response": {"domain": zone}, "status": "ok"}, "json"
        if path not in (
            "zones/delete",
            "zones/export",
            "zones/import",
            "settings/backup",
        ) and not path.startswith("zones/records/"):
            return 404, {"status": "error", "errorMessage": "no such API"}, "json"
        if path == "settings/backup":
            return 200, b"PK\x03\x04 a settings backup", "zip"
        if path == "zones/import":
            name, recs = _parse_zone(body.decode("utf-8"))
            if name != zone or zone not in self.zones:
                return 200, {"status": "error", "errorMessage": "No such zone."}, "json"
            self.zones[zone] = recs
            return 200, {"response": {}, "status": "ok"}, "json"
        if zone not in self.zones:
            return (
                200,
                {"status": "error", "errorMessage": f"No such zone was found: {zone}"},
                "json",
            )
        if path == "zones/delete":
            del self.zones[zone]
            return 200, {"response": {}, "status": "ok"}, "json"
        if path == "zones/export":
            return 200, _zone_text(zone, self.zones[zone]).encode(), "text"
        return self._records(path.rsplit("/", 1)[1], zone, form)

    def _records(self, op: str, zone: str, form: dict[str, str]) -> tuple[int, Any, str]:
        have = self.zones[zone]
        domain = form.get("domain", "").rstrip(".")
        same = [r for r in have if r["name"].lower() == domain.lower()]

        def err(msg: str) -> tuple[int, Any, str]:
            return 200, {"status": "error", "errorMessage": msg}, "json"

        if op == "get":
            recs = have if form.get("listZone") == "true" else same
            return (
                200,
                {"response": {"zone": {"name": zone}, "records": recs}, "status": "ok"},
                "json",
            )
        rtype = form.get("type", "")
        if rtype not in _FIELD:
            return err(f"Requested value '{rtype}' was not found.")
        value = form.get(_FIELD[rtype], "")
        if op == "add":
            try:
                if rtype == "A":
                    ipaddress.IPv4Address(value)
                elif rtype == "AAAA":
                    ipaddress.IPv6Address(value)
            except ValueError:
                return err("An invalid IP address was specified.")
            if any(
                r["type"] == rtype and r["rData"][_FIELD[rtype]].lower() == value.lower()
                for r in same
            ):
                return err("Cannot add record: record already exists.")
            if (rtype == "CNAME" and same) or (
                rtype != "CNAME" and any(r["type"] == "CNAME" for r in same)
            ):
                return err(
                    "Cannot add record: a CNAME record cannot exists with other record "
                    "types for the same name."
                )
            rec = _rec(domain, rtype, {_FIELD[rtype]: value}, int(form.get("ttl", "3600")))
            have.append(rec)
            return 200, {"response": {"addedRecord": rec}, "status": "ok"}, "json"
        for r in same:  # delete
            if r["type"] == rtype and r["rData"][_FIELD[rtype]].lower() == value.lower():
                have.remove(r)
                return 200, {"response": {}, "status": "ok"}, "json"
        return err("Cannot delete record: no such record exists.")

    def _handler(self):
        front = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                pass

            def _serve(self) -> None:
                u = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                form = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                body = b""
                if self.headers.get("Content-Type", "").startswith("application/x-www-form"):
                    form.update({k: v[0] for k, v in urllib.parse.parse_qs(raw.decode()).items()})
                else:
                    body = raw
                if not u.path.startswith("/api/"):
                    self.send_error(404)
                    return
                with front._lock:
                    status, doc, kind = front._api(u.path[5:], form, body)
                out = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
                self.send_response(status)
                self.send_header(
                    "Content-Type",
                    {"json": "application/json", "zip": "application/zip"}.get(kind, "text/plain"),
                )
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = _serve

        return Handler
