# SPDX-License-Identifier: Apache-2.0
"""The ``dns`` contract on a Technitium DNS Server (pinned: 15.4), stdlib HTTP.

``make(**config)`` returns a :class:`ApiZone` on the server's admin API, which is the
endpoint ``HNX_ENDPOINT_DNS`` names for this adapter (``http://<host>:5380``, not the port-53
service row: the zone contract is about records, and the API is how records are written).

* The admin signs in with ``/api/user/login`` once per target (the password is read from the
  variable ``password_env`` names when the target is built and again at the sign-in, never
  held), and every call after it carries the session token in a POST form, never in a URL.
* ``add``, ``lookup`` and ``remove`` are the zone API's own ``records/add``, ``records/get`` and
  ``records/delete``.  A CNAME is followed here (the API lists what is stored at a name); the
  hop limit and the loop check are the contract's.
* The suite's names live under one scratch zone (``zone``, default ``svc.example.internal``).
  The target creates it when the server has none and removes it again at ``close`` only when it
  created it; a zone that was already there, and every record in it, are left as found apart
  from what the suite itself added.

Findings (what the product does differently from the contract, handled here):

* An identical add is an error in the API (``record already exists``); the target answers it as
  an idempotent add, and a different ttl replaces the record (delete, then add).
* The API says "no records" for a name that does not exist and for a type that is missing at an
  existing name alike, so NXDOMAIN is "no record of any type at the name".
* The API keeps the case a record was first added with; names are compared case-insensitively
  here, as DNS does.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from conformance.protocols.dns import CnameLoop, ConflictingRecord, DnsError, NoSuchName, Record
from homelabnext._http import DEFAULT_MAX_BYTES, check_plaintext, read_bounded, safe_urlopen

from ._env import env_secret, resolve

__all__ = ["ApiZone", "make"]

TYPES = ("A", "AAAA", "CNAME", "TXT")
MAX_HOPS = 8
_RDATA = {"A": "ipAddress", "AAAA": "ipAddress", "CNAME": "cname", "TXT": "text"}
_ARG = {"A": "ipAddress", "AAAA": "ipAddress", "CNAME": "cname", "TXT": "text"}


class ApiError(DnsError):
    """The server answered ``status: error`` (its own message, never a credential)."""


def _norm(name: str) -> str:
    return name.rstrip(".").lower()


class ApiZone:
    """:class:`conformance.protocols.dns.DnsZone` on one Technitium primary zone."""

    features = frozenset()

    def __init__(
        self,
        base_url: str,
        *,
        user: str,
        password: Callable[[], str],
        zone: str = "svc.example.internal",
        timeout: float = 10.0,
        allow_plaintext: bool = False,
        max_bytes: int = 4 * DEFAULT_MAX_BYTES,
    ):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        self._base = base_url.rstrip("/")
        self._user = user
        self._password = password
        self.zone = _norm(zone)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._token: str | None = None
        self._created = False
        self._login()
        self._ensure_zone()

    def __repr__(self) -> str:
        return f"ApiZone(zone={self.zone!r})"

    # ------------------------------------------------------------------------------ the API
    def _call(self, path: str, **params: str) -> dict[str, Any]:
        form = {k: v for k, v in params.items() if v is not None}
        if self._token is not None:
            form["token"] = self._token
        req = urllib.request.Request(
            f"{self._base}/api/{path}",
            data=urllib.parse.urlencode(form).encode("ascii"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with safe_urlopen(req, timeout=self.timeout) as resp:
                raw = read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            raise ApiError(f"{path}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ApiError(f"{path}: {type(exc).__name__}") from None
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise ApiError(f"{path}: the answer is not JSON") from None
        if not isinstance(doc, dict):
            raise ApiError(f"{path}: the answer is not an object")
        if doc.get("status") != "ok":
            raise ApiError(str(doc.get("errorMessage") or f"{path}: status {doc.get('status')}"))
        return doc

    def _login(self) -> None:
        try:
            doc = self._call("user/login", user=self._user, **{"pass": self._password()})
        except ApiError:
            raise ApiError(
                "sign-in refused (the user or its password is not the server's)"
            ) from None
        if not doc.get("token"):
            raise ApiError("sign-in answered no session token")
        self._token = str(doc["token"])

    def _ensure_zone(self) -> None:
        zones = self._call("zones/list")["response"]["zones"]
        if any(_norm(z["name"]) == self.zone for z in zones):
            return
        self._call("zones/create", zone=self.zone, type="Primary")
        self._created = True

    def close(self) -> None:
        try:
            if self._created:
                self._call("zones/delete", zone=self.zone)
                self._created = False
            if self._token is not None:
                self._call("user/logout")
        except DnsError:
            pass
        finally:
            self._token = None

    # ------------------------------------------------------------------------- the contract
    def _stored(self, name: str) -> list[Record]:
        doc = self._call("zones/records/get", domain=name, zone=self.zone)
        out = []
        for r in doc["response"].get("records", []):
            rtype = r.get("type")
            if rtype not in TYPES or _norm(r.get("name", "")) != _norm(name):
                continue
            value = str(r["rData"][_RDATA[rtype]])
            out.append(
                Record(
                    _norm(name),
                    rtype,
                    value if rtype == "TXT" else _norm(value),
                    int(r["ttl"]),
                )
            )
        return out

    def add(self, name: str, rtype: str, value: str, ttl: int = 300) -> Record:
        rtype = rtype.upper()
        if rtype not in TYPES:
            raise ValueError(f"unsupported type {rtype!r}")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 2_147_483_647:
            raise ValueError("ttl must be a positive integer")
        if rtype == "A":
            ipaddress.IPv4Address(value)
        elif rtype == "AAAA":
            ipaddress.IPv6Address(value)
        elif not value:
            raise ValueError("value is required")
        key = _norm(name)
        want = Record(key, rtype, value if rtype == "TXT" else _norm(value), ttl)
        args = {
            "domain": name,
            "zone": self.zone,
            "type": rtype,
            "ttl": str(ttl),
            _ARG[rtype]: value,
        }
        try:
            self._call("zones/records/add", **args)
        except ApiError as exc:
            text = str(exc).lower()
            if "cname record cannot exist" in text or "cname record cannot exists" in text:
                raise ConflictingRecord(
                    f"{key}: a CNAME cannot coexist with other records"
                ) from None
            if "already exists" not in text:
                raise
            same = [r for r in self._stored(name) if (r.rtype, r.value) == (want.rtype, want.value)]
            if same and same[0].ttl == ttl:
                return want
            self.remove(name, rtype, value)
            self._call("zones/records/add", **args)
        return want

    def lookup(self, name: str, rtype: str) -> list[Record]:
        rtype = rtype.upper()
        key = _norm(name)
        seen: list[str] = []
        for _ in range(MAX_HOPS + 1):
            have = self._stored(key)
            if not have:
                raise NoSuchName(key)
            direct = sorted((r for r in have if r.rtype == rtype), key=lambda r: r.value)
            if direct:
                return direct
            cname = next((r for r in have if r.rtype == "CNAME"), None)
            if cname is None or rtype == "CNAME":
                return []
            if cname.value in seen or cname.value == key:
                raise CnameLoop(" -> ".join([*seen, key, cname.value]))
            seen.append(key)
            key = cname.value
        raise CnameLoop(f"more than {MAX_HOPS} CNAME hops from {name}")

    def remove(self, name: str, rtype: str, value: str | None = None) -> int:
        rtype = rtype.upper()
        if rtype not in TYPES:
            return 0
        doomed = [r for r in self._stored(name) if r.rtype == rtype and value in (None, r.value)]
        for r in doomed:
            self._call(
                "zones/records/delete",
                domain=name,
                zone=self.zone,
                type=rtype,
                **{_ARG[rtype]: r.value},
            )
        return len(doomed)


def make(
    *,
    user: str = "admin",
    password_env: str,
    zone: str = "svc.example.internal",
    timeout: float = 10.0,
    allow_plaintext: bool = False,
    capability: str = "dns",
) -> ApiZone:
    """A target on the ``dns`` endpoint (the server's admin API), signing in as ``user`` with the
    password the variable ``password_env`` holds (read when the target is built, so a missing one
    fails at once, naming the variable, and again at the sign-in)."""
    password = env_secret(password_env)
    return ApiZone(
        resolve(capability, env_only=True, schemes=("http", "https")).url,
        user=user,
        password=password,
        zone=zone,
        timeout=timeout,
        allow_plaintext=allow_plaintext,
    )
