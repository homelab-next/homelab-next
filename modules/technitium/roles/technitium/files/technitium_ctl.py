#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: dns-zone-ctl
#   kind: tool
#   purpose: Inventory, export, restore, verify and compare the zones of the dns provider's server, restore its archived config from a tar, and ask it questions over DNS; every check that finds nothing where something is expected is an error.
#   owner: platform
#   trigger: [role:technitium]
#   inputs: "a subcommand and its options; the admin password in the environment variable --password-env names"
#   outputs: one JSON document on stdout; the reason for a refusal on stderr
#   exit:
#     "0": done, or every check held
#     "1": refused, or a check failed (the reason on stderr; nothing is changed by a refused restore)
#     "2": usage error
"""Zone tooling for the ``technitium`` module: one stdlib script the role's hooks run on the guest
(``python3 -I technitium_ctl.py <command> ...``) and the cutover runbook runs from a workstation.

Commands (each prints one JSON document on success and exits 0; any refusal or mismatch is a
message on stderr and exit 1; exit 2 is a usage error):

  inventory      the server's zones and each zone's record count
  verify         inventory, then check it against ``--expect`` (zone -> record count)
  export         every primary zone as a zone file, the settings backup, and listing.jsonl
  restore-check  read an export directory and refuse anything the listing does not vouch for
  restore-apply  restore-check, import every listed zone, then check each record count
  archive-check  read an archived config tar and list what would be restored from it
  archive-apply  place the allowlisted files of that tar into a (stopped) server's config folder
  answers        ask a server over DNS (port 53) and check what it says
  compare        every record, and every answer, of one server against another

The admin password is never an argument: it is read from the environment variable named by
``--password-env`` (default ``HNX_TECHNITIUM_PASSWORD``) and sent in a POST form, never in a URL.
A check that finds nothing where something is expected (no zones, no zone files, no answers) is an
error, never a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import socket
import stat
import struct
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_API_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_RESTORED_BYTES = 256 * 1024 * 1024  # everything an archive restore would place, in all
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024  # every regular member, ignored ones included
MAX_MEMBERS = 10000
ZONE_FILE = re.compile(r"[A-Za-z0-9._-]{1,200}\.zone")
ZONE_NAME = re.compile(r"[A-Za-z0-9._-]{1,253}")
# what an archived config tar may restore: the zones and the settings that shape answers. Never
# the admin accounts (auth.config: the new admin password is the secret store's), the web
# service's bind address, the statistics, the cache or the downloaded blocklists.
ARCHIVE_ALLOW = (
    re.compile(r"config/zones/[A-Za-z0-9._-]{1,200}\.zone"),
    re.compile(r"config/scopes/[A-Za-z0-9._ -]{1,100}\.scope"),
    re.compile(r"config/(dns|allowed|blocked|blocklist)\.config"),
)
ARCHIVE_IGNORED = (
    re.compile(r"config/?"),
    re.compile(r"config/(zones|scopes|apps|stats|blocklists)/?"),
    re.compile(r"config/(auth|webservice|log)\.config"),
    re.compile(r"config/(stats|blocklists)/[^/]+"),
    re.compile(r"config/cache\.bin"),
)


class Refused(Exception):
    pass


def fail(why: str) -> Refused:
    return Refused(why)


# ---------------------------------------------------------------------------------- the API
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # type: ignore[override]
        return None


class Api:
    def __init__(self, base: str, user: str, password_env: str, timeout: float = 30.0):
        if not base.startswith(("http://", "https://")):
            raise Refused("the API address must be an http(s) URL")
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)
        password = os.environ.get(password_env, "")
        if not password:
            raise Refused(f"the variable {password_env} (the admin password) is not set")
        doc = self.call("user/login", user=user, **{"pass": password})
        self.token = str(doc.get("token") or "")
        if not self.token:
            raise Refused("sign-in answered no session token")

    def raw(
        self,
        path: str,
        body: bytes | None = None,
        ctype: str | None = None,
        query: dict[str, str] | None = None,
        **form: str,
    ) -> bytes:
        fields = {k: v for k, v in form.items() if v is not None}
        if getattr(self, "token", None):
            fields["token"] = self.token
        if body is None:
            data, headers, url = (
                urllib.parse.urlencode(fields).encode(),
                {"Content-Type": "application/x-www-form-urlencoded"},
                f"{self.base}/api/{path}",
            )
        else:  # a body (a zone file) travels as the body, the rest in the query
            data, headers = body, {"Content-Type": ctype or "text/plain"}
            url = f"{self.base}/api/{path}?{urllib.parse.urlencode({**fields, **(query or {})})}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                out = resp.read(MAX_API_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise Refused(f"{path}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise Refused(f"{path}: {type(exc).__name__}") from None
        if len(out) > MAX_API_BYTES:
            raise Refused(f"{path}: the answer is larger than {MAX_API_BYTES} bytes")
        return out

    def call(self, path: str, **form: str) -> dict[str, Any]:
        out = self.raw(path, **form)
        try:
            doc = json.loads(out.decode("utf-8"))
        except ValueError:
            raise Refused(f"{path}: the answer is not JSON") from None
        if not isinstance(doc, dict) or doc.get("status") != "ok":
            msg = doc.get("errorMessage") if isinstance(doc, dict) else None
            raise Refused(f"{path}: {msg or 'the server refused it'}")
        return doc

    def zones(self) -> list[dict[str, Any]]:
        return list(self.call("zones/list")["response"].get("zones", []))

    def records(self, zone: str) -> list[dict[str, Any]]:
        doc = self.call("zones/records/get", domain=zone, zone=zone, listZone="true")
        return list(doc["response"].get("records", []))


def _api(args: argparse.Namespace, which: str = "") -> Api:
    return Api(
        getattr(args, which + "api"),
        getattr(args, which + "user"),
        getattr(args, which + "password_env"),
    )


def inventory(api: Api) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for z in api.zones():
        name = str(z["name"]).lower()
        out[name] = {"type": z.get("type"), "records": len(api.records(z["name"]))}
    return out


# ---------------------------------------------------------------------------- inventory, verify
def cmd_inventory(args: argparse.Namespace) -> dict[str, Any]:
    return {"zones": inventory(_api(args))}


def _expect(text: str) -> dict[str, int]:
    try:
        doc = json.loads(text)
    except ValueError:
        raise Refused("--expect is not JSON") from None
    if not isinstance(doc, dict) or not all(
        isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v > 0
        for k, v in doc.items()
    ):
        raise Refused("--expect is a JSON object of zone name to a positive record count")
    return {k.lower().rstrip("."): v for k, v in doc.items()}


def check_counts(have: dict[str, dict[str, Any]], expect: dict[str, int]) -> list[str]:
    problems = []
    if not have:
        problems.append("the server has no zones at all")
    for zone, count in sorted(expect.items()):
        if zone not in have:
            problems.append(f"zone {zone}: missing (expected {count} records)")
        elif have[zone]["records"] != count:
            problems.append(f"zone {zone}: {have[zone]['records']} records, expected {count}")
    return problems


def cmd_verify(args: argparse.Namespace) -> dict[str, Any]:
    api = _api(args)
    have = inventory(api)
    problems = check_counts(have, _expect(args.expect) if args.expect else {})
    if args.recursion:
        # a restored config brings its own recursion setting: it must be the one the site chose
        got = api.call("settings/get")["response"].get("recursion")
        if got != args.recursion:
            problems.append(f"recursion is {got!r}, the site's setting is {args.recursion!r}")
    if problems:
        raise Refused("; ".join(problems))
    return {"zones": have}


# --------------------------------------------------------------------------- export and restore
def _write_private(path: str, data: bytes) -> None:
    tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _safe_dir(path: str) -> str:
    real = os.path.realpath(path)
    if real != os.path.abspath(path) or len([p for p in real.split(os.sep) if p]) < 3:
        raise Refused(f"{path}: not a canonical directory path of at least three components")
    st = os.lstat(real)
    if not stat.S_ISDIR(st.st_mode):
        raise Refused(f"{path}: not a directory (or a link)")
    return real


def cmd_export(args: argparse.Namespace) -> dict[str, Any]:
    out = _safe_dir(args.out)
    api = _api(args)
    rows, names = [], set()
    zones = [z for z in api.zones() if z.get("type") == "Primary"]
    if not zones:
        raise Refused("the server has no primary zone to export")
    for z in zones:
        name = str(z["name"])
        if not ZONE_NAME.fullmatch(name):
            raise Refused(f"zone name {name!r} is not one this export names")
        text = api.raw("zones/export", zone=name)
        if b"$ORIGIN" not in text:
            raise Refused(f"zone {name}: the export is not a zone file")
        key = name + ".zone"
        _write_private(os.path.join(out, key), text)
        names.add(key)
        rows.append(
            {
                "key": key,
                "zone": name,
                "records": len(api.records(name)),
                "size": len(text),
                "sha256": hashlib.sha256(text).hexdigest(),
            }
        )
    backup = api.raw(
        "settings/backup",
        blockLists="false",
        logs="false",
        scopes="true",
        apps="true",
        stats="false",
        zones="true",
        allowedZones="true",
        blockedZones="true",
        dnsSettings="true",
        logSettings="true",
        authConfig="false",
    )
    if not backup.startswith(b"PK"):
        raise Refused("the settings backup is not a zip")
    _write_private(os.path.join(out, "settings.zip"), backup)
    names.add("settings.zip")
    rows.append(
        {"key": "settings.zip", "size": len(backup), "sha256": hashlib.sha256(backup).hexdigest()}
    )
    stale = os.path.join(out, "stale")
    for entry in sorted(os.listdir(out)):  # a zone that is gone: moved aside, never deleted
        if (
            entry.endswith(".zone")
            and entry not in names
            and os.path.isfile(os.path.join(out, entry))
            and not os.path.islink(os.path.join(out, entry))
        ):
            os.makedirs(stale, mode=0o700, exist_ok=True)
            os.replace(os.path.join(out, entry), os.path.join(stale, entry))
    _write_private(
        os.path.join(out, "listing.jsonl"),
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode(),
    )
    return {"exported": rows}


def read_export(src: str, uid: int) -> list[dict[str, Any]]:
    """The listing's rows after every check; refuses anything the listing does not vouch for."""
    nf = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        dfd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | nf)
    except OSError:
        raise Refused("the source is not a directory (or is a link)") from None

    def trusted(st: os.stat_result, what: str) -> None:
        if st.st_uid not in (0, uid) or st.st_mode & 0o022:
            raise Refused(
                f"{what} must belong to root or the service user and be writable by no one else"
            )

    def opened(name: str) -> tuple[int, os.stat_result]:
        try:
            fd = os.open(name, os.O_RDONLY | nf, dir_fd=dfd)
        except OSError:
            raise Refused(f"{name}: cannot be opened (missing, or a link)") from None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Refused(f"{name}: not a single-link regular file")
        trusted(st, name)
        return fd, st

    try:
        trusted(os.fstat(dfd), "the source directory")
        fd, _ = opened("listing.jsonl")
        with os.fdopen(fd, encoding="utf-8") as f:
            text = f.read(1 << 20)
        rows: dict[str, dict[str, Any]] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            key = r.get("key")
            if (
                not isinstance(key, str)
                or key in rows
                or not (key == "settings.zip" or ZONE_FILE.fullmatch(key))
            ):
                raise Refused("the listing names an unknown or repeated file")
            rows[key] = r
        if not any(k.endswith(".zone") for k in rows):
            raise Refused("the listing names no zone file (an empty export restores nothing)")
        if set(os.listdir(dfd)) - {"listing.jsonl", "stale"} != set(rows):
            raise Refused("the source holds files the listing does not name, or misses one it does")
        for key, r in sorted(rows.items()):
            fd, st = opened(key)
            data = os.read(fd, st.st_size + 1)
            os.close(fd)
            if len(data) != r.get("size") or st.st_size != r.get("size"):
                raise Refused(f"{key}: not the listed size")
            if hashlib.sha256(data).hexdigest() != r.get("sha256"):
                raise Refused(f"{key}: sha256 differs from the listing")
            if key.endswith(".zone"):
                if (
                    r.get("zone") != key[: -len(".zone")]
                    or not isinstance(r.get("records"), int)
                    or r["records"] < 1
                ):
                    raise Refused(f"{key}: the listing does not give its zone and record count")
                if b"$ORIGIN" not in data:
                    raise Refused(f"{key}: not a zone file")
        return [rows[k] for k in sorted(rows)]
    finally:
        os.close(dfd)


def cmd_restore_check(args: argparse.Namespace) -> dict[str, Any]:
    return {"checked": [r["key"] for r in read_export(args.src, args.uid)]}


def cmd_restore_apply(args: argparse.Namespace) -> dict[str, Any]:
    rows = [r for r in read_export(args.src, args.uid) if r["key"].endswith(".zone")]
    api = _api(args)
    have = {str(z["name"]).lower() for z in api.zones()}
    done, problems = [], []
    for r in rows:
        zone = r["zone"]
        if zone.lower() not in have:
            api.call("zones/create", zone=zone, type="Primary")
        with open(os.path.join(args.src, r["key"]), "rb") as f:
            body = f.read()
        api.raw(
            "zones/import",
            body=body,
            query={"zone": zone, "overwrite": "true", "overwriteSoaSerial": "true"},
        )
        count = len(api.records(zone))
        done.append({"zone": zone, "records": count})
        if count != r["records"]:
            problems.append(
                f"zone {zone}: {count} records after the import, the export had {r['records']}"
            )
    if problems:
        raise Refused("; ".join(problems))
    return {"restored": done}


# ------------------------------------------------------------------------------ archived config
def _archive_plan(path: str) -> list[tarfile.TarInfo]:
    try:
        st = os.lstat(path)
    except OSError:
        raise Refused(f"{path}: cannot be read") from None
    if not stat.S_ISREG(st.st_mode):
        raise Refused(f"{path}: not a regular file (or a link)")
    plan: list[tarfile.TarInfo] = []
    members = total = restored = 0
    seen: set[str] = set()
    try:
        with tarfile.open(path, "r:") as tf:
            for m in tf:
                members += 1
                if members > MAX_MEMBERS:
                    raise Refused(f"the archive holds more than {MAX_MEMBERS} members")
                total += m.size if m.isreg() else 0
                if total > MAX_ARCHIVE_BYTES:
                    raise Refused(f"the archive holds more than {MAX_ARCHIVE_BYTES} bytes")
                name = m.name.rstrip("/") if m.isdir() else m.name
                if name.startswith("/") or ".." in name.split("/"):
                    raise Refused(f"{m.name!r}: an absolute or climbing path")
                if not (m.isreg() or m.isdir()):
                    raise Refused(
                        f"{m.name!r}: only plain files and directories are restored from an archive"
                    )
                if any(p.fullmatch(name) for p in ARCHIVE_ALLOW):
                    if not m.isreg() or m.size > MAX_MEMBER_BYTES:
                        raise Refused(
                            f"{m.name!r}: not a regular file within {MAX_MEMBER_BYTES} bytes"
                        )
                    if name in seen:
                        raise Refused(f"{m.name!r}: named twice")
                    seen.add(name)
                    restored += m.size
                    if restored > MAX_RESTORED_BYTES:
                        raise Refused(
                            f"the files to restore hold more than {MAX_RESTORED_BYTES} bytes"
                        )
                    plan.append(m)
                elif not any(p.fullmatch(name) for p in ARCHIVE_IGNORED):
                    raise Refused(f"{m.name!r}: not a path this archive is expected to hold")
    except tarfile.TarError as exc:
        raise Refused(f"{path}: not a readable tar ({exc})") from None
    if not any(ARCHIVE_ALLOW[0].fullmatch(m.name) for m in plan):
        raise Refused("the archive holds no zone file (an empty restore is an error)")
    return plan


def cmd_archive_check(args: argparse.Namespace) -> dict[str, Any]:
    return {"would_restore": [m.name for m in _archive_plan(args.tar)]}


def cmd_archive_apply(args: argparse.Namespace) -> dict[str, Any]:
    plan = _archive_plan(args.tar)
    config = _safe_dir(args.config)
    for entry in sorted(
        os.listdir(config)
    ):  # the container owns this folder: no link may steer a write
        if stat.S_ISLNK(os.lstat(os.path.join(config, entry)).st_mode):
            raise Refused(f"{entry}: a link inside the config folder (the restore follows none)")
    zones = os.path.join(config, "zones")
    if (
        os.path.isdir(zones)
        and any(f.endswith(".zone") for f in os.listdir(zones))
        and not args.overwrite
    ):
        raise Refused("the config folder already holds zones; pass --overwrite to replace them")
    stage = os.path.join(config, f".restore-{random.randrange(1 << 32):08x}")
    os.mkdir(stage, 0o700)
    placed = []
    try:
        with tarfile.open(args.tar, "r:") as tf:
            for m in plan:
                src = tf.extractfile(m)
                if src is None:
                    raise Refused(f"{m.name!r}: cannot be read")
                rel = m.name[len("config/") :]
                tmp = os.path.join(stage, rel.replace("/", "__"))
                with open(tmp, "xb") as out:
                    out.write(src.read(MAX_MEMBER_BYTES + 1))
                os.chown(tmp, args.uid, args.gid)
                os.chmod(tmp, 0o600)
                placed.append((tmp, rel))
        for tmp, rel in placed:
            dest = os.path.join(config, rel)
            os.makedirs(os.path.dirname(dest), mode=0o750, exist_ok=True)
            os.chown(os.path.dirname(dest), args.uid, args.gid)
            os.replace(tmp, dest)
    finally:
        for tmp, _ in placed:
            if os.path.lexists(tmp):
                os.unlink(tmp)
        os.rmdir(stage)
    return {"restored": [rel for _, rel in placed]}


# -------------------------------------------------------------------------------- DNS answers
TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "TXT": 16, "AAAA": 28}
NUM_TYPE = {v: k for k, v in TYPE_NUM.items()}


def build_query(name: str, qtype: str, qid: int | None = None) -> bytes:
    labels = [p for p in name.rstrip(".").split(".") if p]
    if not labels or any(len(p) > 63 for p in labels):
        raise Refused(f"{name!r}: not a DNS name")
    qid = random.randrange(1 << 16) if qid is None else qid
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in labels) + b"\x00"
    return (
        struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack(">HH", TYPE_NUM[qtype], 1)
    )


def _name_at(msg: bytes, off: int) -> tuple[str, int]:
    labels, end, hops = [], None, 0
    while True:
        if off >= len(msg):
            raise Refused("a truncated DNS answer")
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off, hops = ((n & 0x3F) << 8) | msg[off + 1], hops + 1
            if hops > 16:
                raise Refused("a compression loop in a DNS answer")
        elif n == 0:
            return ".".join(labels).lower(), (end if end is not None else off + 1)
        else:
            labels.append(msg[off + 1 : off + 1 + n].decode("ascii", "replace"))
            off += 1 + n


def parse_answer(msg: bytes, qid: int) -> dict[str, Any]:
    if len(msg) < 12:
        raise Refused("a truncated DNS answer")
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid:
        raise Refused("the answer is not for this query")
    off = 12
    for _ in range(qd):
        _, off = _name_at(msg, off)
        off += 4
    answers = []
    for _ in range(an):
        _, off = _name_at(msg, off)
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", msg[off : off + 10])
        off += 10
        rdata = msg[off : off + rdlen]
        kind = NUM_TYPE.get(rtype)
        if kind == "A" and rdlen == 4:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif kind == "AAAA" and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif kind == "CNAME":
            value = _name_at(msg, off)[0]
        elif kind == "TXT":
            value, i = "", 0
            while i < len(rdata):
                value += rdata[i + 1 : i + 1 + rdata[i]].decode("utf-8", "replace")
                i += 1 + rdata[i]
        else:
            value = ""
        answers.append({"type": kind or str(rtype), "value": value, "ttl": ttl})
        off += rdlen
    return {"rcode": flags & 0xF, "authoritative": bool(flags & 0x0400), "answers": answers}


def dns_ask(server: str, port: int, name: str, qtype: str, timeout: float = 5.0) -> dict[str, Any]:
    qid = random.randrange(1 << 16)
    query = build_query(name, qtype, qid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(query, (server, port))
        try:
            msg, _ = s.recvfrom(4096)
        except OSError:
            raise Refused(f"{server}:{port} did not answer {qtype} {name}") from None
    return parse_answer(msg, qid)


def cmd_answers(args: argparse.Namespace) -> dict[str, Any]:
    got = dns_ask(args.server, args.port, args.name, args.type)
    mine = sorted(a["value"] for a in got["answers"] if a["type"] == args.type)
    if got["rcode"] != 0:
        raise Refused(f"{args.name} {args.type}: rcode {got['rcode']}")
    if not got["answers"]:
        raise Refused(f"{args.name} {args.type}: no answer")
    if args.expect is not None and mine != sorted(v for v in args.expect.split(",") if v):
        raise Refused(f"{args.name} {args.type}: answered {mine}, expected {args.expect}")
    return {"name": args.name, "type": args.type, "values": mine}


# ------------------------------------------------------------------------------------- compare
def _canon(rec: dict[str, Any]) -> str:
    rdata = dict(rec.get("rData") or {})
    for volatile in ("serial",):  # a zone's serial is the server's own counter
        rdata.pop(volatile, None)
    rdata = {k: (v.lower().rstrip(".") if isinstance(v, str) else v) for k, v in rdata.items()}
    return json.dumps(
        [
            str(rec["name"]).lower().rstrip("."),
            rec["type"],
            rec.get("ttl"),
            bool(rec.get("disabled")),
            rdata,
        ],
        sort_keys=True,
    )


def diff_zone(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[str]:
    a, b = {_canon(r) for r in old}, {_canon(r) for r in new}
    return [f"only on the old server: {x}" for x in sorted(a - b)] + [
        f"only on the new server: {x}" for x in sorted(b - a)
    ]


def cmd_compare(args: argparse.Namespace) -> dict[str, Any]:
    old, new = _api(args, "old_"), _api(args, "new_")
    old_zones = {str(z["name"]).lower(): z for z in old.zones() if z.get("type") == "Primary"}
    if not old_zones:
        raise Refused("the old server has no primary zone (nothing to compare is an error)")
    new_zones = {str(z["name"]).lower() for z in new.zones()}
    problems, report, queries = [], {}, 0
    for name in sorted(old_zones):
        if name not in new_zones:
            problems.append(f"zone {name}: missing on the new server")
            continue
        old_recs, new_recs = old.records(name), new.records(name)
        d = diff_zone(old_recs, new_recs)
        problems += [f"zone {name}: {x}" for x in d]
        report[name] = {"old": len(old_recs), "new": len(new_recs), "differences": len(d)}
        if args.dns_old and args.dns_new:
            for r in old_recs:
                if r["type"] not in ("A", "AAAA", "CNAME", "TXT"):
                    continue
                qname = str(r["name"]).replace("*", "hnx-probe")
                answers = []
                for hostport in (args.dns_old, args.dns_new):
                    host, port = hostport.rsplit(":", 1)
                    got = dns_ask(host, int(port), qname, r["type"])
                    answers.append(
                        (got["rcode"], sorted((x["type"], x["value"]) for x in got["answers"]))
                    )
                queries += 1
                if answers[0] != answers[1]:
                    problems.append(
                        f"answer for {r['type']} {qname}: old {answers[0]}, new {answers[1]}"
                    )
    if problems:
        raise Refused("; ".join(problems))
    return {"zones": report, "dns_answers_compared": queries}


# ------------------------------------------------------------------------------------- the CLI
def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def api_args(sp: argparse.ArgumentParser, prefix: str = "") -> None:
        flag = "--" + prefix.replace("_", "-")
        sp.add_argument(
            flag + "api",
            dest=prefix + "api",
            required=True,
            help="the admin API base URL (the web service port, 5380)",
        )
        sp.add_argument(flag + "user", dest=prefix + "user", default="admin")
        sp.add_argument(
            flag + "password-env", dest=prefix + "password_env", default="HNX_TECHNITIUM_PASSWORD"
        )

    sp = sub.add_parser("inventory")
    api_args(sp)
    sp.set_defaults(fn=cmd_inventory)
    sp = sub.add_parser("verify")
    api_args(sp)
    sp.add_argument("--expect")
    sp.add_argument("--recursion", help="fail unless the server's recursion setting is this")
    sp.set_defaults(fn=cmd_verify)
    sp = sub.add_parser("export")
    api_args(sp)
    sp.add_argument("--out", required=True)
    sp.set_defaults(fn=cmd_export)
    sp = sub.add_parser("restore-check")
    sp.add_argument("--src", required=True)
    sp.add_argument("--uid", type=int, required=True)
    sp.set_defaults(fn=cmd_restore_check)
    sp = sub.add_parser("restore-apply")
    api_args(sp)
    sp.add_argument("--src", required=True)
    sp.add_argument("--uid", type=int, required=True)
    sp.set_defaults(fn=cmd_restore_apply)
    sp = sub.add_parser("archive-check")
    sp.add_argument("--tar", required=True)
    sp.set_defaults(fn=cmd_archive_check)
    sp = sub.add_parser("archive-apply")
    sp.add_argument("--tar", required=True)
    sp.add_argument("--config", required=True)
    sp.add_argument("--uid", type=int, required=True)
    sp.add_argument("--gid", type=int, required=True)
    sp.add_argument("--overwrite", action="store_true")
    sp.set_defaults(fn=cmd_archive_apply)
    sp = sub.add_parser("answers")
    sp.add_argument("--server", required=True)
    sp.add_argument("--port", type=int, default=53)
    sp.add_argument("--name", required=True)
    sp.add_argument("--type", choices=sorted(TYPE_NUM), default="A")
    sp.add_argument("--expect")
    sp.set_defaults(fn=cmd_answers)
    sp = sub.add_parser("compare")
    api_args(sp, "old_")
    api_args(sp, "new_")
    sp.add_argument("--dns-old", help="host:port of the old server's DNS, to compare answers too")
    sp.add_argument("--dns-new", help="host:port of the new server's DNS")
    sp.set_defaults(fn=cmd_compare)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        print(json.dumps(args.fn(args), sort_keys=True))
    except Refused as exc:
        print(f"technitium_ctl {args.cmd}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
