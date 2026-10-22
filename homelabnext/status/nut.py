# SPDX-License-Identifier: Apache-2.0
"""``poll-nut``: a UPS read from Network UPS Tools' data server (``upsd``, TCP 3493).

Standard library only: a socket, the NUT network protocol (``docs/net-protocol.txt``) and, for
``STARTTLS``, :mod:`ssl`.  One poll is one connection:

    [STARTTLS -> OK STARTTLS, then a TLS handshake that verifies upsd's certificate]
    [USERNAME <name> -> OK;  PASSWORD <secret> -> OK]      (only with ``auth``)
    LIST UPS -> BEGIN LIST UPS / UPS <name> "<desc>" / END LIST UPS   (only without mapping.ups)
    LIST VAR <ups> -> BEGIN LIST VAR <ups> / VAR <ups> <var> "<value>" / END LIST VAR <ups>
    LOGOUT -> OK Goodbye

The replies were recorded from a real upsd 2.8.1 (NSS build, ``dummy-ups`` driver, STARTTLS
with a certificate database) and are replayed by the fake upsd in the tests
(``tests/status/fixtures/nut/``).  Two facts from that recording: upsd answers ``OK`` to
``PASSWORD`` whatever the password (it checks the pair only for a command that needs it, such
as ``LOGIN``; reads are governed by upsd's own access rules), and ``STARTTLS`` on an upsd with
no certificate answers ``ERR FEATURE-NOT-CONFIGURED``.

``ups.status`` is a list of flags (``docs/new-drivers.txt``, "Status data"): OL on line, OB on
battery, LB low battery, HB high battery, RB replace battery, CHRG charging, DISCHRG
discharging, BYPASS on bypass (no battery protection), CAL calibrating, OFF not powering its
load, OVER overloaded, TRIM / BOOST correcting the input voltage, FSD forced shutdown; upsd adds
ALARM when the driver raised an alarm (``ups.alarm`` says which) and reports WAIT until the
driver first answers.  Clients must accept any other token, so an unknown flag is shown and
otherwise ignored.  The status item's state is the worst of its flags (:data:`FLAG_STATES`:
on battery is warn, low battery, replace battery, overload, off and forced shutdown are fail);
a status with no line flag (OL, OB, OFF, BYPASS) is unknown, never ok.

Every summary of a ``status`` item starts with the raw flags and a colon (``OB DISCHRG: on
battery, ...``) for the reader.  The flags themselves travel as a structured field
(``Draft.flags``), which is how the hub knows a UPS is on battery (:mod:`.power`): never by
re-parsing a summary, since one that means "no reading" (``UPS1: upsd has stale data``,
``NONE: no ups.status``) can look just like a list of flags.  An unreadable UPS has no flags.
"""

from __future__ import annotations

import math
import re
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .mapping import Draft, MappingError, age_text, clean_item, clean_summary
from .model import SEVERITY

if TYPE_CHECKING:
    from .collectors import CollectContext
    from .model import SourceSpec

DEFAULT_PORT = 3493
MAX_LINE = 4096  # a NUT line is a variable and its value; longer is not upsd
MAX_LIST = 2000  # variables (or UPSes) in one list: far above any real driver
#: flag -> state (docs/new-drivers.txt "Status data"; ALARM and WAIT from upsd itself)
FLAG_STATES = {
    "ol": "ok",
    "chrg": "ok",
    "trim": "ok",
    "boost": "ok",
    "ob": "warn",
    "dischrg": "warn",
    "hb": "warn",
    "cal": "warn",
    "bypass": "warn",
    "alarm": "warn",
    "lb": "fail",
    "rb": "fail",
    "over": "fail",
    "off": "fail",
    "fsd": "fail",
    "wait": "unknown",
}
FLAG_WORDS = {
    "OL": "on line power",
    "OB": "on battery",
    "LB": "low battery",
    "HB": "high battery",
    "RB": "replace battery",
    "CHRG": "charging",
    "DISCHRG": "discharging",
    "BYPASS": "on bypass (no battery protection)",
    "CAL": "calibrating",
    "OFF": "off (not powering its load)",
    "OVER": "overloaded",
    "TRIM": "trimming the input voltage",
    "BOOST": "boosting the input voltage",
    "FSD": "forced shutdown",
    "ALARM": "alarm",
    "WAIT": "waiting for its driver",
}
#: the flags that say where the load's power comes from; without one the status says nothing
LINE_FLAGS = {"OL", "OB", "OFF", "BYPASS"}
#: default limits: charge and runtime at or below, load at or above
DEFAULT_LIMITS = {
    "charge": {"warn": 50, "fail": 20},
    "runtime_s": {"warn": 600, "fail": 120},
    "load": {"warn": 80, "fail": 95},
}
#: per-UPS errors that mean "no reading from this UPS right now", not a misconfigured source
UPS_ERRORS = {
    "DATA-STALE": "upsd has stale data (the driver lost the UPS)",
    "DRIVER-NOT-CONNECTED": "upsd has no driver for it (the driver is not running)",
}
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")


class NutError(Exception):
    """upsd answered ``ERR <code>``; ``code`` is the one-word error."""

    def __init__(self, code: str, command: str):
        super().__init__(f"upsd: ERR {code} (to {command})")
        self.code = code


# ---------------------------------------------------------------- the protocol
def split_words(line: str) -> list[str]:
    """One NUT line -> its elements (parseconf rules: whitespace separates, ``"..."`` groups,
    a backslash quotes the next character inside or outside quotes)."""
    out: list[str] = []
    cur: list[str] = []
    started = quoted = escaped = False
    for ch in line:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = started = True
        elif quoted:
            if ch == '"':
                quoted = False
                out.append("".join(cur))
                cur, started = [], False
            else:
                cur.append(ch)
        elif ch == '"' and not started:
            quoted = started = True
        elif ch in " \t":
            if started:
                out.append("".join(cur))
                cur, started = [], False
        else:
            cur.append(ch)
            started = True
    if quoted:
        raise MappingError("upsd: unterminated quote")
    if started:
        out.append("".join(cur))
    return out


def quote(arg: str) -> str:
    """An argument as one NUT element: quoted (``\\`` and ``"`` escaped) when it needs it."""
    if _UNSAFE.search(arg):
        raise ValueError("a NUT argument may not hold a control character")
    if arg and not re.search(r'[\s"\\#=]', arg):
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


class NutSession:
    """One upsd connection under one deadline (``timeout`` bounds the whole session)."""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.host, self.port = host, port
        self._clock = clock
        self._deadline = clock() + timeout
        self._buf = b""
        self.tls = False
        self.sock: socket.socket = socket.create_connection((host, port), timeout=timeout)

    def _remaining(self) -> float:
        left = self._deadline - self._clock()
        if left <= 0:
            raise TimeoutError(f"upsd {self.host}:{self.port}: timed out")
        return left

    def _line(self) -> str:
        while b"\n" not in self._buf:
            if len(self._buf) > MAX_LINE:
                raise MappingError("upsd: a reply line is too long")
            self.sock.settimeout(self._remaining())
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("upsd closed the connection")
            self._buf += chunk
        raw, _, self._buf = self._buf.partition(b"\n")
        if len(raw) > MAX_LINE:
            raise MappingError("upsd: a reply line is too long")
        try:
            return raw.decode("utf-8").rstrip("\r")
        except UnicodeDecodeError:
            return raw.decode("latin-1").rstrip("\r")

    def _send(self, line: str) -> None:
        self.sock.settimeout(self._remaining())
        self.sock.sendall(line.encode("utf-8") + b"\n")

    def command(self, *words: str) -> list[str]:
        """Send one command; its reply line (or, for ``LIST``, the lines between ``BEGIN LIST``
        and ``END LIST``).  ``ERR`` raises :class:`NutError`."""
        name = " ".join(words[:2]) if words[0] in ("LIST", "GET") else words[0]
        self._send(" ".join(quote(w) for w in words))
        first = self._line()
        if first.startswith("ERR "):
            raise NutError(first.split()[1], name)
        if words[0] != "LIST":
            return [first]
        if not first.startswith("BEGIN LIST"):
            raise MappingError(f"upsd: expected BEGIN LIST, got {first[:60]!r}")
        out = []
        while True:
            line = self._line()
            if line.startswith("END LIST"):
                return out
            out.append(line)
            if len(out) > MAX_LIST:
                raise MappingError("upsd: a list is too long")

    def starttls(self, context: ssl.SSLContext) -> None:
        """``STARTTLS`` -> ``OK STARTTLS``, then a verified handshake on the same socket."""
        reply = self.command("STARTTLS")[0]
        if reply != "OK STARTTLS":
            raise MappingError(f"upsd: unexpected STARTTLS answer {reply[:60]!r}")
        if self._buf:  # nothing may arrive between the answer and the handshake
            raise MappingError("upsd: data before the TLS handshake")
        self.sock.settimeout(self._remaining())
        self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
        self.tls = True

    def login(self, username: str, password: str) -> None:
        for verb, value in (("USERNAME", username), ("PASSWORD", password)):
            if self.command(verb, value)[0] != "OK":
                raise MappingError(f"upsd: {verb} was not accepted")

    def list_ups(self) -> list[str]:
        names = []
        for line in self.command("LIST", "UPS"):
            w = split_words(line)
            if len(w) >= 2 and w[0] == "UPS":
                names.append(w[1])
        return names

    def list_var(self, ups: str) -> dict[str, str]:
        out = {}
        for line in self.command("LIST", "VAR", ups):
            w = split_words(line)
            if len(w) == 4 and w[0] == "VAR" and w[1] == ups:
                out[w[2]] = w[3]
        return out

    def get_var(self, ups: str, var: str) -> str | None:
        """One variable, or None when the UPS does not support it."""
        try:
            w = split_words(self.command("GET", "VAR", ups, var)[0])
        except NutError as exc:
            if exc.code == "VAR-NOT-SUPPORTED":
                return None
            raise
        if len(w) != 4 or w[0] != "VAR":
            raise MappingError(f"upsd: unexpected GET VAR answer for {var}")
        return w[3]

    def close(self) -> None:
        try:
            self._send("LOGOUT")
            self._line()
        except (OSError, ValueError, MappingError, TimeoutError):
            pass
        finally:
            self.sock.close()


# ---------------------------------------------------------------- the mapper
def _num(raw: str | None) -> float:
    try:
        return float(raw) if raw is not None else math.nan
    except ValueError:
        return math.nan


def _limits(mapping: Mapping[str, Any], name: str, own_fail: float) -> dict[str, float]:
    """The defaults, then the UPS's own ``battery.*.low`` as fail, then the source's limits."""
    lim = dict(DEFAULT_LIMITS[name])
    if not math.isnan(own_fail):
        lim["fail"] = own_fail
    lim.update((mapping.get("limits") or {}).get(name) or {})
    return lim


def _judge(value: float, lim: Mapping[str, float], below: bool, unit: str) -> tuple[str, str]:
    if math.isnan(value):
        return "unknown", " (not a number)"
    word = "at or below" if below else "at or above"
    for state in ("fail", "warn"):
        bound = lim.get(state)
        if bound is not None and (value <= bound if below else value >= bound):
            return state, f" ({state} {word} {bound:g}{unit})"
    return "ok", ""


def _runtime(seconds: float) -> str:
    return f"{int(seconds)} s" if seconds < 60 else age_text(seconds)


def ups_drafts(
    name: str, var: Mapping[str, str], mapping: Mapping[str, Any], prefix: str = ""
) -> list[Draft]:
    """``LIST VAR`` of one UPS -> its items: ``status`` (from ``ups.status``), and where the UPS
    reports them ``battery-charge``, ``battery-runtime`` and ``load`` judged by the limits."""
    table = {**FLAG_STATES, **{str(k).lower(): v for k, v in (mapping.get("states") or {}).items()}}
    raw = (var.get("ups.status") or "").split()
    flags = [f.upper() for f in raw]
    known = [f for f in flags if f.lower() in table]
    state = max((table[f.lower()] for f in known), key=SEVERITY.__getitem__, default="unknown")
    if state == "ok" and not LINE_FLAGS & set(flags):
        state = "unknown"
    words = []
    for f in flags:
        w = FLAG_WORDS.get(f, f"{f} (not a known flag)")
        if f == "ALARM" and var.get("ups.alarm"):
            w = f"alarm: {var['ups.alarm']}"
        words.append(w)
    model = var.get("device.model") or var.get("ups.model")
    facts = []
    charge, runtime, load = (
        _num(var.get("battery.charge")),
        _num(var.get("battery.runtime")),
        _num(var.get("ups.load")),
    )
    if not math.isnan(charge):
        facts.append(f"{charge:g}% charge")
    if not math.isnan(runtime):
        facts.append(f"{_runtime(runtime)} runtime")
    if not math.isnan(load):
        facts.append(f"load {load:g}%")
    text = ", ".join(words) or "no ups.status"
    if facts:
        text += "; " + ", ".join(facts)
    if model:
        text += f"; {model}"
    head = " ".join(flags) or "NONE"
    status = clean_summary(f"{head}: {text}")
    out = [Draft(clean_item(f"{prefix}status", "status"), state, status, flags=tuple(flags))]
    for item, key, lim_name, below, unit, show in (
        ("battery-charge", "battery.charge", "charge", True, "%", lambda v: f"{v:g}%"),
        ("battery-runtime", "battery.runtime", "runtime_s", True, " s", _runtime),
        ("load", "ups.load", "load", False, "%", lambda v: f"{v:g}%"),
    ):
        if key not in var:
            continue
        own = _num(var.get(f"{key}.low")) if below else math.nan
        value = _num(var[key])
        st, note = _judge(value, _limits(mapping, lim_name, own), below, unit)
        shown = show(value) if not math.isnan(value) else repr(var[key][:20])
        out.append(
            Draft(
                clean_item(f"{prefix}{item}", item),
                st,
                clean_summary(f"{name}: {shown}{note}"),
                value=None if math.isnan(value) else value,
            )
        )
    return out


def unreadable(name: str, code: str, prefix: str = "") -> Draft:
    """A UPS upsd knows but cannot read right now (``DATA-STALE``, ``DRIVER-NOT-CONNECTED``)."""
    return Draft(
        clean_item(f"{prefix}status", "status"),
        "unknown",
        clean_summary(f"{name}: {UPS_ERRORS.get(code, code)} (ERR {code})"),
    )


# ---------------------------------------------------------------- the collector
def _tls_context(spec: SourceSpec, ctx: CollectContext) -> ssl.SSLContext:
    from .collectors import CollectError, _inside

    ca = spec.mapping.get("ca_file")
    try:
        context = ssl.create_default_context(cafile=str(_inside(ctx.root, str(ca))) if ca else None)
    except (OSError, ssl.SSLError) as exc:
        raise CollectError(f"source {spec.id}: ca_file: {exc}") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _endpoint(spec: SourceSpec, ctx: CollectContext) -> tuple[str, int]:
    from .collectors import CollectError

    if ctx.endpoint is None:
        raise CollectError("no endpoint resolver configured")
    parts = urlsplit(ctx.endpoint(spec.polled_service))
    if not parts.hostname:
        raise CollectError(f"{spec.polled_service}: no host")
    return parts.hostname, parts.port or DEFAULT_PORT


def credentials(spec: SourceSpec, ctx: CollectContext) -> tuple[str, str] | None:
    """``(username, password)`` for a source with ``auth`` (the password by secret name), or
    None.  A reference that does not resolve is the source's error, never a silent anonymous
    read; nothing read for the secret store appears in a message."""
    from .collectors import CollectError

    if not spec.auth:
        return None
    value = ctx.secret(str(spec.auth["secret"])) if ctx.secret is not None else None
    if not value:
        raise CollectError(
            f"source {spec.id}: its auth credential did not resolve (environment or --secrets-dir)"
        )
    return str(spec.auth.get("username") or ""), value


class NutCollector:
    """``poll-nut``: ``LIST VAR`` of one UPS (``mapping.ups``) or of every UPS upsd lists."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        from homelabnext._http import is_loopback

        from .collectors import CollectError

        host, port = _endpoint(spec, ctx)
        tls = spec.mapping.get("tls", "starttls") == "starttls"
        creds = credentials(spec, ctx)
        if creds and not tls and not spec.mapping.get("allow_plaintext") and not is_loopback(host):
            raise CollectError(
                f"source {spec.id}: refusing to send the NUT password in plaintext to {host}: "
                "use tls: starttls or set allow_plaintext: true explicitly"
            )
        context = _tls_context(spec, ctx) if tls else None
        try:
            session = NutSession(host, port, spec.timeout_s)
        except OSError as exc:
            raise CollectError(f"upsd {spec.polled_service}: {exc.strerror or exc}") from None
        try:
            return self._read(session, spec, context, creds)
        except NutError as exc:
            if exc.code in ("FEATURE-NOT-CONFIGURED", "FEATURE-NOT-SUPPORTED"):
                raise CollectError(
                    f"upsd {spec.polled_service} does not offer STARTTLS (ERR {exc.code}): give "
                    "upsd a certificate, or set tls: none"
                ) from None
            raise CollectError(str(exc)) from None
        except ssl.SSLError as exc:
            raise CollectError(f"upsd {spec.polled_service}: TLS: {exc.reason or exc}") from None
        except (OSError, TimeoutError) as exc:
            raise CollectError(f"upsd {spec.polled_service}: {exc}") from None
        finally:
            session.close()

    @staticmethod
    def _read(
        session: NutSession,
        spec: SourceSpec,
        context: ssl.SSLContext | None,
        creds: tuple[str, str] | None,
    ) -> list[Draft]:
        if context is not None:
            session.starttls(context)
        if creds:
            session.login(*creds)
        one = spec.mapping.get("ups")
        names = [str(one)] if one else session.list_ups()
        out: list[Draft] = []
        for name in names:
            prefix = "" if one else f"{name}:"
            try:
                out += ups_drafts(name, session.list_var(name), spec.mapping, prefix)
            except NutError as exc:
                if exc.code not in UPS_ERRORS:
                    raise
                out.append(unreadable(name, exc.code, prefix))
        return out


# ---------------------------------------------------------------- registry rules
MAPPING_KEYS = {"module", "ups", "tls", "allow_plaintext", "ca_file", "limits", "states"}


def source_problems(src: Mapping[str, Any], where: str) -> list[str]:
    """Registry rules for ``poll-nut`` the schema cannot state (``hnx registry validate``)."""
    problems = []
    mapping = src.get("mapping") or {}
    target = src.get("target") or {}
    auth = src.get("auth") or {}
    if "path" in target or "file" in target:
        problems.append(f"{where}: poll-nut takes only target.service (upsd, TCP)")
    extra = sorted(set(mapping) - MAPPING_KEYS)
    if extra:
        problems.append(
            f"{where}: poll-nut mapping takes only {sorted(MAPPING_KEYS)} (not {extra})"
        )
    if mapping.get("ups") is not None and not _NAME.match(str(mapping["ups"])):
        problems.append(f"{where}: mapping.ups {mapping['ups']!r} is not a NUT upsname")
    if auth and ("header" in auth or not auth.get("username")):
        problems.append(f"{where}: poll-nut auth is {{username, secret}} (no header)")
    if mapping.get("allow_plaintext") and mapping.get("tls", "starttls") != "none":
        problems.append(f"{where}: allow_plaintext only means something with tls: none")
    if mapping.get("ca_file") and mapping.get("tls", "starttls") == "none":
        problems.append(f"{where}: ca_file is for tls: starttls")
    for k in mapping.get("states") or {}:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,15}", str(k)):
            problems.append(f"{where}: states key {k!r} is not a ups.status flag")
    for name, lim in (mapping.get("limits") or {}).items():
        if not ({"warn", "fail"} & set(lim or {})):
            problems.append(f"{where}: limits.{name} needs warn or fail")
    return problems
