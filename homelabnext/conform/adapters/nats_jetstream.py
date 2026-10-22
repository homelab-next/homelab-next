# SPDX-License-Identifier: Apache-2.0
"""The ``events`` contract on NATS JetStream (pinned: nats 2.10 with ``-js``).

``make(**config)`` builds a :class:`JetStreamBus` on the server named by ``HNX_ENDPOINT_EVENTS``
(``nats://host:port``).  The bus speaks the JetStream wire API (``$JS.API.*`` JSON requests,
``$JS.ACK.*`` replies) through a small :class:`Wire` interface; :class:`NatsPyWire` is that
interface over nats-py (``pip install 'homelabnext[nats]'``), and the unit tests drive the same
mapping with an in-process fake of the server, so no server is needed offline.  A server with
accounts takes ``user`` and ``password_secret``, the secret-store *name* of the password (its
value is delivered as ``HNX_SECRET_<NAME>``, read when the connection is made, and never logged
or held by the bus).  A password goes only over ``tls://`` (``ca_file`` for a private CA) or to a
loopback ``nats://`` endpoint, unless ``allow_plaintext=True`` says otherwise explicitly (the lab).
A ``tls://`` connection does the TLS handshake *first*, before the server's ``INFO`` (nats-py's
``tls_handshake_first``): a client that upgrades only when ``INFO`` asks for TLS sends its
``CONNECT``, password included, in clear to anything that answers without asking.  The server
needs ``tls { handshake_first: true }`` (nats-server 2.10.3 or later).

How the contract maps onto JetStream:

* **Stream.**  One limits-retention stream captures ``<prefix>.>``; a contract subject ``a.b`` is
  the NATS subject ``<prefix>.a.b``.  (A stream may not capture ``>`` itself unless it is no-ack,
  and a no-ack publish returns no sequence, so a prefix is required.)  With ``provision=False``
  the bus creates no stream: both (the stream and its DLQ) must exist already, each with a
  ``max_bytes`` limit, or the bus refuses to open (a long-running consumer that creates unbounded
  streams lets a flood fill the server's disk).
* **publish** is a request to the subject; the PubAck carries the stream sequence.  ``msg_id`` is
  the ``Nats-Msg-Id`` header; a repeat inside the stream's ``duplicate_window`` gets the PubAck of
  the original (``"duplicate": true``) with the original sequence.
* **consumer** is a durable pull consumer (never a push one: no ``deliver_subject``):
  ``deliver_policy=new`` (it sees what is published after it was created), ``ack_policy=explicit``,
  ``max_deliver``, ``ack_wait`` and a filter of ``<prefix>.<pattern>`` (``*`` and ``>`` are native
  NATS wildcards).  With ``replay_s`` a durable this bus creates starts ``replay_s`` seconds back
  instead (``deliver_policy=by_start_time``), so what was published before it existed (the first
  start of a consumer, or one recreated) is not skipped, while a long-retention stream still does
  not replay its whole history.  A literal filter is created with the 2.9+ form
  ``CONSUMER.CREATE.<stream>.<durable>.<filter>``: the server holds the request to the filter in
  its subject, so a user granted exactly that subject can create that durable and no other shape.
* **fetch** is one ``CONSUMER.MSG.NEXT`` pull with ``no_wait``: the server answers with what is
  deliverable now and a ``404``/``408`` status, so an empty consumer returns at once.  The attempt
  number is the delivery count from the ack reply subject.
* **ack / nack / term** are ``+ACK`` / ``-NAK`` / ``+TERM`` sent as *requests*: the server answers
  each one after processing it ("ack the ack"), so a following fetch cannot overtake it.  Only the
  first settlement of a delivery is sent; later ones are no-ops on the client.
* **Dead letters** are JetStream's own advisories, captured by a second stream (the documented DLQ
  pattern): ``$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.<stream>.*`` and ``...MSG_TERMINATED...``.
  ``dead_letters()`` reads the advisories for its consumer and loads each original message by its
  stream sequence, so the list survives the client and is the server's record, not ours.
* **Reopen** binds to the existing durable.  JetStream redelivers a delivery nobody settled once
  its ``ack_wait`` lapses; the server does not know a client restarted.  So when the durable still
  has unacknowledged deliveries, reopening waits one ``ack_wait`` (plus a margin) for the previous
  incarnation's leases to lapse, after which every one of them is redelivered with attempt + 1.
  A durable this bus has not opened before was leased before the bus existed, so a new bus that
  reopens several durables waits one lease from its own start, not one per durable.
  Deliveries handed out before the reopen are detached: settling them is a no-op.

Findings (where the product's semantics are narrower than the contract's words):

* Publish dedup holds only within the stream's ``duplicate_window`` (here ``duplicate_window``
  seconds, default one hour): a ``msg_id`` repeated later is a new message.
* A message nacked on its last allowed attempt is dead-lettered when the server next tries to
  deliver it (the next pull on that consumer), not at the nack; ``dead_letters()`` waits up to
  ``dlq_wait`` seconds for the deliveries this client expects to see dead-lettered.
* An unsettled delivery is also redelivered, without a reopen, once ``ack_wait`` lapses (that is
  JetStream's at-least-once lease); keep handlers shorter than ``ack_wait``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from conformance.protocols.events import Delivery, EventsError
from homelabnext._http import check_plaintext

from ._env import env_secret, resolve

__all__ = [
    "JetStreamApiError",
    "JetStreamBus",
    "JetStreamConsumer",
    "NatsPyWire",
    "PublishRefused",
    "Wire",
    "WireError",
    "WireMsg",
    "make",
    "provision_streams",
]

_ADVISORY_MAX = "$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES"
_ADVISORY_TERM = "$JS.EVENT.ADVISORY.CONSUMER.MSG_TERMINATED"
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SETTLE = {"ack": b"+ACK", "nack": b"-NAK", "term": b"+TERM"}
_NS = 1_000_000_000
_NOT_FOUND = {"stream": 10059, "consumer": 10014, "message": 10037}
_PERMISSION_DENIED = re.compile(r'Permissions Violation for Publish to "([^"]+)"', re.I)


class WireError(EventsError):
    """The transport failed: no connection, no responder, or no reply in time.  ``permanent``:
    retrying the same message cannot succeed (the server refuses this user the subject, or the
    size), as opposed to an outage, which can.  No responders is an outage: a JetStream restart or
    leader election looks the same as a stream that is missing, and neither is the message's
    fault."""

    def __init__(self, message: str, *, permanent: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent


class PublishRefused(EventsError):
    """The message itself cannot be published (an invalid subject or message id): permanent."""

    permanent = True


class JetStreamApiError(EventsError):
    """The JetStream API answered with an error object."""

    def __init__(self, what: str, code: int, err_code: int, description: str):
        super().__init__(f"{what}: JetStream error {code}/{err_code}: {description}")
        self.code, self.err_code, self.description = code, err_code, description


@dataclass(frozen=True)
class WireMsg:
    subject: str
    data: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    reply: str = ""


class Wire(Protocol):
    """The three NATS operations the bus needs.  ``pull`` publishes ``payload`` with a fresh
    reply inbox and returns the data messages that arrive on it, stopping at the first status
    message (``Status`` header), after ``max_msgs`` messages, or after ``timeout`` seconds."""

    def request(
        self,
        subject: str,
        payload: bytes = b"",
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float,
    ) -> WireMsg: ...

    def pull(
        self, subject: str, payload: bytes, *, max_msgs: int, timeout: float
    ) -> list[WireMsg]: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------- helpers
def _check_subject(subject: str, *, pattern: bool) -> list[str]:
    if not isinstance(subject, str) or not subject:
        raise EventsError("subject must be a non-empty string")
    tokens = subject.split(".")
    for i, tok in enumerate(tokens):
        if not tok or any(c.isspace() for c in tok):
            raise EventsError(f"invalid subject {subject!r}: empty token or whitespace")
        if tok in ("*", ">") or "*" in tok or ">" in tok:
            if not pattern:
                raise EventsError(f"cannot publish to a wildcard subject {subject!r}")
            if tok not in ("*", ">") or (tok == ">" and i != len(tokens) - 1):
                raise EventsError(f"invalid subject pattern {subject!r}")
    return tokens


def durable_name(name: str) -> str:
    """The contract's consumer name as a JetStream durable name (no ``.``, ``*``, ``>``, space)."""
    if not isinstance(name, str) or not name:
        raise EventsError("consumer name must be a non-empty string")
    if _NAME_RE.match(name):
        return name
    return "h" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:24]


def parse_ack_reply(reply: str) -> tuple[str, str, int, int]:
    """``(stream, consumer, delivery_count, stream_seq)`` from a ``$JS.ACK`` reply subject (the
    9-token form, and the 12+-token form with domain and account hash)."""
    t = reply.split(".")
    if len(t) < 9 or t[0] != "$JS" or t[1] != "ACK":
        raise EventsError(f"not a JetStream delivery (reply {reply!r})")
    if len(t) == 9:
        stream, consumer, dc, sseq = t[2], t[3], t[4], t[5]
    else:
        stream, consumer, dc, sseq = t[4], t[5], t[6], t[7]
    try:
        return stream, consumer, int(dc), int(sseq)
    except ValueError:
        raise EventsError(f"malformed ack reply subject {reply!r}") from None


def parse_headers(raw: bytes) -> dict[str, str]:
    """Headers from a stored message's ``hdrs`` block (``NATS/1.0\\r\\nKey: value\\r\\n...``)."""
    out: dict[str, str] = {}
    for line in raw.decode("utf-8", "replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def _noop(_how: str) -> None:
    return None


def _api(
    wire: Wire, what: str, body: Mapping[str, Any] | None, *, timeout: float, missing: str = ""
) -> Any:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    msg = wire.request(f"$JS.API.{what}", payload, timeout=timeout)
    try:
        doc = json.loads(msg.data or b"{}")
    except ValueError:
        raise EventsError(f"{what}: reply is not JSON") from None
    if not isinstance(doc, dict):
        raise EventsError(f"{what}: reply is not an object")
    err = doc.get("error")
    if err:
        code, err_code = int(err.get("code", 0)), int(err.get("err_code", 0))
        if missing and err_code == _NOT_FOUND[missing]:
            return None
        raise JetStreamApiError(what, code, err_code, str(err.get("description", "")))
    return doc


def provision_streams(
    wire: Wire,
    *,
    stream: str,
    subject_prefix: str,
    max_bytes: int,
    dlq_max_bytes: int | None = None,
    max_age: float = 30 * 86400.0,
    duplicate_window: float = 86400.0,
    storage: str = "file",
    timeout: float = 5.0,
) -> list[str]:
    """The operator's one-time step for a standing bus: create the stream (``<prefix>.>``) and
    its DLQ (the dead-letter advisories), each bounded (``max_bytes``, ``max_age``), when missing.
    Returns the names it created.  Clients opened with ``provision=False`` (the broker's relay,
    the StackStorm bridge) then need no ``STREAM.CREATE`` at all.  The same as ``nats stream add``
    with these settings."""
    if not _NAME_RE.match(stream or "") or max_bytes <= 0:
        raise EventsError("a stream name and a positive max_bytes are required")
    _check_subject(subject_prefix, pattern=False)
    base = {
        "retention": "limits",
        "storage": storage,
        "discard": "old",
        "num_replicas": 1,
        "max_age": int(max_age * _NS),
    }
    dlq = f"{stream}_DLQ"
    configs = [
        {
            "name": stream,
            "subjects": [f"{subject_prefix}.>"],
            "duplicate_window": int(duplicate_window * _NS),
            "max_bytes": int(max_bytes),
            **base,
        },
        {
            "name": dlq,
            "subjects": [f"{_ADVISORY_MAX}.{stream}.*", f"{_ADVISORY_TERM}.{stream}.*"],
            "max_bytes": int(dlq_max_bytes or max(1, max_bytes // 4)),
            **base,
        },
    ]
    created = []
    for config in configs:
        name = config["name"]
        if _api(wire, f"STREAM.INFO.{name}", None, timeout=timeout, missing="stream") is None:
            _api(wire, f"STREAM.CREATE.{name}", config, timeout=timeout)
            created.append(name)
    return created


# --------------------------------------------------------------------------- the bus
class JetStreamBus:
    """:class:`conformance.protocols.events.EventBus` on one JetStream stream (see module doc)."""

    features = frozenset({"wildcards"})

    def __init__(
        self,
        wire: Wire,
        *,
        stream: str,
        subject_prefix: str,
        ack_wait: float = 3.0,
        duplicate_window: float = 3600.0,
        storage: str = "file",
        request_timeout: float = 5.0,
        fetch_timeout: float = 1.0,
        dlq_wait: float = 3.0,
        delete_on_close: bool = False,
        provision: bool = True,
        replay_s: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        wall: Callable[[], float] = time.time,
    ):
        if not _NAME_RE.match(stream or ""):
            raise EventsError("stream name must be 1-64 of [A-Za-z0-9_-]")
        _check_subject(subject_prefix, pattern=False)
        if storage not in ("file", "memory"):
            raise EventsError("storage must be 'file' or 'memory'")
        if ack_wait <= 0 or duplicate_window < 0.1:
            raise EventsError("ack_wait must be positive and duplicate_window >= 0.1s")
        if replay_s is not None and replay_s <= 0:
            raise EventsError("replay_s must be positive (or None: deliver what is new)")
        self.replay_s = replay_s
        self._wall = wall
        self._wire = wire
        self.stream = stream
        self.dlq_stream = f"{stream}_DLQ"
        self.prefix = subject_prefix
        self.ack_wait = float(ack_wait)
        self.request_timeout = request_timeout
        self.fetch_timeout = fetch_timeout
        self.dlq_wait = dlq_wait
        self._delete_on_close = delete_on_close
        self._clock = clock
        self._sleep = sleep
        self._generation: dict[str, int] = {}
        self._closed = False
        self._opened_at = clock()  # a durable's earlier leases were all granted before this
        base = {
            "retention": "limits",
            "storage": storage,
            "discard": "old",
            "num_replicas": 1,
        }
        if not provision:
            self._require_stream(stream)
            self._require_stream(self.dlq_stream)
            return
        self._ensure_stream(
            {
                "name": stream,
                "subjects": [f"{subject_prefix}.>"],
                "duplicate_window": int(duplicate_window * _NS),
                **base,
            }
        )
        self._ensure_stream(
            {
                "name": self.dlq_stream,
                "subjects": [f"{_ADVISORY_MAX}.{stream}.*", f"{_ADVISORY_TERM}.{stream}.*"],
                **base,
            }
        )

    def __repr__(self) -> str:
        return f"JetStreamBus(stream={self.stream!r}, prefix={self.prefix!r})"

    # ---------------------------------------------------------------- JetStream API
    def api(self, what: str, body: Mapping[str, Any] | None = None, *, missing: str = "") -> Any:
        """One ``$JS.API.<what>`` request.  Returns the decoded reply, or None when it is the
        ``missing`` kind's not-found error (``stream``, ``consumer`` or ``message``)."""
        return _api(self._wire, what, body, timeout=self.request_timeout, missing=missing)

    def _ensure_stream(self, config: Mapping[str, Any]) -> None:
        name = config["name"]
        if self.api(f"STREAM.INFO.{name}", missing="stream") is None:
            self.api(f"STREAM.CREATE.{name}", config)

    def _require_stream(self, name: str) -> None:
        info = self.api(f"STREAM.INFO.{name}", missing="stream")
        if info is None:
            raise EventsError(f"stream {name!r} does not exist; provision it (with limits) first")
        if int(info.get("config", {}).get("max_bytes", -1)) <= 0:
            raise EventsError(
                f"stream {name!r} has no max_bytes limit; a flood would fill the disk, so this "
                "client refuses it"
            )

    # ---------------------------------------------------------------- contract
    def publish(self, subject: str, data: bytes, *, msg_id: str | None = None) -> int:
        try:
            _check_subject(subject, pattern=False)
        except EventsError as exc:
            raise PublishRefused(str(exc)) from None
        headers = None
        if msg_id is not None:
            if not msg_id or any(c in msg_id for c in "\r\n"):
                raise PublishRefused("msg_id must be a non-empty single-line string")
            headers = {"Nats-Msg-Id": msg_id}
        msg = self._wire.request(
            f"{self.prefix}.{subject}", bytes(data), headers=headers, timeout=self.request_timeout
        )
        try:
            ack = json.loads(msg.data)
        except ValueError:
            raise EventsError(f"publish to {subject!r}: the PubAck is not JSON") from None
        if not isinstance(ack, dict) or "error" in ack or "seq" not in ack:
            err = ack.get("error", {}) if isinstance(ack, dict) else {}
            raise EventsError(f"publish to {subject!r} was not stored: {err or ack!r}")
        if ack.get("stream") != self.stream:
            raise EventsError(f"publish to {subject!r} landed in stream {ack.get('stream')!r}")
        return int(ack["seq"])

    def consumer(self, name: str, subject: str, *, max_deliver: int = 3) -> JetStreamConsumer:
        _check_subject(subject, pattern=True)
        if not isinstance(max_deliver, int) or max_deliver < 1:
            raise EventsError("max_deliver must be a positive int")
        durable = durable_name(name)
        filt = f"{self.prefix}.{subject}"
        info = self.api(f"CONSUMER.INFO.{self.stream}.{durable}", missing="consumer")
        if info is None:
            config: dict[str, Any] = {
                "durable_name": durable,
                "deliver_policy": "new",
                "ack_policy": "explicit",
                "ack_wait": int(self.ack_wait * _NS),
                "max_deliver": max_deliver,
                "filter_subject": filt,
                "replay_policy": "instant",
            }
            if self.replay_s is not None:
                start = datetime.fromtimestamp(self._wall() - self.replay_s, UTC)
                config["deliver_policy"] = "by_start_time"
                config["opt_start_time"] = start.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            create = f"CONSUMER.CREATE.{self.stream}.{durable}"
            if "*" not in filt and ">" not in filt:
                create += f".{filt}"  # the server refuses any other filter for this request
            info = self.api(
                create, {"stream_name": self.stream, "config": config, "action": "create"}
            )
        else:
            have = info.get("config", {}).get("filter_subject")
            if have != filt:
                raise EventsError(
                    f"consumer {name!r} exists on another subject; delete it to change it"
                )
            if int(info.get("num_ack_pending", 0)) > 0:
                # the previous incarnation's deliveries are leased for the durable's ack_wait;
                # let them lapse.  One this bus has not opened yet was leased before the bus
                # existed, so opening several waits out one lease in all, not one per durable.
                lease = int(info.get("config", {}).get("ack_wait", self.ack_wait * _NS)) / _NS
                since = self._clock() if durable in self._generation else self._opened_at
                left = since + lease + min(1.0, 0.25 + lease / 4) - self._clock()
                if left > 0:
                    self._sleep(left)
        gen = self._generation[durable] = self._generation.get(durable, 0) + 1
        max_dc = int(info.get("config", {}).get("max_deliver", max_deliver))
        c = JetStreamConsumer(self, name, durable, max_dc, gen)
        # the lease the server holds (an existing durable keeps the one it was created with)
        c.ack_wait = int(info.get("config", {}).get("ack_wait", self.ack_wait * _NS)) / _NS
        return c

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._delete_on_close:
                for name in (self.stream, self.dlq_stream):
                    self.api(f"STREAM.DELETE.{name}", missing="stream")
        finally:
            self._wire.close()

    # ---------------------------------------------------------------- internals
    def _strip(self, subject: str) -> str:
        head = self.prefix + "."
        return subject[len(head) :] if subject.startswith(head) else subject

    def _current(self, durable: str, gen: int) -> bool:
        return self._generation.get(durable) == gen


class JetStreamConsumer:
    """One incarnation of a durable pull consumer (a reopen makes a new one)."""

    #: how many settled-for-good deliveries :meth:`dead_letters` waits for at most (the newest)
    EXPECT_DEAD_MAX = 1024

    def __init__(self, bus: JetStreamBus, name: str, durable: str, max_deliver: int, gen: int):
        self.bus, self.name, self.durable = bus, name, durable
        self.max_deliver, self._gen = max_deliver, gen
        self.ack_wait = bus.ack_wait
        self._expect_dead: set[int] = set()

    def __repr__(self) -> str:
        return f"JetStreamConsumer(name={self.name!r}, durable={self.durable!r})"

    def fetch(self, n: int = 1) -> list[Delivery]:
        if n < 1:
            return []
        bus = self.bus
        req = json.dumps({"batch": int(n), "no_wait": True}).encode("utf-8")
        msgs = bus._wire.pull(
            f"$JS.API.CONSUMER.MSG.NEXT.{bus.stream}.{self.durable}",
            req,
            max_msgs=n,
            timeout=bus.fetch_timeout,
        )
        return [self._delivery(m) for m in msgs]

    def _delivery(self, m: WireMsg) -> Delivery:
        stream, consumer, dc, sseq = parse_ack_reply(m.reply)
        if stream != self.bus.stream or consumer != self.durable:
            raise EventsError(f"delivery for {stream}/{consumer} reached {self.durable}")
        d = Delivery(
            sseq, self.bus._strip(m.subject), bytes(m.data), m.headers.get("Nats-Msg-Id"), dc
        )
        state = {"settled": False}

        def settle(how: str, reply: str = m.reply, delivery: Delivery = d) -> None:
            self._settle(reply, delivery, how, state)

        d._settle = settle
        return d

    def _settle(self, reply: str, d: Delivery, how: str, state: dict[str, bool]) -> None:
        body = _SETTLE.get(how)
        if body is None:
            raise EventsError(f"unknown settlement {how!r}")
        if state["settled"] or not self.bus._current(self.durable, self._gen):
            return  # only the first settlement counts; a reopen detaches older deliveries
        state["settled"] = True
        # sent as a request: the server replies once it has processed the settlement
        self.bus._wire.request(reply, body, timeout=self.bus.request_timeout)
        if how == "term" or (how == "nack" and d.attempt >= self.max_deliver):
            self._expect_dead.add(d.seq)
            while len(self._expect_dead) > self.EXPECT_DEAD_MAX:  # a long-lived consumer
                self._expect_dead.discard(min(self._expect_dead))

    def dead_letters(self) -> list[Delivery]:
        bus = self.bus
        deadline = bus._clock() + bus.dlq_wait
        while True:
            dead = self._read_dead()
            if self._expect_dead <= {d.seq for d in dead} or bus._clock() >= deadline:
                self._expect_dead -= {d.seq for d in dead}  # seen: no need to wait for them again
                return dead
            bus._sleep(0.05)

    def _read_dead(self) -> list[Delivery]:
        bus = self.bus
        filt = f"$JS.EVENT.ADVISORY.CONSUMER.*.{bus.stream}.{self.durable}"
        out: list[Delivery] = []
        seq = 1
        while True:
            got = bus.api(
                f"STREAM.MSG.GET.{bus.dlq_stream}",
                {"seq": seq, "next_by_subj": filt},
                missing="message",
            )
            if got is None:
                return out
            stored = got["message"]
            seq = int(stored["seq"]) + 1
            adv = json.loads(base64.b64decode(stored.get("data") or ""))
            sseq = int(adv["stream_seq"])
            orig = bus.api(f"STREAM.MSG.GET.{bus.stream}", {"seq": sseq}, missing="message")
            if orig is None:
                raise EventsError(f"dead letter {sseq}: the original is no longer in the stream")
            m = orig["message"]
            hdrs = parse_headers(base64.b64decode(m.get("hdrs") or ""))
            out.append(
                Delivery(
                    sseq,
                    bus._strip(m["subject"]),
                    base64.b64decode(m.get("data") or ""),
                    hdrs.get("Nats-Msg-Id"),
                    int(adv.get("deliveries", 0)),
                    _noop,
                )
            )


# --------------------------------------------------------------------------- nats-py wire
def _handshake_first_supported() -> bool:
    """Does the installed nats-py take ``tls_handshake_first`` (2.7 and later)?"""
    import inspect

    try:
        from nats.aio.client import Client
    except ImportError:
        return False
    return "tls_handshake_first" in inspect.signature(Client.connect).parameters


class NatsPyWire:
    """:class:`Wire` over nats-py: an asyncio loop on a private thread, one connection."""

    def __init__(
        self,
        url: str,
        *,
        connect_timeout: float = 5.0,
        name: str = "hnx-conform",
        user: str | None = None,
        password: Callable[[], str] | None = None,
        ca_file: str | None = None,
        inbox_prefix: str | None = None,
    ):
        if (user is None) != (password is None):
            raise EventsError("a NATS user needs a password secret, and a password a user")
        if ca_file is not None and not url.startswith("tls://"):
            raise EventsError("ca_file needs a tls:// events endpoint")
        if inbox_prefix is not None:
            _check_subject(inbox_prefix, pattern=False)
        try:
            import nats
            import nats.errors
        except ImportError as exc:
            raise EventsError("nats-py is not installed: pip install 'homelabnext[nats]'") from exc
        if not url.startswith(("nats://", "tls://")):
            raise EventsError("the events endpoint must be a nats:// or tls:// URL")
        self._errors = nats.errors
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name=name, daemon=True)
        self._thread.start()
        self.last_error = ""
        self._denied: set[str] = set()  # subjects the server refused to let this user publish

        async def note(exc: Exception) -> None:  # nats-py reports connection errors here
            self.last_error = f"{type(exc).__name__}: {exc}"
            m = _PERMISSION_DENIED.search(str(exc))
            if m:
                self._denied.add(m.group(1))

        auth: dict[str, Any] = {"user": user, "password": password()} if user and password else {}
        if inbox_prefix is not None:
            auth["inbox_prefix"] = inbox_prefix  # replies on the user's own inbox, not _INBOX.>
        if url.startswith("tls://"):
            import ssl

            if not _handshake_first_supported():
                raise EventsError(
                    "nats-py cannot do the TLS handshake first (tls:// needs it): "
                    "pip install 'nats-py>=2.7'"
                )
            # TLS before anything else: never wait for the server's INFO to ask for it, or a
            # server (or a man in the middle) that does not ask gets the CONNECT in clear
            auth["tls"] = ssl.create_default_context(cafile=ca_file)  # verifies host and chain
            auth["tls_handshake_first"] = True
        try:
            # max_reconnect_attempts=0 would retry a refused first connect forever in nats-py
            self._nc = self._run(
                nats.connect(
                    url,
                    name=name,
                    **auth,
                    connect_timeout=max(1, int(connect_timeout)),
                    allow_reconnect=False,
                    max_reconnect_attempts=1,
                    reconnect_time_wait=0.5,
                    error_cb=note,
                ),
                connect_timeout + 5,
            )
        except WireError as exc:
            self._stop_loop()
            raise WireError(
                f"cannot connect to the events endpoint: {exc} ({self.last_error})"
            ) from None
        except Exception:
            self._stop_loop()
            raise

    def __repr__(self) -> str:
        return "NatsPyWire(<endpoint>)"

    def _run(self, coro: Any, timeout: float) -> Any:
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout)
        except self._errors.NoRespondersError:
            # not permanent: JetStream restarting, or electing a stream leader, answers nothing
            # for a while too; the bus (not the message) is at fault and a retry can succeed
            raise WireError(
                "no responders (JetStream down, or no stream captures that subject?)"
            ) from None
        except self._errors.MaxPayloadError:
            raise WireError(
                "the message exceeds the server's max_payload", permanent=True
            ) from None
        except (self._errors.TimeoutError, TimeoutError):
            fut.cancel()
            raise WireError(f"no reply within {timeout:.1f}s") from None
        except (self._errors.Error, OSError) as exc:
            raise WireError(f"nats transport error: {type(exc).__name__}: {exc}") from None

    def request(
        self,
        subject: str,
        payload: bytes = b"",
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float,
    ) -> WireMsg:
        async def go() -> WireMsg:
            msg = await self._nc.request(
                subject, payload, timeout=timeout, headers=dict(headers) if headers else None
            )
            return WireMsg(msg.subject, msg.data, dict(msg.headers or {}), msg.reply or "")

        self._denied.discard(subject)
        try:
            return self._run(go(), timeout + 1)
        except WireError:
            # the server drops a publish this user may not make and says so out of band
            if subject in self._denied:
                raise WireError("permission denied: publish", permanent=True) from None
            raise

    def pull(self, subject: str, payload: bytes, *, max_msgs: int, timeout: float) -> list[WireMsg]:
        async def go() -> list[WireMsg]:
            loop = asyncio.get_running_loop()
            inbox = self._nc.new_inbox()
            sub = await self._nc.subscribe(inbox)
            out: list[WireMsg] = []
            try:
                await self._nc.publish(subject, payload, reply=inbox)
                deadline = loop.time() + timeout
                while len(out) < max_msgs:
                    left = deadline - loop.time()
                    if left <= 0:
                        break
                    try:
                        msg = await sub.next_msg(timeout=left)
                    except self._errors.TimeoutError:
                        break
                    hdrs = dict(msg.headers or {})
                    if "Status" in hdrs:
                        if hdrs["Status"] == "100":  # idle heartbeat
                            continue
                        break  # 404 No Messages / 408 Request Timeout / 409 ...: end of batch
                    out.append(WireMsg(msg.subject, msg.data, hdrs, msg.reply or ""))
            finally:
                await sub.unsubscribe()
            return out

        return self._run(go(), timeout + 5)

    def close(self) -> None:
        if self._loop.is_closed():
            return
        try:
            if not self._nc.is_closed:
                self._run(self._nc.close(), 10)
        finally:
            self._stop_loop()

    def _stop_loop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._loop.close()


# --------------------------------------------------------------------------- factory
def make(
    *,
    stream: str | None = None,
    subject_prefix: str | None = None,
    scratch: bool = True,
    ack_wait: float = 3.0,
    duplicate_window: float = 3600.0,
    storage: str = "file",
    request_timeout: float = 5.0,
    fetch_timeout: float = 1.0,
    dlq_wait: float = 3.0,
    capability: str = "events",
    provision: bool = True,
    wire: Wire | None = None,
    user: str | None = None,
    password_secret: str | None = None,
    client_name: str = "hnx-conform",
    allow_plaintext: bool = False,
    ca_file: str | None = None,
    inbox_prefix: str | None = None,
    replay_s: float | None = None,
) -> JetStreamBus:
    """A bus on the ``events`` endpoint.  ``scratch`` (the conformance default) gives every
    subject its own stream and subject prefix, deleted on ``close()``, so checks never see each
    other or an earlier run; otherwise ``stream`` and ``subject_prefix`` name a standing stream.
    ``provision=False`` creates no stream: both must exist, each with a ``max_bytes`` limit.
    ``user`` and ``password_secret`` (a secret name, never a value) authenticate the connection;
    the password goes only over ``tls://`` (``ca_file``: a private CA), to a loopback ``nats://``,
    or with an explicit ``allow_plaintext``.
    ``provision=False`` creates no stream: both must exist, each with a ``max_bytes`` limit.
    A ``user``'s replies arrive on ``inbox_prefix``, by default ``_INBOX.<user>``, so the server
    can grant each user its own inbox instead of ``_INBOX.>`` (where one could read another's).
    ``replay_s``: a durable this bus creates starts that many seconds back (default: only what is
    published after it exists)."""
    password = None
    if user is not None or password_secret is not None:
        if not user or not isinstance(password_secret, str) or not password_secret:
            raise EventsError("a NATS user needs password_secret (a secret name), and vice versa")
        if not password_secret.startswith("secret:"):
            raise EventsError("password_secret is a secret name (secret:<name>), never a value")
        from homelabnext.registry.model import secret_env_name

        password = env_secret(secret_env_name(password_secret))  # checked now, read at connect
        if not _NAME_RE.match(user):
            raise EventsError("a NATS user name is 1-64 of [A-Za-z0-9_-] (it names its inbox)")
        inbox_prefix = inbox_prefix or f"_INBOX.{user}"
    if scratch:
        token = secrets.token_hex(6)
        stream = stream or f"HNXCONF_{token}"
        subject_prefix = subject_prefix or f"hnxconf.{token}"
    elif not stream or not subject_prefix:
        raise EventsError("a standing bus needs both stream and subject_prefix")
    assert stream is not None and subject_prefix is not None
    own = wire is None
    if wire is None:
        url = resolve(capability, env_only=True, schemes=("nats", "tls")).url
        try:
            check_plaintext(url, credentials=password is not None, allow_plaintext=allow_plaintext)
        except ValueError as exc:
            raise EventsError(str(exc)) from None
        wire = NatsPyWire(
            url,
            name=client_name,
            user=user,
            password=password,
            ca_file=ca_file,
            inbox_prefix=inbox_prefix,
        )
    try:
        return JetStreamBus(
            wire,
            stream=stream,
            subject_prefix=subject_prefix,
            ack_wait=ack_wait,
            duplicate_window=duplicate_window,
            storage=storage,
            request_timeout=request_timeout,
            fetch_timeout=fetch_timeout,
            dlq_wait=dlq_wait,
            delete_on_close=scratch,
            provision=provision or scratch,
            replay_s=replay_s,
        )
    except Exception:
        if own:
            wire.close()
        raise
