# SPDX-License-Identifier: Apache-2.0
"""The ``events`` contract on NATS JetStream (pinned: nats 2.15 with ``-js``).

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
needs ``tls { handshake_first: true }`` (nats-server 2.10.3 or later).  Every ``$JS.API``
request carries only fields of the server's own request types: since 2.12 the server refuses an
unknown one (its default ``jetstream { strict: true }``), and the offline fake does too.

How the contract maps onto JetStream:

* **Stream.**  One limits-retention stream captures ``<prefix>.>``; a contract subject ``a.b`` is
  the NATS subject ``<prefix>.a.b``.  (A stream may not capture ``>`` itself unless it is no-ack,
  and a no-ack publish returns no sequence, so a prefix is required.)  With ``provision=False``
  the bus creates no stream: both (the stream and its DLQ) must exist already, each with a
  ``max_bytes`` limit, or the bus refuses to open (a long-running consumer that creates unbounded
  streams lets a flood fill the server's disk); and when ``duplicate_window`` is given, the
  stream's own window must be at least that long, or the bus refuses to open too (the window is
  the stream's, set when it was provisioned: a client's setting it asks for is otherwise a no-op).
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
  its subject.  With ``provision=False`` the bus creates no durable either: it binds to one that
  exists (a pull durable on that filter, with explicit acks) and refuses a missing one
  (:class:`NotProvisioned`) or a push one.  A consumer create takes any configuration, a push
  ``deliver_subject`` included, and the server delivers a push consumer's messages as itself,
  whatever the creator may publish to, so creating a durable is the provisioner's step
  (:func:`provision_consumers`, role ``events_bus``), never a client's.
* **fetch** is one ``CONSUMER.MSG.NEXT`` pull with ``no_wait``: the server answers with what is
  deliverable now and a ``404``/``408`` status, so an empty consumer returns at once.  The attempt
  number is the delivery count from the ack reply subject, in either of its formats (ADR-15):
  v1 ``$JS.ACK.<stream>.<consumer>...`` or v2, with ``<domain>.<account hash>`` after ``ACK``,
  which nats-server 2.14+ hands out with its ``js_ack_fc_v2`` feature flag (2.15.1 still sends
  v1; enabled in 2.16, flag removed in 2.17, on upstream main).  A user's ack grants cover both
  forms, token for token (docs/stackstorm.md).
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
    "NotProvisioned",
    "PublishRefused",
    "Wire",
    "WireError",
    "WireMsg",
    "check_stream_config",
    "make",
    "provision_consumers",
    "provision_streams",
]

_ADVISORY_MAX = "$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES"
_ADVISORY_TERM = "$JS.EVENT.ADVISORY.CONSUMER.MSG_TERMINATED"
#: the server's JetStream API subjects, as the account that holds the streams sees them
API_PREFIX = "$JS.API"
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SETTLE = {"ack": b"+ACK", "nack": b"-NAK", "term": b"+TERM"}
_NS = 1_000_000_000
#: nats-server's duplicate window for a stream created without one (two minutes)
_DEFAULT_DUPLICATE_WINDOW_NS = 120 * _NS
_NOT_FOUND = {"stream": 10059, "consumer": 10014, "message": 10037}
_PERMISSION_DENIED = re.compile(r'Permissions Violation for Publish to "([^"]+)"', re.I)
#: what a refused ``$JS.API.*`` call most often means: a client of the events bus role (which lives
#: in an account of its own and reaches JetStream under ``JS.<account>.API``) left at the default
API_PREFIX_HINT = (
    "on an events_bus-managed bus pass api_prefix JS.<account>.API "
    "(--events-api-prefix; the relay's broker_relay_api_prefix): a client account reaches "
    "JetStream under that prefix, never $JS.API (docs/broker.md, 'The bus ACL')"
)


def permission_denied(subject: str) -> str:
    """The message of a publish the server refused this user: ``subject`` named, and for a
    ``$JS.API.*`` call (a client at the default ``api_prefix``) :data:`API_PREFIX_HINT`."""
    msg = f"permission denied: publish {subject}"
    if subject.startswith(API_PREFIX + "."):
        msg += f"; {API_PREFIX_HINT}"
    return msg


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


class NotProvisioned(EventsError):
    """A client opened with ``provision=False`` found no durable to bind to (or one it must not
    use): the provisioner creates it.  A configuration error, never retried."""

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
    """``(stream, consumer, delivery_count, stream_seq)`` from a ``$JS.ACK`` reply subject (ADR-15:
    the 9-token v1 form, and the v2 form with domain and account hash, 11 tokens or more)."""
    t = reply.split(".")
    if (len(t) != 9 and len(t) < 11) or t[:2] != ["$JS", "ACK"]:
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


def check_api_prefix(prefix: str) -> str:
    """``$JS.API`` (the server's own, in the account that holds the streams) or the prefix a
    client account imports the bus account's JetStream calls under (``JS.HNX.API``: the events
    bus role's account split, docs/broker.md "The bus ACL"): literal tokens, no wildcard."""
    if prefix != API_PREFIX:
        toks = _check_subject(prefix, pattern=False) if isinstance(prefix, str) and prefix else []
        if not toks or any(not re.fullmatch(r"[A-Za-z0-9_-]+", t) for t in toks):
            raise EventsError(f"api_prefix {prefix!r}: $JS.API or literal tokens of [A-Za-z0-9_-]")
    return prefix


def _api(
    wire: Wire,
    what: str,
    body: Mapping[str, Any] | None,
    *,
    timeout: float,
    missing: str = "",
    prefix: str = "$JS.API",
) -> Any:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    msg = wire.request(f"{prefix}.{what}", payload, timeout=timeout)
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


#: a standing stream's messages leave only by its limits (provision_streams)
_EVIDENCE = {"deny_delete": True, "deny_purge": True}
#: the keys a standing stream's configuration may carry (provision_streams renders no other):
#: never a republish, mirror, sources or subject transform, any of which can send the stream's
#: messages to ``$JS.API.*``, where the server takes them as JetStream requests
_STREAM_KEYS = frozenset(
    {"name", "subjects", "duplicate_window", "max_bytes", "retention", "storage", "discard",
     "num_replicas", "max_age", "max_msgs_per_subject", "discard_new_per_subject",
     "deny_delete", "deny_purge"}
)  # fmt: skip


def check_stream_config(config: Mapping[str, Any]) -> None:
    """Refuse a stream configuration :func:`provision_streams` would not render: a key outside
    its own (a ``republish``, ``mirror``, ``sources`` or ``subject_transform`` above all: aimed
    at ``$JS.API.STREAM.DELETE.<other>``, a republish deletes that stream; homelab-next #361
    security F1), a subject that is neither a literal prefix's ``>`` (``lab.>``: every token
    before the ``>`` literal, the first not the server's ``$`` or ``_``) nor one of the
    dead-letter advisories of a named stream (``<advisory>.<stream>.*``), or a missing deny
    flag.  The provisioner checks its own request before it sends it; the server does not check
    the body against any grant."""
    name = config.get("name")
    extra = sorted(set(config) - _STREAM_KEYS)
    if extra:
        raise EventsError(f"stream {name!r}: refused keys {extra} (a standing stream "
                          "is created with its limits and deny flags only)")  # fmt: skip
    subjects = config.get("subjects")
    if not isinstance(subjects, list) or not subjects:
        raise EventsError(f"stream {name!r}: a list of subjects is required")
    for subject in subjects:
        if not _stream_subject_ok(subject):
            raise EventsError(
                f"stream {name!r}: subject {subject!r} is neither a literal prefix's '>' "
                "nor a named stream's dead-letter advisory"
            )
    if not all(config.get(k) is True for k in _EVIDENCE):
        raise EventsError(f"stream {config.get('name')!r}: deny_delete and deny_purge are required")


def _stream_subject_ok(subject: Any) -> bool:
    """``<literal>[.<literal>...].>`` (not under ``$`` or ``_``), or ``<advisory>.<stream>.*``
    for one of the two dead-letter advisories and a literal stream name."""
    if not isinstance(subject, str):
        return False
    try:
        toks = _check_subject(subject, pattern=True)
    except EventsError:
        return False
    for advisory in (_ADVISORY_MAX, _ADVISORY_TERM):
        if subject.startswith(advisory + "."):
            rest = subject[len(advisory) + 1 :].split(".")
            return len(rest) == 2 and bool(_NAME_RE.match(rest[0])) and rest[1] == "*"
    # _check_subject allows ">" last only: the tokens before it are literal unless one is "*"
    return len(toks) >= 2 and toks[-1] == ">" and "*" not in toks and toks[0][0] not in "$_"


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
    discard: str = "old",
    max_msgs_per_subject: int | None = None,
) -> list[str]:
    """The operator's one-time step for a standing bus: create the stream (``<prefix>.>``) and
    its DLQ (the dead-letter advisories), each bounded (``max_bytes``, ``max_age``), when missing.
    Returns the names it created.  Clients opened with ``provision=False`` (the broker's relay,
    the StackStorm bridge) then need no ``STREAM.CREATE`` at all.  The same as ``nats stream add``
    with these settings.

    Both are created with ``deny_delete`` and ``deny_purge``: the server refuses ``MSG.DELETE``
    and ``PURGE`` on them to every user, whatever its grants, so the evidence a stream holds
    leaves only by its limits (``max_bytes``, ``max_age``).  nats-server refuses to relax either
    on an existing stream (``STREAM.UPDATE``: "can not cancel deny message deletes" / "deny
    purge"), so they are final; a stream that already exists is left as it is (an operator adds
    them in place with one ``STREAM.UPDATE``, which keeps the messages).

    ``discard`` is what the stream does when a limit is reached: ``old`` (the default) evicts the
    oldest messages, so whoever can publish enough evicts the evidence; ``new`` refuses the
    publish instead (the relay keeps the event in its outbox and retries, and the stream fills
    up until ``max_age`` frees room or an operator raises the limit), so nothing stored is ever
    pushed out.  ``max_msgs_per_subject`` (with ``discard: new`` only: it sets
    ``discard_new_per_subject``) bounds each subject on its own, so a flood on one subject is
    refused without starving the others.  The DLQ always discards old (a refused advisory is
    lost silently).  Both apply to a stream this creates; an existing one is never changed."""
    if not _NAME_RE.match(stream or "") or max_bytes <= 0:
        raise EventsError("a stream name and a positive max_bytes are required")
    if discard not in ("old", "new"):
        raise EventsError("discard must be 'old' or 'new'")
    if max_msgs_per_subject is not None and (
        isinstance(max_msgs_per_subject, bool)
        or not isinstance(max_msgs_per_subject, int)
        or max_msgs_per_subject < 1
        or discard != "new"
    ):
        raise EventsError("max_msgs_per_subject is a positive int, with discard 'new' only")
    _check_subject(subject_prefix, pattern=False)
    base = {
        "retention": "limits",
        "storage": storage,
        "discard": "old",
        "num_replicas": 1,
        "max_age": int(max_age * _NS),
    }
    dlq = f"{stream}_DLQ"
    limits: dict[str, Any] = {"discard": discard}
    if max_msgs_per_subject is not None:
        limits.update(max_msgs_per_subject=max_msgs_per_subject, discard_new_per_subject=True)
    configs = [
        {
            "name": stream,
            "subjects": [f"{subject_prefix}.>"],
            "duplicate_window": int(duplicate_window * _NS),
            "max_bytes": int(max_bytes),
            **base,
            **limits,
            **_EVIDENCE,
        },
        {
            "name": dlq,
            "subjects": [f"{_ADVISORY_MAX}.{stream}.*", f"{_ADVISORY_TERM}.{stream}.*"],
            "max_bytes": int(dlq_max_bytes or max(1, max_bytes // 4)),
            **base,
            **_EVIDENCE,
        },
    ]
    for config in configs:  # every body checked before the first request: none half-provisioned
        check_stream_config(config)
    created = []
    for config in configs:
        name = config["name"]
        if _api(wire, f"STREAM.INFO.{name}", None, timeout=timeout, missing="stream") is None:
            _api(wire, f"STREAM.CREATE.{name}", config, timeout=timeout)
            created.append(name)
    return created


def _consumer_config(
    durable: str,
    filt: str,
    *,
    ack_wait: float,
    max_deliver: int,
    deliver_policy: str = "new",
    start: float | None = None,
    start_seq: int | None = None,
) -> dict[str, Any]:
    """A pull durable's configuration: explicit acks, one filter, never a ``deliver_subject``."""
    config: dict[str, Any] = {
        "durable_name": durable,
        "deliver_policy": deliver_policy,
        "ack_policy": "explicit",
        "ack_wait": int(ack_wait * _NS),
        "max_deliver": max_deliver,
        "filter_subject": filt,
        "replay_policy": "instant",
    }
    if start_seq is not None:
        config["deliver_policy"] = "by_start_sequence"
        config["opt_start_seq"] = int(start_seq)
    elif start is not None:
        config["deliver_policy"] = "by_start_time"
        config["opt_start_time"] = datetime.fromtimestamp(start, UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    return config


def _create_subject(stream: str, durable: str, filt: str) -> str:
    create = f"CONSUMER.CREATE.{stream}.{durable}"
    if "*" not in filt and ">" not in filt:
        create += f".{filt}"  # the server refuses any other filter for this request
    return create


def _bindable(info: Mapping[str, Any], stream: str, durable: str, filt: str) -> None:
    """Refuse an existing durable a client must not use: a push one, another filter, or acks
    other than explicit."""
    cfg = info.get("config", {}) or {}
    where = f"durable {durable!r} on stream {stream!r}"
    if cfg.get("deliver_subject"):
        raise NotProvisioned(
            f"{where} is a push consumer (deliver_subject set): only pull durables are used; "
            "delete it as the provisioner and let it recreate it"
        )
    if cfg.get("filter_subject") != filt:
        raise NotProvisioned(f"{where} exists on another subject; delete it to change it")
    if cfg.get("ack_policy", "explicit") != "explicit":
        raise NotProvisioned(f"{where} does not take explicit acks")


def provision_consumers(
    wire: Wire,
    *,
    stream: str,
    durables: list[Mapping[str, Any]],
    timeout: float = 5.0,
    wall: Callable[[], float] = time.time,
) -> list[str]:
    """The provisioner's step for the durables clients bind to (``provision=False``): create each
    one missing on ``stream`` as a PULL durable -- no ``deliver_subject``, explicit acks -- and
    check an existing one is such a durable on its filter.  ``durables``: ``{durable, filter}``
    (``filter`` the full NATS subject, prefix included) with optional ``ack_wait`` (seconds,
    default 30), ``max_deliver`` (default 5), and where it starts: ``deliver_policy`` (``new``,
    the default, or ``all``), ``replay_s`` (that many seconds back) or ``start_seq`` (that stream
    sequence).  An existing durable is never changed.  Returns the names it created.

    Only the provisioner may create a consumer: a create takes any configuration, a push
    ``deliver_subject`` included, and the server delivers a push consumer as itself, so a user
    holding the create could have the stream delivered to any subject."""
    if not _NAME_RE.match(stream or ""):
        raise EventsError("stream name must be 1-64 of [A-Za-z0-9_-]")
    created = []
    for d in durables:
        name, filt = str(d.get("durable", "")), str(d.get("filter", ""))
        if not _NAME_RE.match(name):
            raise EventsError(f"durable name {name!r}: 1-64 of [A-Za-z0-9_-]")
        _check_subject(filt, pattern=True)
        if set(d) - {"durable", "filter", "ack_wait", "max_deliver", "deliver_policy",
                     "replay_s", "start_seq", "stream", "user", "ack_policy"}:  # fmt: skip
            raise EventsError(f"durable {name}: unknown settings (a pull durable takes no others)")
        if d.get("ack_policy", "explicit") != "explicit":
            raise EventsError(f"durable {name}: ack_policy must be explicit")
        if d.get("deliver_policy", "new") not in ("new", "all"):
            raise EventsError(f"durable {name}: deliver_policy must be new or all")
        info = _api(
            wire, f"CONSUMER.INFO.{stream}.{name}", None, timeout=timeout, missing="consumer"
        )
        if info is not None:
            _bindable(info, stream, name, filt)
            continue
        replay = d.get("replay_s")
        config = _consumer_config(
            name,
            filt,
            ack_wait=float(d.get("ack_wait", 30.0)),
            max_deliver=int(d.get("max_deliver", 5)),
            deliver_policy=str(d.get("deliver_policy", "new")),
            start=None if replay is None else wall() - float(replay),
            start_seq=None if d.get("start_seq") is None else int(d["start_seq"]),
        )
        _api(
            wire,
            _create_subject(stream, name, filt),
            {"stream_name": stream, "config": config, "action": "create"},
            timeout=timeout,
        )
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
        duplicate_window: float | None = None,
        storage: str = "file",
        request_timeout: float = 5.0,
        fetch_timeout: float = 1.0,
        dlq_wait: float = 3.0,
        delete_on_close: bool = False,
        provision: bool = True,
        replay_s: float | None = None,
        api_prefix: str = API_PREFIX,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        wall: Callable[[], float] = time.time,
    ):
        if not _NAME_RE.match(stream or ""):
            raise EventsError("stream name must be 1-64 of [A-Za-z0-9_-]")
        _check_subject(subject_prefix, pattern=False)
        if storage not in ("file", "memory"):
            raise EventsError("storage must be 'file' or 'memory'")
        if ack_wait <= 0 or (duplicate_window is not None and duplicate_window < 0.1):
            raise EventsError("ack_wait must be positive and duplicate_window >= 0.1s")
        if replay_s is not None and replay_s <= 0:
            raise EventsError("replay_s must be positive (or None: deliver what is new)")
        self.replay_s = replay_s
        self.api_prefix = check_api_prefix(api_prefix)
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
        self._provision = provision  # False: bind to the stream and durables, create nothing
        base = {
            "retention": "limits",
            "storage": storage,
            "discard": "old",
            "num_replicas": 1,
        }
        if not provision:
            self._require_stream(stream, duplicate_window=duplicate_window)
            self._require_stream(self.dlq_stream)
            return
        self._ensure_stream(
            {
                "name": stream,
                "subjects": [f"{subject_prefix}.>"],
                "duplicate_window": int((duplicate_window or 3600.0) * _NS),
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
        """One ``$JS.API.<what>`` request (under :attr:`api_prefix`).  Returns the decoded reply,
        or None when it is the ``missing`` kind's not-found error (``stream``, ``consumer`` or
        ``message``)."""
        return _api(
            self._wire,
            what,
            body,
            timeout=self.request_timeout,
            missing=missing,
            prefix=self.api_prefix,
        )

    def _ensure_stream(self, config: Mapping[str, Any]) -> None:
        name = config["name"]
        if self.api(f"STREAM.INFO.{name}", missing="stream") is None:
            self.api(f"STREAM.CREATE.{name}", config)

    def _require_stream(self, name: str, *, duplicate_window: float | None = None) -> None:
        info = self.api(f"STREAM.INFO.{name}", missing="stream")
        if info is None:
            raise EventsError(f"stream {name!r} does not exist; provision it (with limits) first")
        config = info.get("config", {})
        if int(config.get("max_bytes", -1)) <= 0:
            raise EventsError(
                f"stream {name!r} has no max_bytes limit; a flood would fill the disk, so this "
                "client refuses it"
            )
        if duplicate_window is not None:
            have = int(config.get("duplicate_window", _DEFAULT_DUPLICATE_WINDOW_NS)) / _NS
            if have < duplicate_window:
                raise EventsError(
                    f"stream {name!r} dedupes message ids for {have:g}s, shorter than the "
                    f"duplicate_window {duplicate_window:g}s this client is configured for; raise "
                    f"the stream's (nats stream edit {name} --dupe-window <duration>) or lower "
                    "this one"
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
        if info is None and not self._provision:
            raise NotProvisioned(
                f"durable {durable!r} does not exist on stream {self.stream!r}: this client "
                f"creates no consumer; the provisioner creates it (role events_bus, "
                f"events_bus_durables: a pull durable on {filt})"
            )
        if info is None:
            config = _consumer_config(
                durable,
                filt,
                ack_wait=self.ack_wait,
                max_deliver=max_deliver,
                start=None if self.replay_s is None else self._wall() - self.replay_s,
            )
            info = self.api(
                _create_subject(self.stream, durable, filt),
                {"stream_name": self.stream, "config": config, "action": "create"},
            )
        else:
            have = info.get("config", {}).get("filter_subject")
            if have != filt:
                raise EventsError(
                    f"consumer {name!r} exists on another subject; delete it to change it"
                )
            if not self._provision:
                _bindable(info, self.stream, durable, filt)
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
    #: dead letters :meth:`dead_letters` remembers (the newest); older ones are no longer listed
    DEAD_KEEP = 4096

    def __init__(self, bus: JetStreamBus, name: str, durable: str, max_deliver: int, gen: int):
        self.bus, self.name, self.durable = bus, name, durable
        self.max_deliver, self._gen = max_deliver, gen
        self.ack_wait = bus.ack_wait
        self._expect_dead: set[int] = set()
        self._dead: list[Delivery] = []  # dead letters read so far, oldest first
        self._dead_next = 1  # the next dead-letter stream sequence to read
        #: stream sequences of dead letters whose original had aged out of the stream when read
        self.dead_evicted: list[int] = []

    def __repr__(self) -> str:
        return f"JetStreamConsumer(name={self.name!r}, durable={self.durable!r})"

    def fetch(self, n: int = 1) -> list[Delivery]:
        if n < 1:
            return []
        bus = self.bus
        req = json.dumps({"batch": int(n), "no_wait": True}).encode("utf-8")
        msgs = bus._wire.pull(
            f"{bus.api_prefix}.CONSUMER.MSG.NEXT.{bus.stream}.{self.durable}",
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
        """The dead letters so far: those read before, plus the advisories since the last read.

        The dead-letter stream is read from where the last call stopped, never again from the
        start.  An advisory can outlive its original (the main stream evicts first, under its age
        or byte limit): that dead letter cannot be listed, so it is skipped and its stream
        sequence noted in :attr:`dead_evicted`, and the rest are still returned.
        """
        bus = self.bus
        filt = f"$JS.EVENT.ADVISORY.CONSUMER.*.{bus.stream}.{self.durable}"
        while True:
            got = bus.api(
                f"STREAM.MSG.GET.{bus.dlq_stream}",
                {"seq": self._dead_next, "next_by_subj": filt},
                missing="message",
            )
            if got is None:
                return list(self._dead)
            stored = got["message"]
            adv = json.loads(base64.b64decode(stored.get("data") or ""))
            sseq = int(adv["stream_seq"])
            orig = bus.api(f"STREAM.MSG.GET.{bus.stream}", {"seq": sseq}, missing="message")
            self._dead_next = int(stored["seq"]) + 1
            if orig is None:
                self.dead_evicted.append(sseq)
                self._expect_dead.discard(sseq)  # it will never be listed: do not wait for it
                del self.dead_evicted[: -self.DEAD_KEEP]
                continue
            m = orig["message"]
            hdrs = parse_headers(base64.b64decode(m.get("hdrs") or ""))
            self._dead.append(
                Delivery(
                    sseq,
                    bus._strip(m["subject"]),
                    base64.b64decode(m.get("data") or ""),
                    hdrs.get("Nats-Msg-Id"),
                    int(adv.get("deliveries", 0)),
                    _noop,
                )
            )
            del self._dead[: -self.DEAD_KEEP]


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
            if m:  # nats-py lowercases the server's -ERR text, the subject included
                self._denied.add(m.group(1).lower())

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

        self._denied.discard(subject.lower())
        try:
            return self._run(go(), timeout + 1)
        except WireError:
            # the server drops a publish this user may not make and says so out of band (nats-py
            # hands the text over lowercased, so $JS.API... subjects compare in lower case)
            if subject.lower() in self._denied:
                raise WireError(permission_denied(subject), permanent=True) from None
            raise

    def publish(self, subject: str, payload: bytes = b"", *, reply: str = "") -> bool:
        """A plain publish with a reply subject of the caller's choosing, flushed: what any
        client can send with any one grant (a reply subject is not checked against anyone's
        allow-list).  Not part of :class:`Wire`: broker_e2e's reply-subject checks use it.
        False when the server refused this user the subject itself."""

        async def go() -> None:
            await self._nc.publish(subject, payload, reply=reply)
            await self._nc.flush(timeout=5)  # a refusal (-ERR) arrives before the PONG

        self._denied.discard(subject.lower())
        self._run(go(), 10)
        return subject.lower() not in self._denied

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
    duplicate_window: float | None = None,
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
    api_prefix: str = API_PREFIX,
) -> JetStreamBus:
    """A bus on the ``events`` endpoint.  ``scratch`` (the conformance default) gives every
    subject its own stream and subject prefix, deleted on ``close()``, so checks never see each
    other or an earlier run; otherwise ``stream`` and ``subject_prefix`` name a standing stream.
    ``user`` and ``password_secret`` (a secret name, never a value) authenticate the connection;
    the password goes only over ``tls://`` (``ca_file``: a private CA), to a loopback ``nats://``,
    or with an explicit ``allow_plaintext``.
    ``provision=False`` creates no stream and no durable: both streams must exist, each with a
    ``max_bytes`` limit, a stream whose ``duplicate_window`` is shorter than a given
    ``duplicate_window`` is refused (a stream this bus provisions gets ``duplicate_window``, by
    default one hour), and :meth:`JetStreamBus.consumer` binds to a pull durable the provisioner
    created (:func:`provision_consumers`), refusing a missing one (:class:`NotProvisioned`).
    A ``user``'s replies arrive on ``inbox_prefix``, by default ``_INBOX.<user>``, so the server
    can grant each user its own inbox instead of ``_INBOX.>`` (where one could read another's).
    ``replay_s``: a durable this bus creates (``provision=True`` only) starts that many seconds
    back (default: only what is published after it exists).
    ``api_prefix``: where this connection's account reaches the JetStream API.  ``$JS.API`` in
    the account that holds the streams; a client of the events bus role lives in an account of
    its own that imports its few calls from the bus account under ``JS.<account>.API`` (no
    reply it sets can then reach the bus account's API: docs/broker.md, "The bus ACL")."""
    check_api_prefix(api_prefix)
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
            api_prefix=api_prefix,
        )
    except Exception:
        if own:
            wire.close()
        raise
