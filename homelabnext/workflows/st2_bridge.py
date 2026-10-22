# SPDX-License-Identifier: Apache-2.0
"""``hnx workflows st2 bridge``: the event bridge from the bus to StackStorm's webhook.

The rendered ``bridge.json`` (:func:`homelabnext.workflows.st2.render`) names, per bound event
type, the bus subject, a durable consumer name, the rules it feeds and the producers (``source``)
those rules pin.  The bridge is one long-running process that, for each entry, is a durable
consumer on the subject (``homelabnext.<type>``; with NATS JetStream under the stream's subject
prefix, :mod:`homelabnext.conform.adapters.nats_jetstream`) and POSTs each event to the webhook.

* **Validated before forwarding.**  Every body is parsed and checked against the envelope and its
  type's schema (:func:`homelabnext.events.consumer.decode_event`), its type must be the subject's
  and its ``source`` one the subject's rules pin.  Anything else is *poison*: it is terminated
  (``term``: JetStream's dead-letter stream is the quarantine, never redelivered, never
  forwarded), counted by reason and logged with the event id, never its content.  A body over
  :data:`MAX_EVENT_BYTES` is poison before it is parsed, one nested past the parser's stack is
  ``not-json``, and any other exception while checking a delivery quarantines that delivery
  (``unprocessable``): one hostile body never takes the bridge down (or, redelivered, keeps it
  down).
* **At least once, and a duplicate is harmless.**  A delivery is acked only after the webhook
  answered 2xx.  A refused connection, a timeout, a redirect, 401/403/404, 408, 429 and 5xx are
  *nacked* (redelivered) and the bridge backs off exponentially before fetching again, so an
  outage of StackStorm costs retries, not events.  After ``max_deliver`` attempts the bus
  dead-letters it.  400, 413, 415 and 422 are StackStorm refusing the body: poison.  Each POST
  carries ``Idempotency-Key: <event id>``; StackStorm's webhook ignores it and starts a run per
  POST, so the runtime's ``admit`` drops an event id it has already taken
  (:data:`homelabnext.workflows.st2_runtime.DEDUPE_WINDOW_S`).
* **The credential is a secret name.**  ``bridge.json`` names it (the secret-store name
  ``stackstorm/webhook-key``); it is read from ``HNX_SECRET_STACKSTORM_WEBHOOK_KEY`` at every POST (never held, never logged) and sent as
  ``St2-Api-Key``.  Give it to a StackStorm user whose RBAC role has ``webhook_send`` only.
* **TLS on.**  https with certificate verification (``--ca-file`` for a private CA); plain http
  only to loopback or with an explicit ``allow_plaintext``.  No redirect is followed: a 3xx is a
  failed POST (nacked), so the key never reaches another URL.
* **Bounded.**  At most ``max_in_flight`` POSTs at once (one fetch is at most that many
  deliveries); SIGTERM stops fetching, lets the POSTs in flight finish and settles them.

``stats()`` (and ``--stats-file``, written atomically) reports per subject what was forwarded,
retried, quarantined (by reason) and dead-lettered, for a ``poll-file`` status source.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from homelabnext._http import ResponseTooLarge, check_plaintext, read_bounded
from homelabnext.events.consumer import decode_event
from homelabnext.events.envelope import EventError, canonical_body
from homelabnext.registry.model import secret_env_name
from homelabnext.state.store import atomic_write_text

__all__ = [
    "Bridge",
    "BridgeConfig",
    "BridgeError",
    "Subscription",
    "Webhook",
    "load_bridge",
]

log = logging.getLogger("homelabnext.st2_bridge")

#: StackStorm refused the body itself: retrying the same bytes cannot succeed
PERMANENT_STATUS = frozenset({400, 413, 415, 422})
MAX_REPLY_BYTES = 64 << 10
#: an event body larger than this is poison before it is parsed (the envelope is small; a body this
#: size is a flood or a parser bomb, never an event a rule takes)
MAX_EVENT_BYTES = 256 << 10
#: the bus's lease on a delivery (JetStream ``ack_wait``) the bridge asks for when it creates a
#: durable; it must outlast a POST (the webhook's timeout) plus :data:`LEASE_MARGIN_S` to settle,
#: or the bus hands the delivery out again while it is still being posted
ACK_WAIT_S = 30.0
LEASE_MARGIN_S = 15.0
_WEBHOOK_PATH = re.compile(r"/api/v1/webhooks/[a-z][a-z0-9_-]*")
_SECRET_REF = re.compile(r"secret:[a-z][a-z0-9_-]*(/[a-z][a-z0-9_-]*)*")
_SUBJECT = re.compile(r"homelabnext(\.[a-z][a-z0-9-]*)+")
_DURABLE = re.compile(r"[A-Za-z0-9_-]{1,64}")


class BridgeError(ValueError):
    """``bridge.json`` is malformed, or the bridge is configured wrongly."""


@dataclass(frozen=True)
class Subscription:
    subject: str
    durable: str
    rules: tuple[str, ...]
    sources: frozenset[str]


@dataclass(frozen=True)
class BridgeConfig:
    webhook: str
    api_key: str
    subscriptions: tuple[Subscription, ...]


def load_bridge(path_or_doc: str | os.PathLike[str] | Mapping[str, Any]) -> BridgeConfig:
    """The rendered ``bridge.json``, checked: a webhook path, a secret name, one entry per
    subject, each with a durable name and the producers its rules pin."""
    if isinstance(path_or_doc, Mapping):
        doc: Any = path_or_doc
    else:
        try:
            doc = json.loads(Path(path_or_doc).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BridgeError(f"bridge file: {exc.__class__.__name__}: {exc}") from None
    if not isinstance(doc, Mapping):
        raise BridgeError("bridge file: not an object")
    webhook, key = doc.get("webhook"), doc.get("api_key")
    if not isinstance(webhook, str) or not _WEBHOOK_PATH.fullmatch(webhook):
        raise BridgeError("webhook: not /api/v1/webhooks/<name>")
    if not isinstance(key, str) or not _SECRET_REF.fullmatch(key):
        raise BridgeError("api_key: a secret name (secret:<name>), never a value")
    if doc.get("content_type") != "application/json":
        raise BridgeError("content_type: StackStorm's webhook takes application/json")
    subs = doc.get("subscriptions")
    if not isinstance(subs, list) or not subs:
        raise BridgeError("subscriptions: none")
    out: list[Subscription] = []
    for i, s in enumerate(subs):
        where = f"subscriptions[{i}]"
        if not isinstance(s, Mapping):
            raise BridgeError(f"{where}: not an object")
        subject, durable = s.get("subject"), s.get("durable")
        rules, sources = s.get("rules"), s.get("sources")
        if not isinstance(subject, str) or not _SUBJECT.fullmatch(subject):
            raise BridgeError(f"{where}: subject is not one homelabnext event type")
        if not isinstance(durable, str) or not _DURABLE.fullmatch(durable):
            raise BridgeError(f"{where}: durable is not a consumer name")
        if not isinstance(rules, list) or not rules or not all(isinstance(r, str) for r in rules):
            raise BridgeError(f"{where}: rules: none")
        if (
            not isinstance(sources, list)
            or not sources
            or not all(isinstance(x, str) and x for x in sources)
        ):
            raise BridgeError(f"{where}: sources: the producers the rules pin, none given")
        out.append(Subscription(subject, durable, tuple(rules), frozenset(sources)))
    if len({s.subject for s in out}) != len(out) or len({s.durable for s in out}) != len(out):
        raise BridgeError("subscriptions: a subject or a durable name is listed twice")
    return BridgeConfig(webhook, key, tuple(out))


# ---------------------------------------------------------------- the webhook
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the 3xx surfaces as an HTTPError (a failed POST)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class WebhookUnavailable(RuntimeError):
    """The POST did not get an HTTP answer (refused, timed out, TLS failed) or had no key."""


class Poster(Protocol):
    def post(self, event: Mapping[str, Any]) -> int: ...


class Webhook:
    """POSTs one event to ``<base_url><path>``; returns the HTTP status (any status, 3xx
    included, since no redirect is followed) or raises :class:`WebhookUnavailable`."""

    def __init__(
        self,
        base_url: str,
        path: str,
        api_key: str,
        *,
        env: Mapping[str, str] | None = None,
        ca_file: str | os.PathLike[str] | None = None,
        timeout: float = 10.0,
        allow_plaintext: bool = False,
    ) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise BridgeError("the StackStorm URL must be an absolute https URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise BridgeError("the StackStorm URL carries no credentials, query or fragment")
        if parts.path not in ("", "/"):
            raise BridgeError("the StackStorm URL is the server's base URL, without a path")
        if not _WEBHOOK_PATH.fullmatch(path):
            raise BridgeError("webhook: not /api/v1/webhooks/<name>")
        if not _SECRET_REF.fullmatch(api_key):
            raise BridgeError("the API key is a secret name (secret:<name>), never a value")
        try:
            check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        except ValueError as exc:
            raise BridgeError(str(exc)) from None
        self.url = f"{parts.scheme}://{parts.netloc}{path}"
        self.key_ref = api_key
        self._env = env
        self.timeout = timeout
        ctx = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        self._opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
        )

    def __repr__(self) -> str:
        return f"Webhook({self.url!r}, key={self.key_ref!r})"

    def _key(self) -> str:
        var = secret_env_name(self.key_ref)
        value = (os.environ if self._env is None else self._env).get(var, "")
        if not value:
            raise WebhookUnavailable(f"the webhook API key is not set: {var} ({self.key_ref})")
        return value

    def post(self, event: Mapping[str, Any]) -> int:
        req = urllib.request.Request(self.url, data=canonical_body(event), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("Idempotency-Key", str(event["id"]))
        req.add_header("St2-Api-Key", self._key())
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                with contextlib.suppress(ResponseTooLarge):  # answered; the echo is not read
                    read_bounded(resp, MAX_REPLY_BYTES)
                return int(resp.status)
        except urllib.error.HTTPError as exc:
            exc.close()
            return int(exc.code)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise WebhookUnavailable(f"{type(reason).__name__}") from None


# ---------------------------------------------------------------- the bridge
@dataclass
class SubjectStats:
    forwarded: int = 0
    retried: int = 0
    dead_lettered: int = 0
    quarantined: Counter = field(default_factory=Counter)

    def to_dict(self) -> dict[str, Any]:
        return {
            "forwarded": self.forwarded,
            "retried": self.retried,
            "dead_lettered": self.dead_lettered,
            "quarantined": dict(sorted(self.quarantined.items())),
        }


class Bridge:
    """The bridge over one bus (:class:`conformance.protocols.events.EventBus`)."""

    def __init__(
        self,
        bus: Any,
        config: BridgeConfig,
        webhook: Poster,
        *,
        max_in_flight: int = 8,
        max_deliver: int = 100,
        backoff_base_s: float = 1.0,
        backoff_max_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        stats_file: str | os.PathLike[str] | None = None,
        stats_interval_s: float = 30.0,
        now: Callable[[], str] | None = None,
    ) -> None:
        if max_in_flight < 1 or max_deliver < 1:
            raise BridgeError("max_in_flight and max_deliver are positive")
        self.bus, self.config, self.webhook = bus, config, webhook
        self.max_in_flight, self.max_deliver = int(max_in_flight), int(max_deliver)
        self.backoff_base_s, self.backoff_max_s = backoff_base_s, backoff_max_s
        self.clock = clock
        self.now = now or _now
        self.stats_file = Path(stats_file) if stats_file else None
        self.stats_interval_s = stats_interval_s
        self.per_subject = {s.subject: SubjectStats() for s in config.subscriptions}
        self.failures = 0  # consecutive failed POSTs
        self.pause_until = 0.0
        self.last_forward: str | None = None
        self.last_error: str | None = None
        self._consumers: list[tuple[Subscription, Any]] = []
        self._pool = ThreadPoolExecutor(self.max_in_flight, thread_name_prefix="st2-bridge")
        self._stats_written = float("-inf")

    def open(self) -> None:
        """Create (or reopen) one durable consumer per subscription; refuse one whose lease
        (``ack_wait``, when the bus reports it) a POST could outlast."""
        consumers = [
            (s, self.bus.consumer(s.durable, s.subject, max_deliver=self.max_deliver))
            for s in self.config.subscriptions
        ]
        need = float(getattr(self.webhook, "timeout", 0.0)) + LEASE_MARGIN_S
        for s, cons in consumers:
            lease = getattr(cons, "ack_wait", None)
            if lease is not None and float(lease) < need:
                raise BridgeError(
                    f"durable {s.durable}: ack_wait {float(lease):g}s is shorter than the POST "
                    f"timeout plus {LEASE_MARGIN_S:g}s ({need:g}s), so a delivery would be handed "
                    "out again mid-POST; delete the durable and the bridge recreates it"
                )
        self._consumers = consumers

    def close(self) -> None:
        self._pool.shutdown(wait=True)
        self.write_stats(force=True)

    # ------------------------------------------------------------ one delivery
    def classify(self, sub: Subscription, delivery: Any) -> tuple[dict[str, Any] | None, str]:
        """``(event, "")`` to forward, or ``(None, reason)`` for poison."""
        if delivery.subject != sub.subject:
            return None, "wrong-subject"
        if len(delivery.data) > MAX_EVENT_BYTES:
            return None, "too-large"
        try:
            event = decode_event(delivery.data)
        except EventError as exc:
            return None, "not-json" if "not JSON" in str(exc) else "invalid-event"
        if event["type"] != sub.subject:
            return None, "wrong-type"
        if event.get("source") not in sub.sources:
            return None, "wrong-source"
        if delivery.msg_id is not None and delivery.msg_id != event["id"]:
            return None, "id-mismatch"
        return event, ""

    def _quarantine(self, sub: Subscription, d: Any, reason: str, event_id: Any = None) -> None:
        self.per_subject[sub.subject].quarantined[reason] += 1
        log.warning(
            "st2 bridge: quarantined %s seq %s (%s), event id %r: not forwarded, not retried",
            sub.subject,
            d.seq,
            reason,
            str(event_id)[:80] if event_id is not None else None,
        )
        self._settle_or_log(sub, d, "term")

    def _settle_or_log(self, sub: Subscription, d: Any, how: str) -> bool:
        """Settle ``d``; a bus that fails the settlement costs this delivery a redelivery (the
        lease lapses), never the bridge."""
        try:
            getattr(d, how)()
        except Exception as exc:
            self.last_error = f"{self.now()} {sub.subject}: {how} failed: {type(exc).__name__}"
            log.error(
                "st2 bridge: %s seq %s: %s failed (%s); the bus redelivers it",
                sub.subject,
                d.seq,
                how,
                type(exc).__name__,
            )
            return False
        return True

    def _classify(self, sub: Subscription, d: Any) -> tuple[dict[str, Any] | None, str]:
        """:meth:`classify`, where a defect in a check is poison for this one delivery."""
        try:
            return self.classify(sub, d)
        except Exception as exc:  # e.g. a validator recursing on a hostile body
            log.error(
                "st2 bridge: %s seq %s could not be checked (%s)",
                sub.subject,
                d.seq,
                type(exc).__name__,
            )
            return None, "unprocessable"

    def _post(self, event: Mapping[str, Any]) -> int | str:
        try:
            return self.webhook.post(event)
        except WebhookUnavailable as exc:
            return str(exc)
        except Exception as exc:  # a defect in a poster must cost a retry, never the event
            return type(exc).__name__

    def _settle(self, sub: Subscription, d: Any, event: Mapping[str, Any], got: int | str) -> bool:
        st = self.per_subject[sub.subject]
        if isinstance(got, int) and 200 <= got < 300:
            if not self._settle_or_log(sub, d, "ack"):
                return False
            st.forwarded += 1
            self.last_forward = self.now()
            return True
        if isinstance(got, int) and got in PERMANENT_STATUS:
            self._quarantine(sub, d, f"rejected-{got}", event.get("id"))
            return True
        why = f"HTTP {got}" if isinstance(got, int) else got
        self.last_error = f"{self.now()} {sub.subject}: {why}"
        if d.attempt >= self.max_deliver:
            st.dead_lettered += 1
            log.error(
                "st2 bridge: %s event %r dead-lettered after %d attempts (%s)",
                sub.subject,
                str(event.get("id"))[:80],
                d.attempt,
                why,
            )
        else:
            st.retried += 1
            log.warning(
                "st2 bridge: %s event %r not delivered (%s), attempt %d: retrying",
                sub.subject,
                str(event.get("id"))[:80],
                why,
                d.attempt,
            )
        self._settle_or_log(sub, d, "nack")
        return False

    # ------------------------------------------------------------ the loop
    def poll(self) -> int:
        """One pass over every subscription: fetch at most ``max_in_flight`` deliveries, POST the
        valid ones concurrently, settle each.  Returns how many deliveries were settled; 0 while
        backing off after a failed POST."""
        if self.clock() < self.pause_until:
            return 0
        handled = 0
        for sub, cons in self._consumers:
            batch = list(cons.fetch(self.max_in_flight))
            if not batch:
                continue
            todo: list[tuple[Any, dict[str, Any]]] = []
            for d in batch:
                event, why = self._classify(sub, d)
                if event is None:
                    self._quarantine(sub, d, why)
                else:
                    todo.append((d, event))
            results = list(self._pool.map(lambda pair: self._post(pair[1]), todo))
            ok = True
            for (d, event), got in zip(todo, results, strict=True):
                ok = self._settle(sub, d, event, got) and ok
            handled += len(batch)
            if ok:
                self.failures = 0
            else:
                self.failures += 1
                delay = min(self.backoff_max_s, self.backoff_base_s * 2 ** (self.failures - 1))
                self.pause_until = self.clock() + delay
                break
        self.write_stats()
        return handled

    def run(self, stop: threading.Event, *, idle_s: float = 1.0) -> None:
        """Poll until ``stop`` is set (SIGTERM); then finish and settle what is in flight."""
        self.open()
        try:
            while not stop.is_set():
                if self.poll() == 0:
                    wait = max(0.0, self.pause_until - self.clock()) or idle_s
                    stop.wait(min(wait, self.backoff_max_s))
        finally:
            self.close()

    # ------------------------------------------------------------ stats
    def stats(self) -> dict[str, Any]:
        quarantined = sum(sum(s.quarantined.values()) for s in self.per_subject.values())
        dead = sum(s.dead_lettered for s in self.per_subject.values())
        state = "ok"
        if self.failures:
            state = "warn"
        if dead:
            state = "fail"
        return {
            "bridge": "st2",
            "updated_at": self.now(),
            "state": state,
            "consecutive_failures": self.failures,
            "last_forward": self.last_forward,
            "last_error": self.last_error,
            "quarantined": quarantined,
            "subjects": {k: v.to_dict() for k, v in sorted(self.per_subject.items())},
        }

    def write_stats(self, *, force: bool = False) -> None:
        if self.stats_file is None:
            return
        now = self.clock()
        if not force and now - self._stats_written < self.stats_interval_s:
            return
        self._stats_written = now
        self.stats_file.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(self.stats(), indent=2, sort_keys=True) + "\n"
        atomic_write_text(self.stats_file, text, mode=0o640)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
