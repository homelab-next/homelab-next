# SPDX-License-Identifier: Apache-2.0
"""``hnx broker relay``: publish the broker's outbox to the event bus, at least once, in order.

The broker never speaks the bus while deciding: every event it emits (``decision.requested``,
``decision.returned``, ``proposal.created``) is written to ``<state>/outbox/`` with its place in
emit order (:meth:`homelabnext.broker.state.StateDir.put_outbox`), and this relay, a separate
process under the broker's own user, publishes it.  So a bus outage costs latency, never a
decision, and ``hnx broker serve`` keeps no network listener and needs no network at all.

* **Ordered.**  Each pass takes the oldest undelivered events (at most ``batch``) and publishes
  them one after another; the first failure ends the pass, so a later event is never published
  before an earlier one that failed.  One relay per state directory (an ``flock`` on
  ``relay.lock``), so two relays never interleave.
* **At least once, deduplicated.**  An event is marked delivered (``delivered/<event id>.json``)
  only after the bus acknowledged it (the JetStream PubAck).  The event id is the message id
  (``Nats-Msg-Id``), so a crash between the publish and the mark republishes the same id on the
  next pass and the stream's ``duplicate_window`` answers with the original sequence instead of
  storing it twice.
* **Backs off.**  A failed publish (the bus is down, the connection broke, no PubAck in time)
  drops the connection and waits ``backoff_base_s * 2**(n-1)`` seconds, at most
  ``backoff_max_s``, before reconnecting and retrying the same event.
* **Nothing secret logged.**  Logs and stats name event ids, types and exception *classes*; never
  an event body, an endpoint or a credential (the bus credential is a secret name in the target
  file, read from the environment when connecting).

Every event keeps the broker's source, :data:`BROKER_SOURCE`, which the StackStorm bridge and the
approved-run rule (A03) pin.  That pin means something only when nobody else can publish those
subjects: give the broker's NATS user, and only it, publish on ``homelabnext.decision.>`` and
``homelabnext.proposal.>`` under the stream's prefix (docs/broker.md, "Publishing events").
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .state import StateDir

__all__ = ["BROKER_SOURCE", "OutboxRelay", "RelayBusy"]

#: the ``source`` of every event the broker emits; the StackStorm bridge's and A03's pin
BROKER_SOURCE = "svc:broker"
LOCK_NAME = "relay.lock"

log = logging.getLogger("homelabnext.broker.relay")


class RelayBusy(RuntimeError):
    """Another relay holds this state directory's lock."""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class OutboxRelay:
    """Publishes ``state``'s outbox to the bus ``connect()`` returns (an
    :class:`conformance.protocols.events.EventBus`: ``publish(subject, data, msg_id=)`` returns
    the stream sequence once the bus acknowledged it, and raises otherwise)."""

    def __init__(
        self,
        state: StateDir,
        connect: Callable[[], Any],
        *,
        batch: int = 100,
        backoff_base_s: float = 1.0,
        backoff_max_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], str] = _now,
        stats_file: str | os.PathLike[str] | None = None,
        stats_interval_s: float = 30.0,
    ) -> None:
        if batch < 1 or backoff_base_s <= 0 or backoff_max_s < backoff_base_s:
            raise ValueError("batch >= 1 and 0 < backoff_base_s <= backoff_max_s")
        self.state, self.connect = state, connect
        self.batch = int(batch)
        self.backoff_base_s, self.backoff_max_s = backoff_base_s, backoff_max_s
        self.clock, self.now = clock, now
        self.stats_file = Path(stats_file) if stats_file else None
        self.stats_interval_s = stats_interval_s
        self._stats_written = float("-inf")
        self.bus: Any = None
        self.failures = 0  # consecutive failed passes
        self.pause_until = float("-inf")
        self.published = 0
        self.last_published: str | None = None
        self.last_error: str | None = None
        self._lock_fd: int | None = None

    # ------------------------------------------------------------ the lock
    def acquire(self) -> None:
        """Take the state directory's relay lock, or raise :class:`RelayBusy`."""
        if self._lock_fd is not None:
            return
        import fcntl

        path = self.state.root / LOCK_NAME
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise RelayBusy(f"another relay holds {path}") from None
        self._lock_fd = fd

    def close(self) -> None:
        self._drop_bus()
        if self._lock_fd is not None:
            os.close(self._lock_fd)  # releases the flock
            self._lock_fd = None
        self.write_stats(force=True)

    def _drop_bus(self) -> None:
        bus, self.bus = self.bus, None
        if bus is not None:
            with contextlib.suppress(Exception):
                bus.close()

    # ------------------------------------------------------------ one pass
    def _fail(self, what: str, exc: BaseException, event_id: str | None = None) -> None:
        self._drop_bus()
        self.failures += 1
        delay = min(self.backoff_max_s, self.backoff_base_s * 2 ** (self.failures - 1))
        self.pause_until = self.clock() + delay
        # the exception's class only: a transport message may carry an endpoint or a credential
        self.last_error = f"{self.now()} {what}: {type(exc).__name__}"
        log.warning(
            "broker relay: %s failed (%s)%s; retrying in %.1fs",
            what,
            type(exc).__name__,
            f", event {event_id[:80]!r} stays pending" if event_id else "",
            delay,
        )

    def pass_once(self) -> int:
        """Publish up to ``batch`` pending events, oldest first; returns how many were
        acknowledged (0 while backing off, when nothing is pending or the bus is down)."""
        if self.clock() < self.pause_until:
            return 0
        pending = self.state.outbox_pending(self.batch)
        if not pending:
            self.write_stats()
            return 0
        if self.bus is None:
            try:
                self.bus = self.connect()
            except Exception as exc:  # down, refused, misconfigured: the outbox keeps them
                self._fail("connect", exc)
                self.write_stats(force=True)
                return 0
        from homelabnext.events.envelope import canonical_body

        done = 0
        for event in pending:
            eid, etype = str(event["id"]), str(event["type"])
            try:
                seq = self.bus.publish(etype, canonical_body(event), msg_id=eid)
            except Exception as exc:  # no PubAck: not delivered, retried in order
                self._fail(f"publish {etype}", exc, eid)
                break
            self.state.mark_delivered(eid, {"type": etype, "seq": seq, "at": self.now()})
            log.info("broker relay: published %s %s (seq %s)", etype, eid[:80], seq)
            done += 1
            self.published += 1
            self.last_published = self.now()
        else:
            self.failures = 0
        self.write_stats(force=True)
        return done

    def drain(self, *, max_passes: int = 1000) -> int:
        """Publish until nothing is pending or a pass fails (``--once``); returns how many were
        published.  Does not wait out a backoff."""
        total = 0
        for _ in range(max_passes):
            before = self.failures
            n = self.pass_once()
            total += n
            if n == 0 or self.failures > before:
                break
        return total

    def run(self, stop: threading.Event, *, idle_s: float = 1.0) -> None:
        """Pass until ``stop`` is set (SIGTERM); between passes wait ``idle_s``, or out the
        backoff."""
        self.acquire()
        try:
            while not stop.is_set():
                if self.pass_once() == 0:
                    wait = max(0.0, self.pause_until - self.clock()) or idle_s
                    stop.wait(min(wait, self.backoff_max_s))
        finally:
            self.close()

    # ------------------------------------------------------------ stats
    def stats(self) -> dict[str, Any]:
        pending = len(self.state.outbox_pending())
        return {
            "relay": "broker-outbox",
            "updated_at": self.now(),
            "state": "warn" if self.failures else "ok",
            "pending": pending,
            "published": self.published,
            "consecutive_failures": self.failures,
            "last_published": self.last_published,
            "last_error": self.last_error,
        }

    def write_stats(self, *, force: bool = False) -> None:
        """Write :meth:`stats` to ``stats_file`` (atomically) after a pass that published or
        failed, and otherwise at most every ``stats_interval_s``."""
        if self.stats_file is None:
            return
        now = self.clock()
        if not force and now - self._stats_written < self.stats_interval_s:
            return
        self._stats_written = now
        from homelabnext.state.store import atomic_write_text

        self.stats_file.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(self.stats(), indent=2, sort_keys=True) + "\n"
        atomic_write_text(self.stats_file, text, mode=0o640)
