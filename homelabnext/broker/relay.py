# SPDX-License-Identifier: Apache-2.0
"""``hnx broker relay``: publish the broker's outbox to the event bus, at least once, in order.

The broker never speaks the bus while deciding: every event it emits (``decision.requested``,
``decision.returned``, ``proposal.created``) is written to ``<state>/outbox/`` with its place in
emit order (:meth:`homelabnext.broker.state.StateDir.put_outbox`), and this relay, a separate
process, publishes it.  So a bus outage costs latency, never a decision, and ``hnx broker serve``
keeps no network listener and needs no network at all.  The relay only *reads* ``outbox/``; what
it writes lives in ``<state>/relay/`` (:class:`RelayStore`), so it can run as its own user.

* **Ordered.**  Each pass takes the oldest undelivered events (at most ``batch``) and publishes
  them one after another; a failure that can pass (the bus is down, no PubAck in time) ends the
  pass, so a later event is never published before an earlier one that failed.  One relay per
  state directory (an ``flock`` on ``relay/relay.lock``), so two relays never interleave.
* **At least once, deduplicated.**  An event is marked delivered (``relay/delivered/<id>.json``,
  a copy of the event and its receipt) only after the bus acknowledged it (the JetStream PubAck).
  The event id is the message id (``Nats-Msg-Id``), so a crash between the publish and the mark
  republishes the same id on the next pass and the stream's ``duplicate_window`` answers with the
  original sequence instead of storing it twice.  The broker then removes the outbox file
  (:meth:`~homelabnext.broker.state.StateDir.prune_outbox`): ``outbox/`` holds what is pending,
  and a pass costs O(pending), not O(history).  Delivered markers older than ``retain_s`` are
  removed once the broker has pruned their outbox file.
* **Only the broker's events.**  Each event must pass its envelope and type schema and carry the
  source :data:`BROKER_SOURCE` before it is published; anything else is quarantined.
* **Poison does not stall it.**  A file that is not an event (not JSON, no id, no type, a bad
  ``queued``) is *quarantined*: a record in ``relay/quarantine/`` (file name, reason, time), then
  skipped.  A publish the bus refuses for the event itself (``permanent`` on the exception: an
  invalid subject, a subject no stream captures, a permission violation, a body over
  ``max_payload``) is retried with backoff; after ``max_attempts`` such failures the event is
  moved to ``relay/undeliverable/`` and later events go on.  That breaks per-stream order for that
  one event, deliberately: it will never be delivered, so holding everything behind it forever
  only turns one bad event into an outage.  If ``max_undeliverable_run`` events in a row end up
  undeliverable with nothing published in between, the bus is refusing everything (a
  configuration fault, not poison): the relay stops skipping and holds, ``state`` ``fail``.
  ``hnx broker relay --skip <id>`` is the operator's escape for an event to drop by hand.
* **The first start supersedes history.**  Outbox files from before ``queued`` were written by a
  broker that had no relay; publishing them all on the first start would replay old decisions.
  On a first start (no ``relay/initialized``) with such files pending, ``since`` is required: the
  ones older than it are marked ``superseded`` (in ``delivered/``, never published), the rest are
  published in order.
* **Backs off.**  A failed publish drops the connection (unless the failure was permanent: the
  connection is fine) and waits ``backoff_base_s * 2**(n-1)`` seconds, at most
  ``backoff_max_s``, before retrying the same event.
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

from .state import (
    RELAY_DIR,
    RELAY_DONE,
    OutboxFileError,
    StateDir,
    StateError,
    outbox_files,
    read_outbox_file,
)

__all__ = ["BROKER_SOURCE", "OutboxRelay", "RelayBusy", "RelayFirstStart", "RelayStore"]

#: the ``source`` of every event the broker emits; the StackStorm bridge's and A03's pin
BROKER_SOURCE = "svc:broker"
#: the event types the broker emits (and the subjects its bus user may publish)
BROKER_TYPES = ("homelabnext.decision.", "homelabnext.proposal.")
LOCK_NAME = "relay.lock"
INITIALIZED = "initialized"
#: how long delivered markers are kept once the broker pruned their outbox file (30 days)
RETAIN_S = 30 * 86400.0
_SWEEP_INTERVAL_S = 3600.0

log = logging.getLogger("homelabnext.broker.relay")


class RelayBusy(RuntimeError):
    """Another relay holds this state directory's lock."""


class RelayFirstStart(RuntimeError):
    """A first start with outbox files from before the relay, and no ``since`` to cut them."""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(stamp: str) -> float | None:
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _dumps(doc: Any) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


class RelayStore:
    """The relay's view of a broker state directory: it reads ``outbox/`` and writes only
    ``relay/`` (``delivered/``, ``undeliverable/``, ``quarantine/``, ``relay.lock``,
    ``initialized``), so it needs no other access to the broker's state."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.outbox = self.root / "outbox"
        self.dir = self.root / RELAY_DIR
        for d in (self.dir, *(self.dir / k for k in RELAY_DONE)):
            if d.is_symlink():
                raise StateError(f"{d} is a symlink; relay directories must be real")
            d.mkdir(mode=0o750, exist_ok=True)  # the broker (its group) reads the markers
        if not self.outbox.is_dir():
            raise StateError(f"{self.outbox} is not a directory (is --state the broker's?)")

    # ------------------------------------------------------------ reading
    def names(self) -> list[str]:
        """The outbox's file names (not yet pruned by the broker): listing only, no parsing."""
        return [p.name for p in outbox_files(self.outbox)]

    def done(self, name: str) -> str | None:
        """Which marker the relay holds for outbox file ``name`` (``delivered`` ...), or None."""
        for kind in RELAY_DONE:
            if (self.dir / kind / name).exists():
                return kind
        return None

    def pending_names(self) -> list[str]:
        return [n for n in self.names() if self.done(n) is None]

    def entries(self) -> list[tuple[tuple[int, int, str], dict[str, Any]]]:
        """Every pending outbox event, in emit order; a file that is not one is quarantined."""
        out = []
        for name in self.pending_names():
            try:
                out.append(read_outbox_file(self.outbox / name))
            except FileNotFoundError:
                continue  # pruned meanwhile
            except OutboxFileError as exc:
                self.quarantine(name, exc.reason)
        out.sort(key=lambda e: e[0])
        return out

    def get(self, kind: str, name: str) -> dict[str, Any] | None:
        try:
            return json.loads((self.dir / kind / name).read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return None

    def count(self, kind: str) -> int:
        return sum(1 for p in (self.dir / kind).glob("*.json") if not p.name.startswith("."))

    # ------------------------------------------------------------ writing (relay/ only)
    def mark(self, kind: str, event: dict[str, Any], receipt: dict[str, Any]) -> bool:
        """Record that the relay is done with ``event`` (exclusive: False when it already was).
        The marker keeps the event: once the broker prunes the outbox file it is the copy."""
        from .state import write_exclusive

        name = f"{event['id']}.json"
        return write_exclusive(self.dir / kind / name, _dumps({**receipt, "event": event}))

    def quarantine(self, name: str, reason: str, event_id: str | None = None) -> None:
        """An audit record for a file the relay will not publish: its name, why, and when (the
        file stays where it is until the broker prunes it; its content is not copied)."""
        from .state import write_exclusive

        record = {"file": name, "reason": reason, "at": _now(), "id": event_id}
        if write_exclusive(self.dir / "quarantine" / name, _dumps(record)):
            log.error("broker relay: quarantined outbox file %r (%s)", name[:80], reason)

    def skip(self, event_id: str, *, who: str = "operator") -> bool:
        """``--skip``: mark ``event_id`` undeliverable by hand (False: the relay is already done
        with it).  Its outbox file must exist."""
        name = f"{event_id}.json"
        if "/" in event_id or event_id.startswith(".") or not (self.outbox / name).is_file():
            raise StateError(f"no outbox event {event_id[:80]!r}")
        if self.done(name):
            return False
        try:
            _, event = read_outbox_file(self.outbox / name)
        except OutboxFileError as exc:
            self.quarantine(name, exc.reason)
            return True
        receipt = {"status": "skipped", "reason": f"skipped by {who}", "at": _now()}
        return self.mark("undeliverable", event, receipt)

    def sweep(self, *, retain_s: float, now: float) -> int:
        """Remove delivered markers older than ``retain_s`` whose outbox file the broker has
        already pruned (a marker whose file is still there would let it be republished)."""
        removed = 0
        for p in (self.dir / "delivered").glob("*.json"):
            try:
                if now - p.stat().st_mtime < retain_s or (self.outbox / p.name).exists():
                    continue
                p.unlink()
                removed += 1
            except FileNotFoundError:
                continue
        return removed

    @property
    def initialized(self) -> bool:
        return (self.dir / INITIALIZED).exists()

    def initialize(self, since: str | None) -> int:
        """The first start: outbox files from before ``queued`` (``format`` 0) older than
        ``since`` are marked ``superseded``; returns how many.  :class:`RelayFirstStart` when
        there are such files and no ``since``."""
        from .state import write_exclusive

        old = [(k, ev) for k, ev in self.entries() if k[0] == 0]
        if old and since is None:
            raise RelayFirstStart(
                f"first start with {len(old)} outbox event(s) from before the relay: pass "
                "--since TIME (older ones are marked superseded, never published; "
                "1970-01-01T00:00:00Z publishes them all)"
            )
        cut = _epoch(since) if since is not None else None
        if since is not None and cut is None:
            raise ValueError(f"--since {since[:40]!r} is not an ISO-8601 time")
        n = 0
        for _, ev in old:
            when = _epoch(str(ev.get("time", "")))
            if when is None or (cut is not None and when < cut):
                n += self.mark("delivered", ev, {"status": "superseded", "at": _now()})
        write_exclusive(self.dir / INITIALIZED, _dumps({"at": _now(), "superseded": n}))
        if n:
            log.warning("broker relay: first start: %d old outbox event(s) superseded", n)
        return n


class OutboxRelay:
    """Publishes ``state``'s outbox to the bus ``connect()`` returns (an
    :class:`conformance.protocols.events.EventBus`: ``publish(subject, data, msg_id=)`` returns
    the stream sequence once the bus acknowledged it, and raises otherwise; an exception with a
    true ``permanent`` attribute says the bus refuses that message for good).  ``state`` is the
    broker's state directory (a path, or a :class:`StateDir`)."""

    def __init__(
        self,
        state: StateDir | str | os.PathLike[str],
        connect: Callable[[], Any],
        *,
        batch: int = 100,
        backoff_base_s: float = 1.0,
        backoff_max_s: float = 60.0,
        max_attempts: int = 5,
        max_undeliverable_run: int = 3,
        retain_s: float = RETAIN_S,
        since: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], str] = _now,
        wall: Callable[[], float] = time.time,
        stats_file: str | os.PathLike[str] | None = None,
        stats_interval_s: float = 30.0,
    ) -> None:
        if batch < 1 or backoff_base_s <= 0 or backoff_max_s < backoff_base_s:
            raise ValueError("batch >= 1 and 0 < backoff_base_s <= backoff_max_s")
        if max_attempts < 1 or max_undeliverable_run < 1 or retain_s <= 0:
            raise ValueError("max_attempts, max_undeliverable_run and retain_s must be positive")
        root = state.root if isinstance(state, StateDir) else Path(state)
        self.store = RelayStore(root)
        self.connect = connect
        self.batch = int(batch)
        self.backoff_base_s, self.backoff_max_s = backoff_base_s, backoff_max_s
        self.max_attempts, self.max_undeliverable_run = max_attempts, max_undeliverable_run
        self.retain_s, self.since = retain_s, since
        self.clock, self.now, self.wall = clock, now, wall
        self.stats_file = Path(stats_file) if stats_file else None
        self.stats_interval_s = stats_interval_s
        self._stats_written = float("-inf")
        self._swept = float("-inf")
        self.bus: Any = None
        self.failures = 0  # consecutive failed passes
        self.pause_until = float("-inf")
        self.published = 0
        self.undeliverable = 0  # events this process moved to undeliverable/
        self.holding = False  # the bus refuses everything: stopped skipping
        self._attempts: dict[str, int] = {}  # permanent failures per event id
        self._skip_run = 0  # undeliverable in a row, nothing published in between
        self.last_published: str | None = None
        self.last_error: str | None = None
        self._lock_fd: int | None = None

    # ------------------------------------------------------------ the lock
    def acquire(self) -> None:
        """Take the state directory's relay lock (or raise :class:`RelayBusy`), then do the
        first start if this is one (or raise :class:`RelayFirstStart`)."""
        if self._lock_fd is not None:
            return
        import fcntl

        path = self.store.dir / LOCK_NAME
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise RelayBusy(f"another relay holds {path}") from None
        self._lock_fd = fd
        try:
            if not self.store.initialized:
                self.store.initialize(self.since)
        except Exception:
            self.close()
            raise

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
        if not getattr(exc, "permanent", False):
            self._drop_bus()  # a permanent refusal leaves the connection usable
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

    def _undeliverable(self, event: dict[str, Any], exc: BaseException) -> None:
        eid = str(event["id"])
        receipt = {
            "status": "undeliverable",
            "reason": type(exc).__name__,
            "attempts": self._attempts.pop(eid, 0),
            "at": self.now(),
        }
        self.store.mark("undeliverable", event, receipt)
        self.undeliverable += 1
        self._skip_run += 1
        self.last_error = f"{self.now()} undeliverable {event['type']}: {type(exc).__name__}"
        log.error(
            "broker relay: event %r (%s) is undeliverable after %d attempts (%s); "
            "publishing the ones after it",
            eid[:80],
            str(event["type"])[:120],
            receipt["attempts"],
            type(exc).__name__,
        )

    def _check(self, event: dict[str, Any]) -> str | None:
        """Why ``event`` must not be published (a quarantine reason), or None.  The relay
        publishes the broker's events only: the envelope and the type's schema must hold and the
        source must be :data:`BROKER_SOURCE`, so whoever can write a file into ``outbox/`` (and
        is not the broker) cannot make the broker's bus user publish it."""
        from homelabnext.events.envelope import event_problems

        if event.get("source") != BROKER_SOURCE:
            return "not-the-broker"
        if not str(event.get("type", "")).startswith(BROKER_TYPES):
            return "not-a-broker-type"  # the bus ACL grants the broker these subjects only
        if event_problems(event):
            return "invalid-event"
        return None

    def pass_once(self) -> int:
        """Publish up to ``batch`` pending events, oldest first; returns how many were
        acknowledged (0 while backing off, when nothing is pending or the bus is down)."""
        if self.clock() < self.pause_until:
            return 0
        if not self.store.initialized:
            self.store.initialize(self.since)
        self._sweep()
        entries = self.store.entries()[: self.batch]
        if not entries:
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
        for _, event in entries:
            eid, etype = str(event["id"]), str(event["type"])
            name = f"{eid}.json"
            if self.store.done(name):  # --skip meanwhile
                continue
            why = self._check(event)
            if why is not None:
                self.store.quarantine(name, why, eid)
                continue
            try:
                seq = self.bus.publish(etype, canonical_body(event), msg_id=eid)
            except Exception as exc:  # no PubAck: not delivered
                if getattr(exc, "permanent", False) and not self.holding:
                    n = self._attempts[eid] = self._attempts.get(eid, 0) + 1
                    if n >= self.max_attempts:
                        if self._skip_run >= self.max_undeliverable_run:
                            self.holding = True  # refusing everything: hold, do not drain
                            log.error(
                                "broker relay: %d events in a row refused for good: the bus "
                                "refuses everything (its ACL or stream?); holding",
                                self._skip_run + 1,
                            )
                        else:
                            self._undeliverable(event, exc)
                            continue
                self._fail(f"publish {etype}", exc, eid)
                break
            self.store.mark("delivered", event, {"type": etype, "seq": seq, "at": self.now()})
            log.info("broker relay: published %s %s (seq %s)", etype, eid[:80], seq)
            self._attempts.pop(eid, None)
            self._skip_run, self.holding = 0, False
            done += 1
            self.published += 1
            self.last_published = self.now()
        else:
            self.failures = 0
        self.write_stats(force=True)
        return done

    def _sweep(self) -> None:
        now = self.clock()
        if now - self._swept < _SWEEP_INTERVAL_S:
            return
        self._swept = now
        n = self.store.sweep(retain_s=self.retain_s, now=self.wall())
        if n:
            log.info("broker relay: removed %d delivered marker(s) past retention", n)

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
    def pending(self) -> int:
        """Events still to publish (by name: nothing is parsed)."""
        return len(self.store.pending_names())

    def stats(self) -> dict[str, Any]:
        undeliverable = self.store.count("undeliverable")
        quarantined = self.store.count("quarantine")
        state = "ok"
        if self.failures:
            state = "warn"
        if undeliverable or quarantined or self.holding:
            state = "fail"
        return {
            "relay": "broker-outbox",
            "updated_at": self.now(),
            "state": state,
            "pending": self.pending(),
            "published": self.published,
            "undeliverable": undeliverable,
            "quarantined": quarantined,
            "holding": self.holding,
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
