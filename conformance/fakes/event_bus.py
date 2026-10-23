# SPDX-License-Identifier: Apache-2.0
"""In-memory event bus with durable consumers, redelivery and a dead-letter list."""

from __future__ import annotations

import itertools

from conformance.protocols.events import Delivery


def subject_matches(pattern: str, subject: str) -> bool:
    p, s = pattern.split("."), subject.split(".")
    for i, tok in enumerate(p):
        if tok == ">":
            return len(s) > i
        if i >= len(s):
            return False
        if tok != "*" and tok != s[i]:
            return False
    return len(p) == len(s)


class _Msg:
    __slots__ = ("data", "msg_id", "seq", "subject")

    def __init__(self, seq: int, subject: str, data: bytes, msg_id: str | None):
        self.seq, self.subject, self.data, self.msg_id = seq, subject, data, msg_id


class FakeConsumer:
    def __init__(self, bus: FakeEventBus, name: str, pattern: str, max_deliver: int, start: int):
        self.bus, self.name, self.pattern, self.max_deliver = bus, name, pattern, max_deliver
        self._cursor = start  # next sequence to consider for first delivery
        self._redeliver: list[_Msg] = []
        self._attempts: dict[int, int] = {}
        # seq -> the token of the one delivery of it that may still be settled.  Keyed by
        # delivery, not by message: a stale delivery (an earlier one of the same message, or one
        # handed out before a reopen) must not settle the live redelivery.
        self._in_flight: dict[int, int] = {}
        self._tokens = itertools.count(1)
        self._dead: list[Delivery] = []

    def fetch(self, n: int = 1) -> list[Delivery]:
        out: list[Delivery] = []
        while len(out) < n and self._redeliver:
            out.append(self._deliver(self._redeliver.pop(0)))
        while len(out) < n and self._cursor <= len(self.bus._log):
            msg = self.bus._log[self._cursor - 1]
            self._cursor += 1
            if subject_matches(self.pattern, msg.subject):
                out.append(self._deliver(msg))
        return out

    def _deliver(self, msg: _Msg) -> Delivery:
        attempt = self._attempts.get(msg.seq, 0) + 1
        self._attempts[msg.seq] = attempt
        token = next(self._tokens)
        self._in_flight[msg.seq] = token
        d = Delivery(msg.seq, msg.subject, msg.data, msg.msg_id, attempt)
        d._settle = lambda how, m=msg, dl=d, t=token: self._settle(m, dl, how, t)
        return d

    def _settle(self, msg: _Msg, delivery: Delivery, how: str, token: int) -> None:
        if self._in_flight.get(msg.seq) != token:
            return  # settled already, or superseded by a later delivery: a no-op
        del self._in_flight[msg.seq]
        if how == "ack":
            return
        if how == "term" or delivery.attempt >= self.max_deliver:
            self._dead_letter(delivery)
            return
        self._redeliver.append(msg)

    def _dead_letter(self, delivery: Delivery) -> None:
        self._dead.append(delivery)

    def dead_letters(self) -> list[Delivery]:
        return list(self._dead)

    def _reopen(self) -> None:
        """A restart: whatever was fetched but not settled becomes deliverable again - unless that
        delivery was its last allowed attempt: an unsettled delivery counts against
        ``max_deliver`` like a nack (JetStream counts every delivery), so a message whose
        consumer crashes on it every time is dead-lettered, not delivered forever."""
        pending = sorted(self._in_flight)
        self._in_flight.clear()
        by_seq = {m.seq: m for m in self._redeliver}
        for s in pending:
            msg = self.bus._log[s - 1]
            if self._attempts.get(s, 0) >= self.max_deliver:
                self._dead_letter(
                    Delivery(msg.seq, msg.subject, msg.data, msg.msg_id, self._attempts[s])
                )
            else:
                by_seq[s] = msg
        self._redeliver = [by_seq[s] for s in sorted(by_seq)]


class FakeEventBus:
    features = frozenset({"wildcards"})
    consumer_class = FakeConsumer

    def __init__(self) -> None:
        self._log: list[_Msg] = []
        self._ids: dict[str, int] = {}
        self._consumers: dict[str, FakeConsumer] = {}

    def publish(self, subject: str, data: bytes, *, msg_id: str | None = None) -> int:
        if not subject or " " in subject:
            raise ValueError("bad subject")
        if msg_id is not None and msg_id in self._ids:
            return self._ids[msg_id]
        seq = len(self._log) + 1
        self._log.append(_Msg(seq, subject, bytes(data), msg_id))
        if msg_id is not None:
            self._ids[msg_id] = seq
        return seq

    def consumer(self, name: str, subject: str, *, max_deliver: int = 3) -> FakeConsumer:
        if name in self._consumers:
            c = self._consumers[name]
            c._reopen()
            return c
        c = self.consumer_class(self, name, subject, max_deliver, len(self._log) + 1)
        self._consumers[name] = c
        return c


class _DroppingConsumer(FakeConsumer):
    def _dead_letter(self, delivery: Delivery) -> None:  # the message vanishes
        return


class BrokenDlqEventBus(FakeEventBus):
    """Exhausted messages are discarded instead of dead-lettered."""

    consumer_class = _DroppingConsumer


class _ForgetfulConsumer(FakeConsumer):
    def _reopen(self) -> None:  # unsettled deliveries are lost on restart
        self._in_flight.clear()


class LosesUnsettledEventBus(FakeEventBus):
    """Fetched-but-unsettled messages are lost when the consumer is reopened (at-most-once)."""

    consumer_class = _ForgetfulConsumer


class RestartsAtTailEventBus(FakeEventBus):
    """Reopening a durable consumer starts a fresh one at the end of the log."""

    def consumer(self, name: str, subject: str, *, max_deliver: int = 3) -> FakeConsumer:
        c = self.consumer_class(self, name, subject, max_deliver, len(self._log) + 1)
        self._consumers[name] = c
        return c


class _ResettlingConsumer(FakeConsumer):
    def _settle(self, msg: _Msg, delivery: Delivery, how: str, token: int) -> None:
        self._in_flight[msg.seq] = token  # every settlement counts, not only the first
        super()._settle(msg, delivery, how, token)


class DoubleSettleEventBus(FakeEventBus):
    """A second nack (or a nack after an ack) queues the message again."""

    consumer_class = _ResettlingConsumer


class ReplayingEventBus(FakeEventBus):
    """Defect: a new durable consumer starts at the beginning of the log, so it is handed every
    message published before it existed."""

    def consumer(self, name: str, subject: str, *, max_deliver: int = 3) -> FakeConsumer:
        new = name not in self._consumers
        c = super().consumer(name, subject, max_deliver=max_deliver)
        if new:
            c._cursor = 1
        return c


class _StaleSettlingConsumer(FakeConsumer):
    def _settle(self, msg: _Msg, delivery: Delivery, how: str, token: int) -> None:
        # keyed by message, not by delivery: any delivery of a message in flight settles it
        super()._settle(msg, delivery, how, self._in_flight.get(msg.seq, -1))


class StaleSettleEventBus(FakeEventBus):
    """Defect: settlement is tracked per message, so a stale delivery - an earlier one of the
    same message, or one handed out before a reopen - settles the live redelivery (a late ack
    from a crashed process swallows the new process's nack: the message is lost)."""

    consumer_class = _StaleSettlingConsumer


class _StaleTermConsumer(FakeConsumer):
    def _settle(self, msg: _Msg, delivery: Delivery, how: str, token: int) -> None:
        if how == "term" and msg.seq in self._in_flight:  # term is routed by message
            token = self._in_flight[msg.seq]
        super()._settle(msg, delivery, how, token)


class StaleTermEventBus(FakeEventBus):
    """Defect: ``ack`` and ``nack`` settle per delivery, but ``term`` settles the message, so a
    stale ``term`` from a crashed process dead-letters the live redelivery."""

    consumer_class = _StaleTermConsumer


class _StaleNackRequeuesConsumer(FakeConsumer):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._generation = 0

    def _reopen(self) -> None:
        self._generation += 1
        super()._reopen()

    def _deliver(self, msg: _Msg) -> Delivery:
        d = super()._deliver(msg)
        gen, live = self._generation, d._settle

        def settle(how: str) -> None:
            if gen != self._generation and how == "nack":
                # "to be safe": requeue unless the message is in flight or queued already
                queued = any(m.seq == msg.seq for m in self._redeliver)
                if msg.seq not in self._in_flight and not queued:
                    self._redeliver.append(msg)
                return
            live(how)  # type: ignore[misc]

        d._settle = settle
        return d


class StaleNackRequeuesEventBus(FakeEventBus):
    """Defect: a stale ``ack`` or ``term`` from before a reopen is ignored, but a stale ``nack``
    is honoured "to be safe" and requeues the message - even after the live delivery was acked,
    so an acked message is delivered again."""

    consumer_class = _StaleNackRequeuesConsumer


class _NackRequeuesConsumer(FakeConsumer):
    def _settle(self, msg: _Msg, delivery: Delivery, how: str, token: int) -> None:
        if how == "nack" and self._in_flight.get(msg.seq) != token:
            queued = any(m.seq == msg.seq for m in self._redeliver)
            if msg.seq not in self._in_flight and not queued:
                self._redeliver.append(msg)
            return
        super()._settle(msg, delivery, how, token)


class SettledNackRequeuesEventBus(FakeEventBus):
    """Defect: a ``nack`` of a delivery that is no longer in flight still requeues the message
    unless it is already queued, so a nack after an ack redelivers an acked message."""

    consumer_class = _NackRequeuesConsumer


class _CrashLoopConsumer(FakeConsumer):
    def _reopen(self) -> None:  # every unsettled delivery comes back, however many attempts it had
        pending = sorted(self._in_flight)
        self._in_flight.clear()
        by_seq = {m.seq: m for m in self._redeliver}
        by_seq.update({s: self.bus._log[s - 1] for s in pending})
        self._redeliver = [by_seq[s] for s in sorted(by_seq)]


class CrashLoopEventBus(FakeEventBus):
    """Defect (the reference fake did this): only a nack counts against ``max_deliver``, so a
    poison message whose consumer crashes before settling it is redelivered forever."""

    consumer_class = _CrashLoopConsumer


class _WorkQueueConsumer(FakeConsumer):
    def _settle(self, msg: _Msg, delivery: Delivery, how: str, token: int) -> None:
        if how == "ack" and self._in_flight.get(msg.seq) == token:
            self.bus._acked_once.add(msg.seq)  # gone for every consumer
        super()._settle(msg, delivery, how, token)

    def fetch(self, n: int = 1) -> list[Delivery]:
        out = []
        for d in super().fetch(n):
            if d.seq in self.bus._acked_once:
                self._in_flight.pop(d.seq, None)
                continue
            out.append(d)
        return out


class WorkQueueEventBus(FakeEventBus):
    """Defect: a stream with WorkQueue retention (one word in a JetStream stream config): a
    message one durable acked is removed for every other durable."""

    consumer_class = _WorkQueueConsumer

    def __init__(self) -> None:
        super().__init__()
        self._acked_once: set[int] = set()


class _ForgetfulDlqConsumer(FakeConsumer):
    def _reopen(self) -> None:
        super()._reopen()
        self._dead = []  # the dead-letter list lived in the crashed process's memory


class InMemoryDlqEventBus(FakeEventBus):
    """Defect: the dead-letter list is client memory, so a reopened durable reports none."""

    consumer_class = _ForgetfulDlqConsumer
