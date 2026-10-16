# SPDX-License-Identifier: Apache-2.0
"""In-memory event bus with durable consumers, redelivery and a dead-letter list."""

from __future__ import annotations

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
        self._in_flight: set[int] = set()
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
        self._in_flight.add(msg.seq)
        d = Delivery(msg.seq, msg.subject, msg.data, msg.msg_id, attempt)
        d._settle = lambda how, m=msg, dl=d: self._settle(m, dl, how)
        return d

    def _settle(self, msg: _Msg, delivery: Delivery, how: str) -> None:
        if msg.seq not in self._in_flight:
            return  # already settled: settling twice is a no-op
        self._in_flight.discard(msg.seq)
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
            return self._consumers[name]
        c = self.consumer_class(self, name, subject, max_deliver, len(self._log) + 1)
        self._consumers[name] = c
        return c


class _DroppingConsumer(FakeConsumer):
    def _dead_letter(self, delivery: Delivery) -> None:  # the message vanishes
        return


class BrokenDlqEventBus(FakeEventBus):
    """Exhausted messages are discarded instead of dead-lettered."""

    consumer_class = _DroppingConsumer
