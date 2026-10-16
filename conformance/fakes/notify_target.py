# SPDX-License-Identifier: Apache-2.0
"""``notify`` fakes: the library's ``FakeSender`` behind the target interface, and a defective one."""

from __future__ import annotations

from homelabnext.notify import FakeSender, Message


class FakeNotifyTarget:
    features = frozenset({"fault-injection"})

    def __init__(self) -> None:
        self._fake = FakeSender()
        self.sender = self._fake

    def received(self) -> list[Message]:
        return list(self._fake.sent)

    def fail_next(self, n: int = 1) -> None:
        self._fake.fail_next = n


class _DoubleSender(FakeSender):
    def send(self, message: Message) -> None:
        super().send(message)
        super().send(message)  # delivered twice


class DoubleSendNotifyTarget(FakeNotifyTarget):
    """Defect: every message is delivered twice."""

    def __init__(self) -> None:
        self._fake = _DoubleSender()
        self.sender = self._fake
