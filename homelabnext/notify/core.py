# SPDX-License-Identifier: Apache-2.0
"""Message model and the state-diffed :class:`Notifier`.

Rules the Notifier enforces (each exists because the opposite shipped once and hurt):

* **State-diffed.**  ``report(key, state, msg)`` sends only when the state of ``key`` *changed*.
  The same problem state reported every minute is one page, not sixty.
* **Every alert has a registered recovery.**  A problem is sent only if its ``title`` was registered
  with :meth:`Notifier.register_pair`.  An alert that can never clear is refused at the source
  (:class:`UnregisteredProblem`) instead of paging forever.
* **Recovery is automatic.**  Reporting state ``"ok"`` for a key that is in a problem state sends
  that title's registered recovery message once.
* **Rate limited.**  A global budget (``max_sends`` per ``window_s``) and a per-key minimum interval.
  A rate-limited report does not record the new state, so it is retried on the next call and a
  burst is delayed rather than silently lost.  A report with a ``scope`` (a broker passes the
  agent the message is about) draws on that scope's own budget of the same size instead of the
  global one, so one noisy scope can never spend everyone else's pages.
* **Quiet clear.**  :meth:`Notifier.clear` marks a key ``ok`` without sending its recovery (a
  problem its own reporter withdrew, which nobody needs paged about).
* **A failed send is not recorded** (the exception propagates), so the next call retries.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

LEVELS = ("info", "warn", "crit")
_LEVEL_PRIORITY = {"info": 3, "warn": 4, "crit": 5}
OK = "ok"


class SendError(Exception):
    """A sender could not deliver a message."""


class UnregisteredProblem(ValueError):
    """A problem title has no registered recovery pair."""


@dataclass(frozen=True)
class Message:
    key: str  # the dedupe key: one logical problem
    title: str
    body: str
    level: str = "info"  # info | warn | crit
    priority: int | None = None  # 1..5, default derived from level
    tags: tuple[str, ...] = ()
    topic: str | None = None  # None -> the sender's default topic
    email: str | None = None  # optional extra email target
    click: str | None = None  # optional http(s) link the notification opens (ntfy ``Click``)

    def __post_init__(self) -> None:
        if not self.key or not self.title:
            raise ValueError("Message needs a non-empty key and title")
        if self.level not in LEVELS:
            raise ValueError(f"level must be one of {LEVELS}, got {self.level!r}")
        if self.priority is not None and not (
            isinstance(self.priority, int) and 1 <= self.priority <= 5
        ):
            raise ValueError("priority must be an int in 1..5")
        if self.click is not None and (
            not self.click.startswith(("https://", "http://"))
            or any(c.isspace() for c in self.click)
        ):
            raise ValueError("click must be an http(s) URL")
        object.__setattr__(self, "tags", tuple(self.tags))

    @property
    def effective_priority(self) -> int:
        return self.priority if self.priority is not None else _LEVEL_PRIORITY[self.level]


class Sender(Protocol):
    def send(self, message: Message) -> None: ...


class _Store(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...
    def put(self, key: str, value: Any) -> None: ...


@dataclass(frozen=True)
class RateLimit:
    max_sends: int = 20
    window_s: float = 3600.0
    min_interval_per_key_s: float = 0.0


@dataclass
class Notifier:
    sender: Sender
    store: _Store
    clock: Callable[[], float] = time.time
    rate_limit: RateLimit | None = None
    namespace: str = "notify"
    _pairs: dict[str, str] = field(default_factory=dict, init=False, repr=False)
    suppressed_by_rate_limit: int = field(default=0, init=False)

    # ---------------------------------------------------------------- registration
    def register_pair(self, problem_title: str, recovery_title: str) -> None:
        if not problem_title or not recovery_title:
            raise ValueError("both titles are required")
        if problem_title == recovery_title:
            raise ValueError("recovery title must differ from the problem title")
        self._pairs[problem_title] = recovery_title

    def is_registered(self, problem_title: str) -> bool:
        return problem_title in self._pairs

    # ---------------------------------------------------------------- reporting
    def report(self, key: str, state: str, message: Message, *, scope: str | None = None) -> bool:
        """Report ``key`` is in ``state``.  Returns True if a message was sent.  ``scope`` (a
        short id: whose message this is) counts the send against that scope's own budget."""
        if not key or not state:
            raise ValueError("key and state are required")
        if message.key != key:
            message = replace(message, key=key)
        rec = self.store.get(f"{self.namespace}/{key}")
        prev_state = rec["state"] if rec else OK
        if state == OK:
            if prev_state == OK:
                return False
            return self._recover(key, rec, message, scope)
        if message.title not in self._pairs:
            raise UnregisteredProblem(
                f"problem title {message.title!r} has no registered recovery; "
                "call register_pair(problem_title, recovery_title) first"
            )
        if state == prev_state:
            return False
        if not self._allow(key, scope):
            return False
        self.sender.send(message)
        now = self.clock()
        self._note_send(key, now, scope)
        self.store.put(
            f"{self.namespace}/{key}",
            {
                "state": state,
                "title": message.title,
                "topic": message.topic,
                "email": message.email,
                "tags": list(message.tags),
                "since": now,
            },
        )
        return True

    def _recover(
        self, key: str, rec: dict[str, Any], message: Message, scope: str | None = None
    ) -> bool:
        title = rec["title"]
        recovery_title = self._pairs.get(title)
        if recovery_title is None:
            # The registry changed since the problem was sent; never leave the key red forever.
            recovery_title = f"Recovered: {title}"
        if not self._allow(key, scope):
            return False
        msg = Message(
            key=key,
            title=recovery_title,
            body=message.body or f"{title} has cleared.",
            level="info",
            tags=("recovered", *rec.get("tags", [])),
            topic=rec.get("topic") or message.topic,
            email=rec.get("email") or message.email,
        )
        self.sender.send(msg)
        now = self.clock()
        self._note_send(key, now, scope)
        self.store.put(
            f"{self.namespace}/{key}",
            {"state": OK, "title": None, "since": now, "recovered_from": title},
        )
        return True

    def clear(self, key: str) -> bool:
        """Mark ``key`` ``ok`` without sending anything; True when it was in a problem state."""
        rec = self.store.get(f"{self.namespace}/{key}")
        if not rec or rec.get("state", OK) == OK:
            return False
        self.store.put(
            f"{self.namespace}/{key}",
            {"state": OK, "title": None, "since": self.clock(), "cleared_from": rec.get("title")},
        )
        return True

    def state_of(self, key: str) -> str:
        rec = self.store.get(f"{self.namespace}/{key}")
        return rec["state"] if rec else OK

    # ---------------------------------------------------------------- rate limiting
    def _sends_key(self, scope: str | None) -> str:
        return f"{self.namespace}/_sends" + (f"/{scope}" if scope else "")

    def _allow(self, key: str, scope: str | None = None) -> bool:
        rl = self.rate_limit
        if rl is None:
            return True
        now = self.clock()
        sends = [t for t in self.store.get(self._sends_key(scope), []) if now - t < rl.window_s]
        last_for_key = self.store.get(f"{self.namespace}/_last/{key}")
        ok = len(sends) < rl.max_sends and (
            last_for_key is None or now - last_for_key >= rl.min_interval_per_key_s
        )
        if not ok:
            self.suppressed_by_rate_limit += 1
        return ok

    def _note_send(self, key: str, now: float, scope: str | None = None) -> None:
        rl = self.rate_limit
        if rl is None:
            return
        where = self._sends_key(scope)
        sends = [t for t in self.store.get(where, []) if now - t < rl.window_s]
        sends.append(now)
        self.store.put(where, sends)
        self.store.put(f"{self.namespace}/_last/{key}", now)
