# SPDX-License-Identifier: Apache-2.0
"""The broker's notifications: approval pages (one open page per actor, at most one per
``notify_window_s``, derived from state by ``poll_pages``), lane-quota notices, and the
notifier call every one of them goes through.

A part of :class:`homelabnext.broker.service.BrokerService` (its module doc says how the parts
fit); the methods read and write the service's own attributes, set in its ``__init__``."""

from __future__ import annotations

import contextlib
import heapq
import re
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import lanes as _lanes
from .common import (
    _AUDIT_FAILURES,
    _PAGE_IDS,
    APPROVAL_CLEARED,
    APPROVAL_TITLE,
    LANE_NOTICE_INTERVAL_S,
    LANE_QUOTA_CLEARED,
    LANE_QUOTA_TITLE,
    NOTIFY_WARN_EVERY_S,
    PAGE_RETRY_S,
    log,
)
from .relay import BROKER_SOURCE


class _PagingMixin:
    """Mixed into :class:`~homelabnext.broker.service.BrokerService`; not used on its own."""

    @staticmethod
    def _page_key(rid: str) -> str:
        return f"broker-approval-{rid}"

    def _open_page(self, actor: str, waiting: Sequence[Mapping[str, Any]]) -> str | None:
        """The request of ``actor``'s that has an open page: one still awaiting approval whose
        page the notifier reports sent and not yet settled."""
        rids = [r["request_id"] for r in waiting]
        if self._paged.get(actor) in rids:
            return self._paged[actor]
        state_of = getattr(self.notifier, "state_of", None)
        if state_of is not None:
            return next((r for r in rids if state_of(self._page_key(r)) != "ok"), None)
        return None

    def _wake_at(self, when: float) -> None:
        """Make sure a page check runs at ``when`` (monotonic): it is kept in a heap, and one
        timer is armed for the earliest (best effort: :meth:`poll_pages` also runs at start and
        on every submit, settle and pending listing, and derives what is due from state)."""
        with self._paged_lock:
            if when in self._wakeups:
                return  # already queued (a retry, a floor): one entry per time
            heapq.heappush(self._wakeups, when)
        self._arm()

    def _arm(self) -> None:
        if not self.page_timers:
            return
        with self._paged_lock:
            now = self._mono()
            while self._wakeups and self._wakeups[0] <= now - 3600:
                heapq.heappop(self._wakeups)  # long past and never polled: nothing to arm
            future = [t for t in self._wakeups if t > now]
            if not future:
                return
            nxt = min(future)
            if self._timer is not None and self._timer[0] <= nxt and self._timer[1].is_alive():
                return
            if self._timer is not None:
                self._timer[1].cancel()
            timer = threading.Timer(nxt - now + 0.05, self._timer_fired)
            timer.args = (timer,)
            timer.daemon = True
            self._timer = (nxt, timer)
            timer.start()

    def _timer_fired(self, timer: threading.Timer | None = None) -> None:
        with self._paged_lock:
            if self._timer is not None and self._timer[1] is timer:
                self._timer = None  # only its own: a timer re-armed since stays armed
        try:
            self.poll_pages()
        except Exception:  # a timer thread: log it, the next poll tries again
            log.exception("approval pages could not be polled")

    def poll_pages(self) -> int:
        """Page every actor that has a request awaiting approval and no open page -- a page the
        floor deferred, a page whose send failed, a request whose approval expired unused, one
        filed before a restart -- each subject to the floor and the open-page gate, so this is
        idempotent.  Also retries a lane-quota "cleared" notice that was held back, and re-arms
        the timer for what is due next.  Returns how many actors were checked."""
        if self.notifier is None:
            return 0
        now = self._mono()
        with self._paged_lock:
            while self._wakeups and self._wakeups[0] <= now:
                heapq.heappop(self._wakeups)
        actors = []
        for rid in self.state.open_request_ids():
            rec = self.state.get_request(rid)
            if rec and rec["verdict"] == "needs-approval" and rec["request"]["actor"] not in actors:
                actors.append(rec["request"]["actor"])
        for actor in actors:
            try:
                self._page(actor)
            except Exception:  # one actor's failure never stops the rest
                log.exception("approval page for %s failed", actor)
        for lane_name, actor in list(self._lane_red.values()):
            lane = self._lanes.get(lane_name)
            if lane is not None:
                self._lane_quota(lane, {"actor": actor, "request_id": None}, None)
        self._arm()
        return len(actors)

    def _page(self, actor: str) -> None:
        """Page the approver about ``actor``'s oldest request awaiting approval, unless one of
        its requests already has an open page, or its last page is less than
        ``notify_window_s`` old, or its last attempt failed less than
        :data:`PAGE_RETRY_S` ago (then a check is scheduled for when that passes).  The actor
        counts as paged only once the notifier says the page went out."""
        waiting = self._awaiting(actor)
        if not waiting:
            return
        now = self._mono()
        later = None
        with self._paged_lock:
            if actor in self._paging or self._open_page(actor, waiting) is not None:
                return
            last = self._last_page.get(actor)
            retry = self._retry_at.get(actor)
            if retry is not None and retry > now:
                later = retry
            elif last is not None and now - last < self.notify_window_s:
                later = last + self.notify_window_s
            else:
                self._paging.add(actor)  # of racing requests, one pages
        if later is not None:
            self._wake_at(later)
            return
        request = waiting[0]
        rid = request["request_id"]
        key = self._page_key(rid)
        sent = False
        try:
            from homelabnext.notify.core import Message

            link = self.approval_link(rid)
            body = f"{actor} asks to run {request['action']} ({rid})"
            if len(waiting) > 1:
                ids = [r["request_id"] for r in waiting]
                named = ", ".join(ids[:_PAGE_IDS])
                if len(ids) > _PAGE_IDS:
                    named += f" and {len(ids) - _PAGE_IDS} more"
                body += f"; {len(ids)} requests await approval from {actor}: {named}"
            msg = Message(
                key=key,
                title=APPROVAL_TITLE,
                body=body + (f"\nReview: {link}" if link else ""),
                level="warn",
                click=link,
            )
            sent = self._notify(key, "awaiting-approval", msg, actor=actor)
        finally:
            with self._paged_lock:
                self._paging.discard(actor)
                if sent:
                    self._paged[actor] = rid
                    self._last_page[actor] = now
                    self._retry_at.pop(actor, None)
                else:  # a failed send, or the actor's budget spent: try again shortly
                    self._retry_at[actor] = now + PAGE_RETRY_S
        if not sent:
            self._wake_at(now + PAGE_RETRY_S)
            return
        if rid not in {r["request_id"] for r in self._awaiting(actor)}:
            # it settled while the page was in flight: its settling saw no page to close
            self._close_page(actor, rid, None)
            self._page(actor)

    def _close_page(self, actor: str, rid: str, body: str | None) -> bool:
        """Close ``rid``'s page if it has one: with a settled message, or quietly (``body``
        None: the owner withdrew it, which nobody needs paged about).  True when it had one."""
        key = self._page_key(rid)
        state_of = getattr(self.notifier, "state_of", None)
        with self._paged_lock:
            paged = self._paged.get(actor) == rid
            if paged:
                del self._paged[actor]
        if state_of is not None:
            paged = paged or state_of(key) != "ok"
        if not paged:
            return False
        if body is None:
            clear = getattr(self.notifier, "clear", None)
            if clear is not None:
                try:
                    clear(key)
                except Exception:
                    log.exception("approval page %s could not be cleared", key)
        else:
            from homelabnext.notify.core import Message

            msg = Message(key=key, title=APPROVAL_CLEARED, body=body)
            self._notify(key, "ok", msg, actor=actor)
        forget = getattr(self.notifier, "forget", None)
        if forget is not None:  # a settled request's page is done with: the store stays small
            with contextlib.suppress(Exception):
                forget(key)
        return True

    def _notify_settled(
        self, rid: str, how: str, actor: str | None = None, *, quiet: bool = False
    ) -> None:
        if self.notifier is None or actor is None:
            return
        waiting = self._awaiting(actor)
        body = f"{rid} {how}"
        if waiting:
            body += f"; {len(waiting)} more from {actor} await approval"
        self._close_page(actor, rid, None if quiet else body)
        self.poll_pages()  # the page moves to the oldest still waiting, after the floor

    def _lane_quota(self, lane: _lanes.Lane, request: Mapping[str, Any], refusal: str | None):
        """Tell the operator that ``lane`` refuses an actor's writes for its quota (the agent
        alone hears ``lane-quota-exceeded``, and a finding that is never written looks like a run
        that never happened), and that it has room again -- but only once the directory is back
        under :data:`homelabnext.broker.lanes.USAGE_WARN` of its quotas, not on the next small
        write that fits, and never two notices for one actor and lane within
        :data:`LANE_NOTICE_INTERVAL_S`.  State-diffed by the notifier, so a looping agent's
        thousandth refusal sends nothing, and its notices draw on its own budget."""
        actor = request["actor"]
        key = f"broker-lane-quota-{lane.name}-{re.sub(r'[^a-z0-9-]+', '-', actor.lower())}"
        if self.notifier is None:
            if refusal is not None and key not in self._lane_logged:
                self._lane_logged.add(key)  # no notifier: the log is the operator's signal
                log.warning("%s: lane %s refuses its writes: %s", actor, lane.name, refusal)
            return
        from homelabnext.notify.core import Message

        now = self._now()
        last = self._lane_notice_at.get(key)
        recent = last is not None and (now - last).total_seconds() < LANE_NOTICE_INTERVAL_S
        if refusal is None:
            state_of = getattr(self.notifier, "state_of", None)
            if key not in self._lane_full and (state_of is None or state_of(key) == "ok"):
                return  # nothing was reported: nothing to clear (the common case, one read)
            if recent:
                return
            try:
                used = _lanes.fill(
                    lane, self.data_root, actor, key=self._name_key(), ledger=self._ledger()
                )
            except (OSError, _lanes.LaneError):
                return
            if used >= _lanes.USAGE_WARN:
                return  # still nearly full: the next small write would only be refused again
            body = f"{actor} writes to lane {lane.name} again; it is {used:.0%} full of its quota"
            msg = Message(key=key, title=LANE_QUOTA_CLEARED, body=body)
            if self._notify(key, "ok", msg, request_id=request["request_id"], actor=actor):
                self._lane_full.discard(key)
                self._lane_red.pop(key, None)
                self._lane_notice_at[key] = now
            return
        if recent:
            return
        body = (
            f"{actor}'s writes to lane {lane.name} are refused lane-quota-exceeded: {refusal}. "
            "Raise the lane's quota in the manifest or clear the directory "
            "(hnx broker validate --data-root shows its usage)."
        )
        msg = Message(key=key, title=LANE_QUOTA_TITLE, body=body, level="warn")
        sent = self._notify(
            key, "lane-quota-exceeded", msg, request_id=request["request_id"], actor=actor
        )
        if sent:
            self._lane_full.add(key)
            self._lane_red[key] = (lane.name, actor)  # a held "cleared" is retried on each poll
            self._lane_notice_at[key] = now

    def _ledger(self) -> Path:
        return self.state.root / "lanes-ledger"

    def lane_usage(self) -> list[dict[str, Any]]:
        """Every lane directory's usage against its quotas, each actor's share of a shared lane
        included (:func:`homelabnext.broker.lanes.usage`, with the broker's own key and ledger)."""
        actors = tuple(sorted({g["profile"] for g in self._view()["grants"]}))
        return [
            row
            for lane in self._lanes.values()
            for row in _lanes.usage(
                lane, self.data_root, actors=actors, key=self._name_key(), ledger=self._ledger()
            )
        ]

    def _notify(
        self, key, state, msg, *, request_id: str | None = None, actor: str | None = None
    ) -> bool:
        """Whether the notifier sent ``msg``.  A notification is a courtesy: the event and the
        pending list already carry the request, so a failed send never fails the broker
        operation that triggered it.  A message about ``actor`` draws on that actor's own
        notifier budget (``scope``), so one agent cannot spend the pages of every other."""
        try:
            if actor is not None and self._scoped:
                scope = "actor-" + re.sub(r"[^a-z0-9-]+", "-", actor.lower())
                return bool(self.notifier.report(key, state, msg, scope=scope))
            return bool(self.notifier.report(key, state, msg))
        except Exception as exc:
            now = self._mono()
            if now - self._notify_warned >= NOTIFY_WARN_EVERY_S:  # logged, never a log flood
                self._notify_warned = now
                log.warning("a notification could not be sent: %s", type(exc).__name__)
            rid = request_id or (
                key.removeprefix("broker-approval-") if key.startswith("broker-approval-") else None
            )
            with contextlib.suppress(*_AUDIT_FAILURES):
                self._audit(
                    BROKER_SOURCE, "", "notify", "error", reason="notify-failed", request_id=rid
                )
            return False


def _takes_scope(notifier: Any) -> bool:
    """Whether ``notifier.report`` takes a ``scope`` (a per-actor budget)."""
    import inspect

    try:
        return "scope" in inspect.signature(notifier.report).parameters
    except (AttributeError, TypeError, ValueError):
        return False
