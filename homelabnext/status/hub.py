# SPDX-License-Identifier: Apache-2.0
"""The state service: latest observation per (source, module, item), a bounded history, staleness
from expiry (checklist O-06), and state-diffed notifications on transitions only (O-08).

Persistence is a :class:`homelabnext.state.StateStore` (or anything with its ``get``/``put``/
``delete``/``keys`` methods), so the hub survives restarts and ``hnx status serve`` reads the same
file the collector writes.  Keys::

    status/obs/<source>/<module>/<item>   {"latest": <observation>, "history": [[t, state], ...]}
    status/src/<source>                   {"last_attempt", "last_ok", "error"}

**Staleness is computed, never stored.**  Every observation carries ``expires_at`` (observed_at +
the source's ``stale_after_s``); reading it after that instant yields ``stale`` whatever it said.
A source that stops reporting therefore goes stale on time without anything having to run, and a
collector that died cannot leave its last green on the console.

**Notifications** go through the shared :class:`homelabnext.notify.Notifier` -- the O-08 path, not
a new one: one key per item, ``fail`` and ``stale`` page by default (``notify_on``), anything else
reports ``ok`` so the Notifier sends exactly one recovery when a paged item clears.  A UPS
going on battery (a ``poll-nut`` status item, warn) is one more state-diffed message under its
own key, listing what that UPS feeds (:func:`.power.notify`).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Protocol

from .mapping import Draft, clean_summary
from .model import OBSERVED_EVENT, Observation, SourceSpec, iso, parse_iso
from .scheduler import SourceResult

PREFIX = "status"
_log = logging.getLogger(__name__)
DEFAULT_HISTORY = 20
PROBLEM_TITLE = "Status item needs attention"
RECOVERY_TITLE = "Status item recovered"


class _Store(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...
    def put(self, key: str, value: Any) -> None: ...
    def delete(self, key: str) -> bool: ...
    def keys(self) -> list[str]: ...


class HubError(ValueError):
    """An observation or event the hub refuses (unknown source, invalid shape)."""


def effective_state(obs: Mapping[str, Any], now: float) -> str:
    """What an observation reads as at ``now``: ``stale`` once past ``expires_at``."""
    return "stale" if now >= parse_iso(obs["expires_at"]) else obs["state"]


class StatusHub:
    def __init__(
        self,
        specs: Sequence[SourceSpec],
        store: _Store,
        *,
        clock: Callable[[], float] = time.time,
        history: int = DEFAULT_HISTORY,
        notify_on: Iterable[str] = ("fail", "stale"),
    ):
        self.specs = {s.id: s for s in specs}
        self.store = store
        self.clock = clock
        self.history = history
        self.notify_on = frozenset(notify_on)

    # ---------------------------------------------------------------- keys
    @staticmethod
    def _obs_key(key: str) -> str:
        return f"{PREFIX}/obs/{key}"

    @staticmethod
    def _src_key(source: str) -> str:
        return f"{PREFIX}/src/{source}"

    def _keys_of(self, source: str) -> list[str]:
        pre, keys = f"{PREFIX}/obs/{source}/", self.store.keys()  # a store, not a dict
        return [k for k in keys if k.startswith(pre)]

    # ---------------------------------------------------------------- writes
    def _observe(self, spec: SourceSpec, draft: Draft, now: float) -> Observation:
        obs = Observation(
            source=spec.id,
            module=draft.module or spec.module,
            item=draft.item,
            state=draft.state,
            summary=draft.summary,
            observed_at=iso(now),
            expires_at=iso(now + spec.stale_after_s),
            link=draft.link or f"status:{spec.id}",
            value=draft.value,
            work=draft.work,
            flags=draft.flags,
        )
        self._put(obs, now)
        return obs

    def _put(self, obs: Observation, now: float) -> None:
        k = self._obs_key(obs.key)
        rec = self.store.get(k) or {}
        hist = list(rec.get("history", []))
        if not hist or hist[-1][1] != obs.state:  # history keeps transitions, bounded
            hist.append([iso(now), obs.state])
        new = {"latest": obs.to_dict(), "history": hist[-self.history :]}
        if obs.flags is not None:
            new["flags"] = list(obs.flags)
        self.store.put(k, new)

    def record(self, result: SourceResult) -> list[Observation]:
        """Store one scheduler result; returns the observations it produced."""
        spec = self.specs.get(result.source)
        if spec is None:
            raise HubError(f"unknown status source {result.source!r}")
        now = self.clock()
        src = dict(self.store.get(self._src_key(spec.id)) or {})
        src["last_attempt"] = iso(now)
        src["error"] = result.error
        out: list[Observation] = []
        if result.ok:
            src["last_ok"] = iso(now)
            fresh = set()
            for d in result.drafts:
                obs = self._observe(spec, d, now)
                fresh.add(self._obs_key(obs.key))
                out.append(obs)
            for k in self._keys_of(spec.id):  # an item the source no longer lists is gone
                if spec.polled and k not in fresh:
                    self.store.delete(k)
        elif spec.on_error == "fail":
            # a liveness probe: failing to reach it IS the reading
            known = [self.store.get(k)["latest"] for k in self._keys_of(spec.id)]
            items = [(o["module"], o["item"]) for o in known] or [(spec.module, spec.id)]
            for module, item in items:
                d = Draft(
                    item=item, state="fail", summary=clean_summary(result.error), module=module
                )
                out.append(self._observe(spec, d, now))
        self.store.put(self._src_key(spec.id), src)
        return out

    def ingest(
        self, observation: Mapping[str, Any], *, publisher: str | None = None
    ) -> Observation:
        """Record an observation pushed by a ``push-event`` source (already schema-valid).

        Only the source's owner may report it: ``publisher`` (the event envelope's ``source``,
        given by :meth:`ingest_event`) must be ``svc:<the service that declares the source>``,
        and the module must be the one the source reports (``mapping.module``, else the
        declaring service).  Times are the hub's, not the pusher's: an ``observed_at`` in the
        future is clamped to now (the skew is kept on the source as ``clock_skew_s``), and
        ``expires_at`` is capped at both ``observed_at + stale_after_s`` and
        ``now + stale_after_s``, so a pushed reading always goes stale on time (O-06)."""
        source = observation.get("source")
        spec = self.specs.get(str(source))
        if spec is None or spec.polled:
            return self._refuse(f"{source!r} is not a registered push-event status source")
        if publisher is not None and publisher != f"svc:{spec.service}":
            return self._refuse(
                f"{publisher!r} may not report status source {spec.id!r} "
                f"(declared by svc:{spec.service})"
            )
        if observation.get("module") != spec.module:
            return self._refuse(
                f"status source {spec.id!r} reports module {spec.module!r}, "
                f"not {observation.get('module')!r}"
            )
        now = self.clock()
        obs = Observation.from_dict(observation)
        observed = parse_iso(obs.observed_at)
        skew = max(0.0, observed - now)
        if skew:
            observed = now
        cap = min(observed, now) + spec.stale_after_s
        expires = min(parse_iso(obs.expires_at), cap)
        if skew or expires != parse_iso(obs.expires_at):
            obs = Observation.from_dict(
                {**obs.to_dict(), "observed_at": iso(observed), "expires_at": iso(expires)}
            )
        self._put(obs, now)
        src = dict(self.store.get(self._src_key(spec.id)) or {})
        src.update(last_attempt=iso(now), last_ok=iso(now), error=None)
        if skew:
            src["clock_skew_s"] = round(skew, 3)
            _log.warning(
                "status source %s: observed_at %.0fs in the future, clamped", spec.id, skew
            )
        else:
            src.pop("clock_skew_s", None)
        self.store.put(self._src_key(spec.id), src)
        return obs

    def _refuse(self, reason: str):
        _log.warning("status hub refused a pushed observation: %s", reason)
        raise HubError(reason)

    def ingest_event(self, body: bytes | str | Mapping[str, Any]) -> Observation:
        """Decode and validate a ``homelabnext.status.observed`` event, then :meth:`ingest` it
        with the envelope's ``source`` as the publisher (it must own the status source)."""
        from homelabnext.events.consumer import decode_event

        event = decode_event(body, types=[OBSERVED_EVENT])
        return self.ingest(event["data"], publisher=event["source"])

    # ---------------------------------------------------------------- reads
    def observations(self, now: float | None = None) -> list[dict[str, Any]]:
        """Every latest observation with its effective state (``reported_state`` = as recorded)."""
        now = self.clock() if now is None else now
        out = []
        for k in sorted(self.store.keys()):
            if not k.startswith(f"{PREFIX}/obs/"):
                continue
            rec = self.store.get(k) or {}
            latest = rec.get("latest")
            if not latest or latest.get("source") not in self.specs:
                continue
            row = dict(latest)
            row["reported_state"] = latest["state"]
            row["state"] = effective_state(latest, now)
            row["history"] = [list(h) for h in rec.get("history", [])]
            if rec.get("flags") is not None:
                row["flags"] = [str(f) for f in rec["flags"]]
            out.append(row)
        return out

    def sources(self, now: float | None = None) -> list[dict[str, Any]]:
        """Every registered source with its own state: ok, stale, unknown (never read) or fail."""
        now = self.clock() if now is None else now
        out = []
        for sid in sorted(self.specs):
            spec = self.specs[sid]
            rec = self.store.get(self._src_key(sid)) or {}
            last_ok = rec.get("last_ok")
            if last_ok is None:
                state = "unknown"
            elif now - parse_iso(last_ok) >= spec.stale_after_s:
                state = "stale"
            elif rec.get("error"):
                state = "fail" if spec.on_error == "fail" else "warn"
            else:
                state = "ok"
            out.append(
                {
                    **spec.describe(),
                    "state": state,
                    "last_attempt": rec.get("last_attempt"),
                    "last_ok": last_ok,
                    "error": rec.get("error"),
                    **({"clock_skew_s": rec["clock_skew_s"]} if rec.get("clock_skew_s") else {}),
                }
            )
        return out

    def last_attempts(self) -> dict[str, float | None]:
        out: dict[str, float | None] = {}
        for sid in self.specs:
            rec = self.store.get(self._src_key(sid)) or {}
            out[sid] = parse_iso(rec["last_attempt"]) if rec.get("last_attempt") else None
        return out

    def snapshot(self, now: float | None = None) -> dict[str, Any]:
        now = self.clock() if now is None else now
        return {
            "now": iso(now),
            "observations": self.observations(now),
            "sources": self.sources(now),
        }

    # ---------------------------------------------------------------- notifications and bus
    def notify(self, notifier: Any, now: float | None = None) -> list[str]:
        """Report every item's and every source's paging state to the shared state-diffed
        Notifier; returns the keys a message was sent for (a transition into or out of a paging
        state, nothing else).

        A stale source pages once under its own key (``.../_source``) and its items, stale with
        it, are not reported at all until it reads again (no flood, no false recovery).  An item
        that was paged and has since disappeared from its source is reported recovered.
        """
        from homelabnext.notify import Message

        if not notifier.is_registered(PROBLEM_TITLE):
            notifier.register_pair(PROBLEM_TITLE, RECOVERY_TITLE)
        now = self.clock() if now is None else now
        srcs = self.sources(now)
        dead = {s["id"] for s in srcs if s["state"] == "stale"}
        rows = [r for r in self.observations(now) if r["source"] not in dead]
        rows += [
            {"source": s["id"], "module": s["module"], "item": "_source", "state": s["state"],
             "summary": s["error"] or f"source {s['id']} is {s['state']}"}
            for s in srcs
        ]  # fmt: skip
        sent, seen = [], set()
        for row in rows:
            key = f"{PREFIX}/{row['source']}/{row['module']}/{row['item']}"
            seen.add(key)
            paging = row["state"] if row["state"] in self.notify_on else "ok"
            msg = Message(
                key=key,
                title=PROBLEM_TITLE,
                body=f"{row['module']}/{row['item']} is {row['state']}: {row['summary']}",
                level="crit" if row["state"] == "fail" else "warn",
                tags=("status", row["module"]),
            )
            if notifier.report(key, paging, msg):
                sent.append(key)
        pre = f"{notifier.namespace}/{PREFIX}/"
        for nk in sorted(notifier.store.keys()):
            key = nk[len(notifier.namespace) + 1 :]
            gone = nk.startswith(pre) and key not in seen and key.split("/")[1] not in dead
            if gone and notifier.state_of(key) != "ok":
                body = f"{key[len(PREFIX) + 1 :]} is no longer reported by its source."
                msg = Message(key=key, title=PROBLEM_TITLE, body=body, tags=("status",))
                if notifier.report(key, "ok", msg):
                    sent.append(key)
        from . import power

        # a UPS on battery pages even though its status item is only warn (degraded)
        sent += power.notify(notifier, self.specs, self.observations(now), dead)
        return sent

    def publish(self, publisher: Any, observations: Iterable[Observation], source: str) -> list:
        """Publish observations as ``homelabnext.status.observed`` events (one place to read
        everything); the id derives from the item and ``observed_at``, so a re-send is a
        duplicate.  ``source`` is the publishing service's logical id (``svc:<name>``)."""
        from homelabnext.events.envelope import build_event

        out = []
        for obs in observations:
            ev = build_event(
                OBSERVED_EVENT,
                source,
                obs.to_dict(),
                dedupe_key=f"{obs.key}@{obs.observed_at}",
                time=obs.observed_at,
                subject=obs.key[:256],
                severity={"fail": "high", "warn": "medium"}.get(obs.state, "info"),
            )
            out.append(publisher.publish(ev))
        return out
