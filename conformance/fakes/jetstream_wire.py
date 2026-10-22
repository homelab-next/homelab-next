# SPDX-License-Identifier: Apache-2.0
"""An in-process stand-in for the NATS JetStream wire API, for the adapter's offline tests.

It answers the requests :mod:`homelabnext.conform.adapters.nats_jetstream` sends, shaped as
nats-server 2.10 shapes them (read from the server source, ``server/consumer.go``, ``stream.go``,
``jetstream_api.go`` at v2.10.22):

* ``$JS.API.STREAM.{INFO,CREATE,DELETE,MSG.GET}`` (``seq``, ``next_by_subj``, ``last_by_subj``) and ``$JS.API.CONSUMER.{INFO,CREATE}`` (also the
  2.9+ ``CONSUMER.CREATE.<stream>.<durable>.<filter>`` form, whose filter must be the config's;
  pull consumers only, ``deliver_policy`` ``new``, ``all`` or ``by_start_time``) with the
  server's error objects (``stream not found`` 10059, ``consumer not found`` 10014, ``no message
  found`` 10037) and its stream-config rules (``>`` and ``$JS.`` subjects need no-ack, except
  ``$JS.EVENT.>``; subjects may not overlap another stream's);
* publish with a ``Nats-Msg-Id`` duplicate window answering the original sequence with
  ``"duplicate": true``; no responders when no stream captures the subject;
* pull requests (``CONSUMER.MSG.NEXT``, ``batch``/``no_wait``) with the redelivery queue served
  first, delivery counts, ``ack_wait`` expiry and ``max_deliver``: a message is dropped, with a
  ``MAX_DELIVERIES`` advisory, when the server next tries to deliver it past the limit;
* ``$JS.ACK`` replies (9 tokens) taking ``+ACK``/``-NAK``/``+TERM`` (``+TERM`` publishes a
  ``MSG_TERMINATED`` advisory); advisories are stored by any stream capturing their subject.

What it does not model: clustering, push consumers, flow control, limits other than the dedup
window, and the server's lingering of a ``no_wait`` pull that cannot be filled (it simply ends the
batch, which is what the client sees once its own pull timeout passes).
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from homelabnext.conform.adapters.nats_jetstream import WireError, WireMsg

_MAX = "$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES"
_TERM = "$JS.EVENT.ADVISORY.CONSUMER.MSG_TERMINATED"


def subject_matches(pattern: str, subject: str) -> bool:
    p, s = pattern.split("."), subject.split(".")
    for i, tok in enumerate(p):
        if tok == ">":
            return len(s) > i
        if i >= len(s) or (tok != "*" and tok != s[i]):
            return False
    return len(p) == len(s)


def _overlap(a: str, b: str) -> bool:
    """Could one subject match both patterns (the server's ``SubjectsCollide``)."""
    x, y = a.split("."), b.split(".")
    for i in range(max(len(x), len(y))):
        tx = x[i] if i < len(x) else None
        ty = y[i] if i < len(y) else None
        if tx == ">" or ty == ">":
            return tx is not None and ty is not None
        if tx is None or ty is None:
            return False
        if tx != "*" and ty != "*" and tx != ty:
            return False
    return True


def _err(code: int, err_code: int, description: str) -> dict[str, Any]:
    return {"error": {"code": code, "err_code": err_code, "description": description}}


@dataclass
class _Stored:
    seq: int
    subject: str
    data: bytes
    headers: dict[str, str]
    ts: float = 0.0  # wall-clock seconds when stored (deliver_policy by_start_time)


@dataclass
class _Stream:
    config: dict[str, Any]
    msgs: dict[int, _Stored] = field(default_factory=dict)
    last_seq: int = 0
    dedup: dict[str, tuple[int, float]] = field(default_factory=dict)
    consumers: dict[str, _Consumer] = field(default_factory=dict)


@dataclass
class _Consumer:
    name: str
    config: dict[str, Any]
    sseq: int  # next stream sequence to consider for first delivery
    dseq: int = 0
    pending: dict[int, tuple[int, float]] = field(default_factory=dict)  # sseq -> (dseq, ts)
    rdq: list[int] = field(default_factory=list)
    rdc: dict[int, int] = field(default_factory=dict)  # delivery counts


class FakeJetStreamWire:
    """Implements the adapter's ``Wire`` against an in-memory model of one nats-server."""

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        *,
        drop_advisories=False,
        wall: Callable[[], float] = time.time,
    ):
        self._clock = clock
        self._wall = wall
        self._lock = threading.RLock()
        self.streams: dict[str, _Stream] = {}
        self.log: list[tuple[str, bytes, dict[str, str]]] = []
        self.drop_advisories = drop_advisories  # a defect, for proving the suite catches it
        self.closed = False

    # ---------------------------------------------------------------- Wire
    def request(
        self,
        subject: str,
        payload: bytes = b"",
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float,
    ) -> WireMsg:
        with self._lock:
            if self.closed:
                raise WireError("connection closed")
            hdrs = dict(headers or {})
            self.log.append((subject, bytes(payload), hdrs))
            if subject.startswith("$JS.API."):
                doc = self._api(subject[len("$JS.API.") :], payload)
                return WireMsg("_INBOX.fake", json.dumps(doc).encode())
            if subject.startswith("$JS.ACK."):
                self._ack(subject, payload)
                return WireMsg("_INBOX.fake", b"")
            return WireMsg(
                "_INBOX.fake", json.dumps(self._publish(subject, payload, hdrs)).encode()
            )

    def pull(self, subject: str, payload: bytes, *, max_msgs: int, timeout: float) -> list[WireMsg]:
        with self._lock:
            if self.closed:
                raise WireError("connection closed")
            self.log.append((subject, bytes(payload), {}))
            parts = subject.split(".")
            if parts[:5] != ["$JS", "API", "CONSUMER", "MSG", "NEXT"] or len(parts) != 7:
                raise WireError(f"fake: unexpected pull subject {subject}")
            st = self.streams.get(parts[5])
            c = st.consumers.get(parts[6]) if st else None
            if c is None:
                return []  # the real server answers 404/409; the client sees an empty batch
            req = json.loads(payload)
            batch = min(int(req.get("batch", 1)), max_msgs)
            out: list[WireMsg] = []
            while len(out) < batch:
                m = self._next(st, c)
                if m is None:
                    break
                out.append(m)
            return out

    def close(self) -> None:
        self.closed = True

    # ---------------------------------------------------------------- API
    def _api(self, what: str, payload: bytes) -> dict[str, Any]:
        body = json.loads(payload) if payload else {}
        t = what.split(".")
        if t[0] == "STREAM" and t[1] == "INFO":
            st = self.streams.get(t[2])
            if st is None:
                return _err(404, 10059, "stream not found")
            return {
                "config": st.config,
                "state": {"messages": len(st.msgs), "last_seq": st.last_seq},
            }
        if t[0] == "STREAM" and t[1] == "CREATE":
            return self._create_stream(t[2], body)
        if t[0] == "STREAM" and t[1] == "DELETE":
            if self.streams.pop(t[2], None) is None:
                return _err(404, 10059, "stream not found")
            return {"success": True}
        if t[0] == "STREAM" and t[1] == "MSG" and t[2] == "GET":
            st = self.streams.get(t[3])
            if st is None:
                return _err(404, 10059, "stream not found")
            return self._msg_get(st, body)
        if t[0] == "CONSUMER" and t[1] == "INFO":
            st = self.streams.get(t[2])
            if st is None:
                return _err(404, 10059, "stream not found")
            c = st.consumers.get(t[3])
            if c is None:
                return _err(404, 10014, "consumer not found")
            return self._consumer_info(t[2], c)
        if t[0] == "CONSUMER" and t[1] == "CREATE":
            cfg = body.get("config") or {}
            if len(t) > 4 and cfg.get("filter_subject") != ".".join(t[4:]):
                return _err(
                    400,
                    10131,
                    "Consumer create request did not match filtered subject from create subject",
                )
            return self._create_consumer(t[2], t[3], body)
        return _err(400, 10003, f"fake: unsupported API {what}")

    def _create_stream(self, name: str, cfg: dict[str, Any]) -> dict[str, Any]:
        if cfg.get("name") != name:
            return _err(400, 10056, "stream name in subject does not match request")
        subjects = list(cfg.get("subjects") or [])
        for s in subjects:
            if not cfg.get("no_ack") and (
                s == ">" or (_overlap(s, "$JS.>") and not s.startswith("$JS.EVENT."))
            ):
                return _err(
                    400, 10052, "subjects that overlap with jetstream api require no-ack to be true"
                )
            for other in self.streams.values():
                if any(_overlap(s, o) for o in other.config.get("subjects", [])):
                    return _err(400, 10065, "subjects overlap with an existing stream")
        if name in self.streams:
            return _err(400, 10058, "stream name already in use with a different configuration")
        self.streams[name] = _Stream(dict(cfg))
        return {"config": cfg, "state": {"messages": 0, "last_seq": 0}}

    def _msg_get(self, st: _Stream, body: dict[str, Any]) -> dict[str, Any]:
        seq, nxt = int(body.get("seq", 0)), body.get("next_by_subj")
        last = body.get("last_by_subj")
        found = None
        if last:
            hits = [s for s in st.msgs if subject_matches(last, st.msgs[s].subject)]
            found = st.msgs[max(hits)] if hits else None
        elif nxt:
            for s in sorted(st.msgs):
                if s >= seq and subject_matches(nxt, st.msgs[s].subject):
                    found = st.msgs[s]
                    break
        else:
            found = st.msgs.get(seq)
        if found is None:
            return _err(404, 10037, "no message found")
        hdr = b""
        if found.headers:
            hdr = (
                "NATS/1.0\r\n" + "".join(f"{k}: {v}\r\n" for k, v in found.headers.items()) + "\r\n"
            ).encode()
        msg = {
            "subject": found.subject,
            "seq": found.seq,
            "data": base64.b64encode(found.data).decode(),
        }
        if hdr:
            msg["hdrs"] = base64.b64encode(hdr).decode()
        return {"message": msg}

    def _create_consumer(self, stream: str, name: str, body: dict[str, Any]) -> dict[str, Any]:
        st = self.streams.get(stream)
        if st is None:
            return _err(404, 10059, "stream not found")
        cfg = dict(body.get("config") or {})
        if body.get("stream_name") != stream:
            return _err(400, 10058, "stream name in subject does not match request")
        if cfg.get("durable_name") not in (None, name):
            return _err(
                400, 10017, "consumer name in subject does not match durable name in request"
            )
        if name in st.consumers:
            if body.get("action") == "create" and st.consumers[name].config != cfg:
                return _err(400, 10148, "consumer already exists")
            return self._consumer_info(stream, st.consumers[name])
        policy = cfg.get("deliver_policy", "all")
        if policy not in ("new", "all", "by_start_time") or cfg.get("ack_policy") != "explicit":
            return _err(400, 10003, "fake: deliver_policy new/all/by_start_time, ack explicit")
        if cfg.get("deliver_subject"):
            return _err(400, 10003, "fake: push consumers are not modelled")
        if policy == "new":
            first = st.last_seq + 1
        elif policy == "all":
            first = 1
        else:
            stamp = str(cfg.get("opt_start_time") or "")
            try:
                start = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return _err(400, 10094, "consumer deliver policy requires opt_start_time")
            later = [m.seq for m in st.msgs.values() if m.ts >= start]
            first = min(later) if later else st.last_seq + 1
        c = _Consumer(name, cfg, first)
        st.consumers[name] = c
        return self._consumer_info(stream, c)

    def _consumer_info(self, stream: str, c: _Consumer) -> dict[str, Any]:
        return {
            "stream_name": stream,
            "name": c.name,
            "config": c.config,
            "num_ack_pending": len(c.pending),
            "num_redelivered": sum(1 for v in c.rdc.values() if v > 1),
        }

    # ---------------------------------------------------------------- publish/deliver/ack
    def _capturing(self, subject: str) -> list[_Stream]:
        return [
            s
            for s in self.streams.values()
            if any(subject_matches(p, subject) for p in s.config["subjects"])
        ]

    def _store(self, st: _Stream, subject: str, data: bytes, hdrs: dict[str, str]) -> int:
        st.last_seq += 1
        st.msgs[st.last_seq] = _Stored(st.last_seq, subject, bytes(data), dict(hdrs), self._wall())
        return st.last_seq

    def _publish(self, subject: str, data: bytes, hdrs: dict[str, str]) -> dict[str, Any]:
        targets = self._capturing(subject)
        if not targets:
            raise WireError("no responders (no stream captures that subject?)")
        st = targets[0]
        now = self._clock()
        window = st.config.get("duplicate_window", 120 * 1_000_000_000) / 1e9
        mid = hdrs.get("Nats-Msg-Id")
        if mid:
            hit = st.dedup.get(mid)
            if hit and now - hit[1] < window:
                return {"stream": st.config["name"], "seq": hit[0], "duplicate": True}
        seq = self._store(st, subject, data, hdrs)
        if mid:
            st.dedup[mid] = (seq, now)
        return {"stream": st.config["name"], "seq": seq}

    def _advisory(self, prefix: str, stream: str, consumer: str, doc: dict[str, Any]) -> None:
        if self.drop_advisories:
            return
        subject = f"{prefix}.{stream}.{consumer}"
        for st in self._capturing(subject):
            self._store(st, subject, json.dumps(doc).encode(), {})

    def _next(self, st: _Stream, c: _Consumer) -> WireMsg | None:
        now = self._clock()
        ack_wait = c.config.get("ack_wait", 30 * 1_000_000_000) / 1e9
        maxdc = int(c.config.get("max_deliver", -1))
        stream = st.config["name"]
        for sseq, (_d, ts) in sorted(c.pending.items()):  # checkPending: expired leases
            if now - ts >= ack_wait and sseq not in c.rdq:
                if maxdc > 0 and c.rdc.get(sseq, 1) >= maxdc:
                    del c.pending[sseq]
                    self._advisory(
                        _MAX,
                        stream,
                        c.name,
                        {
                            "stream": stream,
                            "consumer": c.name,
                            "stream_seq": sseq,
                            "deliveries": c.rdc.get(sseq, 1),
                        },
                    )
                else:
                    c.rdq.append(sseq)
        while c.rdq:
            sseq = c.rdq.pop(0)
            dc = c.rdc[sseq] = c.rdc.get(sseq, 1) + 1
            if maxdc > 0 and dc > maxdc:
                if dc == maxdc + 1:
                    self._advisory(
                        _MAX,
                        stream,
                        c.name,
                        {
                            "stream": stream,
                            "consumer": c.name,
                            "stream_seq": sseq,
                            "deliveries": dc - 1,
                        },
                    )
                c.pending.pop(sseq, None)
                continue
            return self._deliver(st, c, sseq, dc, now)
        while c.sseq <= st.last_seq:
            sseq = c.sseq
            c.sseq += 1
            m = st.msgs.get(sseq)
            if m is not None and subject_matches(c.config["filter_subject"], m.subject):
                c.rdc[sseq] = 1
                return self._deliver(st, c, sseq, 1, now)
        return None

    def _deliver(self, st: _Stream, c: _Consumer, sseq: int, dc: int, now: float) -> WireMsg:
        c.dseq += 1
        c.pending[sseq] = (c.dseq, now)
        m = st.msgs[sseq]
        reply = f"$JS.ACK.{st.config['name']}.{c.name}.{dc}.{sseq}.{c.dseq}.0.0"
        return WireMsg(m.subject, m.data, dict(m.headers), reply)

    def _ack(self, reply: str, body: bytes) -> None:
        t = reply.split(".")
        if len(t) != 9:
            return
        st = self.streams.get(t[2])
        c = st.consumers.get(t[3]) if st else None
        if c is None:
            return
        dc, sseq, dseq = int(t[4]), int(t[5]), int(t[6])
        if body in (b"", b"+ACK"):
            c.pending.pop(sseq, None)
            if sseq in c.rdq:
                c.rdq.remove(sseq)
        elif body.startswith(b"-NAK"):
            if sseq in c.pending and sseq not in c.rdq:
                c.rdq.append(sseq)
        elif body.startswith(b"+TERM"):
            c.pending.pop(sseq, None)
            if sseq in c.rdq:
                c.rdq.remove(sseq)
            stream = st.config["name"]
            self._advisory(
                _TERM,
                stream,
                c.name,
                {
                    "stream": stream,
                    "consumer": c.name,
                    "consumer_seq": dseq,
                    "stream_seq": sseq,
                    "deliveries": dc,
                },
            )
