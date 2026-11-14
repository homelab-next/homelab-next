# SPDX-License-Identifier: Apache-2.0
"""A turn source (``inference`` feature ``turn-records``) on the lab's own gateway's usage log.

``make(**config)`` returns a :class:`UsageTurnSource`, a
:class:`conformance.protocols.inference.TurnSource`: ``turns(start, end, tags)`` reads the
gateway's ``GET /v1/usage?start=&end=&tag=`` (ADR-0038 decision 6; the gateway config contract's
R10, R10', R11 and R17) and maps each record to the neutral turn record
(:data:`conformance.protocols.inference.TURN_FIELDS`).  Orchestration telemetry selects it with
``hnx orchestration turns --turn-source homelabnext.conform.adapters.gateway_usage:make``
(``docs/orchestration-telemetry.md``); nothing outside this module knows the route or the record.

**Read path: the telemetry reader's key, named by secret** (default: the secret store's
``llm-gateway/key-telemetry-reader``, :data:`DEFAULT_KEY`, delivered in
``HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER``): the key the rendered config's
``telemetry_reader`` names, which may call ``/v1/usage`` and no model.  The gateway also lets its
admin key read the route; this reader refuses the master key by the variable it is delivered in,
as the spend-log reader does, and a key whose value is the admin key's (the value of
``HNX_SECRET_LLM_GATEWAY_MASTER_KEY``, when that is set), so the hub never holds a key that can call every model.

**Paging.** One read is ``[start, end]`` in whole unix seconds (``end`` included) for one tag;
the gateway returns the earliest 10000 matching records by ``ts`` and ``"truncated": true`` when
more matched.  The reader then asks again from the last record's second and drops the turn ids it
has already seen where the pages meet; a truncated page that ends in the second it began (more than
10000 records in one second) cannot be paged past and is an error, as is a window of more than
``max_pages`` pages.  Several tags are several reads, merged by turn id.

**The record** (:func:`turn_from_record`): the request id, the tag, the start (``ts``, kept to
whole seconds), duration and time to first token, the role asked for (``model_role``), call
type (``chat`` or ``embedding``), token counts, cache figures and cost.  ``model`` is the
deployment that served the call (its id, ``<role>-<n>``, which names one backend and model id of
the rendered ``gateway.json``): the record's own ``model`` is always the alias, and the backend
model id never leaves the gateway (R10').  A call that no deployment served (a refusal) has a null
``model``.  ``status`` is ``success`` for a 2xx and ``failure`` otherwise, with the HTTP status as
``error_code``; ``cache_read_tokens`` and ``cache_hit`` stay null when the upstream reported no
cache figure (R10': null is "not reported", never 0).  Everything else in a record -- the key
alias and owner, the served role, ``stream``, ``fallbacks``, ``usage_estimated``, the TLP
verdict, the contract's ``error_code`` word -- is never read out.

**``count``.** The gateway aggregates refusals to one record per second (R17) whose ``count``
says how many refusals it stands for.  The turn record has no such field and a consumer counts
turns, so a record of ``count`` *n* becomes *n* turns: the first keeps the record's ``turn_id``,
the others are ``<turn_id>.2`` to ``<turn_id>.<n>`` (stable across reads, and still turn ids).
A refusal carries no tokens or cost, so the expansion adds turns, never spend: a record of
``count`` above 1 that is a 2xx or carries a token count or cost other than null or 0 is refused
as not the gateway's, and so is a ``count`` above :data:`MAX_COUNT`, a page of more than
:data:`MAX_RECORDS` records, and a read that would yield more than ``MAX_RECORDS * max_pages``
turns.

Transport as the spend-log reader's: https with verification (``ca_file`` for a private CA), plain
http only to loopback or with ``allow_plaintext``; no redirect is followed and no proxy is used,
so the key never reaches another origin; the reply is read bounded.
"""

from __future__ import annotations

import math
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from typing import Any

from conformance.protocols.inference import TAG, TURN_ID, TurnSourceError
from homelabnext._http import check_plaintext, credential_opener
from homelabnext.registry import env_var_name
from homelabnext.registry.model import secret_env_name
from homelabnext.status.model import iso

from ._turn_source import cost as cost_or_none
from ._turn_source import count, fetch_json, name, plain_float, plain_int

__all__ = [
    "DEFAULT_KEY",
    "MAX_COUNT",
    "MAX_PAGES",
    "MAX_RECORDS",
    "TURN_SOURCES",
    "USAGE_PATH",
    "UsageError",
    "UsageReader",
    "UsageTurnSource",
    "make",
    "parse_ts",
    "turn_from_record",
]

USAGE_PATH = "/v1/usage"
DEFAULT_KEY = "secret:llm-gateway/key-telemetry-reader"
#: the gateway's admin key (the lab spec's ``master_key``): never a reader's credential
MASTER_KEY = "secret:llm-gateway/master-key"
CAPABILITY = "llm-gateway"
#: the gateway's cap on one reply (contract R11)
MAX_RECORDS = 10000
#: the most records one window may take, as pages of up to MAX_RECORDS
MAX_PAGES = 100
#: a usage page holds up to 10000 records of well under 1 KiB each
MAX_PAGE_BYTES = 32 << 20
#: the most refusals one aggregated record may stand for (a second of a flood)
MAX_COUNT = 100_000
#: the longest a single page request may wait, in seconds (``timeout`` is 0 < t <= this)
MAX_TIMEOUT = 600
_SECRET_REF = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")
#: RFC 3339 as the gateway writes ``ts`` (Go's RFC3339Nano, UTC), fractions of any length
_TS = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)")


class UsageError(TurnSourceError):
    """The usage log could not be read (configuration, transport, refusal, shape)."""


class UsageReader:
    """Reads ``/v1/usage`` pages of one gateway (see the module docstring)."""

    def __init__(
        self,
        base_url: str,
        key: str = DEFAULT_KEY,
        *,
        env: Mapping[str, str] | None = None,
        ca_file: str | os.PathLike[str] | None = None,
        timeout: float = 15.0,
        allow_plaintext: bool = False,
        max_pages: int = MAX_PAGES,
    ) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise UsageError("the gateway URL must be an absolute https URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise UsageError("the gateway URL carries no credentials, query or fragment")
        if not (isinstance(key, str) and _SECRET_REF.fullmatch(key)):
            raise UsageError("the gateway key is a secret name (secret:<name>), never a value")
        if secret_env_name(key) == secret_env_name(MASTER_KEY):
            raise UsageError(
                f"{MASTER_KEY} is the gateway's admin key: give the reader the telemetry "
                "reader's key (docs/orchestration-telemetry.md)"
            )
        try:
            check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        max_pages = plain_int(max_pages)
        if max_pages is None or max_pages < 1:
            raise UsageError("max_pages is positive")
        timeout = plain_float(timeout)
        if timeout is None or not 0 < timeout <= MAX_TIMEOUT:
            raise UsageError(f"timeout is seconds, 0 < timeout <= {MAX_TIMEOUT}")
        self.url = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}{USAGE_PATH}"
        self.key_ref, self._env, self.timeout, self.max_pages = key, env, timeout, max_pages
        self._opener = credential_opener(str(ca_file) if ca_file else None)

    def __repr__(self) -> str:
        return f"UsageReader({self.url!r}, key={self.key_ref!r})"

    def _key(self) -> str:
        env = os.environ if self._env is None else self._env
        var, admin = secret_env_name(self.key_ref), secret_env_name(MASTER_KEY)
        value = env.get(var, "")
        if not value:
            raise UsageError(f"the gateway key is not set: {var} ({self.key_ref})")
        if env.get(admin) and value == env.get(admin):
            raise UsageError(
                f"{var} holds the same value as {admin}, the gateway's admin key: give the "
                "reader the telemetry reader's own key"
            )
        return value

    def page(self, start: int, end: int, tag: str) -> dict[str, Any]:
        """One reply of ``/v1/usage`` for ``[start, end]`` (whole unix seconds) and ``tag``."""
        q = urllib.parse.urlencode({"start": start, "end": end, "tag": tag})
        req = urllib.request.Request(f"{self.url}?{q}", method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", f"Bearer {self._key()}")
        doc = fetch_json(
            self._opener,
            req,
            timeout=self.timeout,
            max_bytes=MAX_PAGE_BYTES,
            error=UsageError,
            log="the usage log",
            page="a usage page",
            refused=f"{USAGE_PATH} takes the telemetry reader's key",
        )
        if not isinstance(doc, dict) or not isinstance(doc.get("records"), list):
            raise UsageError("the usage log's answer has no records list")
        if not isinstance(doc.get("truncated", False), bool):
            raise UsageError("the usage log's truncated is not a boolean")
        if len(doc["records"]) > MAX_RECORDS:
            raise UsageError(
                f"a usage page holds {len(doc['records'])} records, more than the gateway's "
                f"cap of {MAX_RECORDS}: not the gateway's answer"
            )
        return doc

    def records(self, start: float, end: float, tag: str) -> Iterator[Mapping[str, Any]]:
        """Every record of ``tag`` started in ``[start, end]``, page by page, each once."""
        lo, hi = math.floor(start), math.ceil(end)
        seen: set[str] = set()
        for _ in range(self.max_pages):
            doc = self.page(lo, hi, tag)
            last = None
            for r in doc["records"]:
                if not isinstance(r, Mapping):
                    continue
                rid, ts = r.get("turn_id"), parse_ts(r.get("ts"))
                if ts is not None:
                    last = ts if last is None else max(last, ts)
                if isinstance(rid, str) and rid not in seen:
                    seen.add(rid)
                    yield r
            if not doc.get("truncated"):
                return
            nxt = math.floor(last) if last is not None else None
            if nxt is None or nxt <= lo:
                raise UsageError(
                    f"more than {MAX_RECORDS} usage records in the second {lo}: the window "
                    "cannot be paged by time"
                )
            lo = nxt
        raise UsageError(f"more than {self.max_pages} pages of usage records in one window")


class UsageTurnSource:
    """The :class:`~conformance.protocols.inference.TurnSource` on one gateway's usage log."""

    def __init__(self, reader: UsageReader) -> None:
        self.reader = reader

    def __repr__(self) -> str:
        return f"UsageTurnSource({self.reader!r})"

    @property
    def max_turns(self) -> int:
        """The most turns one :meth:`turns` call yields: a full window's records
        (``MAX_RECORDS * max_pages``), whatever ``count`` expands them to."""
        return MAX_RECORDS * self.reader.max_pages

    def turns(self, start: float, end: float, tags: Collection[str]) -> Iterator[dict[str, Any]]:
        seen: set[str] = set()
        for tag in sorted({t for t in tags if isinstance(t, str) and TAG.fullmatch(t)}):
            for rec in self.reader.records(start, end, tag):
                for turn in turn_from_record(rec, {tag}):
                    if turn["turn_id"] not in seen and start - 1 < _ts_of(turn) < end + 1:
                        if len(seen) >= self.max_turns:
                            raise UsageError(
                                f"more than {self.max_turns} turns in one read: read a "
                                "narrower window"
                            )
                        seen.add(turn["turn_id"])
                        yield turn


#: the turn source factories this module declares (``hnx orchestration turns --turn-source``
#: calls only a declared one); ``secrets``: the options that hold a secret name
TURN_SOURCES = {
    "make": {
        "secrets": ["key"],
        "options": {
            "base_url": "str", "key": "secret", "ca_file": "str", "allow_plaintext": "bool",
            "timeout": "float", "max_pages": "int",
        },
    }
}  # fmt: skip


def make(
    *,
    base_url: str | None = None,
    key: str | None = None,
    ca_file: str | None = None,
    allow_plaintext: bool = False,
    env: Mapping[str, str] | None = None,
    **reader: Any,
) -> UsageTurnSource:
    """The turn source on the gateway at ``base_url`` (default: ``HNX_ENDPOINT_LLM_GATEWAY``)
    with the telemetry reader's key ``key`` (default :data:`DEFAULT_KEY`); raises
    :class:`UsageError` for an unsafe or missing setting, before any connection."""
    var = env_var_name(CAPABILITY)
    url = base_url or (os.environ if env is None else env).get(var, "")
    if not url:
        raise UsageError(f"the gateway URL: give base_url (--gateway-url) or set {var}")
    return UsageTurnSource(
        UsageReader(
            url,
            key or DEFAULT_KEY,
            env=env,
            ca_file=ca_file,
            allow_plaintext=allow_plaintext,
            **reader,
        )
    )


def parse_ts(v: Any) -> float | None:
    """A record's ``ts`` as epoch seconds, or None when it is not RFC 3339 with a zone."""
    m = _TS.fullmatch(v) if isinstance(v, str) else None
    if m is None:
        return None
    frac = (m.group(2) or "")[:6]
    try:
        dt = datetime.fromisoformat(
            m.group(1)
            + (f".{frac.ljust(6, '0')}" if frac else "")
            + m.group(3).replace("Z", "+00:00")
        )
    except ValueError:
        return None
    return dt.astimezone(UTC).timestamp()


def _ts_of(turn: Mapping[str, Any]) -> float:
    return (
        datetime.strptime(turn["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    )


#: the record fields that spend: an aggregated refusal (count > 1) holds none of them but null or 0
_SPEND = ("input_tokens", "output_tokens", "cache_read_tokens", "cost_usd")


def _spends_nothing(v: Any) -> bool:
    """A spend field of an aggregated refusal: null, or a number equal to 0.  A boolean is no
    number here (``False == 0`` in Python), so it never passes as nothing spent."""
    if v is None:
        return True
    return isinstance(v, int | float) and not isinstance(v, bool) and v == 0


def turn_from_record(rec: Mapping[str, Any], tags: Iterable[str]) -> list[dict[str, Any]]:
    """The neutral turn records of one usage record: ``count`` of them (module docstring), or
    none when the record carries none of ``tags`` or has no usable turn id, time or status."""
    wanted = set(tags)
    tag, rid, start = rec.get("gateway_tag"), rec.get("turn_id"), parse_ts(rec.get("ts"))
    status = rec.get("status")
    if not (isinstance(tag, str) and tag in wanted and TAG.fullmatch(tag)):
        return []
    if not (isinstance(rid, str) and TURN_ID.fullmatch(rid)) or start is None:
        return []
    if not (isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599):
        return []
    times = rec.get("count", 1)
    if not (isinstance(times, int) and not isinstance(times, bool) and 1 <= times <= MAX_COUNT):
        raise UsageError(f"usage record {rid}: count {times!r} is not 1..{MAX_COUNT}")
    ok = 200 <= status < 300
    if times > 1:  # only refusals are aggregated (R17), and a refusal spends nothing
        spent = [k for k in _SPEND if not _spends_nothing(rec.get(k))]
        if ok or spent:
            why = f"status {status}" if ok else ", ".join(spent)
            raise UsageError(
                f"usage record {rid}: count {times} on a record that is not a refusal ({why}): "
                "only refusals are aggregated, and they spend no tokens or cost"
            )
    cache = count(rec.get("cache_read_tokens"))
    hit = rec.get("cache_hit")
    cost = rec.get("cost_usd")
    turn = {
        "turn_id": rid,
        "gateway_tag": tag,
        "started_at": iso(start),
        "duration_ms": count(rec.get("duration_ms")),
        "ttft_ms": count(rec.get("ttft_ms")),
        "model_role": name("model_role", rec.get("model_role")),
        "model": name("model", rec.get("deployment")),
        "call_type": name("call_type", rec.get("call_type")),
        "status": "success" if ok else "failure",
        "error_code": None if ok else str(status),
        "input_tokens": count(rec.get("input_tokens")),
        "output_tokens": count(rec.get("output_tokens")),
        "cache_read_tokens": cache,
        "cache_hit": hit if isinstance(hit, bool) and cache is not None else None,
        "cost_usd": cost_or_none(cost),
    }
    out = [turn]
    for n in range(2, times + 1):
        twin = dict(turn, turn_id=f"{rid}.{n}")
        if not TURN_ID.fullmatch(twin["turn_id"]):
            raise UsageError(f"usage record {rid}: too long a turn id to count {times} turns")
        out.append(twin)
    return out
