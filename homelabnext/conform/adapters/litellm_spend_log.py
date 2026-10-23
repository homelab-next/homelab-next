# SPDX-License-Identifier: Apache-2.0
"""A turn source (``inference`` feature ``turn-records``) on LiteLLM's spend log.

``make(**config)`` returns a :class:`SpendLogTurnSource`, a
:class:`conformance.protocols.inference.TurnSource`: ``turns(start, end, tags)`` reads LiteLLM's
paginated spend-log API (``GET /spend/logs/v2``) and maps each row to the neutral turn record
(:data:`conformance.protocols.inference.TURN_FIELDS`).  Orchestration telemetry selects it with
``hnx orchestration turns --turn-source homelabnext.conform.adapters.litellm_spend_log:make``
(``docs/orchestration-telemetry.md``); nothing outside this module knows LiteLLM's paths, row
fields or key roles.

**Read path: the API with a read-only viewer key, named by secret** (default: the secret store's
``llm-gateway/key-telemetry-reader``, :data:`DEFAULT_KEY`, delivered in
``HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER``).  Not the master key, which this reader refuses
by the variable it is delivered in (however the reference is spelled), and not a Postgres role on
``LiteLLM_SpendLogs``:

* the API is LiteLLM's supported interface; the table is the internals of its ORM, migrated by
  every release (and the gateway is pinned to a fast-moving patch line, ``docs/llm-gateway.md``);
* the list endpoint leaves out the heavy columns (``messages``, ``response``,
  ``proxy_server_request``), while a ``SELECT`` grant on the table hands over prompts and answers
  whenever prompt storage is on, plus key hashes and client addresses -- and a grant on a schema
  that the gateway's own role owns and migrates has to be redone after every migration;
* the key is a LiteLLM virtual key whose user has the ``proxy_admin_viewer`` role (sees all spend,
  cannot create keys or change anything) and ``allowed_routes: ["/spend/logs/v2"]``; it is
  rotated and revoked like every other key, and it needs no network path to the database.

**The allow-list** (:func:`turn_from_row`): the request id, the tag that matched, times, the model
group (LiteLLM's word for the role asked for, stored as ``model_role``) and model, call type
(LiteLLM's own values, ``acompletion`` and so on: opaque to the consumer), status and error code,
token counts, cache-read tokens and the cost.  Everything else in a row -- ``api_base``, ``user``,
``end_user``, ``requester_ip_address``, ``api_key``, the rest of ``metadata`` -- is never read
out, and a name that is not name-shaped is dropped, not kept.

Transport rules as the st2 bridge's webhook: https with verification (``ca_file`` for a private
CA), plain http only to loopback or with ``allow_plaintext``; no redirect is followed and no proxy
is used, so the key never reaches another origin; the reply is read bounded.
"""

from __future__ import annotations

import json
import math
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from typing import Any

from conformance.protocols.inference import ERROR_CODE, TURN_ID, TurnSourceError, is_name
from homelabnext._http import ResponseTooLarge, check_plaintext, credential_opener, read_bounded
from homelabnext.registry import env_var_name
from homelabnext.registry.model import secret_env_name
from homelabnext.status.model import iso, parse_iso

__all__ = [
    "DEFAULT_KEY",
    "MAX_PAGES",
    "PAGE_SIZE",
    "SPEND_LOGS_PATH",
    "TURN_SOURCES",
    "SpendLogError",
    "SpendLogReader",
    "SpendLogTurnSource",
    "make",
    "turn_from_row",
]

SPEND_LOGS_PATH = "/spend/logs/v2"
DEFAULT_KEY = "secret:llm-gateway/key-telemetry-reader"
#: the generated gateway config's master key (docs/llm-gateway.md): never a reader's credential
MASTER_KEY = "secret:llm-gateway/master-key"
#: the endpoint the gateway is resolved by when no ``base_url`` is given
CAPABILITY = "llm-gateway"
MAX_PAGE_BYTES = 8 << 20
#: PAGE_SIZE * MAX_PAGES rows (100k) per read window: an hour of that is ~28 requests a second,
#: far more than the gateway of a lab serves
PAGE_SIZE = 500
MAX_PAGES = 200
_SECRET_REF = re.compile(r"secret:[a-z0-9][a-z0-9/_.-]{0,127}")


class SpendLogError(TurnSourceError):
    """The spend log could not be read (configuration, transport, refusal, shape)."""


class SpendLogReader:
    """Reads ``/spend/logs/v2`` pages of one gateway (see the module docstring)."""

    def __init__(
        self,
        base_url: str,
        key: str = DEFAULT_KEY,
        *,
        env: Mapping[str, str] | None = None,
        ca_file: str | os.PathLike[str] | None = None,
        timeout: float = 15.0,
        allow_plaintext: bool = False,
        page_size: int = PAGE_SIZE,
        max_pages: int = MAX_PAGES,
    ) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise SpendLogError("the gateway URL must be an absolute https URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise SpendLogError("the gateway URL carries no credentials, query or fragment")
        if not (isinstance(key, str) and _SECRET_REF.fullmatch(key)):
            raise SpendLogError("the gateway key is a secret name (secret:<name>), never a value")
        # by the variable the secret is delivered in, not the spelling: master_key, master.key
        # and llm_gateway/master-key all read HNX_SECRET_LLM_GATEWAY_MASTER_KEY
        if secret_env_name(key) == secret_env_name(MASTER_KEY):
            raise SpendLogError(
                f"{MASTER_KEY} is the gateway's master key: give the reader a viewer key "
                "(docs/orchestration-telemetry.md)"
            )
        try:
            check_plaintext(base_url, credentials=True, allow_plaintext=allow_plaintext)
        except ValueError as exc:
            raise SpendLogError(str(exc)) from None
        if not 1 <= page_size <= 1000 or max_pages < 1:
            raise SpendLogError("page_size is 1..1000 and max_pages positive")
        self.url = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}{SPEND_LOGS_PATH}"
        self.key_ref, self._env, self.timeout = key, env, timeout
        self.page_size, self.max_pages = page_size, max_pages
        self._opener = credential_opener(str(ca_file) if ca_file else None)

    def __repr__(self) -> str:
        return f"SpendLogReader({self.url!r}, key={self.key_ref!r})"

    def _key(self) -> str:
        var = secret_env_name(self.key_ref)
        value = (os.environ if self._env is None else self._env).get(var, "")
        if not value:
            raise SpendLogError(f"the gateway key is not set: {var} ({self.key_ref})")
        return value

    def page(self, start: float, end: float, page: int) -> dict[str, Any]:
        """One page of spend-log rows started in ``[start, end]`` (UTC, whole seconds)."""
        q = urllib.parse.urlencode(
            {
                "start_date": _date(start),
                "end_date": _date(end),
                "page": page,
                "page_size": self.page_size,
                "sort_by": "startTime",
                "sort_order": "asc",
                "exclude_internal_health_checks": "true",
            }
        )
        req = urllib.request.Request(f"{self.url}?{q}", method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", f"Bearer {self._key()}")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status, body = int(resp.status), read_bounded(resp, MAX_PAGE_BYTES)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code in (401, 403):
                raise SpendLogError(
                    f"the gateway refused the key ({exc.code}): it needs the proxy_admin_viewer "
                    f"role and the route {SPEND_LOGS_PATH}"
                ) from None
            raise SpendLogError(f"the spend log answered HTTP {exc.code}") from None
        except ResponseTooLarge:
            raise SpendLogError(f"a spend-log page is over {MAX_PAGE_BYTES} bytes") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise SpendLogError(f"the gateway is unreachable ({type(reason).__name__})") from None
        if not 200 <= status < 300:
            raise SpendLogError(f"the spend log answered HTTP {status}")
        try:
            doc = json.loads(body)
        except ValueError:
            raise SpendLogError("the spend log did not answer JSON") from None
        if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
            raise SpendLogError("the spend log's answer has no data list")
        return doc

    def rows(self, start: float, end: float) -> Iterator[Mapping[str, Any]]:
        """Every spend-log row started in ``[start, end]``, page by page."""
        for n in range(1, self.max_pages + 1):
            doc = self.page(start, end, n)
            yield from (r for r in doc["data"] if isinstance(r, Mapping))
            total = doc.get("total_pages")
            if not doc["data"] or not isinstance(total, int) or n >= total:
                return
        raise SpendLogError(
            f"more than {self.max_pages} pages of {self.page_size} rows in one window"
        )


class SpendLogTurnSource:
    """The :class:`~conformance.protocols.inference.TurnSource` on one gateway's spend log."""

    def __init__(self, reader: SpendLogReader) -> None:
        self.reader = reader

    def __repr__(self) -> str:
        return f"SpendLogTurnSource({self.reader!r})"

    def turns(self, start: float, end: float, tags: Collection[str]) -> Iterator[dict[str, Any]]:
        wanted = set(tags)
        for row in self.reader.rows(start, end):
            turn = turn_from_row(row, wanted)
            if turn is not None:
                yield turn


#: the turn source factories this module declares (``hnx orchestration turns --turn-source``
#: calls only a declared one); ``secrets``: the options that hold a secret name
TURN_SOURCES = {"make": {"secrets": ["key"]}}


def make(
    *,
    base_url: str | None = None,
    key: str | None = None,
    ca_file: str | None = None,
    allow_plaintext: bool = False,
    env: Mapping[str, str] | None = None,
    **reader: Any,
) -> SpendLogTurnSource:
    """The turn source on the gateway at ``base_url`` (default: ``HNX_ENDPOINT_LLM_GATEWAY``)
    with the viewer key ``key`` (default :data:`DEFAULT_KEY`); raises :class:`SpendLogError` for
    an unsafe or missing setting, before any connection."""
    var = env_var_name(CAPABILITY)
    url = base_url or (os.environ if env is None else env).get(var, "")
    if not url:
        raise SpendLogError(f"the gateway URL: give base_url (--gateway-url) or set {var}")
    return SpendLogTurnSource(
        SpendLogReader(
            url,
            key or DEFAULT_KEY,
            env=env,
            ca_file=ca_file,
            allow_plaintext=allow_plaintext,
            **reader,
        )
    )


def _date(ts: float) -> str:
    return datetime.fromtimestamp(int(ts), UTC).strftime("%Y-%m-%d %H:%M:%S")


def _time(v: Any) -> float | None:
    if not isinstance(v, str) or not v:
        return None
    try:
        return parse_iso(v)
    except ValueError:
        return None


def _count(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _name(key: str, v: Any) -> str | None:
    """``v`` when the turn record's ``key`` takes it (the one rule,
    :func:`~conformance.protocols.inference.is_name`), else null: a gateway's odd name costs
    that one field, never the turn."""
    return v if is_name(key, v) else None


def _cache_read(meta: Mapping[str, Any]) -> int | None:
    usage = meta.get("usage_object")
    if not isinstance(usage, Mapping):
        return None
    got = _count(usage.get("cache_read_input_tokens"))
    if got is None and isinstance(usage.get("prompt_tokens_details"), Mapping):
        got = _count(usage["prompt_tokens_details"].get("cached_tokens"))
    return got


def turn_from_row(row: Mapping[str, Any], tags: Iterable[str]) -> dict[str, Any] | None:
    """The neutral turn record of one spend-log row, or None when the row carries none of
    ``tags`` (or no usable request id or start time)."""
    wanted = set(tags)
    row_tags = row.get("request_tags")
    if isinstance(row_tags, str):  # some versions return the JSON column as text
        try:
            row_tags = json.loads(row_tags)
        except ValueError:
            row_tags = None
    if not isinstance(row_tags, list | tuple):
        row_tags = ()
    hit = sorted(t for t in row_tags if isinstance(t, str) and t in wanted)
    rid, start = row.get("request_id"), _time(row.get("startTime"))
    if not hit or not isinstance(rid, str) or not TURN_ID.fullmatch(rid) or start is None:
        return None
    meta = row.get("metadata") if isinstance(row.get("metadata"), Mapping) else {}
    first = _time(row.get("completionStartTime"))
    err = meta.get("error_information") if isinstance(meta, Mapping) else None
    code = str(err.get("error_code", "")) if isinstance(err, Mapping) else ""
    cost = row.get("spend")
    hit_cache = str(row.get("cache_hit")).lower()  # "True", true, "False", "", None
    return {
        "turn_id": rid,
        "gateway_tag": hit[0],
        "started_at": iso(start),
        "duration_ms": _count(row.get("request_duration_ms")),
        "ttft_ms": round((first - start) * 1000) if first is not None and first >= start else None,
        "model_role": _name("model_role", row.get("model_group")),  # LiteLLM's word for it
        "model": _name("model", row.get("model")),
        "call_type": _name("call_type", row.get("call_type")),
        "status": row.get("status") if row.get("status") in ("success", "failure") else None,
        "error_code": code if ERROR_CODE.fullmatch(code) else None,
        "input_tokens": _count(row.get("prompt_tokens")),
        "output_tokens": _count(row.get("completion_tokens")),
        "cache_read_tokens": _cache_read(meta),
        "cache_hit": {"true": True, "false": False}.get(hit_cache),
        "cost_usd": float(cost)
        if isinstance(cost, int | float)
        and not isinstance(cost, bool)
        and math.isfinite(cost)
        and cost >= 0
        else None,
    }
