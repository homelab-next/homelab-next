# SPDX-License-Identifier: Apache-2.0
"""What the turn-source adapters (``inference`` feature ``turn-records``) share: plain numbers
for their settings, the turn record's value rules (counts, names, cost), and one bounded,
credentialed JSON read of a gateway's log API that names the failure, never a value."""

from __future__ import annotations

import json
import math
import numbers
import urllib.error
import urllib.request
from typing import Any

from conformance.protocols.inference import is_name
from homelabnext._http import ResponseTooLarge, read_bounded

__all__ = ["cost", "count", "fetch_json", "name", "plain_float", "plain_int"]


def plain_float(value: object) -> float | None:
    """``value`` as a plain ``float``, or None for a bool or a non-real.  The range is checked on
    the converted value, so a subclass that overrides its comparisons cannot pass a check and
    reach the socket as something else."""
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return out if type(out) is float else None


def plain_int(value: object) -> int | None:
    """``value`` as a plain ``int``, or None for a bool or a non-integral (see :func:`plain_float`)."""
    if isinstance(value, bool) or not isinstance(value, numbers.Integral):
        return None
    try:
        out = int(value)
    except (TypeError, ValueError):
        return None
    return out if type(out) is int else None


def count(v: Any) -> int | None:
    """A turn record count: a non-negative int, else None (not reported)."""
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def name(key: str, v: Any) -> str | None:
    """``v`` when the turn record's ``key`` takes it (the one rule,
    :func:`~conformance.protocols.inference.is_name`), else null: a gateway's odd name costs
    that one field, never the turn."""
    return v if is_name(key, v) else None


def cost(v: Any) -> float | None:
    """A turn record cost: a finite non-negative number as a float, else None."""
    if isinstance(v, int | float) and not isinstance(v, bool) and math.isfinite(v) and v >= 0:
        return float(v)
    return None


def fetch_json(
    opener: urllib.request.OpenerDirector,
    req: urllib.request.Request,
    *,
    timeout: float,
    max_bytes: int,
    error: type[Exception],
    log: str,
    page: str,
    refused: str,
) -> Any:
    """``req`` answered as JSON, else ``error`` naming the failure: ``refused`` for a 401 or 403,
    ``<log> answered HTTP <n>`` for another status, ``<page> is over <max_bytes> bytes``, the
    gateway unreachable, or ``<log> did not answer JSON``."""
    try:
        with opener.open(req, timeout=timeout) as resp:
            status, body = int(resp.status), read_bounded(resp, max_bytes)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code in (401, 403):
            raise error(f"the gateway refused the key ({exc.code}): {refused}") from None
        raise error(f"{log} answered HTTP {exc.code}") from None
    except ResponseTooLarge:
        raise error(f"{page} is over {max_bytes} bytes") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise error(f"the gateway is unreachable ({type(reason).__name__})") from None
    if not 200 <= status < 300:
        raise error(f"{log} answered HTTP {status}")
    try:
        return json.loads(body)
    except ValueError:
        raise error(f"{log} did not answer JSON") from None
