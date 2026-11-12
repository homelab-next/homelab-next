# SPDX-License-Identifier: Apache-2.0
"""Checks for the events bus role (``events_bus``): its users' allow-lists and its listen address.

    {{ subjects | hnx_bus_subject_problems(user) }}   {# [] or one message per refused subject #}
    {{ address | hnx_is_loopback }}                    {# true for the 127/8 block and ::1 only #}

A bus user's allow-list is an upper bound the server enforces, so a role must refuse a grant that
reaches further than one user's own work.  Comparing strings is not enough: ``$JS.API.*.>``,
``$JS.*.>`` and ``*.API.>`` all reach every JetStream API call without being ``$JS.API.>``.  So the
subjects are compared **token by token** (NATS semantics: ``*`` is one token, ``>`` one or more
and only last), and a subject is refused when it

* starts with ``*`` or ``>`` (it reaches every account subject, the system's included);
* could match a ``$SYS`` subject (``$SYS.>``: the server's own);
* could match an ``_INBOX`` subject other than this user's own ``_INBOX.<user>.>`` (another
  client's replies);
* covers the whole JetStream API, ``$JS.API.>``, or every stream call, ``$JS.API.STREAM.>``
  (``$JS.>``, ``$JS.API.*.>`` ...); a single call such as ``$JS.API.STREAM.INFO.<stream>`` stays
  allowed;
* could match a destructive stream call, ``$JS.API.STREAM.DELETE``, ``.PURGE``, ``.UPDATE`` or
  ``.MSG.DELETE`` on any stream (``$JS.API.STREAM.*.<stream>``, ``$JS.API.STREAM.MSG.*.<stream>``),
  so no user can drop the evidence the stream holds.

A subject that is not a well-formed NATS subject (an empty token, ``>`` before the last token) is
refused too: the server would reject or misread it."""

from __future__ import annotations

import ipaddress

#: subjects no allow-list may reach any part of (overlap is refused)
_NO_OVERLAP = (
    "$SYS.>",
    "$JS.API.STREAM.DELETE.>",
    "$JS.API.STREAM.PURGE.>",
    "$JS.API.STREAM.UPDATE.>",
    "$JS.API.STREAM.MSG.DELETE.>",
)
#: subject sets no allow-list may cover whole (a single call inside them stays allowed)
_NO_COVER = ("$JS.API.>", "$JS.API.STREAM.>")


def _tokens(subject: str) -> list[str] | None:
    toks = subject.split(".")
    if any(t == "" for t in toks) or ">" in toks[:-1]:
        return None
    if any(len(t) > 1 and ("*" in t or ">" in t) for t in toks):
        return None  # a wildcard is a whole token, never part of one
    return toks


def _overlap(a: list[str], b: list[str]) -> bool:
    """Whether some concrete subject matches both patterns."""
    if not a or not b:
        return not a and not b
    if a[0] == ">":
        return True  # one or more of b's remaining tokens (b is non-empty here)
    if b[0] == ">":
        return True
    if a[0] == "*" or b[0] == "*" or a[0] == b[0]:
        return _overlap(a[1:], b[1:])
    return False


def _covers(a: list[str], b: list[str]) -> bool:
    """Whether every subject matching ``b`` also matches ``a``."""
    if not a:
        return not b
    if a[0] == ">":
        return bool(b)
    if not b or b[0] == ">":
        return False  # b reaches further than a can follow
    if a[0] == "*" or a[0] == b[0]:
        return _covers(a[1:], b[1:])
    return False


def hnx_bus_subject_problems(subjects, user) -> list[str]:
    """One message per subject in ``subjects`` (one user's publish and subscribe allow-lists)
    that reaches beyond what any one user may hold; an empty list when all are within it."""
    out: list[str] = []
    for subject in subjects or []:
        s = str(subject)
        toks = _tokens(s)
        if toks is None:
            out.append(f"{s}: not a well-formed subject")
            continue
        if toks[0] in ("*", ">"):
            out.append(f"{s}: starts with a wildcard (every subject of the account)")
            continue
        hit = [r for r in _NO_OVERLAP if _overlap(toks, r.split("."))]
        if hit:
            out.append(f"{s}: reaches {hit[0]}")
            continue
        hit = [r for r in _NO_COVER if _covers(toks, r.split("."))]
        if hit:
            out.append(f"{s}: covers {hit[0]}")
            continue
        if _overlap(toks, ["_INBOX", ">"]) and not (
            len(toks) >= 3 and toks[0] == "_INBOX" and toks[1] == str(user)
        ):
            out.append(f"{s}: reaches another client's _INBOX (only _INBOX.{user}.> is its own)")
    return out


def hnx_is_loopback(address) -> bool:
    """True for a loopback address (the 127/8 block, ::1) written as an address, else False."""
    try:
        return ipaddress.ip_address(str(address)).is_loopback
    except ValueError:
        return False


class FilterModule:
    def filters(self):
        return {
            "hnx_bus_subject_problems": hnx_bus_subject_problems,
            "hnx_is_loopback": hnx_is_loopback,
        }
