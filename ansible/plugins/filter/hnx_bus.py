# SPDX-License-Identifier: Apache-2.0
"""Checks for the events bus role (``events_bus``): its users' allow-lists and its listen address.

    {{ subjects | hnx_bus_subject_problems(user) }}              {# [] or one message per refused subject #}
    {{ subjects | hnx_bus_subject_problems(user, admin=true) }}  {# the provisioner's: a few more calls #}
    {{ address | hnx_is_loopback }}                              {# true for the 127/8 block and ::1 only #}

A bus user's allow-list is an upper bound the server enforces, so a role must refuse a grant that
reaches further than one user's own work.  The server's own subjects are refused by default and
allowed by name: a subject whose first token starts with ``$`` (``$JS``, ``$KV``, ``$O``, ``$SYS``
and any other the server may add) is refused unless it is one of the JetStream calls below, each
bound to a **named** stream and consumer (a literal token of ``[A-Za-z0-9_-]``, never a wildcard):

========================================================  ============================================
``$JS.API.INFO``                                           the account's JetStream limits
``$JS.API.STREAM.INFO.<stream>``                           a stream's configuration and state
``$JS.API.STREAM.MSG.GET.<stream>``                        read one stored message (the DLQ read-back)
``$JS.API.CONSUMER.INFO.<stream>.<durable>``               a consumer's state
``$JS.API.CONSUMER.CREATE.<stream>.<durable>[.<filter>]``  create that durable (the filter in the
                                                           subject pins its filter subject)
``$JS.API.CONSUMER.DURABLE.CREATE.<stream>.<durable>``     the older form of the same
``$JS.API.CONSUMER.MSG.NEXT.<stream>.<durable>``           pull from that durable
``$JS.ACK.<stream>.<durable>.<...>``                       settle its deliveries (v1; the v2 form,
                                                           ``$JS.ACK.<domain>.<account hash>.<stream>
                                                           .<durable>.<...>``, has the same shape)
========================================================  ============================================

and, for the provisioner (``admin=true``, role ``events_bus_admin_user``) only,
``$JS.API.STREAM.CREATE.<stream>``, ``$JS.API.STREAM.UPDATE.<stream>``,
``$JS.API.CONSUMER.DELETE.<stream>.<durable>`` and ``$JS.API.CONSUMER.NAMES.<stream>``.  Nothing
else under ``$JS`` is reachable: no ``STREAM.DELETE``, ``.PURGE``, ``.MSG.DELETE``, ``.SNAPSHOT``,
``.RESTORE``, ``.LIST``/``.NAMES``, no peer or leader calls, no advisories; no ``$KV.>`` or
``$O.>`` (the key-value and object stores); no ``$SYS``.  (A ``<filter>`` or an ack's ``<...>`` may
hold wildcards: they range over that one consumer's filter subjects or deliveries.)

Any other subject must start with a literal token (a leading ``*`` or ``>`` reaches every
subject of the account, the server's own included).  ``_INBOX`` subjects are the user's own only,
``_INBOX.<user>.<...>``: another client's replies are not this user's to read or forge.

A subject that is not a well-formed NATS subject (an empty token, ``>`` before the last token, a
wildcard inside a token) is refused too: the server would reject or misread it.

The list is an allow-list of shapes, not names: it cannot know which durable is whose, so a grant
of ``CONSUMER.MSG.NEXT.<stream>.<another user's durable>`` passes here.  Which names a user gets
stays the inventory's choice; what the check guarantees is that no user's grant reaches a call
outside these shapes (``tests/roles/test_hnx_bus_filter.py`` proves it against every pattern up
to a length, with a NATS matcher)."""

from __future__ import annotations

import ipaddress
import re

_NAME = re.compile(r"[A-Za-z0-9_-]+\Z")
#: one literal stream or consumer name
NAME = "<name>"
#: one or more further tokens, wildcards allowed
REST = "<rest>"

#: the JetStream calls any user may hold (token by token; NAME and REST as above)
_JS_FORMS: tuple[tuple[str, ...], ...] = (
    ("$JS", "API", "INFO"),
    ("$JS", "API", "STREAM", "INFO", NAME),
    ("$JS", "API", "STREAM", "MSG", "GET", NAME),
    ("$JS", "API", "CONSUMER", "INFO", NAME, NAME),
    ("$JS", "API", "CONSUMER", "CREATE", NAME, NAME),
    ("$JS", "API", "CONSUMER", "CREATE", NAME, NAME, REST),
    ("$JS", "API", "CONSUMER", "DURABLE", "CREATE", NAME, NAME),
    ("$JS", "API", "CONSUMER", "MSG", "NEXT", NAME, NAME),
    ("$JS", "ACK", NAME, NAME, REST),
)
#: and the provisioner's (events_bus_admin_user) besides
_JS_ADMIN_FORMS: tuple[tuple[str, ...], ...] = (
    ("$JS", "API", "STREAM", "CREATE", NAME),
    ("$JS", "API", "STREAM", "UPDATE", NAME),
    ("$JS", "API", "CONSUMER", "DELETE", NAME, NAME),
    ("$JS", "API", "CONSUMER", "NAMES", NAME),
)


def _tokens(subject: str) -> list[str] | None:
    toks = subject.split(".")
    if any(t == "" for t in toks) or ">" in toks[:-1]:
        return None
    if any(len(t) > 1 and ("*" in t or ">" in t) for t in toks):
        return None  # a wildcard is a whole token, never part of one
    if any(any(c.isspace() for c in t) for t in toks):
        return None
    return toks


def _is_form(toks: list[str], form: tuple[str, ...]) -> bool:
    if form and form[-1] == REST:
        head = form[:-1]
        if len(toks) <= len(head):
            return False
        toks = toks[: len(head)]
        form = head
    if len(toks) != len(form):
        return False
    return all(
        bool(_NAME.match(t)) if f == NAME else t == f for t, f in zip(toks, form, strict=True)
    )


def _form_text(form: tuple[str, ...]) -> str:
    return ".".join({NAME: "<name>", REST: ">"}.get(f, f) for f in form)


def hnx_bus_subject_problems(subjects, user, admin=False) -> list[str]:
    """One message per subject in ``subjects`` (one user's publish and subscribe allow-lists)
    that reaches beyond what that user may hold (``admin``: the stream provisioner, who may also
    create and update a named stream and delete or list its consumers); an empty list when all
    are within it."""
    out: list[str] = []
    forms = _JS_FORMS + (_JS_ADMIN_FORMS if admin else ())
    for subject in subjects or []:
        s = str(subject)
        toks = _tokens(s)
        if toks is None:
            out.append(f"{s}: not a well-formed subject")
            continue
        if toks[0] in ("*", ">"):
            out.append(f"{s}: starts with a wildcard (every subject of the account)")
            continue
        if toks[0].startswith("$"):
            if not any(_is_form(toks, f) for f in forms):
                out.append(
                    f"{s}: a server subject outside the JetStream calls a "
                    f"{'provisioner' if admin else 'user'} may hold, each on a named stream and "
                    f"consumer ({', '.join(_form_text(f) for f in forms)})"
                )
            continue
        if toks[0] == "_INBOX" and not (len(toks) >= 3 and toks[1] == str(user)):
            out.append(f"{s}: reaches another client's _INBOX (only _INBOX.{user}.> is its own)")
    return out


def hnx_is_loopback(address) -> bool:
    """True for a loopback address (the 127/8 block, ::1) written as an address, else False."""
    try:
        return ipaddress.ip_address(str(address)).is_loopback
    except ValueError:
        return False


def hnx_nats_hostport(address, port) -> str:
    """``address:port`` as NATS and a URL take it: an IPv6 address in brackets (``[::1]:4222``)."""
    a = str(address)
    return f"[{a}]:{int(port)}" if ":" in a else f"{a}:{int(port)}"


class FilterModule:
    def filters(self):
        return {
            "hnx_bus_subject_problems": hnx_bus_subject_problems,
            "hnx_is_loopback": hnx_is_loopback,
            "hnx_nats_hostport": hnx_nats_hostport,
        }
