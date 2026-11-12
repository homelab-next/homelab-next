# SPDX-License-Identifier: Apache-2.0
"""Checks for the events bus role (``events_bus``): its users' allow-lists, its durables and its
listen address.

    {{ subjects | hnx_bus_subject_problems(user, account=account, streams=streams) }}  {# [] or one message per refused subject #}
    {{ subjects | hnx_bus_subject_problems(user, admin=true, account=account) }}  {# the provisioner's #}
    {{ account | hnx_bus_account_hash }}                         {# nats-server's getHash: HNX -> hKkTAyOX #}
    {{ durables | hnx_bus_durable_problems(users, admin_user, streams, provision) }}
    {{ jsz | hnx_bus_push_consumers }}                           {# /jsz?consumers=true: [] or one per push consumer #}
    {{ address | hnx_is_loopback }}                              {# true for the 127/8 block and ::1 only #}

A bus user's allow-list is an upper bound the server enforces, so a role must refuse a grant that
reaches further than one user's own work.  The server's own subjects are refused by default and
allowed by name: a subject whose first token starts with ``$`` (``$JS``, ``$KV``, ``$O``, ``$SYS``
and any other the server may add) is refused unless it is one of the JetStream calls below, each
bound to a **named** stream and consumer (a literal token of ``[A-Za-z0-9_-]``, never a wildcard):

==============================================================  =======================================
``$JS.API.INFO``                                                 the account's JetStream limits
``$JS.API.STREAM.INFO.<stream>``                                 a stream's configuration and state
``$JS.API.STREAM.MSG.GET.<stream>``                              read one stored message (the DLQ
                                                                 read-back)
``$JS.API.CONSUMER.INFO.<stream>.<durable>``                     a consumer's state
``$JS.API.CONSUMER.MSG.NEXT.<stream>.<durable>``                 pull from that durable
``$JS.ACK.<stream>.<durable>.*.*.*.*.*``                         settle its deliveries, ack form v1:
                                                                 exactly 9 tokens
``$JS.ACK._.<account hash>.<stream>.<durable>.*.*.*.*.>``        ack form v2: 11 tokens or more; the
                                                                 hash is the bus account's, exactly
==============================================================  =======================================

(the provisioner holds neither ``CONSUMER.MSG.NEXT`` nor an ack: it lives in the account
JetStream runs in, where a delivery or an ack's answer sent to a reply of its choosing is taken as
a JetStream request -- the confused deputy the account split closes for every other user) and,
for the provisioner (``admin=true``, role ``events_bus_admin_user``) only,
``$JS.API.STREAM.CREATE.<stream>`` (of a declared stream or its ``_DLQ``),
``$JS.API.CONSUMER.CREATE.<stream>.<durable>[.<filter>]``,
``$JS.API.CONSUMER.DURABLE.CREATE.<stream>.<durable>`` and
``$JS.API.CONSUMER.DELETE.<stream>.<durable>``.  No other call SUBJECT under ``$JS`` is
reachable: no ``STREAM.UPDATE`` (it deletes messages by shrinking a stream's limits or subjects,
deny flags or not), ``.DELETE``, ``.PURGE``, ``.MSG.DELETE``, ``.SNAPSHOT``, ``.RESTORE``,
``.LIST``/``.NAMES``, no consumer listing, no peer or leader calls, no advisories; no ``$KV.>`` or
``$O.>`` (the key-value and object stores); no ``$SYS``.

**What a subject check cannot close: the provisioner's request bodies.**  A grant names the
subject of a call, never its body, and nats-server does not stop a stream's ``republish.dest``
(or a ``mirror``, ``sources``, a ``subject_transform``) pointing into ``$JS.API``: what the stream
then sends there is taken as a JetStream request.  Whoever holds the provisioner's credential can
create a declared stream that is missing (first deploy, a newly declared stream, or one that went
missing) with a republish to ``$JS.API.STREAM.DELETE.<other>`` and delete that stream, deny flags
or not (security F1 of homelab-next #361, reproduced on 2.15.1).  Three things narrow it, none
closes it: ``STREAM.CREATE`` names a declared stream only; the adapter's own create checks the
body it renders before sending (``provision_streams``: no republish, mirror, sources or subject
transform); and the health hook fails on any stream in the bus account that carries one
(:func:`hnx_bus_stream_redirects`).  The provisioner's credential is therefore the operator's:
the residual risk is that credential's compromise, detected after the fact, not prevented.

**Creating a consumer is the provisioner's alone.**  A consumer create takes any configuration,
a push ``deliver_subject`` included, and the server delivers a push consumer's messages as itself:
the creator's publish allow-list never applies to the deliver subject, so a user who may create a
durable can have the stream delivered to any subject (another user's ``_INBOX``) -- a publish-
anywhere grant.  The role's provisioner pre-creates every durable a user needs, a PULL durable (no
``deliver_subject``), declared in ``events_bus_durables``; users hold its ``INFO``, ``MSG.NEXT`` and
acks only (``hnx_bus_durable_problems``), and the health hook fails on any consumer the server
reports with a deliver subject (``hnx_bus_push_consumers``).

The ack forms are exact: the v1 reply subject is ``$JS.ACK.<stream>.<durable>.<delivered>
.<stream seq>.<consumer seq>.<time>.<pending>`` (9 tokens), v2 puts ``<domain>.<account hash>``
after ``ACK`` (11 or more: nats-server appends a random token).  A looser ``$JS.ACK.<a>.<b>.>``
would read as the v2 domain and hash ``<a>.<b>`` and reach the acks of EVERY stream and durable.

Any other subject must start with a literal token (a leading ``*`` or ``>`` reaches every
subject of the account, the server's own included).  ``_INBOX`` subjects are the user's own only,
``_INBOX.<user>.<...>``: no other client may SUBSCRIBE to a user's replies.  No other first token
may start with ``_`` (the server's ``_R_``, ``_GR_``, ``_SYS_`` reply and routing subjects), for
any user.  A client's every other grant sits under a declared stream's subject prefix
(``<prefix>.<...>``, ``streams``): a client publishes events and nothing else -- under ANY declared
stream's prefix its list names, not only "its own" subjects (two clients may hold overlapping
event subjects; each is limited by its own list alone).  The provisioner holds nothing outside
its JetStream calls and its own ``_INBOX`` (it publishes no event), and subscribes to its own
``_INBOX`` alone (:func:`hnx_bus_subscribe_problems`).  (Subject permissions do not stop another
client from publishing a forged reply to a user's inbox: an arbitrary reply subject, such as
``$JS.API.STREAM.DELETE.<stream>``, is not checked against the sender's allow-list -- nats-server
2.15.1 refuses only the reserved ones, ``_R_``, ``_GR_`` and ``$JS.ACK``, from a client
connection -- so a client matches each reply by its own unguessable inbox token, as nats-py's
``new_inbox()`` does.)

A subject that is not a well-formed NATS subject (an empty token, ``>`` before the last token, a
wildcard inside a token) is refused too: the server would reject or misread it.

The subject check is an allow-list of shapes, not names: it cannot know which durable is whose.
``hnx_bus_durable_problems`` does: every ``<stream>.<durable>`` a user's consumer or ack grant
names must be a durable declared for that user, and no two users may name the same one
(``tests/roles/test_hnx_bus_filter.py`` proves the shapes against every pattern up to a length,
with a NATS matcher)."""

from __future__ import annotations

import ipaddress
import re
import string

_NAME = re.compile(r"[A-Za-z0-9_-]+\Z")
#: one literal stream or consumer name
NAME = "<name>"
#: one or more further tokens, wildcards allowed
REST = "<rest>"
#: a v2 ack subject's domain token: "_", the server's when no JetStream domain is configured
DOMAIN = "_"
#: a v2 ack subject's account hash: the bus account's (:func:`hnx_bus_account_hash`)
HASH = "<hash>"
#: nats-server's getHash alphabet (server/accounts.go ``digits``, ``base`` 62)
_DIGITS = string.digits + string.ascii_uppercase + string.ascii_lowercase


def hnx_bus_account_hash(account) -> str:
    """The account hash nats-server puts in a v2 ack subject (``$JS.ACK.<domain>.<hash>...``):
    ``getHash(accName)`` of server/events.go (2.15.1), the sha256 of the account name whose first
    8 bytes are each taken mod 62 into ``0-9A-Za-z``.  ``HNX`` -> ``hKkTAyOX``."""
    import hashlib

    digest = hashlib.sha256(str(account).encode("utf-8")).digest()
    return "".join(_DIGITS[b % 62] for b in digest[:8])


#: the JetStream calls any user may hold (token by token; NAME and REST as above)
_JS_FORMS: tuple[tuple[str, ...], ...] = (
    ("$JS", "API", "INFO"),
    ("$JS", "API", "STREAM", "INFO", NAME),
    ("$JS", "API", "CONSUMER", "INFO", NAME, NAME),
)
#: a client's reads of its own durable (never the provisioner's: see the module docstring)
_JS_READ_FORMS: tuple[tuple[str, ...], ...] = (
    ("$JS", "API", "CONSUMER", "MSG", "NEXT", NAME, NAME),
    # the ack reply subjects, exactly: v1 (9 tokens) and v2 (11 or more)
    ("$JS", "ACK", NAME, NAME, "*", "*", "*", "*", "*"),
    # v2 pins the domain to "_" and the account hash to the bus account's own: a v2-shaped grant
    # whose tokens 2-3 were a stream and durable could never be told apart from one durable's
    ("$JS", "ACK", DOMAIN, HASH, NAME, NAME, "*", "*", "*", "*", ">"),
)
#: and the provisioner's (events_bus_admin_user) besides: no STREAM.UPDATE (it deletes messages
#: by shrinking limits or subjects), no consumer listing
#: the provisioner's stream create: of a declared stream or its DLQ only (its body is unchecked
#: by the server: see the module docstring)
_CREATE_STREAM = ("$JS", "API", "STREAM", "CREATE", NAME)
_JS_ADMIN_FORMS: tuple[tuple[str, ...], ...] = (
    # reads ANY stored message of the stream, whatever subject or durable it belongs to
    ("$JS", "API", "STREAM", "MSG", "GET", NAME),
    _CREATE_STREAM,
    ("$JS", "API", "CONSUMER", "CREATE", NAME, NAME),
    ("$JS", "API", "CONSUMER", "CREATE", NAME, NAME, REST),
    ("$JS", "API", "CONSUMER", "DURABLE", "CREATE", NAME, NAME),
    ("$JS", "API", "CONSUMER", "DELETE", NAME, NAME),
)
#: where a consumer or ack grant names its stream and durable: (form prefix, stream index)
_DURABLE_AT: tuple[tuple[tuple[str, ...], int], ...] = (
    (("$JS", "API", "CONSUMER", "INFO"), 4),
    (("$JS", "API", "CONSUMER", "MSG", "NEXT"), 5),
    (("$JS", "API", "CONSUMER", "CREATE"), 4),
    (("$JS", "API", "CONSUMER", "DURABLE", "CREATE"), 5),
    (("$JS", "API", "CONSUMER", "DELETE"), 4),
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


def _is_form(toks: list[str], form: tuple[str, ...], account_hash: str = "") -> bool:
    if form and form[-1] == REST:
        head = form[:-1]
        if len(toks) <= len(head):
            return False
        toks = toks[: len(head)]
        form = head
    if len(toks) != len(form):
        return False
    return all(_token_is(t, f, account_hash) for t, f in zip(toks, form, strict=True))


def _token_is(tok: str, form: str, account_hash: str = "") -> bool:
    if form == NAME:
        return bool(_NAME.match(tok))
    if form == HASH:
        return bool(account_hash) and tok == account_hash
    return tok == form


def _form_text(form: tuple[str, ...]) -> str:
    return ".".join(
        {NAME: "<name>", REST: ">", HASH: "<the account's hash>"}.get(f, f) for f in form
    )


def _stream_prefixes(streams) -> set[str]:
    out = set()
    for st in streams or []:
        prefix = st.get("subject_prefix") if isinstance(st, dict) else st
        if prefix:
            out.add(str(prefix))
    return out


def _stream_names(streams) -> set[str]:
    """The declared streams' names and their DLQs' (``<name>_DLQ``): what the provisioner may
    create."""
    out = set()
    for st in streams or []:
        name = st.get("name") if isinstance(st, dict) else None
        if name:
            out |= {str(name), f"{name}_DLQ"}
    return out


def hnx_bus_subject_problems(subjects, user, admin=False, account=None, streams=None) -> list[str]:
    """One message per subject in ``subjects`` (one user's publish and subscribe allow-lists)
    that reaches beyond what that user may hold (``admin``: the provisioner, who may also create a
    named stream and create or delete a named durable, and may not pull or ack); an empty list
    when all are within it.

    ``account``: the bus account (``events_bus_account``), whose hash a v2 ack grant must carry
    (:func:`hnx_bus_account_hash`; without it no v2 ack grant passes).  ``streams``: the declared
    streams (``events_bus_streams``, or their subject prefixes): a client's grant that is neither
    a JetStream call nor its own ``_INBOX`` must sit under one of them."""
    out: list[str] = []
    account_hash = hnx_bus_account_hash(account) if account else ""
    prefixes = _stream_prefixes(streams)
    names = _stream_names(streams)
    forms = _JS_FORMS + _JS_ADMIN_FORMS if admin else _JS_FORMS + _JS_READ_FORMS
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
            if admin and _is_form(toks, _CREATE_STREAM) and toks[4] not in names:
                out.append(
                    f"{s}: creates {toks[4]}, which is not a declared stream or its DLQ "
                    f"({', '.join(sorted(names)) or 'no events_bus_streams'}): the provisioner "
                    "creates the declared streams alone"
                )
                continue
            if any(_is_form(toks, f, account_hash) for f in forms):
                continue
            if admin and any(_is_form(toks, f, account_hash) for f in _JS_READ_FORMS):
                out.append(
                    f"{s}: not the provisioner's: it lives in the account JetStream runs in, where "
                    "a pull's delivery or an ack's answer sent to a reply subject of its choosing "
                    "($JS.API.STREAM.DELETE.<stream>) is taken as that request; a reader is a "
                    "client user with a durable of its own (events_bus_durables)"
                )
                continue
            if not admin and _is_form(toks, _JS_ADMIN_FORMS[0]):
                out.append(
                    f"{s}: the provisioner's call alone (it reads any stored message of the "
                    "stream, every subject and every durable's)"
                )
                continue
            if not admin and any(_is_form(toks, f) for f in _JS_ADMIN_FORMS):
                out.append(
                    f"{s}: the provisioner's call alone (a consumer create can push the "
                    "stream to any subject): declare the durable in events_bus_durables, "
                    "the provisioner creates it"
                )
                continue
            if toks[:2] == ["$JS", "ACK"] and len(toks) >= 11 and toks[2] == DOMAIN:
                want = account_hash or "(no events_bus_account given)"
                out.append(
                    f"{s}: a v2 ack names the bus account's hash, {want} "
                    f"(nats-server's getHash of {account or '?'}), and nothing else"
                )
                continue
            out.append(
                f"{s}: a server subject outside the JetStream calls a "
                f"{'provisioner' if admin else 'user'} may hold, each on a named stream and "
                f"consumer ({', '.join(_form_text(f) for f in forms)})"
            )
            continue
        if toks[0] == "_INBOX":
            if not (len(toks) >= 3 and toks[1] == str(user)):
                out.append(
                    f"{s}: reaches another client's _INBOX (only _INBOX.{user}.> is its own)"
                )
            continue
        if toks[0].startswith("_"):
            out.append(
                f"{s}: a server subject (_R_, _GR_, _SYS_ ...: replies and routing); a "
                f"{'provisioner' if admin else 'client'}'s only _ subject is its own "
                f"_INBOX.{user}.>"
            )
            continue
        if admin:
            out.append(
                f"{s}: not the provisioner's: it holds its JetStream calls and its own "
                f"_INBOX.{user}.> and nothing else (it lives in the bus account, where a stream "
                "subject it publishes is stored as an event and a republish or a delivery it "
                "aims there is taken as one)"
            )
            continue
        if len(toks) < 2 or toks[0] not in prefixes:
            out.append(
                f"{s}: not under a declared stream's subjects "
                f"({', '.join(sorted(p + '.>' for p in prefixes)) or 'no events_bus_streams'}): "
                "a client publishes events and nothing else"
            )
    return out


def _durable_of(subject: str) -> tuple[str, str] | None:
    """``(stream, durable)`` a consumer call or an ack grant names, else None."""
    toks = _tokens(str(subject))
    if toks is None:
        return None
    for head, at in _DURABLE_AT:
        if tuple(toks[: len(head)]) == head and len(toks) > at + 1:
            return toks[at], toks[at + 1]
    if toks[:2] == ["$JS", "ACK"]:
        if len(toks) == 9:
            return toks[2], toks[3]
        if len(toks) >= 11:
            return toks[4], toks[5]
    return None


#: the keys a declared durable may carry; anything else (deliver_subject above all) is refused
_DURABLE_KEYS = frozenset(
    {"stream", "durable", "user", "filter", "ack_policy", "max_deliver", "ack_wait",
     "deliver_policy", "replay_s", "start_seq"}
)  # fmt: skip


def hnx_bus_durable_create_subjects(durable) -> list[str]:
    """The two calls the provisioner makes for one declared durable: its ``CONSUMER.INFO`` and
    its create, in the filtered form when the filter is literal (the server then refuses any
    other filter for the request)."""
    s, d, f = durable["stream"], durable["durable"], str(durable["filter"])
    create = f"$JS.API.CONSUMER.CREATE.{s}.{d}"
    if "*" not in f.split(".") and ">" not in f.split("."):
        create += f".{f}"
    return [f"$JS.API.CONSUMER.INFO.{s}.{d}", create]


def hnx_bus_durable_problems(durables, users, admin_user="", streams=(), provision=False):
    """One message per problem with the declared durables (``events_bus_durables``) and the
    users' consumer and ack grants (``events_bus_users``); [] when there is none.

    * a durable is ``{stream, durable, user, filter}`` plus optional ``ack_policy`` (``explicit``
      only: the adapter's nack and term need it), ``max_deliver``, ``ack_wait`` (seconds), and
      where it starts: ``deliver_policy`` (``new`` or ``all``), ``replay_s`` (that many seconds
      back) or ``start_seq`` (that stream sequence);
      nothing else, a ``deliver_subject`` least of all (a pull durable has none);
    * each ``<stream>.<durable>`` is declared once, for one user that is not the provisioner;
      its filter is a well-formed subject, under the stream's prefix when the role provisions
      the stream;
    * every ``<stream>.<durable>`` a user's ``CONSUMER.*`` or ``$JS.ACK`` grant names is a durable
      declared for that user, and no two users name the same one (the provisioner's own grants,
      which create the durables, are not counted);
    * with ``provision``, the provisioner holds the calls it makes for each
      (:func:`hnx_bus_durable_create_subjects`)."""
    out: list[str] = []
    users = list(users or [])
    by_name = {str(u.get("user")): u for u in users if isinstance(u, dict)}
    prefixes = {
        str(s.get("name")): str(s.get("subject_prefix"))
        for s in (streams or [])
        if isinstance(s, dict)
    }
    declared: dict[tuple[str, str], str] = {}
    for i, d in enumerate(durables or []):
        where = f"durable {i}"
        if not isinstance(d, dict):
            out.append(f"{where}: not a mapping")
            continue
        where = f"durable {d.get('stream', '?')}.{d.get('durable', '?')}"
        extra = sorted(set(d) - _DURABLE_KEYS)
        if extra:
            why = (
                " (a pull durable: never a push deliver_subject)"
                if any(k.startswith("deliver_") and k != "deliver_policy" for k in extra)
                else ""
            )
            out.append(f"{where}: unknown keys {extra}{why}")
        missing = [k for k in ("stream", "durable", "user", "filter") if k not in d]
        if missing:
            out.append(f"{where}: missing {missing}")
            continue
        s, n, owner, f = (str(d[k]) for k in ("stream", "durable", "user", "filter"))
        if not _NAME.match(s) or not _NAME.match(n):
            out.append(f"{where}: stream and durable are names of [A-Za-z0-9_-]")
        ftoks = _tokens(f)
        if ftoks is None or f.startswith("$") or ftoks[0] in ("*", ">"):
            out.append(f"{where}: filter {f!r} is not a well-formed subject under a literal prefix")
        elif s in prefixes and ftoks[0] != prefixes[s]:
            out.append(f"{where}: filter {f} is outside the stream's subjects ({prefixes[s]}.>)")
        if d.get("ack_policy", "explicit") != "explicit":
            out.append(f"{where}: ack_policy must be explicit (nack and term need it)")
        md, aw = d.get("max_deliver", 5), d.get("ack_wait", 30)
        if isinstance(md, bool) or not isinstance(md, int) or md < 1:
            out.append(f"{where}: max_deliver must be a positive integer")
        if isinstance(aw, bool) or not isinstance(aw, (int, float)) or aw <= 0:
            out.append(f"{where}: ack_wait must be a positive number of seconds")
        policy, replay = d.get("deliver_policy", "new"), d.get("replay_s")
        if policy not in ("new", "all"):
            out.append(f"{where}: deliver_policy must be new or all")
        if replay is not None and (
            isinstance(replay, bool)
            or not isinstance(replay, (int, float))
            or replay <= 0
            or "deliver_policy" in d
        ):
            out.append(f"{where}: replay_s is a positive number of seconds, without deliver_policy")
        seq = d.get("start_seq")
        if seq is not None and (
            isinstance(seq, bool)
            or not isinstance(seq, int)
            or seq < 1
            or "deliver_policy" in d
            or replay is not None
        ):
            out.append(
                f"{where}: start_seq is a positive stream sequence, without deliver_policy or "
                "replay_s"
            )
        if (s, n) in declared:
            out.append(f"{where}: declared twice")
        declared[(s, n)] = owner
        if owner == str(admin_user) or owner not in by_name:
            out.append(
                f"{where}: user {owner} must be one of events_bus_users, not the provisioner"
            )
    holders: dict[tuple[str, str], set[str]] = {}
    for name, u in by_name.items():
        if name == str(admin_user):
            continue
        for subject in list(u.get("publish") or []) + list(u.get("subscribe") or []):
            key = _durable_of(subject)
            if key is None:
                continue
            holders.setdefault(key, set()).add(name)
            if declared.get(key) != name:
                out.append(
                    f"user {name}: {subject} names {key[0]}.{key[1]}, which is not a durable "
                    f"declared for {name} in events_bus_durables"
                )
    for key, names in sorted(holders.items()):
        if len(names) > 1:
            out.append(f"durable {key[0]}.{key[1]}: granted to {sorted(names)}; one user each")
    if provision and declared:
        admin = by_name.get(str(admin_user), {})
        held = set(admin.get("publish") or [])
        for d in durables or []:
            if not isinstance(d, dict) or not all(k in d for k in ("stream", "durable", "filter")):
                continue
            lacking = [x for x in hnx_bus_durable_create_subjects(d) if x not in held]
            if lacking:
                out.append(
                    f"durable {d['stream']}.{d['durable']}: the provisioner "
                    f"{admin_user or '(none)'} needs {lacking} in its publish list"
                )
    return out


def hnx_bus_subscribe_problems(subjects, user, admin=False) -> list[str]:
    """One message per subject a user may not SUBSCRIBE to: every user subscribes to its own
    replies alone, ``_INBOX.<user>.>``.  A client lives in an account of its own and reaches the
    bus only through the services that account imports (:func:`hnx_bus_accounts`; a core
    subscription to a stream subject would need a stream import, and a client reads the stream
    through its durable).  The provisioner (``admin``) lives in the bus account itself, where a
    subscription to ``$JS.API.*`` would receive the clients' JetStream requests (and could answer
    them) and one to ``_R_.>`` every service-import reply: it needs its replies and nothing
    else."""
    out = []
    for subject in subjects or []:
        toks = _tokens(str(subject))
        if toks is None or toks[:2] != ["_INBOX", str(user)] or len(toks) < 3:
            why = (
                "the provisioner subscribes to its own replies only "
                f"(_INBOX.{user}.>): in the bus account any other subscription receives the "
                "clients' requests or their replies"
                if admin
                else f"a client subscribes to its own replies only (_INBOX.{user}.>); it "
                "reads the stream through a durable, never a core subscription"
            )
            out.append(f"{subject}: {why}")
    return out


def hnx_bus_client_account(account, user) -> str:
    """The account a client user lives in: ``<bus account>-<user>``, one per user, so a reply
    subject the server answers to can only reach what that one user's account imports."""
    return f"{account}-{user}"


def _permissions(u) -> dict:
    publish = list(u.get("publish") or [])
    subscribe = list(u.get("subscribe") or []) or [f"_INBOX.{u['user']}.>"]
    return {
        # never {"allow": []}: NATS reads an empty allow-list as no restriction
        "publish": {"allow": publish}
        if publish and not u.get("subscribe_only")
        else {"deny": [">"]},
        "subscribe": {"allow": subscribe},
    }


#: what the optional monitor user (events_bus_monitor_user) sees: the advisories a deletion or a
#: stream change leaves, imported as STREAMS from the bus account into an account of its own
MONITOR_SUBJECTS = (
    "$JS.EVENT.ADVISORY.STREAM.DELETED.>",
    "$JS.EVENT.ADVISORY.CONSUMER.DELETED.>",
    "$JS.EVENT.ADVISORY.STREAM.UPDATED.>",
)


def hnx_bus_accounts(users, admin_user, account, api_prefix, monitor=None) -> dict:
    """The ``accounts`` block of the server's configuration (role ``events_bus``): the bus
    account ``account`` holds the streams (JetStream on) and the provisioner alone; every other
    user lives in an account of its own (:func:`hnx_bus_client_account`, JetStream off) that
    imports, as SERVICES from the bus account, exactly the subjects its allow-list names, and
    nothing else is exported to it.

    Why (homelab-next #360, round 5): an arbitrary reply subject is not checked against the
    sender's allow-list (nats-server 2.15.1 refuses only the reserved ``_R_``, ``_GR_`` and
    ``$JS.ACK`` replies from a client), and JetStream treats a message its own internal client
    publishes -- a pull's delivery (a ``404`` status included) or an ack's answer -- as a request
    when it lands on ``$JS.API.*``.  In one account a user holding only its durable's
    ``MSG.NEXT`` could send it with reply ``$JS.API.STREAM.DELETE.<stream>`` and the server
    deleted the stream, deny flags or not.  (An API response aimed there did not reproduce on
    2.15.1: ``STREAM.INFO`` answered to ``STREAM.DELETE`` left the stream in place.  The split
    does not depend on it.)
    Across a service import the server rewrites the reply to a private ``_R_.`` subject and
    routes the answer back into the CLIENT's account, where no JetStream API listens: the
    answer can reach nothing but that client's own imports.

    * ``$JS.API.<call>`` is imported under ``<api_prefix>.<call>`` (``JS.HNX.API``): in an
      account without JetStream the server answers ``$JS.API.*`` itself ("JetStream not enabled
      for account"), so a client names its calls under the prefix (the adapter's
      ``api_prefix``), and its allow-list is rewritten to match;
    * ``$JS.ACK.<...>`` is imported as it is (a delivery's reply subject is the ack subject);
    * a stream subject (``<prefix>.homelabnext.decision.>``) is imported as a service, so a
      publish reaches the stream and its PubAck comes back across the import;
    * ``CONSUMER.MSG.NEXT`` is exported with ``response_type: stream`` (a batch is several
      messages answering one request);
    * ``_INBOX.<user>`` subjects stay in the client's own account.

    ``users``: the rendered users (``user``, ``password_hash``, ``publish``, ``subscribe``,
    ``subscribe_only``).  ``monitor`` (optional, ``{user, password_hash}``): a user in an account
    of its own that imports exactly :data:`MONITOR_SUBJECTS` from the bus account as STREAMS and
    may subscribe to those alone, publish nothing: it watches for a stream or durable deleted
    or a stream changed (what an ACL bypass would leave) without holding any call."""
    prefix = str(api_prefix).rstrip(".")
    exports: dict[str, dict] = {}
    bus_users, clients = [], {}
    for u in users or []:
        name = str(u["user"])
        entry = {"user": name, "password": u["password_hash"]}
        if name == str(admin_user):
            bus_users.append({**entry, "permissions": _permissions(u)})
            continue
        acc = hnx_bus_client_account(account, name)
        imports, allow = [], []
        for subject in [] if u.get("subscribe_only") else list(u.get("publish") or []):
            subject = str(subject)
            if subject.startswith("_INBOX."):
                allow.append(subject)
                continue
            imp: dict = {"service": {"account": str(account), "subject": subject}}
            if subject.startswith("$JS.API."):
                imp["to"] = f"{prefix}.{subject[len('$JS.API.') :]}"
            imports.append(imp)
            allow.append(imp.get("to", subject))
            ex = exports.setdefault(subject, {"service": subject, "accounts": []})
            if acc not in ex["accounts"]:
                ex["accounts"].append(acc)
            if subject.startswith("$JS.API.CONSUMER.MSG.NEXT."):
                ex["response_type"] = "stream"
        perms = _permissions({**u, "publish": allow})
        clients[acc] = {"users": [{**entry, "permissions": perms}], "imports": imports}
    streams_out = []
    if monitor:
        name = str(monitor["user"])
        acc = hnx_bus_client_account(account, name)
        clients[acc] = {
            "users": [{"user": name, "password": monitor["password_hash"], "permissions": {
                "publish": {"deny": [">"]}, "subscribe": {"allow": list(MONITOR_SUBJECTS)}}}],
            "imports": [{"stream": {"account": str(account), "subject": s}}
                        for s in MONITOR_SUBJECTS],
        }  # fmt: skip
        streams_out = [{"stream": s, "accounts": [acc]} for s in MONITOR_SUBJECTS]
    out = {
        str(account): {
            "jetstream": "enabled",
            "users": bus_users,
            "exports": [exports[k] for k in sorted(exports)] + streams_out,
        }
    }
    out.update(clients)
    return out


def hnx_bus_push_consumers(jsz) -> list[str]:
    """``<account>/<stream>/<consumer> -> <deliver subject>`` for every push consumer in a
    ``/jsz?consumers=true&config=true`` document (the monitor's view of every account): none
    may exist, since the provisioner creates pull durables only and no user may create one."""
    out: list[str] = []
    doc = jsz if isinstance(jsz, dict) else {}
    for account in doc.get("account_details") or []:
        for stream in (account or {}).get("stream_detail") or []:
            for c in (stream or {}).get("consumer_detail") or []:
                deliver = ((c or {}).get("config") or {}).get("deliver_subject")
                if deliver:
                    out.append(
                        f"{account.get('name')}/{stream.get('name')}/{c.get('name')} -> {deliver}"
                    )
    return out


def hnx_bus_missing(jsz, account, streams=(), durables=()) -> dict:
    """What is declared but not on the bus, from a ``/jsz?accounts=true&streams=true&consumers=
    true`` document: ``{"streams": [...], "durables": [...]}`` -- each standing stream and its
    ``_DLQ`` (``events_bus_streams``) missing from ``account``, and each ``<stream>/<durable>`` of
    ``events_bus_durables`` its stream does not hold.  A stream that was there and is gone is
    what a successful ``STREAM.DELETE`` leaves (the health hook fails on it: the detection
    backstop for an attack the ACL should have made impossible); a declared durable that was
    never created is ``events_bus_provision_durables`` still off (reported, not failed)."""
    doc = jsz if isinstance(jsz, dict) else {}
    have: dict[str, set[str]] = {}
    for acc in doc.get("account_details") or []:
        if (acc or {}).get("name") != str(account):
            continue
        for st in acc.get("stream_detail") or []:
            names = {str((c or {}).get("name")) for c in (st or {}).get("consumer_detail") or []}
            have[str(st.get("name"))] = names
    want = [
        x for s in streams or [] if isinstance(s, dict) for x in (s["name"], f"{s['name']}_DLQ")
    ]
    return {
        "streams": [n for n in want if n not in have],
        "durables": [
            f"{d['stream']}/{d['durable']}"
            for d in durables or []
            if isinstance(d, dict)
            and str(d.get("durable")) not in have.get(str(d.get("stream")), set())
        ],
    }


def hnx_bus_expected_accounts(users, admin_user, account, monitor_user="") -> dict:
    """``{account name: [its users]}`` the role's configuration gives the server: the bus account
    with ``admin_user`` alone, one ``<account>-<user>`` per other user (and the monitor's)."""
    names = [str(u.get("user") if isinstance(u, dict) else u) for u in users or []]
    out = {str(account): [n for n in names if n == str(admin_user)]}
    for n in names + ([str(monitor_user)] if monitor_user else []):
        if n != str(admin_user):
            out[hnx_bus_client_account(account, n)] = [n]
    return out


def hnx_bus_expected_imports(users, admin_user, account, api_prefix, monitor_user="") -> dict:
    """``{account name: sorted [(from account, subject, local subject)]}``: the imports
    :func:`hnx_bus_accounts` renders for ``users`` (``events_bus_users``: their publish lists),
    the way ``/accountz?acc=<name>`` reports them (``account``, ``subject``, ``local_subject``)."""
    rendered = [
        {**u, "password_hash": ""} for u in users or [] if isinstance(u, dict) and "user" in u
    ]
    monitor = {"user": monitor_user, "password_hash": ""} if monitor_user else None
    out: dict[str, list] = {}
    for name, acc in hnx_bus_accounts(rendered, admin_user, account, api_prefix, monitor).items():
        rows = []
        for imp in acc.get("imports") or []:
            src = imp.get("service") or imp.get("stream") or {}
            subject = str(src.get("subject"))
            rows.append((str(src.get("account")), subject, str(imp.get("to", subject))))
        out[name] = sorted(rows)
    return out


def hnx_bus_account_problems(accountz, details, users, admin_user, account, monitor_user="",
                             connz=None, api_prefix=None) -> list[str]:  # fmt: skip
    """What the running server says about its accounts that is not the role's account split
    (read-only, from the loopback monitor): ``accountz`` is ``/accountz``, ``details`` each
    ``/accountz?acc=<name>`` of the expected accounts, ``connz`` ``/connz?auth=true``,
    ``api_prefix`` the client accounts' JetStream prefix (default ``JS.<account>.API``).

    * the server's accounts are exactly the expected ones (:func:`hnx_bus_expected_accounts`)
      besides its own ``$G`` and ``$SYS``;
    * JetStream is on in the bus account alone; the bus account imports nothing, and every
      other account imports from the bus account exactly the subjects the role renders for its
      user (:func:`hnx_bus_expected_imports`; the server's own ``$SYS`` imports aside): a
      hand-added ``$JS.API.>`` import is named, not only one from another account;
    * every connected user is in its own account: ``admin_user`` in the bus account, any other in
      ``<account>-<user>`` (``/accountz`` does not list an account's users; ``/connz`` shows
      the account each connection authenticated into).  A connection without a user has not
      finished its CONNECT yet (the server lists it from the moment it accepts it; it is closed
      unless it authenticates within the auth timeout) and is skipped: it can do nothing.
      ``/connz`` returns at most its ``limit`` connections: when its ``total`` is more than it
      returned, the check cannot see every connection and says so (a problem: it fails)."""
    out: list[str] = []
    prefix = api_prefix or f"JS.{account}.API"
    imports = hnx_bus_expected_imports(users, admin_user, account, prefix, monitor_user)
    want = hnx_bus_expected_accounts(users, admin_user, account, monitor_user)
    have = set((accountz or {}).get("accounts") or [])
    for name in sorted(set(want) - have):
        out.append(f"account {name}: expected, not on the server")
    for name in sorted(have - set(want) - {"$G", "$SYS"}):
        out.append(f"account {name}: on the server, not in the role's configuration")
    for doc in details or []:
        d = (doc or {}).get("account_detail") or {}
        name = str(d.get("account_name", "?"))
        js = bool(d.get("jetstream_enabled"))
        if js != (name == str(account)):
            out.append(
                f"account {name}: JetStream {'on' if js else 'off'}; it is on in {account} alone"
            )
        froms = sorted({str(i.get("account")) for i in d.get("imports") or []} - {"$SYS"})
        allowed = [] if name == str(account) else [str(account)]
        if [f for f in froms if f not in allowed]:
            out.append(f"account {name}: imports from {froms}; allowed {allowed or 'none'}")
            continue
        if name not in imports:
            continue
        got = sorted(
            (str(i.get("account")), str(i.get("subject")),
             str(i.get("local_subject") or i.get("to") or i.get("subject")))
            for i in d.get("imports") or [] if i.get("account") != "$SYS"
        )  # fmt: skip
        extra = [r for r in got if r not in imports[name]]
        lacking = [r for r in imports[name] if r not in got]
        if extra:
            out.append(
                f"account {name}: imports "
                f"{', '.join(_import_text(r) for r in extra)}, which the role does not render"
            )
        if lacking:
            out.append(
                f"account {name}: lacks the imports {', '.join(_import_text(r) for r in lacking)}"
            )
    doc = connz if isinstance(connz, dict) else {}
    conns = doc.get("connections") or []
    total = doc.get("total")
    if isinstance(total, int) and total > int(doc.get("offset") or 0) + len(conns):
        out.append(
            f"/connz lists {total} connections and returned {len(conns)} (its limit): the "
            "check cannot see every connection; raise the limit in the health hook"
        )
    expected_of = {u: acc for acc, us in want.items() for u in us}
    for c in conns:
        user = c.get("authorized_user")
        if not user:
            continue  # its CONNECT not processed yet: no account, no subject, closed if it never is
        got = c.get("account") or "$G"
        if expected_of.get(user) != got:
            out.append(
                f"user {user}: connected in account {got}, expected "
                f"{expected_of.get(user, '(not a user of the role)')}"
            )
    return out


def _import_text(row) -> str:
    acc, subject, local = row
    return f"{subject} from {acc}" + (f" as {local}" if local != subject else "")


#: a stream configuration that moves messages somewhere else: a republish, a mirror, sources, a
#: subject transform (the adapter never sets one).  Any of them can aim at ``$JS.API.*``, where
#: what the stream sends is taken as a JetStream request (republish to ``STREAM.DELETE.<s>``
#: deletes that stream: security F1 of #361, reproduced on 2.15.1)
STREAM_REDIRECTS = ("republish", "mirror", "sources", "subject_transform")


def hnx_bus_stream_redirects(jsz, account, declared=()) -> list[str]:
    """The streams of ``account`` (``/jsz?accounts=true&streams=true&config=true``) whose
    configuration carries one of :data:`STREAM_REDIRECTS`: ``<stream>: <key> <what>`` for each.
    ``declared``: the ``<stream>.<key>`` pairs the inventory declares (none today: the role's
    streams take no such key), which are not reported.  The provisioner's ``STREAM.CREATE``
    names the stream, and the server does not limit the body: whoever holds the provisioner's
    credential can create a declared stream that is missing with a republish into
    ``$JS.API``.  The health hook fails on any."""
    out: list[str] = []
    allowed = {str(x) for x in declared or ()}
    for name, cfg in _stream_configs(jsz, account):
        for key in STREAM_REDIRECTS:
            value = cfg.get(key)
            if value and f"{name}.{key}" not in allowed:
                out.append(f"{name}: {key} {_redirect_text(value)}")
    return out


def _stream_configs(jsz, account):
    """``(name, config)`` of every stream of ``account`` in a ``/jsz?...&config=true`` document."""
    for acc in (jsz if isinstance(jsz, dict) else {}).get("account_details") or []:
        if (acc or {}).get("name") != str(account):
            continue
        for st in acc.get("stream_detail") or []:
            yield str((st or {}).get("name")), (st or {}).get("config") or {}


def _redirect_text(value) -> str:
    """Where a redirect points, briefly (its destination, source or name)."""
    items = value if isinstance(value, list) else [value]
    parts = []
    for v in items:
        if isinstance(v, dict):
            what = v.get("dest") or v.get("name") or v.get("src") or "?"
            src = v.get("src")
            parts.append(f"{src} -> {what}" if src and what != src else str(what))
        else:
            parts.append(str(v))
    return ", ".join(parts)


def hnx_bus_unprotected_streams(jsz, account) -> list[str]:
    """The streams of ``account`` (``/jsz?accounts=true&streams=true&config=true``) without
    ``deny_delete`` or ``deny_purge``: a stream created before the adapter set them.  Reported,
    never changed (a flag can only be set by a STREAM.UPDATE, which no user holds)."""
    out: list[str] = []
    for name, cfg in _stream_configs(jsz, account):
        lacking = [f for f in ("deny_delete", "deny_purge") if not cfg.get(f)]
        if lacking:
            out.append(f"{name} (no {' or '.join(lacking)})")
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
            "hnx_bus_durable_problems": hnx_bus_durable_problems,
            "hnx_bus_durable_create_subjects": hnx_bus_durable_create_subjects,
            "hnx_bus_push_consumers": hnx_bus_push_consumers,
            "hnx_bus_subscribe_problems": hnx_bus_subscribe_problems,
            "hnx_bus_client_account": hnx_bus_client_account,
            "hnx_bus_accounts": hnx_bus_accounts,
            "hnx_bus_account_hash": hnx_bus_account_hash,
            "hnx_bus_expected_accounts": hnx_bus_expected_accounts,
            "hnx_bus_account_problems": hnx_bus_account_problems,
            "hnx_bus_unprotected_streams": hnx_bus_unprotected_streams,
            "hnx_bus_stream_redirects": hnx_bus_stream_redirects,
            "hnx_bus_expected_imports": hnx_bus_expected_imports,
            "hnx_bus_missing": hnx_bus_missing,
            "hnx_is_loopback": hnx_is_loopback,
            "hnx_nats_hostport": hnx_nats_hostport,
        }
