# SPDX-License-Identifier: Apache-2.0
"""Checks for the events bus role (``events_bus``): its users' allow-lists, its durables and its
listen address.

    {{ subjects | hnx_bus_subject_problems(user) }}              {# [] or one message per refused subject #}
    {{ subjects | hnx_bus_subject_problems(user, admin=true) }}  {# the provisioner's: a few more calls #}
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
``$JS.ACK.<domain>.<account hash>.<stream>.<durable>.*.*.*.*.>``  ack form v2: 11 tokens or more
==============================================================  =======================================

and, for the provisioner (``admin=true``, role ``events_bus_admin_user``) only,
``$JS.API.STREAM.CREATE.<stream>``, ``$JS.API.CONSUMER.CREATE.<stream>.<durable>[.<filter>]``,
``$JS.API.CONSUMER.DURABLE.CREATE.<stream>.<durable>`` and
``$JS.API.CONSUMER.DELETE.<stream>.<durable>``.  Nothing else under ``$JS`` is reachable: no
``STREAM.UPDATE`` (it deletes messages by shrinking a stream's limits or subjects, deny flags or
not), ``.DELETE``, ``.PURGE``, ``.MSG.DELETE``, ``.SNAPSHOT``, ``.RESTORE``, ``.LIST``/``.NAMES``,
no consumer listing, no peer or leader calls, no advisories; no ``$KV.>`` or ``$O.>`` (the
key-value and object stores); no ``$SYS``.

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
``_INBOX.<user>.<...>``: no other client may SUBSCRIBE to a user's replies.  (Subject permissions
do not stop another client from publishing a forged reply to them: a request's reply subject is
not checked against anyone's allow-list, so a client matches each reply by its own unguessable
inbox token, as nats-py's ``new_inbox()`` does.)

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

_NAME = re.compile(r"[A-Za-z0-9_-]+\Z")
_HASH = re.compile(r"[A-Za-z0-9]{8}\Z")
#: one literal stream or consumer name
NAME = "<name>"
#: one or more further tokens, wildcards allowed
REST = "<rest>"
#: a v2 ack subject's domain token: "_", the server's when no JetStream domain is configured
DOMAIN = "_"
#: a v2 ack subject's account hash: 8 characters of [A-Za-z0-9] (server/events.go getHash)
HASH = "<hash>"

#: the JetStream calls any user may hold (token by token; NAME and REST as above)
_JS_FORMS: tuple[tuple[str, ...], ...] = (
    ("$JS", "API", "INFO"),
    ("$JS", "API", "STREAM", "INFO", NAME),
    ("$JS", "API", "CONSUMER", "INFO", NAME, NAME),
    ("$JS", "API", "CONSUMER", "MSG", "NEXT", NAME, NAME),
    # the ack reply subjects, exactly: v1 (9 tokens) and v2 (11 or more)
    ("$JS", "ACK", NAME, NAME, "*", "*", "*", "*", "*"),
    # v2 pins the domain to "_" and the account hash to its 8-character shape: a v2-shaped grant
    # whose tokens 2-3 were a stream and durable could never be told apart from one durable's
    ("$JS", "ACK", DOMAIN, HASH, NAME, NAME, "*", "*", "*", "*", ">"),
)
#: and the provisioner's (events_bus_admin_user) besides: no STREAM.UPDATE (it deletes messages
#: by shrinking limits or subjects), no consumer listing
_JS_ADMIN_FORMS: tuple[tuple[str, ...], ...] = (
    # reads ANY stored message of the stream, whatever subject or durable it belongs to
    ("$JS", "API", "STREAM", "MSG", "GET", NAME),
    ("$JS", "API", "STREAM", "CREATE", NAME),
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


def _is_form(toks: list[str], form: tuple[str, ...]) -> bool:
    if form and form[-1] == REST:
        head = form[:-1]
        if len(toks) <= len(head):
            return False
        toks = toks[: len(head)]
        form = head
    if len(toks) != len(form):
        return False
    return all(_token_is(t, f) for t, f in zip(toks, form, strict=True))


def _token_is(tok: str, form: str) -> bool:
    if form == NAME:
        return bool(_NAME.match(tok))
    if form == HASH:
        return bool(_HASH.match(tok))
    return tok == form


def _form_text(form: tuple[str, ...]) -> str:
    return ".".join({NAME: "<name>", REST: ">", HASH: "<account hash>"}.get(f, f) for f in form)


def hnx_bus_subject_problems(subjects, user, admin=False) -> list[str]:
    """One message per subject in ``subjects`` (one user's publish and subscribe allow-lists)
    that reaches beyond what that user may hold (``admin``: the provisioner, who may also create a
    named stream and create or delete a named durable); an empty list when all are within it."""
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
                out.append(
                    f"{s}: a server subject outside the JetStream calls a "
                    f"{'provisioner' if admin else 'user'} may hold, each on a named stream and "
                    f"consumer ({', '.join(_form_text(f) for f in forms)})"
                )
            continue
        if toks[0] == "_INBOX" and not (len(toks) >= 3 and toks[1] == str(user)):
            out.append(f"{s}: reaches another client's _INBOX (only _INBOX.{user}.> is its own)")
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
    """One message per subject a client (any user but the provisioner) may not SUBSCRIBE to:
    a client lives in an account of its own and reaches the bus only through the services that
    account imports (:func:`hnx_bus_accounts`), so the only subjects it can subscribe to are its
    own replies, ``_INBOX.<user>.>`` (a core subscription to a stream subject would need a stream
    import; a client reads the stream through its durable)."""
    if admin:
        return []
    out = []
    for subject in subjects or []:
        toks = _tokens(str(subject))
        if toks is None or toks[:2] != ["_INBOX", str(user)] or len(toks) < 3:
            out.append(
                f"{subject}: a client subscribes to its own replies only (_INBOX.{user}.>); it "
                "reads the stream through a durable, never a core subscription"
            )
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


def hnx_bus_accounts(users, admin_user, account, api_prefix) -> dict:
    """The ``accounts`` block of the server's configuration (role ``events_bus``): the bus
    account ``account`` holds the streams (JetStream on) and the provisioner alone; every other
    user lives in an account of its own (:func:`hnx_bus_client_account`, JetStream off) that
    imports, as SERVICES from the bus account, exactly the subjects its allow-list names, and
    nothing else is exported to it.

    Why (homelab-next #360, round 5): a reply subject is not checked against anyone's
    allow-list, and JetStream treats a message its own internal client publishes -- a pull's
    delivery, an ack's answer, an API response -- as a request when it lands on ``$JS.API.*``.
    In one account a user holding only its durable's ``MSG.NEXT`` could send it with reply
    ``$JS.API.STREAM.DELETE.<stream>`` and the server deleted the stream, deny flags or not.
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
    ``subscribe_only``)."""
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
    out = {
        str(account): {
            "jetstream": "enabled",
            "users": bus_users,
            "exports": [exports[k] for k in sorted(exports)],
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
            "hnx_bus_missing": hnx_bus_missing,
            "hnx_is_loopback": hnx_is_loopback,
            "hnx_nats_hostport": hnx_nats_hostport,
        }
