# SPDX-License-Identifier: Apache-2.0
"""The events bus role's subject ceiling and loopback check (``ansible/plugins/filter/hnx_bus.py``),
called directly; ``test_control_plane_roles.py`` runs them through the role's validate hook.

The ceiling is an allow-list of shapes under the server's own ``$`` subjects, so besides the
examples the oracle tests below prove it: every pattern a NATS matcher (the wire fake's
``subject_matches``, not the filter's own code) says reaches a refused call is refused by the
filter, over every pattern that can reach one."""

import importlib.util
import itertools
from pathlib import Path

import pytest

from conformance.fakes.jetstream_wire import subject_matches

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "ansible/plugins/filter/hnx_bus.py"
_spec = importlib.util.spec_from_file_location("hnx_bus", PLUGIN)
bus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bus)
USER = "hnx-broker"


@pytest.mark.parametrize(
    "subject",
    [
        ">", "*", "*.homelabnext.>", "*.*",
        "$SYS.>", "$SYS.ACCOUNT.*.CONNECT", "$SYS.REQ.SERVER.PING",
        "_INBOX.>", "_INBOX.*", "_INBOX.*.>", "_INBOX.other-user.>", "_INBOX.hnx-broker",
        "$JS.>", "$JS.API.>", "$JS.API.*.>", "$JS.API.STREAM.>", "$JS.*.STREAM.>",
        "$JS.API.STREAM.DELETE.LAB", "$JS.API.STREAM.PURGE.LAB", "$JS.API.STREAM.UPDATE.LAB",
        "$JS.API.STREAM.MSG.DELETE.LAB", "$JS.API.STREAM.*.LAB", "$JS.API.STREAM.MSG.*.LAB",
        "$JS.API.STREAM.PURGE.*", "$JS.API.*.PURGE.LAB", "$JS.*.STREAM.DELETE.LAB",
        # the allow-list: no consumer delete, no stream create, snapshot or restore for a user,
        # no wildcard over a stream or durable name, nothing of the KV or object stores
        "$JS.API.CONSUMER.DELETE.LAB.bridge-x", "$JS.API.STREAM.CREATE.LAB",
        "$JS.API.STREAM.SNAPSHOT.LAB", "$JS.API.STREAM.RESTORE.LAB", "$JS.API.STREAM.LIST",
        "$JS.API.STREAM.NAMES", "$JS.API.STREAM.INFO.*", "$JS.API.CONSUMER.INFO.LAB.*",
        "$JS.API.CONSUMER.MSG.NEXT.*.bridge-x", "$JS.API.CONSUMER.CREATE.LAB.>",
        "$JS.API.CONSUMER.CREATE.LAB", "$JS.ACK.LAB.>", "$JS.ACK.*.bridge-x.>",
        # creating a consumer is the provisioner's: a create can push the stream to any subject
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x",
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned",
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x.>", "$JS.API.CONSUMER.DURABLE.CREATE.LAB.bridge-x",
        "$JS.API.CONSUMER.NAMES.LAB",
        # the ack forms are exact: v1 9 tokens, v2 11 or more; `.>` after two names would read
        # them as the v2 domain and hash and reach every stream's and durable's acks
        "$JS.ACK.LAB.bridge-x.>", "$JS.ACK.LAB.bridge-x.*.*.*.*", "$JS.ACK.LAB.bridge-x.*.*.*.*.*.*",
        "$JS.ACK.LAB.bridge-x.1.*.*.*.*", "$JS.ACK.LAB.bridge-x.*.*.*.*.>",
        "$JS.ACK._.ACCOUNTHASH.LAB.bridge-x.*.*.*.*", "$JS.ACK._.ACCOUNTHASH.LAB.bridge-x.>",
        "$JS.ACK._.ACCOUNTHASH.LAB.bridge-x.*.*.*.*.*", "$JS.ACK._.ACCOUNTHASH.*.bridge-x.*.*.*.*.>",
        # v2 acks name the domain "_" and an 8-character account hash, nothing else (round 5):
        # tokens 2-3 may not be another stream and durable, another domain or a short hash
        "$JS.ACK.LAB.other.LAB.bridge-x.*.*.*.*.>", "$JS.ACK.dom.hKkTAyOX.LAB.bridge-x.*.*.*.*.>",
        "$JS.ACK._.hKkTAy.LAB.bridge-x.*.*.*.*.>", "$JS.ACK.*.hKkTAyOX.LAB.bridge-x.*.*.*.*.>",
        "$JS.ACK._.*.LAB.bridge-x.*.*.*.*.>",
        # reads every stored message: the provisioner's alone (round 5)
        "$JS.API.STREAM.MSG.GET.LAB",
        "$JS.API.STREAM.LEADER.STEPDOWN.LAB", "$JS.API.STREAM.PEER.REMOVE.LAB",
        "$JS.API.ACCOUNT.PURGE.HNX", "$JS.EVENT.ADVISORY.>", "$JS.API.DIRECT.GET.LAB",
        "$KV.>", "$KV.bucket.key", "$O.>", "$O.store.C.x", "$JSC.>", "$NRG.>", "$G",
        "a..b", "a.>.b", "a.b*", "", "a b",
    ],
)  # fmt: skip
def test_refused(subject):
    assert bus.hnx_bus_subject_problems([subject], USER), subject


@pytest.mark.parametrize(
    "subject",
    [
        "lab.homelabnext.decision.>", "lab.*.decision.returned",
        "_INBOX.hnx-broker.>", "_INBOX.hnx-broker.reply.1",
        "$JS.API.INFO",
        "$JS.API.STREAM.INFO.LAB", "$JS.API.STREAM.INFO.LAB_DLQ",
        "$JS.API.CONSUMER.INFO.LAB.bridge-x",
        "$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x", "$JS.ACK.LAB.bridge-x.*.*.*.*.*",
        "$JS.ACK._.hKkTAyOX.LAB.bridge-x.*.*.*.*.>",
    ],
)  # fmt: skip
def test_allowed(subject):
    assert bus.hnx_bus_subject_problems([subject], USER) == []


ADMIN_ONLY = ("$JS.API.STREAM.CREATE.LAB", "$JS.API.STREAM.MSG.GET.LAB",
              "$JS.API.CONSUMER.CREATE.LAB.bridge-x",
              "$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned",
              "$JS.API.CONSUMER.DURABLE.CREATE.LAB.bridge-x",
              "$JS.API.CONSUMER.DELETE.LAB.e2e-scratch")  # fmt: skip


@pytest.mark.parametrize("subject", ADMIN_ONLY)
def test_the_provisioner_alone_creates_streams_and_creates_and_deletes_consumers(subject):
    got = bus.hnx_bus_subject_problems([subject], USER)
    assert got and "the provisioner's call alone" in got[0], got
    assert bus.hnx_bus_subject_problems([subject], "hnx-events-admin", admin=True) == []


@pytest.mark.parametrize(
    "subject",
    ["$JS.API.STREAM.DELETE.LAB", "$JS.API.STREAM.PURGE.LAB", "$JS.API.STREAM.MSG.DELETE.LAB",
     "$JS.API.STREAM.CREATE.*", "$JS.API.CONSUMER.DELETE.LAB.*", "$JS.API.STREAM.RESTORE.LAB",
     # UPDATE deletes messages by shrinking limits or subjects, deny flags or not
     "$JS.API.STREAM.UPDATE.LAB", "$JS.API.STREAM.UPDATE.LAB_DLQ", "$JS.API.CONSUMER.NAMES.LAB",
     "$JS.API.CONSUMER.CREATE.*.bridge-x", "$JS.API.CONSUMER.CREATE.LAB.*",
     "$KV.>", "$JS.API.>"],
)  # fmt: skip
def test_the_provisioner_still_cannot_destroy(subject):
    assert bus.hnx_bus_subject_problems([subject], "hnx-events-admin", admin=True)


def test_every_problem_is_named():
    got = bus.hnx_bus_subject_problems(["$JS.API.>", "lab.ok", "_INBOX.>"], USER)
    assert len(got) == 2 and got[0].startswith("$JS.API.>") and got[1].startswith("_INBOX.>")


# ---------------------------------------------------------------- the oracle
#: every call no user may reach (S, D: a stream and a durable the patterns may name; Q: one they
#: cannot, reachable only by a wildcard); the provisioner may reach the ADMIN ones
REFUSED = [
    "$SYS.Q", "$SYS.REQ.SERVER.PING", "$KV.S.Q", "$KV.Q.Q", "$O.S.Q", "$JSC.Q", "$NRG.Q",
    "_INBOX.other.Q", "_INBOX.S.Q",
    "$JS.API.ACCOUNT.PURGE.Q", "$JS.API.META.LEADER.STEPDOWN", "$JS.API.STREAM.LIST",
    "$JS.API.STREAM.NAMES", "$JS.EVENT.ADVISORY.Q", "$JS.API.DIRECT.GET.S",
    "$JS.API.CONSUMER.CREATE.S", "$JS.API.CONSUMER.CREATE.Q",
    "$JS.API.CONSUMER.PAUSE.S.D", "$JS.API.CONSUMER.UNPIN.S.D", "$JS.API.CONSUMER.LIST.S",
    "$JS.API.STREAM.LEADER.STEPDOWN.S", "$JS.API.STREAM.PEER.REMOVE.S",
    "$JS.API.CONSUMER.LEADER.STEPDOWN.S.D", "$JS.API.CONSUMER.NAMES.S",
    # acks of a durable no pattern may name (Q), in both forms: a loose ack grant reaches them
    "$JS.ACK._.hKkTAyOX.Q.Q.1.2.3.4.5.6", "$JS.ACK.Q.Q.1.2.3.4.5",
] + [
    f"$JS.API.STREAM.{verb}.{s}" for verb in ("DELETE", "PURGE", "SNAPSHOT", "RESTORE", "UPDATE")
    for s in ("S", "Q")
] + [f"$JS.API.STREAM.MSG.DELETE.{s}" for s in ("S", "Q")]  # fmt: skip
ADMIN = [f"$JS.API.STREAM.{v}.{s}" for v in ("CREATE", "MSG.GET") for s in ("S", "Q")] + [
    "$JS.API.CONSUMER.DELETE.S.D", "$JS.API.CONSUMER.DELETE.Q.Q",
    "$JS.API.CONSUMER.CREATE.S.D", "$JS.API.CONSUMER.CREATE.Q.Q",
    "$JS.API.CONSUMER.CREATE.S.D.lab.x", "$JS.API.CONSUMER.DURABLE.CREATE.S.D",
    "$JS.API.CONSUMER.DURABLE.CREATE.Q.Q",
]  # fmt: skip
#: every literal token a refused call or an allowed form names, a user's own, and stand-ins; a
#: literal outside this set matches exactly what "other" matches
ALPHABET = [
    *sorted(
        (
            {t for s in REFUSED + ADMIN for t in s.split(".")}
            | {t for f in bus._JS_FORMS + bus._JS_ADMIN_FORMS for t in f if not t.startswith("<")}
            | {USER, "other", "S", "D", "hKkTAyOX"}
        )
        - {"Q"}
    ),
    "*",
    ">",
]


def _reaching(targets: list[str]):
    """Every well-formed pattern over ALPHABET that matches at least one of ``targets``: a
    depth-first walk that extends a prefix only while some target can still match it, so it is
    exhaustive without enumerating the patterns that reach nothing."""
    split = [t.split(".") for t in targets]
    longest = max(map(len, split))

    def walk(prefix: list[str], alive: list[list[str]]):
        if prefix and prefix[-1] == ">":
            yield ".".join(prefix)
            return
        if prefix and any(len(t) == len(prefix) for t in alive):
            yield ".".join(prefix)
        if len(prefix) == longest:
            return
        i = len(prefix)
        for tok in ALPHABET:
            if tok == ">":
                nxt = [t for t in alive if len(t) > i]
            else:
                nxt = [t for t in alive if len(t) > i and tok in ("*", t[i])]
            if nxt:
                yield from walk([*prefix, tok], nxt)

    yield from walk([], split)


@pytest.mark.parametrize("admin", [False, True], ids=["user", "provisioner"])
def test_no_pattern_that_reaches_a_refused_call_is_allowed(admin):
    """Exhaustive over the alphabet: every pattern a NATS matcher says reaches a refused call
    (for the provisioner, the refused calls but its own) is refused by the filter."""
    targets = REFUSED if admin else REFUSED + ADMIN
    seen = 0
    for pattern in _reaching(targets):
        seen += 1
        hits = [t for t in targets if subject_matches(pattern, t)]
        assert hits, pattern  # the walk yields only patterns that reach something
        assert bus.hnx_bus_subject_problems([pattern], USER, admin=admin), (pattern, hits)
    assert seen > 1_000, seen  # the walk really explored (a broken walk proves nothing)


def test_every_short_pattern_is_refused_or_reaches_no_refused_call():
    """The reviewer's form: every well-formed pattern of up to three tokens over the alphabet,
    whatever it matches."""
    targets = REFUSED + ADMIN
    for n in (1, 2, 3):
        for toks in itertools.product(ALPHABET, repeat=n):
            if ">" in toks[:-1]:
                continue
            pattern = ".".join(toks)
            if bus.hnx_bus_subject_problems([pattern], USER) == []:
                assert not [t for t in targets if subject_matches(pattern, t)], pattern


def test_the_allowed_forms_reach_their_own_calls():
    """And the other way: the grants the filter allows reach exactly the calls the clients make
    (the adapter's stream lookups, a durable's info and next, its acks in both reply-subject
    forms; the provisioner's creates), checked with the NATS matcher."""
    user = [
        "$JS.API.STREAM.INFO.S", "$JS.API.CONSUMER.INFO.S.D",
        "$JS.API.CONSUMER.MSG.NEXT.S.D", "$JS.ACK.S.D.*.*.*.*.*", "$JS.ACK._.hKkTAyOX.S.D.*.*.*.*.>",
    ]  # fmt: skip
    admin = ["$JS.API.CONSUMER.CREATE.S.D.lab.homelabnext.decision.returned",
             "$JS.API.STREAM.CREATE.S", "$JS.API.STREAM.MSG.GET.S"]  # fmt: skip
    assert bus.hnx_bus_subject_problems(user, USER) == []
    assert bus.hnx_bus_subject_problems(admin + user, "hnx-events-admin", admin=True) == []
    calls = {
        "$JS.API.STREAM.INFO.S": True, "$JS.API.CONSUMER.MSG.NEXT.S.D": True,
        "$JS.ACK.S.D.1.2.3.4.5": True, "$JS.ACK._.hKkTAyOX.S.D.1.2.3.4.5.6": True,
        "$JS.ACK._.hKkTAyOX.S.D.1.2.3.4.5.6.7": True,  # a later v2 may append tokens
        "$JS.ACK.S.Q.1.2.3.4.5": False, "$JS.ACK._.hKkTAyOX.Q.D.1.2.3.4.5.6": False,
        "$JS.ACK.S.D.1.2.3.4": False, "$JS.ACK._.hKkTAyOX.S.D.1.2.3.4": False,
    }  # fmt: skip
    for call, reached in calls.items():
        assert any(subject_matches(g, call) for g in user) is reached, call


def test_durables_are_declared_once_for_one_user_and_granted_to_it_alone():
    durable = {"stream": "LAB", "durable": "bridge-x", "user": "hnx-bridge",
               "filter": "lab.homelabnext.decision.returned"}  # fmt: skip
    grants = ["$JS.API.CONSUMER.INFO.LAB.bridge-x", "$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x",
              "$JS.ACK.LAB.bridge-x.*.*.*.*.*", "$JS.ACK._.hKkTAyOX.LAB.bridge-x.*.*.*.*.>"]  # fmt: skip
    users = [{"user": "hnx-bridge", "publish": grants},
             {"user": "hnx-admin", "publish": bus.hnx_bus_durable_create_subjects(durable)},
             {"user": "hnx-other", "publish": ["lab.x"]}]  # fmt: skip
    streams = [{"name": "LAB", "subject_prefix": "lab"}]

    def problems(ds=(durable,), us=users, provision=True):
        return bus.hnx_bus_durable_problems(list(ds), us, "hnx-admin", streams, provision)

    assert problems() == []
    assert problems(ds=[dict(durable, start_seq=4)]) == []
    assert bus.hnx_bus_durable_create_subjects(durable) == [
        "$JS.API.CONSUMER.INFO.LAB.bridge-x",
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned",
    ]
    # a second user naming the same durable, by any of its calls
    for g in grants:
        thief = [*users[:2], {"user": "hnx-other", "publish": [g]}]
        got = problems(us=thief)
        assert any("one user each" in p for p in got) and any("hnx-other" in p for p in got), g
    # a grant on a durable nobody declared, or declared for someone else
    stray = [*users[:2], {"user": "hnx-other", "publish": ["$JS.API.CONSUMER.MSG.NEXT.LAB.y"]}]
    assert any("not a durable declared" in p for p in problems(us=stray))
    assert any(
        "not a durable declared" in p for p in problems(ds=[dict(durable, user="hnx-other")])
    )
    # the declaration itself
    for bad in (
        dict(durable, deliver_subject="_INBOX.hnx-other.x"),  # a push durable
        dict(durable, ack_policy="none"), dict(durable, max_deliver=0), dict(durable, ack_wait=-1),
        dict(durable, deliver_policy="last"), dict(durable, replay_s=60, deliver_policy="all"),
        dict(durable, start_seq=0), dict(durable, start_seq=4, replay_s=60),
        dict(durable, user="hnx-admin"), dict(durable, user="nobody"),
        dict(durable, filter="other.homelabnext.x"), dict(durable, filter=">"),
        dict(durable, durable="a.b"), {k: v for k, v in durable.items() if k != "filter"},
    ):  # fmt: skip
        assert problems(ds=[bad]), bad
    assert any("declared twice" in p for p in problems(ds=[durable, durable]))
    # provisioning needs the provisioner's two calls; without provisioning they are not required
    lacking = [users[0], {"user": "hnx-admin", "publish": ["$JS.API.STREAM.CREATE.LAB"]}]
    assert any("needs" in p for p in problems(us=lacking))
    assert problems(us=lacking, provision=False) == []


def test_a_push_consumer_in_jsz_is_reported():
    def doc(*consumers):
        return {"account_details": [{"name": "HNX", "stream_detail": [
            {"name": "LAB", "consumer_detail": list(consumers)}]}]}  # fmt: skip

    pull = {"name": "bridge-x", "config": {"durable_name": "bridge-x", "ack_policy": "explicit"}}
    push = {"name": "evil", "config": {"durable_name": "evil", "deliver_subject": "_INBOX.v.x"}}
    assert bus.hnx_bus_push_consumers(doc(pull)) == []
    assert bus.hnx_bus_push_consumers(doc(pull, push)) == ["HNX/LAB/evil -> _INBOX.v.x"]
    assert bus.hnx_bus_push_consumers({}) == [] and bus.hnx_bus_push_consumers(None) == []


def test_the_labs_grants_are_within_the_ceiling():
    """The lab's NATS users (compose/lab-in-a-box/config/nats/nats.conf, the grants docs/broker.md
    quotes) pass the role's check: the role refuses nothing the lab needs."""
    spec = importlib.util.spec_from_file_location(
        "lab_conf", ROOT / "tests/compose/test_lab_in_a_box.py"
    )
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    users = {n: u for n, u in lab.nats_users().items() if u["account"].startswith("HNX")}
    assert len(users) >= 3 and "hnx-broker" in users and "hnx-lab-admin" in users
    for name, u in users.items():
        perms = u["permissions"]
        # a client names its JetStream calls under the import prefix: the grant is the import's
        publish = [lab.bus_subject(s) for s in perms["publish"]["allow"]]
        subjects = publish + perms["subscribe"]["allow"]
        assert subjects and publish, name
        admin = name == "hnx-lab-admin"
        got = bus.hnx_bus_subject_problems(subjects, name, admin=admin)
        got += bus.hnx_bus_subscribe_problems(perms["subscribe"]["allow"], name, admin=admin)
        assert got == [], (name, got)


def test_the_labs_accounts_are_what_the_role_renders():
    """The lab's bus (config/nats/nats.conf) is the role's account split, account for account:
    the role's filter, given the lab's users, renders exactly the lab's HNX and client accounts
    (passwords aside), so the lab cannot drift from what a deployment runs."""
    spec = importlib.util.spec_from_file_location(
        "lab_conf", ROOT / "tests/compose/test_lab_in_a_box.py"
    )
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    conf = lab.parse_nats_conf(lab.NATS_CONF.read_text())
    accounts = {k: v for k, v in conf["accounts"].items() if k.startswith("HNX")}
    users = []
    for name, u in lab.nats_users().items():
        if not u["account"].startswith("HNX"):
            continue
        perms = u["permissions"]
        users.append({"user": name, "password_hash": u["password"],
                      "publish": [lab.bus_subject(s) for s in perms["publish"].get("allow", [])],
                      "subscribe": perms["subscribe"]["allow"]})  # fmt: skip
    assert bus.hnx_bus_accounts(users, "hnx-lab-admin", "HNX", "JS.HNX.API") == accounts


def _accounts(*users, admin="adm"):
    rendered = [{"user": u, "password_hash": "h", "publish": p, "subscribe": [f"_INBOX.{u}.>"]}
                for u, p in users]  # fmt: skip
    return bus.hnx_bus_accounts(rendered, admin, "HNX", "JS.HNX.API")


def test_every_client_lives_in_an_account_of_its_own_and_imports_its_grants_alone():
    got = _accounts(
        ("adm", ["$JS.API.STREAM.CREATE.S"]),
        ("pub", ["s.decision.>", "$JS.API.STREAM.INFO.S", "_INBOX.pub.x"]),
        ("rd", ["$JS.API.STREAM.INFO.S", "$JS.API.CONSUMER.MSG.NEXT.S.d",
                "$JS.ACK.S.d.*.*.*.*.*"]),
    )  # fmt: skip
    assert list(got) == ["HNX", "HNX-pub", "HNX-rd"]
    assert got["HNX"]["jetstream"] == "enabled" and [u["user"] for u in got["HNX"]["users"]] == [
        "adm"
    ]
    assert got["HNX"]["users"][0]["permissions"]["publish"] == {
        "allow": ["$JS.API.STREAM.CREATE.S"]
    }
    assert all("jetstream" not in a for n, a in got.items() if n != "HNX")
    exports = {e["service"]: e for e in got["HNX"]["exports"]}
    # each subject exported to the accounts that hold it, no more; a pull answers in a stream
    assert exports["$JS.API.STREAM.INFO.S"]["accounts"] == ["HNX-pub", "HNX-rd"]
    assert exports["s.decision.>"]["accounts"] == ["HNX-pub"]
    assert exports["$JS.API.CONSUMER.MSG.NEXT.S.d"] == {
        "service": "$JS.API.CONSUMER.MSG.NEXT.S.d",
        "accounts": ["HNX-rd"],
        "response_type": "stream",
    }
    assert "_INBOX.pub.x" not in exports  # an inbox stays in the client's own account
    # the client's allow-list is what its imports expose: $JS.API under the prefix, acks and
    # stream subjects as they are
    rd = got["HNX-rd"]
    assert rd["users"][0]["permissions"]["publish"]["allow"] == [
        "JS.HNX.API.STREAM.INFO.S",
        "JS.HNX.API.CONSUMER.MSG.NEXT.S.d",
        "$JS.ACK.S.d.*.*.*.*.*",
    ]
    assert [i.get("to", i["service"]["subject"]) for i in rd["imports"]] == rd["users"][0][
        "permissions"
    ]["publish"]["allow"]
    assert all(i["service"]["account"] == "HNX" for i in rd["imports"])
    # a subscribe-only client imports nothing and may publish nothing
    quiet = bus.hnx_bus_accounts([{"user": "q", "password_hash": "h", "publish": [],
                                   "subscribe": [], "subscribe_only": True}], "adm", "HNX", "P")  # fmt: skip
    assert quiet["HNX-q"] == {"users": [{"user": "q", "password": "h", "permissions": {
        "publish": {"deny": [">"]}, "subscribe": {"allow": ["_INBOX.q.>"]}}}], "imports": []}  # fmt: skip


@pytest.mark.parametrize(
    ("subject", "ok"),
    [("_INBOX.hnx-broker.>", True), ("_INBOX.hnx-broker.r.1", True), ("_INBOX.hnx-broker", False),
     ("_INBOX.other.>", False), ("lab.homelabnext.decision.>", False), ("$JS.ACK.S.d.>", False),
     (">", False)],
)  # fmt: skip
def test_a_client_subscribes_to_its_own_replies_alone(subject, ok):
    assert (bus.hnx_bus_subscribe_problems([subject], USER) == []) is ok
    assert bus.hnx_bus_subscribe_problems([subject], USER, admin=True) == []


LOOPBACK = ("127.0.0.1", "127.1.2.3", "::1")  # no-raw-endpoint: allow the loopback cases
NOT_LOOPBACK = ("0.0.0.0", "::", "192.0.2.10", "2001:db8::1")  # no-raw-endpoint: allow refused
NOT_LOOPBACK += (
    "not-an-address",
    "",
    "localhost",
    "127.0.0.1.10",
)  # no-raw-endpoint: allow refused


@pytest.mark.parametrize(
    ("address", "loopback"),
    [(a, True) for a in LOOPBACK] + [(a, False) for a in NOT_LOOPBACK],
)
def test_loopback(address, loopback):
    assert bus.hnx_is_loopback(address) is loopback


def test_hostport_brackets_ipv6():
    v4 = "127.0.0.1"  # no-raw-endpoint: allow loopback
    assert bus.hnx_nats_hostport(v4, 4222) == f"{v4}:4222"
    assert bus.hnx_nats_hostport("::1", "4222") == "[::1]:4222"


def test_what_is_declared_but_not_on_the_bus_is_named():
    """The health hook's backstop: a deleted stream (or DLQ) and a declared durable not created."""

    def jsz(*streams, account="HNX"):
        return {"account_details": [{"name": account, "stream_detail": [
            {"name": n, "consumer_detail": [{"name": c} for c in cs]} for n, cs in streams]}]}  # fmt: skip

    streams = [{"name": "LAB", "subject_prefix": "lab", "max_bytes": 1}]
    durables = [{"stream": "LAB", "durable": "bridge-x"}]
    full = jsz(("LAB", ["bridge-x"]), ("LAB_DLQ", []))
    assert bus.hnx_bus_missing(full, "HNX", streams, durables) == {"streams": [], "durables": []}
    assert bus.hnx_bus_missing(jsz(("LAB", [])), "HNX", streams, durables) == {
        "streams": ["LAB_DLQ"], "durables": ["LAB/bridge-x"]}  # fmt: skip
    # another account's stream of the same name is not the bus's
    assert bus.hnx_bus_missing(jsz(("LAB", ["bridge-x"]), ("LAB_DLQ", []), account="HNX-x"),
                               "HNX", streams, durables)["streams"] == ["LAB", "LAB_DLQ"]  # fmt: skip
    assert bus.hnx_bus_missing(None, "HNX") == {"streams": [], "durables": []}
