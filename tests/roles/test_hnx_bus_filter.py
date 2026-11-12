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
#: the bus account (its v2 ack hash, nats-server's getHash, is pinned below) and its stream
ACCOUNT = "HNX"
STREAMS = [{"name": "LAB", "subject_prefix": "lab"}]


def problems(subjects, user=USER, admin=False):
    """The role's call: the bus account and its declared streams given."""
    return bus.hnx_bus_subject_problems(subjects, user, admin=admin, account=ACCOUNT,
                                        streams=STREAMS)  # fmt: skip


def test_the_v2_ack_hash_is_nats_servers_get_hash_of_the_account():
    """server/events.go getHash (2.15.1): sha256 of the name, its first 8 bytes each mod 62 into
    0-9A-Za-z; the hash the server puts in a v2 ack of a consumer in account HNX."""
    assert bus.hnx_bus_account_hash("HNX") == "hKkTAyOX"
    assert bus.hnx_bus_account_hash("HNX-x") != "hKkTAyOX"
    assert len(bus.hnx_bus_account_hash("ANY_ACCOUNT")) == 8


def test_a_v2_ack_grant_carries_the_bus_accounts_own_hash():
    v2 = "$JS.ACK._.{}.LAB.bridge-x.*.*.*.*.>"
    assert problems([v2.format("hKkTAyOX")]) == []
    for other in ("ABCDEFGH", bus.hnx_bus_account_hash("HNX-hnx-broker"), "hKkTAyOx"):
        got = problems([v2.format(other)])
        assert got and "hKkTAyOX" in got[0], (other, got)
    # without the account no v2 grant passes: its hash cannot be checked
    assert bus.hnx_bus_subject_problems([v2.format("hKkTAyOX")], USER, streams=STREAMS)
    assert bus.hnx_bus_subject_problems([v2.format("hKkTAyOX")], USER, account="OTHER",
                                        streams=STREAMS)  # fmt: skip


@pytest.mark.parametrize(
    "subject",
    ["_R_.abc.>", "_R_.x", "_GR_.srv.x", "_SYS_.x", "_X.y", "other.homelabnext.decision.>",
     "lab", "lab_DLQ.x", "LAB.x"],
)  # fmt: skip
def test_a_client_publishes_under_a_declared_stream_or_its_own_inbox_alone(subject):
    """Security F1 (round 5): no server _ subject but the client's own _INBOX, and every other
    grant under a declared stream's subject prefix."""
    assert problems([subject]), subject


def test_with_no_stream_declared_a_client_holds_no_event_subject():
    assert bus.hnx_bus_subject_problems(["lab.homelabnext.x"], USER, account=ACCOUNT) != []
    assert problems(["lab.homelabnext.x", f"_INBOX.{USER}.r"]) == []


ADMIN_USER = "hnx-events-admin"


@pytest.mark.parametrize(
    "subject",
    ["_R_.>", "_R_.abc.>", "_GR_.>", "_GR_.srv.x", "_SYS_.x", "_X.y", "lab.homelabnext.x",
     "lab.>", "tx.>", "other.x", f"_INBOX.{USER}.>"],
)  # fmt: skip
def test_the_provisioner_holds_its_jetstream_calls_and_its_own_inbox_alone(subject):
    """Round 7 (security F2, design 3): the provisioner lives in the bus account, where ``_R_.>``
    carries every service-import reply (a client's PubAcks and pull deliveries) and a stream
    subject it publishes is stored as an event (the republish trigger of F1): no _ subject but
    its own _INBOX, and no subject outside $JS at all."""
    got = problems([subject], ADMIN_USER, admin=True)
    assert got, subject
    assert problems([f"_INBOX.{ADMIN_USER}.>", "$JS.API.STREAM.CREATE.LAB"], ADMIN_USER,
                    admin=True) == []  # fmt: skip


def test_r_subjects_name_why_they_are_refused_for_either():
    for admin, who in ((True, ADMIN_USER), (False, USER)):
        [got] = problems(["_R_.>"], who, admin=admin)
        assert "a server subject (_R_, _GR_, _SYS_" in got and f"_INBOX.{who}.>" in got, got
    [got] = problems(["lab.homelabnext.x"], ADMIN_USER, admin=True)
    assert "not the provisioner's" in got and "nothing else" in got, got


def test_the_provisioner_creates_the_declared_streams_alone():
    """Round 7 (security F1): the server does not check a STREAM.CREATE body, so the subject is
    narrowed to what is declared: a stream or its DLQ, never a stream that would only ever exist
    to carry a republish."""
    assert problems(["$JS.API.STREAM.CREATE.LAB", "$JS.API.STREAM.CREATE.LAB_DLQ"], ADMIN_USER,
                    admin=True) == []  # fmt: skip
    for other in ("TESTX", "LAB_X", "LABDLQ", "OTHER_DLQ"):
        [got] = problems([f"$JS.API.STREAM.CREATE.{other}"], ADMIN_USER, admin=True)
        assert f"creates {other}, which is not a declared stream" in got, got
    # with no stream declared (or its prefix alone) the provisioner creates none
    assert bus.hnx_bus_subject_problems(["$JS.API.STREAM.CREATE.LAB"], ADMIN_USER, admin=True,
                                        account=ACCOUNT)  # fmt: skip
    assert bus.hnx_bus_subject_problems(["$JS.API.STREAM.CREATE.LAB"], ADMIN_USER, admin=True,
                                        account=ACCOUNT, streams=["lab"])  # fmt: skip


@pytest.mark.parametrize(
    "subject",
    ["$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x", "$JS.ACK.LAB.bridge-x.*.*.*.*.*",
     "$JS.ACK._.hKkTAyOX.LAB.bridge-x.*.*.*.*.>"],
)  # fmt: skip
def test_the_provisioner_neither_pulls_nor_acks(subject):
    """Security F2 (round 5): the provisioner lives in the JetStream account, where a delivery or
    an ack's answer sent to a reply of its choosing is taken as a JetStream request."""
    got = problems([subject], "hnx-events-admin", admin=True)
    assert got and "not the provisioner's" in got[0], got
    assert problems([subject]) == []  # a client's own durable


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
    assert problems([subject]), subject


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
    assert problems([subject]) == []


ADMIN_ONLY = ("$JS.API.STREAM.CREATE.LAB", "$JS.API.STREAM.MSG.GET.LAB",
              "$JS.API.CONSUMER.CREATE.LAB.bridge-x",
              "$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned",
              "$JS.API.CONSUMER.DURABLE.CREATE.LAB.bridge-x",
              "$JS.API.CONSUMER.DELETE.LAB.e2e-scratch")  # fmt: skip


@pytest.mark.parametrize("subject", ADMIN_ONLY)
def test_the_provisioner_alone_creates_streams_and_creates_and_deletes_consumers(subject):
    got = problems([subject])
    assert got and "the provisioner's call alone" in got[0], got
    assert problems([subject], "hnx-events-admin", admin=True) == []


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
    assert problems([subject], "hnx-events-admin", admin=True)


def test_every_problem_is_named():
    got = problems(["$JS.API.>", "lab.ok", "_INBOX.>"])
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
#: a client's own reads, never the provisioner's (it lives in the JetStream account); the v2 ack
#: (11 tokens: it would double the walk) is test_the_provisioner_neither_pulls_nor_acks's, and no
#: $JS.ACK form is in the provisioner's list at all
READS = ["$JS.API.CONSUMER.MSG.NEXT.S.D", "$JS.ACK.S.D.1.2.3.4.5"]
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
            | {
                t
                for f in bus._JS_FORMS + bus._JS_READ_FORMS + bus._JS_ADMIN_FORMS
                for t in f
                if not t.startswith("<")
            }
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
    targets = REFUSED + READS if admin else REFUSED + ADMIN
    seen = 0
    for pattern in _reaching(targets):
        seen += 1
        hits = [t for t in targets if subject_matches(pattern, t)]
        assert hits, pattern  # the walk yields only patterns that reach something
        assert problems([pattern], admin=admin), (pattern, hits)
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
            if problems([pattern]) == []:
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
             "$JS.API.STREAM.CREATE.LAB", "$JS.API.STREAM.MSG.GET.S"]  # fmt: skip
    assert problems(user) == []
    assert problems(admin + user[:2], "hnx-events-admin", admin=True) == []
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
        got = bus.hnx_bus_subject_problems(subjects, name, admin=admin, account="HNX",
                                           streams=[{"name": "HNXLAB_BROKER",
                                                     "subject_prefix": "hnxlab"}])  # fmt: skip
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
    # subscribe_only is the provisioner's alone (the role refuses it for a client, which could
    # receive nothing): rendered deny-all, never {"allow": []} (no restriction at all)
    quiet = bus.hnx_bus_accounts([{"user": "adm", "password_hash": "h", "publish": [],
                                   "subscribe": [], "subscribe_only": True}], "adm", "HNX", "P")  # fmt: skip
    assert quiet["HNX"]["users"] == [{"user": "adm", "password": "h", "permissions": {
        "publish": {"deny": [">"]}, "subscribe": {"allow": ["_INBOX.adm.>"]}}}]  # fmt: skip


def test_the_monitor_imports_the_deletion_advisories_alone():
    """Optional events_bus_monitor_user: an account of its own importing exactly the stream and
    consumer deletion and stream update advisories, as STREAMS; it publishes nothing."""
    got = bus.hnx_bus_accounts([{"user": "adm", "password_hash": "h", "publish": ["$JS.API.INFO"],
                                 "subscribe": []}], "adm", "HNX", "JS.HNX.API",
                               {"user": "hnx-watch", "password_hash": "m"})  # fmt: skip
    subjects = ["$JS.EVENT.ADVISORY.STREAM.DELETED.>", "$JS.EVENT.ADVISORY.CONSUMER.DELETED.>",
                "$JS.EVENT.ADVISORY.STREAM.UPDATED.>"]  # fmt: skip
    assert list(bus.MONITOR_SUBJECTS) == subjects
    assert got["HNX-hnx-watch"] == {
        "users": [{"user": "hnx-watch", "password": "m", "permissions": {
            "publish": {"deny": [">"]}, "subscribe": {"allow": subjects}}}],
        "imports": [{"stream": {"account": "HNX", "subject": s}} for s in subjects]}  # fmt: skip
    assert [e for e in got["HNX"]["exports"] if "stream" in e] == [
        {"stream": s, "accounts": ["HNX-hnx-watch"]} for s in subjects]  # fmt: skip
    assert "jetstream" not in got["HNX-hnx-watch"]


def _detail(name, js=False, imports=()):
    """An ``/accountz?acc=`` answer as nats-server 2.15.1 gives it (its own $SYS imports, the
    $JS.API import from $SYS of an account without JetStream, then ``(account, subject[,
    local subject])`` rows)."""
    sys_ = [{"subject": f"$SYS.REQ.ACCOUNT.{name}.CONNZ", "account": "$SYS", "type": "service",
             "local_subject": "$SYS.REQ.ACCOUNT.PING.CONNZ"},
            {"subject": "$JS.API.>", "account": "$SYS", "type": "service",
             "local_subject": "$JS.API.>"}]  # fmt: skip
    rows = [(r[0], r[1], r[2] if len(r) > 2 else r[1]) for r in imports]
    return {"account_detail": {"account_name": name, "jetstream_enabled": js,
                               "imports": sys_ + [{"subject": s, "account": a, "to": loc,
                                                   "local_subject": loc, "type": "service"}
                                                  for a, s, loc in rows]}}  # fmt: skip


def test_the_account_split_is_read_back_from_the_running_server():
    """Security F3 (round 5): the health hook reads /accountz (accounts, JetStream, imports) and
    /connz?auth=true (which account each connected user is in) and names every departure."""
    users = [{"user": "adm", "publish": ["$JS.API.STREAM.CREATE.LAB"]},
             {"user": "relay", "publish": ["lab.>", "$JS.API.STREAM.INFO.LAB"]},
             {"user": "bridge", "publish": ["$JS.ACK.LAB.b.*.*.*.*.*"]}]  # fmt: skip
    want = bus.hnx_bus_expected_accounts(users, "adm", "HNX", "watch")
    assert want == {"HNX": ["adm"], "HNX-relay": ["relay"], "HNX-bridge": ["bridge"],
                    "HNX-watch": ["watch"]}  # fmt: skip
    accountz = {"accounts": ["$G", "$SYS", *want]}
    relay_imports = [("HNX", "lab.>"),
                     ("HNX", "$JS.API.STREAM.INFO.LAB", "JS.HNX.API.STREAM.INFO.LAB")]  # fmt: skip
    details = [_detail("HNX", js=True), _detail("HNX-relay", imports=relay_imports),
               _detail("HNX-bridge", imports=[("HNX", "$JS.ACK.LAB.b.*.*.*.*.*")]),
               _detail("HNX-watch", imports=[("HNX", s) for s in bus.MONITOR_SUBJECTS])]  # fmt: skip
    connz = {"total": 2, "offset": 0,
             "connections": [{"cid": 1, "authorized_user": "adm", "account": "HNX"},
                             {"cid": 2, "authorized_user": "relay", "account": "HNX-relay"}]}  # fmt: skip

    def check(**kw):
        args = {"accountz": accountz, "details": details, "connz": connz, **kw}
        return bus.hnx_bus_account_problems(args["accountz"], args["details"], users, "adm",
                                            "HNX", "watch", args["connz"])  # fmt: skip

    assert check() == []
    # the one-account shape the split replaced: the relay connected in HNX itself
    one = {"connections": [{"cid": 2, "authorized_user": "relay", "account": "HNX"}]}
    assert check(connz=one) == ["user relay: connected in account HNX, expected HNX-relay"]
    assert check(connz={"connections": [{"cid": 3, "authorized_user": "ghost"}]})
    assert check(accountz={"accounts": ["$G", "HNX"]})  # the client accounts missing
    assert check(accountz={"accounts": [*accountz["accounts"], "HNX-old"]})
    js_client = [*details[:1], _detail("HNX-relay", js=True), *details[2:]]
    assert any("JetStream on" in p for p in check(details=js_client))
    cross = [*details[:1], _detail("HNX-relay", imports=[("HNX-bridge", "x.>")]), *details[2:]]
    assert any("imports from" in p for p in check(details=cross))
    bus_imports = [_detail("HNX", js=True, imports=[("HNX-relay", "x")]), *details[1:]]
    assert any("account HNX: imports" in p for p in check(details=bus_imports))


def test_the_split_check_reads_the_import_subjects_too():
    """Round 7 (security F3): an import from the bus account is checked subject by subject
    against what the role renders for that account's user, not only by where it comes from."""
    users = [{"user": "adm", "publish": ["$JS.API.STREAM.CREATE.LAB"]},
             {"user": "relay", "publish": ["lab.>", "$JS.API.STREAM.INFO.LAB"]}]  # fmt: skip
    rendered = [
        ("HNX", "$JS.API.STREAM.INFO.LAB", "JS.HNX.API.STREAM.INFO.LAB"),
        ("HNX", "lab.>", "lab.>"),
    ]
    assert bus.hnx_bus_expected_imports(users, "adm", "HNX", "JS.HNX.API") == {
        "HNX": [], "HNX-relay": rendered}  # fmt: skip
    accountz = {"accounts": ["$G", "$SYS", "HNX", "HNX-relay"]}

    def check(relay_imports, api_prefix=None):
        details = [_detail("HNX", js=True), _detail("HNX-relay", imports=relay_imports)]
        return bus.hnx_bus_account_problems(accountz, details, users, "adm", "HNX", "", {},
                                            api_prefix)  # fmt: skip

    assert check(rendered) == [] and check(rendered, "JS.HNX.API") == []
    # a hand-added $JS.API.> (every call, STREAM.DELETE included) from the bus account itself
    got = check([*rendered, ("HNX", "$JS.API.>", "JS.HNX.API.>")])
    assert got == ["account HNX-relay: imports $JS.API.> from HNX as JS.HNX.API.>, which the "
                   "role does not render"], got  # fmt: skip
    got = check([*rendered, ("HNX", "lab.homelabnext.>")])
    assert got and "lab.homelabnext.> from HNX" in got[0], got
    # the same subject under another local name, or one the role renders missing
    got = check([rendered[1], ("HNX", "$JS.API.STREAM.INFO.LAB", "x.STREAM.INFO.LAB")])
    assert any("x.STREAM.INFO.LAB" in p for p in got) and any("lacks" in p for p in got), got
    assert check(rendered[:1]) == ["account HNX-relay: lacks the imports lab.> from HNX"]
    # under another API prefix, the rendered import is not the one the server holds
    assert check(rendered, "JS.OTHER.API")


def test_the_split_check_skips_a_connection_mid_handshake_and_sees_every_connection():
    """Round 7 (design 2, security F3): /connz lists a connection from the moment the server
    accepts it, before its CONNECT (no user, no account: what nats-server 2.15.1 shows for it);
    it can do nothing and is skipped.  /connz returns at most ``limit`` connections: when its
    ``total`` is more than it returned, the check could not see them all, and fails."""
    users = [{"user": "adm", "publish": ["$JS.API.STREAM.CREATE.LAB"]}]
    accountz = {"accounts": ["$G", "$SYS", "HNX"]}
    details = [_detail("HNX", js=True)]
    pending = {"cid": 7, "kind": "Client", "type": "nats", "name_tag": "$G"}
    adm = {"cid": 8, "authorized_user": "adm", "account": "HNX"}

    def check(connz):
        return bus.hnx_bus_account_problems(accountz, details, users, "adm", "HNX", "", connz)

    assert check({"total": 2, "offset": 0, "connections": [pending, adm]}) == []
    got = check({"total": 2, "offset": 0, "limit": 1, "connections": [pending]})
    assert got == ["/connz lists 2 connections and returned 1 (its limit): the check cannot see "
                   "every connection; raise the limit in the health hook"], got  # fmt: skip
    # a user in the wrong account is still named, whatever else is mid-handshake
    assert check({"total": 2, "connections": [pending, dict(adm, account="HNX-x")]}) == [
        "user adm: connected in account HNX-x, expected HNX"]  # fmt: skip
    assert check(None) == [] and check({}) == []


def test_a_stream_that_sends_its_messages_elsewhere_is_named():
    """Round 7 (security F1): a republish, mirror, sources or subject transform can aim a
    stream's messages at $JS.API.*; the role's streams never carry one, so each is named."""

    def jsz(*cfgs, account="HNX"):
        return {"account_details": [{"name": account, "stream_detail": [
            {"name": n, "config": c} for n, c in cfgs]}]}  # fmt: skip

    plain = {"subjects": ["lab.>"], "deny_delete": True, "deny_purge": True}
    assert bus.hnx_bus_stream_redirects(jsz(("LAB", plain), ("LAB_DLQ", plain)), "HNX") == []
    doc = jsz(("LAB", plain),
              ("TESTX", {"republish": {"src": "tx.a", "dest": "$JS.API.STREAM.DELETE.LAB"}}),
              ("M", {"mirror": {"name": "LAB"}}), ("S", {"sources": [{"name": "LAB"}]}),
              ("T", {"subject_transform": {"src": "t.>", "dest": "$JS.API.>"}}))  # fmt: skip
    assert bus.hnx_bus_stream_redirects(doc, "HNX") == [
        "TESTX: republish tx.a -> $JS.API.STREAM.DELETE.LAB", "M: mirror LAB",
        "S: sources LAB", "T: subject_transform t.> -> $JS.API.>"]  # fmt: skip
    # one the inventory declares is not named (none does today); another account's is not ours
    assert bus.hnx_bus_stream_redirects(doc, "HNX", ["M.mirror", "S.sources", "T.subject_transform",
                                                     "TESTX.republish"]) == []  # fmt: skip
    assert bus.hnx_bus_stream_redirects(doc, "HNX-x") == []
    assert bus.hnx_bus_stream_redirects(None, "HNX") == []
    # empty values are what a server without them may print: not a redirect
    assert bus.hnx_bus_stream_redirects(jsz(("LAB", {**plain, "sources": [], "mirror": None})),
                                        "HNX") == []  # fmt: skip


def test_streams_without_deny_flags_are_reported():
    def jsz(*cfgs, account="HNX"):
        return {"account_details": [{"name": account, "stream_detail": [
            {"name": n, "config": c} for n, c in cfgs]}]}  # fmt: skip

    flagged = {"deny_delete": True, "deny_purge": True}
    assert bus.hnx_bus_unprotected_streams(jsz(("LAB", flagged)), "HNX") == []
    assert bus.hnx_bus_unprotected_streams(
        jsz(("LAB", {}), ("LAB_DLQ", {"deny_delete": True})), "HNX"
    ) == ["LAB (no deny_delete or deny_purge)", "LAB_DLQ (no deny_purge)"]
    assert bus.hnx_bus_unprotected_streams(jsz(("LAB", {}), account="HNX-x"), "HNX") == []
    assert bus.hnx_bus_unprotected_streams(None, "HNX") == []


@pytest.mark.parametrize(
    ("subject", "ok"),
    [("_INBOX.hnx-broker.>", True), ("_INBOX.hnx-broker.r.1", True), ("_INBOX.hnx-broker", False),
     ("_INBOX.other.>", False), ("lab.homelabnext.decision.>", False), ("$JS.ACK.S.d.>", False),
     (">", False), ("_R_.>", False)],
)  # fmt: skip
def test_every_user_subscribes_to_its_own_replies_alone(subject, ok):
    """A client (round 5), and the provisioner too (round 7: in the bus account ``_R_.>`` would
    receive every service-import reply and ``$JS.API.*`` the clients' requests)."""
    assert (bus.hnx_bus_subscribe_problems([subject], USER) == []) is ok
    got = bus.hnx_bus_subscribe_problems([subject], USER, admin=True)
    assert (got == []) is ok
    assert not got or "the provisioner subscribes to its own replies only" in got[0]
    for sub in ("_R_.>", "$JS.API.STREAM.INFO.LAB", "$JS.API.>"):
        assert bus.hnx_bus_subscribe_problems([sub], ADMIN_USER, admin=True), sub


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
