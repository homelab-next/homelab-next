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
        "$JS.API.STREAM.MSG.GET.LAB", "$JS.API.CONSUMER.INFO.LAB.bridge-x",
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x",
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned",
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x.>", "$JS.API.CONSUMER.DURABLE.CREATE.LAB.bridge-x",
        "$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x", "$JS.ACK.LAB.bridge-x.*.*.*.*.*",
        "$JS.ACK._.ACCOUNTHASH.LAB.bridge-x.*.*.*.*.>", "$JS.ACK.LAB.bridge-x.>",
    ],
)  # fmt: skip
def test_allowed(subject):
    assert bus.hnx_bus_subject_problems([subject], USER) == []


ADMIN_ONLY = ("$JS.API.STREAM.CREATE.LAB", "$JS.API.STREAM.UPDATE.LAB_DLQ",
              "$JS.API.CONSUMER.DELETE.LAB.e2e-scratch", "$JS.API.CONSUMER.NAMES.LAB")  # fmt: skip


@pytest.mark.parametrize("subject", ADMIN_ONLY)
def test_the_provisioner_alone_creates_updates_and_deletes_consumers(subject):
    assert bus.hnx_bus_subject_problems([subject], USER)
    assert bus.hnx_bus_subject_problems([subject], "hnx-events-admin", admin=True) == []


@pytest.mark.parametrize(
    "subject",
    ["$JS.API.STREAM.DELETE.LAB", "$JS.API.STREAM.PURGE.LAB", "$JS.API.STREAM.MSG.DELETE.LAB",
     "$JS.API.STREAM.CREATE.*", "$JS.API.CONSUMER.DELETE.LAB.*", "$JS.API.STREAM.RESTORE.LAB",
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
    "$JS.API.CONSUMER.LEADER.STEPDOWN.S.D",
] + [
    f"$JS.API.STREAM.{verb}.{s}" for verb in ("DELETE", "PURGE", "SNAPSHOT", "RESTORE")
    for s in ("S", "Q")
] + [f"$JS.API.STREAM.MSG.DELETE.{s}" for s in ("S", "Q")]  # fmt: skip
ADMIN = [
    f"$JS.API.STREAM.{verb}.{s}" for verb in ("CREATE", "UPDATE") for s in ("S", "Q")
] + ["$JS.API.CONSUMER.DELETE.S.D", "$JS.API.CONSUMER.DELETE.Q.Q",
     "$JS.API.CONSUMER.NAMES.S"]  # fmt: skip
#: every literal token a refused call or an allowed form names, a user's own, and stand-ins; a
#: literal outside this set matches exactly what "other" matches
ALPHABET = [
    *sorted(
        (
            {t for s in REFUSED + ADMIN for t in s.split(".")}
            | {t for f in bus._JS_FORMS + bus._JS_ADMIN_FORMS for t in f if not t.startswith("<")}
            | {USER, "other", "S", "D"}
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
    """And the other way: the forms the filter allows are exactly the calls the clients make
    (the adapter's stream lookups, a durable's create/info/next and acks in both ack formats)."""
    allowed = [
        "$JS.API.STREAM.INFO.S", "$JS.API.STREAM.MSG.GET.S", "$JS.API.CONSUMER.INFO.S.D",
        "$JS.API.CONSUMER.CREATE.S.D.lab.homelabnext.decision.returned",
        "$JS.API.CONSUMER.MSG.NEXT.S.D", "$JS.ACK.S.D.1.2.3.4.5", "$JS.ACK._.HASH.S.D.1.2.3.4.5.6",
    ]  # fmt: skip
    assert bus.hnx_bus_subject_problems(allowed, USER) == []


def test_the_labs_grants_are_within_the_ceiling():
    """The lab's NATS users (compose/lab-in-a-box/config/nats/nats.conf, the grants docs/broker.md
    quotes) pass the role's check: the role refuses nothing the lab needs."""
    spec = importlib.util.spec_from_file_location(
        "lab_conf", ROOT / "tests/compose/test_lab_in_a_box.py"
    )
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    users = {n: u for n, u in lab.nats_users().items() if u["account"] == "HNX"}
    assert len(users) >= 3 and "hnx-broker" in users and "hnx-lab-admin" in users
    for name, u in users.items():
        perms = u["permissions"]
        subjects = perms["publish"]["allow"] + perms["subscribe"]["allow"]
        assert subjects and perms["publish"]["allow"], name
        got = bus.hnx_bus_subject_problems(subjects, name, admin=name == "hnx-lab-admin")
        assert got == [], (name, got)


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
