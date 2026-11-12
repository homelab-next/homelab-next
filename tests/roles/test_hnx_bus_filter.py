# SPDX-License-Identifier: Apache-2.0
"""The events bus role's subject ceiling and loopback check (``ansible/plugins/filter/hnx_bus.py``),
called directly; ``test_control_plane_roles.py`` runs them through the role's validate hook."""

import importlib.util
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "ansible/plugins/filter/hnx_bus.py"
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
        "a..b", "a.>.b", "a.b*", "",
    ],
)  # fmt: skip
def test_refused(subject):
    assert bus.hnx_bus_subject_problems([subject], USER), subject


@pytest.mark.parametrize(
    "subject",
    [
        "lab.homelabnext.decision.>", "lab.*.decision.returned",
        "_INBOX.hnx-broker.>", "_INBOX.hnx-broker.reply.1",
        "$JS.API.STREAM.INFO.LAB", "$JS.API.STREAM.INFO.LAB_DLQ", "$JS.API.STREAM.CREATE.LAB",
        "$JS.API.STREAM.MSG.GET.LAB", "$JS.API.CONSUMER.INFO.LAB.bridge-x",
        "$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned",
        "$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x", "$JS.ACK.LAB.bridge-x.*.*.*.*.*",
        "$JS.ACK._.ACCOUNTHASH.LAB.bridge-x.*.*.*.*.>",
    ],
)  # fmt: skip
def test_allowed(subject):
    assert bus.hnx_bus_subject_problems([subject], USER) == []


def test_every_problem_is_named():
    got = bus.hnx_bus_subject_problems(["$JS.API.>", "lab.ok", "_INBOX.>"], USER)
    assert len(got) == 2 and got[0].startswith("$JS.API.>") and got[1].startswith("_INBOX.>")


LOOPBACK = ("127.0.0.1", "127.1.2.3", "::1")  # no-raw-endpoint: allow the loopback cases
NOT_LOOPBACK = ("0.0.0.0", "::", "192.0.2.10", "2001:db8::1")  # no-raw-endpoint: allow refused
NOT_LOOPBACK += ("not-an-address", "")


@pytest.mark.parametrize(
    ("address", "loopback"),
    [(a, True) for a in LOOPBACK] + [(a, False) for a in NOT_LOOPBACK],
)
def test_loopback(address, loopback):
    assert bus.hnx_is_loopback(address) is loopback
