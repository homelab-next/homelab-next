# SPDX-License-Identifier: Apache-2.0
"""Snapshot expiry through the catalog (``TrinoRestLake.expire_snapshots`` and
``RestCatalog.remove_snapshots``) against a fake catalog, and the catalog reply cap's message."""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

from homelabnext.lake.errors import LakeError
from homelabnext.lake.rest_catalog import CommitConflict, RestCatalog
from homelabnext.lake.tables import load_schemas
from homelabnext.lake.trino_rest import TrinoRestLake

HOUR = 3600 * 1000
NOW = 1_800_000_000_000


def snap(i, age_h):
    return {"snapshot-id": i, "timestamp-ms": NOW - age_h * HOUR, "manifest-list": f"m{i}.avro"}


class FakeCatalog:
    root = "http://fake"

    def __init__(self, snaps, refs=None, conflicts=0):
        self.meta = {
            "table-uuid": "u-1",
            "snapshots": snaps,
            "refs": refs
            if refs is not None
            else {"main": {"snapshot-id": snaps[-1]["snapshot-id"]}},
        }
        self.calls, self.conflicts = [], conflicts

    def load_table(self, ns, table):
        return dict(self.meta)

    def remove_snapshots(self, ns, table, ids, *, main_snapshot_id, table_uuid):
        self.calls.append((table, sorted(ids), main_snapshot_id, table_uuid))
        if self.conflicts:
            self.conflicts -= 1
            raise CommitConflict("raced")
        self.meta["snapshots"] = [s for s in self.meta["snapshots"] if s["snapshot-id"] not in ids]
        return dict(self.meta)


def lake(cat):
    return TrinoRestLake(
        SimpleNamespace(), cat, namespace="soc", schemas=load_schemas(), ensure=False
    )


def ids_of(cat):
    return [s["snapshot-id"] for s in cat.meta["snapshots"]]


def test_keeps_main_and_the_newest_n():
    # snapshot 1 is the OLDEST but main points at it: it must survive any count
    cat = FakeCatalog([snap(i, 10 - i) for i in range(1, 9)], refs={"main": {"snapshot-id": 1}})
    out = lake(cat).expire_snapshots("dns_activity", keep=3, now_ms=NOW)
    assert ids_of(cat) == [1, 6, 7, 8] and out["expired"] == 4 and out["kept"] == 4
    assert cat.calls == [("dns_activity", [2, 3, 4, 5], 1, "u-1")]


def test_the_age_limit_expires_old_snapshots_too_but_never_main():
    cat = FakeCatalog([snap(1, 100), snap(2, 80), snap(3, 10), snap(4, 1)])
    out = lake(cat).expire_snapshots("dns_activity", max_age_ms=72 * HOUR, now_ms=NOW)
    assert ids_of(cat) == [3, 4] and out["expired"] == 2
    cat = FakeCatalog([snap(1, 100), snap(2, 99)], refs={"main": {"snapshot-id": 1}})
    lake(cat).expire_snapshots("dns_activity", max_age_ms=HOUR, now_ms=NOW)
    assert ids_of(cat) == [1]


def test_nothing_to_expire_sends_no_commit():
    cat = FakeCatalog([snap(i, i) for i in range(1, 4)])
    out = lake(cat).expire_snapshots("dns_activity", keep=500, now_ms=NOW)
    assert cat.calls == [] and out["expired"] == 0 and out["kept"] == 3


@pytest.mark.parametrize(
    "refs",
    [
        {"main": {"snapshot-id": 4}, "tag-1": {"snapshot-id": 2}},
        {"main": {"snapshot-id": 4}, "audit": {"snapshot-id": 1}},
        {},
    ],
)
def test_refuses_a_table_with_any_ref_but_main(refs):
    cat = FakeCatalog([snap(i, i) for i in range(1, 5)], refs=refs)
    out = lake(cat).expire_snapshots("dns_activity", keep=1, now_ms=NOW)
    assert cat.calls == [] and out["expired"] == 0 and "skipped" in out and len(ids_of(cat)) == 4


def test_a_race_retries_on_fresh_metadata_and_then_gives_up():
    cat = FakeCatalog([snap(i, 10 - i) for i in range(1, 6)], conflicts=1)
    assert lake(cat).expire_snapshots("dns_activity", keep=2, now_ms=NOW)["expired"] == 3
    assert len(cat.calls) == 2
    cat = FakeCatalog([snap(i, 10 - i) for i in range(1, 6)], conflicts=9)
    with pytest.raises(CommitConflict):
        lake(cat).expire_snapshots("dns_activity", keep=2, now_ms=NOW)


def test_asking_for_no_limit_is_an_error():
    cat = FakeCatalog([snap(1, 1)])
    with pytest.raises(LakeError, match="keep or max_age_ms"):
        lake(cat).expire_snapshots("dns_activity")


def test_the_commit_asserts_main_and_the_table_and_removes_only_snapshots():
    sent = {}

    class Opener:
        def open(self, req, timeout=None):
            import json

            sent.update(json.loads(req.data), path=req.full_url)
            return io.BytesIO(b'{"metadata": {"snapshots": []}}')

    cat = RestCatalog("http://x:1", warehouse="w", prefix_optional=True, opener=Opener())
    cat._prefix = ""  # no config round trip
    cat.remove_snapshots("soc", "dns_activity", [5, 6], main_snapshot_id=9, table_uuid="u-1")
    assert sent["path"].endswith("/v1/namespaces/soc/tables/dns_activity")
    assert sent["requirements"] == [
        {"type": "assert-table-uuid", "uuid": "u-1"},
        {"type": "assert-ref-snapshot-id", "ref": "main", "snapshot-id": 9},
    ]
    assert sent["updates"] == [{"action": "remove-snapshots", "snapshot-ids": [5, 6]}]


def test_a_reply_over_the_cap_names_the_snapshot_count_and_the_cap_is_settable():
    body = (
        b'{"metadata": {"snapshots": ['
        + b'{"manifest-list": "m"},' * 399
        + b'{"manifest-list": "m"}]}}'
    )

    class Opener:
        def open(self, req, timeout=None):
            return io.BytesIO(body)

    cat = RestCatalog(
        "http://x:1", warehouse="w", prefix_optional=True, opener=Opener(), max_bytes=2048
    )
    cat._prefix = ""
    with pytest.raises(LakeError, match=r"response larger than 2048 bytes.*at least \d+ snapshots"):
        cat.load_table("soc", "raw_archive")
    cat.max_bytes = 1 << 20
    assert len(cat.load_table("soc", "raw_archive")["snapshots"]) == 400
