# SPDX-License-Identifier: Apache-2.0
"""The catalog's remove-snapshots commit and the catalog reply cap's message, against the lab fake."""

from __future__ import annotations

import pytest

from homelabnext.lake.errors import LakeError
from homelabnext.lake.rest_catalog import CommitConflict, RestCatalog
from tests.lake.fake_lab import FakeLab


@pytest.fixture
def lab():
    with FakeLab() as fl:
        fl.tables[("soc", "t")] = {
            "table-uuid": "u-1",
            "properties": {},
            "snapshots": [{"snapshot-id": i, "manifest-list": f"m{i}"} for i in range(1, 400)],
            "refs": {"main": {"snapshot-id": 399}},
        }
        fl.lakes["soc"] = None
        yield fl


def test_the_commit_removes_snapshots_asserting_the_table_and_main(lab):
    cat = RestCatalog(lab.url, warehouse="lab")
    meta = cat.remove_snapshots("soc", "t", [1, 2, 3], main_snapshot_id=399, table_uuid="u-1")
    assert [s["snapshot-id"] for s in meta["snapshots"]][:2] == [4, 5] and len(
        meta["snapshots"]
    ) == 396


def test_a_moved_main_or_another_table_is_a_conflict_and_removes_nothing(lab):
    cat = RestCatalog(lab.url, warehouse="lab")
    with pytest.raises(CommitConflict):
        cat.remove_snapshots("soc", "t", [1], main_snapshot_id=5, table_uuid="u-1")
    with pytest.raises(CommitConflict):
        cat.remove_snapshots("soc", "t", [1], main_snapshot_id=399, table_uuid="other")
    assert len(lab.tables[("soc", "t")]["snapshots"]) == 399


def test_a_reply_over_the_cap_names_the_snapshot_count_and_the_cap_is_settable(lab):
    small = RestCatalog(lab.url, warehouse="lab", max_bytes=2048)
    with pytest.raises(LakeError, match=r"response larger than 2048 bytes.*at least \d+ snapshots"):
        small.load_table("soc", "t")
    assert len(RestCatalog(lab.url, warehouse="lab").load_table("soc", "t")["snapshots"]) == 399
