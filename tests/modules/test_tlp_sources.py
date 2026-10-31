# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.modules.tlp_sources``: the source table from the site's selection (ADR-0033)."""

import copy

import pytest

from homelabnext.logpipeline import SourceTable, SourceTableError
from homelabnext.modules import tlp_sources

MODS = {
    "feeds": {
        "kind": "feature",
        "data": [
            {"id": "open", "tlp": "clear"},
            {"id": "community", "tlp": "green", "honour_item_labels": True},
            {"id": "undeclared"},
        ],
    },
    "unselected": {"kind": "feature", "data": [{"id": "x", "tlp": "clear"}]},
    "core-x": {"kind": "core", "data": [{"id": "log"}]},
}
SITE = {"slots": {}, "features": {"feeds": {}}}


def test_every_dataset_of_every_selected_module_is_a_source():
    doc = tlp_sources.render(SITE, MODS)
    assert {k: (v["tlp"], v["honour_item_labels"]) for k, v in doc["sources"].items()} == {
        "core-x/log": ("red", False),
        "feeds/community": ("green", True),
        "feeds/open": ("clear", False),
        "feeds/undeclared": ("red", False),
    }
    SourceTable.from_doc(doc)  # what render writes, the pipeline loads


def test_a_module_the_site_does_not_select_is_not_a_source():
    assert "unselected/x" not in tlp_sources.render(SITE, MODS)["sources"]


def test_an_unreadable_selection_or_declaration_is_refused():
    with pytest.raises(SourceTableError, match="selection"):
        tlp_sources.render({"features": {"feeds": {}}}, MODS)
    bad = copy.deepcopy(MODS)
    bad["feeds"]["data"][0]["tlp"] = "black"
    with pytest.raises(ValueError, match="not a TLP label"):
        tlp_sources.render(SITE, bad)


def test_write(tmp_path):
    tlp_sources.write(tlp_sources.render(SITE, MODS), tmp_path / "out")
    assert SourceTable.load(tmp_path / "out" / tlp_sources.FILE).lookup("feeds/open") is not None
