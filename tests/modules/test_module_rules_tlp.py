# SPDX-License-Identifier: Apache-2.0
"""``rules.dataset_label``: a dataset's TLP declaration (ADR-0033 decisions 2 and 3)."""

import pytest

from homelabnext.modules import rules
from homelabnext.tlp import Label


def test_a_dataset_without_a_declaration_is_red_and_not_honoured():
    assert rules.dataset_label({"id": "sessions"}) == (Label.RED, False)


@pytest.mark.parametrize(
    "ds, want",
    [
        ({"tlp": "clear"}, (Label.CLEAR, False)),
        ({"tlp": "amber+strict"}, (Label.AMBER_STRICT, False)),
        ({"tlp": "green", "honour_item_labels": True}, (Label.GREEN, True)),
        ({"tlp": "green", "honour_item_labels": False}, (Label.GREEN, False)),
        ({"honour_item_labels": True}, (Label.RED, True)),
        # only True honours
        ({"tlp": "amber", "honour_item_labels": "yes"}, (Label.AMBER, False)),
        ({"tlp": "amber", "honour_item_labels": 1}, (Label.AMBER, False)),
    ],
)
def test_the_declaration_and_the_trust(ds, want):
    assert rules.dataset_label(ds) == want


@pytest.mark.parametrize("bad", ["black", "", None, "amber-strict"])
def test_a_declaration_that_is_not_a_label_is_refused(bad):
    with pytest.raises(ValueError, match="not a TLP label"):
        rules.dataset_label({"tlp": bad})
