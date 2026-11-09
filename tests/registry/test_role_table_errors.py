# SPDX-License-Identifier: Apache-2.0
"""A file read as a role table that is not one (a JSON credentials file a spec's ``roles:`` was
pointed at, say) has none of its values, and no key that is not a plain name, echoed by the
error that refuses it: the message names the rule and the schema's expectation only."""

from __future__ import annotations

import json

import pytest

from homelabnext.registry.models import RoleTable, RoleTableError

SECRET = "AKIAEXAMPLESECRETVALUE0"


@pytest.mark.parametrize(
    "doc",
    [
        {"AWS_SECRET_ACCESS_KEY": SECRET, "version": SECRET},
        {"version": 1, "roles": {SECRET: {"tier": "large", "bindings": []}}},
        {"version": 1, "roles": {"r": {"tier": SECRET, "bindings": [{"backend": SECRET}]}}},
        {"version": 1, "roles": {"r": {"tier": "large", "bindings": []}}, SECRET: 1},
    ],
)
def test_a_refused_role_table_echoes_no_value_and_no_odd_key(doc):
    with pytest.raises(RoleTableError) as caught:
        RoleTable.loads(json.dumps(doc))
    told = str(caught.value) + " ".join(getattr(caught.value, "problems", None) or [])
    assert SECRET not in told
    assert "AWS_SECRET_ACCESS_KEY" not in told
