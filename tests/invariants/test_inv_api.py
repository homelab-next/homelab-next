# SPDX-License-Identifier: Apache-2.0
"""Registry registration semantics: a plugin reachable by two routes is registered once."""

import pytest

from homelabnext.invariants.api import Check, Registry


def test_same_plugin_registered_twice_is_idempotent_but_a_different_check_still_clashes():
    def same(ctx):
        return None

    def other(ctx):
        return None

    reg = Registry()
    first = reg.register(Check("X-99", "statement", same))
    assert reg.register(Check("X-99", "statement", same)) is first
    with pytest.raises(ValueError):
        reg.register(Check("X-99", "statement", other))
