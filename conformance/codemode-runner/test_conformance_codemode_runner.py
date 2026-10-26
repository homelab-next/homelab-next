# SPDX-License-Identifier: Apache-2.0
"""Conformance test for the codemode-runner capability (the handler of codemode.execute, an
extended suite).

Runs the suite one check at a time against ``$HNX_CONFORM_TARGET`` (default: the reference
runner over the in-memory broker).  Point it at another target with a target file, see
docs/conformance.md.
"""

import pytest

from homelabnext.conform import testing

CAPABILITY = "codemode-runner"


@pytest.mark.parametrize("check_id", testing.check_ids(CAPABILITY))
def test_codemode_runner(check_id):
    testing.assert_check(CAPABILITY, check_id)


def test_codemode_runner_enough_checks_executed():
    testing.assert_enough_executed(CAPABILITY)
