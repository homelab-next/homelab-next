# SPDX-License-Identifier: Apache-2.0
"""Conformance test for the detections capability.

Runs the suite one check at a time against ``$HNX_CONFORM_TARGET`` (default: the in-memory
fake).  Point it at a real service with a target file, see docs/conformance.md.
"""

import pytest

from homelabnext.conform import testing

CAPABILITY = "detections"


@pytest.mark.parametrize("check_id", testing.check_ids(CAPABILITY))
def test_detections(check_id):
    testing.assert_check(CAPABILITY, check_id)


def test_detections_enough_checks_executed():
    testing.assert_enough_executed(CAPABILITY)
