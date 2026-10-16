# SPDX-License-Identifier: Apache-2.0
"""Conformance test for the lake-query capability.

Runs the suite one check at a time against ``$HNX_CONFORM_TARGET`` (default: the in-memory
fake).  Point it at a real service with a target file, see docs/conformance.md.
"""

import pytest

from homelabnext.conform import testing

CAPABILITY = "lake-query"


@pytest.mark.parametrize("check_id", testing.check_ids(CAPABILITY))
def test_lake_query(check_id):
    testing.assert_check(CAPABILITY, check_id)
