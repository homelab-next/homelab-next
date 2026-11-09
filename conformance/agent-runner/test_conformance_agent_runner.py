# SPDX-License-Identifier: Apache-2.0
"""Conformance test for the agent-runner capability (the agent-runtime slot's contract,
ADR-0051), an extended suite of ``homelabnext.conform.registry.EXTENDED``.

Runs the suite one check at a time against ``$HNX_CONFORM_TARGET`` (default: the reference fake
runtime under the development launcher). Point it at another target with a target file, see
docs/conformance.md.
"""

import pytest

from homelabnext.conform import testing

CAPABILITY = "agent-runner"


@pytest.mark.parametrize("check_id", testing.check_ids(CAPABILITY))
def test_agent_runner(check_id):
    testing.assert_check(CAPABILITY, check_id)


def test_agent_runner_enough_checks_executed():
    testing.assert_enough_executed(CAPABILITY)
