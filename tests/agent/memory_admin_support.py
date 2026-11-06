# SPDX-License-Identifier: Apache-2.0
"""Shared setup for the retraction tests (ADR-0037 PR 3): an operators file and the operator
principal of the user running the tests, built the way ``hnx agent memory`` builds it."""

import json
import os
import pwd

#: uids the fake agent runtime and broker run as (never the test's own)
RUNTIME_UID, BROKER_UID = 4242, 4343


def operators_file(directory, users=None, **extra):
    """An operators file in ``directory`` listing ``users`` (by default the invoking user)."""
    me = pwd.getpwuid(os.getuid()).pw_name
    doc = {
        "operators": users or [me],
        "agent_runtime": [{"uid": RUNTIME_UID}],
        "broker": [{"uid": BROKER_UID}],
        **extra,
    }
    path = directory / "memory-operators.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    path.chmod(0o644)
    return path


def operator(directory):
    """The :class:`OperatorPrincipal` of the invoking user, from :func:`operators_file`."""
    from homelabnext.memory_admin.principal import invoking_operator, load_operators

    return invoking_operator(load_operators(operators_file(directory)))
