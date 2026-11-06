# SPDX-License-Identifier: Apache-2.0
"""Shared setup for the retraction tests (ADR-0037 PR 3): an operators file and the operator
principal of the user running the tests, built the way ``hnx agent memory`` builds it.

CI does not run as root, so the test's own uid stands in for root's ownership
(``_ROOT_OWNERS``), and the directories above pytest's ``tmp_path`` (``/tmp`` may be
world-writable) are left out of the check by pointing ``_TRUST_ABOVE`` at the test's directory;
the rule itself is never relaxed."""

import contextlib
import json
import os
import pwd

#: uids the fake agent runtime and broker run as (never the test's own)
RUNTIME_UID, BROKER_UID = 4242, 4343


@contextlib.contextmanager
def trusted(directory):
    """Check ownership only up to ``directory`` for the ``with`` body."""
    from homelabnext.memory_admin import principal

    before = principal._TRUST_ABOVE, principal._ROOT_OWNERS
    # CI does not run as root: the test's own uid stands in for root's ownership
    principal._TRUST_ABOVE, principal._ROOT_OWNERS = directory, frozenset({0, os.getuid()})
    try:
        yield
    finally:
        principal._TRUST_ABOVE, principal._ROOT_OWNERS = before


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

    with trusted(directory):
        return invoking_operator(load_operators(operators_file(directory)))
