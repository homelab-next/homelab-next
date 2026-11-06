# SPDX-License-Identifier: Apache-2.0
"""The broker service is one facade over one module per privilege boundary: deciding and
auditing (service), the request lifecycle, the approver's verdicts, paging, and Code Mode tokens.
Each part is reviewable on its own only while its methods stay in its own module."""

from __future__ import annotations

import inspect

from homelabnext.broker import approvals, codemode_tokens, common, paging, requests, service

#: method -> the module that must define it (one per boundary; a sample of each)
OWNERS = {
    "call": requests,
    "submit": requests,
    "run": requests,
    "cancel": requests,
    "actions_for": requests,
    "approve": approvals,
    "deny": approvals,
    "approval_state": approvals,
    "pending": approvals,
    "poll_pages": paging,
    "lane_usage": paging,
    "_notify": paging,
    "issue_token": codemode_tokens,
    "token_call": codemode_tokens,
    "spend_token": codemode_tokens,
    "sweep_tokens": codemode_tokens,
    "_audit": service,
    "_admit": service,
    "_execute": service,
}

#: the most lines the facade module may grow back to (it was 2,654 before the split)
MAX_SERVICE_LINES = 1400


def test_each_boundary_lives_in_its_own_module():
    wrong = {
        name: getattr(service.BrokerService, name).__module__
        for name, mod in OWNERS.items()
        if getattr(service.BrokerService, name).__module__ != mod.__name__
    }
    assert not wrong, wrong


def test_no_part_defines_a_method_another_part_has():
    parts = [
        service.BrokerService.__dict__,
        *(
            vars(cls)
            for cls in service.BrokerService.__mro__[1:-1]  # the mixins, not object
        ),
    ]
    seen: dict[str, int] = {}
    for i, attrs in enumerate(parts):
        for name, value in attrs.items():
            if callable(value) and not name.startswith("__"):
                assert name not in seen, f"{name} is defined in two parts"
                seen[name] = i


def test_the_facade_still_exports_the_shared_names():
    for name in ("TRANSPORT_PEER", "REQUEST_DENIED", "DEFAULT_PENDING_PER_ACTOR", "_reasoned"):
        assert getattr(service, name) is getattr(common, name)
    assert service.check_approvals_url is approvals.check_approvals_url


def test_the_facade_module_stays_small():
    lines = len(inspect.getsource(service).splitlines())
    assert lines <= MAX_SERVICE_LINES, lines
