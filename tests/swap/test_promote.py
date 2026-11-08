# SPDX-License-Identifier: Apache-2.0
"""``plan_promote``: the standing half of a switch (ADR-0039 decision 6, step 7).  The eval row
becomes the primary, the incumbent retiring (or legacy, for an old-lab product) until the switch
date plus the ledger's rollback window, as one diff whose inverse is exact; ``plan_flip`` no
longer changes the product behind a capability that has a non-primary row."""

from __future__ import annotations

import datetime as dt

import pytest
from support import registry_text

from homelabnext.modules import swap as ms
from homelabnext.registry import loads
from homelabnext.swap import FlipError, PromotePlan, plan_flip, plan_promote, promote_text
from homelabnext.swap.flip import load_doc

#: the candidate query engine, an eval row on the second lake host
CANDIDATE = """  query-b:
    capability: lake-query
    impl: duckdb
    host: lake-core-2
    protocol: https
    port: 8443
    health: {kind: http, path: /v1/info, expect_status: 200}
    upstreams: [lake-catalog, object-store]
    owner: data-team
    version: "1.5"
    tls: internal
    auth: idp
    standing: {tier: eval, until: "2026-12-31", why: the query engine candidate}

"""

#: the old lab's sign-in, beside the repository's IdP as its candidate
OLD_IDP = """  sso-next:
    capability: idp
    impl: keycloak
    host: lake-core-2
    protocol: https
    port: 8443
    health: {kind: http, path: /health/ready, expect_status: 200}
    clients: [edge, data, compute]
    owner: identity-team
    version: "26.8.1"
    tls: internal
    auth: own
    standing: {tier: eval, until: "2026-12-31", why: the sign-in candidate}

"""


def _text() -> str:
    """The example registry, its query row renamed (a retiring row may not be named like a
    capability) and a candidate beside it."""
    text = registry_text()
    old = "  lake-query:\n    capability: lake-query\n"
    assert old in text
    text = text.replace(old, "  query-a:\n    capability: lake-query\n", 1)
    return text.replace("  records-db:\n", CANDIDATE + "  records-db:\n", 1)


def _idp_text() -> str:
    return registry_text().replace("  records-db:\n", OLD_IDP + "  records-db:\n", 1)


def _plan(text: str | None = None, **kw) -> PromotePlan:
    return plan_promote(load_doc(text or _text()), "lake-query", "query-b", "2026-11-08", 14, **kw)


def test_promote_makes_the_eval_row_primary_and_retires_the_incumbent_until_the_window_ends():
    text = _text()
    p = _plan(text)
    reg = loads(promote_text(text, p))
    assert reg.by_capability("lake-query").name == "query-b"
    retired = reg.non_primary["query-a"]
    assert (retired.standing, retired.until) == ("retiring", "2026-11-22")  # 2026-11-08 + 14 days
    assert p.until == "2026-11-22" and p.incumbent == "query-a"
    assert p.diff() == (
        "promote query-b to primary of lake-query (switched 2026-11-08, rollback window 14 days, "
        "until 2026-11-22)\n"
        '  services.query-b.standing: {tier: eval, until: "2026-12-31", why: the query engine '
        "candidate} -> (absent)\n"
        '  services.query-a.standing: (absent) -> {tier: retiring, until: "2026-11-22", why: '
        "replaced by query-b on 2026-11-08; stopped and kept restorable for its rollback window}\n"
    )


def test_promote_then_its_inverse_is_byte_identical():
    text = _text()
    p = _plan(text)
    after = promote_text(text, p)
    assert after != text
    assert promote_text(after, p.inverse()) == text
    assert p.inverse().apply(p.apply(load_doc(text))) == load_doc(text)
    assert p.inverse().inverse() == p
    assert PromotePlan.from_dict(p.to_dict()) == p


def test_an_old_lab_incumbent_goes_legacy_and_hands_over_its_public_route():
    """The IdP row is named like its capability, which a legacy row may be; its public route is a
    primary's and moves to the new primary, and the inverse puts it back where it was."""
    text = _idp_text()
    p = plan_promote(load_doc(text), "idp", "sso-next", dt.date(2026, 11, 8), 30, old_lab=True)
    after = promote_text(text, p)
    reg = loads(after)
    assert reg.by_capability("idp").name == "sso-next"
    assert reg.by_capability("idp").public_hostname == "login.lab.example"
    old = reg.non_primary["idp"]
    assert (old.standing, old.until, old.public_hostname) == ("legacy", "2026-12-08", None)
    assert promote_text(after, p.inverse()) == text


def test_a_retiring_incumbent_named_like_its_capability_is_refused():
    with pytest.raises(FlipError, match="rename the row"):
        plan_promote(load_doc(_idp_text()), "idp", "sso-next", "2026-11-08", 14)


def test_a_promote_that_would_leave_the_capability_without_a_primary_is_refused():
    doc = load_doc(_text())
    with pytest.raises(FlipError, match="leave lake-query with no primary"):
        plan_promote(doc, "lake-query", "events", "2026-11-08", 14)
    with pytest.raises(FlipError, match="only an eval row is promoted"):
        plan_promote(doc, "lake-query", "query-a", "2026-11-08", 14)


def test_a_promote_that_would_leave_two_primaries_is_refused():
    """A plan made before a second primary appeared cannot be applied over it."""
    p = _plan()
    doc = load_doc(_text())
    # the incumbent is the primary the plan retires; the registry has since grown a twin primary
    # and moved the incumbent aside, so applying the old plan would leave two
    doc["services"]["query-a"]["capability"] = "lake-query-twin"
    doc["services"]["query-c"] = dict(
        doc["services"]["query-a"], capability="lake-query", host="lake-core-2", port=9443
    )
    doc["services"]["query-c"].pop("mcp", None)
    with pytest.raises(FlipError, match="lake-query has two primaries: query-b, query-c"):
        p.apply(doc)


def test_inputs_are_checked():
    doc = load_doc(_text())
    with pytest.raises(FlipError, match="rollback_days"):
        plan_promote(doc, "lake-query", "query-b", "2026-11-08", 0)
    with pytest.raises(FlipError, match="not a date"):
        plan_promote(doc, "lake-query", "query-b", "8 Nov", 14)
    with pytest.raises(FlipError, match="not a time"):
        plan_promote(doc, "lake-query", "query-b", dt.datetime(2026, 11, 8, tzinfo=dt.UTC), 14)
    with pytest.raises(FlipError, match="no service"):
        plan_promote(doc, "lake-query", "nope", "2026-11-08", 14)


def test_a_stale_promotion_is_refused():
    text = _text()
    p = _plan(text)
    with pytest.raises(FlipError, match="changed since the plan"):
        p.apply(p.apply(load_doc(text)))


def test_plan_flip_refuses_an_impl_change_beside_a_non_primary_row():
    doc = load_doc(_text())
    with pytest.raises(FlipError, match=r"non-primary row \(query-b\).*plan_promote"):
        plan_flip(doc, "query-a", impl="duckdb")
    # moving the same product is still a flip
    assert not plan_flip(doc, "query-a", version="485.0").empty
    # and a capability with no other row still flips its impl
    assert plan_flip(load_doc(registry_text()), "lake-query", impl="duckdb").changes


def test_the_switch_applies_the_selection_diff_and_the_promotion_together(monkeypatch):
    calls = []

    def selection(site, swap, mods, *, models=None):
        calls.append(site)
        return {"after": True}

    monkeypatch.setattr(ms, "apply_selection_diff", selection)
    text = _text()
    p = _plan(text)
    site, reg = ms.apply_switch({"before": True}, {}, {}, load_doc(text), p)
    assert site == {"after": True} and calls == [{"before": True}]
    assert reg == p.apply(load_doc(text))
    with pytest.raises(ValueError, match="standing promotion does not apply"):
        ms.apply_switch({"before": True}, {}, {}, reg, p)  # already switched: stale
    with pytest.raises(ValueError, match="not its inverse"):
        ms.apply_switch({"before": True}, {}, {}, reg, p.inverse())
