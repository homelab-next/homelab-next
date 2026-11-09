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


#: the swap whose standing half the lake-query promotion is: its selection diff moves the
#: lake-query slot from the incumbent's provider to the candidate's
SWAP = {
    "route": {
        "selection_diff": [
            {
                "slot": "lake-query",
                "instance": "lake-query",
                "from": "query-mod-a",
                "to": "query-mod-b",
            }
        ]
    }
}
MODS = {
    # the incumbent's product, as the example registry names it (read, not spelled here)
    "query-mod-a": {
        "product": {"name": load_doc(registry_text())["services"]["lake-query"]["impl"]}
    },
    "query-mod-b": {"product": {"name": "duckdb"}},
}


@pytest.fixture
def selection(monkeypatch):
    calls = []

    def fake(site, swap, mods, *, models=None):
        calls.append(site)
        return {"after": True}

    monkeypatch.setattr(ms, "apply_selection_diff", fake)
    return calls


def test_the_switch_applies_the_selection_diff_and_the_promotion_together(selection):
    text = _text()
    p = _plan(text)
    site, after = ms.apply_switch({"before": True}, SWAP, MODS, text, p)
    assert site == {"after": True} and selection == [{"before": True}]
    assert after == promote_text(text, p)  # the text, byte-exact, not a re-dumped document
    with pytest.raises(ValueError, match="standing promotion does not apply"):
        ms.apply_switch({"before": True}, SWAP, MODS, after, p)  # already switched: stale
    with pytest.raises(ValueError, match="not its inverse"):
        ms.apply_switch({"before": True}, SWAP, MODS, after, p.inverse())


def test_the_switch_refuses_a_promotion_of_another_capability_or_provider(selection):
    text = _idp_text()
    p = plan_promote(load_doc(text), "idp", "sso-next", "2026-11-08", 30, old_lab=True)
    with pytest.raises(ValueError, match="moves no idp line"):
        ms.apply_switch({}, SWAP, MODS, text, p)
    text = _text()
    p = _plan(text)
    other = {**MODS, "query-mod-b": {"product": {"name": "another-engine"}}}
    with pytest.raises(ValueError, match="query-b runs 'duckdb', not the incoming provider"):
        ms.apply_switch({}, SWAP, other, text, p)
    swapped = {**MODS, "query-mod-a": {"product": {"name": "another-engine"}}}
    with pytest.raises(ValueError, match=r"retiring row query-a runs '.+', not the outgoing"):
        ms.apply_switch({}, SWAP, swapped, text, p)
    assert selection == []  # neither half applied


def test_the_switch_refuses_a_tampered_plan(selection):
    """A plan read back with from_dict is not trusted: an extra change, or one altered, is
    refused before anything is applied."""
    text = _text()
    d = _plan(text).to_dict()
    extra = {
        **d,
        "changes": [
            *d["changes"],
            {
                "path": "services.query-a.owner",
                "before": "data-team",
                "after": "someone-else",
                "anchor": None,
            },
        ],
    }
    with pytest.raises(
        ValueError, match=r"changes services\.query-a\.owner, which no promotion touches"
    ):
        ms.apply_switch({}, SWAP, MODS, text, PromotePlan.from_dict(extra))
    longer = {**d, "until": "2027-06-01"}
    with pytest.raises(ValueError, match="not the one plan_promote computes"):
        ms.apply_switch({}, SWAP, MODS, text, PromotePlan.from_dict(longer))
    assert selection == []


# ---- review follow-up: an egress incumbent leaves primacy at the new primary's ceiling --------

NOTIFY_B = """  notify-b:
    capability: notify
    impl: other-notify
    host: lake-core-2
    protocol: http
    port: 8080
    owner: platform-team
    version: "1.0"
    tls: none
    auth: own
    tlp_ceiling: green
    standing: {tier: eval, until: "2026-12-31", why: the notify candidate}

"""


def _notify_text(ceiling: str | None = "amber") -> str:
    text = registry_text()
    old = "  notify:\n    capability: notify\n"
    assert old in text
    new = "  notify-a:\n    capability: notify\n"
    text = text.replace(old, new, 1)
    if ceiling:
        text = text.replace(
            "    tags: [ops, notify]\n", f"    tags: [ops, notify]\n    tlp_ceiling: {ceiling}\n", 1
        )
    return text.replace("  metrics:\n", NOTIFY_B + "  metrics:\n", 1)


@pytest.mark.parametrize("ceiling", ["amber", "green"])
def test_an_egress_incumbent_is_lowered_to_the_new_primary_s_ceiling(ceiling):
    """A retiring egress row may not sit above the primary's ceiling: an amber incumbent behind a
    green candidate made the registry refuse the promotion. It is stopped, so it takes the new
    primary's ceiling, and the inverse gives its own back; one already at it is not touched."""
    text = _notify_text(ceiling)
    p = plan_promote(load_doc(text), "notify", "notify-b", "2026-11-08", 14)
    after = promote_text(text, p)
    reg = loads(after)
    assert reg.by_capability("notify").name == "notify-b"
    assert reg.non_primary["notify-a"].tlp_ceiling == "green"
    lowered = "services.notify-a.tlp_ceiling" in {c.path for c in p.changes}
    assert lowered == (ceiling == "amber")
    assert promote_text(after, p.inverse()) == text
