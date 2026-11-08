# SPDX-License-Identifier: Apache-2.0
"""A site's service references by tier (ADR-0039 decision 2, step 3).

An ``eval`` or ``retiring`` row answers by its own row name, so a service exception (the shadow
lane's and the conformance targets' way through the firewall) may name one; every other site
reference (a zone's resolvers, the router's management endpoint, a resolver host) is something the
site uses and names a primary.  A ``legacy`` row is never named.  The site's DNS records give an
eval or retiring row its row-name record and a legacy row none."""

from __future__ import annotations

import copy

import pytest
import yaml
from netutil import REGISTRY

from homelabnext.network import build_ir, validate
from homelabnext.registry.model import build_registry

UNTIL = {"until": "2026-12-31", "why": "under test"}


def _registry():
    doc = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    base = doc["services"]["idp"]
    for name, tier, port in (("idp-cand", "eval", 8443), ("idp-prev", "retiring", 8444),
                             ("idp-old", "legacy", 8445)):  # fmt: skip
        row = copy.deepcopy(base)
        row.pop("public_hostname")
        row.update(port=port, standing={"tier": tier, **UNTIL})
        doc["services"][name] = row
    dns = copy.deepcopy(doc["services"]["dns"])
    dns.update(port=5353, standing={"tier": "eval", **UNTIL})
    doc["services"]["dns-cand"] = dns
    return build_registry(doc)


REG = _registry()


def _exception(doc, to):
    doc["firewall"]["service_exceptions"].append(
        {"from": "zone:compute", "to": f"svc:{to}", "action": "allow"}
    )
    return doc


@pytest.mark.parametrize("row", ["idp-cand", "idp-prev"])
def test_a_service_exception_may_name_an_eval_or_retiring_row(doc, row):
    rep = validate(_exception(doc, row), REG)
    assert rep.ok, rep.errors
    rule = next(r for r in build_ir(doc, REG).policy.rules if r.service == row)
    assert rule.dst.cidrs == (REG.hosts["idp-core"].address + "/32",) and rule.ports == (
        REG.non_primary[row].port,
    )


def test_a_service_exception_may_not_name_a_legacy_row(doc):
    errs = validate(_exception(doc, "idp-old"), REG).errors
    assert any("svc:idp-old is a legacy row; only a primary, eval or retiring row" in e
               for e in errs), errs  # fmt: skip


@pytest.mark.parametrize(
    "mutate,where",
    [
        (lambda d: d["router"].update(mgmt_endpoint="svc:idp-cand"), "router.mgmt_endpoint"),
        (lambda d: d["dns"]["resolvers"][0].update(host="svc:dns-cand"), "dns.resolvers"),
        (lambda d: next(z for z in d["zones"] if z.get("dns", {}).get("resolvers"))["dns"].update(
            resolvers=["svc:dns-cand"]), "dns resolver"),
    ],
)  # fmt: skip
def test_what_the_site_uses_names_a_primary(doc, mutate, where):
    mutate(doc)
    errs = validate(doc, REG).errors
    assert any(where in e and "is an eval row; only a primary row may be named here" in e
               for e in errs), errs  # fmt: skip


def test_site_dns_records_give_a_row_its_own_name_and_a_legacy_row_none(doc):
    records = {r.fqdn: r for r in build_ir(doc, REG).dns_records if r.origin == "registry.service"}
    assert records["idp.svc.example.internal"].value == "idp-core.example.internal"
    assert records["idp-cand.svc.example.internal"].value == "idp-core.example.internal"
    assert records["idp-prev.svc.example.internal"].value == "idp-core.example.internal"
    assert not [f for f in records if f.startswith("idp-old.")]
    assert sum(1 for f in records if f.startswith("idp.")) == 1


def test_build_ir_refuses_an_unvalidated_exception_to_a_legacy_row(doc):
    """build_ir runs on a validated site; one that skipped validation fails with the reason,
    not with an attribute error on a missing row."""
    with pytest.raises(ValueError, match=r"svc:idp-old is no primary, eval or retiring row"):
        build_ir(_exception(doc, "idp-old"), REG)
