# SPDX-License-Identifier: Apache-2.0
"""``provider_for(slot, instance)`` (ADR-0027 decision 9; homelabnext.modules.providers): the site
selection answers which module serves a slot instance, ``hnx modules providers`` lists each with
its product and licence, and ``hnx modules check`` refuses a core registry whose ``impl:``
disagrees with the selection."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.modules.providers import (
    ProviderLookupError,
    provider_for,
    providers,
    registry_impl_problems,
)

ROOT = Path(__file__).resolve().parents[2]
SITES = ROOT / "examples" / "modules" / "sites"


@pytest.fixture(scope="module")
def mods():
    tree, _ = ld.discover(ROOT / "modules", ROOT / "examples" / "modules", None, ld.Budget())
    return tree.mods


def _product(mods, mid):
    """A provider's product name, read from its manifest (tests name slots, not products)."""
    return mods[mid]["product"]["name"]


def _site(name="full"):
    return yaml.safe_load((SITES / f"{name}.yml").read_text(encoding="utf-8"))


def test_a_slot_instance_resolves_to_its_provider_product_and_licence(mods):
    p = provider_for(_site(), mods, "cap:object-store", "samples")
    assert (p.module, p.product) == ("other-object-store", _product(mods, "other-object-store"))
    assert p.version == mods["other-object-store"]["product"]["version"]
    assert (p.licence_kind, p.licence_spdx, p.licence) == ("subscription", None, "subscription")
    p = provider_for(_site(), mods, "object-store", "objects")
    assert (p.module, p.licence) == ("example-object-store", "open-source Apache-2.0")


def test_one_instance_needs_no_name_and_none_resolves_to_nothing(mods):
    assert provider_for(_site(), mods, "secrets").module == "example-platform"
    assert provider_for(_site(), mods, "cases") is None  # the site selects none
    assert provider_for(_site("small-lab"), mods, "log-pipeline") is None  # pass-through


@pytest.mark.parametrize(
    ("slot", "instance", "why"),
    [
        ("object-store", None, "several instances are selected"),
        ("object-store", "nope", "the site selects no such instance"),
        ("teleporter", None, "does not name this slot"),
    ],
)
def test_a_lookup_the_selection_cannot_answer_is_refused_never_guessed(mods, slot, instance, why):
    with pytest.raises(ProviderLookupError, match=why):
        provider_for(_site(), mods, slot, instance)


def test_providers_lists_every_selected_instance_once(mods):
    site = _site()
    rows = providers(site, mods)
    want = sorted(
        (s, c["instance"]) for s, v in site["slots"].items() if isinstance(v, list) for c in v
    )
    assert [(p.slot, p.instance) for p in rows] == want


def _registry(**rows):
    return {"services": {n: {"capability": c, "impl": i} for n, (c, i) in rows.items()}}


def test_the_registry_impl_must_be_a_selected_providers_product(mods):
    site = _site()
    one, two = _product(mods, "example-object-store"), _product(mods, "other-object-store")
    good = _registry(objects=("object-store", one), blobs=("object-store", two))
    assert registry_impl_problems(site, mods, good) == []
    # an alias of the product is the product
    (alias,) = mods["example-object-store"]["product"]["aliases"]
    assert registry_impl_problems(site, mods, _registry(o=("object-store", alias))) == []
    # a slot the selection does not name is not judged
    assert registry_impl_problems(site, mods, _registry(x=("teleporter", "anything"))) == []
    stale = _registry(objects=("object-store", "retired-objects"))
    (p,) = registry_impl_problems(site, mods, stale)
    assert p.startswith("services.objects: impl 'retired-objects' is not the product of a provider")
    assert f"({one}, {two})" in p


def test_a_registry_row_for_a_slot_the_site_turned_off_is_a_problem(mods):
    (p,) = registry_impl_problems(_site(), mods, _registry(c=("cases", "old-cases")))
    assert p == (
        "services.c: capability cases is none in the site selection, but the registry still "
        "runs impl 'old-cases'"
    )


def test_check_refuses_a_given_registry_that_disagrees_with_the_selection(tmp_path, capsys):
    """Negative: with a registry that is the lab's own (--services, or the overlay's), a row
    naming a product no selected provider ships is a registry problem; with the repository's
    example registry (another lab) the comparison is a note, not a problem."""
    reg = yaml.safe_load((ROOT / "examples/services.yml").read_text(encoding="utf-8"))
    reg = copy.deepcopy(reg)
    reg["services"] = {
        "objects": {**next(iter(reg["services"].values())), "capability": "object-store"}
    }
    reg["services"]["objects"]["impl"] = "retired-objects"
    path = tmp_path / "services.yml"
    path.write_text(yaml.safe_dump(reg, sort_keys=False), encoding="utf-8")
    site = str(SITES / "full.yml")
    mcli.main(
        [
            "check",
            "--root",
            str(ROOT),
            "--examples",
            "--site",
            site,
            "--services",
            str(path),
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert any(
        p.startswith("registry: services.objects: impl 'retired-objects' is not the product")
        for p in out["problems"]
    ), out["problems"]
    rc = mcli.main(["check", "--root", str(ROOT), "--examples", "--site", site, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0, out["problems"]
    assert any("impl: was not compared with the site selection" in n for n in out["notes"])


def test_the_providers_command_prints_each_instance_with_its_licence(mods, capsys):
    rc = mcli.main(
        ["providers", "--root", str(ROOT), "--examples", "--site", str(SITES / "full.yml")]
    )
    out = capsys.readouterr().out.splitlines()
    assert rc == 0
    product = mods["other-object-store"]["product"]
    assert (
        f"object-store/samples: other-object-store ({product['name']} {product['version']}; "
        "licence subscription)"
    ) in out
    assert "cases: none" in out
    rc = mcli.main(
        [
            "providers",
            "--root",
            str(ROOT),
            "--examples",
            "--site",
            str(SITES / "full.yml"),
            "--json",
        ]
    )
    doc = json.loads(capsys.readouterr().out)
    row = next(r for r in doc["providers"] if r["instance"] == "objects")
    assert row["licence"] == {"kind": "open-source", "spdx": "Apache-2.0"}
    assert doc["unserved"] == {"cases": "none"}


def test_the_providers_command_refuses_a_provider_without_a_manifest(tmp_path, capsys):
    site = _site()
    site["slots"]["dns"] = [{"provider": "missing-module", "instance": "platform"}]
    path = tmp_path / "site.yml"
    path.write_text(yaml.safe_dump(site, sort_keys=False), encoding="utf-8")
    rc = mcli.main(["providers", "--root", str(ROOT), "--examples", "--site", str(path)])
    assert rc == 2
    assert "missing-module has no manifest" in capsys.readouterr().err
