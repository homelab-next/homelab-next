# SPDX-License-Identifier: Apache-2.0
"""Registry equality (H4; docs/modules/registry-rows.md, "Registry rows: checked, not generated"):
every service row a selected module contributes appears in the lab registry identically, as the
site binds it (a provider's row renamed to the instance with its product's version, ``host``
the placed guest), and every difference is named, field by field."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.modules import registry_rows as rr
from homelabnext.modules import rules as mr

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
SITE = ld.load_yaml(EXAMPLES / "sites" / "small-lab.yml")
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
CORE, _ = ld.core_names(ld.load_yaml(ROOT / "examples" / "services.yml"))
TREE, _FOUND = ld.discover(fixtures=EXAMPLES)
ROWS = ld.inputs(TREE).rows
STORE = "example-object-store"
COLLECTOR = "external-collector"
STORE_ROW = ld.load_yaml(EXAMPLES / STORE / "registry" / "services.yml")["services"]["object-store"]
COLLECTOR_ROW = ld.load_yaml(EXAMPLES / COLLECTOR / "registry" / "services.yml")["services"][
    "external-collector-receiver"
]
STORE_VERSION = str(TREE.mods[STORE]["product"]["version"])


def lab_registry() -> dict:
    """The small-lab's rows written out by hand, as an operator copies them: the store's row
    renamed to its instance (samples) with the product's version and the placed host (data);
    the collector's row keeps its name, its host role receiver placed on data."""
    samples = {**copy.deepcopy(STORE_ROW), "host": "data", "version": STORE_VERSION}
    receiver = {**copy.deepcopy(COLLECTOR_ROW), "host": "data"}
    return {"services": {"samples": samples, "external-collector-receiver": receiver}}


def problems(site=SITE, registry=None) -> list[str]:
    sel = mr.selected(site, TREE.mods)
    return rr.row_problems(site, sel, ROWS, lab_registry() if registry is None else registry)


def test_the_examples_load():
    assert _FOUND == []


def test_a_registry_that_carries_every_row_as_bound_is_clean():
    assert problems() == []


def test_the_expected_rows_are_bound_by_the_site():
    sel = mr.selected(SITE, TREE.mods)
    got = {e.name: e for e in rr.expected_rows(SITE, sel, ROWS)}
    assert set(got) == {"samples", "external-collector-receiver"}
    assert got["samples"].source == "object-store"
    assert got["samples"].row["host"] == "data"
    assert got["samples"].row["version"] == STORE_VERSION
    assert got["external-collector-receiver"].row["host"] == "data"


def test_a_missing_row_is_named_with_its_module_and_source_row():
    reg = lab_registry()
    del reg["services"]["samples"]
    assert problems(registry=reg) == [
        f"services.samples: {STORE} (instance samples) contributes this row (its row "
        "object-store), but the lab registry has no such row (copy it as the site binds it)"
    ]


def test_every_differing_field_is_named():
    reg = lab_registry()
    row = reg["services"]["samples"]
    row["port"] = 9001
    row["health"] = {"kind": "tcp"}
    del row["tags"]
    row["description"] = "added by hand"
    got = problems(registry=reg)
    who = f"{STORE} (instance samples)"
    assert got == [
        f"services.samples.description: {who} contributes (absent) (its row object-store), the "
        'lab registry has "added by hand"',
        f'services.samples.health: {who} contributes {{"kind": "http", "path": "/health/live"}} '
        '(its row object-store), the lab registry has {"kind": "tcp"}',
        f"services.samples.port: {who} contributes 9000 (its row object-store), the lab "
        "registry has 9001",
        f'services.samples.tags: {who} contributes ["storage"] (its row object-store), the lab '
        "registry has (absent)",
    ]


def test_the_host_must_be_the_placed_host():
    reg = lab_registry()
    reg["services"]["external-collector-receiver"]["host"] = "core"
    assert problems(registry=reg) == [
        'services.external-collector-receiver.host: external-collector contributes "data", the '
        'lab registry has "core"'
    ]


def test_a_host_that_references_a_guest_is_the_guest_s_name():
    site = copy.deepcopy(SITE)
    site["hosts"]["data"] = {"guest": "guest:apps-01"}
    reg = lab_registry()
    assert sorted(problems(site, reg)) == [
        'services.external-collector-receiver.host: external-collector contributes "apps-01", '
        'the lab registry has "data"',
        f'services.samples.host: {STORE} (instance samples) contributes "apps-01" (its row '
        'object-store), the lab registry has "data"',
    ]
    for r in reg["services"].values():
        r["host"] = "apps-01"
    assert problems(site, reg) == []


def test_a_provider_row_takes_the_product_version():
    reg = lab_registry()
    reg["services"]["samples"]["version"] = "0.0.1"
    got = problems(registry=reg)
    assert got == [
        f'services.samples.version: {STORE} (instance samples) contributes "{STORE_VERSION}" '
        '(its row object-store), the lab registry has "0.0.1"'
    ]


def test_an_unquoted_version_equal_as_text_is_the_same():
    reg = lab_registry()
    reg["services"]["external-collector-receiver"]["version"] = "0.2.0"
    site_row = reg["services"]["samples"]
    site_row["version"] = yaml.safe_load(STORE_VERSION)  # what an unquoted YAML value reads as
    assert problems(registry=reg) == []


def test_the_lab_s_own_fields_are_not_the_module_s():
    reg = lab_registry()
    row = reg["services"]["samples"]
    row["standing"] = {"tier": "eval", "until": "2027-01-31", "why": "a candidate under test"}
    row["backup_job"] = "nightly"
    row["scope"] = "out"
    assert problems(registry=reg) == []


def test_clients_the_registry_adds_is_a_difference():
    """Extra zones widen who may reach the service: never the lab's alone to add."""
    reg = lab_registry()
    reg["services"]["samples"]["clients"] = ["mgmt"]
    assert problems(registry=reg) == [
        f"services.samples.clients: {STORE} (instance samples) contributes (absent) (its row "
        'object-store), the lab registry has ["mgmt"]'
    ]


def test_a_lab_field_the_module_sets_is_compared():
    rows = copy.deepcopy(ROWS)
    rows[COLLECTOR]["external-collector-receiver"]["scope"] = "out"
    sel = mr.selected(SITE, TREE.mods)
    got = rr.row_problems(SITE, sel, rows, lab_registry())
    assert got == [
        'services.external-collector-receiver.scope: external-collector contributes "out", '
        "the lab registry has (absent)"
    ]


def test_an_unplaced_host_role_is_a_problem_and_the_rest_is_still_compared():
    site = copy.deepcopy(SITE)
    del site["features"][COLLECTOR]["placement"]["receiver"]
    reg = lab_registry()
    reg["services"]["external-collector-receiver"]["port"] = 1
    assert problems(site, reg) == [
        "services.external-collector-receiver: external-collector's host role receiver is "
        "placed on no site host, so the registry row's host cannot be compared",
        "services.external-collector-receiver.port: external-collector contributes 8443, the lab "
        "registry has 1",
    ]


def test_each_instance_of_a_provider_is_its_own_row():
    site = copy.deepcopy(SITE)
    site["slots"]["object-store"].append(
        {"provider": STORE, "instance": "archive", "placement": {"store": "core"}}
    )
    reg = lab_registry()
    assert problems(site, reg) == [
        f"services.archive: {STORE} (instance archive) contributes this row (its row "
        "object-store), but the lab registry has no such row (copy it as the site binds it)"
    ]
    reg["services"]["archive"] = {**reg["services"]["samples"], "host": "core"}
    assert problems(site, reg) == []


def test_a_slot_the_site_answers_none_contributes_no_row():
    site = copy.deepcopy(SITE)
    site["slots"]["object-store"] = "none"
    reg = lab_registry()
    del reg["services"]["samples"]
    assert problems(site, reg) == []


def test_a_planted_value_is_printed_escaped_and_cut():
    reg = lab_registry()
    reg["services"]["samples"]["owner"] = "x\n::error::" + "y" * 400
    (got,) = problems(registry=reg)
    assert "\n" not in got and "\\n::error::" in got
    assert got.endswith('..."') or got.endswith("...")
    assert len(got) < 400


def test_an_unplaced_role_never_reads_as_a_host_mismatch():
    site = copy.deepcopy(SITE)
    del site["slots"]["object-store"][0]["placement"]
    got = problems(site)
    assert not [p for p in got if ".host:" in p], got
    assert got == [
        f"services.samples: {STORE} (instance samples)'s host role store is placed on no site "
        "host, so the registry row's host cannot be compared"
    ]


@pytest.mark.parametrize(
    "line",
    [
        "not-a-line",
        {"provider": ["x"], "instance": "samples"},
        {"provider": STORE, "instance": "samples", "placement": ["store"]},
        {"provider": STORE, "instance": "samples", "placement": {"store": ["data"]}},
    ],
)
def test_a_malformed_selection_line_is_never_a_crash(line):
    site = copy.deepcopy(SITE)
    site["slots"]["object-store"] = [line]
    sel = {**mr.selected(SITE, TREE.mods)}
    assert isinstance(rr.row_problems(site, sel, ROWS, lab_registry()), list)


def test_a_provider_row_that_repeats_its_version_is_refused(tmp_path):
    import shutil

    root = tmp_path / "fixtures"
    shutil.copytree(EXAMPLES, root)
    f = root / STORE / "registry" / "services.yml"
    doc = yaml.safe_load(f.read_text())
    doc["services"]["object-store"]["version"] = "9.9.9"
    f.write_text(yaml.safe_dump(doc))
    tree, _ = ld.discover(fixtures=root)
    report = ld.check(tree, slots=SLOTS, roles={}, in_tree_roots=(root,), core=CORE)
    assert (
        f"{STORE}: registry/services.yml: object-store: a provider's row takes its version from "
        "product.version" in [str(p) for p in report.problems]
    )


def test_a_registry_without_services_is_one_problem():
    assert problems(registry={"hosts": {}}) == [
        "the lab registry has no services mapping: no contributed row could be compared"
    ]


# ----------------------------------------------------------------------------- through the loader


def check(**kw):
    return ld.check(
        TREE, slots=SLOTS, roles={}, in_tree_roots=(EXAMPLES,), core=CORE, site=SITE, **kw
    )


def test_the_loader_reports_registry_rows_under_registry():
    reg = lab_registry()
    reg["services"]["samples"]["port"] = 9001
    got = [str(p) for p in check(lab_registry=reg).problems if p.where == "registry"]
    assert len(got) == 1 and got[0].startswith("registry: services.samples.port:")


def test_without_a_lab_registry_the_loader_says_the_rows_were_not_compared():
    report = check()
    assert not [p for p in report.problems if p.where == "registry"]
    assert any(
        n.startswith("the selected modules' service rows were not compared") for n in report.notes
    )


# ----------------------------------------------------------------------------- the CLI


def _registry_file(tmp_path: Path, extra: dict) -> Path:
    doc = ld.load_yaml(ROOT / "examples" / "services.yml")
    doc["services"].update(extra)
    p = tmp_path / "services.yml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


def _cli(capsys, services: Path) -> tuple[int, str]:
    code = mcli.main(
        [
            "check",
            "--root",
            str(ROOT),
            "--examples",
            "--site",
            str(EXAMPLES / "sites" / "small-lab.yml"),
            "--services",
            str(services),
        ]
    )
    return code, capsys.readouterr().out


@pytest.mark.parametrize("drift", [False, True])
def test_hnx_modules_check_compares_the_given_lab_registry(tmp_path, capsys, drift):
    rows = lab_registry()["services"]
    if drift:
        rows["samples"]["port"] = 9001
    _code, out = _cli(capsys, _registry_file(tmp_path, rows))
    regs = [line for line in out.splitlines() if line.startswith("registry: services.")]
    rowlines = [line for line in regs if "contributes" in line]
    if drift:
        assert rowlines == [
            f"registry: services.samples.port: {STORE} (instance samples) contributes 9000 (its "
            "row object-store), the lab registry has 9001"
        ], out
    else:
        assert rowlines == [], out
    assert "service rows were not compared" not in out


def test_hnx_modules_check_names_a_row_missing_from_the_lab_registry(tmp_path, capsys):
    code, out = _cli(capsys, _registry_file(tmp_path, {}))
    assert code == 1
    assert f"registry: services.samples: {STORE} (instance samples) contributes this row" in out, (
        out
    )


# ------------------------------------------------------- site-bound fields (public_hostname)


def _with_public_store(rows_public: dict):
    """The rows with the store's row declaring ``rows_public`` (a module whose row is public)."""
    rows = copy.deepcopy(dict(ROWS))
    rows[STORE] = {**rows[STORE], "object-store": {**rows[STORE]["object-store"], **rows_public}}
    return rows


DECLARED = {"public_hostname": "store.example.internal", "edge_tls": {"ca": "secret:pki/lab-ca"}}


def test_a_declared_public_hostname_takes_the_sites_value():
    rows = _with_public_store(DECLARED)
    reg = lab_registry()
    reg["services"]["samples"].update(
        public_hostname="store.lab.example", edge_tls={"ca": "secret:site/ca"}
    )
    sel = mr.selected(SITE, TREE.mods)
    assert rr.row_problems(SITE, sel, rows, reg) == []


def test_a_declared_public_hostname_the_registry_lacks_is_named():
    rows = _with_public_store(DECLARED)
    sel = mr.selected(SITE, TREE.mods)
    got = rr.row_problems(SITE, sel, rows, lab_registry())
    assert sorted(got) == [
        f"services.samples.edge_tls: {STORE} (instance samples) declares one (its row "
        "object-store) (its value is the site's), the lab registry has (absent)",
        f"services.samples.public_hostname: {STORE} (instance samples) declares one (its row "
        "object-store) (its value is the site's), the lab registry has (absent)",
    ]


def test_a_site_cannot_make_an_internal_row_public():
    """Only a field the module declares is the site's to fill: added to a row whose module
    has none, it is a difference like any other."""
    reg = lab_registry()
    reg["services"]["samples"]["public_hostname"] = "store.lab.example"
    assert problems(registry=reg) == [
        f"services.samples.public_hostname: {STORE} (instance samples) contributes (absent) "
        '(its row object-store), the lab registry has "store.lab.example"'
    ]
