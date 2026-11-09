# SPDX-License-Identifier: Apache-2.0
"""``hnx registry bindings`` (ADR-0039 decision 3, step 5): every binding site pointed at a
non-primary row is refused, the two declared exceptions hold, and the current examples pass."""

from __future__ import annotations

import ast
import copy
import dataclasses
import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext.cli import main as hnx
from homelabnext.registry import bindings as bd
from homelabnext.registry.dns import FakeDNS
from homelabnext.registry.model import RegistryError, build_registry, load
from homelabnext.registry.models import Binding, ModelResolver, NonPrimaryBinding, RoleTable
from homelabnext.registry.resolver import ResolutionError, Resolver

ROOT = Path(__file__).resolve().parents[2]
NON_PRIMARY = ("eval", "retiring", "legacy")
CANDIDATE = "inference-candidate"
SITES = sorted((ROOT / "examples/modules/sites").glob("*.yml"))
GATEWAYS = (
    "compose/lab-in-a-box/config/llm-gateway/gateway.yml",
    "compose/lab-in-a-box/config/llm-gateway-conformance/gateway.yml",
    "examples/llm-orchestrator-gateway/gateway.yml",
)


def _url(host: str, port: int) -> str:
    return f"http://{host}.example.internal:{port}"


def _product(module: str) -> str:
    doc = yaml.safe_load((ROOT / "examples/modules" / module / "module.yml").read_text())
    return doc["product"]["name"]


def _doc() -> dict:
    return yaml.safe_load((ROOT / "examples/services.yml").read_text(encoding="utf-8"))


def _candidate_row(doc: dict, name: str, cap_row: str, tier: str, **over) -> dict:
    row = copy.deepcopy(doc["services"][cap_row])
    for k in ("env_var", "mcp", "status_sources", "public_hostname", "front_door", "roles"):
        row.pop(k, None)
    used = {s["port"] for s in doc["services"].values() if s["host"] == row["host"]}
    while row["port"] in used:
        row["port"] += 1
    row["standing"] = {"tier": tier, "until": "2027-01-31", "why": "a candidate under test"}
    row.update(over)
    doc["services"][name] = row
    return row


def _registry(tmp_path: Path, tier: str | None = None) -> Path:
    """The example registry, plus (with ``tier``) an inference row of that standing."""
    doc = _doc()
    if tier:
        _candidate_row(doc, CANDIDATE, "inference", tier)
    path = tmp_path / "services.yml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


def _roles(tmp_path: Path, backend: str, name: str = "model_roles.json") -> Path:
    doc = json.loads((ROOT / "examples/model_roles.json").read_text(encoding="utf-8"))
    for role in doc["roles"].values():
        for b in role.get("bindings", []):
            b["backend"] = backend
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _report(tmp_path: Path, backend: str, name: str = "eval.json") -> Path:
    doc = json.loads((ROOT / "examples/model_roles.eval.json").read_text(encoding="utf-8"))
    for entry in doc["canary"].values():
        for b in entry["bindings"]:
            b["backend"] = backend
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _pack(tmp_path: Path, target: str, source: str = "svc:events") -> Path:
    doc = yaml.safe_load((ROOT / "workflows/packs/case-opened-notify.yml").read_text())
    text = json.dumps(doc)
    text = text.replace('"svc:notify"', '"@target@"').replace('"svc:cases"', '"@source@"')
    text = text.replace('"@target@"', json.dumps(target)).replace('"@source@"', json.dumps(source))
    path = tmp_path / "pack.yml"
    path.write_text(yaml.safe_dump(json.loads(text)), encoding="utf-8")
    return path


def _run(*argv: str, capsys) -> tuple[int, str, str]:
    rc = hnx(["registry", "bindings", *argv])
    out, err = capsys.readouterr()
    return rc, out, err


# ---------------------------------------------------------------- the examples pass


@pytest.mark.parametrize("site", SITES, ids=lambda p: p.stem)
def test_the_current_examples_pass(site, capsys):
    rc, out, err = _run(
        str(ROOT / "examples/services.yml"),
        "--reference-examples",
        "--roles",
        str(ROOT / "examples/model_roles.json"),
        "--eval-report",
        str(ROOT / "examples/model_roles.eval.json"),
        "--packs",
        str(ROOT / "workflows/packs"),
        *[a for g in GATEWAYS for a in ("--gateway", str(ROOT / g))],
        "--site",
        str(site),
        "--modules",
        str(ROOT / "examples/modules"),
        capsys=capsys,
    )
    assert (rc, err) == (0, ""), err
    assert "bindings: 0 problem(s); 1 role table(s), 1 report(s), 5 pack(s), 0 target(s), " in out
    assert "3 gateway spec(s)" in out


def test_make_check_runs_the_bindings_check_over_the_examples():
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"^check:.*\bbindings-check\b", make, re.M)
    recipe = make.split("\nbindings-check:\n", 1)[1].split("\n\n", 1)[0]
    for arg in (
        "registry bindings examples/services.yml --reference-examples",
        "--roles $(MODEL_ROLES)",
        "--eval-report $(MODEL_EVAL)",
        "--packs workflows/packs \\\n",
        "$(foreach g,$(BINDINGS_GATEWAYS),--gateway $(g))",
        "examples/modules/sites/*.yml",
        "--modules examples/modules",
    ):
        assert arg in recipe, arg


def test_the_overlay_template_runs_the_bindings_check_over_lab():
    path = ROOT / "examples/private-overlay/.github/workflows/checks.yml"
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = wf["jobs"]["registry-bindings"]
    assert "registry-bindings" in wf["jobs"]["checks"]["needs"]
    run = "\n".join(s.get("run", "") for s in job["steps"])
    assert "hnx registry bindings lab/services.yml" in run
    assert "--eval-report lab/model_roles.eval.json --ci-base" in run
    assert "--roles lab/model_roles.json" in run
    assert "--packs hnx/workflows/packs --deployed hnx/workflows/deploy.yml" in run
    assert "--gateway lab/llm-gateway/gateway.yml" in run
    assert "--reference-examples" not in run  # a lab's check never gets the leniency


def test_make_check_names_every_example_gateway_spec_and_checks_every_pack():
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    line = next(x for x in make.splitlines() if x.startswith("BINDINGS_GATEWAYS :="))
    for var, path in (
        ("$(GATEWAY_SPEC)", GATEWAYS[0]),
        ("$(CONFORMANCE_GATEWAY)/gateway.yml", GATEWAYS[1]),
        ("$(ORCH_GATEWAY)/gateway.yml", GATEWAYS[2]),
    ):
        assert var in line and (ROOT / path).is_file()
    recipe = make.split("\nbindings-check:\n", 1)[1].split("\n\n", 1)[0]
    assert "--deployed" not in recipe


# ---------------------------------------------------------------- each binding site, each tier


@pytest.mark.parametrize("tier", NON_PRIMARY)
def test_a_role_binding_naming_a_non_primary_row_is_refused(tmp_path, tier, capsys):
    reg = _registry(tmp_path, tier)
    rc, _out, err = _run(
        str(reg), "--roles", str(_roles(tmp_path, f"svc:{CANDIDATE}")), capsys=capsys
    )
    assert rc == 1
    assert f"svc:{CANDIDATE} names {'an' if tier == 'eval' else 'a'} {tier} row" in err


@pytest.mark.parametrize("tier", NON_PRIMARY)
def test_a_pack_target_naming_a_non_primary_row_is_refused(tmp_path, tier, capsys):
    reg = _registry(tmp_path, tier)
    rc, _out, err = _run(
        str(reg), "--packs", str(_pack(tmp_path, f"svc:{CANDIDATE}")), capsys=capsys
    )
    assert rc == 1
    assert re.search(rf"steps\[0\]\.target: svc:{CANDIDATE} names an? {tier} row", err)


@pytest.mark.parametrize("tier", NON_PRIMARY)
def test_a_pack_event_source_naming_a_non_primary_row_is_refused(tmp_path, tier, capsys):
    reg = _registry(tmp_path, tier)
    pack = _pack(tmp_path, "svc:notify", source=f"svc:{CANDIDATE}")
    rc, _out, err = _run(str(reg), "--packs", str(pack), capsys=capsys)
    assert rc == 1
    assert re.search(rf"\.source: svc:{CANDIDATE} names an? {tier} row", err)


@pytest.mark.parametrize("tier", NON_PRIMARY)
def test_a_binding_to_a_capability_whose_only_row_is_non_primary_is_refused(tmp_path, tier):
    doc = _doc()
    doc["services"]["inference"]["standing"] = {
        "tier": tier,
        "until": "2027-01-31",
        "why": "a test row",
    }
    for k in ("env_var", "mcp", "status_sources", "public_hostname"):
        doc["services"]["inference"].pop(k, None)
    for s in doc["services"].values():
        s["upstreams"] = [u for u in s.get("upstreams", []) if u != "inference"]
    if tier != "legacy":  # an eval or retiring row may not be named like a capability
        doc["services"]["inference-old-engine"] = doc["services"].pop("inference")
    reg = build_registry(doc)
    table = RoleTable.from_dict(json.loads((ROOT / "examples/model_roles.json").read_text()))
    found = bd.role_problems(reg, table)
    why = (
        "svc:inference names a legacy row"  # the legacy row keeps the capability's name
        if tier == "legacy"
        else "svc:inference names capability inference, which has no primary"
    )
    assert found and all(why in p for p in found)


@pytest.mark.parametrize("tier", NON_PRIMARY)
def test_an_upstream_to_a_capability_whose_only_row_is_non_primary_is_refused(
    tmp_path, tier, capsys
):
    doc = _doc()
    name = "inference" if tier == "legacy" else "inference-engine"
    row = doc["services"].pop("inference")
    for k in ("env_var", "mcp", "status_sources", "public_hostname"):
        row.pop(k, None)
    row["standing"] = {"tier": tier, "until": "2027-01-31", "why": "a test row"}
    doc["services"][name] = row
    doc["services"]["llm-gateway"]["upstreams"] = ["inference"]
    path = tmp_path / "services.yml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    with pytest.raises(RegistryError):
        load(path)
    rc, _out, err = _run(str(path), capsys=capsys)
    assert rc == 1
    assert "upstream 'inference' has no primary" in err
    # the check's own pass applies the rule to every tier of a registry, built here without
    # the validation that loading runs
    reg = load(_registry(tmp_path))
    held = dataclasses.replace(reg.services["inference"], name=name, standing=tier)
    gw = dataclasses.replace(reg.services["llm-gateway"], upstreams=("inference",))
    services = {k: v for k, v in reg.services.items() if k != "inference"} | {"llm-gateway": gw}
    bad = dataclasses.replace(reg, services=services, non_primary={name: held})
    assert bd.row_upstream_problems(bad) == [
        "service llm-gateway: upstream 'inference' has no primary (a binding reaches only a "
        "primary)"
    ]


def _object_store_lab(tmp_path: Path, tier: str, *, primary: bool = True) -> tuple[Path, Path]:
    """small-lab selecting the other object-store provider, whose product is a non-primary
    row's; the primary's impl is the first provider's product."""
    doc = _doc()
    doc["services"]["object-store"]["impl"] = _product("example-object-store")
    _candidate_row(
        doc, "objects-candidate", "object-store", tier, impl=_product("other-object-store")
    )
    if not primary:
        doc["services"]["objects-main"] = doc["services"].pop("object-store")
        doc["services"]["objects-main"]["standing"] = {
            "tier": "retiring" if tier == "eval" else "eval",
            "until": "2027-01-31",
            "why": "a test row",
        }
        for s in doc["services"].values():
            s["upstreams"] = [u for u in s.get("upstreams", []) if u != "object-store"]
    reg = tmp_path / "services.yml"
    reg.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    site = yaml.safe_load((ROOT / "examples/modules/sites/small-lab.yml").read_text())
    site["slots"]["object-store"][0]["provider"] = "other-object-store"
    sp = tmp_path / "site.yml"
    sp.write_text(yaml.safe_dump(site, sort_keys=False), encoding="utf-8")
    return reg, sp


@pytest.mark.parametrize("tier", NON_PRIMARY)
def test_requires_through_the_selection_to_a_non_primary_row_is_refused(tmp_path, tier, capsys):
    reg, site = _object_store_lab(tmp_path, tier)
    rc, _out, err = _run(
        str(reg), "--site", str(site), "--modules", str(ROOT / "examples/modules"), capsys=capsys
    )
    assert rc == 1
    assert re.search(
        rf"external-collector: requires cap:object-store: the selection's provider "
        rf"other-object-store \({_product('other-object-store')}\) is an? {tier} row's product "
        r"\(objects-candidate\)",
        err,
    )


def test_requires_on_a_capability_with_no_primary_is_refused(tmp_path, capsys):
    reg, site = _object_store_lab(tmp_path, "legacy", primary=False)
    rc, _out, err = _run(
        str(reg), "--site", str(site), "--modules", str(ROOT / "examples/modules"), capsys=capsys
    )
    assert rc == 1
    assert "requires cap:object-store: the capability has no primary" in err


def test_requires_through_the_selection_to_the_primary_passes(tmp_path, capsys):
    reg, site = _object_store_lab(tmp_path, "eval")
    doc = yaml.safe_load(site.read_text())
    doc["slots"]["object-store"][0]["provider"] = "example-object-store"
    site.write_text(yaml.safe_dump(doc, sort_keys=False))
    rc, _out, err = _run(
        str(reg), "--site", str(site), "--modules", str(ROOT / "examples/modules"), capsys=capsys
    )
    assert (rc, err) == (0, "")


# ---------------------------------------------------------------- unregistered, declared, lanes


def test_a_pack_naming_an_unregistered_svc_is_refused(tmp_path, capsys):
    rc, _out, err = _run(
        str(_registry(tmp_path)), "--packs", str(_pack(tmp_path, "svc:nowhere")), capsys=capsys
    )
    assert rc == 1
    assert "svc:nowhere names no registry row, capability or declared platform source" in err


def test_a_role_binding_naming_an_unregistered_svc_is_refused(tmp_path, capsys):
    rc, _out, err = _run(
        str(_registry(tmp_path)), "--roles", str(_roles(tmp_path, "svc:nowhere")), capsys=capsys
    )
    assert rc == 1
    assert "svc:nowhere names no registry row or capability" in err


@pytest.mark.parametrize("source", [d.name for d in bd.PLATFORM_SOURCES])
def test_a_declared_platform_source_passes(tmp_path, source, capsys):
    pack = _pack(tmp_path, "svc:notify", source=f"svc:{source}")
    rc, _out, err = _run(str(_registry(tmp_path)), "--packs", str(pack), capsys=capsys)
    assert (rc, err) == (0, "")


def test_a_declared_unplaced_capability_of_the_pack_is_a_note_for_the_examples_only(
    tmp_path, capsys
):
    args = [str(_registry(tmp_path)), "--packs", str(_pack(tmp_path, "svc:cases"))]
    rc, out, err = _run(*args, "--reference-examples", capsys=capsys)
    assert (rc, err) == (0, "")
    assert "svc:cases is a declared unplaced capability of this pack" in out
    # a lab's check never gets the leniency
    rc, _out, err = _run(*args, capsys=capsys)
    assert rc == 1
    assert "svc:cases names no registry row, capability or declared platform source" in err


@pytest.mark.parametrize(
    ("target", "pack_name"),
    [("svc:cases", "another-pack"), ("svc:orchestration", None), ("svc:projects", None)],
)
def test_an_undeclared_unplaced_capability_is_refused(tmp_path, capsys, target, pack_name):
    path = _pack(tmp_path, target)
    if pack_name:
        doc = yaml.safe_load(path.read_text())
        doc["pack"] = pack_name
        path.write_text(yaml.safe_dump(doc))
    rc, _out, err = _run(
        str(_registry(tmp_path)), "--packs", str(path), "--reference-examples", capsys=capsys
    )
    assert rc == 1
    assert f"{target} names no registry row, capability or declared platform source" in err


def test_a_declared_unplaced_capability_the_registry_holds_rows_of_is_judged(tmp_path, capsys):
    doc = _doc()
    _candidate_row(doc, "cases-candidate", "notify", "eval", capability="cases")
    path = tmp_path / "services.yml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    pack = str(_pack(tmp_path, "svc:cases"))
    rc, _out, err = _run(str(path), "--packs", pack, "--reference-examples", capsys=capsys)
    assert rc == 1
    assert "svc:cases names capability cases, which has no primary" in err


@pytest.mark.parametrize("bad", ["svc:Cases", "svc:cases_db", "svc:", "svc:-x", "svc:a b"])
def test_a_malformed_svc_id_is_refused(tmp_path, capsys, bad):
    rc, _out, err = _run(
        str(_registry(tmp_path)), "--packs", str(_pack(tmp_path, bad)), capsys=capsys
    )
    assert rc == 1
    assert "malformed svc: id" in err
    tp = tmp_path / "target.yml"
    tp.write_text(
        yaml.safe_dump(
            {
                "name": "t",
                "capabilities": {"inference": {"adapter": "x.y:z", "config": {"row": bad}}},
            }
        )
    )
    rc, _out, err = _run(str(_registry(tmp_path)), "--target", str(tp), capsys=capsys)
    assert rc == 1 and "malformed svc: id" in err


def test_every_unplaced_entry_is_a_platform_capability_scoped_to_existing_packs():
    from homelabnext.capability_names import platform_capabilities

    packs = {
        yaml.safe_load(p.read_text())["pack"] for p in (ROOT / "workflows/packs").glob("*.yml")
    }
    for d in bd.UNPLACED:
        assert d.name in platform_capabilities(), d.name
        assert d.why.strip() and d.packs and set(d.packs) <= packs, d.name


def test_the_declarations_are_listed_each_with_a_why():
    assert [d.name for d in bd.PLATFORM_SOURCES] == ["broker", "llm-orchestrator"]
    assert [d.name for d in bd.UNPLACED] == [
        "orchestration",
        "cases",
        "siem-source",
        "mail-gateway",
    ]
    assert [d.name for d in bd.EXCEPTIONS] == ["canary", "conformance-target"]
    assert all(d.why.strip() for d in (*bd.PLATFORM_SOURCES, *bd.EXCEPTIONS))


def test_an_agent_lane_naming_the_controller_is_not_checked(tmp_path, capsys):
    site = yaml.safe_load((ROOT / "examples/modules/sites/small-lab.yml").read_text())
    for feature in site["features"].values():
        for agent in feature.get("agents", {}).values():
            agent["lanes"] = {"real": "llm-orchestrator", "shadow": CANDIDATE}
    sp = tmp_path / "site.yml"
    sp.write_text(yaml.safe_dump(site, sort_keys=False), encoding="utf-8")
    rc, _out, err = _run(
        str(_registry(tmp_path, "legacy")),
        "--site",
        str(sp),
        "--modules",
        str(ROOT / "examples/modules"),
        capsys=capsys,
    )
    assert (rc, err) == (0, "")


# ---------------------------------------------------------------- the two exceptions


def test_the_canary_binding_may_name_an_eval_row_and_the_role_table_may_not(tmp_path, capsys):
    reg = str(_registry(tmp_path, "eval"))
    report = _report(tmp_path, f"svc:{CANDIDATE}")
    assert _run(reg, "--eval-report", str(report), capsys=capsys)[0] == 0
    rc, _out, err = _run(reg, "--roles", str(_roles(tmp_path, f"svc:{CANDIDATE}")), capsys=capsys)
    assert rc == 1 and f"svc:{CANDIDATE} names an eval row" in err


@pytest.mark.parametrize("tier", ["retiring", "legacy"])
def test_the_canary_binding_may_not_name_a_retiring_or_legacy_row(tmp_path, tier, capsys):
    reg = str(_registry(tmp_path, tier))
    rc, _out, err = _run(
        reg, "--eval-report", str(_report(tmp_path, f"svc:{CANDIDATE}")), capsys=capsys
    )
    assert rc == 1
    assert f"canary.fast-classifier.bindings[0]: svc:{CANDIDATE} names a {tier} row" in err


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        check=True,
        capture_output=True,
    )


def test_the_canary_report_is_read_from_the_change_and_from_the_base_commit(
    tmp_path, capsys, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    reg = str(_registry(tmp_path, "retiring"))
    _git(repo, "init", "-q")
    _report(repo, "svc:inference", "eval.json")
    _git(repo, "add", "eval.json")
    _git(repo, "commit", "-q", "-m", "base")
    monkeypatch.chdir(repo)
    head = ["--eval-report", "eval.json", "--root", "."]
    assert _run(reg, *head, "--base", "HEAD", capsys=capsys)[0] == 0
    _report(repo, f"svc:{CANDIDATE}", "eval.json")  # the change names the retiring row
    rc, _out, err = _run(reg, *head, "--base", "HEAD", capsys=capsys)
    assert rc == 1 and f"eval.json: canary.fast-classifier.bindings[0]: svc:{CANDIDATE}" in err
    _git(repo, "commit", "-q", "-am", "change")
    _report(repo, "svc:inference", "eval.json")  # the tree is clean again, the base is not
    rc, _out, err = _run(reg, *head, "--base", "HEAD", capsys=capsys)
    assert rc == 1 and "eval.json@" in err and f"svc:{CANDIDATE} names a retiring row" in err
    assert _run(reg, *head, "--base", "HEAD~1", capsys=capsys)[0] == 0


def test_a_lab_input_through_a_symbolic_link_is_refused(tmp_path, capsys, monkeypatch):
    lab = tmp_path / "lab"
    lab.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text((ROOT / "examples/model_roles.json").read_text())
    (lab / "model_roles.json").symlink_to(outside)
    monkeypatch.chdir(tmp_path)
    reg = str(_registry(tmp_path))
    rc, _out, err = _run(reg, "--roles", "lab/model_roles.json", capsys=capsys)
    assert rc == 2 and "a symbolic link on its path" in err
    (tmp_path / "linked").symlink_to(lab, target_is_directory=True)
    (lab / "model_roles.json").unlink()
    (lab / "model_roles.json").write_text(outside.read_text())
    rc, _out, err = _run(reg, "--roles", "linked/model_roles.json", capsys=capsys)
    assert rc == 2 and "a symbolic link on its path" in err
    assert _run(reg, "--roles", "lab/model_roles.json", capsys=capsys)[0] == 0


def _gateway_spec(tmp_path: Path, host: str, port: int) -> Path:
    roles = {
        "version": 1,
        "roles": {
            "agent-local": {
                "tier": "large",
                "bindings": [{"backend": "svc:llm-shadow", "model_id": "m-large"}],
            }
        },
    }
    (tmp_path / "roles.json").write_text(json.dumps(roles))
    spec = {
        "roles": "roles.json",
        "master_key": "secret:llm-gateway/master-key",
        "database_url": "secret:llm-gateway/database-url",
        "backends": {"svc:llm-shadow": {"locality": "local", "host": host, "port": port}},
        "keys": [
            {
                "name": "local-agent",
                "key": "secret:llm-gateway/key-local-agent",
                "roles": ["mdl:agent-local"],
                "data_tier": "local-only",
            }
        ],
    }
    path = tmp_path / "gateway.yml"
    path.write_text(yaml.safe_dump(spec))
    return path


@pytest.mark.parametrize("tier", ["eval", "retiring"])
def test_a_gateway_spec_reaching_a_non_primary_row_by_its_host_is_refused(tmp_path, capsys, tier):
    reg = _registry(tmp_path, tier)
    row = yaml.safe_load(reg.read_text())["services"][CANDIDATE]
    spec = _gateway_spec(tmp_path, f"{CANDIDATE}.svc.example.internal", row["port"])
    rc, _out, err = _run(str(reg), "--gateway", str(spec), capsys=capsys)
    assert rc == 1
    assert re.search(rf"host {CANDIDATE}\.svc\.example\.internal is an? {tier} row's record", err)
    ok = _gateway_spec(tmp_path, "inference-big.svc.example.internal", 8000)
    assert _run(str(reg), "--gateway", str(ok), capsys=capsys)[0] == 0


def test_a_gateway_role_table_binding_a_non_primary_row_is_refused(tmp_path, capsys):
    reg = _registry(tmp_path, "eval")
    spec = _gateway_spec(tmp_path, "unused.svc.example.internal", 9)
    doc = yaml.safe_load(spec.read_text())
    doc["backends"] = {f"svc:{CANDIDATE}": {"locality": "local", "port": 9}}
    spec.write_text(yaml.safe_dump(doc))
    roles = json.loads((tmp_path / "roles.json").read_text())
    roles["roles"]["agent-local"]["bindings"][0]["backend"] = f"svc:{CANDIDATE}"
    (tmp_path / "roles.json").write_text(json.dumps(roles))
    rc, _out, err = _run(str(reg), "--gateway", str(spec), capsys=capsys)
    assert rc == 1
    assert f"roles.json: mdl:agent-local bindings[0]: svc:{CANDIDATE} names an eval row" in err


@pytest.mark.parametrize(("tier", "ok"), [("eval", True), ("retiring", True), ("legacy", False)])
def test_a_conformance_target_may_name_any_non_legacy_row(tmp_path, tier, ok, capsys):
    target = {
        "name": "candidate",
        "capabilities": {
            "inference": {"adapter": "x.y:make", "config": {"row": f"svc:{CANDIDATE}"}}
        },
    }
    tp = tmp_path / "target.yml"
    tp.write_text(yaml.safe_dump(target), encoding="utf-8")
    rc, _out, err = _run(str(_registry(tmp_path, tier)), "--target", str(tp), capsys=capsys)
    assert (rc == 0) is ok, err
    if not ok:
        assert f"svc:{CANDIDATE} names a legacy row" in err


# ---------------------------------------------------------------- the resolver at run time


def _resolver(tmp_path: Path, tier: str, backend: str) -> ModelResolver:
    reg = load(_registry(tmp_path, tier))
    table = RoleTable.load(_roles(tmp_path, backend))
    env = {"HNX_ENDPOINT_INFERENCE_CANDIDATE": _url("candidate", 8001)}
    return ModelResolver(reg, table, Resolver(reg, environ=env, hosts={}, dns=FakeDNS()))


@pytest.mark.parametrize("tier", NON_PRIMARY)
def test_resolve_raises_on_a_binding_naming_a_non_primary_row(tmp_path, tier):
    mr = _resolver(tmp_path, tier, f"svc:{CANDIDATE}")
    role = next(iter(mr.table.roles))
    with pytest.raises(NonPrimaryBinding, match=f"is an? {tier} row"):
        mr.resolve(role)


def test_resolve_raises_rather_than_falling_back_past_a_non_primary_binding(tmp_path):
    reg = load(_registry(tmp_path, "eval"))
    doc = json.loads((ROOT / "examples/model_roles.json").read_text(encoding="utf-8"))
    name, role = next((n, r) for n, r in doc["roles"].items() if r.get("fallback"))
    role["bindings"] = [{**role["bindings"][0], "backend": f"svc:{CANDIDATE}"}]
    table = RoleTable.from_dict(doc)
    env = {"HNX_ENDPOINT_INFERENCE": _url("inference", 8000)}
    mr = ModelResolver(reg, table, Resolver(reg, environ=env, hosts={}, dns=FakeDNS()))
    with pytest.raises(NonPrimaryBinding):
        mr.resolve(name)


def test_resolve_binding_on_an_eval_row_without_allow_eval_raises(tmp_path):
    mr = _resolver(tmp_path, "eval", f"svc:{CANDIDATE}")
    role = next(iter(mr.table.roles))
    binding = mr.table.get(role).bindings[0]
    with pytest.raises(NonPrimaryBinding):
        mr.resolve_binding(role, binding)
    got = mr.resolve_binding(role, binding, allow_eval=True)
    assert got.endpoint.url == _url("candidate", 8001)


@pytest.mark.parametrize("tier", ["retiring", "legacy"])
def test_allow_eval_reaches_no_retiring_or_legacy_row(tmp_path, tier):
    mr = _resolver(tmp_path, tier, f"svc:{CANDIDATE}")
    role = next(iter(mr.table.roles))
    with pytest.raises(NonPrimaryBinding):
        mr.resolve_binding(role, mr.table.get(role).bindings[0], allow_eval=True)


def test_allow_eval_resolves_the_row_by_its_name_never_through_the_capability(tmp_path):
    mr = _resolver(tmp_path, "eval", f"svc:{CANDIDATE}")
    role = next(iter(mr.table.roles))
    binding = Binding(backend=CANDIDATE, model_id="m")
    mr.resolver.environ = {"HNX_ENDPOINT_INFERENCE": _url("inference", 8000)}
    with pytest.raises(ResolutionError, match="inference-candidate"):
        mr.resolve_binding(role, binding, allow_eval=True)  # the capability's variable is not used


def _allow_eval_uses(tree: ast.AST) -> list[tuple[str, int]]:
    """``(enclosing top-level function, line)`` of every ``allow_eval=`` keyword in any call
    (``functools.partial``, a ``getattr`` result, an alias), every string literal
    ``"allow_eval"`` (a ``**{...}`` mapping, ``setattr``), and every ``resolve_binding`` call
    passing a ``**`` mapping, whatever spelling reaches it."""
    out: list[tuple[str, int]] = []

    def visit(node: ast.AST, owner: str) -> None:
        for child in ast.iter_child_nodes(node):
            name = owner
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) and owner == "<module>":
                name = child.name
            if isinstance(child, ast.keyword) and child.arg == "allow_eval":
                out.append((owner, child.value.lineno))
            elif (isinstance(child, ast.Constant) and child.value == "allow_eval") or (
                isinstance(child, ast.Call)
                and (getattr(child.func, "attr", None) or getattr(child.func, "id", None))
                == "resolve_binding"
                and any(k.arg is None for k in child.keywords)
            ):
                out.append((owner, child.lineno))
            visit(child, name)

    visit(tree, "<module>")
    return out


def test_only_the_egress_canary_runner_passes_allow_eval():
    found = []
    for p in sorted((ROOT / "homelabnext").rglob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        found += [(p.relative_to(ROOT).as_posix(), f) for f, _line in _allow_eval_uses(tree)]
    assert found == [("homelabnext/golden/cli.py", "_binding_completer")]


@pytest.mark.parametrize(
    "src",
    [
        "def f(r, b):\n    r.resolve_binding('x', b, allow_eval=1)\n",
        "def f(r, b):\n    r.resolve_binding('x', b, **{'allow_eval': True})\n",
        "def f(r, b):\n    r.resolve_binding(\n        'x',\n        b,  # a comment\n"
        "        allow_eval=True,\n    )\n",
        "def f(r, b, kw):\n    resolve_binding('x', b, **kw)\n",
        "def f(r, b):\n    functools.partial(r.resolve_binding, allow_eval=True)\n",
        "def f(r, b):\n    getattr(r, 'resolve_binding')('x', b, allow_eval=True)\n",
        "def f(r, b):\n    rb = r.resolve_binding\n    rb('x', b, allow_eval=True)\n",
        "def f(r, b):\n    kw = dict(allow_eval=True)\n",
        "def f(r, b):\n    setattr(o, 'allow_eval', True)\n",
    ],
)
def test_the_allow_eval_scan_catches_every_spelling(src):
    found = _allow_eval_uses(ast.parse(src))
    assert found and {f for f, _line in found} == {"f"}


@pytest.mark.parametrize("value", [1, "yes", [True]])
def test_a_truthy_stand_in_for_allow_eval_grants_nothing(tmp_path, value):
    mr = _resolver(tmp_path, "eval", f"svc:{CANDIDATE}")
    role = next(iter(mr.table.roles))
    with pytest.raises(NonPrimaryBinding):
        mr.resolve_binding(role, mr.table.get(role).bindings[0], allow_eval=value)
