# SPDX-License-Identifier: Apache-2.0
"""``hnx registry bindings`` (ADR-0039 decision 3, step 5): every binding site pointed at a
non-primary row is refused, the two declared exceptions hold, and the current examples pass."""

from __future__ import annotations

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
        "--roles",
        str(ROOT / "examples/model_roles.json"),
        "--eval-report",
        str(ROOT / "examples/model_roles.eval.json"),
        "--packs",
        str(ROOT / "workflows/packs"),
        "--deployed",
        str(ROOT / "workflows/deploy.yml"),
        "--site",
        str(site),
        "--modules",
        str(ROOT / "examples/modules"),
        capsys=capsys,
    )
    assert (rc, err) == (0, ""), err
    assert "bindings: 0 problem(s); 1 role table(s), 1 report(s), 2 pack(s)" in out


def test_make_check_runs_the_bindings_check_over_the_examples():
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"^check:.*\bbindings-check\b", make, re.M)
    recipe = make.split("\nbindings-check:\n", 1)[1].split("\n\n", 1)[0]
    for arg in (
        "registry bindings examples/services.yml",
        "--roles $(MODEL_ROLES)",
        "--eval-report $(MODEL_EVAL)",
        "--packs workflows/packs --deployed workflows/deploy.yml",
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


def test_a_platform_capability_the_registry_does_not_place_is_a_note(tmp_path, capsys):
    rc, out, err = _run(
        str(_registry(tmp_path)), "--packs", str(_pack(tmp_path, "svc:cases")), capsys=capsys
    )
    assert (rc, err) == (0, "")
    assert "svc:cases is a platform capability this registry does not place" in out


def test_the_declarations_are_listed_each_with_a_why():
    assert [d.name for d in bd.PLATFORM_SOURCES] == ["broker", "llm-orchestrator"]
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


def test_the_canary_report_is_read_from_the_base_commit(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    reg = str(_registry(tmp_path, "retiring"))
    _git(repo, "init", "-q")
    _report(repo, "svc:inference", "eval.json")
    _git(repo, "add", "eval.json")
    _git(repo, "commit", "-q", "-m", "base")
    _report(repo, f"svc:{CANDIDATE}", "eval.json")  # the change names the retiring row
    head = ["--eval-report", "eval.json", "--root", str(repo)]
    assert _run(reg, *head, "--base", "HEAD", capsys=capsys)[0] == 0
    _git(repo, "commit", "-q", "-am", "change")
    rc, _out, err = _run(reg, *head, "--base", "HEAD", capsys=capsys)
    assert rc == 1 and f"svc:{CANDIDATE} names a retiring row" in err
    assert _run(reg, *head, "--base", "HEAD~1", capsys=capsys)[0] == 0


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


def test_only_the_egress_canary_runner_passes_allow_eval():
    found = sorted(
        str(p.relative_to(ROOT))
        for p in (ROOT / "homelabnext").rglob("*.py")
        if re.search(r"allow_eval\s*=\s*True\s*[,)]", p.read_text(encoding="utf-8"))
    )
    assert found == ["homelabnext/golden/cli.py"]
    text = (ROOT / "homelabnext/golden/cli.py").read_text(encoding="utf-8")
    body = text.split("def _binding_completer(", 1)[1].split("\ndef ", 1)[0]
    calls = re.compile(r"allow_eval\s*=\s*True\s*[,)]")
    assert len(calls.findall(text)) == len(calls.findall(body)) == 1
