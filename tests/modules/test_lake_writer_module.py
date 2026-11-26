# SPDX-License-Identifier: Apache-2.0
"""The lake-writer feature module, ``modules/lake-writer`` (its README).

* The manifest: a feature in the SOC bundle (no product, no credentials block), its secrets in its own
  namespace, the object store, catalog and query service required and the log pipeline preferred, no
  egress and no registry row, datasets with their TLP and retention, ten lake-table records in the
  ``soc`` namespace, a removal that exports first.
* The defaults hold no lab value; the namespace is derived and never an input of the role; the
  timers are on the calendar, never an interval; one writer per table (a template unit and one
  timer per table).
* A fictional overlay placing it beside the three lake modules checks clean and renders its checks.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.test_lake_modules import _args
from tests.modules.test_lake_modules import overlay as lake_overlay

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "lake-writer"
ROLE = MODULE / "roles" / "lake_writer"
MANIFEST = ld.load_yaml(MODULE / "module.yml")
DEFAULTS = ld.load_yaml(ROLE / "defaults" / "main.yml")
VARS = ld.load_yaml(ROLE / "vars" / "main.yml")
TABLES = {
    "authentication",
    "compliance_finding",
    "detection_finding",
    "dns_activity",
    "file_activity",
    "http_activity",
    "network_activity",
    "process_activity",
    "raw_archive",
    "vulnerability_finding",
}


@pytest.mark.static
def test_the_manifest_is_a_soc_feature_with_its_own_secrets_and_no_egress():
    m = MANIFEST
    assert m["kind"] == "feature" and m["id"] == "lake-writer" and m["bundle"]["id"] == "soc"
    assert not {"product", "licence", "credentials", "provides"} & set(m)
    assert m["identifiers"] == [
        {"kind": "secret-name", "name": "lake-writer", "on_remove": "keep"},
        {"kind": "lake-namespace", "name": "soc", "on_remove": "keep"},
    ]
    assert [r["cap"] for r in m["requires"]["capabilities"]] == [
        "cap:secrets",
        "cap:object-store",
        "cap:lake-catalog",
        "cap:lake-query",
    ]
    assert [r["cap"] for r in m["prefers"]["capabilities"]] == ["cap:log-pipeline"]
    assert m["egress"] == "none"
    assert "services" not in m["contributes"] and not (MODULE / "registry").exists()
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["lake_writer"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert m["lifecycle"]["remove"]["export_first"] is True
    for key, var in (
        ("lake_password", "lake_writer_lake_login_ref"),
        ("s3_access_key", "lake_writer_s3_id_ref"),
        ("s3_secret_key", "lake_writer_s3_key_ref"),
    ):
        ref = m["config"][key]["default"]
        assert DEFAULTS[var] == ref and ref.split("/")[0] == "secret:lake-writer"


def test_the_datasets_declare_their_label_and_retention():
    data = {d["id"]: d for d in MANIFEST["data"]}
    assert set(data) == {"staging", "state"}
    staging = data["staging"]
    assert staging["kind"] == "object-prefix" and staging["tlp"] == "red"
    assert staging["prefix"] == DEFAULTS["lake_writer_staging_prefix"]
    assert staging["retention"]["days"] >= 1 and "honour_item_labels" not in staging
    assert data["state"]["kind"] == "state" and data["state"]["retention"] == {"keep": "forever"}


def test_every_table_is_one_record_in_soc_owned_by_the_module_and_declared_once():
    files = [e["file"] for e in MANIFEST["contributes"]["lake_tables"]]
    ids = []
    for f in files:
        rec = ld.load_yaml(MODULE / f)
        ids.append(rec["id"])
        assert rec["owner"] == "lake-writer" and rec["id"].startswith("table:soc.")
        assert rec["retention_days"] >= 1 and rec["freshness"]["stale_after_s"] >= 60
    assert sorted(ids) == sorted(f"table:soc.{t}" for t in TABLES) and len(set(ids)) == len(ids)
    assert set(DEFAULTS["lake_writer_tables"]) == TABLES == set(VARS["lake_writer_known_tables"])


@pytest.mark.static
def test_the_namespace_is_derived_and_never_an_input_of_the_role():
    assert VARS["lake_writer_namespace"] == "soc"
    assert "lake_writer_namespace" not in DEFAULTS
    spec = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())["argument_specs"]
    assert "lake_writer_namespace" not in spec["main"]["options"]
    validate = (ROLE / "tasks" / "validate.yml").read_text()
    assert "lake_writer_namespace == 'soc'" in validate


@pytest.mark.static
def test_the_defaults_hold_no_address_no_lab_name_and_every_secret_is_a_reference():
    text = (ROLE / "defaults" / "main.yml").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", code):
        assert ip == "0.0.0.0", ip
    assert not re.search(r"\.(casa|local|lan)\b", code)
    refs = {k: v for k, v in DEFAULTS.items() if k.endswith("_ref") and v != ""}
    assert refs and all(re.fullmatch(r"secret:[A-Za-z0-9._/-]+", v) for v in refs.values())
    for k in ("lake_query", "lake_catalog", "object_store"):
        assert DEFAULTS[f"lake_writer_{k}_url"] == ""
    spec = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())["argument_specs"][
        "main"
    ]["options"]
    for k in ("logical_id", "lake_user", "lake_warehouse", "s3_region"):
        assert spec[f"lake_writer_{k}"]["required"] is True


@pytest.mark.static
def test_one_template_unit_and_one_timer_per_table_on_the_calendar_never_an_interval():
    assert re.search(r"\*:0/\d+", DEFAULTS["lake_writer_oncalendar"])
    timer = (ROLE / "templates" / "lake-writer.timer.j2").read_text().splitlines()
    assert any(ln.startswith("OnCalendar=") for ln in timer)
    assert not any(ln.startswith(("OnUnitActiveSec=", "OnBootSec=")) for ln in timer)
    service = (ROLE / "templates" / "lake-writer.service.j2").read_text()
    assert "commit --table %i" in service
    assert VARS["lake_writer_service_unit"].endswith("@.service")
    assert VARS["lake_writer_timer_unit"].endswith("@.timer")
    assert "ProtectSystem=strict" in service and "CapabilityBoundingSet=\n" in service


# ----------------------------------------------------------------------------- an overlay


def overlay(tmp: Path) -> Path:
    """The three lake modules on one guest (the lake tests' overlay) and the writer beside them."""
    ov = lake_overlay(tmp)
    path = ov / "lab" / "modules.yml"
    sel = yaml.safe_load(path.read_text())
    sel["features"] = {"lake-writer": {"placement": {"writer": "lake"}}}
    sel["lab_table_namespaces"] = [{"namespace": "soc", "why": "the SOC's fresh tables"}]
    path.write_text(yaml.safe_dump(sel, sort_keys=False))
    guest = ov / "lab" / "guests" / "lake-1.yml"  # room for the writer's footprint beside the three
    guest.write_text(
        guest.read_text()
        .replace("cores: 8", "cores: 16")
        .replace("size_mb: 32768", "size_mb: 40960")
    )
    return ov


def test_an_overlay_placing_it_beside_the_lake_checks_clean_and_renders_its_checks(
    tmp_path, capsys
):
    ov = overlay(tmp_path / "ov")
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    plays = [
        p
        for p in yaml.safe_load((dest / "modules.yml").read_text())
        if p["hosts"] == "mod_lake_writer_writer"
    ]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/lake-writer/roles/lake_writer")
    checks = yaml.safe_load((dest / "checks" / "lake-writer.yml").read_text())
    hooks = [
        t["name"].split(":")[0]
        for p in checks
        if p["hosts"] == "mod_lake_writer_writer"
        for t in p["tasks"]
    ]
    assert hooks == ["readiness", "health"]


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
