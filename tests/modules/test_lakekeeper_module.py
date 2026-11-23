# SPDX-License-Identifier: Apache-2.0
"""The lake-catalog provider module on Lakekeeper (modules/lakekeeper).

* the manifest fills the slot the lake contracts name with the shared adapter and the conformance
  target, keeps its secrets in its own namespace, and pins both images by digest;
* the lake's fixed names agree with the object store's (the bucket, the region), and the warehouse's
  base is the bucket ROOT (a key prefix would put the lake's existing table locations outside it);
* the container ids clash with no other module's, the target speaks the /catalog API, and role_lint
  passes the role and the lifecycle playbooks;
* a fictional overlay selecting it in place of the other lake-catalog provider checks clean and renders.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from homelabnext.conform.target import load_target
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules import test_lake_modules as base

ROOT = Path(__file__).resolve().parents[2]
MID = "lakekeeper"
ROLE = "lakekeeper"
NEW = {**base.MODULES, MID: {"slot": "lake-catalog", "role": ROLE, "row": "lake-catalog"}}
NEW.pop("iceberg-rest")


def manifest() -> dict:
    return ld.load_yaml(ROOT / "modules" / MID / "module.yml")


def defaults() -> dict:
    return ld.load_yaml(ROOT / "modules" / MID / "roles" / ROLE / "defaults" / "main.yml")


def test_the_module_fills_the_lake_catalog_slot_with_the_shared_adapter():
    m = manifest()
    assert m["kind"] == "provider" and m["egress"] == "none"
    assert list(m["provides"]["slots"]) == ["lake-catalog"]
    slot = m["provides"]["slots"]["lake-catalog"]
    assert slot["adapter"] == "homelabnext.conform.adapters.lake:make_lake"
    assert (ROOT / "modules" / MID / slot["conformance"]["target"]).is_file()
    assert sorted(p.name for p in (ROOT / "modules" / MID / "roles").iterdir()) == [ROLE]
    assert not any(p.is_symlink() for p in (ROOT / "modules" / MID).rglob("*"))
    row = ld.load_yaml(ROOT / "modules" / MID / "registry" / "services.yml")["services"][
        "lake-catalog"
    ]
    assert row["capability"] == "lake-catalog" and row["impl"] == m["product"]["name"]
    assert "version" not in row and "public_hostname" not in row  # internal only
    assert (
        row["auth"] == "none"
    )  # the network is the only control (decision D2), and the row says so


def test_every_secret_is_in_the_modules_own_namespace():
    refs = [c["secret"] for c in manifest()["credentials"]]
    assert sorted(refs) == [
        "secret:lakekeeper/encryption-key",
        "secret:lakekeeper/pg-password",
        "secret:lakekeeper/s3-access-key",
        "secret:lakekeeper/s3-secret-key",
    ]
    d = defaults()
    assert {d[k] for k in d if k.endswith("_ref")} == set(
        refs
    )  # named by reference, never by value


def test_both_images_are_pinned_by_digest_and_the_catalog_is_the_product_version():
    d = defaults()
    for key in ("lakekeeper_image", "lakekeeper_postgres_image"):
        repo_tag, digest = d[key].split("@")
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest) and not repo_tag.endswith(":latest")
    assert d["lakekeeper_image"].split("@")[0].rsplit(":", 1)[1] == "v" + str(
        manifest()["product"]["version"]
    )


def test_the_warehouse_names_agree_with_the_object_store_and_its_base_is_the_bucket_root():
    g, d = base.defaults("garage"), defaults()
    assert d["lakekeeper_bucket"] == g["garage_bucket"] == "iceberg-warehouse"
    assert d["lakekeeper_region"] == g["garage_region"]
    # no setting can put a prefix on the warehouse: every existing table location must be inside it
    assert not [k for k in d if "prefix" in k]
    text = (ROOT / "modules" / MID / "roles" / ROLE / "tasks" / "converge.yml").read_text()
    assert "key-prefix" not in text.split("Create the warehouse")[1].split("when:")[0]


def test_the_container_ids_clash_with_no_other_module():
    d = defaults()
    mine = {
        d["lakekeeper_uid"],
        d["lakekeeper_gid"],
        d["lakekeeper_db_uid"],
        d["lakekeeper_db_gid"],
    }
    taken = set()
    for p in (ROOT / "modules").glob("*/roles/*/defaults/main.yml"):
        if p.parts[-5] == MID:
            continue
        taken |= {
            v
            for k, v in ld.load_yaml(p).items()
            if re.search(r"_(uid|gid)$", k) and isinstance(v, int)
        }
    assert not mine & taken, mine & taken


def test_the_target_speaks_the_catalog_api_under_the_catalog_path():
    target = load_target(str(ROOT / "modules" / MID / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("lake-catalog")
    assert binding.adapter == "homelabnext.conform.adapters.lake:make_lake"
    assert (
        binding.config["api_root"] == "/catalog" and "catalog_prefix_optional" not in binding.config
    )
    assert binding.config["credential"].startswith("secret:")  # a secret NAME, never a value


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run(
        [*lint, str(ROOT / "modules" / MID / "roles" / ROLE)], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (ROOT / "modules" / MID / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_nothing_in_the_module_names_the_operators_workstation():
    for f in (ROOT / "modules" / MID).rglob("*"):
        if f.is_file():
            assert not re.search(r"192\.168\.20\.150|wsl", f.read_text().lower()), f


def test_an_overlay_selecting_it_in_place_of_the_other_catalog_checks_clean_and_renders(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setattr(base, "MODULES", NEW)
    ov = base.overlay(tmp_path / "ov")
    assert mcli.main(["check", *base._args(ov)]) == 0, capsys.readouterr().out
    dest = tmp_path / "out"
    assert mcli.main(["render", *base._args(ov), "--out", str(dest)]) == 0, capsys.readouterr().out
    assert (dest / "modules.yml").is_file()


@pytest.mark.parametrize("field, value", [("port", 9999), ("impl", "other"), ("auth", "own")])
def test_a_registry_row_that_differs_is_named(field, value, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(base, "MODULES", NEW)
    ov = base.overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["lake-catalog"][field] = value
    (ov / "lab" / "services.yml").write_text(base._dump(reg))
    assert mcli.main(["check", *base._args(ov)]) == 1
    assert f"services.lake-catalog.{field}" in capsys.readouterr().out
