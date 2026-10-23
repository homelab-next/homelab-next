# SPDX-License-Identifier: Apache-2.0
"""``hnx site validate|plan|render`` and its dispatch from the top-level ``hnx``."""

from __future__ import annotations

import io
import json

import yaml

from homelabnext import cli as top
from homelabnext.network import cli


def run(argv, tmp=None):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def args(site_path, registry_path, *more):
    return [*more[:1], str(site_path), "--registry", str(registry_path), *more[1:]]


def test_validate_ok_prints_ok_and_warnings_to_stderr(site_path, registry_path):
    code, out, err = run(args(site_path, registry_path, "validate"))
    assert (code, out.strip()) == (0, "ok")
    assert "placeholder" in err


def test_validate_json(site_path, registry_path):
    code, out, _ = run(args(site_path, registry_path, "validate", "--json"))
    body = json.loads(out)
    assert code == 0 and body["ok"] is True and body["errors"] == []


def test_validate_invalid_site_exits_1(site_path, registry_path, tmp_path, doc):
    doc["zones"][1]["vlan_id"] = 10
    bad = tmp_path / "site.yml"
    bad.write_text(yaml.safe_dump(doc))
    code, out, err = run(args(bad, registry_path, "validate"))
    assert code == 1 and "already used" in err and out == ""


def test_default_registry_is_services_yml_next_to_the_site(tmp_path, site_path, registry_path):
    (tmp_path / "site.yml").write_text(site_path.read_text())
    (tmp_path / "services.yml").write_text(registry_path.read_text())
    code, out, _ = run(["validate", str(tmp_path / "site.yml")])
    assert (code, out.strip()) == (0, "ok")


def test_missing_registry_is_exit_2(tmp_path, site_path):
    # bad input, not an invalid site: docs/interfaces.md's exit codes
    code, _, err = run(["validate", str(site_path), "--registry", str(tmp_path / "nope.yml")])
    assert code == 2 and "cannot read registry" in err


def test_render_then_plan_is_a_no_op(site_path, registry_path, tmp_path):
    out_dir = tmp_path / "out"
    code, out, _ = run(
        args(site_path, registry_path, "render", "--adapter", "linux", "--out", str(out_dir))
    )
    assert code == 0 and "written" in out and (out_dir / "etc/nftables.d/50-hnx-site.nft").is_file()
    code, out, _ = run(
        args(site_path, registry_path, "render", "--adapter", "linux", "--out", str(out_dir))
    )
    assert code == 0 and "0 written" in out
    code, out, _ = run(
        args(
            site_path,
            registry_path,
            "plan",
            "--adapter",
            "linux",
            "--current",
            str(out_dir),
            "--exit-code",
        )
    )
    assert code == 0 and "0 to create, 0 to update, 0 to delete" in out


def test_plan_exit_code_flag_signals_changes(site_path, registry_path, tmp_path):
    code, out, _ = run(
        args(
            site_path,
            registry_path,
            "plan",
            "--adapter",
            "dnsmasq",
            "--current",
            str(tmp_path),
            "--exit-code",
        )
    )
    assert code == 3 and "to create" in out
    code, _, _ = run(
        args(site_path, registry_path, "plan", "--adapter", "dnsmasq", "--current", str(tmp_path))
    )
    assert code == 0


def test_plan_json(site_path, registry_path):
    code, out, _ = run(
        args(site_path, registry_path, "plan", "--adapter", "unifi", "--format", "json")
    )
    assert code == 0 and json.loads(out)["counts"]["create"] == 5


def test_default_adapter_comes_from_the_document(site_path, registry_path):
    code, out, _ = run(args(site_path, registry_path, "plan", "--no-diff"))
    assert code == 0 and out.startswith("plan (unifi)")


def test_unknown_adapter_is_exit_2_and_names_the_choices(site_path, registry_path, tmp_path):
    code, _out, err = run(
        args(
            site_path,
            registry_path,
            "render",
            "--adapter",
            "acmerouter",
            "--out",
            str(tmp_path / "o"),
        )
    )
    assert code == 2 and "unknown adapter 'acmerouter'" in err and "linux" in err
    assert not (tmp_path / "o").exists()


def test_deferred_adapter_is_exit_2_and_writes_nothing(site_path, registry_path, tmp_path):
    code, _, err = run(
        args(
            site_path,
            registry_path,
            "render",
            "--adapter",
            "opnsense",
            "--out",
            str(tmp_path / "o"),
        )
    )
    assert code == 2 and "deferred" in err and not (tmp_path / "o").exists()


def test_usage_errors(site_path):
    assert run([])[0] == 2
    assert run(["frobnicate"])[0] == 2
    assert run(["render", str(site_path)])[0] == 2  # --out is required


def test_adapters_listing():
    code, out, _ = run(["adapters"])
    assert code == 0 and "opnsense  deferred" in out and "unifi     ready" in out


def test_ir_command_prints_json(site_path, registry_path):
    code, out, _ = run(args(site_path, registry_path, "ir"))
    assert code == 0 and json.loads(out)["site_id"] == "northwind"


def test_top_level_dispatch(site_path, registry_path, capsys):
    assert "site" in top.COMMANDS
    assert top.main(["site", "validate", str(site_path), "--registry", str(registry_path)]) == 0
    assert capsys.readouterr().out.strip() == "ok"
    assert top.main(["site", "--help"]) == 0
    assert "usage" in capsys.readouterr().out.lower()
