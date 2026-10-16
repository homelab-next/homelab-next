# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json

from cust_helpers import make_doc, write_custom

from homelabnext import cli


def hnx(capsys, *args):
    code = cli.main(["custom", *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_listed_in_help(capsys):
    assert cli.main(["--help"]) == 0
    assert "custom" in capsys.readouterr().out


def test_list_shows_shipped_profiles(capsys):
    code, out, _ = hnx(capsys, "list", "--today", "2026-10-15")
    assert code == 0 and "custom:board-sensor-driver" in out and "inactive" in out


def test_list_json_and_local_dir(tmp_path, capsys):
    write_custom(tmp_path, "a", make_doc())
    code, out, _ = hnx(capsys, "list", "--dir", str(tmp_path), "--json", "--today", "2026-10-15")
    rows = {r["id"]: r for r in json.loads(out)}
    assert code == 0 and rows["custom:test-port"]["state"] == "active"
    assert rows["custom:test-port"]["origin"] == "local"


def test_check_clean_then_expired(tmp_path, capsys):
    write_custom(tmp_path, "a", make_doc())
    assert hnx(capsys, "check", "--dir", str(tmp_path), "--today", "2026-10-15")[0] == 0
    code, out, _ = hnx(capsys, "check", "--dir", str(tmp_path), "--today", "2027-02-01")
    assert code == 1 and "CU008" in out


def test_check_strict_fails_on_warning(tmp_path, capsys, monkeypatch):
    write_custom(tmp_path, "a", make_doc(review_by="2026-10-20"))
    assert hnx(capsys, "check", "--dir", str(tmp_path), "--today", "2026-10-15")[0] == 0
    assert hnx(capsys, "check", "--dir", str(tmp_path), "--today", "2026-10-15", "--strict")[0] == 1


def test_env_var_discovery(tmp_path, capsys, monkeypatch):
    write_custom(tmp_path, "a", make_doc(id="custom:from-env"))
    monkeypatch.setenv("HNX_CUSTOMIZATIONS_DIR", str(tmp_path))
    assert "custom:from-env" in hnx(capsys, "list", "--today", "2026-10-15")[1]


def test_plan_output_and_exit_codes(tmp_path, capsys):
    write_custom(tmp_path, "a", make_doc())
    code, out, _ = hnx(capsys, "plan", "--dir", str(tmp_path), "--today", "2026-10-15")
    plan = json.loads(out)
    assert code == 0 and plan["resolved"]["role_vars"]["example_service"]
    write_custom(tmp_path, "b", make_doc(id="custom:clash"))
    code, out, _ = hnx(capsys, "plan", "--dir", str(tmp_path), "--today", "2026-10-15")
    assert code == 1 and json.loads(out)["conflicts"]


def test_plan_enable_shipped_profile(capsys):
    code, out, _ = hnx(
        capsys, "plan", "--enable", "custom:board-sensor-driver=mon-core", "--today", "2026-10-15"
    )
    plan = json.loads(out)
    assert code == 0 and plan["resolved"]["profiles"]["board-sensor-driver"]["hosts"] == [
        "mon-core"
    ]


def test_plan_out_refuses_core_path(capsys, repo_root):
    code, _, err = hnx(
        capsys, "plan", "--today", "2026-10-15", "--out", str(repo_root / "schemas" / "plan.json")
    )
    assert code == 2 and "refusing" in err
    assert not (repo_root / "schemas" / "plan.json").exists()


def test_register_command(tmp_path, capsys):
    code, _, _ = hnx(capsys, "register", str(tmp_path / "o"), "--today", "2026-10-15")
    assert code == 0 and (tmp_path / "o" / "customizations.html").is_file()


def test_bad_date_is_usage_error(capsys):
    assert hnx(capsys, "list", "--today", "tomorrow")[0] == 2
