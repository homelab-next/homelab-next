# SPDX-License-Identifier: Apache-2.0
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from homelabnext import scaffold
from homelabnext.scaffold import core

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("kind", sorted(core.KINDS))
def test_scaffold_output_passes_its_own_checker(tmp_path, kind):
    out = scaffold.new(kind, "demo_thing" if kind == "role" else "demo-thing", tmp_path)
    assert out.is_dir()
    assert scaffold.verify(kind, out) == []


def test_role_scaffold_passes_the_linter_cli(tmp_path):
    out = scaffold.new("role", "billing_api", tmp_path)
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "role_lint.py"), str(out)],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible not installed")
def test_role_scaffold_main_runs_under_ansible(tmp_path):
    scaffold.new("role", "billing_api", tmp_path)
    (tmp_path / "p.yml").write_text(
        "- hosts: localhost\n  connection: local\n  gather_facts: false\n  roles:\n    - role: billing_api\n"
        f"      billing_api_logical_id: billing-api\n      billing_api_data_dir: {tmp_path}/data\n"
    )
    env = dict(
        os.environ, ANSIBLE_ROLES_PATH=str(tmp_path / "roles"), ANSIBLE_HOME=str(tmp_path / ".a")
    )
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(tmp_path / "p.yml")],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "data").is_dir()


def test_capability_scaffold_conformance_test_passes(tmp_path):
    out = scaffold.new("capability", "kv-store", tmp_path)
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(out)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_capability_conformance_fails_a_broken_fake(tmp_path):
    out = scaffold.new("capability", "kv-store", tmp_path)
    fake = out / "fake.py"
    fake.write_text(
        fake.read_text().replace("return self._data[key]", "return self._data.get(key)")
    )
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(out)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert r.returncode != 0 and "02_missing_raises" in r.stdout


# --- negatives: the checkers must reject damaged scaffolds
def test_role_checker_rejects_damage(tmp_path):
    out = scaffold.new("role", "svc_a", tmp_path)
    (out / "tasks" / "export.yml").unlink()
    assert any("RL003" in p for p in scaffold.verify("role", out))


def test_schema_checker_rejects_damage(tmp_path):
    out = scaffold.new("schema", "thing", tmp_path)
    shutil.rmtree(out / "negatives")
    assert any("negative" in p for p in scaffold.verify("schema", out))
    out2 = scaffold.new("schema", "thing2", tmp_path)
    (out2 / "examples" / "valid.json").write_text(
        json.dumps({"id": "BAD ID", "schema_version": "1.0.0"})
    )
    assert any("example rejected" in p for p in scaffold.verify("schema", out2))
    out3 = scaffold.new("schema", "thing3", tmp_path)
    (out3 / "negatives" / "missing-id.json").write_text(
        json.dumps({"id": "ok", "schema_version": "1.0.0"})
    )
    assert any("negative was accepted" in p for p in scaffold.verify("schema", out3))


def test_capability_checker_rejects_damage(tmp_path):
    out = scaffold.new("capability", "cap-x", tmp_path)
    (out / "CONTRACT.md").unlink()
    (out / "fake.py").write_text("x = 1\n")
    probs = scaffold.verify("capability", out)
    assert any("CONTRACT.md" in p for p in probs) and any("SPDX" in p for p in probs)


def test_detection_checker_rejects_damage(tmp_path):
    out = scaffold.new("detection", "det-x", tmp_path)
    (out / "fixtures" / "must_not_fire.json").unlink()
    assert any("must_not_fire" in p for p in scaffold.verify("detection", out))
    out2 = scaffold.new("detection", "det-y", tmp_path)
    (out2 / "rule.yml").write_text(
        "title: t\nlogsource: {}\nlevel: low\ndetection: {selection: {a: 1}}\n"
    )
    assert any("condition" in p for p in scaffold.verify("detection", out2))


@pytest.mark.parametrize(
    "kind,name",
    [
        ("role", "Bad-Name"),
        ("role", "1abc"),
        ("schema", "Bad_Name"),
        ("capability", "x y"),
        ("detection", "../escape"),
    ],
)
def test_bad_names_refused(tmp_path, kind, name):
    with pytest.raises(core.ScaffoldError):
        scaffold.new(kind, name, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_refuses_to_overwrite(tmp_path):
    scaffold.new("schema", "dup", tmp_path)
    with pytest.raises(core.ScaffoldError, match="already exists"):
        scaffold.new("schema", "dup", tmp_path)


def test_cli_new(tmp_path, capsys):
    assert core.main(["new", "detection", "cli-det", "--dest", str(tmp_path)]) == 0
    assert core.main(["new", "detection", "cli-det", "--dest", str(tmp_path)]) == 1
    assert (tmp_path / "detections" / "cli-det" / "rule.yml").is_file()


def test_every_scaffolded_file_has_spdx_where_commentable(tmp_path):
    for kind, name in (("role", "r_x"), ("capability", "c-x"), ("detection", "d-x")):
        out = scaffold.new(kind, name, tmp_path)
        for f in out.rglob("*"):
            if f.is_file() and f.suffix in (".py", ".yml", ".md"):
                assert "SPDX-License-Identifier: Apache-2.0" in f.read_text(), f
