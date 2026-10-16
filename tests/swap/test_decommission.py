# SPDX-License-Identifier: Apache-2.0
"""Fixture trees: stale alias, env var, systemd unit, doc, registry row, inventory -> non-zero."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from support import ROOT, registry_text

from homelabnext.swap import Retired, retired_from_record, scan
from homelabnext.swap.decommission import load_allow

TOOL = ROOT / "tools" / "decommission_check.py"
RET = Retired(
    "oldlake",
    hosts=("oldlake-core",),
    impls=("oldlake",),
    aliases=("query-old.svc.example.internal",),
    env_vars=("OLDLAKE_URL",),
    units=("oldlake-sync",),
)


def build(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def kinds(found):
    return sorted({f.kind for f in found})


def test_clean_tree_is_clean(tmp_path):
    build(tmp_path, {"a.md": "The lake-core host serves queries.\n", "b.yml": "x: 1\n"})
    assert scan([tmp_path], RET) == []


@pytest.mark.parametrize(
    "rel,text,kind",
    [
        ("etc/app.env", "OLDLAKE_URL=https://x.example.internal\n", "env-var"),
        ("cfg/dns.conf", "cname query-old.svc.example.internal.\n", "alias"),
        ("units/oldlake-sync.service", "[Service]\nExecStart=/bin/true\n", "unit-file"),
        ("units/other.timer", "[Timer]\nUnit=oldlake-sync.service\n", "systemd-unit"),
        ("docs/ops.md", "Restart oldlake-core after patching.\n", "doc"),
        ("src/app.py", "client = connect('oldlake-core')\n", "host"),
        ("src/app2.py", "backend = 'OldLake'\n", "impl"),
    ],
)
def test_each_kind_of_stale_reference_is_found(tmp_path, rel, text, kind):
    build(tmp_path, {rel: text})
    assert kind in kinds(scan([tmp_path], RET))


def test_word_boundaries_avoid_false_positives(tmp_path):
    build(
        tmp_path,
        {
            "a.md": "oldlake-core-2 and oldlake-corex and notoldlake are different names\n",
            "b.env": "OLDLAKE_URL_NEW=1\nmy_OLDLAKE_URL=1\n",
        },
    )
    assert scan([tmp_path], RET) == []


def test_env_var_match_is_case_sensitive_names_are_not(tmp_path):
    build(tmp_path, {"a.env": "oldlake_url=1\n", "b.md": "see OLDLAKE-CORE\n"})
    found = scan([tmp_path], RET)
    assert [f.path for f in found] == ["b.md"]


def test_registry_rows_and_inventory(tmp_path):
    reg = tmp_path / "services.yml"
    reg.write_text(registry_text().replace("impl: trino", "impl: oldlake"), encoding="utf-8")
    inv = tmp_path / "hosts.yml"
    inv.write_text("all:\n  hosts:\n    oldlake-core:\n", encoding="utf-8")
    found = scan([], RET, registry=reg, inventory=[inv])
    assert {"registry-impl", "inventory"} <= set(kinds(found))
    reg.write_text(registry_text(), encoding="utf-8")
    assert scan([], RET, registry=reg) == []


def test_allow_globs_and_default_exclusions(tmp_path):
    build(
        tmp_path,
        {
            "CHANGELOG.md": "retired oldlake-core\n",
            "swaps/s1.swap.json": '{"x": "oldlake"}',
            "swaps/s1.evidence/step.json": "oldlake",
            "src/a.py": "oldlake\n",
            ".git/config": "oldlake\n",
        },
    )
    found = scan([tmp_path], RET)
    assert sorted(f.path for f in found) == ["CHANGELOG.md", "src/a.py"]
    assert [f.path for f in scan([tmp_path], RET, allow=["CHANGELOG.md"])] == ["src/a.py"]


def test_binary_and_missing_root(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe\x00oldlake")
    assert scan([tmp_path], RET) == []
    with pytest.raises(FileNotFoundError):
        scan([tmp_path / "nope"], RET)


def test_retired_from_record_keeps_names_the_flip_kept():
    rec = {
        "from_adapter": "a-lake",
        "route": {
            "before": {"host": "h1", "port": 1, "impl": "x"},
            "after": {"host": "h2", "port": 1, "impl": "x"},
        },
    }
    r = retired_from_record(rec)
    assert r.impls == () and r.hosts == () and r.name == "a-lake"


def run(*args):
    return subprocess.run(
        [sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True, check=False
    )


def test_cli_exit_codes(tmp_path):
    clean = build(tmp_path / "clean", {"a.md": "fine\n"})
    dirty = build(tmp_path / "dirty", {"a.md": "uses oldlake-core\n", "x.env": "OLDLAKE_URL=1\n"})
    assert run(clean, "--host", "oldlake-core").returncode == 0
    r = run(dirty, "--host", "oldlake-core", "--env-var", "OLDLAKE_URL")
    assert r.returncode == 1 and "2 reference(s)" in r.stdout
    j = run(dirty, "--host", "oldlake-core", "--json")
    assert json.loads(j.stdout)["clean"] is False
    assert run(dirty).returncode == 2  # nothing to look for
    assert run(tmp_path / "missing", "--host", "h").returncode == 2
    allow = tmp_path / "allow.txt"
    allow.write_text("# history\na.md\n", encoding="utf-8")
    assert run(dirty, "--host", "oldlake-core", "--allow", allow).returncode == 0
    assert load_allow(allow) == ["a.md"]


def test_cli_from_record(tmp_path):
    rec = tmp_path / "r.swap.json"
    rec.write_text(
        json.dumps(
            {
                "from_adapter": "oldlake",
                "route": {
                    "before": {"host": "h", "port": 1, "impl": "oldlake"},
                    "after": {"host": "h", "port": 1, "impl": "newlake"},
                },
            }
        )
    )
    tree = build(tmp_path / "t", {"a.md": "still on oldlake\n"})
    assert run(tree, "--from-record", rec).returncode == 1
    assert run(build(tmp_path / "t2", {"a.md": "ok\n"}), "--from-record", rec).returncode == 0
    assert run(tree, "--from-record", tmp_path / "nope.json").returncode == 2
