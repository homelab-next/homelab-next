# SPDX-License-Identifier: Apache-2.0
"""Pass and fail fixtures for each pillar-X plugin; SERVER ones must skip with a reason."""

import json

import pytest

from homelabnext.invariants import Context, default_registry
from homelabnext.invariants.plugins import pillar_x

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://schemas.lab.example/thing/v1",
    "x-version": "1.0",
    "type": "object",
    "required": ["name"],
    "properties": {"name": {"type": "string"}},
    "additionalProperties": False,
}


def write(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text if isinstance(text, str) else json.dumps(text))


def ctx(root, run=None):
    return Context(root, run)


def good_schema_tree(root):
    d = root / "schemas" / "platform"
    write(d / "thing.schema.json", SCHEMA)
    write(d / "examples" / "thing.basic.json", {"name": "a"})
    write(d / "negatives" / "thing.noname.json", {"other": 1})
    return d


# ---- X-01 / X-05: tool-wrapping checks --------------------------------------------------------


@pytest.mark.parametrize(
    "fn, tool, extra",
    [
        (pillar_x.x01, "tools/no_raw_endpoints.py", None),
        (pillar_x.x05, "tools/role_lint.py", "ansible/roles/r"),
    ],
)
def test_tool_checks_pass_fail_skip_error(tmp_path, fn, tool, extra):
    if extra:
        (tmp_path / extra).mkdir(parents=True)
    assert fn(ctx(tmp_path)).status == "skip"  # tool absent
    for code, want in ((0, "pass"), (1, "fail"), (100, "error")):
        write(tmp_path / tool, f"import sys; print('tool output'); sys.exit({code})\n")
        r = fn(ctx(tmp_path))
        assert r.status == want, r


def test_x05_skips_without_roles_dir(tmp_path):
    write(tmp_path / "tools/role_lint.py", "import sys; sys.exit(1)\n")
    assert pillar_x.x05(ctx(tmp_path)).status == "skip"


def test_x01_runs_the_real_tool_through_injected_runner(tmp_path):
    write(tmp_path / "tools/no_raw_endpoints.py", "")
    seen = []
    pillar_x.x01(ctx(tmp_path, lambda argv, timeout=0: seen.append(argv) or (0, "")))
    assert seen and seen[0][1].endswith("tools/no_raw_endpoints.py")


# ---- X-03 -------------------------------------------------------------------------------------


def test_x03_pass(tmp_path):
    good_schema_tree(tmp_path)
    assert pillar_x.x03(ctx(tmp_path)).status == "pass"


def test_x03_skip_without_schemas(tmp_path):
    assert pillar_x.x03(ctx(tmp_path)).status == "skip"


@pytest.mark.parametrize(
    "breakage, needle",
    [
        ("unpinned", "not version-pinned"),
        ("no_id", "needs $schema and $id"),
        ("bad_example", "example invalid"),
        ("accepted_negative", "negative was ACCEPTED"),
        ("no_negative", "no negative"),
        ("no_example", "no example"),
        ("broken_schema", "not a valid schema"),
    ],
)
def test_x03_fail_fixtures(tmp_path, breakage, needle):
    d = good_schema_tree(tmp_path)
    s = dict(SCHEMA)
    if breakage == "unpinned":
        s.pop("x-version"), s.update({"$id": "https://schemas.lab.example/thing"})
        write(d / "thing.schema.json", s)
    elif breakage == "no_id":
        s.pop("$id")
        write(d / "thing.schema.json", s)
    elif breakage == "bad_example":
        write(d / "examples" / "thing.basic.json", {"name": 5})
    elif breakage == "accepted_negative":
        write(d / "negatives" / "thing.noname.json", {"name": "fine"})
    elif breakage == "no_negative":
        (d / "negatives" / "thing.noname.json").unlink()
    elif breakage == "no_example":
        (d / "examples" / "thing.basic.json").unlink()
    elif breakage == "broken_schema":
        write(d / "thing.schema.json", {**SCHEMA, "type": "not-a-type"})
    r = pillar_x.x03(ctx(tmp_path))
    assert r.status == "fail" and needle in r.evidence


def test_x03_version_in_id_segment_is_enough(tmp_path):
    d = good_schema_tree(tmp_path)
    s = dict(SCHEMA)
    s.pop("x-version")
    write(d / "thing.schema.json", s)
    assert pillar_x.x03(ctx(tmp_path)).status == "pass"


# ---- X-04 -------------------------------------------------------------------------------------


def test_x04_pass_from_conformance_tree(tmp_path):
    write(tmp_path / "conformance/lake-query/test_basic.py", "")
    write(tmp_path / "conformance/notify/test_basic.py", "")
    assert pillar_x.x04(ctx(tmp_path)).status == "pass"


def test_x04_fail_when_declared_capability_has_no_test(tmp_path):
    write(tmp_path / "capabilities.yml", "capabilities: [lake-query, notify, secrets]\n")
    write(tmp_path / "conformance/lake-query/test_basic.py", "")
    write(tmp_path / "conformance/notify/README.md", "no tests yet")
    r = pillar_x.x04(ctx(tmp_path))
    assert r.status == "fail" and "notify" in r.evidence and "secrets" in r.evidence
    assert "lake-query" not in r.evidence


def test_x04_skip_without_any_tree(tmp_path):
    assert pillar_x.x04(ctx(tmp_path)).status == "skip"


# ---- X-06 -------------------------------------------------------------------------------------


def test_x06_pass_with_logical_ids(tmp_path):
    write(tmp_path / "det_map.yml", "detections:\n  auth.burst: 900001\n  dns.nrd: 900002\n")
    write(
        tmp_path / "charters/reader.md",
        "Watches det:auth.burst and det:dns.nrd. See det:auth.burst.\n",
    )
    assert pillar_x.x06(ctx(tmp_path)).status == "pass"


@pytest.mark.parametrize(
    "line",
    [
        "Rule 900299 fired",
        "rule_id: 900299",
        "rule id=5712",
        'rule: "900299"',
        "Rule #31151 is noisy",
    ],
)
def test_x06_flags_raw_rule_numbers(tmp_path, line):
    write(tmp_path / "profiles/p.yml", f"charter: |\n  {line}\n")
    r = pillar_x.x06(ctx(tmp_path))
    assert r.status == "fail" and "profiles/p.yml" in r.evidence


def test_x06_flags_unknown_logical_id(tmp_path):
    write(tmp_path / "det_map.yml", "detections:\n  auth.burst: 900001\n")
    write(tmp_path / "schedules/s.yml", "watch: det:auth.nonexistent\n")
    r = pillar_x.x06(ctx(tmp_path))
    assert r.status == "fail" and "auth.nonexistent" in r.evidence


def test_x06_ignores_ordinary_numbers_and_skips_when_no_specs(tmp_path):
    assert pillar_x.x06(ctx(tmp_path)).status == "skip"
    write(tmp_path / "charters/c.md", "Runs 1000 times; port 8080; ruled out 2024 cases.\n")
    assert pillar_x.x06(ctx(tmp_path)).status == "pass"


# ---- SERVER ones + registry -------------------------------------------------------------------


@pytest.mark.parametrize("id_", ["X-02", "X-07", "X-08"])
def test_server_checks_skip_with_reason(tmp_path, id_):
    r = default_registry().get(id_).fn(ctx(tmp_path))
    assert r.status == "skip" and r.evidence.startswith("SERVER:")


def test_all_eight_pillar_x_checks_registered():
    assert sorted(default_registry().checks) == [f"X-0{i}" for i in range(1, 9)]
