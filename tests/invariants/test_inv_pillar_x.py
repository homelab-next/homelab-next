# SPDX-License-Identifier: Apache-2.0
"""Pass and fail fixtures for each pillar-X plugin; SERVER ones must skip with a reason."""

import json
import pathlib

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
    write(d / "negative" / "thing.noname.json", {"other": 1})
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
        write(d / "negative" / "thing.noname.json", {"name": "fine"})
    elif breakage == "no_negative":
        (d / "negative" / "thing.noname.json").unlink()
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


# ---- X-03 regression: directory is 'negative/' singular, not 'negatives/' ----
#
# The bug: the plugin used to glob ``negatives/`` (plural) while the repo's directory layout
# (and the matching ``tools/schema_check.py``) is ``negative/`` (singular). A schema whose
# negative wrongly validated would have been reported as ``no negative`` instead of
# ``negative was ACCEPTED`` - the critical signal (a false acceptance by the schema) was
# silently invisible to this check. This test puts a wrongly-validating negative into the
# correct singular directory and asserts the plugin FLAGS it with the accepted message. Run
# against the pre-fix plugin, the test fails: the plugin's ``negatives/`` glob misses the
# file in ``negative/`` and reports ``no negative`` instead.


def test_x03_flags_wrongly_validating_negative_in_singular_directory(tmp_path):
    d = tmp_path / "schemas" / "platform"
    write(d / "thing.schema.json", SCHEMA)
    write(d / "examples" / "thing.basic.json", {"name": "a"})
    # Negative lives in SINGULAR 'negative/' - matches the repo layout.
    # Its content VALIDATES against the schema, which is the whole bug the check must catch.
    write(d / "negative" / "thing.wrong.json", {"name": "accepted"})
    r = pillar_x.x03(ctx(tmp_path))
    assert r.status == "fail", r
    assert "negative was ACCEPTED" in r.evidence, r.evidence
    # Pre-fix plugin would report 'no negative' - evidence of the directory-name bug.
    assert "no negative in" not in r.evidence, r.evidence


def test_x03_resolves_cross_schema_ref_without_network(tmp_path):
    # The plugin must build a validator with a referencing Registry so that cross-schema
    # ``$ref``s do not fall through to HTTP retrieval. Without a registry, ``is_valid``
    # either hits the network or raises Unresolvable - either way the gate is broken.
    other_id = "https://schemas.lab.example/other/v1"
    other = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": other_id,
        "x-version": "1.0",
        "$defs": {"name": {"type": "string", "minLength": 1}},
    }
    using = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.lab.example/using/v1",
        "x-version": "1.0",
        "type": "object",
        "required": ["name"],
        "properties": {"name": {"$ref": other_id + "#/$defs/name"}},
        "additionalProperties": False,
    }
    d = tmp_path / "schemas"
    write(d / "a" / "other.schema.json", other)
    write(d / "b" / "using.schema.json", using)
    write(d / "a" / "examples" / "other.ok.json", {})  # $defs-only; empty object is fine
    write(d / "a" / "negative" / "other.bad.json", {"$defs": "nope"})
    write(d / "b" / "examples" / "using.basic.json", {"name": "ok"})
    # Negative: name is empty -> fails the referenced minLength rule; only passes if the
    # $ref resolves through the registry.
    write(d / "b" / "negative" / "using.empty.json", {"name": ""})
    r = pillar_x.x03(ctx(tmp_path))
    # Not asserting pass on 'other' (a $defs-only schema is awkward to make clean here)
    # - the specific thing being asserted is that the ``using`` schema's example and
    # negative did NOT raise an Unresolvable, which the old code would have.
    assert "Unresolvable" not in r.evidence, r.evidence
    assert "could not validate" not in r.evidence or "using" not in r.evidence, r.evidence


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


DET_MAP = "entries:\n  det:auth.burst: 900001\n  det:dns.nrd: 900002\nretired: []\n"
REPO = pathlib.Path(__file__).resolve().parents[2]


def test_x06_pass_with_logical_ids(tmp_path):
    write(tmp_path / "detections/det_map.yml", DET_MAP)
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
    write(tmp_path / "detections/det_map.yml", DET_MAP)
    write(tmp_path / "schedules/s.yml", "watch: det:auth.nonexistent\n")
    r = pillar_x.x06(ctx(tmp_path))
    assert r.status == "fail" and "auth.nonexistent" in r.evidence
    assert "detections/det_map.yml" in r.evidence


def test_x06_resolves_against_the_repositorys_real_det_map(tmp_path):
    # regression: the plugin once read a root det_map.yml under `detections:`, which this
    # repository does not have, so an unknown det: id was never caught
    write(tmp_path / "detections/det_map.yml", (REPO / "detections/det_map.yml").read_text())
    write(tmp_path / "profiles/p/README.md", "Watches det:web-shell-write.\n")
    assert pillar_x.x06(ctx(tmp_path)).status == "pass"
    write(tmp_path / "profiles/p/README.md", "Watches det:no-such-detection.\n")
    r = pillar_x.x06(ctx(tmp_path))
    assert r.status == "fail" and "det:no-such-detection" in r.evidence


def test_x06_falls_back_to_a_root_det_map(tmp_path):
    write(tmp_path / "det_map.yml", DET_MAP)
    write(tmp_path / "charters/c.md", "det:auth.burst and det:auth.gone\n")
    r = pillar_x.x06(ctx(tmp_path))
    assert r.status == "fail" and "auth.gone" in r.evidence and "auth.burst" not in r.evidence


def test_x06_ignores_ordinary_numbers_and_skips_when_no_specs(tmp_path):
    assert pillar_x.x06(ctx(tmp_path)).status == "skip"
    write(tmp_path / "charters/c.md", "Runs 1000 times; port 8080; ruled out 2024 cases.\n")
    assert pillar_x.x06(ctx(tmp_path)).status == "pass"


# ---- SERVER ones + registry -------------------------------------------------------------------


@pytest.mark.parametrize("id_", ["X-02", "X-07", "X-08"])
def test_server_checks_skip_with_reason(tmp_path, id_):
    r = default_registry().get(id_).fn(ctx(tmp_path))
    assert r.status == "skip" and r.evidence.startswith("SERVER:")


def test_the_pillar_x_checks_registered_here():
    """X-01..X-08 and X-11 live in pillar_x; X-09 and X-10 come through the entry-point group."""
    assert sorted(default_registry().checks) == [*(f"X-0{i}" for i in range(1, 9)), "X-11"]


def test_x11_runs_the_product_name_lint(tmp_path):
    r = default_registry().get("X-11").fn(ctx(tmp_path))
    assert r.status == "skip"  # no tool in an empty tree
