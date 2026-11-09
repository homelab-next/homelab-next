# SPDX-License-Identifier: Apache-2.0
"""Pass and fail fixtures for each pillar-X plugin; SERVER ones must skip with a reason."""

import json
import pathlib

import pytest
import yaml

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
    """X-01..X-08, X-11 and X-12 live in pillar_x; X-09 and X-10 come through the entry-point
    group."""
    assert sorted(default_registry().checks) == [
        *(f"X-0{i}" for i in range(1, 9)),
        "X-11",
        "X-12",
    ]


def test_x11_runs_the_product_name_lint(tmp_path):
    r = default_registry().get("X-11").fn(ctx(tmp_path))
    assert r.status == "skip"  # no tool in an empty tree


# X-06 and `detections lint-ids` are one rule with one implementation: same files, same verdict
PARITY_FILES = {
    "agents/triage/charters/charter.md": "Escalate when rule 900301 fires.\n",
    "profiles/p/x.md": "sid: 900302\n",
    "workflows/decisions/page.yml": "when: rule 900300\n",
    "homelabnext/decide/examples/decision_spec.yml": "on: rule_id 900303\n",
    "schedules/s.yml": "watch: det:no-such-detection\n",
    "workflows/packs/p.yml": "trigger: {where: [{ref: $event.data.detection, equals: det:no-such-pack-det}]}\n",
}


def test_x06_and_lint_ids_agree_on_the_same_tree(tmp_path, monkeypatch, capsys):
    from homelabnext.detections.cli import main as det_main

    write(tmp_path / "detections/det_map.yml", (REPO / "detections/det_map.yml").read_text())
    for rel, text in PARITY_FILES.items():
        write(tmp_path / rel, text)
    monkeypatch.chdir(tmp_path)
    r = pillar_x.x06(ctx(tmp_path))
    assert det_main(["--root", "detections", "lint-ids"]) == 1
    out = capsys.readouterr().out
    assert r.status == "fail"
    for rel in PARITY_FILES:
        assert rel in r.evidence and rel in out, rel
    for rel in PARITY_FILES:
        write(tmp_path / rel, "Watches det:web-shell-write. Revised on 2026-10-15.\n")
    assert pillar_x.x06(ctx(tmp_path)).status == "pass"
    assert det_main(["--root", "detections", "lint-ids"]) == 0


# ---- X-03 in a tree with the repository checker: one implementation, the checker's ----------


def test_x03_runs_the_repository_schema_checker_where_the_tree_has_it(tmp_path):
    """With ``tools/schema_check.py`` present, X-03 is that checker under ``--strict`` (the one
    CI runs: every ``*.json`` schema, its instance rule, its ``$id`` rule), not a second copy
    that covered fewer schemas and matched instances differently."""
    good_schema_tree(tmp_path)
    write(tmp_path / "tools" / "schema_check.py", "raise SystemExit(0)\n")
    seen = []

    def run(argv, timeout=120):
        seen.append(argv)
        return 1, "ERROR schemas/ocsf/thing.v1.json: example invalid"

    r = pillar_x.x03(ctx(tmp_path, run))
    assert r.status == "fail" and "thing.v1.json" in r.evidence
    assert seen and seen[0][1].endswith("tools/schema_check.py") and "--strict" in seen[0]


def test_x03_on_this_repository_checks_every_schema_the_checker_does():
    root = pathlib.Path(__file__).resolve().parents[2]
    r = pillar_x.x03(ctx(root))
    assert r.status == "pass", r.evidence
    assert "schema_check --strict" in r.evidence


# ---- X-12: no non-primary registry row past its until (ADR-0039 decision 8) -------------------

REPO = pathlib.Path(__file__).resolve().parents[2]
LATE = """
  dns-trial:
    capability: dns
    impl: other-resolver
    host: dns-core
    protocol: dns
    port: 5353
    owner: platform-team
    version: "1.0"
    tls: none
    standing: {tier: eval, until: "2026-11-30", why: the resolver candidate}
"""


def _lab_registry(root: pathlib.Path, extra: str = "") -> pathlib.Path:
    text = (REPO / "examples" / "minimal" / "services.yml").read_text()
    path = root / "lab" / "services.yml"
    write(path, text.rstrip("\n") + "\n" + extra)
    return path


def test_x12_runs_green_over_the_repository_s_registries(monkeypatch):
    monkeypatch.setenv("HNX_TODAY", "2026-11-08")
    r = default_registry().get("X-12").fn(ctx(REPO))
    assert r.status == "pass", r.evidence
    # examples/ and its three labs; the four-box lab's dated eval row makes the green a judgement
    assert r.evidence.startswith("4 registries, 1 non-primary row(s) in date on 2026-11-08")


def test_x12_fails_on_a_row_past_its_until_and_passes_on_the_day(tmp_path, monkeypatch):
    _lab_registry(tmp_path, LATE)
    monkeypatch.setenv("HNX_TODAY", "2026-11-30")  # on its date: not yet past it
    assert pillar_x.x12(ctx(tmp_path)).status == "pass"
    monkeypatch.setenv("HNX_TODAY", "2026-12-01")
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "fail"
    assert "lab/services.yml: dns-trial (eval dns) until 2026-11-30" in r.evidence


def test_x12_skips_an_empty_tree_ignores_tests_and_errors_on_what_it_cannot_judge(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HNX_TODAY", "2027-01-01")
    assert pillar_x.x12(ctx(tmp_path)).status == "skip"
    _lab_registry(tmp_path / "tests", LATE)  # a test fixture is no registry of the tree
    assert pillar_x.x12(ctx(tmp_path)).status == "skip"
    write(tmp_path / "lab" / "services.yml", "registry_version: 1\nservices: [unclosed\n")
    assert pillar_x.x12(ctx(tmp_path)).status == "error"
    _lab_registry(tmp_path)
    monkeypatch.setenv("HNX_TODAY", "tomorrow")
    assert pillar_x.x12(ctx(tmp_path)).status == "error"


# ---- X-12 review follow-ups -------------------------------------------------------------------


def test_x12_follows_no_link_out_of_the_tree_and_echoes_no_file_content(tmp_path, monkeypatch):
    """A symlinked services.yml (or a symlinked directory holding one) pointed the check at a file
    outside the repository, and an unparseable registry's error quoted its lines."""
    monkeypatch.setenv("HNX_TODAY", "2026-11-09")
    outside = tmp_path / "outside"
    write(outside / "services.yml", "registry_version: 1\nservices: [MARKER-OUTSIDE-TEXT\n")
    root = tmp_path / "repo"
    (root / "lab").mkdir(parents=True)
    (root / "lab" / "services.yml").symlink_to(outside / "services.yml")
    (root / "linked").symlink_to(outside, target_is_directory=True)
    r = pillar_x.x12(ctx(root))
    assert r.status == "error"
    assert "lab/services.yml: a symbolic link" in r.evidence
    assert "linked/" not in r.evidence  # a linked directory is not walked
    assert "MARKER" not in r.evidence
    (root / "lab" / "services.yml").unlink()
    write(root / "lab" / "services.yml", "registry_version: 1\nservices: [MARKER-INSIDE-TEXT\n")
    r = pillar_x.x12(ctx(root))
    assert r.status == "error" and "MARKER" not in r.evidence
    assert "lab/services.yml: cannot be read as one YAML document" in r.evidence  # text not quoted


def test_x12_selects_registries_by_content_at_any_depth(tmp_path, monkeypatch):
    monkeypatch.setenv("HNX_TODAY", "2026-12-01")
    deep = tmp_path / "a" / "b" / "c" / "services.yml"
    write(deep, (REPO / "examples" / "minimal" / "services.yml").read_text() + LATE)
    write(tmp_path / "mod" / "services.yml", "services: {}\n")  # a module fragment: no version
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "fail" and "a/b/c/services.yml: dns-trial" in r.evidence
    assert "mod/services.yml" not in r.evidence


def test_x12_judges_every_registry_and_names_what_it_could_not(tmp_path, monkeypatch):
    """An invalid registry no longer stops the check before an overdue row elsewhere."""
    monkeypatch.setenv("HNX_TODAY", "2026-12-01")
    write(tmp_path / "a" / "services.yml", "registry_version: 1\nservices: [unclosed\n")
    _lab_registry(tmp_path, LATE)
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "fail"
    assert "lab/services.yml: dns-trial (eval dns) until 2026-11-30" in r.evidence
    assert "could not judge: a/services.yml:" in r.evidence


def test_x12_names_a_registry_whose_until_is_no_date_as_unjudged(tmp_path, monkeypatch):
    """The registry refuses an until that is no calendar date, so X-12 cannot judge that
    registry: an error naming it, never "overdue by 1 day"."""
    monkeypatch.setenv("HNX_TODAY", "2026-11-01")
    _lab_registry(tmp_path, LATE.replace("2026-11-30", "2026-02-30"))
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "error" and "lab/services.yml: RegistryError" in r.evidence
    assert "overdue" not in r.evidence


def test_x12_passes_with_the_date_it_judged_and_marks_an_override(tmp_path, monkeypatch):
    _lab_registry(tmp_path, LATE)
    monkeypatch.setenv("HNX_TODAY", "2026-11-09")
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "pass" and "in date on 2026-11-09 (HNX_TODAY)" in r.evidence


def _minimal_registry_doc() -> dict:
    return yaml.safe_load((REPO / "examples" / "minimal" / "services.yml").read_text())


@pytest.mark.parametrize("spelling", ["double", "single", "explicit", "json"])
def test_x12_finds_a_registry_however_its_version_key_is_spelled(tmp_path, monkeypatch, spelling):
    """A quoted, explicit-key or JSON registry loads like any other; X-12 used to read it as no
    registry and skip, hiding its overdue rows."""
    monkeypatch.setenv("HNX_TODAY", "2026-12-01")
    doc = _minimal_registry_doc()
    doc["services"]["dns-trial"] = yaml.safe_load(LATE)["dns-trial"]
    body = yaml.safe_dump({k: v for k, v in doc.items() if k != "registry_version"})
    version = doc["registry_version"]
    text = {
        "double": f'"registry_version": {version}\n' + body,
        "single": f"'registry_version': {version}\n" + body,
        "explicit": f"? registry_version\n: {version}\n" + body,
        "json": json.dumps(doc),
    }[spelling]
    write(tmp_path / "lab" / "services.yml", text)
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "fail", r.evidence
    assert "lab/services.yml: dns-trial (eval dns) until 2026-11-30" in r.evidence


def test_x12_refuses_a_services_file_it_cannot_parse_and_names_what_it_skipped(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("HNX_TODAY", "2026-11-09")
    assert "not searched: hidden directories, __pycache__, build, dist, node_modules, tests" in (
        pillar_x.x12(ctx(tmp_path)).evidence
    )
    write(tmp_path / "lab" / "services.yml", '"registry_version": [unclosed\n')
    r = pillar_x.x12(ctx(tmp_path))
    assert (
        r.status == "error"
        and "lab/services.yml: cannot be read as one YAML document" in r.evidence
    )
    assert "unclosed" not in r.evidence


@pytest.mark.parametrize("form", ["mapping", "anchor", "list"])
def test_x12_finds_a_registry_whose_version_comes_through_a_merge_key(tmp_path, monkeypatch, form):
    """``<<: {registry_version: 1}`` (or through an anchor) loads as a registry; X-12 read it as
    none and skipped, hiding its overdue rows."""
    monkeypatch.setenv("HNX_TODAY", "2026-12-01")
    doc = _minimal_registry_doc()
    doc["services"]["dns-trial"] = yaml.safe_load(LATE)["dns-trial"]
    version = doc.pop("registry_version")
    body = yaml.safe_dump(doc)
    text = {
        "mapping": f"<<: {{registry_version: {version}}}\n" + body,
        "anchor": f"<<: [&base {{registry_version: {version}}}, *base]\n" + body,
        "list": f"<<: [{{registry_version: {version}}}]\n" + body,
    }[form]
    from homelabnext.registry import model

    path = tmp_path / "lab" / "services.yml"
    write(path, text)
    model.load(path)  # the registry loader reads it as a registry
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "fail", r.evidence
    assert "lab/services.yml: dns-trial (eval dns) until 2026-11-30" in r.evidence


def test_x12_names_a_multi_document_services_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HNX_TODAY", "2026-11-09")
    write(tmp_path / "lab" / "services.yml", "registry_version: 1\n---\nservices: {}\n")
    r = pillar_x.x12(ctx(tmp_path))
    assert r.status == "error"
    assert "lab/services.yml: cannot be read as one YAML document" in r.evidence
