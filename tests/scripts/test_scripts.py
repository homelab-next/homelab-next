# SPDX-License-Identifier: Apache-2.0
"""Script catalog (M-01), catalog vs reality (M-02), checks only in the runner (M-04).

Each check is shown failing on a small synthetic tree with the defect planted, passing once the
defect is gone, and passing on this repository.
"""

from __future__ import annotations

import json
import pathlib
import textwrap

import pytest
import yaml

from homelabnext.invariants import Check, CheckResult, Context, Registry, run_criteria
from homelabnext.scripts import (
    Allow,
    HeaderError,
    build,
    check_current,
    discover,
    find_header,
    load_allow,
    reality_problems,
    runner_problems,
    tracked_files,
    validate,
)
from homelabnext.scripts import catalog as catalog_mod
from homelabnext.scripts.cli import main
from homelabnext.scripts.reality import AllowError

REPO = pathlib.Path(__file__).resolve().parents[2]
MARK = "# hnx-" + "script:"  # spelled in two parts so this file never carries a header line


def header(**fields) -> str:
    """A header block (after a shebang and the SPDX line) for a synthetic script."""
    doc = {
        "id": "demo",
        "kind": "tool",
        "purpose": "Do the demo thing for the tests.",
        "owner": "maintainers",
        "trigger": ["manual"],
        "inputs": "nothing",
        "outputs": "nothing",
        "exit": {"0": "ok"},
    }
    doc.update(fields)
    doc = {k: v for k, v in doc.items() if v is not None}
    body = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False).splitlines()
    return "\n".join(
        ["#!/usr/bin/env python3", "# SPDX-License-Identifier: Apache-2.0", MARK]
        + [f"#   {line}" for line in body]
        + ['"""Demo."""', ""]
    )


def tree(root: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text) if not text.startswith("#!") else text)
    return root


CHECK = header(
    id="demo-check",
    kind="check",
    trigger=["make:demo"],
    invariant=["Q-09"],
    exit={"0": "holds", "1": "broken"},
)
REGISTER = """\
criteria:
- id: Q-09
  statement: Demo.
  evidence: auto
  observable: python3 tools/demo_check.py && echo ok
"""
MAKEFILE = "PY ?= python3\n\ndemo:\n\t$(PY) tools/demo_check.py\n"


def good_tree(root: pathlib.Path) -> pathlib.Path:
    return tree(
        root,
        {
            "Makefile": MAKEFILE,
            "tools/demo_check.py": CHECK,
            "examples/registers/invariants.yml": REGISTER,
        },
    )


def verdicts(root: pathlib.Path, registry: Registry | None = None):
    files = tracked_files(root)
    cat = build(root, files)
    allow = load_allow(root)
    real = discover(root, cat, files, allow, plugin_registry=registry or Registry())
    return cat, reality_problems(cat, real, allow), runner_problems(cat, real, allow)


# ---- the header ------------------------------------------------------------------------------


def test_header_parses_and_normalises_exit_codes():
    text = header(exit={0: "ok", 2: "usage"})
    head = find_header(text)
    assert head["id"] == "demo" and head["exit"] == {"0": "ok", "2": "usage"}
    assert validate(head) == []


def test_no_marker_is_no_header_and_a_bare_marker_is_an_error():
    assert find_header("#!/bin/sh\necho hi\n") is None
    with pytest.raises(HeaderError):
        find_header(f"#!/bin/sh\n{MARK}\necho hi\n")
    with pytest.raises(HeaderError):
        find_header(f"#!/bin/sh\n{MARK}\n#   id: [unclosed\n")


def test_marker_after_the_first_lines_does_not_count():
    assert find_header("\n" * 45 + header()) is None


@pytest.mark.parametrize(
    ("fields", "needle"),
    [
        ({"owner": None}, "'owner' is a required property"),
        ({"exit": {"1": "failed"}}, "'0' is a required property"),
        ({"trigger": ["cron:nightly"]}, "trigger/0"),
        ({"invariant": ["Q-09"]}, "only a header with kind: check"),
        ({"kind": "check", "exit": {"0": "ok", "100": "unmeasured"}}, "failing code in 1..99"),
        ({"id": "Bad_Id"}, "id:"),
        ({"surprise": 1}, "Additional properties"),
    ],
)
def test_invalid_headers_are_refused(fields, needle):
    errs = validate(find_header(header(**fields)))
    assert any(needle in e for e in errs), errs


# ---- M-01 ------------------------------------------------------------------------------------


def test_m01_fails_on_a_script_without_a_header_then_passes(tmp_path):
    root = good_tree(tmp_path)
    (root / "tools" / "bare.sh").write_text("#!/bin/sh\necho hi\n")
    cat = build(root)
    assert any("tools/bare.sh: no '# hnx-script:' header" in p for p in cat.problems)
    assert main(["--root", str(root), "catalog", "--check"]) == 1
    (root / "tools" / "bare.sh").unlink()
    assert main(["--root", str(root), "catalog"]) == 0
    assert main(["--root", str(root), "catalog", "--check"]) == 0


def test_m01_fails_on_an_invalid_header_and_a_duplicate_id(tmp_path):
    root = good_tree(tmp_path)
    tree(root, {"tools/other.py": header(id="demo-check"), "tools/bad.py": header(kind="daemon")})
    probs = build(root).problems
    assert any("duplicate script id 'demo-check'" in p for p in probs), probs
    assert any(p.startswith("tools/bad.py: header kind") for p in probs), probs


def test_m01_fails_when_the_committed_catalog_is_stale(tmp_path):
    root = good_tree(tmp_path)
    assert main(["--root", str(root), "catalog"]) == 0
    assert check_current(root, build(root)) == []
    doc = json.loads((root / catalog_mod.CATALOG_JSON).read_text())
    assert [e["id"] for e in doc["scripts"]] == ["demo-check"]
    text = (root / "tools" / "demo_check.py").read_text()
    (root / "tools" / "demo_check.py").write_text(text.replace("Do the demo", "Do another demo"))
    stale = check_current(root, build(root))
    assert len(stale) == 2 and all("stale" in p for p in stale)


def test_excluded_classes_are_not_scripts_unless_they_carry_a_header(tmp_path):
    root = tree(
        tmp_path,
        {
            "homelabnext/mod.py": "x = 1\n",
            "tests/test_x.py": "#!/usr/bin/env python3\n",
            "conftest.py": "x = 1\n",
            "conformance/fakes/server.py": header(id="fake-server", kind="service"),
        },
    )
    cat = build(root)
    assert cat.problems == []
    assert [e["path"] for e in cat.entries] == ["conformance/fakes/server.py"]


# ---- M-02 ------------------------------------------------------------------------------------


def test_m02_passes_when_triggers_match_the_callers(tmp_path):
    _, reality, runner = verdicts(good_tree(tmp_path))
    assert reality == [] and runner == []


def test_m02_reports_a_caller_the_header_omits_and_a_trigger_nothing_backs(tmp_path):
    root = good_tree(tmp_path)
    (root / "Makefile").write_text(MAKEFILE + "\nagain:\n\tpython3 tools/demo_check.py --x\n")
    _, reality, _ = verdicts(root)
    assert reality == [
        "tools/demo_check.py: called by make:again, which its header's trigger list does not name"
    ]
    (root / "Makefile").write_text("other:\n\ttrue\n")
    _, reality, runner = verdicts(root)
    assert reality == [
        "tools/demo_check.py: header names trigger make:demo, but nothing there runs it"
    ]
    assert runner == []  # still run by its criterion


def test_m02_called_but_uncatalogued(tmp_path):
    root = good_tree(tmp_path)
    tree(root, {"scripts/run.py": "print('hi')\n"})  # no header; a file with no shebang
    (root / "Makefile").write_text(MAKEFILE + "\nrun:\n\tpython3 scripts/run.py\n")
    _, reality, _ = verdicts(root)
    assert reality == ["make:run: runs scripts/run.py, which has no script header"]


def test_m02_scheduled_but_uncatalogued_and_its_allowlist(tmp_path):
    root = good_tree(tmp_path)
    tree(
        root,
        {
            "deploy/fleet_units.yml": """\
                - name: nightly-sweep
                  exec: /usr/local/bin/sweep --all
                  on_calendar: "*-*-* 02:00:00 UTC"
                - name: invariants
                  exec: /usr/local/bin/hnx invariants run /etc/hnx/invariants.yml
                  on_calendar: "*-*-* *:05:00 UTC"
            """
        },
    )
    _, reality, _ = verdicts(root)
    assert (
        len(reality) == 1 and "fleet-unit:nightly-sweep: execs /usr/local/bin/sweep" in reality[0]
    )
    allow = {"external_exec": {"/usr/local/bin/sweep": "the product's own sweeper binary"}}
    tree(root, {"tools/scripts.allow.yml": yaml.safe_dump(allow)})
    assert verdicts(root)[1] == []
    allow["external_exec"]["/usr/local/bin/gone"] = "a binary that is no longer scheduled"
    tree(root, {"tools/scripts.allow.yml": yaml.safe_dump(allow)})
    assert verdicts(root)[1] == [
        "tools/scripts.allow.yml: external_exec /usr/local/bin/gone matches no scheduled exec "
        "(stale entry)"
    ]


def test_m02_an_excluded_spec_is_not_this_trees_jobs_but_only_it(tmp_path):
    """fleet_unit_specs_exclude skips the fictional module examples (their code is named, not
    shipped, and their own tests validate them), and nothing else: a real spec beside them is
    still checked, so the exclusion cannot hide an uncatalogued job."""
    root = good_tree(tmp_path)
    unit = """\
        - name: example-job
          exec: /usr/local/libexec/hnx-modules/example/run
          on_calendar: "*-*-* 02:00:00 UTC"
    """
    tree(root, {"examples/modules/example/units/fleet_units.yml": unit})
    assert len(verdicts(root)[1]) == 1
    allow = {"fleet_unit_specs_exclude": ["examples/modules/**"]}
    tree(root, {"tools/scripts.allow.yml": yaml.safe_dump(allow)})
    assert verdicts(root)[1] == []
    tree(root, {"deploy/fleet_units.yml": unit})
    assert len(verdicts(root)[1]) == 1


def test_m02_uncalled_active_script_and_its_allowlist(tmp_path):
    root = good_tree(tmp_path)
    tree(root, {"tools/orphan.py": header(id="orphan")})
    _, reality, _ = verdicts(root)
    assert reality == [
        "tools/orphan.py: active script with no caller; add one, mark it deprecated, or "
        "allowlist it under uncalled with a reason"
    ]
    tree(root, {"tools/orphan.py": header(id="orphan", status="deprecated")})
    assert verdicts(root)[1] == []
    tree(
        root,
        {
            "tools/orphan.py": header(id="orphan"),
            "tools/scripts.allow.yml": "uncalled:\n  orphan: an operator runs it by hand, per the runbook\n",
        },
    )
    assert verdicts(root)[1] == []
    (root / "Makefile").write_text(MAKEFILE + "\norphan:\n\tpython3 tools/orphan.py\n")
    assert "uncalled orphan has a caller now (stale entry)" in "\n".join(verdicts(root)[1])


def test_m02_duplicate_ids_fail_reality_too(tmp_path):
    root = good_tree(tmp_path)
    tree(root, {"tools/twin.py": header(id="demo-check")})
    assert any("duplicate script id" in p for p in verdicts(root)[1])


def test_compose_service_resolves_through_the_dockerfile(tmp_path):
    root = good_tree(tmp_path)
    tree(
        root,
        {
            "compose/lab/docker-compose.yml": """\
                services:
                  api:
                    build: {context: ../.., dockerfile: compose/lab/Dockerfile}
                    command: ["python", "/app/server.py", "--port", "8000"]
                  init:
                    build: {context: ../.., dockerfile: compose/lab/Dockerfile}
                    command: ["python", "/app/init.py"]
                  db:
                    image: example/db
                    command: ["postgres"]
            """,
            "compose/lab/Dockerfile": (
                "FROM scratch\nCOPY conformance/fakes/server.py /app/server.py\n"
                "COPY compose/lab/init.py /app/\n"
            ),
            "conformance/fakes/server.py": header(
                id="fake-server", kind="service", trigger=["compose:lab/api"]
            ),
            "compose/lab/init.py": "print('init')\n",
        },
    )
    probs = verdicts(root)[1]
    assert probs == ["compose:lab/init: runs compose/lab/init.py, which has no script header"]


def test_script_to_script_calls_ignore_comments(tmp_path):
    root = good_tree(tmp_path)
    tree(
        root,
        {
            "lab/run.sh": header(id="lab-run", trigger=["manual"])
            + '# see helper.sh\nhere="$(dirname "$0")"\n"$here/helper.sh"\n',
            "lab/helper.sh": header(id="lab-helper", trigger=["script:lab-run"]),
            "lab/quiet.sh": header(id="lab-quiet"),
            "lab/mention.sh": header(id="lab-mention") + "# quiet.sh is not run here\n",
            "tools/scripts.allow.yml": (
                "uncalled:\n  lab-run: started by hand\n  lab-mention: started by hand\n"
            ),
        },
    )
    # helper.sh is called (and declared); a comment naming quiet.sh is not a call
    assert verdicts(root)[1] == [
        "lab/quiet.sh: active script with no caller; add one, mark it deprecated, or "
        "allowlist it under uncalled with a reason"
    ]


# ---- M-04 ------------------------------------------------------------------------------------


def test_m04_check_scheduled_directly_by_a_fleet_unit(tmp_path):
    root = good_tree(tmp_path)
    tree(
        root,
        {
            "fleet_units/checks.yml": """\
                - name: demo-check
                  exec: /usr/bin/python3 /opt/homelab-next/tools/demo_check.py
                  on_calendar: "*-*-* 03:00:00 UTC"
            """
        },
    )
    _, reality, runner = verdicts(root)
    assert any("called by fleet-unit:demo-check" in p for p in reality)
    assert runner == [
        "tools/demo_check.py: check scheduled directly by fleet-unit:demo-check; schedule "
        "`hnx invariants run` and let the criterion run it"
    ]


def test_m04_check_on_a_role_timer_or_a_scheduled_workflow(tmp_path):
    root = good_tree(tmp_path)
    tree(
        root,
        {
            "tools/demo_check.py": CHECK.replace(
                "#   - make:demo",
                "#   - make:demo\n#   - timer:sweeper/demo\n#   - ci:nightly/sweep",
            ).replace(
                "#   purpose:", "#   installs_to: /usr/local/libexec/demo-check\n#   purpose:"
            ),
            "ansible/roles/sweeper/templates/demo.timer.j2": "[Timer]\nOnCalendar=daily UTC\n",
            "ansible/roles/sweeper/templates/demo.service.j2": (
                "[Service]\nExecStart=/usr/local/libexec/demo-check --quiet\n"
            ),
            ".github/workflows/nightly.yml": """\
                on:
                  schedule: [{cron: "0 3 * * *"}]
                jobs:
                  sweep:
                    steps:
                      - run: python tools/demo_check.py
            """,
        },
    )
    cat, reality, runner = verdicts(root)
    assert cat.problems == [] and reality == [], (cat.problems, reality)
    assert sorted(p.split(" by ")[1].split(";")[0] for p in runner) == [
        "ci:nightly/sweep",
        "timer:sweeper/demo",
    ]


def test_m04_check_that_no_criterion_runs_and_its_allowlist(tmp_path):
    root = good_tree(tmp_path)
    (root / "examples/registers/invariants.yml").write_text("criteria: []\n")
    runner = verdicts(root)[2]
    assert "tools/demo_check.py: header names invariant Q-09, which no register defines" in runner
    assert any("check that no invariants criterion runs" in p for p in runner)
    tree(root, {"tools/demo_check.py": CHECK.replace("#   invariant:\n#   - Q-09\n", "")})
    assert "invariant:" not in (root / "tools/demo_check.py").read_text()
    tree(
        root,
        {"tools/scripts.allow.yml": "not_in_runner:\n  demo-check: a CI-only gate, see docs\n"},
    )
    assert verdicts(root)[2] == []


def test_m04_header_and_criteria_disagree(tmp_path):
    root = good_tree(tmp_path)
    reg = REGISTER + REGISTER.split("\n", 1)[1].replace("Q-09", "Q-10")
    (root / "examples/registers/invariants.yml").write_text(reg)
    assert verdicts(root)[2] == [
        "tools/demo_check.py: criterion Q-10 runs it, but its header's invariant list omits it"
    ]
    (root / "examples/registers/invariants.yml").write_text(
        reg.replace("python3 tools/demo_check.py && echo ok", "true")
    )
    runner = verdicts(root)[2]
    assert runner == [
        "tools/demo_check.py: header names invariant Q-09, but that criterion does not run it",
        "tools/demo_check.py: check that no invariants criterion runs; add a criterion whose "
        "observable runs it, or allowlist it under not_in_runner with a reason",
    ]


def test_m04_a_criterion_running_a_tool(tmp_path):
    root = good_tree(tmp_path)
    tree(root, {"tools/demo_check.py": header(id="demo-check", trigger=["make:demo"])})
    assert verdicts(root)[2] == [
        "tools/demo_check.py: criteria Q-09 run it as a check, but its header says kind: tool"
    ]


def _plugin(ctx: Context) -> CheckResult:
    """Mentions tools/other.py in its docstring only, which must not count."""
    return CheckResult("pass", ctx.run(["python3", "tools/demo_check.py"]))


def test_m04_plugin_criteria_count_their_string_constants_not_docstrings(tmp_path):
    root = good_tree(tmp_path)
    (root / "examples/registers/invariants.yml").write_text(
        "criteria:\n- id: Q-09\n  statement: Demo.\n  evidence: plugin\n  plugin: Q-09\n"
    )
    registry = Registry()
    registry.register(Check("Q-09", "demo", _plugin))
    assert verdicts(root, registry)[2] == []
    assert any("no invariants criterion runs" in p for p in verdicts(root, Registry())[2])


# ---- settings, CLI, and this repository --------------------------------------------------


def test_allowlist_entries_need_reasons(tmp_path):
    tree(tmp_path, {"tools/scripts.allow.yml": "uncalled:\n  x: ok\n"})
    with pytest.raises(AllowError):
        load_allow(tmp_path)
    tree(tmp_path, {"tools/scripts.allow.yml": "surprise: []\n"})
    with pytest.raises(AllowError):
        load_allow(tmp_path)
    assert main(["--root", str(tmp_path), "reality"]) == 2
    assert load_allow(tmp_path / "nowhere") == Allow()


def test_cli_usage_error():
    assert main(["bogus"]) == 2


def test_the_repository_catalog_is_current_and_matches_reality():
    files = tracked_files(REPO)
    cat = build(REPO, files)
    assert cat.problems == []
    assert check_current(REPO, cat) == []
    allow = load_allow(REPO)
    real = discover(REPO, cat, files, allow)
    assert reality_problems(cat, real, allow) == []
    assert runner_problems(cat, real, allow) == []
    kinds = {e["id"]: e["kind"] for e in cat.entries}
    assert kinds["leak-scan"] == "check" and kinds["lab-smoke"] == "tool"


def test_the_register_runs_m01_m02_m04_on_the_repository():
    reg = yaml.safe_load((REPO / "examples/registers/invariants.yml").read_text())
    res = run_criteria(reg["criteria"], Context(REPO), only={"M-01", "M-02", "M-04"})["results"]
    assert {i: r["status"] for i, r in res.items()} == dict.fromkeys(
        ["M-01", "M-02", "M-04"], "pass"
    ), res
