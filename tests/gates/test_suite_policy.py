# SPDX-License-Identifier: Apache-2.0
"""Q-02: the suite policy plugin -- per-suite time budgets, no silent skips, bounded quarantine."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import textwrap
from datetime import date
from pathlib import Path

import pytest

from tests import shard_report
from tests import suite_policy as sp

ROOT = str(Path(__file__).resolve().parents[2])
TODAY = date(2026, 1, 1)


def test_parse_budgets():
    assert sp.parse_budgets(["tests/roles = 480", " tools/tests/ =2.5"]) == {
        "tests/roles": 480.0,
        "tools/tests": 2.5,
    }
    with pytest.raises(pytest.UsageError):
        sp.parse_budgets(["tests/roles 480"])


def test_suite_of(tmp_path):
    assert sp.suite_of(tmp_path / "tests" / "lake" / "x" / "test_a.py", tmp_path) == "tests/lake"
    assert sp.suite_of(tmp_path / "tools" / "tests" / "test_a.py", tmp_path) == "tools/tests"
    assert sp.suite_of(tmp_path / "tests" / "test_a.py", tmp_path) == "tests"
    assert sp.suite_of(tmp_path / "test_a.py", tmp_path) == "."


def test_skip_reasons():
    pats = ["^could not import '[A-Za-z0-9_.]+'", r"\bnot installed\b"]
    assert sp.skip_reason_allowed("could not import 'duckdb': No module named 'duckdb'", pats)
    assert sp.skip_reason_allowed("shellcheck not installed", pats)
    assert not sp.skip_reason_allowed("flaky, fix later", pats)
    assert not sp.skip_reason_allowed("", pats)
    assert not sp.skip_reason_allowed("unconditional skip", pats)


@pytest.mark.parametrize(
    "kwargs, problem",
    [
        ({"owner": "data-team", "until": "2026-02-01", "reason": "flaky"}, None),
        ({"owner": "data-team", "until": "2026-01-01", "reason": "flaky"}, None),  # last day
        ({"owner": "data-team", "until": "2025-12-31", "reason": "flaky"}, "expired on 2025-12-31"),
        ({"until": "2026-02-01", "reason": "flaky"}, "needs owner"),
        ({"owner": "data-team", "reason": "flaky"}, "needs until"),
        ({"owner": "data-team", "until": "2026-02-01"}, "needs reason"),
        ({"owner": "data-team", "until": "soon", "reason": "flaky"}, "not a YYYY-MM-DD"),
        ({"owner": "data-team", "until": "2026-06-01", "reason": "flaky"}, "more than 90 days"),
    ],
)
def test_check_quarantine(kwargs, problem):
    got = sp.check_quarantine(kwargs, TODAY, 90)
    assert (got is None) if problem is None else (problem in got), got


@pytest.mark.parametrize(
    ("env", "want"),
    [
        ({}, set()),
        ({"HNX_REQUIRE_TOOLS": " zizmor , nats-server ,"}, {"zizmor", "nats-server"}),
        ({"HNX_REQUIRE_GO": "1"}, {"go"}),  # the older switch still works
        ({"HNX_REQUIRE_GO": "0", "HNX_REQUIRE_TOOLS": "docker"}, {"docker"}),
        ({"HNX_REQUIRE_GO": "1", "HNX_REQUIRE_TOOLS": "go,actionlint"}, {"go", "actionlint"}),
    ],
)
def test_required_tools(env, want):
    assert sp.required_tools(env) == want


@pytest.mark.parametrize(
    ("env", "outcome", "why"),
    [
        ({}, pytest.skip.Exception, "hnx-fake-lint is not installed"),
        ({"HNX_REQUIRE_TOOLS": "other"}, pytest.skip.Exception, "hnx-fake-lint is not installed"),
        (
            {"HNX_REQUIRE_TOOLS": "hnx-fake-lint"},
            pytest.fail.Exception,
            "HNX_REQUIRE_TOOLS requires",
        ),
    ],
)
def test_require_tool_skips_or_fails(monkeypatch, tmp_path, env, outcome, why):
    monkeypatch.setenv("PATH", str(tmp_path))  # nothing here
    monkeypatch.delenv("HNX_REQUIRE_TOOLS", raising=False)
    monkeypatch.delenv("HNX_REQUIRE_GO", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(outcome, match=why):
        sp.require_tool("hnx-fake-lint")


def test_require_tool_returns_the_path_and_honours_its_availability_check(monkeypatch, tmp_path):
    tool = tmp_path / "hnx-fake-lint"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("HNX_REQUIRE_TOOLS", "hnx-fake-lint")
    assert sp.require_tool("hnx-fake-lint") == str(tool)
    with pytest.raises(pytest.fail.Exception):  # on PATH but not usable (docker without compose)
        sp.require_tool("hnx-fake-lint", lambda: False)


def test_a_missing_required_tool_is_named_missing_not_unusable(monkeypatch, tmp_path):
    """The unusable wording (needs root, no user namespace) was used for a tool that is not
    installed at all, so the failure sent the reader after the wrong problem."""
    monkeypatch.setenv("PATH", str(tmp_path))  # nothing here
    monkeypatch.setenv("HNX_REQUIRE_TOOLS", "hnx-fake-lint")
    with pytest.raises(pytest.fail.Exception, match="hnx-fake-lint is not on PATH") as info:
        sp.require_tool("hnx-fake-lint", lambda: False, unusable="needs root (not available)")
    assert "needs root" not in str(info.value)


def test_a_required_tools_skip_is_a_failure_end_to_end(tmp_path):
    _project(
        tmp_path,
        a__test_tools="""
            from tests.suite_policy import require_tool

            def test_needs_lint():
                require_tool("hnx-fake-lint")

            def test_needs_other():
                require_tool("hnx-fake-other")
        """,
    )
    proc = _pytest(tmp_path, env={"HNX_REQUIRE_TOOLS": "hnx-fake-lint"})
    assert proc.returncode == 1, proc.stdout
    assert "HNX_REQUIRE_TOOLS requires it" in proc.stdout
    assert "1 failed, 1 skipped" in proc.stdout
    assert _pytest(tmp_path).returncode == 0  # without the variable both are ordinary skips


def test_the_requires_tool_marker_skips_or_fails_before_any_fixture(tmp_path):
    """The marker calls require_tool before the module's fixtures: a required tool that is
    missing fails the test, never a fixture that shells out to it first."""
    _project(
        tmp_path,
        a__test_marked="""
            import pytest

            pytestmark = pytest.mark.requires_tool("hnx-fake-lint")

            @pytest.fixture(scope="module")
            def ran():
                raise AssertionError("the fixture ran before the tool check")

            def test_one(ran):
                pass

            @pytest.mark.requires_tool("sh", "hnx-fake-other")
            def test_two():
                pass
        """,
    )
    proc = _pytest(tmp_path)
    assert proc.returncode == 0, proc.stdout
    assert "2 skipped" in proc.stdout and "hnx-fake-lint is not installed" in proc.stdout
    proc = _pytest(tmp_path, env={"HNX_REQUIRE_TOOLS": "hnx-fake-lint"})
    assert proc.returncode == 1, proc.stdout
    assert "HNX_REQUIRE_TOOLS requires it" in proc.stdout
    assert "the fixture ran before" not in proc.stdout


@pytest.mark.parametrize(
    "reason, required, want",
    [
        ("could not import 'pyiceberg': No module named 'pyiceberg'", {"pyiceberg"}, "pyiceberg"),
        ("could not import 'ansible.errors': no", {"ansible"}, "ansible"),
        ("could not import 'ansible.errors': no", {"ansible.errors"}, "ansible.errors"),
        ("could not import 'ansiblex': no", {"ansible"}, None),
        ("could not import 'duckdb': no", set(), None),
        ("shellcheck is not installed", {"shellcheck"}, None),
    ],
)
def test_required_module_skipped(reason, required, want):
    assert sp.required_module_skipped(reason, required) == want


def test_a_required_modules_importorskip_is_a_failure_end_to_end(tmp_path):
    _project(
        tmp_path,
        a__test_extras="""
            import pytest

            def test_needs_extra():
                pytest.importorskip("hnx_fake_optional_extra.sub")

            def test_needs_other():
                pytest.importorskip("hnx_fake_other_extra")
        """,
    )
    proc = _pytest(tmp_path, env={"HNX_REQUIRE_MODULES": "hnx_fake_optional_extra"})
    assert proc.returncode == 1, proc.stdout
    assert "HNX_REQUIRE_MODULES requires it" in proc.stdout
    assert "1 failed, 1 skipped" in proc.stdout
    assert _pytest(tmp_path).returncode == 0  # without the variable both are ordinary skips


def test_no_test_skips_through_its_own_shutil_which():
    """A ``skipif(shutil.which(...))`` decides the skip itself, so HNX_REQUIRE_TOOLS can never
    turn it into a failure: every tool check goes through require_tool or the marker."""
    own = re.compile(r"skipif\(\s*(?:not\s+)?shutil\.which\(")
    offenders = []
    for base in ("tests", "tools/tests", "conformance"):
        for f in sorted((Path(ROOT) / base).rglob("*.py")):
            if f.name in ("suite_policy.py", "test_suite_policy.py"):  # they name the form
                continue
            text = f.read_text(encoding="utf-8")
            offenders += [f"{f.relative_to(ROOT)}: {m[0]}" for m in own.finditer(text)]
    assert offenders == []


def test_the_job_with_the_extras_requires_them():
    """CI's test job on the Python that installs the lake, mcp and ansible extras makes their
    imports and ansible-playbook required, so they fail there instead of skipping."""
    import yaml

    ci = yaml.safe_load((Path(ROOT) / ".github" / "workflows" / "ci.yml").read_text())
    job = ci["jobs"]["test"]
    (py312,) = [p for p in job["strategy"]["matrix"]["python"] if p["version"] == "3.12"]
    assert {"lake", "mcp", "ansible"} <= set(py312["extras"].split(","))
    assert set(py312["require-modules"].split(",")) >= {"duckdb", "pyiceberg", "mcp", "ansible"}
    assert "ansible-playbook" in py312["require-tools"].split(",")
    (run,) = [s for s in job["steps"] if "pytest" in s.get("run", "")]
    assert run["env"]["HNX_REQUIRE_MODULES"] == "${{ matrix.python.require-modules }}"
    assert run["env"]["HNX_REQUIRE_TOOLS"] == "${{ matrix.python.require-tools }}"


CI_REQUIRED = (
    "actionlint", "zizmor", "nats-server", "docker", "go", "nft", "dnsmasq", "unshare", "setpriv",
)  # fmt: skip


def test_the_tools_ci_requires_are_only_skipped_through_the_helper():
    """A skip that names one of these tools in its own words is outside the HNX_REQUIRE_TOOLS
    contract (CI could not turn it into a failure): it must go through require_tool."""
    tools = "|".join(map(re.escape, CI_REQUIRED))
    own = re.compile(
        rf"(?:pytest\.skip\(|reason=)\s*f?[\"'][^\"']*\b(?:{tools})\b[^\"']*\bnot "
        r"(?:installed|available)\b"
    )
    offenders = []
    for base in ("tests", "tools/tests", "conformance"):
        for f in sorted((Path(ROOT) / base).rglob("*.py")):
            if f.name == "suite_policy.py" or f.name == "test_suite_policy.py":
                continue
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if own.search(line):
                    offenders.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()}")
    assert offenders == []


#: Probes that predate the rule, shrink-only: a function that looks a tool up with shutil.which and
#: then skips or returns False decides the skip itself, so HNX_REQUIRE_TOOLS cannot make a missing
#: tool a failure.  Move one to require_tool (or the requires_tool marker) and delete its line;
#: a line whose probe is gone fails the test below.
LOCAL_PROBE_BASELINE = {
    "tests/browser/test_maps_browser.py::_node",
    "tests/compose/test_lab_in_a_box.py::docker_compose_available",
    "tests/decide/test_decide_lint.py::test_the_repository_specs_pass",
    "tests/decide/test_decide_lint.py::test_untracked_spec_fails_in_git",
    "tests/decide/test_decide_lint.py::test_frozen_and_negative_dirs_are_not_discovered",
    "tests/decide/test_decide_lint.py::test_not_a_git_tree_cannot_be_measured",
    "tests/overlay/test_private_overlay_example.py::_loader_step",
    "tests/overlay/test_private_overlay_example.py::_bash",
    "tests/overlay/test_private_overlay_example.py::upstream",
    "tests/overlay/test_private_overlay_example.py::hook",
    "tests/packaging/pkgbuild.py::export_tree",
    "tests/roles/test_role_render.py::docker_compose_ok",
    "tools/tests/test_caddy_lint.py::<module>",
    "tests/workflows/test_workflows_validate.py::test_r01_untracked_pack_fails_in_git",
}
#: root-only tests that skip on the euid themselves (module level); the agent memory retraction
#: tests are in another change's files
ROOT_SKIP_BASELINE = {
    "tests/agent/test_agent_memory_retraction.py",
    "tests/agent/test_agent_memory_retraction_audit.py",
}


def _test_sources():
    for base in ("tests", "tools/tests", "conformance"):
        for f in sorted((Path(ROOT) / base).rglob("*.py")):
            if f.name not in ("suite_policy.py", "test_suite_policy.py"):
                yield f.relative_to(ROOT).as_posix(), ast.parse(f.read_text(encoding="utf-8"))


def _scopes(tree: ast.AST):
    """(name, nodes) for each function (decorators and nested code included) and for the
    module-level statements outside any function (name ``<module>``)."""
    body = getattr(tree, "body", [])
    top = [n for n in body if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    decorators = [
        d
        for n in body
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        for d in n.decorator_list
    ]
    yield "<module>", [m for n in [*top, *decorators] for m in ast.walk(n)]
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            yield fn.name, list(ast.walk(fn))


def _skip_names(tree: ast.AST) -> set[str]:
    """Names a call can skip through: ``pytest.skip``, ``pytest.mark.skipif`` and any alias
    (``skip = pytest.skip``, ``from pytest import skip``)."""
    names = {"pytest.skip", "pytest.skipif", "pytest.mark.skipif", "skipif", "skip"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and ast.unparse(n.value) in names:
            names |= {ast.unparse(t) for t in n.targets}
    return names


def _calls(nodes: list[ast.AST]) -> list[str]:
    return [ast.unparse(n.func) for n in nodes if isinstance(n, ast.Call)]


def _is_which(call: str) -> bool:
    return call == "which" or call.endswith(".which")


def local_probes(tree: ast.AST) -> list[str]:
    """Names of the scopes of ``tree`` that look a tool up with ``which`` (``shutil.which`` or
    ``from shutil import which``) and then decide a skip themselves: a skip call or ``skipif``
    (aliases included), or an answer of False, None or a bare ``return``."""
    skips = _skip_names(tree)
    found = []
    for name, nodes in _scopes(tree):
        calls = _calls(nodes)
        answers_no = any(
            isinstance(n, ast.Return)
            and (n.value is None or (isinstance(n.value, ast.Constant) and not n.value.value))
            for n in nodes
        )
        if any(map(_is_which, calls)) and (answers_no or any(c in skips for c in calls)):
            found.append(name)
    return found


def root_skips(tree: ast.AST) -> list[str]:
    """Names of the scopes of ``tree`` that skip on the process's uid or euid: a skip call or
    ``skipif`` (aliases included) that itself reads ``geteuid``/``getuid``, or an ``if`` on one
    whose body skips."""

    def reads_uid(node: ast.AST) -> bool:
        return any(
            ast.unparse(c.func).rsplit(".", 1)[-1] in ("geteuid", "getuid")
            for c in ast.walk(node)
            if isinstance(c, ast.Call)
        )

    skips = _skip_names(tree)
    found = []
    for name, nodes in _scopes(tree):
        for n in nodes:
            skip_call = isinstance(n, ast.Call) and ast.unparse(n.func) in skips
            if (skip_call and reads_uid(n)) or (
                isinstance(n, ast.If)
                and reads_uid(n.test)
                and any(
                    ast.unparse(c.func) in skips for c in ast.walk(n) if isinstance(c, ast.Call)
                )
            ):
                found.append(name)
                break
    return found


def test_no_new_local_probe_and_skip():
    """A function of a test file that finds a tool with shutil.which and then skips or returns
    False, or a skipif on the euid, decides the skip itself: HNX_REQUIRE_TOOLS can never turn it
    into a failure (the nft -c and dnsmasq --test checks skipped for good in CI that way).  New
    ones go through tests.suite_policy: require_tool, require_nft_check, require_dnsmasq,
    require_root_setpriv or the requires_tool marker."""
    probes, roots = set(), set()
    for rel, tree in _test_sources():
        probes |= {f"{rel}::{name}" for name in local_probes(tree)}
        if root_skips(tree):
            roots.add(rel)
    assert sorted(probes - LOCAL_PROBE_BASELINE) == []
    assert sorted(roots - ROOT_SKIP_BASELINE) == []
    assert sorted(LOCAL_PROBE_BASELINE - probes) == [], "delete the baseline lines already fixed"
    assert sorted(ROOT_SKIP_BASELINE - roots) == [], "delete the baseline lines already fixed"


def test_the_policy_catches_a_local_probe_and_a_root_skip():
    probe = ast.parse(
        "import shutil, pytest\n"
        "def _can(tmp):\n"
        "    if not shutil.which('nft'):\n"
        "        return False\n"
        "    return True\n"
        "def test_x():\n"
        "    if shutil.which('dnsmasq') is None:\n"
        "        pytest.skip('dnsmasq is not installed')\n"
    )
    assert local_probes(probe) == ["_can", "test_x"]
    assert root_skips(ast.parse("import os, pytest\nR = pytest.mark.skipif(os.geteuid() != 0)"))
    assert not root_skips(ast.parse("import os\nx = os.geteuid()"))
    assert local_probes(ast.parse("def test_y():\n    assert True\n")) == []
    # the shapes a first version missed
    for src in (
        "import shutil\ndef _p():\n    if not shutil.which('nft'):\n        return None\n",
        "import shutil\ndef _p():\n    if not shutil.which('nft'):\n        return\n",
        "from shutil import which\nimport pytest\n"
        "def test_x():\n    if not which('nft'):\n        pytest.skip('gone')\n",
        "import shutil, pytest\nX = shutil.which('nft')\n"
        "@pytest.mark.skipif(X is None, reason='checker is not available')\ndef test_x(): ...\n",
        "import shutil, pytest\nskip = pytest.skip\n"
        "def test_x():\n    if not shutil.which('nft'):\n        skip('gone')\n",
    ):
        assert local_probes(ast.parse(src)), src
    assert not local_probes(ast.parse("import shutil\ndef _node():\n    return shutil.which('n')"))
    for src in (
        "import os, pytest\ndef test_x():\n    if os.geteuid() != 0:\n"
        "        pytest.skip('root is not available')\n",
        "import os, pytest\nR = pytest.mark.skipif(os.getuid() != 0, reason='x')\n",
        "import os, pytest\nskip = pytest.skip\ndef test_x():\n    if os.geteuid():\n"
        "        skip('x')\n",
    ):
        assert root_skips(ast.parse(src)), src


def test_the_real_tool_checks_go_through_the_required_tools():
    """The nft -c, dnsmasq --test and setpriv tests ask for their tools through the helpers (so
    HNX_REQUIRE_TOOLS makes a missing one a failure), and the CI job that installs the tools
    requires every one of them and runs those files."""
    import yaml

    wanted = {
        "tests/network/test_external_tools.py": ("require_nft_check", "require_dnsmasq"),
        "tests/network/test_wan6.py": ("require_nft_check",),
        "tests/network/test_ipv6_render.py": ("require_nft_check",),
        "tests/roles/test_control_roles.py": ("require_nft_check",),
        "tests/orchestration/test_orchestration_readonly.py": ("require_root_setpriv",),
    }
    for rel, helpers in wanted.items():
        text = (Path(ROOT) / rel).read_text(encoding="utf-8")
        assert all(f"{h}()" in text for h in helpers), rel
    ci = yaml.safe_load((Path(ROOT) / ".github" / "workflows" / "ci.yml").read_text())
    steps = ci["jobs"]["real-tools"]["steps"]
    (run,) = [s for s in steps if "pytest" in s.get("run", "")]
    assert set(run["env"]["HNX_REQUIRE_TOOLS"].split(",")) >= {
        "nft", "dnsmasq", "unshare", "setpriv",
    }  # fmt: skip
    for rel in wanted:
        assert rel in run["run"], rel


def test_a_required_nft_that_cannot_check_fails_instead_of_skipping(monkeypatch):
    """nft is on PATH but the user and network namespace cannot be made (the runner's AppArmor
    restriction): a skip by default, a failure where HNX_REQUIRE_TOOLS names unshare."""
    monkeypatch.setattr(sp.shutil, "which", lambda name, path=None: f"/usr/sbin/{name}")
    monkeypatch.setattr(sp, "_userns_can_check", lambda nft: False)
    monkeypatch.delenv("HNX_REQUIRE_TOOLS", raising=False)
    with pytest.raises(
        pytest.skip.Exception, match="unshare cannot create a user and network namespace"
    ):
        sp.require_nft_check()
    monkeypatch.setenv("HNX_REQUIRE_TOOLS", "nft,dnsmasq,unshare")
    with pytest.raises(pytest.fail.Exception, match="HNX_REQUIRE_TOOLS requires it"):
        sp.require_nft_check()
    monkeypatch.setattr(sp.shutil, "which", lambda name, path=None: None)
    with pytest.raises(pytest.fail.Exception, match="dnsmasq is not on PATH"):
        sp.require_dnsmasq()


def test_setpriv_as_a_normal_user_is_a_failure_where_it_is_required(monkeypatch):
    monkeypatch.setattr(sp.shutil, "which", lambda name, path=None: "/usr/bin/setpriv")
    monkeypatch.setattr(sp.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("HNX_REQUIRE_TOOLS", "setpriv")
    with pytest.raises(pytest.fail.Exception, match="setpriv needs root"):
        sp.require_root_setpriv()
    monkeypatch.setattr(sp.os, "geteuid", lambda: 0)
    assert sp.require_root_setpriv() == "/usr/bin/setpriv"


def _project(tmp_path, ini_budgets="", **files):
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\n"
        "suite_budget_default = 60\n"
        f"suite_budgets =\n    {ini_budgets or 'unused = 1'}\n"
        "skip_reasons =\n    ^could not import '[A-Za-z0-9_.]+'\n    \\bnot installed\\b\n"
    )
    for rel, text in files.items():
        p = tmp_path / (rel.replace("__", "/") + ".py")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


def _pytest(tmp_path, *extra, env=None, plugin=True):
    argv = ["-p", "tests.suite_policy"] if plugin else []
    argv += ["-p", "no:cacheprovider", "-q", "-rA"]
    argv += ["-c", str(tmp_path / "pytest.ini"), "--rootdir", str(tmp_path), *extra]
    e = {
        "PYTHONPATH": ROOT,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HNX_TODAY": "2026-01-01",
    }
    e.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "pytest", *argv, str(tmp_path)],
        capture_output=True, text=True, cwd=tmp_path, env=e, check=False,
    )  # fmt: skip


SKIPS = """
    import pytest

    def test_allowed_skip():
        pytest.skip("shellcheck not installed")

    def test_silent_skip():
        pytest.skip("flaky, fix later")

    @pytest.mark.skip
    def test_skip_without_reason():
        pass

    @pytest.mark.xfail(reason="known bug", strict=True)
    def test_xfail_is_not_a_skip():
        assert False

    @pytest.mark.quarantine(owner="data-team", until="2026-02-01", reason="flaky on slow disks")
    def test_quarantined_failure_does_not_break_the_build():
        assert False

    @pytest.mark.quarantine(owner="data-team", until="2025-12-01", reason="flaky")
    def test_expired_quarantine_fails():
        pass

    @pytest.mark.quarantine(until="2026-02-01", reason="flaky")
    def test_quarantine_without_owner_fails():
        pass
"""
MODULE_OK = """
    import pytest

    pytest.importorskip("hnx_fake_optional_extra")
"""
MODULE_SILENT = """
    import pytest

    pytest.skip("not ready", allow_module_level=True)
"""


def test_skips_and_quarantine_end_to_end(tmp_path):
    _project(
        tmp_path,
        a__test_skips=SKIPS,
        a__test_module_ok=MODULE_OK,
    )
    proc = _pytest(tmp_path)
    out = proc.stdout
    assert proc.returncode == 1, out
    assert "SKIPPED [1] a/test_skips.py" in out and "shellcheck not installed" in out
    assert "SKIPPED [1] a/test_module_ok.py" in out  # an absent optional extra
    assert "FAILED a/test_skips.py::test_silent_skip" in out
    assert "ERROR a/test_skips.py::test_skip_without_reason" in out  # refused at setup
    assert "XFAIL a/test_skips.py::test_xfail_is_not_a_skip" in out
    assert "XFAIL a/test_skips.py::test_quarantined_failure_does_not_break_the_build" in out
    assert "quarantined until 2026-02-01 by data-team" in out
    assert "ERROR a/test_skips.py::test_expired_quarantine_fails" in out  # refused at setup
    assert "quarantine expired on 2025-12-01 (owner data-team)" in out
    assert "ERROR a/test_skips.py::test_quarantine_without_owner_fails" in out  # refused at setup
    assert "quarantined tests" in out
    assert "1 failed, 2 skipped, 2 xfailed, 3 errors" in out


def test_without_the_plugin_the_same_suite_passes_silently(tmp_path):
    silent = "import pytest\n\ndef test_silent_skip():\n    pytest.skip('flaky, fix later')\n"
    _project(tmp_path, a__test_silent=silent)
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    proc = _pytest(tmp_path, plugin=False)
    assert proc.returncode == 0, proc.stdout  # the gap the plugin closes
    assert "1 skipped" in proc.stdout


def test_a_silent_module_level_skip_is_a_collection_error(tmp_path):
    _project(tmp_path, a__test_module_silent=MODULE_SILENT)
    proc = _pytest(tmp_path)
    assert proc.returncode == 2, proc.stdout  # collection errors interrupt the session
    assert "ERROR a/test_module_silent.py" in proc.stdout
    assert "silent skip: reason 'not ready'" in proc.stdout


def test_all_good_passes(tmp_path):
    _project(tmp_path, a__test_ok="def test_ok():\n    pass\n", a__test_module_ok=MODULE_OK)
    proc = _pytest(tmp_path, "--suite-times")
    assert proc.returncode == 0, proc.stdout
    assert "suite time budgets" in proc.stdout


SLOW = """
    import time

    def test_slow():
        time.sleep(0.3)
"""


def test_suite_over_budget_fails_the_session(tmp_path):
    _project(
        tmp_path,
        ini_budgets="slow = 0.1",
        slow__test_slow=SLOW,
        fast__test_ok="def test_ok():\n    pass\n",
    )
    proc = _pytest(tmp_path)
    assert proc.returncode == 1, proc.stdout
    assert "2 passed" in proc.stdout
    assert "suite time budget exceeded" in proc.stdout
    assert "slow: 0.3s > budget 0s" in proc.stdout
    assert "fast:" not in proc.stdout.split("suite time budget exceeded")[1]
    # a slow machine scales every budget instead of editing them
    ok = _pytest(tmp_path, env={"HNX_SUITE_BUDGET_SCALE": "100"})
    assert ok.returncode == 0, ok.stdout


def test_this_suite_is_configured():
    import tomllib

    cfg = tomllib.loads((Path(ROOT) / "pyproject.toml").read_text())["tool"]["pytest"]
    ini = cfg["ini_options"]
    assert float(ini["suite_budget_default"]) > 0
    assert sp.parse_budgets(ini["suite_budgets"])
    assert ini["skip_reasons"]
    assert (Path(ROOT) / "conftest.py").read_text().count("tests.suite_policy") == 1


@pytest.mark.parametrize("text", ["0/3", "4/3", "1/0", "3", "a/b", "1/2/3", ""])
def test_parse_shard_refuses(text):
    with pytest.raises(ValueError):
        shard_report.parse_shard(text)


def test_select_spreads_the_tests_over_the_shards_whatever_their_order():
    ids = [f"tests/x/test_{k // 10}.py::test_{k}" for k in range(400)]
    picks = [shard_report.select(ids, i, 4) for i in (1, 2, 3, 4)]
    assert all(sum(col) == 1 for col in zip(*picks, strict=True))  # each test in exactly one
    assert all(70 < sum(p) < 130 for p in picks), [sum(p) for p in picks]
    # by node id, not position: another collection order keeps every test in its shard
    assert shard_report.select(ids[::-1], 2, 4) == picks[1][::-1]
    assert shard_report.parse_shard("2/3") == (2, 3)
    assert shard_report.select(ids, 1, 1) == [True] * 400


SHARDED = {
    f"{suite}__test_{suite}_{name}": "".join(f"def test_{k}():\n    pass\n\n" for k in range(5))
    for suite in ("a", "b")
    for name in ("one", "two")
}


def _shards(tmp_path, count, *extra, **project):
    (tmp_path / "p").mkdir()
    _project(tmp_path / "p", **project)
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    procs = [
        _pytest(
            tmp_path / "p", f"--shard={i}/{count}", f"--shard-report={reports}/{i}.json", *extra
        )
        for i in range(1, count + 1)
    ]
    return procs, reports


def _merge(*argv):
    proc = subprocess.run(
        [sys.executable, "-m", "tests.shard_report", *map(str, argv)],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )  # fmt: skip
    return proc.returncode, proc.stdout + proc.stderr


def test_shards_run_every_test_once_end_to_end(tmp_path):
    procs, reports = _shards(tmp_path, 3, "-k", "not test_4", **SHARDED)
    assert all(p.returncode == 0 for p in procs), [p.stdout for p in procs]
    ran = [re.findall(r"^PASSED (\S+)", p.stdout, re.M) for p in procs]
    assert sorted(n for r in ran for n in r) == sorted(
        f"{s}/test_{s}_{n}.py::test_{k}" for s in "ab" for n in ("one", "two") for k in range(4)
    )  # -k dropped test_4 before the split, and no test ran twice
    assert all(ran), [len(r) for r in ran]
    rc, out = _merge(reports, "--groups", "{}.{}".format(*sys.version_info[:2]))
    assert rc == 0, out
    assert "3 shards" in out and "  a\n" in out
    rc, out = _merge(reports, "--groups", "3.11,3.12,3.13,3.14")
    assert rc == 1 and "expected" in out


def test_the_merge_refuses_shards_that_do_not_add_up(tmp_path):
    _, reports = _shards(tmp_path, 3, **SHARDED)
    data = {i: json.loads((reports / f"{i}.json").read_text()) for i in (1, 2, 3)}

    def merged(**changes):
        for i, change in changes.items():
            (reports / f"{i[1:]}.json").write_text(json.dumps({**data[int(i[1:])], **change}))
        try:
            return _merge(reports)
        finally:
            for i in (1, 2, 3):
                (reports / f"{i}.json").write_text(json.dumps(data[i]))

    assert _merge(reports)[0] == 0
    one = data[1]["selected"]
    cases = [
        ({"s2": {"selected": data[2]["selected"] + one[:1]}}, "not each of the 20"),
        ({"s2": {"selected": data[2]["selected"][1:]}}, "ran 19 tests"),
        ({"s3": {"shard": 2}}, "missing [3], reported twice [2]"),
        ({"s3": {"of": 4}}, "disagree on how many"),
        ({"s1": {"collected_sha256": "0" * 64}}, "did not collect the same tests"),
        ({"s1": {"exitstatus": 1}}, "shard 1/3 exited 1"),
        ({"s1": {"exitstatus": "0"}}, "shard 1/3 exited 0"),
        ({"s1": {"ran": data[1]["ran"][1:]}}, "shard 1/3 ran"),
        ({"s1": {"collected": None}}, "never finished collecting"),
        ({"s2": {"default_budget": 1.0}}, "different budgets"),
        ({"s1": {"times": {"a": 61.0}}}, "a: 6"),  # over 60s only once the shards are summed
        ({"s1": {"times": {"a": float("nan")}}}, "a: nan"),
        ({"s1": {"format": 0}}, "format 0"),
    ]
    for changes, problem in cases:
        rc, out = merged(**changes)
        assert rc == 1 and problem in out, (changes, out)
    (reports / "bad.json").write_text("{")
    assert _merge(reports)[0] == 2
    assert _merge(tmp_path / "nowhere")[0] == 2


def test_each_shard_keeps_the_budget_on_its_share_and_the_merge_on_the_sum(tmp_path):
    slow = "import time\n\n" + "".join(
        f"def test_{k}():\n    time.sleep(0.2)\n\n" for k in range(6)
    )
    procs, reports = _shards(tmp_path, 2, ini_budgets="slow = 0.8", slow__test_slow=slow)
    assert [p.returncode for p in procs] == [0, 0], [p.stdout for p in procs]  # 3 x 0.2s each
    rc, out = _merge(reports)
    assert rc == 1 and "over all shards > budget 0.8s" in out, out


def test_a_test_dropped_after_the_split_is_not_reported_as_run(tmp_path):
    # a later trylast hook (a conftest registers after the plugin) drops a kept test
    late = """
        import pytest

        @pytest.hookimpl(trylast=True)
        def pytest_collection_modifyitems(items):
            items[:] = [i for i in items if not i.nodeid.endswith("test_3")]
    """
    tests = "".join(f"def test_{k}():\n    pass\n\n" for k in range(4))
    procs, reports = _shards(tmp_path, 2, sub__conftest=late, sub__test_sub=tests)
    assert [p.returncode for p in procs] == [0, 0], [p.stdout for p in procs]
    rc, out = _merge(reports)
    assert rc == 1 and "shard 1/2 ran 2 of the 3 tests it kept" in out, out
