# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_tests


def _touch(root: Path, rel: str, text: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _tree(root: Path) -> Path:
    """A minimal repository in which every kind of component has its tests."""
    _touch(root, "homelabnext/alpha/__init__.py")
    _touch(root, "tests/alpha/test_alpha.py")
    _touch(root, "homelabnext/not_a_package/data.yml")  # no __init__.py: not a component
    _touch(root, "conformance/dns/test_conformance_dns.py")
    _touch(root, "ansible/roles/web_app/tasks/main.yml")
    _touch(root, "ansible/plugins/lookup/fake_lookup.py")
    _touch(root, "compose/lab-kit/docker-compose.yml")
    _touch(root, "tools/fake_gate.py")
    _touch(root, "tests/misc/test_named.py", "web_app fake_lookup lab-kit fake_gate\n")
    return root


def test_a_complete_tree_passes(tmp_path):
    assert component_tests.problems(_tree(tmp_path), allow={}) == []


def test_each_kind_of_untested_component_fails(tmp_path, capsys):
    root = _tree(tmp_path)
    _touch(root, "homelabnext/beta/__init__.py")  # no tests/beta/
    _touch(root, "tests/beta/helper.py")  # a directory with no test file does not count
    _touch(root, "conformance/edge/README.md")
    _touch(root, "ansible/roles/db_app/tasks/main.yml")
    _touch(root, "tools/other_gate.py")
    _touch(root, "tests/misc/test_more.py", "db_app_vars other_gate_x\n")  # not whole words
    found = component_tests.problems(root, allow={})
    assert sorted(p.split(":")[0] for p in found) == [
        "ansible/roles/db_app",
        "conformance/edge",
        "homelabnext/beta",
        "tools/other_gate.py",
    ]
    assert component_tests.main(["--root", str(root)]) == 1
    assert "homelabnext/beta: no tests (add tests/beta/test_*.py)" in capsys.readouterr().err


def test_allowlist_exempts_and_goes_stale(tmp_path):
    root = _tree(tmp_path)
    _touch(root, "conformance/support/helpers.py")
    reason = {"conformance/support": "support code"}
    assert component_tests.problems(root, allow=reason) == []
    assert component_tests.problems(root, allow={}) != []
    _touch(root, "conformance/support/test_support.py")
    assert component_tests.problems(root, allow=reason) == [
        "conformance/support: has tests now; remove its ALLOW entry"
    ]
    assert component_tests.problems(root, allow={"conformance/gone": "x"}) == [
        "conformance/gone: ALLOW entry names no component"
    ]


def test_every_allowlist_entry_has_a_reason():
    assert all(r.strip() for r in component_tests.ALLOW.values())


def test_this_repo_passes():
    assert component_tests.main([]) == 0


def test_every_go_package_of_every_module_holds_a_go_test_file(tmp_path):
    root = _tree(tmp_path)
    assert component_tests.problems(root, allow={}) == []  # no Go module: a no-op
    _touch(root, "orchestrator/go.mod", "module example.com/fixture\n")
    _touch(root, "orchestrator/internal/queue/queue.go", "package queue\n")
    _touch(root, "orchestrator/internal/queue/queue_test.go", "package queue\n")
    _touch(root, "orchestrator/internal/tools/notes/notes.go", "package notes\n")  # nested
    _touch(root, "orchestrator/pkg/safefs/safefs.go", "package safefs\n")
    _touch(root, "orchestrator/pkg/safefs/doc.md")
    _touch(root, "orchestrator/cmd/controller/main.go", "package main\n")
    _touch(root, "orchestrator/cmd/controller/main_test.go", "package main\n")
    # any directory of the module is a package, its root and examples/ included
    _touch(root, "orchestrator/doc.go", "package fixture\n")
    _touch(root, "orchestrator/examples/hello/main.go", "package main\n")
    # a second module, and one nested in the first, are discovered like it
    _touch(root, "labkit/go.mod", "module example.com/labkit\n")
    _touch(root, "labkit/probe/probe.go", "package probe\n")
    _touch(root, "orchestrator/internal/hidden/go.mod", "module example.com/hidden\n")
    _touch(root, "orchestrator/internal/hidden/h.go", "package hidden\n")
    # not packages: test data, ignored directories, a directory with only tests, the linters'
    # module, Go in no module (tools/go_modules.py fails on that), build output
    _touch(root, "orchestrator/internal/queue/testdata/fixture.go", "package fixture\n")
    _touch(root, "orchestrator/internal/_scratch/x.go", "package x\n")
    _touch(root, "orchestrator/internal/onlytests/x_test.go", "package x\n")
    _touch(root, "orchestrator/tools/go.mod", "module example.com/fixture/tools\n")
    _touch(root, "orchestrator/tools/tools.go", "package tools\n")
    _touch(root, "scratch/loose.go", "package loose\n")
    _touch(root, "build/go.mod", "module example.com/out\n")
    _touch(root, "build/out.go", "package out\n")
    found = component_tests.problems(root, allow={})
    assert found == [
        "labkit/probe: no tests (add labkit/probe/*_test.go)",
        "orchestrator: no tests (add orchestrator/*_test.go)",
        "orchestrator/examples/hello: no tests (add orchestrator/examples/hello/*_test.go)",
        "orchestrator/internal/hidden: no tests (add orchestrator/internal/hidden/*_test.go)",
        "orchestrator/internal/tools/notes: no tests (add orchestrator/internal/tools/notes/*_test.go)",
        "orchestrator/pkg/safefs: no tests (add orchestrator/pkg/safefs/*_test.go)",
    ]
    kinds = component_tests.components(root)
    assert kinds["orchestrator/internal/queue"] == "go-package"
    assert "orchestrator/internal/tools" not in kinds and "orchestrator/tools" not in kinds
    for d in (
        "labkit/probe",
        "orchestrator",
        "orchestrator/examples/hello",
        "orchestrator/internal/hidden",
        "orchestrator/internal/tools/notes",
        "orchestrator/pkg/safefs",
    ):
        _touch(root, f"{d}/x_test.go", "package x\n")
    assert component_tests.problems(root, allow={}) == []
