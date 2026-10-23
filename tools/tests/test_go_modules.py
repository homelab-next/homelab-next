# SPDX-License-Identifier: Apache-2.0
"""tools/go_modules.py: every tracked go.mod is a Go module CI's go job runs for (a linters'
module at <module>/tools/go.mod belongs to its module); Go outside every module, a symlinked
go.mod and a go.work fail instead of hiding code from the job."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import go_modules

ROOT = Path(__file__).resolve().parents[2]
GO_MOD = "module example.com/fixture\n\ngo 1.24\n"
SRC = "// SPDX-License-Identifier: Apache-2.0\npackage api\n"
M = go_modules.Module


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ([], []),  # no Go at all: nothing to run
        (["orchestrator/README.md"], []),
        (["orchestrator/go.mod", "orchestrator/internal/api/api.go"], [M("orchestrator", False)]),
        (["orchestrator/go.mod", "orchestrator/tools/go.mod", "orchestrator/tools/go.sum"], [M("orchestrator", True)]),
        # a second module and a nested one are modules of their own, each with its own job
        (["orchestrator/go.mod", "labtools/go.mod"], [M("labtools", False), M("orchestrator", False)]),
        (["orchestrator/go.mod", "orchestrator/internal/hidden/go.mod"], [M("orchestrator", False), M("orchestrator/internal/hidden", False)]),
        # the module at the repository root; tools/ is only a linters' module below a module
        (["go.mod", "tools/go.mod"], [M(".", True)]),
        (["tools/go.mod"], [M("tools", False)]),
        (["a/go.mod", "a/b/tools/go.mod"], [M("a", False), M("a/b/tools", False)]),
    ],
)  # fmt: skip
def test_every_go_mod_is_a_module_and_tools_belongs_to_its_module(files, expected):
    assert go_modules.problems(files) == []
    assert go_modules.modules(files) == expected


@pytest.mark.parametrize(
    ("files", "links", "why"),
    [
        # Go without its module file: deleted, renamed, moved
        (["orchestrator/internal/api/api.go"], [], "Go source in no module"),
        (["orchestrator/go.mod.bak", "orchestrator/main.go"], [], "Go source in no module"),
        (["orchestrator/go.sum"], [], "a go.sum with no go.mod beside it"),
        (["orchestrator/go.mod/x"], [], "directory named go.mod"),
        (["orchestrator/go.mod", "orchestrator/main.go"], ["orchestrator/go.mod"], "a symbolic link"),
        # a workspace changes how modules resolve: CI runs GOWORK=off, so it must not exist
        (["go.work", "orchestrator/go.mod"], [], "a Go workspace file"),
        (["orchestrator/go.mod", "orchestrator/go.work.sum"], [], "a Go workspace file"),
        # the linters' module: its go.sum or Go file without tools/go.mod
        (["orchestrator/go.mod", "orchestrator/tools/go.sum"], [], "a go.sum with no go.mod beside it"),
        (["orchestrator/go.mod", "orchestrator/tools/tools.go"], [], "reserved for the linters' module"),
    ],
)  # fmt: skip
def test_go_that_no_module_covers_or_a_workspace_is_a_problem(files, links, why):
    found = go_modules.problems(files, links)
    assert len(found) == 1 and why in found[0], found


git_missing = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _repo(tmp_path: Path, layout: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    for rel, text in layout.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if text.startswith("->"):
            p.symlink_to(text[2:])
        else:
            p.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    return repo


@git_missing
def test_a_nested_module_gets_its_own_job_instead_of_vanishing(tmp_path, capsys):
    # verify.md's repro: ./... in orchestrator/ never reaches internal/hidden/, which does not
    # compile and whose test fails, so a job run only in orchestrator/ passes without them
    repo = _repo(
        tmp_path,
        {
            "orchestrator/go.mod": GO_MOD,
            "orchestrator/internal/api/api.go": SRC,
            "orchestrator/internal/hidden/go.mod": "module example.com/hidden\n\ngo 1.24\n",
            "orchestrator/internal/hidden/h.go": "package hidden\n\nfunc F() int { return x }\n",
            "orchestrator/internal/hidden/h_test.go": "package hidden\n",
            "README.md": "x\n",
        },
    )
    out = tmp_path / "github-output"
    assert go_modules.main(["--repo", str(repo), "--github-output", str(out)]) == 0
    listed = [m["dir"] for m in json.loads(capsys.readouterr().out.splitlines()[0])]
    assert listed == ["orchestrator", "orchestrator/internal/hidden"]
    lines = out.read_text().splitlines()
    assert lines[1] == "present=true"
    assert json.loads(lines[0].removeprefix("modules=")) == [
        {"dir": "orchestrator", "tools": False},
        {"dir": "orchestrator/internal/hidden", "tools": False},
    ]


@git_missing
def test_the_command_fails_on_a_workspace_or_a_symlinked_go_mod(tmp_path, capsys):
    repo = _repo(tmp_path, {"orchestrator/go.mod": GO_MOD, "go.work": "go 1.24\n"})
    assert go_modules.main(["--repo", str(repo)]) == 1
    assert "::error::go.work: a Go workspace file" in capsys.readouterr().out
    repo2 = _repo(
        tmp_path / "b",
        {"orchestrator/real.mod": GO_MOD, "orchestrator/go.mod": "->real.mod", "orchestrator/main.go": SRC},
    )  # fmt: skip
    assert go_modules.main(["--repo", str(repo2)]) == 1
    assert "orchestrator/go.mod: a symbolic link" in capsys.readouterr().out


@git_missing
def test_no_go_is_a_no_op_and_untracked_go_is_not_a_module(tmp_path, capsys):
    repo = _repo(tmp_path, {"README.md": "x\n"})
    (repo / "scratch").mkdir()
    (repo / "scratch" / "go.mod").write_text(GO_MOD)  # untracked: not a module of the repository
    out = tmp_path / "github-output"
    assert go_modules.main(["--repo", str(repo), "--github-output", str(out)]) == 0
    assert out.read_text() == "modules=[]\npresent=false\n"
    assert "no Go module in the repository" in capsys.readouterr().out
    assert go_modules.main(["--repo", str(tmp_path / "nowhere")]) == 2


@git_missing
def test_this_repository_has_no_go_outside_a_module():
    files, links = go_modules.tracked(ROOT)
    assert go_modules.problems(files, links) == []
