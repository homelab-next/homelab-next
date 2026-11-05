# SPDX-License-Identifier: Apache-2.0
"""tools/lab_paths.py and CI's lab-paths / lab-in-a-box / lab-ok jobs: the real stack runs on
every change that can affect it, the list of what can is re-derived from the compose file (so a
new COPY, bind mount or adapter it misses fails here instead of skipping the stack), and lab-ok,
the one stable check name, passes only when the stack passed or was rightly skipped."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab_paths

ROOT = Path(__file__).resolve().parents[2]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
JOBS = CI["jobs"]
LAB = lab_paths.LAB
git_missing = pytest.mark.requires_tool("git")


# --- the list -----------------------------------------------------------------------------------


def test_the_list_covers_everything_the_real_stack_reads():
    inputs = lab_paths.stack_inputs()
    # the derivation sees each kind of input, so an empty or broken parse cannot pass as covered
    for expected in (
        f"{LAB}/docker-compose.yml",
        f"{LAB}/broker/Dockerfile",
        f"{LAB}/config/nats/nats.conf",  # a bind mount
        "homelabnext",  # the broker image's COPY of the whole package
        "constraints/ci.txt",
        "conformance/fakes/openai_server.py",
        "homelabnext/conform/adapters/s3.py",  # a target's adapter
    ):
        assert expected in inputs, expected
    assert lab_paths.uncovered() == []
    assert lab_paths.main(["--check"]) == 0


@pytest.mark.parametrize(
    ("path", "hit"),
    [
        (f"{LAB}/docker-compose.yml", True),
        (f"{LAB}/fakes/Dockerfile", True),
        (f"{LAB}/targets/events.yml", True),
        ("homelabnext/conform/adapters/nats_jetstream.py", True),
        ("homelabnext/lake/client.py", True),
        ("conformance/events/suite.py", True),
        ("constraints/ci.txt", True),
        ("pyproject.toml", True),
        (".github/actions/python-deps/action.yml", True),
        (".github/workflows/nightly.yml", True),
        (".github/workflows/ci.yml", True),
        ("tools/lab_paths.py", True),
        ("docs/conformance.md", False),
        ("tests/compose/test_lab_in_a_box.py", False),
        ("tools/leak_scan.py", False),
        ("ansible/roles/last_run/tasks/main.yml", False),
        (".github/workflows/codeql.yml", False),
        ("CHANGELOG.md", False),
        ("homelabnext-notes.md", False),  # a prefix of a directory entry is not inside it
        ("compose/lab-in-a-box-old/x.yml", False),
    ],
)
def test_a_path_is_judged_by_the_list(path, hit):
    assert lab_paths.covered(path) is hit
    assert lab_paths.affected(["docs/README.md", path, path]) == ([path] if hit else [])


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_an_input_the_list_misses_fails_the_check(tmp_path, capsys):
    compose = {
        "services": {
            "built": {
                "build": {"context": "../..", "dockerfile": "elsewhere/Dockerfile"},
                "volumes": ["./config/a.conf:/a:ro", "named:/data", "../../outside.conf:/o:ro"],
                "env_file": ["../../secrets.env"],
            },
            "pulled": {"image": "example/x:1", "volumes": [{"type": "bind", "source": "/abs"}]},
        }
    }
    root = _tree(
        tmp_path,
        {
            f"{LAB}/docker-compose.yml": yaml.safe_dump(compose),
            "elsewhere/Dockerfile": (
                "FROM scratch AS a\nCOPY --chown=1:1 homelabnext newpkg /src/\n"
                "COPY --from=a /x /y\nADD tools/extra.py /x.py\n"
            ),
            f"{LAB}/targets/t.yml": "target:\n  adapter: otherpkg.adapters.thing:make\n",
        },
    )
    assert lab_paths.uncovered(root) == [
        "/abs (outside the repository)",  # a host path: no diff can cover it
        "elsewhere/Dockerfile",
        "newpkg",
        "otherpkg/adapters/thing.py",
        "outside.conf",
        "secrets.env",
        "tools/extra.py",
    ]  # homelabnext (covered), the named volume and the --from copy are not reported
    assert lab_paths.main(["--check", "--repo", str(root)]) == 1
    assert "::error::newpkg: the lab-in-a-box reads it" in capsys.readouterr().out


# --- deciding from git ------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@git_missing
def test_the_decision_reads_both_sides_of_a_rename_and_writes_the_output(tmp_path, capsys):
    repo = _tree(tmp_path / "r", {"homelabnext/mod.py": "x = 1\n", "docs/a.md": "a\n"})
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    out = tmp_path / "github-output"
    decide = ["--changed-since", base, "--repo", str(repo), "--github-output", str(out)]

    (repo / "docs/a.md").write_text("b\n")
    _git(repo, "commit", "-qam", "docs only")
    assert lab_paths.main(decide) == 0
    assert out.read_text() == "affected=false\n"
    assert capsys.readouterr().out == ""

    # moving a module out of the package changes the image: the deletion counts
    (repo / "tools").mkdir()
    _git(repo, "mv", "homelabnext/mod.py", "tools/mod.py")
    _git(repo, "commit", "-qm", "move")
    assert lab_paths.main(decide) == 0
    assert out.read_text() == "affected=false\naffected=true\n"
    assert capsys.readouterr().out.splitlines() == ["homelabnext/mod.py"]

    assert lab_paths.main(["--changed-since", "e" * 40, "--repo", str(repo)]) == 2
    assert "lab_paths:" in capsys.readouterr().err
    # paths given directly, as a reviewer would ask "would this run the stack?"
    assert lab_paths.main([f"{LAB}/smoke.sh", "README.md"]) == 0
    assert capsys.readouterr().out.splitlines() == [f"{LAB}/smoke.sh"]


# --- the CI jobs --------------------------------------------------------------------------------


def test_lab_paths_takes_the_base_by_the_one_rule_and_feeds_the_stack_job():
    job = JOBS["lab-paths"]
    (checkout,) = [s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")]
    assert checkout["with"] == {"persist-credentials": False, "fetch-depth": 0}
    (step,) = [s for s in job["steps"] if s.get("id") == "decide"]
    assert "base=$(python -m homelabnext.gitbase)\n" in step["run"]
    call = 'tools/lab_paths.py --changed-since "$base" --github-output "$GITHUB_OUTPUT"'
    assert call in step["run"]
    assert step["env"] == {
        "HNX_PR_BASE": "${{ github.event.pull_request.base.sha }}",
        "HNX_PUSH_BEFORE": "${{ github.event.before }}",
    }
    assert job["outputs"] == {"affected": "${{ steps.decide.outputs.affected }}"}
    lab = JOBS["lab-in-a-box"]
    assert lab["needs"] == "lab-paths"
    assert lab["if"] == "needs.lab-paths.outputs.affected == 'true'"
    assert "continue-on-error" not in lab


def test_the_lab_jobs_run_on_pull_requests_with_no_secret_and_a_read_only_token():
    on = CI.get("on") or CI.get(True)
    assert "pull_request" in on and "pull_request_target" not in on
    assert CI["permissions"] == {"contents": "read"}
    for name in ("lab-paths", "lab-in-a-box", "lab-ok"):
        text = yaml.safe_dump(JOBS[name])
        # Dependabot's pull_request runs get no Actions secrets: the smoke must need none
        assert "secrets." not in text and "github.token" not in text, name
        assert JOBS[name].get("permissions", {"contents": "read"}) == {"contents": "read"}, name
        for step in JOBS[name]["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False, name


def _lab_ok(paths: str, affected: str, lab: str) -> int:
    job = JOBS["lab-ok"]
    (step,) = job["steps"]
    env = {**os.environ, "PATHS": paths, "AFFECTED": affected, "LAB": lab}
    return subprocess.run(
        ["bash", "-e", "-c", step["run"]], env=env, capture_output=True, check=False
    ).returncode


@pytest.mark.parametrize(
    ("paths", "affected", "lab", "ok"),
    [
        ("success", "true", "success", True),
        ("success", "false", "skipped", True),  # nothing the stack reads changed
        ("success", "true", "failure", False),
        ("success", "true", "cancelled", False),
        ("success", "true", "skipped", False),  # affected but never ran
        ("success", "false", "success", False),  # the decision and the run disagree
        ("failure", "", "skipped", False),  # no decision is not a pass
        ("cancelled", "", "skipped", False),
        ("skipped", "", "skipped", False),
    ],
)
def test_lab_ok_passes_only_when_the_stack_passed_or_was_rightly_skipped(paths, affected, lab, ok):
    job = JOBS["lab-ok"]
    assert job["needs"] == ["lab-paths", "lab-in-a-box"] and job["if"] == "always()"
    (step,) = job["steps"]
    assert step["env"] == {
        "PATHS": "${{ needs.lab-paths.result }}",
        "AFFECTED": "${{ needs.lab-paths.outputs.affected }}",
        "LAB": "${{ needs.lab-in-a-box.result }}",
    }
    assert not {"if", "continue-on-error", "shell"} & set(step) and "continue-on-error" not in job
    assert (_lab_ok(paths, affected, lab) == 0) is ok
