# SPDX-License-Identifier: Apache-2.0
"""The fictional private-overlay skeleton (examples/private-overlay/, docs/private-overlay.md).

* its workflows are linted the way this repository keeps its own: every action pinned to a full
  commit SHA with the release named, least-privilege ``permissions``, checkouts without persisted
  credentials, a timeout on every job, no ``pull_request_target``, and no ``${{ }}`` expression
  inside a ``run:`` script (values reach a script through ``env:``); the same lint runs over
  ``.github/workflows`` so it is not tuned to the template alone; ``actionlint`` runs too when it
  is installed;
* the deploy workflow deploys from main only, through the protected Environment, and the
  Tailscale action is pinned like every other action;
* the vault password client reads the environment or OpenBao (faked here, in process and on a
  loopback socket), never a file, never follows a redirect and revokes the token it minted;
* ``ansible.cfg`` names that client, and ``.sops.yaml`` carries only recipients marked fake.
"""

from __future__ import annotations

import configparser
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
import yaml
from fake_openbao import FakeOpenBao as FakeBao
from fake_openbao import self_signed

from homelabnext.modules import review_tier as rt
from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]
SKELETON = ROOT / "examples" / "private-overlay"
TEMPLATES = sorted((SKELETON / ".github" / "workflows").glob("*.yml"))
OWN = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
CLIENT = SKELETON / "bin" / "vault-pass-client.py"
#: the ref every checks.yml job but hnx-pin checks homelab-next out at: the commit hnx-pin read
#: from locks/hnx-ref and proved to be on homelab-next's main
PINNED_SHA = "${{ needs.hnx-pin.outputs.sha }}"

# the sdist and the wheel leave the template out (setup.py NOT_PACKAGED, MANIFEST.in)
pytestmark = pytest.mark.skipif(
    not (SKELETON / ".hnx-private-overlay.yml").is_file(),
    reason="the private-overlay template is not in this tree (an sdist leaves it out)",
)

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
RELEASE_COMMENT = re.compile(r"^\s+#\s+v\d+(?:\.\d+)*\b")
EXPR = re.compile(r"\$\{\{")
READ = {"read", "none"}
#: the self-hosted deploy runner's label: only the deploy workflow may name it (or any
#: self-hosted runner), because a label does not restrict which workflow a runner accepts
DEPLOY_LABEL = "hnx-deploy"
HOOK = SKELETON / "runner" / "job-started.sh"


def _on(doc: dict) -> object:
    return doc.get("on", doc.get(True))  # PyYAML reads the bare key `on` as True


def _triggers(doc: dict) -> set[str]:
    on = _on(doc)
    if isinstance(on, str):
        return {on}
    return set(on or [])


def lint_workflow(path: Path) -> list[str]:
    """Problems with one workflow file (empty when it follows the repository's rules)."""
    text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    out: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        m = USES.match(line)
        if not m or line.lstrip().startswith("#"):
            continue
        ref = m["ref"]
        if ref.startswith("./"):
            continue
        if not PINNED.match(ref):
            out.append(f"line {n}: {ref} is not pinned to a full commit SHA")
        elif not RELEASE_COMMENT.match(m["rest"]):
            out.append(f"line {n}: {ref} has no trailing '# vX.Y.Z' naming the release")
    if "pull_request_target" in _triggers(doc):
        out.append("pull_request_target runs untrusted code with secrets")
    jobs = (doc.get("jobs") or {}).values()
    if path.name != "deploy.yml":
        for name, job in (doc.get("jobs") or {}).items():
            blob = json.dumps(job)  # runs-on, and a matrix or expression that could feed it
            if DEPLOY_LABEL in blob or "self-hosted" in blob:
                out.append(f"job {name}: names the self-hosted deploy runner; only deploy.yml may")
    if "pull_request" in _triggers(doc) and any("environment" in j for j in jobs):
        out.append("a job with an Environment runs on pull_request (its secrets reach PR code)")
    perms = doc.get("permissions")
    if perms is None:
        out.append("no top-level permissions (the default token is too broad)")
    elif not (perms == "read-all" or (isinstance(perms, dict) and set(perms.values()) <= READ)):
        out.append(f"top-level permissions {perms!r}: read-only here, grant more per job")
    for name, job in (doc.get("jobs") or {}).items():
        if "uses" in job:  # a reusable-workflow call has no steps of its own
            continue
        if "timeout-minutes" not in job:
            out.append(f"job {name}: no timeout-minutes")
        for i, step in enumerate(job.get("steps") or []):
            where = f"job {name} step {step.get('name', i)}"
            uses = str(step.get("uses", ""))
            persist = (step.get("with") or {}).get("persist-credentials")
            if uses.startswith("actions/checkout@") and persist is not False:
                out.append(f"{where}: checkout without persist-credentials: false")
            if "run" in step and EXPR.search(str(step["run"])):
                out.append(f"{where}: an expression inside run: (pass it through env:)")
    return out


@pytest.mark.parametrize("path", TEMPLATES + OWN, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_workflow_follows_the_repository_rules(path):
    assert lint_workflow(path) == []


def test_the_lint_catches_what_it_claims(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "on: [pull_request_target, pull_request]\n"
        "permissions: write-all\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v7\n"
        "      - uses: tailscale/github-action@" + "a" * 40 + "\n"
        "      - uses: actions/setup-python@" + "b" * 40 + "  # v7.0.0\n"
        "      - uses: actions/checkout@" + "c" * 40 + "  # v7.0.1\n"
        "      - run: echo ${{ secrets.FAKE_TOKEN }}\n"
        "  d:\n    runs-on: ubuntu-latest\n    environment: production\n    steps: []\n"
    )
    problems = "\n".join(lint_workflow(bad))
    assert "self-hosted deploy runner" not in problems
    for needle in (
        "actions/checkout@v7 is not pinned",
        "has no trailing",
        "pull_request_target",
        "top-level permissions",
        "no timeout-minutes",
        "without persist-credentials",
        "expression inside run",
        "runs on pull_request",
    ):
        assert needle in problems, needle


@pytest.mark.parametrize(
    "runs_on",
    [
        "[self-hosted, hnx-deploy]",
        "${{ matrix.r }}\n    strategy:\n      matrix:\n        r: [hnx-deploy]",
        "[self-hosted, linux]",
    ],
)
def test_only_the_deploy_workflow_may_name_the_deploy_runner(tmp_path, runs_on):
    """A branch or pull request that edits checks.yml to run on the management runner."""
    body = (
        "on: [pull_request]\npermissions: {}\njobs:\n  j:\n"
        f"    runs-on: {runs_on}\n    timeout-minutes: 5\n    steps:\n      - run: id\n"
    )
    checks = tmp_path / "checks.yml"
    checks.write_text(body)
    assert any("only deploy.yml may" in p for p in lint_workflow(checks))
    (tmp_path / "deploy").mkdir()
    deploy = tmp_path / "deploy" / "deploy.yml"
    deploy.write_text(body.replace("[pull_request]", "workflow_dispatch"))
    assert not any("only deploy.yml may" in p for p in lint_workflow(deploy))


def test_actionlint_accepts_the_templates():
    require_tool("actionlint")
    r = subprocess.run(
        ["actionlint", "-no-color", *map(str, TEMPLATES)], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_templates_are_present():
    assert {p.name for p in TEMPLATES} == {"checks.yml", "deploy.yml"}


# ---- the deploy workflow -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def deploy() -> dict:
    return yaml.safe_load((SKELETON / ".github" / "workflows" / "deploy.yml").read_text())


def test_deploy_is_dispatched_by_hand_from_main_through_the_environment(deploy):
    # GitHub Pro/Team: a private repository's Environment has no required reviewers, so the
    # manual dispatch is the approval step; a push or pull-request trigger would deploy unreviewed
    assert _triggers(deploy) == {"workflow_dispatch"}
    assert not _triggers(deploy) & {"push", "pull_request", "pull_request_target"}
    assert deploy["permissions"] == {}
    assert deploy["concurrency"]["cancel-in-progress"] is False
    (job,) = deploy["jobs"].values()
    assert job["environment"] == "production"
    assert job["if"] == "github.ref == 'refs/heads/main'"
    # id-token: the Tailscale action's workload identity federation; nothing can write
    assert job["permissions"] == {"contents": "read", "id-token": "write"}


def test_deploy_offers_both_paths(deploy):
    (job,) = deploy["jobs"].values()
    assert "self-hosted" in job["runs-on"] and "ubuntu-latest" in job["runs-on"]
    ts = [s for s in job["steps"] if str(s.get("uses", "")).startswith("tailscale/github-action@")]
    assert len(ts) == 1
    assert ts[0]["if"] == "vars.HNX_DEPLOY_PATH != 'self-hosted'"
    assert ts[0]["with"]["tags"] == "tag:ci-deploy"
    # workload identity federation: an OIDC exchange, no long-lived OAuth secret to steal
    assert set(ts[0]["with"]) >= {"oauth-client-id", "audience"}
    assert "oauth-secret" not in ts[0]["with"] and "authkey" not in ts[0]["with"]


def test_tailscale_action_is_pinned_not_left_as_a_placeholder():
    """The pin was verified against the action's repository (v4.2.0); a `<pin-me>` placeholder
    would be allowed only while docs/private-overlay.md says so."""
    text = (SKELETON / ".github" / "workflows" / "deploy.yml").read_text()
    if "<pin-me>" in text:
        assert "<pin-me>" in (ROOT / "docs" / "private-overlay.md").read_text()
    else:
        assert re.search(r"tailscale/github-action@[0-9a-f]{40}  # v\d", text)


def test_secrets_reach_only_the_steps_that_use_them(deploy):
    (job,) = deploy["jobs"].values()
    assert "env" not in job and "env" not in deploy
    users = {}
    for step in job["steps"]:
        blob = json.dumps({k: step.get(k) for k in ("env", "with")})
        for name in re.findall(r"secrets\.([A-Z0-9_]+)", blob):
            users.setdefault(name, []).append(step.get("name", step.get("uses")))
    # role credentials come from OpenBao by name, not one Actions secret each
    assert set(users) == {
        "SOPS_AGE_KEY",
        "ANSIBLE_VAULT_PASSWORD",
        "DEPLOY_SSH_KEY",
        "BAO_SECRET_ID",
    }
    assert not any(n.startswith(("HNX_SECRET_", "TS_")) for n in users)
    text = (SKELETON / ".github" / "workflows" / "deploy.yml").read_text()
    assert "set -x" not in text and "ACTIONS_STEP_DEBUG" not in text


def test_deploy_reads_role_credentials_from_openbao(deploy):
    (job,) = deploy["jobs"].values()
    (step,) = [s for s in job["steps"] if s.get("name") == "deploy"]
    env = step["env"]
    assert env["BAO_ADDR"] == "${{ vars.BAO_ADDR }}"
    assert env["BAO_ROLE_ID"] == "${{ vars.BAO_ROLE_ID }}"
    assert env["BAO_SECRET_ID"] == "${{ secrets.BAO_SECRET_ID }}"
    assert env["HNX_VAULT_PASSWORD_REF"] == "${{ vars.HNX_VAULT_PASSWORD_REF }}"
    pins = job["steps"][0]
    assert "BAO_ADDR" in pins["env"] and "https://" in pins["run"]
    ca = [s for s in job["steps"] if "BAO_CACERT_PEM" in (s.get("env") or {})]
    assert len(ca) == 1 and "BAO_CACERT=" in ca[0]["run"]


# ---- the module loader at deploy time (docs/modules.md, "The loader at deploy time") ------------


def _step(job: dict, name: str) -> tuple[int, dict]:
    (found,) = [(i, s) for i, s in enumerate(job["steps"]) if s.get("name") == name]
    return found


def test_the_loader_runs_before_the_deploy_and_checks_what_runs_after_it(deploy):
    (job,) = deploy["jobs"].values()
    i_check, check = _step(job, "the module loader, before anything changes on a host")
    i_deploy, run = _step(job, "deploy")
    i_after, after = _step(job, "what runs matches what the lab declares")
    assert i_check < i_deploy < i_after
    # nothing before the check reaches a host: the tailnet join is the first thing that could
    i_net = next(
        i
        for i, s in enumerate(job["steps"])
        if s.get("if") == "vars.HNX_DEPLOY_PATH != 'self-hosted'"
    )
    assert i_check < i_net
    for step in (check, run, after):
        # a failing check fails the run, never only warns, and none is ever skipped: a lab that
        # takes up no modules is checked as an empty selection (hnx decides it, not the step)
        assert "continue-on-error" not in step
        assert "if" not in step
    assert check["run"].strip() == "hnx modules check --root hnx --overlay . --deploy"
    script = run["run"]
    assert script.index("ansible/playbooks/site.yml") < script.index("module_census.yml")
    assert "if " not in script.split("ansible/playbooks/site.yml", 1)[1]  # the census always
    # the overlay's group_vars and host_vars cannot point the census at a stand-in: an extra
    # variable wins, so every census input naming a command or a data source is pinned
    assert "-e module_census_systemctl_cli=/usr/bin/systemctl" in script
    defaults = yaml.safe_load(
        (ROOT / "ansible" / "roles" / "module_census" / "defaults" / "main.yml").read_text()
    )
    for var in ("module_census_hnx_cli", "module_census_pairs_dir"):
        assert f"-e {var}={defaults[var]}" in script, var  # the role's own default, pinned
    assert "hnx modules gather" in after["run"]
    assert "--deploy --running" in after["run"]


def test_the_loader_also_runs_on_every_pull_request():
    """checks.yml runs the same check as deploy.yml before it changes a host, with the pinned hnx
    and no secret, so a problem shows on the pull request."""
    checks = yaml.safe_load((SKELETON / ".github" / "workflows" / "checks.yml").read_text())
    job = checks["jobs"]["module-loader"]
    names = [s.get("name") for s in job["steps"]]
    assert names[0] == "refuse an unpinned hnx"
    (step,) = [
        s
        for s in job["steps"]
        if s.get("name") == "the module loader over this lab's own selection"
    ]
    assert step["run"].strip() == "hnx modules check --root hnx --overlay . --deploy"
    assert "continue-on-error" not in step and "if" not in step
    assert "secrets." not in yaml.safe_dump(job)
    hnx = [
        s
        for s in job["steps"]
        if s.get("with", {}).get("repository") == "homelab-next/homelab-next"
    ]
    assert hnx and hnx[0]["with"]["ref"] == PINNED_SHA
    assert all(s.get("with", {}).get("persist-credentials") is False
               for s in job["steps"] if "actions/checkout" in s.get("uses", ""))  # fmt: skip


def test_the_site_review_tier_runs_on_every_pull_request():
    """checks.yml rates each change to what the lab claims, with the pinned hnx, the base read
    through git (a full-history checkout) and no secret."""
    checks = yaml.safe_load((SKELETON / ".github" / "workflows" / "checks.yml").read_text())
    job = checks["jobs"]["site-review-tier"]
    assert job["steps"][0]["name"] == "refuse an unpinned hnx"
    (step,) = [
        s
        for s in job["steps"]
        if s.get("name") == "the review tier of this change to the lab's site and selection"
    ]
    assert step["run"].strip() == "hnx site review-tier --root . --ci-base"
    assert step["env"] == {
        "HNX_PR_BASE": "${{ github.event.pull_request.base.sha }}",
        "HNX_PUSH_BEFORE": "${{ github.event.before }}",
    }
    assert "continue-on-error" not in step and "if" not in step
    assert "secrets." not in yaml.safe_dump(job)
    checkouts = [s for s in job["steps"] if "actions/checkout" in s.get("uses", "")]
    assert all(s["with"]["persist-credentials"] is False for s in checkouts)
    (own,) = [s for s in checkouts if "repository" not in s["with"]]
    assert own["with"]["fetch-depth"] == 0
    (hnx,) = [s for s in checkouts if s["with"].get("repository") == "homelab-next/homelab-next"]
    assert hnx["with"]["ref"] == PINNED_SHA


def _loader_step(tmp_path: Path, hnx_exit: int, *lab_files: str) -> tuple[int, str]:
    """Run the template's loader step: in an overlay with ``lab_files``, with an ``hnx`` that
    exits ``hnx_exit`` and logs its arguments.  Returns (exit, what it ran and printed)."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    (job,) = yaml.safe_load((SKELETON / ".github" / "workflows" / "deploy.yml").read_text())[
        "jobs"
    ].values()
    _, step = _step(job, "the module loader, before anything changes on a host")
    work = tmp_path / "overlay"
    (work / "lab").mkdir(parents=True)
    for f in lab_files:
        (work / "lab" / f).write_text("x\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "hnx"
    fake.write_text(f'#!/bin/sh\necho "hnx $*" >> {tmp_path}/calls\nexit {hnx_exit}\n')
    fake.chmod(0o755)
    r = subprocess.run(
        [bash, "-e", "-c", step["run"]],
        cwd=work,
        capture_output=True,
        text=True,
        env={"PATH": f"{bin_dir}:{os.environ['PATH']}"},
    )
    calls = (tmp_path / "calls").read_text() if (tmp_path / "calls").exists() else ""
    return r.returncode, calls + r.stdout


def test_the_deploy_stops_when_the_loader_finds_a_problem(tmp_path):
    code, said = _loader_step(tmp_path, 1, "modules.yml")
    assert code == 1
    assert "hnx modules check --root hnx --overlay . --deploy" in said


def test_a_lab_without_modules_is_checked_too(tmp_path):
    """No lab/modules.yml, lab/modules/ or lab/modules.lock: the step still runs hnx, which
    checks an empty selection; a problem there stops the deploy as any other."""
    for code_in in (0, 1):
        code, said = _loader_step(tmp_path / str(code_in), code_in)
        assert code == code_in and "hnx modules check --root hnx --overlay . --deploy" in said


def test_zizmor_accepts_the_templates():
    """docs/private-overlay.md says the templates pass zizmor (checked with 1.31.1, offline)."""
    require_tool("zizmor")
    r = subprocess.run(
        ["zizmor", "--offline", "--no-progress", *map(str, TEMPLATES)],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


# ---- HNX_REF: the tracked pin, proved to be on homelab-next main -------------------------------

HNX_REF_FILE = SKELETON / "locks" / "hnx-ref"
READ_PIN = "refuse an unpinned hnx"
ANCESTRY = "refuse an hnx commit that is not on homelab-next main"


def _workflow(name: str) -> dict:
    return yaml.safe_load((SKELETON / ".github" / "workflows" / name).read_text())


def _pin_job(name: str) -> dict:
    """The job that reads locks/hnx-ref and proves it: deploy.yml's one job, checks.yml's
    ``hnx-pin``."""
    doc = _workflow(name)
    return doc["jobs"]["hnx-pin"] if name == "checks.yml" else next(iter(doc["jobs"].values()))


def _bash() -> str:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    return bash


@pytest.mark.parametrize("workflow", ["checks.yml", "deploy.yml"])
def test_hnx_ref_is_the_tracked_file_never_a_variable(workflow):
    """HNX_REF lives in locks/hnx-ref (under CODEOWNERS), so it moves only by a reviewed pull
    request: no workflow reads an Actions variable for it, every hnx/ checkout takes the commit
    the pin step read, and the ancestry check runs right after the checkout, before anything from
    hnx/ is installed or run."""
    text = (SKELETON / ".github" / "workflows" / workflow).read_text()
    assert "vars.HNX_REF" not in text
    job = _pin_job(workflow)
    i_pin, pin = _step(job, READ_PIN)
    assert pin["id"] == "hnx-ref" and "locks/hnx-ref" in pin["run"]
    i_hnx, hnx = next(
        (i, s) for i, s in enumerate(job["steps"]) if (s.get("with") or {}).get("path") == "hnx"
    )
    assert i_pin < i_hnx
    assert hnx["with"]["ref"] == "${{ steps.hnx-ref.outputs.sha }}"
    assert hnx["with"]["fetch-depth"] == 0  # the history the ancestry check walks
    i_anc, anc = _step(job, ANCESTRY)
    assert i_anc == i_hnx + 1
    assert anc["env"] == {"HNX_REF": "${{ steps.hnx-ref.outputs.sha }}"}
    assert "continue-on-error" not in anc and "if" not in anc
    for step in job["steps"][:i_anc]:  # nothing installs or runs what hnx/ holds before it
        run = str(step.get("run", ""))
        assert not re.search(r"pip install|python hnx|\./hnx|^\s*hnx ", run, re.M), step.get("name")


def test_the_pin_and_ancestry_scripts_are_the_same_in_both_workflows():
    for name in (READ_PIN, ANCESTRY):
        runs = {wf: _step(_pin_job(wf), name)[1]["run"] for wf in ("checks.yml", "deploy.yml")}
        assert runs["checks.yml"] == runs["deploy.yml"], name


def test_every_checks_job_uses_the_proved_pin():
    """Each job that checks out homelab-next needs hnx-pin and takes its output, so a commit not on
    main never reaches a job that installs or runs it; ``checks`` needs hnx-pin too."""
    jobs = _workflow("checks.yml")["jobs"]
    pin = jobs["hnx-pin"]
    assert pin["outputs"] == {"sha": "${{ steps.hnx-ref.outputs.sha }}"}
    users = 0
    for name, job in jobs.items():
        if name == "hnx-pin":
            continue
        assert "hnx-pin" in ([job["needs"]] if isinstance(job["needs"], str) else job["needs"])
        for step in job["steps"]:
            if (step.get("with") or {}).get("path") == "hnx":
                users += 1
                assert step["with"]["ref"] == PINNED_SHA, name
    assert users == len(jobs) - 2


def _read_pin(tmp_path: Path, content: str | None, *, link: bool = False) -> tuple[int, str, str]:
    """Run the pin step in an overlay whose locks/hnx-ref holds ``content``.  Returns (exit,
    output, what it wrote to GITHUB_OUTPUT)."""
    bash = _bash()
    _, step = _step(_pin_job("deploy.yml"), READ_PIN)
    work = tmp_path / "overlay"
    (work / "locks").mkdir(parents=True)
    if content is not None:
        target = work / ("elsewhere" if link else "locks/hnx-ref")
        target.write_text(content)
        if link:
            (work / "locks" / "hnx-ref").symlink_to(target)
    out = tmp_path / "github_output"
    out.write_text("")
    r = subprocess.run(
        [bash, "-c", step["run"]],
        cwd=work,
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(out)},
    )
    return r.returncode, r.stdout + r.stderr, out.read_text()


SHA_A = "0123456789abcdef0123456789abcdef01234567"


def test_the_pin_step_reads_one_full_sha_and_comments(tmp_path):
    code, said, out = _read_pin(tmp_path, f"# SPDX-License-Identifier: Apache-2.0\n\n{SHA_A}\n")
    assert code == 0, said
    assert out == f"sha={SHA_A}\n"


@pytest.mark.parametrize(
    "content, why",
    [
        (None, "is missing"),
        ("", "one full commit SHA"),
        ("# only a comment\n", "one full commit SHA"),
        (SHA_A[:12] + "\n", "one full commit SHA"),
        (SHA_A.upper() + "\n", "one full commit SHA"),
        (f"{SHA_A} \n", "one full commit SHA"),
        (f"{SHA_A}\r\n", "one full commit SHA"),
        (f"{SHA_A}\n{SHA_A}\n", "one full commit SHA"),
        ("main\n", "one full commit SHA"),
        ("0" * 40 + "\n", "placeholder"),
    ],
)
def test_the_pin_step_refuses_anything_else(tmp_path, content, why):
    code, said, out = _read_pin(tmp_path, content)
    assert code == 1 and why in said and out == ""


def test_the_pin_step_refuses_a_link(tmp_path):
    code, said, out = _read_pin(tmp_path, f"{SHA_A}\n", link=True)
    assert code == 1 and "is missing" in said and out == ""


def test_the_template_ships_the_placeholder_the_pin_step_refuses(tmp_path):
    """A fresh copy of the template fails until the operator pins a commit they reviewed."""
    code, said, _ = _read_pin(tmp_path, HNX_REF_FILE.read_text())
    assert code == 1 and "placeholder" in said
    rules = rt.parse_codeowners((SKELETON / ".github" / "CODEOWNERS").read_text())
    assert rt.codeowners_for(rules, "locks/hnx-ref")


def _git(cwd: Path, *args: str) -> str:
    r = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )  # fmt: skip
    return r.stdout.strip()


@pytest.fixture
def upstream(tmp_path) -> dict[str, str | Path]:
    """A stand-in for homelab-next: main (c1, c2) and an unmerged pull request's commit (pr,
    branched from c1).  GitHub would serve ``pr`` under the parent's name too."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    up = tmp_path / "upstream"
    up.mkdir()
    _git(up, "init", "-q")
    shas: dict[str, str | Path] = {"path": up}
    for n in ("c1", "c2"):
        (up / n).write_text(n)
        _git(up, "add", n)
        _git(up, "commit", "-q", "-m", n)
        shas[n] = _git(up, "rev-parse", "HEAD")
    _git(up, "checkout", "-q", "-b", "pr", str(shas["c1"]))
    (up / "pr").write_text("pr")
    _git(up, "add", "pr")
    _git(up, "commit", "-q", "-m", "pr")
    shas["pr"] = _git(up, "rev-parse", "HEAD")
    _git(up, "checkout", "-q", "main")
    return shas


def _ancestry(tmp_path: Path, upstream: dict, at: str, ref: str, *, shallow: bool = False,
              local_main: str | None = None) -> tuple[int, str]:  # fmt: skip
    """Check homelab-next out at ``at`` into overlay/hnx (as actions/checkout does: origin is
    homelab-next, HEAD detached) and run the ancestry step with HNX_REF ``ref``."""
    bash = _bash()
    _, step = _step(_pin_job("deploy.yml"), ANCESTRY)
    work = tmp_path / "overlay"
    work.mkdir(parents=True)
    clone = ["clone", "-q", "--no-checkout"]
    if shallow:
        clone += ["--depth", "1", "--branch", "main", f"file://{upstream['path']}"]
    else:
        clone += [str(upstream["path"])]
    _git(work, *clone, "hnx")
    if not shallow:
        _git(work / "hnx", "fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*")
    _git(work / "hnx", "checkout", "-q", "--detach", at)
    if local_main:  # a branch the clone carries that only looks like main
        _git(work / "hnx", "update-ref", "refs/heads/main", local_main)
        _git(work / "hnx", "update-ref", "refs/hnx-pin/main", local_main)
    r = subprocess.run(
        [bash, "-c", step["run"]],
        cwd=work,
        capture_output=True,
        text=True,
        env={**os.environ, "HNX_REF": ref, "GIT_CONFIG_NOSYSTEM": "1",
             "GIT_CONFIG_GLOBAL": os.devnull},
    )  # fmt: skip
    return r.returncode, r.stdout + r.stderr


def test_a_commit_on_main_passes(tmp_path, upstream):
    for sha in (upstream["c1"], upstream["c2"]):  # the tip, and an older commit of main
        code, said = _ancestry(tmp_path / sha, upstream, sha, sha)
        assert code == 0 and "is on homelab-next main" in said, said


def test_a_commit_main_does_not_contain_is_refused(tmp_path, upstream):
    """F03: an unmerged pull request's (or a fork's) commit, a full SHA GitHub serves under the
    parent's name, never reaches the job's later steps."""
    code, said = _ancestry(tmp_path, upstream, upstream["pr"], upstream["pr"])
    assert code == 1 and "is not on homelab-next main" in said, said


def test_a_local_ref_named_main_does_not_vouch(tmp_path, upstream):
    """The check compares against main as fetched from origin, not a ref the clone has."""
    code, said = _ancestry(
        tmp_path, upstream, upstream["pr"], upstream["pr"], local_main=upstream["pr"]
    )
    assert code == 1 and "is not on homelab-next main" in said, said


def test_a_checkout_at_another_commit_is_refused(tmp_path, upstream):
    code, said = _ancestry(tmp_path, upstream, upstream["c2"], upstream["c1"])
    assert code == 1 and "not the pinned" in said, said


def test_a_shallow_checkout_is_refused(tmp_path, upstream):
    code, said = _ancestry(tmp_path, upstream, upstream["c2"], upstream["c2"], shallow=True)
    assert code == 1 and "shallow" in said, said


def test_the_docs_give_one_home_for_hnx_ref():
    """ADR-0021, ADR-0028, docs/private-overlay.md, the operator's to-do list and the first-deploy
    runbook agree: HNX_REF is the tracked file locks/hnx-ref, moved by a reviewed pull request,
    and none of them still calls it an Actions variable."""
    docs = {
        p: (ROOT / p).read_text()
        for p in (
            "docs/adr/0021-public-and-private-repositories.md",
            "docs/adr/0028-veritas-single-source-of-truth.md",
            "docs/private-overlay.md",
            "docs/modules/swap-flow.md",
            "examples/registers/runbooks/01a15f29-ff7e-764c-a17e-d2d50c304e9b.md",
        )
    }
    stale = re.compile(r"HNX_REF`?,? [^.\n]{0,40}\b(?:Environment|repository|Actions) variable")
    for path, text in docs.items():
        assert "locks/hnx-ref" in text, path
        assert not stale.search(text), path
        assert not re.search(r"variables[^.\n]{0,40}\bHNX_REF\b", text), path
    overlay = docs["docs/private-overlay.md"]
    assert "merge-base --is-ancestor" in overlay
    assert "refused unless a full SHA" not in docs["docs/modules/swap-flow.md"]
    todo = (ROOT / "TODO.md").read_text()
    assert "locks/hnx-ref" in todo
    assert not re.search(r"Variables: `HNX_REF`", todo)


# ---- the specs the operator applies by hand, checked on every pull request ---------------------


def test_the_deploy_certificate_outlives_the_deploy_job():
    """lab/ssh-ca.yml says the deploy certificate must outlive the run: its ttl is at least the
    deploy job's timeout, or a connection opened late in a long run fails."""
    from homelabnext import sshca

    spec = sshca.load(SKELETON / "lab" / "ssh-ca.yml")
    (job,) = _workflow("deploy.yml")["jobs"].values()
    deploy_roles = [r for r in spec.roles if r.kind == "deploy"]
    assert deploy_roles
    for role in deploy_roles:
        assert sshca.seconds("ttl", role.ttl) >= job["timeout-minutes"] * 60, role.name


SPECS = "the SSH certificate roles and the seeding spec validate"


def _specs_step(tmp_path: Path, files: dict[str, str]) -> tuple[int, str]:
    """Run checks.yml's spec step in an overlay holding ``files`` (under lab/), with ``hnx`` the
    real command line of this tree."""
    bash = _bash()
    _, step = _step(_workflow("checks.yml")["jobs"]["lab-specs"], SPECS)
    work = tmp_path / "overlay"
    (work / "lab").mkdir(parents=True)
    for name, text in files.items():
        (work / "lab" / name).write_text(text)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = bin_dir / "hnx"
    shim.write_text(
        f'#!/bin/sh\necho "hnx $*" >> {tmp_path}/calls\n'
        f'exec "{sys.executable}" -m homelabnext.cli "$@"\n'
    )
    shim.chmod(0o755)
    r = subprocess.run(
        [bash, "-c", step["run"]],
        cwd=work,
        capture_output=True,
        text=True,
        env={"PATH": f"{bin_dir}:{os.environ['PATH']}", "PYTHONPATH": str(ROOT)},
    )
    calls = (tmp_path / "calls").read_text() if (tmp_path / "calls").exists() else ""
    return r.returncode, calls + r.stdout + r.stderr


def test_checks_validate_the_template_specs(tmp_path):
    files = {n: (SKELETON / "lab" / n).read_text() for n in ("ssh-ca.yml", "secrets.yml")}
    code, said = _specs_step(tmp_path, files)
    assert code == 0, said
    assert "hnx ssh-ca check lab/ssh-ca.yml" in said
    assert "hnx secrets plan lab --spec lab/secrets.yml" in said


@pytest.mark.parametrize(
    "name, old, new",
    [
        (
            "ssh-ca.yml",
            "    max_ttl: 1h\n    extensions: []",
            "    max_ttl: 2h\n    extensions: []",
        ),
        ("secrets.yml", "secrets_version: 1", "secrets_version: 2"),
    ],
)
def test_checks_fail_on_a_broken_spec(tmp_path, name, old, new):
    files = {n: (SKELETON / "lab" / n).read_text() for n in ("ssh-ca.yml", "secrets.yml")}
    assert old in files[name]
    files[name] = files[name].replace(old, new)
    code, said = _specs_step(tmp_path, files)
    assert code != 0, said


def test_a_lab_without_the_specs_passes(tmp_path):
    code, said = _specs_step(tmp_path, {})
    assert code == 0 and "hnx " not in said, said


# ---- the self-hosted runner's job-started hook -------------------------------------------------

REPO = "lab-owner-fake/lab-private"
DEPLOY_JOB = {
    "HNX_DEPLOY_REPOSITORY": REPO,
    "GITHUB_REPOSITORY": REPO,
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/deploy.yml@refs/heads/main",
}


def hook(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed")
    return subprocess.run(
        [bash, str(HOOK)], capture_output=True, text=True, env={"PATH": os.environ["PATH"], **env}
    )


def test_the_hook_accepts_only_the_manual_deploy_from_main():
    r = hook(DEPLOY_JOB)
    assert r.returncode == 0 and "accepted" in r.stdout, r.stderr


@pytest.mark.parametrize(
    ("change", "why"),
    [
        # a branch or pull request that edits checks.yml to run on the deploy runner
        ({"GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/checks.yml@refs/heads/main"}, "is not"),
        ({"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/7/merge"}, "event"),
        ({"GITHUB_EVENT_NAME": "push"}, "event"),
        # deploy.yml, edited on a branch and dispatched from it
        (
            {
                "GITHUB_REF": "refs/heads/evil",
                "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/deploy.yml@refs/heads/evil",
            },
            "ref",
        ),
        # main's ref, but the workflow file comes from elsewhere (a reusable or another repo)
        (
            {"GITHUB_WORKFLOW_REF": "other-fake/repo/.github/workflows/deploy.yml@refs/heads/main"},
            "is not",
        ),
        ({"GITHUB_REPOSITORY": "other-fake/repo"}, "repository"),
        ({"HNX_DEPLOY_REPOSITORY": ""}, "not set on the runner host"),
    ],
)
def test_the_hook_refuses_every_other_job(change, why):
    r = hook({**DEPLOY_JOB, **change})
    assert r.returncode == 1 and r.stdout == ""
    assert "refusing this job" in r.stderr and why in r.stderr


def test_the_hook_is_executable_and_documented():
    assert os.access(HOOK, os.X_OK)
    doc = (ROOT / "docs" / "private-overlay.md").read_text()
    assert "ACTIONS_RUNNER_HOOK_JOB_STARTED" in doc and "runner/job-started.sh" in doc
    assert "generate-jitconfig" in doc  # ephemeral, just-in-time registration is the setup


def test_codeowners_guards_the_workflows_and_the_deploy_tools():
    owners = (SKELETON / ".github" / "CODEOWNERS").read_text()
    rules = {
        line.split()[0]: line.split()[1:]
        for line in owners.splitlines()
        if line.strip() and not line.startswith("#")
    }
    for path in ("/.github/", "/bin/", "/runner/", "/ansible.cfg", "/.sops.yaml", "/locks/"):
        assert rules.get(path), path
    assert "/.hnx-private-overlay.yml" in rules
    assert rules.get("/lab/site.yml")  # the site's delegated IPv6 prefixes are trusted, not proved
    assert rules.get("/lab/modules.yml")  # the selection's scope and grants widen trust too
    assert rules.get("/lab/ssh-ca.yml")  # who may sign in over SSH, and for how long
    # the rest of what the lab trusts: hnx site review-tier rates every change to these human
    for path in (
        "/lab/services.yml",
        "/lab/guests/",
        "/lab/modules/",
        "/lab/modules.lock",
        "/lab/model_roles.json",
        "/lab/swaps/",
        "/lab/model-serving/model_store.json",
        "/lab/model_roles.eval.json",
        "/lab/model-evals/",
        # which hosts the deploy reaches and how, the host keys it trusts, and tasks a hook adds
        "/ansible/inventory/",
        "/ansible/known_hosts",
        "/lab/customizations/",
    ):
        assert rules.get(path), path


def test_codeowners_owns_every_path_by_default():
    """Deny by default: the first rule is ``*``, no later rule names no owner (GitHub applies the
    last match, so an empty one would un-own a path), and every file the skeleton ships has a
    valid owner as GitHub matches it, including the paths no line names on its own."""
    text = (SKELETON / ".github" / "CODEOWNERS").read_text()
    lines = [
        ln.split() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert lines[0][0] == "*" and lines[0][1:], lines[0]
    assert all(len(ln) > 1 for ln in lines), [ln for ln in lines if len(ln) == 1]
    rules = rt.parse_codeowners(text)
    files = [p.relative_to(SKELETON).as_posix() for p in SKELETON.rglob("*") if p.is_file()]
    for rel in (*files, "ansible/known_hosts", "lab/customizations/x.yml", "a/new/path.yml"):
        assert rt.codeowners_for(rules, rel), rel


def test_one_checks_job_needs_every_other_job():
    """Branch protection requires checks by job name: the one ``checks`` job needs every other
    job, runs even when one failed or was skipped, and fails unless every one succeeded."""
    checks = yaml.safe_load((SKELETON / ".github" / "workflows" / "checks.yml").read_text())
    jobs = checks["jobs"]
    job = jobs["checks"]
    assert job["name"] == "checks"
    assert set(job["needs"]) == set(jobs) - {"checks"}
    assert job["if"] == "always()"
    (step,) = job["steps"]
    assert step["env"] == {"RESULTS": "${{ join(needs.*.result, ' ') }}"}
    for results, rc in (
        ("success success success success", 0),
        ("success failure success success", 1),
        ("success skipped success success", 1),
        ("success cancelled success success", 1),
        ("", 1),
    ):
        r = subprocess.run(
            ["bash", "-c", step["run"]], env={**os.environ, "RESULTS": results}, capture_output=True
        )
        assert r.returncode == rc, (results, r.stdout)


def test_the_swap_gate_runs_on_every_pull_request():
    """checks.yml runs the swap gate over the lab's own evidence (lab/), with the pinned hnx, the
    base read through git (a full-history checkout), the same refusals as the other hnx jobs
    and no secret."""
    checks = yaml.safe_load((SKELETON / ".github" / "workflows" / "checks.yml").read_text())
    job = checks["jobs"]["swap-gate"]
    steps = job["steps"]
    assert steps[0]["name"] == "refuse an unpinned hnx"
    (step,) = [s for s in steps if s.get("name") == "a role-table change needs a swap record"]
    assert step["run"].strip() == "hnx modules swap-gate --overlay . --ci-base"
    assert step["env"] == {
        "HNX_PR_BASE": "${{ github.event.pull_request.base.sha }}",
        "HNX_PUSH_BEFORE": "${{ github.event.before }}",
    }
    assert "continue-on-error" not in step and "if" not in step
    assert "secrets." not in yaml.safe_dump(job)
    checkouts = [s for s in steps if "actions/checkout" in s.get("uses", "")]
    assert all(s["with"]["persist-credentials"] is False for s in checkouts)
    assert any(s["with"].get("fetch-depth") == 0 for s in checkouts)
    (pinned,) = [s for s in checkouts if s["with"].get("path") == "hnx"]
    assert pinned["with"]["repository"] == "homelab-next/homelab-next"
    assert pinned["with"]["ref"] == PINNED_SHA
    assert "--root" not in step["run"]  # the overlay is the checkout; hnx is only the code


@pytest.mark.parametrize("workflow", ["checks.yml", "deploy.yml"])
def test_every_pinned_checkout_refuses_an_hnx_the_change_carries(workflow):
    """The pinned homelab-next is checked out to hnx/ and installed from there: each job first
    fails when the overlay's own tree has an hnx/ (a file, a directory or a link)."""
    doc = yaml.safe_load((SKELETON / ".github" / "workflows" / workflow).read_text())
    pinned = 0
    for name, job in doc["jobs"].items():
        steps = job.get("steps") or []
        for i, step in enumerate(steps):
            if (step.get("with") or {}).get("path") != "hnx":
                continue
            pinned += 1
            guard = steps[i - 1]
            assert guard.get("name") == "refuse an hnx/ the change itself carries", name
            assert "[ -e hnx ] || [ -L hnx ]" in guard["run"] and "exit 1" in guard["run"], name
    assert pinned >= 1


# ---- the vault password client -----------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    spec = importlib.util.spec_from_file_location("overlay_pass_client", CLIENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpenBao:
    """Records requests; answers an AppRole login, one KV v2 read and revoke-self (204)."""

    def __init__(self, value: str = "fake-vault-password", status: int = 200, revoke: int = 204):
        self.value, self.status, self.revoke, self.calls = value, status, revoke, []

    def __call__(self, req, timeout, context):
        import urllib.error

        self.calls.append((req.get_method(), req.full_url, dict(req.header_items()), req.data))
        assert context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname
        if self.status != 200:
            raise urllib.error.HTTPError(req.full_url, self.status, "no", {}, None)
        if req.full_url.endswith("/v1/auth/approle/login"):
            return FakeResponse(json.dumps({"auth": {"client_token": "fake-token"}}).encode())
        if req.full_url.endswith("/v1/auth/token/revoke-self"):
            if self.revoke != 204:
                raise urllib.error.HTTPError(req.full_url, self.revoke, "no", {}, None)
            return FakeResponse(b"")
        return FakeResponse(json.dumps({"data": {"data": {"value": self.value}}}).encode())


BAO = {
    "BAO_ADDR": "https://bao.example.internal",
    "HNX_VAULT_PASSWORD_REF": "secret:ansible/fake-vault",
}


def test_password_from_the_environment(client):
    assert client.password({"HNX_VAULT_PASSWORD": "fake-from-actions"}) == "fake-from-actions"


def test_password_from_openbao_with_a_token(client):
    bao = FakeOpenBao()
    assert client.password({**BAO, "BAO_TOKEN": "fake-token"}, bao) == "fake-vault-password"
    ((method, url, headers, _),) = bao.calls
    assert method == "GET"
    assert url == "https://bao.example.internal/v1/secret/data/ansible/fake-vault"
    assert headers["X-vault-token"] == "fake-token"


def test_password_from_openbao_with_approle(client):
    bao = FakeOpenBao()
    env = {**BAO, "BAO_ROLE_ID": "fake-role", "BAO_SECRET_ID": "fake-id", "BAO_KV_MOUNT": "kv"}
    assert client.password(env, bao) == "fake-vault-password"
    (login, read, revoke) = bao.calls
    assert login[0] == "POST" and json.loads(login[3]) == {
        "role_id": "fake-role",
        "secret_id": "fake-id",
    }
    assert read[1].endswith("/v1/kv/data/ansible/fake-vault")
    # the minted token dies as soon as the value is read
    assert revoke[:2] == ("POST", "https://bao.example.internal/v1/auth/token/revoke-self")
    assert revoke[2]["X-vault-token"] == "fake-token"


def test_a_token_the_operator_gave_is_not_revoked(client):
    bao = FakeOpenBao()
    client.password({**BAO, "BAO_TOKEN": "fake-token"}, bao)
    assert [c[1].rsplit("/v1/", 1)[1] for c in bao.calls] == ["secret/data/ansible/fake-vault"]


def test_a_failed_revoke_warns_without_the_token_and_still_answers(client):
    warned: list[str] = []
    env = {**BAO, "BAO_ROLE_ID": "fake-role", "BAO_SECRET_ID": "fake-id"}
    ref = env["HNX_VAULT_PASSWORD_REF"]
    got = client.from_openbao(ref, env, FakeOpenBao(revoke=403), warned.append)
    assert got == "fake-vault-password"
    (line,) = warned
    assert "could not revoke" in line and "HTTP 403" in line
    assert "fake-token" not in line and "fake-id" not in line and "fake-vault-password" not in line


def test_the_default_opener_refuses_a_redirect(client):
    """urllib's default opener replays X-Vault-Token to any Location, http:// included."""
    import ssl
    import urllib.request

    with FakeBao(redirect_to="http://127.0.0.1:9") as bao:  # discard port: never reached
        req = urllib.request.Request(bao.url + "/v1/secret/data/x", method="GET")
        req.add_header("X-Vault-Token", "fake-token")
        with pytest.raises(urllib.error.HTTPError) as exc:
            client.urlopen_no_redirect(req, 5, ssl.create_default_context())
    assert exc.value.code == 307
    assert len(bao.calls) == 1


def test_an_https_to_http_redirect_never_carries_the_token(client, tmp_path):
    tls = self_signed(tmp_path)
    if tls is None:
        pytest.skip("openssl is not installed")
    server_ctx, ca = tls
    with FakeBao() as sink, FakeBao(tls=server_ctx, redirect_to=sink.url) as bao:
        env = {**BAO, "BAO_ADDR": bao.url, "BAO_CACERT": str(ca), "BAO_TOKEN": "fake-token"}
        with pytest.raises(client.ClientError, match=r"HTTP 307 .*redirects are refused") as exc:
            client.password(env)
    assert sink.calls == []  # nothing, and no token, reached the plain-http origin
    assert "fake-token" not in str(exc.value)


def test_approle_against_a_real_socket_revokes_the_token(client, tmp_path):
    tls = self_signed(tmp_path)
    if tls is None:
        pytest.skip("openssl is not installed")
    server_ctx, ca = tls
    values = {"secret/ansible/fake-vault": {"value": "fake-vault-password"}}
    with FakeBao(values, tls=server_ctx) as bao:
        env = {**BAO, "BAO_ADDR": bao.url, "BAO_CACERT": str(ca)}
        env |= {"BAO_ROLE_ID": "fake-role", "BAO_SECRET_ID": "fake-id"}
        assert client.password(env) == "fake-vault-password"
        assert bao.live == set()  # the minted token was revoked
    assert [c[:2] for c in bao.calls] == [
        ("POST", "/v1/auth/approle/login"),
        ("GET", "/v1/secret/data/ansible/fake-vault"),
        ("POST", "/v1/auth/token/revoke-self"),
    ]


@pytest.mark.parametrize(
    ("env", "msg"),
    [
        ({}, "never reads a password file"),
        ({**BAO, "BAO_ADDR": "http://bao.example.internal"}, "https://"),
        ({**BAO, "HNX_VAULT_PASSWORD_REF": "ansible/fake-vault"}, "not a secret reference"),
        ({**BAO, "HNX_VAULT_PASSWORD_REF": "secret:../x"}, "not a secret reference"),
        (BAO, "BAO_TOKEN, or BAO_ROLE_ID"),
        ({**BAO, "BAO_TOKEN": "t", "BAO_KV_MOUNT": "a/b"}, "mount name"),
    ],
)
def test_misconfiguration_is_exit_2(client, env, msg):
    with pytest.raises(client.ClientError, match=re.escape(msg)) as exc:
        client.password(env, FakeOpenBao())
    assert exc.value.code == 2


def test_openbao_refusal_names_the_status_not_the_secret(client):
    with pytest.raises(client.ClientError, match="HTTP 403") as exc:
        client.password({**BAO, "BAO_TOKEN": "fake-token"}, FakeOpenBao(status=403))
    assert exc.value.code == 1 and "fake-token" not in str(exc.value)
    with pytest.raises(client.ClientError, match="no non-empty field"):
        client.password({**BAO, "BAO_TOKEN": "fake-token"}, FakeOpenBao(value=""))


def test_main_prints_only_the_password(client, tmp_path):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = client.main(["--vault-id", "default"], env={"HNX_VAULT_PASSWORD": "fake-pw"})
    assert (rc, out.getvalue(), err.getvalue()) == (0, "fake-pw\n", "")


def test_a_password_file_next_to_the_client_is_never_read(tmp_path):
    (tmp_path / ".vault-pass").write_text("fake-file-password\n")
    r = subprocess.run(
        [sys.executable, str(CLIENT), "--vault-id", "default"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert r.returncode == 2 and r.stdout == ""
    assert "fake-file-password" not in r.stderr


# ---- configuration files -----------------------------------------------------------------------


def test_ansible_cfg_uses_the_client():
    cp = configparser.ConfigParser()  # what Ansible reads it with: option names fold to lower case
    cp.read(SKELETON / "ansible.cfg")
    ident = cp.get("defaults", "vault" + "_identity_list")
    ident_id, _, script = ident.partition("@")
    assert ident_id == "default" and script == "bin/vault-pass-client.py"
    assert Path(script).stem.endswith("-client")  # Ansible's rule for a client script
    assert os.access(SKELETON / script, os.X_OK)
    assert cp.get("defaults", "host_key_checking") == "True"
    assert cp.get("diff", "always") == "False"


def test_sops_config_recipients_are_marked_fake():
    text = (SKELETON / ".sops.yaml").read_text()
    doc = yaml.safe_load(text)
    recipients = [
        r.strip()
        for rule in doc["creation_rules"]
        for r in str(rule["age"]).split(",")
        if r.strip()
    ]
    assert recipients and all(r.startswith("age1fake") for r in recipients)
    assert "FAKE" in text.upper() and "fictional" in text.lower()


@pytest.mark.parametrize(
    "env", [{"BAO_REF": "secret:ansible/fake-vault-password\n"}, {"BAO_KV_MOUNT": "kv\n"}]
)
def test_a_name_or_mount_with_a_trailing_newline_is_refused(client, env):
    """``^...$`` matches before a final newline, so a reference ending in one read as a name ending in one."""
    bao = FakeOpenBao()
    with pytest.raises(client.ClientError) as exc:
        client.from_openbao(
            env.get("BAO_REF", "secret:ansible/vault-password"),
            {**BAO, "BAO_TOKEN": "fake-token", **env},
            bao,
        )
    assert exc.value.code == 2 and bao.calls == []
