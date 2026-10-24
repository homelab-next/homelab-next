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

from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]
SKELETON = ROOT / "examples" / "private-overlay"
TEMPLATES = sorted((SKELETON / ".github" / "workflows").glob("*.yml"))
OWN = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
CLIENT = SKELETON / "bin" / "vault-pass-client.py"

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


def test_zizmor_accepts_the_templates():
    """docs/private-overlay.md says the templates pass zizmor (checked with 1.31.1, offline)."""
    require_tool("zizmor")
    r = subprocess.run(
        ["zizmor", "--offline", "--no-progress", *map(str, TEMPLATES)],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


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
