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
* the vault password client reads the environment or OpenBao (faked here), never a file;
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

ROOT = Path(__file__).resolve().parents[2]
SKELETON = ROOT / "examples" / "private-overlay"
TEMPLATES = sorted((SKELETON / ".github" / "workflows").glob("*.yml"))
OWN = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
CLIENT = SKELETON / "bin" / "vault-pass-client.py"

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
RELEASE_COMMENT = re.compile(r"^\s+#\s+v\d+(?:\.\d+)*\b")
EXPR = re.compile(r"\$\{\{")
READ = {"read", "none"}


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
        "on: [pull_request_target]\n"
        "permissions: write-all\n"
        "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v7\n"
        "      - uses: tailscale/github-action@" + "a" * 40 + "\n"
        "      - uses: actions/setup-python@" + "b" * 40 + "  # v7.0.0\n"
        "      - uses: actions/checkout@" + "c" * 40 + "  # v7.0.1\n"
        "      - run: echo ${{ secrets.FAKE_TOKEN }}\n"
    )
    problems = "\n".join(lint_workflow(bad))
    for needle in (
        "actions/checkout@v7 is not pinned",
        "has no trailing",
        "pull_request_target",
        "top-level permissions",
        "no timeout-minutes",
        "without persist-credentials",
        "expression inside run",
    ):
        assert needle in problems, needle


@pytest.mark.skipif(shutil.which("actionlint") is None, reason="actionlint is not installed")
def test_actionlint_accepts_the_templates():
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


def test_deploy_runs_from_main_through_the_protected_environment(deploy):
    assert _triggers(deploy) == {"push", "workflow_dispatch"}
    assert _on(deploy)["push"] == {"branches": ["main"]}
    assert deploy["permissions"] == {}
    assert deploy["concurrency"]["cancel-in-progress"] is False
    (job,) = deploy["jobs"].values()
    assert job["environment"] == "production"
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["permissions"] == {"contents": "read"}


def test_deploy_offers_both_paths(deploy):
    (job,) = deploy["jobs"].values()
    assert "self-hosted" in job["runs-on"] and "ubuntu-latest" in job["runs-on"]
    ts = [s for s in job["steps"] if str(s.get("uses", "")).startswith("tailscale/github-action@")]
    assert len(ts) == 1
    assert ts[0]["if"] == "vars.HNX_DEPLOY_PATH != 'self-hosted'"
    assert ts[0]["with"]["tags"] == "tag:ci-deploy"
    assert set(ts[0]["with"]) >= {"oauth-client-id", "oauth-secret"}


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
    assert set(users) == {
        "SOPS_AGE_KEY",
        "ANSIBLE_VAULT_PASSWORD",
        "DEPLOY_SSH_KEY",
        "TS_OAUTH_CLIENT_ID",
        "TS_OAUTH_SECRET",
    }
    text = (SKELETON / ".github" / "workflows" / "deploy.yml").read_text()
    assert "set -x" not in text and "ACTIONS_STEP_DEBUG" not in text


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
    """Records requests; answers an AppRole login and one KV v2 read."""

    def __init__(self, value: str = "fake-vault-password", status: int = 200):
        self.value, self.status, self.calls = value, status, []

    def __call__(self, req, timeout, context):
        import urllib.error

        self.calls.append((req.get_method(), req.full_url, dict(req.header_items()), req.data))
        assert context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname
        if self.status != 200:
            raise urllib.error.HTTPError(req.full_url, self.status, "no", {}, None)
        if req.full_url.endswith("/v1/auth/approle/login"):
            return FakeResponse(json.dumps({"auth": {"client_token": "fake-token"}}).encode())
        return FakeResponse(json.dumps({"data": {"data": {"value": self.value}}}).encode())


BAO = {
    "BAO_ADDR": "https://bao.example.internal:8200",
    "HNX_VAULT_PASSWORD_REF": "secret:ansible/fake-vault",
}


def test_password_from_the_environment(client):
    assert client.password({"HNX_VAULT_PASSWORD": "fake-from-actions"}) == "fake-from-actions"


def test_password_from_openbao_with_a_token(client):
    bao = FakeOpenBao()
    assert client.password({**BAO, "BAO_TOKEN": "fake-token"}, bao) == "fake-vault-password"
    ((method, url, headers, _),) = bao.calls
    assert method == "GET"
    assert url == "https://bao.example.internal:8200/v1/secret/data/ansible/fake-vault"
    assert headers["X-vault-token"] == "fake-token"


def test_password_from_openbao_with_approle(client):
    bao = FakeOpenBao()
    env = {**BAO, "BAO_ROLE_ID": "fake-role", "BAO_SECRET_ID": "fake-id", "BAO_KV_MOUNT": "kv"}
    assert client.password(env, bao) == "fake-vault-password"
    (login, read) = bao.calls
    assert login[0] == "POST" and json.loads(login[3]) == {
        "role_id": "fake-role",
        "secret_id": "fake-id",
    }
    assert read[1].endswith("/v1/kv/data/ansible/fake-vault")


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
