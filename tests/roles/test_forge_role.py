# SPDX-License-Identifier: Apache-2.0
"""Role of the module that fills the ``forge`` slot (modules/<id>/roles/<id>), run on localhost
against fakes (CI is unprivileged): main renders one container with every credential only in the
env_file and a second run is ``changed=0``; a reference with no value in the secret store, or a
malformed input or credential, is refused by name before anything is written; with the container
"started" (a fake docker and an HTTPS stand-in verified against a lab CA) the first administrator is
created once, from a password that is in no command line, and the certificate change restarts the
service; health passes and fails on every check it makes (version, an open anonymous read, the
registry challenge, the SSH host keys, the administrator's sign-in); export stops the service, dumps
it, writes a listing and starts it again whatever happened; restore refuses a tampered or vacuous
export before writing anything, verifies the restored instance before the service starts and leaves
it stopped on a mismatch; upgrade refuses a target that is unpinned, from another repository or older."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import time
from pathlib import Path

import pytest
import yaml
from forge_front import (
    LOOPBACK,
    NAME,
    Banner,
    Front,
    calls,
    docker,
    free_port,
    make_dump,
    make_pki,
    pem,
    ssh_tools,
    tsv,
)
from rolerun import first_run, run_role

from homelabnext.registry.model import secret_env_name

ROOT = Path(__file__).resolve().parents[2]


def _module_id() -> str:
    for d in sorted((ROOT / "modules").iterdir()):
        m = d / "module.yml"
        if m.is_file() and "forge" in (
            yaml.safe_load(m.read_text()).get("provides", {}).get("slots") or {}
        ):
            return d.name
    raise AssertionError("no module fills the forge slot")


MID = _module_id()
ROLE = str(ROOT / "modules" / MID / "roles" / MID)
P = MID
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
DEFAULTS = yaml.safe_load((Path(ROLE) / "defaults" / "main.yml").read_text())
REPO = DEFAULTS[f"{MID}_image"].split("@")[0].rsplit(":", 1)[0]
PKI = make_pki(Path(__import__("tempfile").mkdtemp()))
# a second CA standing in for the host's public root store
PUBLIC_ROOTS = make_pki(Path(__import__("tempfile").mkdtemp()))[2]
SSH_TYPES = ("ed25519", "rsa", "ecdsa")
SUFFIX = {"ed25519": "ed", "rsa": "rsa", "ecdsa": "ecdsa"}
VALUES = {
    f"secret:{MID}/secret-key": "k" * 40,
    f"secret:{MID}/internal-token": "i" * 60,
    f"secret:{MID}/jwt-secret": "j" * 43,
    f"secret:{MID}/admin-password": "Admin-password-fake-01",
    f"secret:{MID}/tls-cert": PKI[0],
    f"secret:{MID}/tls-key": PKI[1],
    f"secret:{MID}/ca": PKI[2],
    **{
        f"secret:{MID}/ssh-host-key-{SUFFIX[t]}": pem("OPENSSH|PRIVATE|KEY", "b" * 30)
        for t in SSH_TYPES
    },
}
SECRETS = {secret_env_name(r): v for r, v in VALUES.items()}
ADMIN = "Admin-password-fake-01"


def pv(tmp_path: Path, **kw) -> dict:
    v = {
        f"{P}_logical_id": "forge",
        f"{P}_hostname": NAME,
        "ansible_host": GUEST,
        f"{P}_dir": str(tmp_path / "app"),
        f"{P}_data_root": str(tmp_path / "data"),
        f"{P}_owner": USER,
        f"{P}_group": grp.getgrgid(os.getgid()).gr_name,
        # the unprivileged test's own ids (the role requires 1000 or more): it can chown to no other
        f"{P}_uid": os.getuid(),
        f"{P}_gid": os.getgid(),
        f"{P}_admin_user": "admin",
        f"{P}_start": False,
        f"{P}_validate_with_docker": False,
    }
    v.update(
        {
            (f"{P}_{k}" if not k.startswith(("ansible", "hnx", P)) else k): val
            for k, val in kw.items()
        }
    )
    return v


def fp(path: Path) -> tuple[int, str]:
    b = path.read_bytes()
    return len(b), hashlib.sha256(b).hexdigest()


# ----------------------------------------------------------------------------- render


def _first_main_renders_one_container_with_the_application_secrets_only_as_read_only_files(
    tmp_path,
):
    v = pv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_one_container_with_the_application_secrets_only_as_read_only_files)
def test_main_renders_one_container_with_the_application_secrets_only_as_read_only_files(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]
    assert sorted(svc) == [MID]
    s = svc[MID]
    assert s["image"] == DEFAULTS[f"{P}_image"]
    assert s["cap_drop"] == ["ALL"] and s["security_opt"] == ["no-new-privileges:true"]
    assert s["user"] == f"{os.getuid()}:{os.getgid()}"
    assert s["ports"] == [f"{GUEST}:3443:3000", f"{GUEST}:2222:2222"]
    assert s["volumes"] == [
        f"{tmp_path}/data/data:/var/lib/{P}", f"{tmp_path}/data/conf:/etc/{P}",
        f"{tmp_path}/data/export:/export", f"{tmp_path}/app/tls:/tls:ro",
        f"{tmp_path}/app/sshkeys:/sshkeys:ro", f"{tmp_path}/app/appsecrets:/appsecrets:ro",
    ]  # fmt: skip
    env = s["environment"]
    assert env[f"{P.upper()}__server__ROOT_URL"] == f"https://{NAME}:3443/"
    assert env[f"{P.upper()}__server__SSH_SERVER_HOST_KEYS"] == ",".join(
        f"/sshkeys/{P}.{t}" for t in sorted(SSH_TYPES)
    )
    assert (
        env[f"{P.upper()}__server__SSH_PORT"] == "2222"
        and env[f"{P.upper()}__server__DOMAIN"] == NAME
    )
    assert "SSL_CERT_FILE" not in env  # only with an identity provider to trust
    # no value anywhere `docker inspect` can show: not in the compose file, not in the environment,
    # not in an env_file; the environment names a file for each of the three
    for secret in (*SECRETS.values(),):
        assert secret not in text and secret not in r.stdout
    assert "env_file" not in s and not (tmp_path / "app" / "secrets").exists()
    for setting, name in (
        ("security__SECRET_KEY", "secret_key"),
        ("security__INTERNAL_TOKEN", "internal_token"),
        ("oauth2__JWT_SECRET", "jwt_secret"),
    ):
        assert env[f"{P.upper()}__{setting}__FILE"] == f"/appsecrets/{name}"
        assert f"{P.upper()}__{setting}" not in env
    held = {
        n: (tmp_path / "app" / "appsecrets" / n)
        for n in ("secret_key", "internal_token", "jwt_secret")
    }
    assert [f.read_text() for f in held.values()] == ["k" * 40, "i" * 60, "j" * 43]  # no newline
    assert all(oct(f.stat().st_mode & 0o777) == "0o440" for f in held.values())
    assert oct((tmp_path / "app" / "appsecrets").stat().st_mode & 0o777) == "0o750"
    for f in (tmp_path / "app").rglob("*"):
        if f.is_file() and f.parent.name != "appsecrets":
            assert not any(v.encode() in f.read_bytes() for v in ("k" * 40, "i" * 60, "j" * 43)), f
    assert ADMIN not in text  # the administrator's password is never given to the container
    assert oct((tmp_path / "app" / "tls" / "server.key").stat().st_mode & 0o777) == "0o440"
    for t in SSH_TYPES:
        f = tmp_path / "app" / "sshkeys" / f"{P}.{t}"
        assert oct(f.stat().st_mode & 0o777) == "0o440" and f.read_text().startswith(
            "-----BEGIN OPENSSH"
        )
    assert oct((tmp_path / "data" / "conf").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_puts_the_container_in_the_role_slice_the_module_play_names(tmp_path):
    v = pv(tmp_path, hnx_module_slice=f"hnx-{MID}-server.slice")
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@first_run(_first_main_puts_the_container_in_the_role_slice_the_module_play_names)
def test_main_puts_the_container_in_the_role_slice_the_module_play_names(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert {s["cgroup_parent"] for s in doc["services"].values()} == {f"hnx-{MID}-server.slice"}


def _first_an_identity_provider_adds_its_ca_to_the_trust_and_nothing_else_to_the_environment(
    tmp_path,
):
    ref = f"secret:{MID}/oidc-client-secret"
    env = {**SECRETS, secret_env_name(ref): "o" * 24}
    roots = tmp_path / "public-roots.pem"
    roots.write_text(PUBLIC_ROOTS)
    v = pv(
        tmp_path,
        oidc_enabled=True,
        oidc_issuer_url="https://sso.example.internal/realms/lab",
        oidc_client_id="forge",
        system_ca_file=str(roots),
    )
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": env}


@first_run(_first_an_identity_provider_adds_its_ca_to_the_trust_and_nothing_else_to_the_environment)
def test_an_identity_provider_adds_its_ca_to_the_trust_and_nothing_else_to_the_environment(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    svc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"][MID]
    # the trust replaces the image's own store, so it carries the public roots (an issuer behind a
    # public edge certificate) AND the lab CA, not the lab CA alone
    assert svc["environment"]["SSL_CERT_FILE"] == "/tls/ca-bundle.pem"
    bundle = (tmp_path / "app" / "tls" / "ca-bundle.pem").read_text()
    assert PUBLIC_ROOTS.strip() in bundle and PKI[2].strip() in bundle
    assert bundle.index(PUBLIC_ROOTS.strip()) < bundle.index(PKI[2].strip())
    assert "o" * 24 not in (tmp_path / "app" / "docker-compose.yml").read_text()


def _first_an_identity_provider_with_no_public_roots_is_refused(tmp_path):
    ref = f"secret:{MID}/oidc-client-secret"
    env = {**SECRETS, secret_env_name(ref): "o" * 24}
    roots = tmp_path / "empty-roots.pem"
    roots.write_text("no certificate here\n")
    v = pv(
        tmp_path,
        oidc_enabled=True,
        oidc_issuer_url="https://sso.example.internal/realms/lab",
        oidc_client_id="forge",
        system_ca_file=str(roots),
    )
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": env}


@first_run(_first_an_identity_provider_with_no_public_roots_is_refused)
def test_an_identity_provider_with_no_public_roots_is_refused(first):
    r, tmp_path = first
    assert r.returncode != 0
    assert "holds no PEM certificate" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "tls" / "ca-bundle.pem").exists()


# ----------------------------------------------------------------------------- refusals


def _first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(tmp_path, ref):
    env = {**SECRETS, secret_env_name(ref): ""}
    return {"role": ROLE, "tasks_from": "main", "extra_vars": pv(tmp_path), "env": env}


@pytest.mark.parametrize("ref", sorted(VALUES))
@first_run(_first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing)
def test_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(first, ref):
    """Review Focus 3: a module deployed before its secret exists is refused, by name."""
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert ref in r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    for value in SECRETS.values():
        assert value not in r.stdout + r.stderr


def _first_an_optional_secret_is_refused_by_name_only_when_its_feature_is_on(
    tmp_path, which, extra_env
):
    ref = f"secret:{MID}/" + ("oidc-client-secret" if which == "oidc" else "registry-pull-token")
    (tmp_path / "off").mkdir()
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path, **extra_env),
        "env": SECRETS,
        "setup": {"ref": ref},
    }


@pytest.mark.parametrize("which, extra_env", [
    ("oidc", {"oidc_enabled": True, "oidc_issuer_url": "https://sso.example.internal/r", "oidc_client_id": "forge"}),
    ("pull", {"registry_pull_user": "puller"}),
])  # fmt: skip
@first_run(_first_an_optional_secret_is_refused_by_name_only_when_its_feature_is_on)
def test_an_optional_secret_is_refused_by_name_only_when_its_feature_is_on(first, which, extra_env):
    r, tmp_path = first
    ref = first.setup["ref"]
    assert r.returncode != 0 and ref in r.stdout + r.stderr
    assert not (tmp_path / "app").exists()
    # the same configuration with the feature off never reads the reference
    off = run_role(tmp_path / "off", ROLE, "main", pv(tmp_path / "off"), env=SECRETS)
    assert off.returncode == 0, off.stdout + off.stderr


def _first_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path, **over),
        "env": {**SECRETS, **env},
    }


@pytest.mark.parametrize(
    "over, env",
    [
        ({"image": f"{REPO}:latest"}, {}),
        ({"image": f"{REPO}:28.4.0@sha256:" + "a" * 64}, {}),  # not the rootless build
        ({"image": f"{REPO}:28.4.0-rootless"}, {}),  # no digest
        ({"ansible_host": "0.0.0.0"}, {}),
        ({"ansible_host": "git.example.internal"}, {}),
        ({"hostname": "Git"}, {}),
        ({"hostname": "localhost"}, {}),
        ({"logical_id": "Forge"}, {}),
        ({"ssh_port": 3443}, {}),
        ({"port": 70000}, {}),
        ({"uid": 0}, {}),
        ({"data_root": "/var/lib/../etc"}, {}),
        ({"dir": "relative/dir"}, {}),
        ({"mem_limit": "lots"}, {}),
        ({"ssh_host_key_refs": {}}, {}),
        ({"ssh_host_key_refs": {"dsa": f"secret:{MID}/ssh-host-key-rsa"}}, {}),
        ({"admin_login_ref": f"secret:{MID}/secret-key"}, {}),
        ({"oidc_enabled": True}, {}),  # no issuer, no client
        ({}, {secret_env_name(f"secret:{MID}/secret-key"): "short"}),
        ({}, {secret_env_name(f"secret:{MID}/secret-key"): "has'quote-" + "k" * 30}),
        ({}, {secret_env_name(f"secret:{MID}/internal-token"): "k" * 40}),  # equals the app key
        ({}, {secret_env_name(f"secret:{MID}/admin-password"): "k" * 40}),
        ({}, {secret_env_name(f"secret:{MID}/tls-cert"): "not pem"}),
        ({}, {secret_env_name(f"secret:{MID}/tls-key"): "not pem"}),
        ({}, {secret_env_name(f"secret:{MID}/ssh-host-key-rsa"): "not a key"}),
    ],
)  # fmt: skip
@first_run(_first_main_refuses_bad_inputs_and_credentials)
def test_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- started


def _live(tmp_path, front, banner, **kw):
    kw.setdefault("start", True)
    return pv(
        tmp_path,
        bind=LOOPBACK,
        port=front.port,
        ssh_port=banner.port,
        ready_timeout=15,
        **kw,
    ) | {"ansible_host": LOOPBACK}


def _env(tmp_path, **kw):
    ssh_tools(tmp_path / "bin")
    return {**SECRETS, **docker(tmp_path, **kw)}


def test_the_first_administrator_is_created_once_from_a_password_in_no_command_line(tmp_path):
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN) as front:
        banner = Banner()
        env = _env(tmp_path)
        v = _live(tmp_path, front, banner)
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        log = calls(tmp_path)
        creates = [c for c in log if "user create" in c]
        assert len(creates) == 1 and ADMIN not in "\n".join(log)
        assert "-e HNX_FORGE_PASSWORD" in creates[0]
        assert (tmp_path / "env.log").read_text().splitlines() == ["HNX_FORGE_PASSWORD=set"]
        assert any(" restart " in c for c in log)  # the first certificate is read at the next start
        before = len(log)
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0, again.stdout + again.stderr
        new = calls(tmp_path)[before:]
        assert not any("user create" in c for c in new)  # the account exists now
        assert not any(" restart " in c for c in new)  # nothing changed
        banner.close()


def test_a_password_that_does_not_sign_in_is_set_only_when_the_sync_is_on(tmp_path):
    with Front(PKI[0], PKI[1], tmp_path, password="v" * 20) as front:
        banner = Banner()
        env = _env(tmp_path, users="ID\tUsername\n1\tadmin\n")
        off = run_role(tmp_path, ROLE, "main", _live(tmp_path, front, banner), env=env)
        assert off.returncode == 0 and not any("change-password" in c for c in calls(tmp_path))
        on = run_role(
            tmp_path,
            ROLE,
            "main",
            _live(tmp_path, front, banner, admin_password_sync=True),
            env=env,
        )
        assert on.returncode == 0, on.stdout + on.stderr
        changes = [c for c in calls(tmp_path) if "change-password" in c]
        assert len(changes) == 1 and ADMIN not in changes[0]
        banner.close()


def test_the_identity_provider_source_is_created_then_updated_with_its_secret_in_no_command_line(
    tmp_path,
):
    ref = f"secret:{MID}/oidc-client-secret"
    secret = "o" * 24
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN) as front:
        banner = Banner()
        env = {**_env(tmp_path, users="ID\tUsername\n1\tadmin\n"), secret_env_name(ref): secret}
        v = _live(
            tmp_path,
            front,
            banner,
            oidc_enabled=True,
            oidc_issuer_url="https://sso.example.internal/realms/lab",
            oidc_client_id="forge",
        )
        first = run_role(tmp_path, ROLE, "main", v, env=env)
        assert first.returncode == 0, first.stdout[-3000:]
        adds = [c for c in calls(tmp_path) if "add-oauth" in c or "update-oauth" in c]
        assert len(adds) == 1 and secret not in adds[0] and "add-oauth" in adds[0]
        assert "https://sso.example.internal/realms/lab/.well-known/openid-configuration" in adds[0]
        (tmp_path / "auth.txt").write_text("ID\tName\tType\tEnabled\n7\tsso\tOAuth2\ttrue\n")
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        updates = [c for c in calls(tmp_path) if "update-oauth" in c]
        assert (
            len(updates) == 1
            and secret not in updates[0]
            and updates[0].rstrip().endswith("openid-configuration")
        )
        assert " 7 " in updates[0]
        banner.close()


# ----------------------------------------------------------------------------- health


def _health(tmp_path, front, banner, env, **kw):
    """Health on an installed instance: main first (it writes the certificate and the host keys the
    checks verify against), nothing started."""
    v = _live(tmp_path, front, banner, start=False, **kw)
    assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
    return run_role(tmp_path, ROLE, "health", v, env=env)


def test_health_passes_against_a_service_that_does_everything_it_checks(tmp_path):
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN) as front:
        banner = Banner()
        r = _health(tmp_path, front, banner, _env(tmp_path))
        assert r.returncode == 0, r.stdout + r.stderr
        assert "/v2/" in front.requests and "/api/healthz" in front.requests
        banner.close()


@pytest.mark.parametrize("front_kw, banner_ok, ssh, message", [
    ({"version": "27.0.0"}, True, {}, "version"),
    ({"anonymous_ok": True}, True, {}, "anonymous"),
    ({"registry": ""}, True, {}, "registry"),
    ({"password": "w" * 20}, True, {}, "cannot sign in"),
    ({}, False, {}, "ssh"),
    ({}, True, {"presented": "AAAAdifferent"}, "host key"),
])  # fmt: skip
def test_health_fails_on_each_check_it_makes(tmp_path, front_kw, banner_ok, ssh, message):
    with Front(PKI[0], PKI[1], tmp_path, **{"password": ADMIN, **front_kw}) as front:
        banner = Banner()
        env = {**SECRETS, **docker(tmp_path)}
        ssh_tools(tmp_path / "bin", **ssh)
        port = banner.port
        if not banner_ok:
            banner.close()
            port = free_port()  # nothing listens there
        v = pv(tmp_path, bind=LOOPBACK, port=front.port, ssh_port=port) | {"ansible_host": LOOPBACK}
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        r = run_role(tmp_path, ROLE, "health", v, env=env)
        assert r.returncode != 0 and message.lower() in (r.stdout + r.stderr).lower(), (
            r.stdout + r.stderr
        )
        for value in SECRETS.values():
            assert value not in r.stdout + r.stderr
        banner.close()


def test_health_proves_the_pull_account_when_one_is_named(tmp_path):
    ref = f"secret:{MID}/registry-pull-token"
    env = {**_env(tmp_path), secret_env_name(ref): "t" * 20}
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN, pull="puller:" + "t" * 20) as front:
        banner = Banner()
        ok = _health(tmp_path, front, banner, env, registry_pull_user="puller")
        assert ok.returncode == 0, ok.stdout + ok.stderr
        probes = [r for r in front.requests if r.startswith("POST ")]
        assert len(probes) == 2 and "/blobs/uploads/" in probes[0]  # a registry write, an API write
        assert "/api/v1/user" in front.requests  # and a read outside the registry
        front.pull = "puller:other"
        bad = _health(tmp_path, front, banner, env, registry_pull_user="puller")
        assert bad.returncode != 0 and "pull account" in bad.stdout + bad.stderr
        banner.close()


def test_health_fails_when_the_pull_token_is_not_read_only(tmp_path):
    ref = f"secret:{MID}/registry-pull-token"
    env = {**_env(tmp_path), secret_env_name(ref): "t" * 20}
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN, pull="puller:" + "t" * 20,
               pull_writable=True) as front:  # fmt: skip
        banner = Banner()
        bad = _health(tmp_path, front, banner, env, registry_pull_user="puller")
        assert bad.returncode != 0, bad.stdout
        out = (bad.stdout + bad.stderr).lower()
        assert "not read-only" in out and "registry write" in out and "t" * 20 not in out
        banner.close()


# ----------------------------------------------------------------------------- export, restore


def _stood(tmp_path, **kw):
    """The data directories the export and restore hooks expect, with a fake docker whose dump is a
    real archive of two repositories."""
    dump = make_dump(tmp_path / "source.zip")
    env = {**_env(tmp_path, dump=dump, repos_out=tsv()), **kw}
    (tmp_path / "data" / "export").mkdir(parents=True, exist_ok=True)
    return env


def _export(tmp_path, env):
    v = pv(tmp_path, start=True)
    r = run_role(tmp_path, ROLE, "export", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path / "data" / "export"


def test_export_stops_dumps_lists_and_starts_the_service_again(tmp_path):
    env = _stood(tmp_path)
    out = _export(tmp_path, env)
    assert sorted(p.name for p in out.iterdir()) == [
        "dump.zip",
        "listing.jsonl",
        "manifest.json",
        "repos.tsv",
    ]
    listing = [json.loads(ln) for ln in (out / "listing.jsonl").read_text().splitlines()]
    assert sorted(r["key"] for r in listing) == ["dump.zip", "manifest.json", "repos.tsv"]
    for r in listing:
        assert (r["size"], r["sha256"]) == fp(out / r["key"])
    m = json.loads((out / "manifest.json").read_text())
    assert (
        m["format"] == 1
        and m["counts"]["users"] == 2
        and m["counts"]["orgs"] == 1
        and m["counts"]["repos"] == 2
    )
    assert (
        m["repositories"] == 2
        and m["product_version"] == DEFAULTS[f"{P}_image"].split(":")[1].split("-")[0]
    )
    assert (out / "repos.tsv").read_text() == tsv()
    # the configuration (the application secrets) is not in the archive; the archive is 0600
    import zipfile

    with zipfile.ZipFile(out / "dump.zip") as z:
        assert "app.ini" not in z.namelist() and "data/jwt/private.pem" in z.namelist()
    assert oct((out / "dump.zip").stat().st_mode & 0o777) == "0o600"
    assert oct(out.stat().st_mode & 0o777) == "0o700"
    assert m["config_included"] is False
    assert sorted(m["app_key_fingerprints"]) == ["internal_token", "jwt_secret", "secret_key"]
    blob = b"".join(p.read_bytes() for p in out.iterdir())
    assert not any(v.encode() in blob for v in ("k" * 40, "i" * 60, "j" * 43))
    log = calls(tmp_path)
    order = [next(i for i, c in enumerate(log) if k in c) for k in (" stop ", " run ", " up ")]
    assert order == sorted(order)  # stopped, dumped, started
    again = _export(tmp_path, env)
    assert (again / "dump.zip.prev").is_file()  # one previous generation is kept


def _first_export_starts_the_service_again_even_when_the_dump_fails(tmp_path):
    env = _stood(tmp_path)
    (tmp_path / "dump.fails").write_text("")
    return {
        "role": ROLE,
        "tasks_from": "export",
        "extra_vars": pv(tmp_path, start=True),
        "env": env,
    }


@first_run(_first_export_starts_the_service_again_even_when_the_dump_fails)
def test_export_starts_the_service_again_even_when_the_dump_fails(first):
    r, tmp_path = first
    assert r.returncode != 0
    log = calls(tmp_path)
    assert any(" stop " in c for c in log) and any(" up " in c for c in log)
    assert not (tmp_path / "data" / "export" / "dump.zip").exists()


def _first_export_refuses_a_dump_that_proves_nothing_and_puts_nothing_in_place(
    tmp_path, repos_out, why
):
    env = _stood(tmp_path)
    (tmp_path / "repos.out").write_text(repos_out)
    return {
        "role": ROLE,
        "tasks_from": "export",
        "extra_vars": pv(tmp_path, start=True),
        "env": env,
    }


@pytest.mark.parametrize("repos_out, why", [
    (tsv(fsck="fail"), "failing fsck"),
    (tsv(repos=(("labs", "alpha"),)), "fewer repositories on disk than the database lists"),
    ("", "no repository on disk"),
])  # fmt: skip
@first_run(_first_export_refuses_a_dump_that_proves_nothing_and_puts_nothing_in_place)
def test_export_refuses_a_dump_that_proves_nothing_and_puts_nothing_in_place(first, repos_out, why):
    r, tmp_path = first
    assert r.returncode != 0 and "nothing was put in place" in r.stdout + r.stderr, why
    assert not (tmp_path / "data" / "export" / "dump.zip").exists()
    assert any(" up " in c for c in calls(tmp_path))  # and the service is back


def _restore(tmp_path, env, source, front=None, banner=None, **kw):
    if front is not None:
        v = _live(tmp_path, front, banner, restore_source=str(source), **kw)
    else:
        v = pv(tmp_path, restore_source=str(source), ready_timeout=3, **kw)
    return run_role(tmp_path, ROLE, "restore", v, env=env)


def test_restore_refuses_a_tampered_export_and_writes_nothing(tmp_path):
    env = _stood(tmp_path)
    src = _export(tmp_path, env)
    calls_before = len(calls(tmp_path))
    with (src / "dump.zip").open("ab") as f:
        f.write(b"x")
    r = _restore(tmp_path, env, src)
    assert r.returncode != 0 and "not an intact export" in r.stdout + r.stderr
    assert not any(
        " stop " in c for c in calls(tmp_path)[calls_before:]
    )  # the service was not touched
    assert not (tmp_path / "data" / "data" / f"{P}.db").exists()


def test_restore_places_verifies_and_only_then_starts_the_service(tmp_path):
    env = _stood(tmp_path)
    src = _export(tmp_path, env)
    n = len(calls(tmp_path))
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN) as front:
        banner = Banner()
        # the instance is installed first (the certificate and the host keys the checks verify against)
        installed = run_role(
            tmp_path, ROLE, "main", _live(tmp_path, front, banner, start=False), env=env
        )
        assert installed.returncode == 0, installed.stdout[-2000:]
        r = _restore(tmp_path, env, src, front, banner, start=True)
        banner.close()
    assert r.returncode == 0, r.stdout + r.stderr
    log = calls(tmp_path)[n:]
    stop = next(i for i, c in enumerate(log) if " stop " in c)
    run = [i for i, c in enumerate(log) if " run " in c]
    up = next(i for i, c in enumerate(log) if " up " in c)
    assert run and stop < run[0] and run[-1] < up  # verified while stopped, then started
    assert any("regenerate hooks" in c for c in log[up:])
    data = tmp_path / "data" / "data"
    assert (data / "git" / "repositories" / "labs" / "alpha.git" / "HEAD").is_file()
    assert (data / "avatars" / "a.png").is_file() and (data / "jwt" / "private.pem").is_file()
    assert not (data / "ssh").exists() and not (data / "log").exists()  # not the role's to take
    assert not (data / ".restore-stage").exists()
    db = __import__("sqlite3").connect(str(data / f"{P}.db"))
    assert db.execute('SELECT count(*) FROM "user"').fetchone()[0] == 3
    db.close()


def test_restore_leaves_the_service_stopped_when_a_repository_differs(tmp_path):
    env = _stood(tmp_path)
    src = _export(tmp_path, env)
    n = len(calls(tmp_path))
    (tmp_path / "repos.out").write_text(
        tsv().replace("alpha", "alpha", 1).replace(("alpha" * 64)[:64], "f" * 64)
    )
    r = _restore(tmp_path, env, src)
    assert (
        r.returncode != 0 and "STOPPED" in r.stdout + r.stderr
    ) or "left stopped" in r.stdout + r.stderr
    assert not any(" up " in c for c in calls(tmp_path)[n:])


def _relist(src: Path, edit) -> None:
    """Rewrite an export's manifest with ``edit`` and make its listing say what the files now are, so
    only the manifest's own content is what the restore can object to."""
    m = json.loads((src / "manifest.json").read_text())
    edit(m)
    (src / "manifest.json").write_text(json.dumps(m))
    rows = []
    for name in ("dump.zip", "manifest.json", "repos.tsv"):
        size, digest = fp(src / name)
        rows.append(json.dumps({"key": name, "size": size, "sha256": digest}))
    (src / "listing.jsonl").write_text("\n".join(rows) + "\n")


def test_restore_refuses_a_vacuous_export_and_one_whose_repositories_are_not_listed(tmp_path):
    env = _stood(tmp_path)
    src = _export(tmp_path, env)

    def vacuous(m):
        m["counts"]["repos"] = 0
        m["repositories"] = 0

    (src / "repos.tsv").write_text("")
    _relist(src, vacuous)
    r = _restore(tmp_path, env, src)
    assert r.returncode != 0 and "not one to restore from" in r.stdout + r.stderr
    assert not (tmp_path / "data" / "data" / f"{P}.db").exists()


def test_restore_refuses_an_export_of_a_newer_version(tmp_path):
    env = _stood(tmp_path)
    src = _export(tmp_path, env)
    _relist(src, lambda m: m.update(product_version="99.0.0"))
    r = _restore(tmp_path, env, src)
    assert r.returncode != 0 and "not one to restore from" in r.stdout + r.stderr


# ----------------------------------------------------------------------------- upgrade


def _first_upgrade_records_only_a_pinned_newer_target_of_the_same_repository(tmp_path):
    env = _stood(tmp_path)
    base = DEFAULTS[f"{P}_image"].split("@")[0].rsplit(":", 1)[0]
    ok = f"{base}:28.5.0-rootless@sha256:" + "a" * 64
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path),
        "env": env,
        "setup": {"base": base, "env": env, "ok": ok},
    }


@first_run(_first_upgrade_records_only_a_pinned_newer_target_of_the_same_repository)
def test_upgrade_records_only_a_pinned_newer_target_of_the_same_repository(first):
    r, tmp_path = first
    base = first.setup["base"]
    env = first.setup["env"]
    ok = first.setup["ok"]
    assert r.returncode == 0, r.stdout + r.stderr
    good = run_role(tmp_path, ROLE, "upgrade", pv(tmp_path, target_image=ok), env=env)
    assert good.returncode == 0, good.stdout + good.stderr
    for bad in (
        f"{base}:28.3.0-rootless@sha256:" + "b" * 64,  # older
        f"{base}:28.5.0-rootless",  # not pinned
        f"{base}:28.5.0@sha256:" + "c" * 64,  # not the rootless build
        "docker.io/other/image:28.5.0-rootless@sha256:" + "d" * 64,  # another repository
    ):
        r = run_role(tmp_path, ROLE, "upgrade", pv(tmp_path, target_image=bad), env=env)
        assert r.returncode != 0, bad


def test_restore_refuses_application_secrets_that_are_not_the_exports_before_stopping(tmp_path):
    env = _stood(tmp_path)
    src = _export(tmp_path, env)
    n = len(calls(tmp_path))
    other = {**env, secret_env_name(f"secret:{MID}/secret-key"): "q" * 40}
    r = _restore(tmp_path, other, src)
    text = r.stdout + r.stderr
    assert r.returncode != 0 and "secret_key is not the source's" in text, text
    assert "q" * 40 not in text and "k" * 40 not in text
    assert not any(" stop " in c for c in calls(tmp_path)[n:])  # nothing was touched
    assert not (tmp_path / "data" / "data" / f"{P}.db").exists()


def test_restore_refuses_an_export_that_records_no_fingerprints(tmp_path):
    env = _stood(tmp_path)
    src = _export(tmp_path, env)
    n = len(calls(tmp_path))
    _relist(src, lambda m: m.pop("app_key_fingerprints"))
    r = _restore(tmp_path, env, src)
    assert r.returncode != 0 and "no fingerprint" in r.stdout + r.stderr
    assert not any(" stop " in c for c in calls(tmp_path)[n:])


# ----------------------------------------------------------------------------- a SECRET_KEY never set
# An export of a source that ran on the product's built-in default SECRET_KEY (never set) carries no
# fingerprint of it but the dump's proof that nothing is encrypted under it; such an export restores
# only with a fresh key declared as such (app_key_origin: generated), and generated is refused for an
# export of a source with its own key. Every refusal comes before the service is stopped.

_ROWS = ("two_factor", "secret", "webhook", "login_source", "task")
FRESH_KEY = {secret_env_name(f"secret:{MID}/secret-key"): "f" * 43}


def _as_builtin(m: dict) -> None:
    """What the migration tool's dump writes for a source on the built-in key."""
    m["app_key_fingerprints"].pop("secret_key")
    m["secret_key_source"] = "builtin-default"
    m["secret_key_unused_proof"] = {
        "rules": DEFAULTS[f"{P}_image"].split(":")[1].split("-")[0],
        "encrypted_rows": dict.fromkeys(_ROWS, 0),
    }


def _builtin_export(tmp_path, **sql_kw):
    tmp_path.mkdir(parents=True, exist_ok=True)
    dump = make_dump(tmp_path / "source.zip", **sql_kw)
    env = _env(tmp_path, dump=dump, repos_out=tsv())
    (tmp_path / "data" / "export").mkdir(parents=True, exist_ok=True)
    src = _export(tmp_path, env)
    _relist(src, _as_builtin)
    return env, src


def test_restore_takes_a_fresh_key_for_an_export_that_proved_the_built_in_one_unused(tmp_path):
    env, src = _builtin_export(tmp_path)
    env = {**env, **FRESH_KEY}
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN) as front:
        banner = Banner()
        installed = run_role(
            tmp_path, ROLE, "main", _live(tmp_path, front, banner, start=False), env=env
        )
        assert installed.returncode == 0, installed.stdout[-2000:]
        r = _restore(tmp_path, env, src, front, banner, start=True, app_key_origin="generated")
        banner.close()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "f" * 43 not in r.stdout + r.stderr
    assert (tmp_path / "data" / "data" / f"{P}.db").is_file()


@pytest.mark.parametrize("builtin, origin, message", [
    (True, "source", "cannot be carried"),  # the default: the operator must declare the fresh key
    (False, "generated", "has its own SECRET_KEY"),  # a key of its own is always copied
])  # fmt: skip
def test_restore_refuses_a_key_origin_that_does_not_fit_the_export_before_stopping(
    tmp_path, builtin, origin, message
):
    if builtin:
        env, src = _builtin_export(tmp_path)
    else:
        env = _stood(tmp_path)
        src = _export(tmp_path, env)
    n = len(calls(tmp_path))
    r = _restore(tmp_path, {**env, **FRESH_KEY}, src, app_key_origin=origin)
    text = r.stdout + r.stderr
    assert r.returncode != 0 and message in text, text[-2000:]
    assert not any(" stop " in c for c in calls(tmp_path)[n:])
    assert not (tmp_path / "data" / "data" / f"{P}.db").exists()


def test_restore_refuses_a_fresh_key_when_the_proof_is_absent_or_the_archive_holds_a_row(tmp_path):
    env, src = _builtin_export(tmp_path / "a", encrypted=["webhook"])
    n = len(calls(tmp_path / "a"))
    r = _restore(tmp_path / "a", {**env, **FRESH_KEY}, src, app_key_origin="generated")
    assert r.returncode != 0 and "webhook: 1 rows" in r.stdout + r.stderr
    assert not any(" stop " in c for c in calls(tmp_path / "a")[n:])
    env, src = _builtin_export(tmp_path / "b")
    _relist(src, lambda m: m.pop("secret_key_unused_proof"))
    r = _restore(tmp_path / "b", {**env, **FRESH_KEY}, src, app_key_origin="generated")
    assert r.returncode != 0 and "no proof" in r.stdout + r.stderr


# ----------------------------------------------------------------------------- --check on a fresh guest


def test_check_mode_on_a_fresh_guest_reports_changes_and_waits_for_no_service(tmp_path):
    """--check starts nothing, so a guest with no container yet has no service to wait for or to
    seed: the readiness wait (a read-only task that runs in --check) must not poll out its whole
    timeout, and nothing may be run inside a container that does not exist."""
    ssh_tools(tmp_path / "bin")
    env = {**SECRETS, **docker(tmp_path, running=False)}
    v = pv(tmp_path, start=True, ready_timeout=25, bind=LOOPBACK, port=free_port())
    t0 = time.monotonic()
    r = run_role(tmp_path, ROLE, "main", v, env=env, check=True)
    took = time.monotonic() - t0
    assert r.returncode == 0, r.stdout + r.stderr
    assert took < 20, took  # the wait would have used its 25 s
    assert not any(" exec " in c for c in calls(tmp_path))
    assert (
        "changed=" in r.stdout and "changed=0" not in r.stdout
    )  # the dry run reports what it would do


def test_check_mode_on_a_running_service_still_waits_and_reads(tmp_path):
    """The guard is for a service that is not there: where one runs, --check keeps its read-only
    checks (the answer wait and the account listing), so a real run's behaviour is not guessed."""
    with Front(PKI[0], PKI[1], tmp_path, password=ADMIN) as front:
        banner = Banner()
        env = _env(tmp_path, users="ID\tUsername\n1\tadmin\n")
        v = _live(tmp_path, front, banner)
        (tmp_path / "app" / "tls").mkdir(parents=True)  # an installed service has its CA on disk
        (tmp_path / "app" / "tls" / "ca.pem").write_text(PKI[2])
        r = run_role(tmp_path, ROLE, "main", v, env=env, check=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert any("admin user list" in c for c in calls(tmp_path))
        banner.close()
