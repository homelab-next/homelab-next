# SPDX-License-Identifier: Apache-2.0
"""The role of the dataflow provider module (the one the module that fills the ``dataflow`` slot
contributes), run on localhost against fakes (CI is unprivileged):

* main renders the compose project with no secret in it (the credentials only in the 0600
  env_file), the certificate files and the lake's endpoints as parameters, and a second run is
  ``changed=0``; a malformed input, or a malformed or UNSET credential, is refused before anything
  is rendered, naming the ``secret:`` reference;
* the API script (the role's own, run as the hooks run it) is exercised against a stand-in
  controller: converge is idempotent, health refuses what it must (an anonymous answer, a clustered
  node, invalid components, a missing or wrongly sensitive parameter, a registry client that does
  not match the settings, a smoke flow that is not running) and the export and the import of flow
  definitions round-trip;
* the hooks run end to end over TLS against that stand-in: health reads the smoke flow's file, the
  export archives the state with the service stopped (and starts it again whatever happens), and the
  restore refuses a tampered, linked or foreign archive and moves what it replaces aside.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml
from dataflow_front import Controller, make_pki, smoke_definition
from rolerun import fake, first_run, run_role

from homelabnext.registry.model import secret_env_name

ROOT = Path(__file__).resolve().parents[2]
USER = pwd.getpwuid(os.getuid()).pw_name
SLOT = "dataflow"


def url(scheme: str, host: str, port: int) -> str:
    return f"{scheme}://{host}:{port}"


SELF_HOST = "dataflow.example.internal"
SELF_URL = url("https", SELF_HOST, 9443)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["dns-core"][
    "address"
]


def _module_id() -> str:
    found = [
        d.name
        for d in sorted((ROOT / "modules").iterdir())
        if (d / "module.yml").is_file()
        and SLOT
        in (yaml.safe_load((d / "module.yml").read_text()).get("provides", {}).get("slots") or {})
    ]
    assert len(found) == 1, found
    return found[0]


MID = _module_id()
P = MID  # the role's variable prefix is the module's id
ROLE_DIR = ROOT / "modules" / MID / "roles" / MID
ROLE = str(ROLE_DIR)
SCRIPT = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())[f"{P}_api_script"]
ROLE_VARS = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
FIXED_NAMES = ROLE_VARS[f"{P}_fixed_parameter_names"]  # every parameter the role always supplies
SENSITIVE_NAMES = ROLE_VARS[f"{P}_sensitive_fixed_names"]  # the ones among them from secret refs
SMOKE_FILE = ROLE_DIR / "files" / "hnx-smoke.json"
S3_URL = url("http", "store.example.internal", 3900)
CATALOG_URL = url("http", "catalog.example.internal", 8181)
QUERY_URL = url("https", "query.example.internal", 8443)
EVENTS_URL = url("https", "events.example.internal", 8099)
KEY_ID = "GK" + "ab12" * 6
KEY_SECRET = "c0de" * 16
STORE_PW = "store-pass-0123456789"
PROPS_KEY = "k" * 24
USER_PW = "single-user-pass-123"
EVENTS_AUTH = "Bearer events-0123456789"
CERT, KEY = make_pki(Path(__import__("tempfile").mkdtemp()))


def ref(name: str) -> str:
    return f"secret:{MID}/{name}"


def env_of(name: str, value: str) -> dict:
    return {secret_env_name(ref(name)): value}


def secrets(**over) -> dict:
    s = {
        "tls-cert": CERT.read_text().strip(), "tls-key": KEY.read_text().strip(),
        "ca": CERT.read_text().strip(), "store-password": STORE_PW,
        "sensitive-props-key": PROPS_KEY, "single-user-password": USER_PW,
        "s3-access-key": KEY_ID, "s3-secret-key": KEY_SECRET, "events-token": EVENTS_AUTH,
    }  # fmt: skip
    s.update(over)
    out = {}
    for k, v in s.items():
        out.update(env_of(k, v))
    return out


def vs(tmp: Path, **kw) -> dict:
    """The role's variables with the role prefix applied to every short name."""
    v = {
        "logical_id": SLOT, "dir": str(tmp / "app"), "data_root": str(tmp / "data"),
        "export_dir": str(tmp / "export"), "owner": USER, "uid": os.getuid(), "gid": os.getgid(),
        "start": False, "validate_with_docker": False, "warehouse": "s3://lake-warehouse/",
        "region": "lake1", "s3_url": S3_URL, "catalog_url": CATALOG_URL, "query_url": QUERY_URL,
        "events_url": EVENTS_URL, "self_url": SELF_URL,
    }  # fmt: skip
    v.update(kw)
    out = {f"{P}_{k}": val for k, val in v.items()}
    out["ansible_host"] = GUEST
    return out


def pick(env: dict, suffix: str) -> str:
    """The value of the one variable whose name ends with ``suffix`` (the names carry the product's
    prefix, which this test does not)."""
    keys = [k for k in env if k.endswith(suffix)]
    assert len(keys) == 1, (suffix, keys)
    return env[keys[0]]


def compose(tmp: Path) -> dict:
    return yaml.safe_load((tmp / "app" / "docker-compose.yml").read_text())["services"][MID]


def default_ref(name: str) -> str:
    return yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text())[f"{P}_{name}"]


# ----------------------------------------------------------------------------- jdbc drivers


def _first_the_driver_directory_is_mounted_read_only_and_empty_by_default(tmp_path):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": vs(tmp_path), "env": secrets()}


@first_run(_first_the_driver_directory_is_mounted_read_only_and_empty_by_default)
def test_the_driver_directory_is_mounted_read_only_and_empty_by_default(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(
        v.endswith("/drivers:" + ROLE_VARS[f"{P}_container_home"] + "/drivers:ro")
        for v in compose(tmp_path)["volumes"]
    )
    assert not any(
        (tmp_path / "data" / "drivers").iterdir()
    )  # nothing is fetched unless a site lists a driver
    assert default_ref("jdbc_drivers") == []


# ----------------------------------------------------------------------------- main renders


def _first_main_renders_the_service_with_no_secret_in_the_compose_file(tmp_path):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": vs(tmp_path), "env": secrets()}


@first_run(_first_main_renders_the_service_with_no_secret_in_the_compose_file)
def test_main_renders_the_service_with_no_secret_in_the_compose_file(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = compose(tmp_path)
    assert svc["image"].startswith("docker.io/apache/") and "@sha256:" in svc["image"]
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["ports"] == [GUEST + ":9443:9443"]  # the one published port, on the guest's address
    assert svc["mem_limit"] == "4g"
    env = svc["environment"]
    # the heap, the stores, the proxy hosts the service accepts, and the sign-in
    assert pick(env, "_JVM_HEAP_INIT") == pick(env, "_JVM_HEAP_MAX") == "2g"
    assert env["KEYSTORE_TYPE"] == env["TRUSTSTORE_TYPE"] == "PKCS12"
    assert pick(env, "_WEB_PROXY_HOST") == ",".join(
        [SELF_HOST + ":" + str(9443), GUEST + ":" + str(9443)]
    )
    assert env["AUTH"] == "tls" and pick(env, "_USER_AUTHORIZER") == "single-user-authorizer"
    # the lake's endpoints are parameters, rendered from the registry (here the overrides)
    assert env["HNX_LAKE_S3_ENDPOINT"] == S3_URL and env["HNX_LAKE_CATALOG_URI"] == CATALOG_URL
    assert env["HNX_LAKE_QUERY_URL"] == QUERY_URL and env["HNX_EVENTS_URL"] == EVENTS_URL
    assert (
        env["HNX_LAKE_WAREHOUSE"] == "s3://lake-warehouse/" and env["HNX_LAKE_S3_REGION"] == "lake1"
    )
    # every value a secret reference supplies is in the 0600 env_file and nowhere else
    values = [KEY_ID, KEY_SECRET, STORE_PW, PROPS_KEY, USER_PW, EVENTS_AUTH]
    for value in values:
        assert value not in text and value not in r.stdout and value not in r.stderr
    envfile = tmp_path / "app" / "secrets" / f"{MID}.env"
    assert oct(envfile.stat().st_mode & 0o777) == "0o600"
    body = envfile.read_text()
    for name in (
        "KEYSTORE_PASSWORD", "TRUSTSTORE_PASSWORD", "_SENSITIVE_PROPS_KEY",
        "SINGLE_USER_CREDENTIALS_USERNAME", "SINGLE_USER_CREDENTIALS_PASSWORD", *SENSITIVE_NAMES,
    ):  # fmt: skip
        assert re.search(r"^(\w*)" + name + "=", body, re.M), name
    for value in values:
        assert value in body
    # everything the service writes is under the data root, the container user's and 0700
    for d in ("conf", "state", "flowfile_repository", "content_repository", "database_repository",
              "provenance_repository", "logs", "smoke"):  # fmt: skip
        assert f"{tmp_path}/data/{d}:" in "\n".join(svc["volumes"]), d
        assert oct((tmp_path / "data" / d).stat().st_mode & 0o777) == "0o700", d
    assert any(v.startswith(f"{tmp_path}/app/tls:") and v.endswith(":ro") for v in svc["volumes"])
    # the certificate files: the key is the container group's, not the world's
    tls = tmp_path / "app" / "tls"
    assert oct((tls / "server.key").stat().st_mode & 0o777) == "0o640"
    assert (tls / "ca.pem").read_text().strip() == CERT.read_text().strip()
    again = run_role(tmp_path, ROLE, "main", vs(tmp_path), env=secrets())
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_the_container_joins_the_role_slice_the_module_play_names(tmp_path):
    v = vs(tmp_path)
    v["hnx_module_slice"] = f"hnx-{MID}-server.slice"
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": secrets()}


@first_run(_first_the_container_joins_the_role_slice_the_module_play_names)
def test_the_container_joins_the_role_slice_the_module_play_names(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    assert compose(tmp_path)["cgroup_parent"] == f"hnx-{MID}-server.slice"


def _first_extra_parameters_reach_the_flows_as_sensitive_values_only_in_the_env_file(tmp_path):
    extra = {"HNX_FEED_LOGIN": ref("feed-key")}
    env = {**secrets(), **env_of("feed-key", "feed-key-value-0123")}
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": vs(tmp_path, extra_parameters=extra),
        "env": env,
    }


@first_run(_first_extra_parameters_reach_the_flows_as_sensitive_values_only_in_the_env_file)
def test_extra_parameters_reach_the_flows_as_sensitive_values_only_in_the_env_file(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert "feed-key-value-0123" not in (tmp_path / "app" / "docker-compose.yml").read_text()
    assert (
        "HNX_FEED_LOGIN='feed-key-value-0123'"
        in (tmp_path / "app" / "secrets" / f"{MID}.env").read_text()
    )


def _first_oidc_renders_its_settings_and_reads_its_client_secret_from_the_store(tmp_path):
    over = {
        "auth": "oidc", "oidc_issuer_url": "https://idp.example.internal/realms/lab",
        "oidc_client_id": "dataflow", "initial_admin": "alice",
    }  # fmt: skip
    env = {**secrets(), **env_of("oidc-client-secret", "oidc-client-secret-0123456789"),
           **env_of("api-token", "api-token-0123456789abcdefgh")}  # fmt: skip
    return {"role": ROLE, "tasks_from": "main", "extra_vars": vs(tmp_path, **over), "env": env}


@first_run(_first_oidc_renders_its_settings_and_reads_its_client_secret_from_the_store)
def test_oidc_renders_its_settings_and_reads_its_client_secret_from_the_store(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    e = compose(tmp_path)["environment"]
    assert e["AUTH"] == "oidc" and e["INITIAL_ADMIN_IDENTITY"] == "alice"
    assert pick(e, "_OIDC_DISCOVERY_URL") == (
        "https://idp.example.internal/realms/lab/.well-known/openid-configuration"
    )
    assert pick(e, "_OIDC_CLIENT_ID") == "dataflow"
    assert pick(e, "_OIDC_CLAIM_IDENTIFYING_USER") == "preferred_username"
    body = (tmp_path / "app" / "secrets" / f"{MID}.env").read_text()
    assert (
        re.search(r"^\w+_OIDC_CLIENT_SECRET=", body, re.M)
        and "oidc-client-secret-0123456789" in body
    )
    assert "SINGLE_USER_CREDENTIALS" not in body and "single-user" not in json.dumps(e)
    assert (
        "oidc-client-secret-0123456789" not in (tmp_path / "app" / "docker-compose.yml").read_text()
    )


# ----------------------------------------------------------------------------- refusals

BAD = [
    ({"image": default_ref("image").split("@")[0].rsplit(":", 1)[0] + ":latest"}, {}),
    ({"bind": "0.0.0.0"}, {}),
    ({"uid": 0}, {}),
    ({"data_root": "/var/lib/../etc"}, {}),
    ({"export_dir": "relative"}, {}),
    ({"auth": "none"}, {}),
    ({"auth": "oidc"}, {}),  # no issuer, client or administrator
    (
        {
            "auth": "oidc",
            "oidc_issuer_url": "http://idp.example.internal/realms/lab",
            "oidc_client_id": "dataflow",
            "initial_admin": "alice",
        },
        {},
    ),  # not https
    ({"heap": "2g", "mem_limit": "2g"}, {}),  # no room over the heap
    ({"heap": "512m"}, {}),
    ({"self_url": url("http", SELF_HOST, 9443)}, {}),  # a token would travel in clear
    ({"warehouse": "lake-warehouse"}, {}),
    ({"extra_parameters": {"lower_case": ref("x")}}, {}),
    ({"extra_parameters": {"HNX_LAKE_S3_REGION": ref("x")}}, {}),  # a fixed name
    ({"extra_parameters": {"HNX_X": "not-a-reference"}}, {}),
    ({"extra_parameters": {"HNX_X": ref("tls-key")}}, {}),  # a reference used twice
    (
        {"registry_url": "https://git.example.internal/api/v3"},
        {},
    ),  # url without owner and repository
    (
        {
            "registry_url": "http://git.example.internal/api/v3",
            "registry_owner": "o",
            "registry_repo": "r",
        },
        {},
    ),
    ({"restore_mode": "everything"}, {}),
    (
        {
            "jdbc_drivers": [
                {"name": "x.jar", "url": "http://driver.example.internal/x.jar", "sha256": "a" * 64}
            ]
        },
        {},
    ),  # not https
    (
        {
            "jdbc_drivers": [
                {
                    "name": "x.jar",
                    "url": "https://driver.example.internal/x.jar",
                    "sha256": "A" * 64,
                }
            ]
        },
        {},
    ),  # not lower-case hex
    (
        {
            "jdbc_drivers": [
                {
                    "name": "x.jar",
                    "url": "https://driver.example.internal/x.jar",
                    "sha256": "a" * 63,
                }
            ]
        },
        {},
    ),
    (
        {
            "jdbc_drivers": [
                {
                    "name": "../x.jar",
                    "url": "https://driver.example.internal/x.jar",
                    "sha256": "a" * 64,
                }
            ]
        },
        {},
    ),  # a path, not a name
    (
        {
            "jdbc_drivers": [
                {
                    "name": "x.txt",
                    "url": "https://driver.example.internal/x.jar",
                    "sha256": "a" * 64,
                }
            ]
        },
        {},
    ),
    (
        {"jdbc_drivers": [{"name": "x.jar", "url": "https://driver.example.internal/x.jar"}]},
        {},
    ),  # no digest: an unpinned file is never fetched
    (
        {
            "jdbc_drivers": [
                {
                    "name": "x.jar",
                    "url": "https://driver.example.internal/x.jar",
                    "sha256": "a" * 64,
                }
            ]
            * 2
        },
        {},
    ),  # one name twice
    ({"provenance_max_age": "forever"}, {}),
    ({"smoke_max_age_minutes": 0}, {}),
    ({"s3_access_key_ref": ref("s3-secret-key")}, {}),  # two references the same
    ({}, {"tls-cert": "not a certificate"}),
    ({}, {"tls-key": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"}),
    ({}, {"store-password": "short"}),
    ({}, {"sensitive-props-key": "short"}),
    ({}, {"single-user-password": "short"}),
    ({}, {"s3-secret-key": "not-hex"}),
    ({}, {"s3-access-key": "AK123"}),
    ({}, {"events-token": "x"}),
]


def _first_main_refuses_bad_inputs_and_credentials_before_rendering_anything(tmp_path, over, bad):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": vs(tmp_path, **over),
        "env": secrets(**bad),
    }


@pytest.mark.parametrize("over, bad", BAD)
@first_run(_first_main_refuses_bad_inputs_and_credentials_before_rendering_anything)
def test_main_refuses_bad_inputs_and_credentials_before_rendering_anything(first, over, bad):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_a_credential_the_store_does_not_hold_is_refused_by_name(tmp_path):
    env = secrets()
    del env[secret_env_name(ref("events-token"))]
    r = run_role(tmp_path, ROLE, "main", vs(tmp_path), env=env)
    assert r.returncode != 0
    assert secret_env_name(ref("events-token")) in r.stdout + r.stderr or ref("events-token") in (
        r.stdout + r.stderr
    )
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_oidc_refuses_a_missing_client_secret_and_a_missing_api_token(tmp_path):
    over = {
        "auth": "oidc", "oidc_issuer_url": "https://idp.example.internal/realms/lab",
        "oidc_client_id": "dataflow", "initial_admin": "alice",
    }  # fmt: skip
    env = {**secrets(), **env_of("oidc-client-secret", "oidc-client-secret-0123456789")}
    return {"role": ROLE, "tasks_from": "main", "extra_vars": vs(tmp_path, **over), "env": env}


@first_run(_first_oidc_refuses_a_missing_client_secret_and_a_missing_api_token)
def test_oidc_refuses_a_missing_client_secret_and_a_missing_api_token(first):
    r, tmp_path = first
    assert r.returncode != 0  # no bearer token for the role's own calls: not a skipped check
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_upgrade_refuses_an_unpinned_a_foreign_and_an_older_target(tmp_path):
    base = default_ref("image").split("@")[0]
    repo = base.rsplit(":", 1)[0]
    digest = "sha256:" + "1a" * 32
    for target in (
        f"{repo}:2.99.0",
        f"docker.io/other/x:2.99.0@{digest}",
        f"{repo}:1.0.0@{digest}",
    ):
        v = vs(tmp_path, target_image=target)
        assert run_role(tmp_path, ROLE, "upgrade", v, env=secrets()).returncode != 0, target
    (tmp_path / "app").mkdir()  # the project directory the bump is recorded in
    v = vs(tmp_path, target_image=f"{repo}:2.99.0@{digest}")
    r = run_role(tmp_path, ROLE, "upgrade", v, env=secrets())
    assert r.returncode == 0, r.stdout + r.stderr


def _first_upgrade_refuses_the_running_tag_at_another_digest_unless_allowed(tmp_path):
    running = default_ref("image")
    repo_tag, digest = running.split("@")
    other = "sha256:" + "2b" * 32
    (tmp_path / "app").mkdir()
    v = vs(tmp_path, target_image=f"{repo_tag}@{other}")
    return {
        "role": ROLE,
        "tasks_from": "upgrade",
        "extra_vars": v,
        "env": secrets(),
        "setup": {"digest": digest, "repo_tag": repo_tag, "v": v},
    }


@first_run(_first_upgrade_refuses_the_running_tag_at_another_digest_unless_allowed)
def test_upgrade_refuses_the_running_tag_at_another_digest_unless_allowed(first):
    first_result, tmp_path = first
    digest = first.setup["digest"]
    repo_tag = first.setup["repo_tag"]
    v = first.setup["v"]
    assert first_result.returncode != 0
    ok = run_role(
        tmp_path, ROLE, "upgrade", dict(v, **{f"{P}_allow_same_tag_rebuild": True}), env=secrets()
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    same = vs(
        tmp_path, target_image=f"{repo_tag}@{digest}"
    )  # the pinned digest itself is no change
    assert run_role(tmp_path, ROLE, "upgrade", same, env=secrets()).returncode == 0


# ----------------------------------------------------------------------------- the scripts


SCRIPT_VARS = [k for k in ROLE_VARS if k.startswith(f"{P}_") and k.endswith("_script")]


def _secret_option_findings(script: str) -> list[str]:
    """Every password-taking option in ``script`` whose value is a literal or an expansion (the
    only safe forms read the value from the environment, or from a file or standard input)."""
    bad = []
    for line in script.splitlines():
        for m in re.finditer(
            r"(?<![\w-])(-(?:src|dest)?(?:store|key|trust)?(?:pass|passin|passout)(?::\w+)?|-pass(?:in|out)?|--password)\s+(\S+)",
            line,
        ):
            opt, val = m.group(1), m.group(2)
            if opt.endswith(":env"):
                ok = re.fullmatch(r"[A-Z_]+", val) is not None  # a variable NAME
            else:
                ok = re.fullmatch(r"(env|file|fd):\S+", val) is not None and not val.startswith(
                    "pass:"
                )
            if not ok:
                bad.append(line.strip())
    return bad


def test_script_vars_exist_to_be_checked():
    assert f"{P}_stores_script" in SCRIPT_VARS and f"{P}_api_script" in SCRIPT_VARS


@pytest.mark.parametrize("name", SCRIPT_VARS)
def test_no_script_gives_a_tool_a_password_on_its_command_line(name):
    script = ROLE_VARS[name]
    assert _secret_option_findings(script) == []
    # the shell must never expand a password variable into an argument
    for line in script.splitlines():
        assert not re.search(r"\$\{?PW\b", line) or re.search(
            r"(export PW|env:PW|:env PW)", line
        ), line


def test_the_stores_script_reads_the_password_from_stdin_and_hands_it_over_by_name():
    script = ROLE_VARS[f"{P}_stores_script"]
    assert "read -r PW" in script and "-storepass:env PW" in script and "-passout env:PW" in script
    assert '-storepass "' not in script and not re.search(r"\bpass:", script)


def test_the_option_check_catches_what_it_is_for():
    assert _secret_option_findings('keytool -importcert -storepass "$PW"')
    assert _secret_option_findings("keytool -storepass hunter2")
    assert _secret_option_findings("openssl pkcs12 -export -passout pass:$PW")
    assert _secret_option_findings("keytool -storepass:env $PW")
    assert not _secret_option_findings("keytool -storepass:env PW -keypass:env PW")
    assert not _secret_option_findings("openssl pkcs12 -passin env:PW -passout env:PW")


# ----------------------------------------------------------------------------- the API script


def run_script(command: str, cfg: dict, *, check=True):
    r = subprocess.run(
        [sys.executable, "-I", "-c", SCRIPT, command],
        input=json.dumps(cfg), capture_output=True, text=True, timeout=120,
    )  # fmt: skip
    if check:
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)
    return r


def cfg_for(c: Controller, **over) -> dict:
    base = {
        "base_url": c.url, "ca_file": None, "wait_s": 5, "timeout": 5,
        "auth": {"mode": "single-user", "username": c.user, "password": c.password},
        "expect_version": c.version,
        "provider": {"name": "provider", "group": "grp", "context": "ctx",
                     "env_names": ["HNX_A", "HNX_B"], "sensitive": ["HNX_B"]},
        "registry_name": "reg", "registry": None,
        "smoke": {"enabled": True, "definition": smoke_definition()},
    }  # fmt: skip
    base.update(over)
    return base


def test_converge_builds_the_context_the_client_and_the_running_smoke_flow_and_is_idempotent():
    with Controller() as c:
        reg = {"url": "https://git.example.internal/api", "owner": "o", "repo": "r",
               "branch": "main", "path": "flows", "token": "t" * 12}  # fmt: skip
        cfg = cfg_for(c, registry=reg)
        out = run_script("converge", cfg)
        assert out == {"parameters": 2, "registry_client": "present", "smoke": "running"}
        assert c.contexts["ctx"] == {"HNX_A": {"sensitive": False, "provided": True},
                                     "HNX_B": {"sensitive": True, "provided": True}}  # fmt: skip
        (client,) = c.clients.values()
        assert client["properties"]["Repository Owner"] == "o"
        assert client["properties"]["Authentication Type"] == "PERSONAL_ACCESS_TOKEN"
        (group,) = c.groups.values()
        assert group["name"] == "hnx-smoke" and {p["state"] for p in group["processors"]} == {
            "RUNNING"
        }
        again = run_script("converge", cfg)
        assert again == out
        assert len(c.providers) == len(c.clients) == len(c.groups) == 1  # nothing duplicated
        assert run_script("health", cfg)["smoke"] == "running"


def test_converge_with_no_registry_url_removes_a_client_that_was_there():
    with Controller() as c:
        reg = {"url": "https://git.example.internal/api", "owner": "o", "repo": "r",
               "branch": "main", "path": "", "token": ""}  # fmt: skip
        run_script("converge", cfg_for(c, registry=reg))
        assert next(iter(c.clients.values()))["properties"]["Authentication Type"] == "NONE"
        out = run_script("converge", cfg_for(c))
        assert out["registry_client"] == "absent" and c.clients == {}


def test_converge_starts_a_stopped_smoke_flow_and_stops_it_when_disabled():
    with Controller() as c:
        run_script("converge", cfg_for(c))
        (g,) = c.groups.values()
        for p in g["processors"]:
            p["state"] = "STOPPED"
        assert run_script("converge", cfg_for(c))["smoke"] == "running"
        assert {p["state"] for p in g["processors"]} == {"RUNNING"}
        off = cfg_for(c, smoke={"enabled": False, "definition": ""})
        assert run_script("converge", off)["smoke"] == "stopped"
        assert {p["state"] for p in g["processors"]} == {"STOPPED"}


def test_a_refused_sign_in_and_an_unreachable_service_fail_with_one_line_and_no_secret():
    with Controller() as c:
        bad = cfg_for(
            c, auth={"mode": "single-user", "username": "admin", "password": "wrong-password-xyz"}
        )
        r = run_script("converge", bad, check=False)
        assert r.returncode != 0 and "refused" in r.stderr and "wrong-password-xyz" not in r.stderr
        r = run_script("converge", cfg_for(c, auth={"mode": "none"}), check=False)
        assert r.returncode != 0 and "no API credential" in r.stderr
    r = run_script("converge", {**cfg_for(c), "wait_s": 1}, check=False)  # the server is gone
    assert r.returncode != 0 and "did not answer" in r.stderr


def test_a_bearer_credential_is_sent_as_one():
    with Controller(bearer="b" * 40) as c:
        cfg = cfg_for(c, auth={"mode": "bearer", "token": "b" * 40})
        assert run_script("converge", cfg)["parameters"] == 2
        r = run_script(
            "health", cfg_for(c, auth={"mode": "bearer", "token": "x" * 40}), check=False
        )
        assert r.returncode != 0


@pytest.mark.parametrize(
    "mutate, why",
    [
        (lambda c: setattr(c, "version", "2.0.0"), "expected"),
        (lambda c: c.cluster.update(clustered=True), "clustered"),
        (lambda c: c.cluster.update(connectedToCluster=True), "clustered"),
        (lambda c: c.status.update(invalidCount=2), "invalid"),
        (lambda c: c.status.update(syncFailureCount=1), "sync"),
        (lambda c: c.contexts["ctx"].pop("HNX_A"), "lacks"),
        (lambda c: c.contexts["ctx"]["HNX_B"].update(sensitive=False), "wrong sensitivity"),
        (lambda c: c.contexts["ctx"]["HNX_A"].update(provided=False), "lacks"),
        (
            lambda c: next(iter(c.groups.values()))["processors"][0].update(state="STOPPED"),
            "not running",
        ),
        (lambda c: c.groups.clear(), "not imported"),
        (lambda c: setattr(c, "allow_anonymous", True), "no credential"),
    ],
)
def test_health_refuses_what_it_must(mutate, why):
    with Controller() as c:
        cfg = cfg_for(c)
        run_script("converge", cfg)
        mutate(c)
        r = run_script("health", cfg, check=False)
        assert r.returncode != 0 and why in r.stderr, r.stderr


def test_health_refuses_a_registry_client_that_does_not_match_the_settings():
    with Controller() as c:
        reg = {"url": "https://git.example.internal/api", "owner": "o", "repo": "r",
               "branch": "main", "path": "flows", "token": ""}  # fmt: skip
        cfg = cfg_for(c, registry=reg)
        run_script("converge", cfg)
        assert run_script("health", cfg)["registry_client"] == "present"
        next(iter(c.clients.values()))["properties"]["Repository Name"] = "other"
        assert "differs" in run_script("health", cfg, check=False).stderr
        c.clients.clear()
        assert "absent" in run_script("health", cfg, check=False).stderr
        run_script("converge", cfg_for(c, registry=reg))
        assert "none is configured" in run_script("health", cfg_for(c), check=False).stderr


def test_export_writes_each_group_and_a_listing_and_refuses_an_empty_service(tmp_path):
    with Controller() as c:
        cfg = cfg_for(c, dest=str(tmp_path / "out"), expect_min=1)
        r = run_script("export", cfg, check=False)
        assert r.returncode != 0 and "at least 1" in r.stderr  # zero where one is expected
        assert not (tmp_path / "out" / "flows" / "listing.jsonl").exists()
        run_script("converge", cfg_for(c))
        assert run_script("export", cfg) == {"flows": 1}
        rows = [
            json.loads(x)
            for x in (tmp_path / "out" / "flows" / "listing.jsonl").read_text().splitlines()
        ]
        (row,) = rows
        body = (tmp_path / "out" / row["key"]).read_bytes()
        assert row["key"] == "flows/hnx-smoke.json" and row["name"] == "hnx-smoke"
        assert row["size"] == len(body) and row["sha256"] == hashlib.sha256(body).hexdigest()
        assert oct((tmp_path / "out" / row["key"]).stat().st_mode & 0o777) == "0o600"


def test_import_flows_adds_only_the_groups_the_service_lacks():
    with Controller() as c:
        run_script("converge", cfg_for(c))
        items = [{"name": "hnx-smoke", "text": smoke_definition()},
                 {"name": "feed-one", "text": smoke_definition(2)}]  # fmt: skip
        out = run_script("import-flows", cfg_for(c, flows=items))
        assert out == {"imported": ["feed-one"]}
        assert sorted(g["name"] for g in c.groups.values()) == ["feed-one", "hnx-smoke"]


# ----------------------------------------------------------------------------- the hooks, end to end


def fake_docker(tmp: Path, *, health: str = "healthy") -> dict:
    """A docker that lists one container in the given state and logs every other call (and what
    arrives on its standard input, which is where the role puts a password)."""
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    state = json.dumps({"Service": MID, "State": "running", "Health": health})
    fake(
        bindir / "docker",
        "import sys\n"
        f"open({str(tmp / 'docker.log')!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        "if 'ps' in sys.argv:\n"
        f"    print({state!r})\n"
        "elif 'run' in sys.argv and '-i' in sys.argv:\n"
        "    sys.stdin.read()\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def docker_calls(tmp: Path) -> list[str]:
    log = tmp / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def hook_vars(tmp: Path, c: Controller, **kw) -> dict:
    return vs(tmp, self_url=c.url, start=True, **kw)


def hook_env(tmp: Path, **kw) -> dict:
    return {**secrets(), **fake_docker(tmp, **kw)}


def prepare(tmp: Path, c: Controller) -> None:
    """The certificate files the hooks verify the service with (what main writes), and a converged
    service, and the smoke flow's file."""
    assert run_role(tmp, ROLE, "main", vs(tmp, self_url=c.url), env=secrets()).returncode == 0
    assert run_script("converge", {**cfg_for(c, ca_file=str(tmp / "app" / "tls" / "ca.pem")),
                                   "provider": {"name": "p", "group": "g", "context": "hnx-lake",
                                                "env_names": ["HNX_LAKE_S3_ENDPOINT"], "sensitive": []},
                                   "auth": {"mode": "single-user", "username": c.user,
                                            "password": USER_PW},
                                   "smoke": {"enabled": True, "definition": smoke_definition()}})  # fmt: skip


def converged_controller(tmp: Path) -> Controller:
    c = Controller(user="admin", password=USER_PW, https=(CERT, KEY))
    c.__enter__()
    return c


def test_health_passes_and_fails_with_the_smoke_flow_and_the_container(tmp_path):
    c = converged_controller(tmp_path)
    try:
        # the stand-in's context holds what the role's provider would have filled
        assert (
            run_role(tmp_path, ROLE, "main", vs(tmp_path, self_url=c.url), env=secrets()).returncode
            == 0
        )
        c.contexts["hnx-lake"] = {}
        names = sorted(FIXED_NAMES)
        sens = set(SENSITIVE_NAMES)
        for n in names:
            c.contexts["hnx-lake"][n] = {"sensitive": n in sens, "provided": True}
        gid = c.nid("pg")
        c.groups[gid] = {
            "name": "hnx-smoke",
            "definition": b"{}",
            "processors": [{"state": "RUNNING"}] * 3,
        }
        beat = tmp_path / "data" / "smoke" / "heartbeat.txt"
        beat.write_text("hnx-smoke")
        env = hook_env(tmp_path)
        v = hook_vars(tmp_path, c)
        r = run_role(tmp_path, ROLE, "health", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        # a stale file fails it, a missing file fails it
        os.utime(beat, (1, 1))  # the epoch's first second: stale whatever the date is
        r = run_role(tmp_path, ROLE, "health", v, env=env)
        assert r.returncode != 0 and "smoke flow" in r.stdout
        beat.unlink()
        assert run_role(tmp_path, ROLE, "health", v, env=env).returncode != 0
        beat.write_text("x")
        # an unhealthy container fails it before the API is asked
        r = run_role(tmp_path, ROLE, "health", v, env=hook_env(tmp_path, health="unhealthy"))
        assert r.returncode != 0 and "unhealthy" in r.stdout
        # no smoke flow expected: no file needed (and a healthy container again: the fake is one file)
        env = hook_env(tmp_path)
        beat.unlink()
        v2 = hook_vars(tmp_path, c, smoke_enabled=False)
        c.groups.clear()
        assert run_role(tmp_path, ROLE, "health", v2, env=env).returncode == 0
    finally:
        c.__exit__()


def seed_state(tmp: Path) -> dict[str, str]:
    data = tmp / "data"
    files = {
        "conf/flow.json.gz": "flow-v1", "conf/users.xml": "users-v1",
        "conf/authorizations.xml": "auth-v1", f"conf/{MID}.properties": "keystorePasswd=SECRET-PW",
        "state/local/checkpoint": "state-v1", "flowfile_repository/checkpoint": "ff-v1",
        "content_repository/1/archive/x": "content-v1", "database_repository/h2": "db-v1",
        "provenance_repository/p": "prov-v1",
    }  # fmt: skip
    for rel, text in files.items():
        (data / rel).parent.mkdir(parents=True, exist_ok=True)
        (data / rel).write_text(text)
    return files


def exported(tmp: Path, c: Controller, **kw):
    prepare(tmp, c)
    files = seed_state(tmp)
    env = hook_env(tmp)
    r = run_role(tmp, ROLE, "export", hook_vars(tmp, c, **kw), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return files, env


def test_export_archives_the_state_with_the_service_stopped_and_lists_every_file(tmp_path):
    c = converged_controller(tmp_path)
    try:
        exported(tmp_path, c)
        out = tmp_path / "export"
        archive = out / "state.tar.gz"
        with tarfile.open(archive) as t:
            members = t.getnames()
            body = {m: t.extractfile(m).read().decode() for m in members if t.getmember(m).isfile()}
        # the state, the repositories and the stored flow; the seeded configuration (it holds a
        # password) and the provenance (not asked for) are left out
        assert (
            body["conf/flow.json.gz"] == "flow-v1" and body["state/local/checkpoint"] == "state-v1"
        )
        assert f"conf/{MID}.properties" not in members and not any(
            m.startswith("provenance") for m in members
        )
        rows = [json.loads(x) for x in (out / "listing.jsonl").read_text().splitlines()]
        assert [r["key"] for r in rows] == [archive.name, "flows/hnx-smoke.json"]
        assert rows[0]["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
        assert oct(archive.stat().st_mode & 0o777) == "0o600"
        calls = docker_calls(tmp_path)
        stop = next(i for i, x in enumerate(calls) if " stop" in x)
        up = next(i for i, x in enumerate(calls) if " up -d" in x)
        assert stop < up  # started again after the archive
    finally:
        c.__exit__()


def test_a_second_export_keeps_the_previous_archive_as_prev(tmp_path):
    c = converged_controller(tmp_path)
    try:
        _, env = exported(tmp_path, c)
        out = tmp_path / "export"
        first = (out / "state.tar.gz").read_bytes()
        assert not (out / "state.tar.gz.prev").exists()
        r = run_role(tmp_path, ROLE, "export", hook_vars(tmp_path, c), env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert (out / "state.tar.gz.prev").read_bytes() == first
        assert (out / "state.tar.gz").is_file()
    finally:
        c.__exit__()


def test_export_includes_provenance_only_when_asked_and_refuses_a_service_with_no_flow(tmp_path):
    c = converged_controller(tmp_path)
    try:
        prepare(tmp_path, c)
        env = hook_env(tmp_path)
        r = run_role(tmp_path, ROLE, "export", hook_vars(tmp_path, c), env=env)
        assert r.returncode != 0 and "no stored flow" in r.stdout + r.stderr
        seed_state(tmp_path)
        r = run_role(
            tmp_path, ROLE, "export", hook_vars(tmp_path, c, export_provenance=True), env=env
        )
        assert r.returncode == 0, r.stdout
        archive = tmp_path / "export" / "state.tar.gz"
        with tarfile.open(archive) as t:
            assert any(m.startswith("provenance_repository") for m in t.getnames())
    finally:
        c.__exit__()


def test_a_failed_archive_still_starts_the_service_again(tmp_path):
    c = converged_controller(tmp_path)
    try:
        prepare(tmp_path, c)
        seed_state(tmp_path)
        bindir = tmp_path / "bin"
        env = hook_env(tmp_path)
        fake(bindir / "tar", "import sys\nsys.exit(2)\n")
        r = run_role(tmp_path, ROLE, "export", hook_vars(tmp_path, c), env=env)
        assert r.returncode != 0
        assert any(" up -d" in x for x in docker_calls(tmp_path))
    finally:
        c.__exit__()


def archive_of(tmp: Path, members: dict[str, str], *, listing_hash=None, links=None, extra=None):
    """A hand-built export directory: an archive of ``members`` and its listing."""
    out = tmp / "src"
    out.mkdir()
    arc = out / "state.tar.gz"
    with tarfile.open(arc, "w:gz") as t:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            import io

            t.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            t.addfile(info)
    digest = listing_hash or hashlib.sha256(arc.read_bytes()).hexdigest()
    row = {"key": "state.tar.gz", "size": arc.stat().st_size, "sha256": digest}
    (out / "listing.jsonl").write_text(json.dumps(row) + "\n")
    return out


GOOD = {"conf/flow.json.gz": "flow-restored", "conf/users.xml": "users-restored",
        "state/local/checkpoint": "state-restored"}  # fmt: skip


def restore_vars(tmp: Path, src: Path, **kw) -> dict:
    return {**vs(tmp, restore_source=str(src), start=True, **kw)}


def _first_restore_swaps_the_state_in_and_moves_what_it_replaces_aside(tmp_path):
    seed_state(tmp_path)
    src = archive_of(tmp_path, GOOD)
    env = {**secrets(), **fake_docker(tmp_path)}
    return {
        "role": ROLE,
        "tasks_from": "restore",
        "extra_vars": restore_vars(tmp_path, src),
        "env": env,
        "setup": {"env": env, "src": src},
    }


@first_run(_first_restore_swaps_the_state_in_and_moves_what_it_replaces_aside)
def test_restore_swaps_the_state_in_and_moves_what_it_replaces_aside(first):
    r, tmp_path = first
    env = first.setup["env"]
    src = first.setup["src"]
    assert r.returncode == 0, r.stdout + r.stderr
    data = tmp_path / "data"
    assert (data / "conf" / "flow.json.gz").read_text() == "flow-restored"
    assert (data / "state" / "local" / "checkpoint").read_text() == "state-restored"
    # never deleted: the replaced paths are under before-restore, untouched
    assert (data / "before-restore" / "conf" / "flow.json.gz").read_text() == "flow-v1"
    assert (data / "before-restore" / "state" / "local" / "checkpoint").read_text() == "state-v1"
    # what the archive does not hold stays (the seeded configuration, the repositories)
    assert (data / "conf" / f"{MID}.properties").read_text() == "keystorePasswd=SECRET-PW"
    assert (data / "flowfile_repository" / "checkpoint").read_text() == "ff-v1"
    assert not (data / "restoring").exists()
    calls = docker_calls(tmp_path)
    assert next(i for i, x in enumerate(calls) if " stop" in x) < next(
        i for i, x in enumerate(calls) if " up -d" in x
    )
    # a second restore will not go over the first's before-restore
    again = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, src), env=env)
    assert again.returncode != 0 and "before-restore" in again.stdout


def _first_restore_refuses_a_tampered_foreign_or_linked_archive_and_changes_nothing(
    tmp_path, build
):
    seed_state(tmp_path)
    src = build(tmp_path)
    env = {**secrets(), **fake_docker(tmp_path)}
    return {
        "role": ROLE,
        "tasks_from": "restore",
        "extra_vars": restore_vars(tmp_path, src),
        "env": env,
    }


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda t: archive_of(t, GOOD, listing_hash="0" * 64), id="hash-differs"),
        pytest.param(
            lambda t: archive_of(t, {**GOOD, "../escape": "x"}), id="leaves-the-directory"
        ),
        pytest.param(lambda t: archive_of(t, {**GOOD, "/abs/path": "x"}), id="absolute"),
        pytest.param(
            lambda t: archive_of(t, {**GOOD, f"conf/{MID}.properties": "x"}), id="a-config-file"
        ),
        pytest.param(lambda t: archive_of(t, {**GOOD, "elsewhere/x": "x"}), id="a-foreign-path"),
        pytest.param(lambda t: archive_of(t, {"state/local/checkpoint": "x"}), id="no-stored-flow"),
        pytest.param(
            lambda t: archive_of(t, GOOD, links={"state/link": "/etc/passwd"}), id="a-link"
        ),
    ],
)
@first_run(_first_restore_refuses_a_tampered_foreign_or_linked_archive_and_changes_nothing)
def test_restore_refuses_a_tampered_foreign_or_linked_archive_and_changes_nothing(first, build):
    r, tmp_path = first
    assert r.returncode != 0
    data = tmp_path / "data"
    assert (data / "conf" / "flow.json.gz").read_text() == "flow-v1"
    assert not (data / "before-restore").exists()
    assert not any(" stop" in x for x in docker_calls(tmp_path))  # never stopped for a bad archive


def test_restore_flows_imports_the_definitions_the_service_lacks_after_checking_each(tmp_path):
    c = converged_controller(tmp_path)
    try:
        prepare(tmp_path, c)
        seed_state(tmp_path)
        env = hook_env(tmp_path)
        assert run_role(tmp_path, ROLE, "export", hook_vars(tmp_path, c), env=env).returncode == 0
        src = tmp_path / "export"
        c.groups.clear()
        v = hook_vars(tmp_path, c, restore_source=str(src), restore_mode="flows")
        r = run_role(tmp_path, ROLE, "restore", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert [g["name"] for g in c.groups.values()] == ["hnx-smoke"]
        # a flow file that differs from its listing is refused, and nothing is imported
        (src / "flows" / "hnx-smoke.json").write_text(smoke_definition(1))
        c.groups.clear()
        r = run_role(tmp_path, ROLE, "restore", v, env=env)
        assert r.returncode != 0 and c.groups == {}
    finally:
        c.__exit__()


def _first_restore_needs_a_source_and_an_intact_listing(tmp_path):
    env = {**secrets(), **fake_docker(tmp_path)}
    return {
        "role": ROLE,
        "tasks_from": "restore",
        "extra_vars": vs(tmp_path, start=True),
        "env": env,
        "setup": {"env": env},
    }


@first_run(_first_restore_needs_a_source_and_an_intact_listing)
def test_restore_needs_a_source_and_an_intact_listing(first):
    first_result, tmp_path = first
    env = first.setup["env"]
    assert first_result.returncode != 0
    src = tmp_path / "src"
    src.mkdir()
    (src / "listing.jsonl").write_text("")
    r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, src), env=env)
    assert r.returncode != 0
    (src / "listing.jsonl").write_text(
        json.dumps({"key": "../../etc/passwd", "sha256": "0" * 64}) + "\n"
    )
    assert run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, src), env=env).returncode != 0


def _first_backup_names_the_data_root(tmp_path):
    return {"role": ROLE, "tasks_from": "backup", "extra_vars": vs(tmp_path), "env": secrets()}


@first_run(_first_backup_names_the_data_root)
def test_backup_names_the_data_root(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert str(tmp_path / "data") not in manifest["paths"]  # not the whole root: see below
    data = str(tmp_path / "data")
    for state in ROLE_VARS[f"{P}_state_files"] + ROLE_VARS[f"{P}_restore_dirs"]:
        assert f"{data}/{state}" in manifest["paths"]
    # the files that hold the sensitive-props key, the keystore passwords and the single-user hash
    # (and the keys) are rebuilt, so no manifest path is, or contains, one of them
    for path in manifest["paths"]:
        for seeded in ROLE_VARS[f"{P}_seed_files"] + [".hnx-seed"]:
            assert not path.endswith(seeded), path
        assert path != f"{data}/conf" and "/tls" not in path, path


# ----------------------------------------------------------------------------- readiness and the bus


def _listener():
    import socket

    s = socket.socket()
    s.bind((".".join(["127", "0", "0", "1"]), 0))
    s.listen(8)
    return s


def _ready_run(tmp_path, events_url, query_sock):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    host = ".".join(["127", "0", "0", "1"])
    srvs = [HTTPServer((host, 0), H) for _ in range(2)]
    for s in srvs:
        threading.Thread(
            target=s.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
    d = tmp_path / "fakes"
    d.mkdir(parents=True)
    fake(d / "docker", 'import sys\nsys.stdout.write(\'{"ServerVersion": "29.0.0"}\')\n')
    fake(d / "systemctl", "print('active')\n")
    v = vs(
        tmp_path, s3_url=f"http://{host}:{srvs[0].server_port}",
        catalog_url=f"http://{host}:{srvs[1].server_port}",
        query_url=f"tcp://{host}:{query_sock.getsockname()[1]}", events_url=events_url,
        health_timeout=2,
    )  # fmt: skip
    v["docker_engine_cli"], v["docker_engine_systemctl_cli"] = (
        str(d / "docker"), str(d / "systemctl"),
    )  # fmt: skip
    v["docker_engine_state_dir"] = str(tmp_path / "state")
    try:
        return run_role(tmp_path, ROLE, "readiness", v, env=secrets())
    finally:
        for s in srvs:
            s.shutdown()


def test_readiness_skips_the_bus_when_events_are_off(tmp_path):
    q = _listener()
    try:
        r = _ready_run(tmp_path, "", q)
    finally:
        q.close()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "events are off" in r.stdout


def test_readiness_still_waits_for_the_forwarder_when_events_are_on(tmp_path):
    host = ".".join(["127", "0", "0", "1"])
    q, up, down = _listener(), _listener(), _listener()
    down_url = f"http://{host}:{down.getsockname()[1]}"
    down.close()  # nothing listens there any more
    try:
        ok = _ready_run(tmp_path / "a", f"http://{host}:{up.getsockname()[1]}", q)
        bad = _ready_run(tmp_path / "b", down_url, q)
    finally:
        q.close()
        up.close()
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "events are off" not in ok.stdout
    assert bad.returncode != 0
