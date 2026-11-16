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
from rolerun import fake, run_role

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


# ----------------------------------------------------------------------------- main renders


def test_main_renders_the_service_with_no_secret_in_the_compose_file(tmp_path):
    r = run_role(tmp_path, ROLE, "main", vs(tmp_path), env=secrets())
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


def test_the_container_joins_the_role_slice_the_module_play_names(tmp_path):
    v = vs(tmp_path)
    v["hnx_module_slice"] = f"hnx-{MID}-server.slice"
    assert run_role(tmp_path, ROLE, "main", v, env=secrets()).returncode == 0
    assert compose(tmp_path)["cgroup_parent"] == f"hnx-{MID}-server.slice"


def test_extra_parameters_reach_the_flows_as_sensitive_values_only_in_the_env_file(tmp_path):
    extra = {"HNX_FEED_LOGIN": ref("feed-key")}
    env = {**secrets(), **env_of("feed-key", "feed-key-value-0123")}
    r = run_role(tmp_path, ROLE, "main", vs(tmp_path, extra_parameters=extra), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "feed-key-value-0123" not in (tmp_path / "app" / "docker-compose.yml").read_text()
    assert (
        "HNX_FEED_LOGIN='feed-key-value-0123'"
        in (tmp_path / "app" / "secrets" / f"{MID}.env").read_text()
    )


def test_oidc_renders_its_settings_and_reads_its_client_secret_from_the_store(tmp_path):
    over = {
        "auth": "oidc", "oidc_issuer_url": "https://idp.example.internal/realms/lab",
        "oidc_client_id": "dataflow", "initial_admin": "alice",
    }  # fmt: skip
    env = {**secrets(), **env_of("oidc-client-secret", "oidc-client-secret-0123456789"),
           **env_of("api-token", "api-token-0123456789abcdefgh")}  # fmt: skip
    r = run_role(tmp_path, ROLE, "main", vs(tmp_path, **over), env=env)
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


@pytest.mark.parametrize("over, bad", BAD)
def test_main_refuses_bad_inputs_and_credentials_before_rendering_anything(tmp_path, over, bad):
    r = run_role(tmp_path, ROLE, "main", vs(tmp_path, **over), env=secrets(**bad))
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


def test_oidc_refuses_a_missing_client_secret_and_a_missing_api_token(tmp_path):
    over = {
        "auth": "oidc", "oidc_issuer_url": "https://idp.example.internal/realms/lab",
        "oidc_client_id": "dataflow", "initial_admin": "alice",
    }  # fmt: skip
    env = {**secrets(), **env_of("oidc-client-secret", "oidc-client-secret-0123456789")}
    r = run_role(tmp_path, ROLE, "main", vs(tmp_path, **over), env=env)
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


def test_restore_swaps_the_state_in_and_moves_what_it_replaces_aside(tmp_path):
    seed_state(tmp_path)
    src = archive_of(tmp_path, GOOD)
    env = {**secrets(), **fake_docker(tmp_path)}
    r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, src), env=env)
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
def test_restore_refuses_a_tampered_foreign_or_linked_archive_and_changes_nothing(tmp_path, build):
    seed_state(tmp_path)
    src = build(tmp_path)
    env = {**secrets(), **fake_docker(tmp_path)}
    r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, src), env=env)
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


def test_restore_needs_a_source_and_an_intact_listing(tmp_path):
    env = {**secrets(), **fake_docker(tmp_path)}
    assert run_role(tmp_path, ROLE, "restore", vs(tmp_path, start=True), env=env).returncode != 0
    src = tmp_path / "src"
    src.mkdir()
    (src / "listing.jsonl").write_text("")
    r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, src), env=env)
    assert r.returncode != 0
    (src / "listing.jsonl").write_text(
        json.dumps({"key": "../../etc/passwd", "sha256": "0" * 64}) + "\n"
    )
    assert run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, src), env=env).returncode != 0


def test_backup_names_the_data_root(tmp_path):
    r = run_role(tmp_path, ROLE, "backup", vs(tmp_path), env=secrets())
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert str(tmp_path / "data") in manifest["paths"]
