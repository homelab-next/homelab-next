# SPDX-License-Identifier: Apache-2.0
"""Role ``keycloak`` (modules/keycloak/roles/keycloak), run on localhost against fakes (CI is
unprivileged): main renders the database and the IdP through compose_app with every secret only
in the env_files and a second run is ``changed=0``; malformed inputs, credentials and realms are
refused; with the containers "started" (a fake docker) main imports the realm into the HTTPS
stand-in and converges it; health passes there and fails on a reserved user, a one-time code or
a passkey that is no longer required; export writes an object-tree with a sha256 listing and
restore refuses a tampered one; upgrade records only a pinned target. The admin-API script's
own rules (flow drift refused, the reserved list converged, the CA enforced) are tested on it
directly."""

from __future__ import annotations

import grp
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from homelabnext.generators import generate
from homelabnext.registry import load
from tests.modules.keycloak_stand_in import FRONTEND, LOOPBACK, SERVER_NAME, StandIn, make_pki

pytestmark = pytest.mark.requires_tool("openssl")

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "keycloak" / "roles" / "keycloak")
SCRIPT = ROOT / "modules" / "keycloak" / "roles" / "keycloak" / "files" / "keycloak_api.py"
USER = pwd.getpwuid(os.getuid()).pw_name
#: the example registry's edge address (a documentation-range address, never connected to)
EDGE = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
ADMIN = ("hnx-admin", "admin-password-fake-0123456789")
DB_PASSWORD = "db-password-fake-0123456789abc"
REG = load(ROOT / "examples" / "services.yml")
REALM = REG.lab_name


def _realm_text(reserved=None) -> str:
    opts = {"reserved_usernames": reserved} if reserved else None
    return generate(REG, ["idp_realm"], opts)["idp_realm"]["idp/realm.json"]


CLIENTS = [c["clientId"] for c in json.loads(_realm_text())["clients"]]


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_pki(tmp_path_factory.mktemp("pki"))


def secrets_env(pki) -> dict:
    env = {
        "HNX_SECRET_KEYCLOAK_ADMIN_PASSWORD": ADMIN[1],
        "HNX_SECRET_KEYCLOAK_DB_PASSWORD": DB_PASSWORD,
        "HNX_SECRET_KEYCLOAK_TLS_CERT": Path(pki["cert"]).read_text(),
        "HNX_SECRET_KEYCLOAK_TLS_KEY": Path(pki["key"]).read_text(),
        "HNX_SECRET_KEYCLOAK_CA": Path(pki["ca"]).read_text(),
    }
    for c in CLIENTS:
        env["HNX_SECRET_IDP_CLIENTS_" + c.upper().replace("-", "_")] = (
            f"{c}-client-secret-" + "x" * 32
        )
    return env


def kc_vars(tmp_path: Path, **kw) -> dict:
    realm_file = tmp_path / "realm.json"
    if not realm_file.exists():
        realm_file.write_text(_realm_text())
    v = {
        "keycloak_logical_id": "idp",
        "ansible_host": EDGE,
        "keycloak_hostname": FRONTEND,
        "keycloak_realm": REALM,
        "keycloak_realm_file": str(realm_file),
        "keycloak_tls_server_name": SERVER_NAME,
        "keycloak_edge_addresses": [EDGE],
        "keycloak_dir": str(tmp_path / "app"),
        "keycloak_owner": USER,
        "keycloak_group": grp.getgrgid(os.getgid()).gr_name,
        "keycloak_data_root": str(tmp_path / "data"),
        "keycloak_db_uid": os.getuid(),
        "keycloak_db_gid": os.getgid(),
        "keycloak_uid": os.getuid() + 1,
        "keycloak_start": False,
        "keycloak_validate_with_docker": False,
    }
    v.update(kw)
    return v


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker: ``compose ps`` lists both services in ``health``; ``exec ... pg_dump -f F``
    writes a dump at F's host path (the export mount), ``mv`` moves it; everything else succeeds.
    Every call is logged."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = "".join(
        json.dumps({"Service": s, "State": "running", "Health": health}) + "\n"
        for s in ("postgres", "keycloak")
    )
    export = tmp_path / "data" / "export" / "db"
    body = f"""
import os, shutil, sys
a = sys.argv[1:]
open({str(tmp_path / "docker.log")!r}, "a").write(" ".join(a) + "\\n")
def host(p):
    return os.path.join({str(export)!r}, os.path.basename(p))
if "ps" in a:
    sys.stdout.write({rows!r})
elif "pg_dump" in a:
    open(host(a[len(a) - 1 - a[::-1].index("-f") + 1]), "wb").write(b"PGDMP fake dump")
elif "mv" in a:
    shutil.move(host(a[-2]), host(a[-1]))
"""
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _live(tmp_path, kc, **kw):
    return kc_vars(tmp_path, keycloak_bind=LOOPBACK, keycloak_port=kc.port, **kw)


# ----------------------------------------------------------------------------- render


def test_main_renders_both_containers_with_the_secrets_only_in_the_env_files(tmp_path, pki):
    v = kc_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env=secrets_env(pki))
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    db, kc = doc["services"]["postgres"], doc["services"]["keycloak"]
    assert db["image"].startswith("docker.io/library/postgres:17.")
    assert kc["image"].startswith("quay.io/keycloak/keycloak:26.")
    assert "ports" not in db  # the database is never published
    assert kc["ports"] == [f"{EDGE}:8443:8443"]
    assert kc["user"] == f"{os.getuid() + 1}:0"
    assert kc["command"] == ["start"]
    assert kc["volumes"] == [f"{tmp_path}/app/tls:/opt/keycloak/conf/hnx-tls:ro"]
    for svc in (db, kc):
        assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    env = kc["environment"]
    assert env["KC_HTTP_ENABLED"] == "false" and env["KC_HOSTNAME_STRICT"] == "true"
    assert env["KC_HOSTNAME"] == f"https://{FRONTEND}"
    assert env["KC_HOSTNAME_ADMIN"] == f"https://{SERVER_NAME}:8443"
    assert env["KC_PROXY_TRUSTED_ADDRESSES"] == EDGE
    assert env["KC_BOOTSTRAP_ADMIN_USERNAME"] == ADMIN[0]
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    assert ADMIN[1] not in text and DB_PASSWORD not in text
    kc_env = (tmp_path / "app" / "secrets" / "keycloak.env").read_text()
    assert f"KC_DB_PASSWORD='{DB_PASSWORD}'" in kc_env
    assert f"KC_BOOTSTRAP_ADMIN_PASSWORD='{ADMIN[1]}'" in kc_env
    assert (
        f"POSTGRES_PASSWORD='{DB_PASSWORD}'"
        in (tmp_path / "app" / "secrets" / "postgres.env").read_text()
    )
    key = tmp_path / "app" / "tls" / "server.key"
    assert oct(key.stat().st_mode & 0o777) == "0o640"
    assert key.read_text().strip() == Path(pki["key"]).read_text().strip()
    again = run_role(tmp_path, ROLE, "main", v, env=secrets_env(pki))
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _mutated(tmp_path: Path, mutate) -> str:
    doc = json.loads(_realm_text())
    mutate(doc)
    path = tmp_path / "bad-realm.json"
    path.write_text(json.dumps(doc))
    return str(path)


def _with_otp(d):
    forms = next(f for f in d["authenticationFlows"] if f["alias"].endswith("-forms"))
    forms["authenticationExecutions"][1]["authenticator"] = "auth-otp-form"


@pytest.mark.parametrize(
    "over,env",
    [
        ({"keycloak_image": "quay.io/keycloak/keycloak:26.8.1"}, {}),
        ({"keycloak_bind": "0.0.0.0"}, {}),
        ({"keycloak_edge_addresses": EDGE}, {}),
        ({"keycloak_realm": "master"}, {}),
        ({"keycloak_reserved_usernames": ["Operator One"]}, {}),
        # the realm file is another lab's, or offers a code, or lets a direct grant through
        ({"keycloak_realm": "otherlab"}, {}),
        ({"_realm": _with_otp}, {}),
        ({"_realm": lambda d: d["authenticationFlows"][-1]["authenticationExecutions"].clear()}, {}),
        ({"_realm": lambda d: d["clients"][0].update(secret="literal-secret")}, {}),
        # the realm's floor: a reserved name the rendered realm does not refuse
        ({"keycloak_reserved_usernames": ["operator-one", "ops-proof"]}, {}),
        ({}, {"HNX_SECRET_KEYCLOAK_DB_PASSWORD": "short"}),
        ({}, {"HNX_SECRET_KEYCLOAK_TLS_KEY": "not a key"}),
        ({}, {"HNX_SECRET_IDP_CLIENTS_AUTH_PROXY": "too-short"}),
    ],
)  # fmt: skip
def test_main_refuses_bad_inputs_realms_and_credentials(tmp_path, pki, over, env):
    over = dict(over)
    if "_realm" in over:
        over["keycloak_realm_file"] = _mutated(tmp_path, over.pop("_realm"))
    r = run_role(tmp_path, ROLE, "main", kc_vars(tmp_path, **over), env={**secrets_env(pki), **env})
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    for value in (ADMIN[1], DB_PASSWORD):
        assert value not in r.stdout


# ----------------------------------------------------------------------------- live (stand-in)


def test_main_imports_the_realm_then_converges_it_and_health_passes(tmp_path, pki):
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        env = {**secrets_env(pki), **_docker(tmp_path)}
        v = _live(tmp_path, kc, keycloak_start=True)
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert REALM in kc.realms and "realm northwind: created" in r.stdout
        realm = kc.realms[REALM]
        # the client secrets came from the secret store, never the rendered references
        assert realm.by_client_id("auth-proxy")["secret"].startswith("auth-proxy-client-secret-")
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0, again.stdout
        assert "realm northwind: unchanged" in again.stdout
        # an approver who registered a passkey is fine; the master realm is brute-force protected
        realm.users.append({"id": "u9", "username": "approver-a", "enabled": True,
                            "groups": [realm.groups[0]["id"]],
                            "credentials": [{"type": "password"}, {"type": "webauthn"}]})  # fmt: skip
        assert kc.master["bruteForceProtected"] is True
        health = run_role(tmp_path, ROLE, "health", v, env=env)
        assert health.returncode == 0, health.stdout + health.stderr
        log = (tmp_path / "docker.log").read_text()
        assert "exec -T postgres pg_isready" in log
        for value in (ADMIN[1], DB_PASSWORD, "auth-proxy-client-secret-"):
            assert value not in r.stdout + again.stdout + health.stdout


@pytest.mark.parametrize(
    "damage,reason",
    [
        (lambda r: r.users.append({"id": "u1", "username": "operator-one"}),
         "a user holds the reserved username 'operator-one'"),
        (lambda r: r.actions["CONFIGURE_TOTP"].update(enabled=True), "CONFIGURE_TOTP is enabled"),
        (lambda r: r.flows["hnx-browser-mfa-forms"]["authenticationExecutions"][1].update(
            requirement="ALTERNATIVE"), "WebAuthn is not REQUIRED"),
        (lambda r: r.settings.update(directGrantFlow="direct grant"), "directGrantFlow is"),
        (lambda r: r.profile["attributes"][0]["validations"].pop("pattern"),
         "reserved-username pattern"),
        (lambda r: r.mappings.clear(), "roles on status-hub differ"),
        (lambda r: r.brokers.append({"alias": "elsewhere"}), "an identity provider is configured"),
        (lambda r: r.clients[0].update(authenticationFlowBindingOverrides={"browser": "x"}),
         "overrides a flow binding"),
        (lambda r: r.profile["attributes"][0]["validations"].pop("up-username-not-idn-homograph"),
         "username validators differ"),
        (lambda r: r.users.append({"id": "u3", "username": "alice", "enabled": True,
                                   "groups": [r.groups[0]["id"]]}), "has no passkey registered"),
    ],
)  # fmt: skip
def test_health_fails_on_a_damaged_realm(tmp_path, pki, damage, reason):
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        env = {**secrets_env(pki), **_docker(tmp_path)}
        v = _live(tmp_path, kc, keycloak_start=True)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        damage(kc.realms[REALM])
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0 and reason in r.stdout, r.stdout


def test_health_names_an_approver_pending_first_login_and_still_fails_one_who_never_will(
    tmp_path, pki
):
    """An approver with no passkey whose ``webauthn-register`` action is still pending is the
    trust-on-first-use window, reported under its own name ("N approvers have no passkey yet
    (pending first login)") and not a failure; one with no passkey and no such action pending
    (nothing will ever ask them for one) still fails health."""
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        env = {**secrets_env(pki), **_docker(tmp_path)}
        v = _live(tmp_path, kc, keycloak_start=True)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        realm = kc.realms[REALM]
        group = realm.groups[0]["id"]
        realm.users.append({"id": "u4", "username": "carol", "enabled": True, "groups": [group],
                            "requiredActions": ["UPDATE_PASSWORD", "webauthn-register"]})  # fmt: skip
        r = run_role(tmp_path, ROLE, "health", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "1 approvers have no passkey yet" in r.stdout and "pending first login" in r.stdout
        assert "carol" in r.stdout
        realm.users.append({"id": "u5", "username": "dave", "enabled": True, "groups": [group],
                            "requiredActions": ["UPDATE_PASSWORD"]})  # fmt: skip
        r = run_role(tmp_path, ROLE, "health", v, env=env)
        assert r.returncode != 0, r.stdout
        assert "user 'dave'" in r.stdout and "no webauthn-register action pending" in r.stdout
        assert "carol" not in r.stdout  # the pending one is not among the problems
        realm.users[-1]["credentials"] = [{"type": "webauthn"}]  # dave registered: fine again
        assert run_role(tmp_path, ROLE, "health", v, env=env).returncode == 0


def test_health_fails_when_a_container_is_unhealthy(tmp_path, pki):
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        v = _live(tmp_path, kc, keycloak_start=True)
        env = {**secrets_env(pki), **_docker(tmp_path)}
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        r = run_role(tmp_path, ROLE, "health", v, env={**env, **_docker(tmp_path, "unhealthy")})
    assert r.returncode != 0 and "unhealthy" in r.stdout


def test_the_realm_refuses_to_create_a_reserved_user(tmp_path, pki):
    """The user profile the realm carries refuses the reserved names on the admin API (the
    stand-in applies its pattern as a whole-value match, as the IdP's validator does)."""
    import urllib.request

    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        v = _live(tmp_path, kc, keycloak_start=True)
        env = {**secrets_env(pki), **_docker(tmp_path)}
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        realm = kc.realms[REALM]
        assert not realm.username_ok("operator-one") and not realm.username_ok("Operator-One")
        assert realm.username_ok("alice")
        import ssl

        ctx = ssl.create_default_context(cafile=str(pki["ca"]))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        base = f"https://{LOOPBACK}:{kc.port}"
        form = f"grant_type=password&client_id=admin-cli&username={ADMIN[0]}&password={ADMIN[1]}"
        tok = json.loads(urllib.request.urlopen(urllib.request.Request(
            base + "/realms/master/protocol/openid-connect/token", data=form.encode()), context=ctx
        ).read())["access_token"]  # fmt: skip
        req = urllib.request.Request(
            f"{base}/admin/realms/{REALM}/users", method="POST",
            data=json.dumps({"username": "operator-one"}).encode(),
            headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
        )  # fmt: skip
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, context=ctx)
        assert exc.value.code == 400 and realm.users == []


# ----------------------------------------------------------------------------- the API script


def _script(mode: str, settings: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), mode], input=json.dumps(settings),
        capture_output=True, text=True, timeout=120,
    )  # fmt: skip


def _settings(kc, pki, **kw) -> dict:
    out = {
        "address": LOOPBACK, "port": kc.port, "server_name": SERVER_NAME,
        "cafile": str(pki["ca"]), "realm": REALM, "admin_user": ADMIN[0],
        "admin_password": ADMIN[1], "issuer": f"https://{FRONTEND}/realms/{REALM}",
        "doc": json.loads(_realm_text()), "reserved": ["operator-one"],
        "client_secrets": {c: f"{c}-client-secret-" + "x" * 32 for c in CLIENTS},
    }  # fmt: skip
    out.update(kw)
    return out


def test_sync_converges_a_new_reserved_name_on_an_existing_realm(tmp_path, pki):
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        assert _script("sync", _settings(kc, pki)).returncode == 0
        realm = kc.realms[REALM]
        assert realm.username_ok("ops-proof")
        doc = json.loads(_realm_text(["ops-proof"]))
        r = _script("sync", _settings(kc, pki, doc=doc))
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["created"] is False and "user profile" in out["changed"]
        assert not realm.username_ok("ops-proof")
        assert realm.settings["attributes"]["hnx.reserved_usernames"] == "operator-one,ops-proof"
        # a client secret rotated in the store reaches the realm
        secrets = {c: f"{c}-rotated-secret-" + "y" * 32 for c in CLIENTS}
        r = _script("sync", _settings(kc, pki, doc=doc, client_secrets=secrets))
        assert "client auth-proxy secret" in json.loads(r.stdout)["changed"]
        assert realm.by_client_id("auth-proxy")["secret"] == secrets["auth-proxy"]


def test_sync_reports_changed_only_when_the_live_realm_differs(tmp_path, pki):
    """The first real deploy read every client's settings and mappers as changed on every run:
    the IdP stores them normalised (string attributes, attributes and mapper defaults of its own,
    sets in its own order), and a byte comparison with the rendered document never settles. A
    second sync against such an IdP changes nothing; a rendered value that really differs is
    still found, put right once, and then settles too."""
    with StandIn(tmp_path, ADMIN, pki=pki, normalise=True) as kc:
        first = _script("sync", _settings(kc, pki))
        assert first.returncode == 0, first.stderr
        assert json.loads(first.stdout)["created"] is True
        again = _script("sync", _settings(kc, pki))
        assert again.returncode == 0, again.stderr
        assert json.loads(again.stdout) == {"created": False, "changed": []}, again.stdout
        realm = kc.realms[REALM]
        client = realm.by_client_id("auth-proxy")
        client["redirectUris"].append("https://stray.lab.example/oauth2/callback")  # real drift
        client["protocolMappers"][0]["config"]["included.client.audience"] = "someone-else"
        r = json.loads(_script("sync", _settings(kc, pki)).stdout)
        assert r["changed"] == ["client auth-proxy settings", "client auth-proxy mapper audience"]
        assert "https://stray.lab.example/oauth2/callback" not in client["redirectUris"]
        assert json.loads(_script("sync", _settings(kc, pki)).stdout)["changed"] == []


def test_sync_refuses_a_drifted_flow_and_never_edits_it(tmp_path, pki):
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        assert _script("sync", _settings(kc, pki)).returncode == 0
        forms = kc.realms[REALM].flows["hnx-browser-mfa-forms"]
        forms["authenticationExecutions"][1]["authenticator"] = "auth-otp-form"
        before = json.dumps(forms, sort_keys=True)
        r = _script("sync", _settings(kc, pki))
        assert r.returncode == 1 and "flow hnx-browser-mfa differs" in r.stderr
        assert json.dumps(forms, sort_keys=True) == before
        assert ADMIN[1] not in r.stderr + r.stdout


def test_sync_refuses_a_missing_client_secret_and_a_literal_one(tmp_path, pki):
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        r = _script("sync", _settings(kc, pki, client_secrets={}))
        assert r.returncode == 1 and "idp/clients area" in r.stderr
        doc = json.loads(_realm_text())
        doc["clients"][0]["secret"] = "a-literal-value"
        r = _script("sync", _settings(kc, pki, doc=doc))
        assert r.returncode == 1 and "not a reference" in r.stderr
        assert kc.realms == {}


def test_the_script_verifies_the_server_by_name_against_the_ca(tmp_path, pki):
    (tmp_path / "o").mkdir()
    other = make_pki(tmp_path / "o")
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        r = _script("sync", _settings(kc, pki, cafile=str(other["ca"])))
        assert r.returncode == 1 and "SSL" in r.stderr
        r = _script("sync", _settings(kc, pki, server_name="elsewhere.example.internal"))
        assert r.returncode == 1 and "SSL" in r.stderr
        # the admin password never left: the stand-in saw no request at all
        assert kc.requests == [] and kc.realms == {}


# ----------------------------------------------------------------------------- export, restore


def test_export_writes_an_object_tree_and_restore_checks_it(tmp_path, pki):
    with StandIn(tmp_path, ADMIN, pki=pki) as kc:
        env = {**secrets_env(pki), **_docker(tmp_path)}
        v = _live(tmp_path, kc, keycloak_start=True)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        r = run_role(tmp_path, ROLE, "export", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        export = tmp_path / "data" / "export"
        rows = [json.loads(x) for x in (export / "listing.jsonl").read_text().splitlines()]
        assert [x["key"] for x in rows] == ["db/keycloak.dump", "realm.json"]
        realm = json.loads((export / "realm.json").read_text())
        assert realm["realm"] == REALM
        assert all(c["secret"] == "**********" for c in realm["clients"])
        assert oct((export / "realm.json").stat().st_mode & 0o777) == "0o600"
        ok = run_role(tmp_path, ROLE, "restore", {**v, "keycloak_restore_source": str(export)},
                      env=env)  # fmt: skip
        assert ok.returncode == 0, ok.stdout
        log = (tmp_path / "docker.log").read_text()
        assert "stop keycloak" in log and "pg_restore" in log and "up -d keycloak" in log
        assert "--single-transaction" in log
        assert not (export / "db" / ".restore.dump").exists()
        # a tampered dump is refused before anything stops
        (tmp_path / "docker.log").write_text("")
        (export / "db" / "keycloak.dump").write_bytes(b"PGDMP tampered")
        bad = run_role(tmp_path, ROLE, "restore", {**v, "keycloak_restore_source": str(export)},
                       env=env)  # fmt: skip
        assert bad.returncode != 0 and "not the listed size" in bad.stdout + bad.stderr
        assert "stop keycloak" not in (tmp_path / "docker.log").read_text()


def test_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(tmp_path, pki):
    v = kc_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=secrets_env(pki)).returncode == 0
    for bad in ({"keycloak_target_image": "quay.io/keycloak/keycloak:27.0.0"},
                {"keycloak_target_image": "quay.io/someone/keycloak:27.0.0@sha256:" + "a" * 64},
                {"keycloak_target_postgres_image": "docker.io/library/postgres:18.1@sha256:" + "a" * 64},
                {}):  # fmt: skip
        assert run_role(tmp_path, ROLE, "upgrade", {**v, **bad}).returncode != 0, bad
    target = "quay.io/keycloak/keycloak:26.9.0@sha256:" + "a" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "keycloak_target_image": target})
    assert ok.returncode == 0, ok.stdout
    minor = "docker.io/library/postgres:17.11@sha256:" + "b" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "keycloak_target_postgres_image": minor})
    assert ok.returncode == 0, ok.stdout
