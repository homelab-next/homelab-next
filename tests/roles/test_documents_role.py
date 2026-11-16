# SPDX-License-Identifier: Apache-2.0
"""Role ``documents`` (modules/documents/roles/documents), run on localhost against fakes (CI is
unprivileged): main renders the application and its broker through compose_app with the signing key
and the admin password only in the env_file and a second run is ``changed=0``; a reference with no
value in the secret store, or a malformed input or credential, is refused by name before anything is
written; with the containers "started" (a fake docker) the API token is seeded into the product's
token table through the environment of one command, never an argument; health passes against a
stand-in and fails when the library is open to anonymous readers, holds fewer documents than expected,
or reports a database or broker problem; export runs the product's exporter and writes an archive with
a sha256 listing; restore refuses a tampered or unsafe archive and a library that holds anything, and on
an intact one imports, verifies and seeds the token; upgrade refuses an unpinned, foreign or older target."""

from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pwd
import socket
import tarfile
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from tests.modules.documents_front import TOKEN, Server

LOOPBACK = socket.gethostbyname("localhost")  # the stand-in listens here; resolved, never a literal

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "documents" / "roles" / "documents")
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULTS = yaml.safe_load(
    (ROOT / "modules" / "documents" / "roles" / "documents" / "defaults" / "main.yml").read_text()
)
DEFAULT_IMAGE = DEFAULTS["documents_image"]
REPO = DEFAULT_IMAGE.split("@")[0].rsplit(":", 1)[0]
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
SIGNING = "s" * 60  # built from a short piece: a stand-in value, never a real key
ADMIN = "Admin-fake-" + "x" * 8
SECRETS = {
    "HNX_SECRET_DOCUMENTS_SECRET_KEY": SIGNING,
    "HNX_SECRET_DOCUMENTS_ADMIN_PASSWORD": ADMIN,
    "HNX_SECRET_DOCUMENTS_API_TOKEN": TOKEN,
}


def dv(tmp_path: Path, **kw) -> dict:
    v = {
        "documents_logical_id": "docs-library",
        "ansible_host": GUEST,
        "documents_dir": str(tmp_path / "app"),
        "documents_owner": USER,
        "documents_group": grp.getgrgid(os.getgid()).gr_name,
        "documents_data_root": str(tmp_path / "data"),
        # the unprivileged test's own ids (the role requires 1000 or more): it can chown to no other
        "documents_app_uid": os.getuid(),
        "documents_app_gid": os.getgid(),
        "documents_broker_uid": os.getuid(),
        "documents_broker_gid": os.getgid(),
        "documents_start": False,
        "documents_validate_with_docker": False,
    }
    v.update(kw)
    return v


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())


# ----------------------------------------------------------------------------- render


def test_main_renders_the_application_and_its_broker_with_the_secrets_only_in_the_env_file(
    tmp_path,
):
    v = dv(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = compose(tmp_path)
    assert sorted(doc["services"]) == ["app", "broker"]
    app, broker = doc["services"]["app"], doc["services"]["broker"]
    assert (
        app["image"] == DEFAULT_IMAGE
        and "@sha256:" in app["image"]
        and "@sha256:" in broker["image"]
    )
    assert app["user"] == f"{os.getuid()}:{os.getgid()}" and app["cap_drop"] == ["ALL"]
    assert app["security_opt"] == ["no-new-privileges:true"] and "privileged" not in app
    assert (
        app["ports"] == [GUEST + ":8000:8000"] and "ports" not in broker
    )  # the broker is never published
    root = str(tmp_path / "data")
    assert set(app["volumes"]) == {
        f"{root}/data:/usr/src/paperless/data",
        f"{root}/media:/usr/src/paperless/media",
        f"{root}/consume:/usr/src/paperless/consume",
        f"{root}/export:/usr/src/paperless/export",
    }
    env = app["environment"]
    assert env["PAPERLESS_REDIS"] == "redis://broker" and env["PAPERLESS_OCR_LANGUAGE"] == "eng"
    assert (
        "PAPERLESS_DBENGINE" not in env and "PAPERLESS_URL" not in env
    )  # SQLite; no route, no name
    assert env["PAPERLESS_ADMIN_USER"] == "admin"
    # no secret in the compose file or the environment; the key and the admin password in the env_file
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    assert SIGNING not in text and ADMIN not in text and TOKEN not in text
    envfile = tmp_path / "app" / "secrets" / "app.env"
    assert oct(envfile.stat().st_mode & 0o777) == "0o600"
    body = envfile.read_text()
    assert (
        f"PAPERLESS_SECRET_KEY='{SIGNING}'" in body
        and f"PAPERLESS_ADMIN_PASSWORD='{ADMIN}'" in body
    )
    # the API token is not in any file the role writes under the project
    assert not [p for p in (tmp_path / "app").rglob("*") if p.is_file() and TOKEN in p.read_text()]
    assert oct((tmp_path / "data" / "data").stat().st_mode & 0o777) == "0o700"
    assert oct((tmp_path / "data" / "consume").stat().st_mode & 0o777) == "0o770"
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_a_library_to_be_imported_creates_no_administrator(tmp_path):
    v = dv(tmp_path, documents_admin_bootstrap=False)
    env = {
        k: val for k, val in SECRETS.items() if "ADMIN" not in k
    }  # the admin password is not needed
    r = run_role(tmp_path, ROLE, "main", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    app = compose(tmp_path)["services"]["app"]
    assert "PAPERLESS_ADMIN_USER" not in app["environment"]
    assert "PAPERLESS_ADMIN_PASSWORD" not in (tmp_path / "app" / "secrets" / "app.env").read_text()


def test_ocr_languages_are_data_and_the_url_and_extra_settings_reach_the_environment(tmp_path):
    v = dv(
        tmp_path,
        documents_ocr_languages=["eng", "deu"],
        documents_url="https://docs.example.internal",
        documents_timezone="Europe/Berlin",
        documents_consumer_recursive=True,
        documents_extra_env={
            "PAPERLESS_FILENAME_FORMAT": "{{ '{{' }}created_year{{ '}}' }}/x"[:0] + "year/title"
        },
    )
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    env = compose(tmp_path)["services"]["app"]["environment"]
    assert env["PAPERLESS_OCR_LANGUAGE"] == "eng+deu"
    assert env["PAPERLESS_URL"] == "https://docs.example.internal"
    assert env["PAPERLESS_TIME_ZONE"] == "Europe/Berlin"
    assert (
        env["PAPERLESS_CONSUMER_RECURSIVE"] == "true"
        and env["PAPERLESS_CONSUMER_SUBDIRS_AS_TAGS"] == "false"
    )
    assert env["PAPERLESS_FILENAME_FORMAT"] == "year/title"


def test_the_containers_join_the_role_slice_the_module_play_names(tmp_path):
    v = dv(tmp_path, hnx_module_slice="hnx-documents-server.slice")
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    for svc in compose(tmp_path)["services"].values():
        assert svc["cgroup_parent"] == "hnx-documents-server.slice"


@pytest.mark.parametrize(
    "over",
    [
        {"documents_image": REPO + ":latest"},
        {"documents_image": REPO + ":3.4@sha256:" + "a" * 64},  # a tag that is not a version
        {"documents_image": DEFAULT_IMAGE.split("@")[0]},  # a tag without a digest
        {"documents_broker_image": "docker.io/library/redis:8"},
        {"ansible_host": "docs.example.internal"},
        {"documents_app_uid": 0},
        {"documents_data_root": "/srv/docs"},  # a shallow data root
        {"documents_data_root": "relative/data"},
        {"documents_ocr_languages": ["eng", "jpn"]},  # not a language the image ships
        {"documents_ocr_languages": []},
        {"documents_ocr_languages": "eng"},
        {"documents_url": "javascript:alert(1)"},
        {"documents_api_user": "bad user"},
        {"documents_extra_env": {"PAPERLESS_REDIS": "redis://elsewhere"}},  # the role's own
        {"documents_extra_env": {"PAPERLESS_DBPASS": "x"}},  # looks like a secret
        {"documents_extra_env": {"OTHER": "x"}},
        {"documents_extra_env": {"PAPERLESS_X": "a'b"}},
        {"documents_expected_min_documents": -1},
        {"documents_admin_login_ref": "secret:documents/secret-key"},  # three distinct references
        {"documents_signing_ref": "not-a-reference"},
        {"documents_mem_limit": "lots"},
    ],
)
def test_main_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path, **over), env=SECRETS)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- credentials


@pytest.mark.parametrize(
    "missing, ref",
    [
        ("HNX_SECRET_DOCUMENTS_SECRET_KEY", "secret:documents/secret-key"),
        ("HNX_SECRET_DOCUMENTS_ADMIN_PASSWORD", "secret:documents/admin-password"),
        ("HNX_SECRET_DOCUMENTS_API_TOKEN", "secret:documents/api-token"),
    ],
)
def test_a_reference_with_no_value_is_named_and_nothing_is_written(tmp_path, missing, ref):
    env = {k: v for k, v in SECRETS.items() if k != missing}
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env=env)
    assert r.returncode != 0 and ref in r.stdout + r.stderr, r.stdout
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()


@pytest.mark.parametrize(
    "name, value",
    [
        ("HNX_SECRET_DOCUMENTS_SECRET_KEY", "short"),
        ("HNX_SECRET_DOCUMENTS_SECRET_KEY", "k" * 60 + "'"),  # a quote would end the env_file value
        ("HNX_SECRET_DOCUMENTS_API_TOKEN", "A" * 40),  # not lowercase hex
        ("HNX_SECRET_DOCUMENTS_API_TOKEN", "a" * 39),
        ("HNX_SECRET_DOCUMENTS_ADMIN_PASSWORD", "short"),
        ("HNX_SECRET_DOCUMENTS_ADMIN_PASSWORD", SIGNING),  # equal to the signing key
    ],
)
def test_a_malformed_or_repeated_credential_is_refused(tmp_path, name, value):
    env = {**SECRETS, name: value}
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env=env)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert value not in r.stdout + r.stderr or len(value) < 8  # a value is never printed


def test_the_credential_check_names_a_missing_reference_and_passes_with_all(tmp_path):
    """The readiness hook runs this file after the container engine's own check."""
    env = {k: v for k, v in SECRETS.items() if k != "HNX_SECRET_DOCUMENTS_API_TOKEN"}
    bad = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env=env)
    assert bad.returncode != 0 and "secret:documents/api-token" in bad.stdout + bad.stderr
    ok = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr


# ----------------------------------------------------------------------------- start, token


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker.  ``compose ps`` lists the two services in ``health``.  ``exec`` answers by what
    it is asked: the state read (the contents of ``state`` or an empty library), the token seeding
    (the contents of ``token``, default ``created``; it logs only whether the token reached its
    environment), the verification (the contents of ``verify`` or ok), the exporter (writes a tree
    into export/.library), the importer (logs the staging directory).  Every call is logged."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = "".join(
        json.dumps({"Service": s, "State": "running", "Health": health}) + "\n"
        for s in ("broker", "app")
    )
    export = tmp_path / "data" / "export"
    body = f"""
import os, sys
a = sys.argv[1:]
open({str(tmp_path / "docker.log")!r}, "a").write(" ".join(a).replace(chr(10), " ") + "\\n")
def read(name, default):
    p = {str(tmp_path)!r} + "/" + name
    return open(p).read() if os.path.exists(p) else default
if "ps" in a:
    sys.stdout.write({rows!r})
elif "exec" in a:
    code = a[-1]
    if "HNX-TOKEN" in code:
        open({str(tmp_path / "token-env.log")!r}, "a").write(
            ("token-in-env" if os.environ.get("HNX_API_TOKEN") == {TOKEN!r} else "no-token") + " "
            + os.environ.get("HNX_API_USER", "") + "\\n")
        sys.stdout.write("noise\\nHNX-TOKEN " + read("token", "created").strip() + "\\n")
    elif "HNX-STATE" in code:
        sys.stdout.write("HNX-STATE " + read("state", "0 0").strip() + "\\n")
    elif "HNX-VERIFY" in code:
        sys.stdout.write(read("verify", 'HNX-VERIFY {{"ok": true}}\\n'))
        sys.exit(1 if os.path.exists({str(tmp_path / "verify.fails")!r}) else 0)
    elif "document_exporter" in a:
        d = {str(export)!r} + "/.library"
        os.makedirs(d, exist_ok=True)
        open(d + "/manifest.json", "w").write("[]")
        open(d + "/0000001.pdf", "w").write("pdf")
    elif "document_importer" in a:
        if os.path.exists({str(tmp_path / "importer.fails")!r}):
            sys.exit(1)
sys.exit(0)
"""
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def _live(tmp_path, front, **kw):
    return dv(tmp_path, documents_bind=LOOPBACK, documents_port=front.addr[1], documents_start=True,
              documents_ready_timeout=10, **kw)  # fmt: skip


def test_main_starts_waits_for_the_sign_in_page_and_seeds_the_token_through_the_environment(
    tmp_path,
):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "/accounts/login/" in front.paths
    calls = _calls(tmp_path)
    assert any("--remove-orphans" in c for c in calls)  # compose_app started it
    seeding = [c for c in calls if "HNX-TOKEN" in c]
    assert len(seeding) == 1 and "-e HNX_API_USER -e HNX_API_TOKEN" in seeding[0]
    assert TOKEN not in "\n".join(calls)  # never an argument
    assert (tmp_path / "token-env.log").read_text().split() == ["token-in-env", "admin"]


def test_an_unchanged_token_is_not_a_change_and_a_missing_account_is_said_not_failed(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        (tmp_path / "token").write_text("unchanged")
        v = _live(tmp_path, front)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
        (tmp_path / "token").write_text("no-user")
        gone = run_role(
            tmp_path, ROLE, "main", _live(tmp_path, front, documents_admin_bootstrap=False), env=env
        )
        assert gone.returncode == 0, gone.stdout + gone.stderr
        assert "no account named admin yet" in gone.stdout


def test_a_command_that_does_not_report_the_token_state_fails_the_run(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        (tmp_path / "token").write_text("")  # prints "HNX-TOKEN " with nothing: still a report
        ok = run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env)
        assert ok.returncode == 0
        bindir = tmp_path / "bin"
        fake(
            bindir / "docker", "import sys\nsys.exit(0)\n"
        )  # prints nothing: the seeding said nothing
        bad = run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env)
        assert bad.returncode != 0


# ----------------------------------------------------------------------------- health


def _health(tmp_path, front, **kw):
    v = _live(tmp_path, front, **kw)
    return run_role(tmp_path, ROLE, "health", v, env={**SECRETS, **_docker(tmp_path)})


def test_health_passes_and_only_reads(tmp_path):
    with Server(count=3) as front:
        r = _health(tmp_path, front, documents_expected_min_documents=3)
        paths = list(front.paths)
        tokens = list(front.tokens)
    assert r.returncode == 0, r.stdout + r.stderr
    assert paths == [
        "/accounts/login/",
        "/api/documents/?page_size=1",
        "/api/documents/?page_size=1",
        "/api/status/",
    ]
    assert tokens == [TOKEN, TOKEN]  # only the two authenticated reads carry it


def test_health_fails_when_the_library_is_open_to_anonymous_readers(tmp_path):
    with Server(anonymous=200) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "An anonymous read of the library is refused" in r.stdout


def test_health_fails_when_the_library_holds_fewer_documents_than_expected(tmp_path):
    with Server(count=2) as front:
        r = _health(tmp_path, front, documents_expected_min_documents=1465)
    assert r.returncode != 0 and "at least 1465" in r.stdout


def test_health_fails_on_a_token_the_application_does_not_know(tmp_path):
    with Server() as front:
        v = _live(tmp_path, front)
        env = {**SECRETS, "HNX_SECRET_DOCUMENTS_API_TOKEN": "f" * 40, **_docker(tmp_path)}
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0 and "401" in r.stdout


@pytest.mark.parametrize(
    "front_kw", [{"database": "ERROR"}, {"redis": "ERROR"}, {"pending": ["0001_x"]}]
)
def test_health_fails_on_a_database_broker_or_migration_problem(tmp_path, front_kw):
    with Server(**front_kw) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "/api/status/ reports" in r.stdout


def test_health_fails_when_the_sign_in_page_does_not_answer(tmp_path):
    with Server(login=500) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "The sign-in page answers" in r.stdout


def test_health_fails_when_a_container_is_unhealthy(tmp_path):
    with Server() as front:
        v = _live(tmp_path, front)
        r = run_role(tmp_path, ROLE, "health", v, env={**SECRETS, **_docker(tmp_path, "unhealthy")})
    assert r.returncode != 0 and "unhealthy" in r.stdout + r.stderr


# ----------------------------------------------------------------------------- export, restore


def _export(tmp_path, env, v):
    r = run_role(tmp_path, ROLE, "export", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path / "data" / "export"


def test_export_runs_the_products_exporter_and_writes_an_archive_with_a_listing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    exp = _export(tmp_path, env, dv(tmp_path))
    exporter = [c for c in _calls(tmp_path) if "document_exporter" in c]
    assert len(exporter) == 1 and "/usr/src/paperless/export/.library" in exporter[0]
    assert "--delete" in exporter[0] and "--no-progress-bar" in exporter[0]
    tar = exp / "library.tar"
    assert oct(tar.stat().st_mode & 0o777) == "0o600"
    with tarfile.open(tar) as t:
        assert {m.name.removeprefix("./") for m in t} >= {"manifest.json", "0000001.pdf"}
    listing = [json.loads(line) for line in (exp / "listing.jsonl").read_text().splitlines()]
    assert listing == [
        {
            "key": "library.tar",
            "size": tar.stat().st_size,
            "sha256": hashlib.sha256(tar.read_bytes()).hexdigest(),
        }
    ]
    again = run_role(tmp_path, ROLE, "export", dv(tmp_path), env=env)
    assert again.returncode == 0  # a snapshot: every run writes a new one


def _archive(tmp_path: Path, members: dict | None = None, extra=None) -> Path:
    """A source directory holding library.tar and its listing."""
    src = tmp_path / "source"
    src.mkdir()
    members = members if members is not None else {"manifest.json": b"[]", "0000001.pdf": b"pdf"}
    with tarfile.open(src / "library.tar", "w") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        for ti in extra or []:
            t.addfile(ti)
    data = (src / "library.tar").read_bytes()
    (src / "listing.jsonl").write_text(
        json.dumps(
            {"key": "library.tar", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
        + "\n"
    )
    return src


def _restore(tmp_path, src, **kw):
    v = dv(tmp_path, documents_restore_source=str(src), **kw)
    return run_role(tmp_path, ROLE, "restore", v, env={**SECRETS, **_docker(tmp_path)})


def test_restore_imports_into_an_empty_library_verifies_and_seeds_the_token(tmp_path):
    src = _archive(tmp_path)
    r = _restore(tmp_path, src)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = _calls(tmp_path)
    order = [
        next(i for i, c in enumerate(calls) if k in c)
        for k in ("HNX-STATE", "document_importer", "HNX-VERIFY", "HNX-TOKEN")
    ]
    assert order == sorted(order)  # empty-check, import, verify, token
    assert "/usr/src/paperless/export/.restoring" in next(
        c for c in calls if "document_importer" in c
    )
    assert not (tmp_path / "data" / "export" / ".restoring").exists()  # removed after it verified
    assert TOKEN not in "\n".join(calls)


@pytest.mark.parametrize("state", ["3 0", "0 1", "1465 2"])
def test_restore_refuses_a_library_that_holds_a_document_or_an_account(tmp_path, state):
    src = _archive(tmp_path)
    (tmp_path / "state").write_text(state)
    r = _restore(tmp_path, src)
    assert r.returncode != 0 and "the library is not empty" in r.stdout + r.stderr
    assert not [c for c in _calls(tmp_path) if "document_importer" in c]
    assert not (tmp_path / "data" / "export" / ".restoring").exists()


def test_restore_refuses_a_tampered_archive_and_writes_nothing(tmp_path):
    src = _archive(tmp_path)
    with (src / "library.tar").open("ab") as f:
        f.write(b"\0" * 512)
    r = _restore(tmp_path, src)
    assert r.returncode != 0 and "not an intact export" in r.stdout + r.stderr
    assert not [c for c in _calls(tmp_path) if "document_importer" in c or "HNX-STATE" in c]
    assert not (tmp_path / "data" / "export" / ".restoring").exists()


@pytest.mark.parametrize(
    "kind",
    [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE],
)
def test_restore_refuses_link_and_special_members_before_touching_anything(tmp_path, kind):
    ti = tarfile.TarInfo("evil")
    ti.type, ti.linkname = kind, "/etc/passwd"
    src = _archive(tmp_path, extra=[ti])
    r = _restore(tmp_path, src)
    assert r.returncode != 0 and "link or special file" in r.stdout + r.stderr
    assert not [c for c in _calls(tmp_path) if "document_importer" in c]


def test_restore_refuses_a_member_that_leaves_the_directory_and_an_archive_without_a_manifest(
    tmp_path,
):
    r = _restore(tmp_path, _archive(tmp_path, {"manifest.json": b"[]", "../escape": b"x"}))
    assert r.returncode != 0 and "leaves its directory" in r.stdout + r.stderr
    (tmp_path / "source" / "library.tar").unlink()
    (tmp_path / "source" / "listing.jsonl").unlink()
    (tmp_path / "source").rmdir()
    r = _restore(tmp_path, _archive(tmp_path, {"0000001.pdf": b"pdf"}))
    assert r.returncode != 0 and "no manifest.json" in r.stdout + r.stderr


def test_restore_that_fails_verification_leaves_the_staging_directory_and_does_not_seed(tmp_path):
    src = _archive(tmp_path)
    (tmp_path / "verify").write_text('HNX-VERIFY {"ok": false, "bad": [4]}\n')
    (tmp_path / "verify.fails").write_text("")
    r = _restore(tmp_path, src)
    assert r.returncode != 0 and "LEFT for inspection" in r.stdout + r.stderr
    assert (tmp_path / "data" / "export" / ".restoring").is_dir()
    assert not [c for c in _calls(tmp_path) if "HNX-TOKEN" in c]
    # a second restore refuses to extract over what the first one left
    again = _restore(tmp_path, src)
    assert again.returncode != 0 and "left from an earlier restore" in again.stdout + again.stderr


def test_a_verification_that_does_not_say_ok_fails_even_if_the_command_succeeds(tmp_path):
    src = _archive(tmp_path)
    (tmp_path / "verify").write_text('HNX-VERIFY {"ok": false}\n')  # exit 0, but not ok
    r = _restore(tmp_path, src)
    assert r.returncode != 0


# ----------------------------------------------------------------------------- backup, upgrade


def test_backup_names_the_data_root(tmp_path):
    r = run_role(tmp_path, ROLE, "backup", dv(tmp_path), env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    m = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert m == {"app": "documents", "paths": [str(tmp_path / "data")]}


def test_upgrade_records_a_newer_pinned_target_and_refuses_the_rest(tmp_path):
    v = dv(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    newer = REPO + ":3.5.0@sha256:" + "b" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "documents_target_image": newer}, env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    for bad in (
        REPO + ":3.4.1@sha256:" + "c" * 64,  # older: the database cannot go back
        REPO + ":3.3.9@sha256:" + "c" * 64,
        REPO + ":latest@sha256:" + "c" * 64,
        REPO + ":3.5.0",  # no digest
        "docker.io/library/redis:7.2.16@sha256:" + "c" * 64,  # another repository
    ):
        r = run_role(tmp_path, ROLE, "upgrade", {**v, "documents_target_image": bad}, env=SECRETS)
        assert r.returncode != 0, bad
