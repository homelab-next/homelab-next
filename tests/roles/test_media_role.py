# SPDX-License-Identifier: Apache-2.0
"""Role ``media`` (modules/media/roles/media), run on localhost against fakes (CI is unprivileged):
main renders the server through compose_app (library read-only, cache outside the data root, no
secrets, Quick Connect seeded without overwriting) and a second run is ``changed=0``; malformed
inputs and a missing library are refused; health passes against a stand-in and fails on a server
that is not Healthy, has another server id or has Quick Connect off; export archives the config
with the server stopped and restore refuses a tampered archive; upgrade refuses an unpinned target."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import tarfile
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from tests.modules.media_front import SERVER_ID, Server

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "media" / "roles" / "media")
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULT_IMAGE = yaml.safe_load(
    (ROOT / "modules" / "media" / "roles" / "media" / "defaults" / "main.yml").read_text()
)["media_image"]
REPO = DEFAULT_IMAGE.split("@")[0].rsplit(":", 1)[0]
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["dns-core"][
    "address"
]


def media_vars(tmp_path: Path, **kw) -> dict:
    lib = tmp_path / "library"
    lib.mkdir(exist_ok=True)
    (lib / ".hnx-media-library").write_text("")  # the operator's marker on a mounted library
    v = {
        "media_logical_id": "media",
        "ansible_host": GUEST,
        "media_dir": str(tmp_path / "app"),
        "media_data_root": str(tmp_path / "data"),
        "media_cache_dir": str(tmp_path / "cache"),
        "media_library_path": str(lib),
        "media_owner": USER,
        "media_uid": os.getuid(),
        "media_gid": os.getgid(),
        "media_start": False,
        "media_validate_with_docker": False,
    }
    v.update(kw)
    return v


def test_main_renders_a_read_only_library_cpu_transcoding_and_no_secrets(tmp_path):
    v = media_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]["media"]
    assert svc["image"] == DEFAULT_IMAGE
    assert "@sha256:" in svc["image"]
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["ports"] == [GUEST + ":8096:8096"]
    lib = v["media_library_path"]
    assert f"{lib}:{lib}:ro" in svc["volumes"]  # the library never writable
    assert f"{tmp_path}/data/config:/config" in svc["volumes"]
    assert f"{tmp_path}/cache:/cache" in svc["volumes"]  # outside the data root: not backed up
    # CPU transcoding: no device, no GPU variable, no privilege
    assert "devices" not in svc and not svc.get("privileged")
    assert not any("NVIDIA" in k or "VAAPI" in k for k in svc.get("environment", {}))
    assert not (tmp_path / "app" / "secrets").exists()  # the module holds no secret
    # Quick Connect seeded on a fresh install, readable only by the container's user
    sysxml = tmp_path / "data" / "config" / "config" / "system.xml"
    assert "<QuickConnectAvailable>true</QuickConnectAvailable>" in sysxml.read_text()
    assert oct(sysxml.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "data" / "config").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_an_existing_system_xml_is_never_overwritten(tmp_path):
    v = media_vars(tmp_path)
    existing = tmp_path / "data" / "config" / "config"
    existing.mkdir(parents=True)
    (existing / "system.xml").write_text(
        "<ServerConfiguration><ServerName>keep</ServerName></ServerConfiguration>"
    )
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    assert "<ServerName>keep</ServerName>" in (existing / "system.xml").read_text()


def test_published_url_and_timezone_reach_the_environment(tmp_path):
    v = media_vars(
        tmp_path,
        media_published_url="https://media.example.internal",
        media_timezone="Europe/Berlin",
    )
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    env = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"][
        "media"
    ]["environment"]
    assert env["TZ"] == "Europe/Berlin"
    assert list(env.values()).count("https://media.example.internal") == 1 and len(env) == 2


def test_the_container_joins_the_role_slice_the_module_play_names(tmp_path):
    v = media_vars(tmp_path, hnx_module_slice="hnx-media-server.slice")
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["services"]["media"]["cgroup_parent"] == "hnx-media-server.slice"


@pytest.mark.parametrize(
    "over",
    [
        {"media_image": REPO + ":latest"},
        {"media_image": DEFAULT_IMAGE.split("@")[0]},  # a tag without a digest
        {"ansible_host": "media.example.internal"},
        {"media_hwaccel": "nvenc"},  # hardware transcoding is not supported yet
        {"media_uid": 0},
        {"media_library_path": "/srv"},  # a host-wide directory
        {"media_library_path": "relative/media"},
        {"media_library_path": "/var/lib/../etc"},
        {"media_expected_server_id": "not-hex"},
        {"media_published_url": "javascript:alert(1)"},
        {"media_quick_connect": "yes please"},
    ],
)
def test_main_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, ROLE, "main", media_vars(tmp_path, **over))
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_main_refuses_a_library_inside_the_data_root(tmp_path):
    inside = tmp_path / "data" / "config" / "lib"
    inside.mkdir(parents=True)
    r = run_role(tmp_path, ROLE, "main", media_vars(tmp_path, media_library_path=str(inside)))
    assert r.returncode != 0 and not (tmp_path / "app" / "docker-compose.yml").exists()


def test_main_refuses_to_start_on_a_library_that_is_not_there(tmp_path):
    """No mount at the library path would be served as an empty library (and pruned on a scan)."""
    v = media_vars(tmp_path, media_start=True, media_library_path=str(tmp_path / "not-mounted"))
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0 and "is not a mounted library" in r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_main_refuses_to_start_on_an_empty_directory_that_is_not_a_mount(tmp_path):
    """An unmounted mount point is an existing, empty directory: is-a-directory proves nothing."""
    empty = tmp_path / "empty-library"
    empty.mkdir()
    r = run_role(
        tmp_path,
        ROLE,
        "main",
        media_vars(tmp_path, media_start=True, media_library_path=str(empty)),
    )
    assert r.returncode != 0 and "is not a mounted library" in r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- health


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    state = json.dumps({"Service": "media", "State": "running", "Health": health})
    fake(bindir / "docker", f"import sys\nsys.stdout.write({state + chr(10)!r})\n")
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _health(tmp_path, srv, **kw):
    host, port = srv.addr
    v = media_vars(tmp_path, media_bind=host, media_port=port, **kw)
    return run_role(tmp_path, ROLE, "health", v, env=_docker(tmp_path))


def test_health_passes_and_only_reads(tmp_path):
    with Server() as srv:
        r = _health(tmp_path, srv, media_expected_server_id=SERVER_ID)
        paths = list(srv.paths)
    assert r.returncode == 0, r.stdout + r.stderr
    assert paths == ["/health", "/System/Info/Public", "/QuickConnect/Enabled"]


def test_health_fails_when_the_server_is_not_healthy(tmp_path):
    with Server(health="Unhealthy") as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "The server answers /health" in r.stdout


def test_health_fails_on_another_server_id(tmp_path):
    """A different id makes every TV client treat the server as new."""
    with Server(server_id="f" * 32) as srv:
        r = _health(tmp_path, srv, media_expected_server_id=SERVER_ID)
    assert r.returncode != 0 and "expected server" in r.stdout


def test_health_fails_when_quick_connect_is_off(tmp_path):
    with Server(quick_connect="false") as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "Quick Connect is off" in r.stdout


def test_health_fails_when_the_library_is_no_longer_mounted(tmp_path):
    with Server() as srv:
        (tmp_path / "library").mkdir()
        (tmp_path / "library" / ".hnx-media-library").unlink(missing_ok=True)
        host, port = srv.addr
        v = media_vars(tmp_path, media_bind=host, media_port=port)
        (
            tmp_path / "library" / ".hnx-media-library"
        ).unlink()  # the mount (and its marker) went away
        r = run_role(tmp_path, ROLE, "health", v, env=_docker(tmp_path))
    assert r.returncode != 0 and "is not a mounted library" in r.stdout


def test_health_fails_when_the_container_is_unhealthy(tmp_path):
    with Server() as srv:
        host, port = srv.addr
        v = media_vars(tmp_path, media_bind=host, media_port=port)
        r = run_role(tmp_path, ROLE, "health", v, env=_docker(tmp_path, "unhealthy"))
    assert r.returncode != 0


# ----------------------------------------------------------------------------- export, restore


def _config(root: Path) -> None:
    (root / "config" / "data").mkdir(parents=True)
    (root / "config" / "config").mkdir()
    (root / "config" / "log").mkdir()
    (root / "config" / "data" / "device.txt").write_text(SERVER_ID)
    (root / "config" / "data" / "main.db").write_bytes(b"db")
    (root / "config" / "log" / "x.log").write_text("noise")


def _docker_log(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n",
    )
    return log


def test_export_archives_the_config_with_the_server_stopped_and_restore_checks_it(tmp_path):
    v = media_vars(tmp_path)
    _config(tmp_path / "data")
    log = _docker_log(tmp_path)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    r = run_role(tmp_path, ROLE, "export", {**v, "media_start": True}, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = log.read_text().splitlines()
    assert calls[0].endswith(" stop") and calls[-1].endswith(
        " up -d"
    )  # restarted whatever happened
    export = tmp_path / "data" / "export"
    with tarfile.open(export / "media-config.tar.gz") as t:
        names = sorted(t.getnames())
    assert "./data/device.txt" in names and not any("log" in n for n in names)  # logs left out
    listing = json.loads((export / "listing.jsonl").read_text())
    assert (
        listing["sha256"]
        == hashlib.sha256((export / "media-config.tar.gz").read_bytes()).hexdigest()
    )
    # restore from a copy of the export into a config with another server id
    src = tmp_path / "src"
    src.mkdir()
    for p in export.iterdir():
        (src / p.name).write_bytes(p.read_bytes())
    (tmp_path / "data" / "config" / "data" / "device.txt").write_text("e" * 32)
    log.unlink()
    ok = run_role(tmp_path, ROLE, "restore", {**v, "media_restore_source": str(src)}, env=env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert (tmp_path / "data" / "config" / "data" / "device.txt").read_text() == SERVER_ID
    assert (
        tmp_path / "data" / "config.before-restore" / "data" / "device.txt"
    ).read_text() == "e" * 32
    # a tampered archive is refused before anything is stopped or moved
    log.unlink(missing_ok=True)
    with open(src / "media-config.tar.gz", "ab") as f:
        f.write(b"x")
    bad = run_role(tmp_path, ROLE, "restore", {**v, "media_restore_source": str(src)}, env=env)
    assert bad.returncode != 0 and "not intact" in bad.stdout
    assert not log.exists()


def test_restore_refuses_an_archive_without_a_server_id(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "something").write_text("x")
    archive = src / "media-config.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        t.add(payload / "something", arcname="something")
    (src / "listing.jsonl").write_text(
        json.dumps(
            {"key": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        )
        + "\n"
    )
    _docker_log(tmp_path)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    r = run_role(
        tmp_path,
        ROLE,
        "restore",
        {**media_vars(tmp_path), "media_restore_source": str(src)},
        env=env,
    )
    assert r.returncode != 0 and "data/device.txt" in r.stdout


def test_backup_names_the_data_root_not_the_library(tmp_path):
    v = media_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "backup", v).returncode == 0
    manifest = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert manifest == {"app": "media", "paths": [str(tmp_path / "data")]}


def test_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(tmp_path):
    v = media_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    assert (
        run_role(
            tmp_path,
            ROLE,
            "upgrade",
            {**v, "media_target_image": REPO + ":10.99.0"},
        ).returncode
        != 0
    )
    other = "docker.io/someone/other:10.99.0@sha256:" + "a" * 64
    assert run_role(tmp_path, ROLE, "upgrade", {**v, "media_target_image": other}).returncode != 0
    target = REPO + ":10.99.0@sha256:" + "a" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "media_target_image": target})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending == {"service": "media", "tag": "10.99.0", "digest": "sha256:" + "a" * 64}


def _export_for_restore(tmp_path):
    v = media_vars(tmp_path)
    _config(tmp_path / "data")
    log = _docker_log(tmp_path)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    assert run_role(tmp_path, ROLE, "export", v, env=env).returncode == 0
    src = tmp_path / "src"
    src.mkdir()
    for p in (tmp_path / "data" / "export").iterdir():
        (src / p.name).write_bytes(p.read_bytes())
    log.unlink(missing_ok=True)
    return v, src, log, env


def _write_archive(src: Path, add) -> None:
    archive = src / "media-config.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        data = SERVER_ID.encode()
        info = tarfile.TarInfo("data/device.txt")
        info.size = len(data)
        t.addfile(info, __import__("io").BytesIO(data))
        add(t)
    (src / "listing.jsonl").write_text(
        json.dumps(
            {"key": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        )
        + "\n"
    )


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_restore_refuses_link_and_special_members_before_stopping_anything(tmp_path, kind):
    v, src, log, env = _export_for_restore(tmp_path)

    def add(t):
        info = tarfile.TarInfo("data/evil")
        info.type = kind
        info.linkname = "data/device.txt" if kind == tarfile.LNKTYPE else "/etc/passwd"
        t.addfile(info)

    _write_archive(src, add)
    bad = run_role(tmp_path, ROLE, "restore", {**v, "media_restore_source": str(src)}, env=env)
    assert bad.returncode != 0 and "link or special file" in bad.stdout
    assert not log.exists()  # the server was never stopped
    assert not (tmp_path / "data" / "config.restoring").exists()


def test_restore_with_another_server_id_leaves_the_server_running_and_the_config_alone(tmp_path):
    v, src, log, env = _export_for_restore(tmp_path)
    other = "f" * 32
    bad = run_role(
        tmp_path, ROLE, "restore",
        {**v, "media_restore_source": str(src), "media_expected_server_id": other}, env=env,
    )  # fmt: skip
    assert bad.returncode != 0 and "is not the expected" in bad.stdout
    assert not log.exists()  # never stopped
    assert (tmp_path / "data" / "config" / "data" / "device.txt").read_text() == SERVER_ID
    assert not (tmp_path / "data" / "config.before-restore").exists()


def test_restore_starts_the_server_only_after_the_swap(tmp_path):
    v, src, log, env = _export_for_restore(tmp_path)
    ok = run_role(
        tmp_path, ROLE, "restore",
        {**v, "media_restore_source": str(src), "media_expected_server_id": SERVER_ID, "media_start": True}, env=env,
    )  # fmt: skip
    assert ok.returncode == 0, ok.stdout + ok.stderr
    calls = log.read_text().splitlines()
    assert calls[0].endswith(" stop") and calls[-1].endswith(" up -d")
    assert (tmp_path / "data" / "config" / "data" / "device.txt").read_text() == SERVER_ID
