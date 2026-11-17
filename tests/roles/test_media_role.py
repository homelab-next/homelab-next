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
import shutil
import tarfile
import xml.etree.ElementTree as ET
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


# The library is mounted into the container at its own path, and the container's /tmp is a tmpfs, so
# a library under /tmp is refused (the mounts would overlap). pytest's base directory is /tmp on CI,
# so the test library lives under /var/tmp, one directory per test, removed afterwards.
_LIBS: list[Path] = []


def lib_dir(tmp_path: Path) -> Path:
    lib = Path("/var/tmp") / (
        "hnx-media-lib-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:16]
    )
    lib.mkdir(exist_ok=True)
    if lib not in _LIBS:
        _LIBS.append(lib)
    return lib


@pytest.fixture(autouse=True)
def _remove_test_libraries():
    yield
    while _LIBS:
        lib = _LIBS.pop()
        # only a directory this module made: /var/tmp/hnx-media-lib-<16 hex>, never a link
        assert (
            lib.parent == Path("/var/tmp")
            and lib.name.startswith("hnx-media-lib-")
            and not lib.is_symlink()
        )
        shutil.rmtree(lib, ignore_errors=True)


def media_vars(tmp_path: Path, **kw) -> dict:
    lib = lib_dir(tmp_path)
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


GIB = 1 << 30


def _encoding(tmp_path: Path) -> str:
    return (tmp_path / "data" / "config" / "config" / "encoding.xml").read_text()


def test_main_runs_a_read_only_root_with_the_transcode_tmpfs_and_points_the_server_at_it(tmp_path):
    v = media_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    svc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]["media"]
    assert svc["read_only"] is True
    tmpfs = [m for m in svc["volumes"] if isinstance(m, dict)]
    assert {m["target"]: m for m in tmpfs} == {
        "/tmp": {"type": "tmpfs", "target": "/tmp", "tmpfs": {"size": 256 << 20, "mode": 0o1777}},
        "/transcode": {
            "type": "tmpfs",
            "target": "/transcode",
            "tmpfs": {"size": 8 * GIB, "mode": 0o1777},
        },
    }
    assert svc["mem_limit"] == "12g"
    xml = _encoding(tmp_path)
    assert "<TranscodingTempPath>/transcode</TranscodingTempPath>" in xml
    assert "<EnableThrottling>true</EnableThrottling>" in xml
    assert "<EnableSegmentDeletion>true</EnableSegmentDeletion>" in xml
    assert "<ThrottleDelaySeconds>60</ThrottleDelaySeconds>" in xml
    assert "<SegmentKeepSeconds>300</SegmentKeepSeconds>" in xml
    enc = tmp_path / "data" / "config" / "config" / "encoding.xml"
    assert oct(enc.stat().st_mode & 0o777) == "0o600"
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


EXISTING_ENCODING = """<?xml version="1.0" encoding="utf-8"?>
<EncodingOptions xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <EncodingThreadCount>-1</EncodingThreadCount>
  <TranscodingTempPath>/old/transcodes</TranscodingTempPath>
  <EnableThrottling>false</EnableThrottling>
  <ThrottleDelaySeconds>180</ThrottleDelaySeconds>
  <EnableSegmentDeletion>false</EnableSegmentDeletion>
  <SegmentKeepSeconds>720</SegmentKeepSeconds>
  <HardwareAccelerationType>none</HardwareAccelerationType>
</EncodingOptions>
"""


def test_an_existing_encoding_xml_is_edited_in_place_and_keeps_its_other_settings(tmp_path):
    v = media_vars(tmp_path)
    cfg = tmp_path / "data" / "config" / "config"
    cfg.mkdir(parents=True)
    (cfg / "encoding.xml").write_text(EXISTING_ENCODING)
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    xml = _encoding(tmp_path)
    assert "/old/transcodes" not in xml and xml.count("<TranscodingTempPath>") == 1
    assert "<TranscodingTempPath>/transcode</TranscodingTempPath>" in xml
    assert (
        "<EnableThrottling>true</EnableThrottling>" in xml and "false</EnableThrottling>" not in xml
    )
    assert "<EnableSegmentDeletion>true</EnableSegmentDeletion>" in xml
    assert "<SegmentKeepSeconds>300</SegmentKeepSeconds>" in xml
    assert "<EncodingThreadCount>-1</EncodingThreadCount>" in xml
    assert "<HardwareAccelerationType>none</HardwareAccelerationType>" in xml
    assert xml.rstrip().endswith("</EncodingOptions>") and xml.count("<EncodingOptions") == 1


def test_an_indented_closing_tag_is_found_and_the_edit_stays_inside_the_root(tmp_path):
    cfg = tmp_path / "data" / "config" / "config"
    cfg.mkdir(parents=True)
    body = EXISTING_ENCODING.replace(
        "  <TranscodingTempPath>/old/transcodes</TranscodingTempPath>\n", ""
    )
    (cfg / "encoding.xml").write_text(body.replace("</EncodingOptions>", "    </EncodingOptions>"))
    assert run_role(tmp_path, ROLE, "main", media_vars(tmp_path)).returncode == 0
    xml = _encoding(tmp_path)
    assert xml.index("<TranscodingTempPath>/transcode<") < xml.index("</EncodingOptions>")
    assert xml.rstrip().endswith("</EncodingOptions>") and xml.count("</EncodingOptions>") == 1
    ET.fromstring(xml)  # still well-formed


@pytest.mark.parametrize(
    ("name", "text", "why"),
    [
        (
            "no closing tag",
            EXISTING_ENCODING.replace("</EncodingOptions>\n", ""),
            "not well-formed",
        ),
        (
            "a self-closing root",
            '<?xml version="1.0"?>\n<EncodingOptions />\n',
            "no closing </EncodingOptions>",
        ),
        ("not xml at all", "this is not xml\n", "not well-formed"),
        ("a truncated file", EXISTING_ENCODING[:200], "not well-formed"),
        ("another root", "<Other>\n  <A>1</A>\n</Other>\n", "not EncodingOptions"),
        ("an empty file", "", "not well-formed"),
    ],
)
def test_a_malformed_encoding_xml_is_refused_and_left_alone(tmp_path, name, text, why):
    cfg = tmp_path / "data" / "config" / "config"
    cfg.mkdir(parents=True)
    (cfg / "encoding.xml").write_text(text)
    r = run_role(tmp_path, ROLE, "main", media_vars(tmp_path))
    assert r.returncode != 0, name
    assert why in r.stdout + r.stderr, (name, r.stdout)
    assert "left unchanged" in r.stdout + r.stderr
    assert (cfg / "encoding.xml").read_text() == text, name
    assert not (tmp_path / "app" / "docker-compose.yml").exists()  # nothing was started


def test_an_empty_transcoding_path_element_is_filled(tmp_path):
    cfg = tmp_path / "data" / "config" / "config"
    cfg.mkdir(parents=True)
    (cfg / "encoding.xml").write_text(
        EXISTING_ENCODING.replace(
            "<TranscodingTempPath>/old/transcodes</TranscodingTempPath>", "<TranscodingTempPath />"
        )
    )
    assert run_role(tmp_path, ROLE, "main", media_vars(tmp_path)).returncode == 0
    xml = _encoding(tmp_path)
    assert xml.count("TranscodingTempPath") == 2 and "<TranscodingTempPath>/transcode<" in xml


def test_a_size_of_zero_keeps_transcodes_in_the_cache_volume(tmp_path):
    v = media_vars(tmp_path, media_transcode_tmpfs_size=0, media_mem_limit="4g")
    cfg = tmp_path / "data" / "config" / "config"
    cfg.mkdir(parents=True)
    (cfg / "encoding.xml").write_text(EXISTING_ENCODING.replace("/old/transcodes", "/transcode"))
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    svc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]["media"]
    assert svc["read_only"] is True  # still read-only: only /tmp is a tmpfs
    assert [m["target"] for m in svc["volumes"] if isinstance(m, dict)] == ["/tmp"]
    xml = _encoding(tmp_path)
    assert "<TranscodingTempPath />" in xml and "/transcode<" not in xml
    assert "<EnableThrottling>false</EnableThrottling>" in xml  # not ours to change when off
    # a fresh install with the tmpfs off writes no encoding.xml at all
    t2 = tmp_path / "fresh"
    t2.mkdir()
    assert run_role(t2, ROLE, "main", media_vars(t2, media_transcode_tmpfs_size=0)).returncode == 0
    assert not (t2 / "data" / "config" / "config" / "encoding.xml").exists()


def test_a_size_of_zero_leaves_a_path_it_did_not_set_alone(tmp_path):
    cfg = tmp_path / "data" / "config" / "config"
    cfg.mkdir(parents=True)
    (cfg / "encoding.xml").write_text(EXISTING_ENCODING)
    v = media_vars(tmp_path, media_transcode_tmpfs_size=0, media_mem_limit="4g")
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    assert "<TranscodingTempPath>/old/transcodes</TranscodingTempPath>" in _encoding(tmp_path)


@pytest.mark.parametrize(
    "over",
    [
        {"media_transcode_tmpfs_size": 1},  # a page, not a transcode directory
        {"media_transcode_tmpfs_size": GIB - 1},
        {"media_transcode_tmpfs_size": (1 << 40) + 1},
        {"media_transcode_tmpfs_size": -1},
        {"media_transcode_tmpfs_size": "8g"},  # bytes, not a unit
        {"media_transcode_tmpfs_size": True},
        {"media_transcode_tmpfs_size": 8.5},
        {"media_mem_limit": "8g"},  # the default tmpfs plus /tmp and headroom does not fit
        {"media_mem_limit": "10g"},  # 8 GiB + 256 MiB + 2 GiB = 10.25 GiB
        {"media_transcode_tmpfs_size": 4 * GIB, "media_mem_limit": "6g"},
        {"media_transcode_tmpfs_size": 0, "media_mem_limit": "2g"},  # /tmp and headroom alone
    ],
)
def test_main_refuses_a_tmpfs_the_memory_limit_cannot_hold(tmp_path, over):
    r = run_role(tmp_path, ROLE, "main", media_vars(tmp_path, **over))
    assert r.returncode != 0, r.stdout


def test_a_memory_limit_that_covers_the_tmpfs_is_accepted(tmp_path):
    v = media_vars(tmp_path, media_transcode_tmpfs_size=4 * GIB, media_mem_limit="7g")
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0


def test_the_library_cannot_be_mounted_over_the_transcode_directory(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    v = media_vars(t, media_library_path="/transcode")
    r = run_role(t, ROLE, "main", {**v, "media_start": False})
    assert r.returncode != 0 and "refused tmpfs mount" in r.stdout + r.stderr, r.stdout


def test_a_library_under_tmp_is_refused_because_tmp_is_a_tmpfs(tmp_path):
    v = media_vars(tmp_path, media_library_path="/tmp/hnx-media-test-library")
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0 and "refused tmpfs mount" in r.stdout + r.stderr, r.stdout


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
        lib_dir(tmp_path).mkdir(exist_ok=True)
        (lib_dir(tmp_path) / ".hnx-media-library").unlink(missing_ok=True)
        host, port = srv.addr
        v = media_vars(tmp_path, media_bind=host, media_port=port)
        (lib_dir(tmp_path) / ".hnx-media-library").unlink()  # the mount (and its marker) went away
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
