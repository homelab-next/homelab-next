# SPDX-License-Identifier: Apache-2.0
"""The dns provider module's role (modules/<id>/roles/<id>), run on localhost against fakes (CI is
unprivileged): main renders the server through compose_app with the admin password only in the
env_file and a second run is ``changed=0``; malformed inputs are refused; health passes against a
stand-in API and a stand-in DNS answerer and fails when the password, a zone count, an answer or
the very thing to ask about is missing; export writes a zone-file tree with a sha256 listing and
restore refuses a tampered one and checks record counts; restore_archive places only the
allowlisted files of an archived config, never the accounts, and fails on a wrong count; and the
zone tooling's refusals (a link, a climbing path, no zone, a stranger) each have a test."""

from __future__ import annotations

import importlib.util
import io
import ipaddress
import json
import os
import pwd
import socket
import struct
import tarfile
import threading
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from tests.modules.dns_front import FakeDnsAdmin
from tests.modules.dns_module import CTL, MID, ROLE_DIR, P, defaults, env_for, ref

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROLE_DIR)
IMAGE = defaults()[P + "image"]
REPO = IMAGE.split("@")[0].rsplit(":", 1)[0]
TAG = IMAGE.split("@")[0].rsplit(":", 1)[1]
DIGEST = IMAGE.split("@")[1]
VARS = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
CTL_ENV = VARS[P + "ctl_env"]
USER = pwd.getpwuid(os.getuid()).pw_name
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]


def addr(n: int) -> str:
    """The n-th address after the guest's, in the same documentation range."""
    return str(ipaddress.IPv4Address(GUEST) + n)


PASSWORD = "admin-password-fake"
PW_ENV = env_for(ref("admin-password"))
SECRETS = {PW_ENV: PASSWORD}
LOOPBACK = socket.gethostbyname("localhost")  # the stand-in answerer listens here; resolved

_spec = importlib.util.spec_from_file_location("zone_ctl", CTL)
ctl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ctl)  # type: ignore[union-attr]


# ------------------------------------------------------------------------------ the fakes
class Answerer:
    """A loopback DNS server answering from a table ``{(name, type): [values]}``: NOERROR with
    the values (A only; any other type gets one empty record), NXDOMAIN for an unknown name."""

    def __init__(self, table: dict[tuple[str, str], list[str]]):
        self.table = table
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LOOPBACK, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        self._t.join()
        self.sock.close()

    def _run(self):
        while not self._stop:
            try:
                msg, addr = self.sock.recvfrom(512)
            except OSError:
                continue
            name, off = ctl._name_at(msg, 12)
            qtype = struct.unpack(">H", msg[off : off + 2])[0]
            kind = ctl.NUM_TYPE[qtype]
            values = self.table.get((name, kind))
            known = any(n == name for n, _ in self.table)
            question = msg[12 : off + 4]
            if values is None:
                rcode = 0 if known else 3
                self.sock.sendto(
                    msg[:2] + struct.pack(">HHHHH", 0x8180 | rcode, 1, 0, 0, 0) + question, addr
                )
                continue
            answers = b""
            for v in values:
                rdata = socket.inet_aton(v) if kind == "A" else b""
                answers += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(rdata)) + rdata
            self.sock.sendto(
                msg[:2] + struct.pack(">HHHHH", 0x8580, 1, len(values), 0, 0) + question + answers,
                addr,
            )


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake ``docker``: ``compose ps`` lists the one container, every call is logged."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    state = json.dumps({"Service": MID, "State": "running", "Health": health})
    fake(bindir / "docker",
         "import sys\n"
         f"open({str(tmp_path / 'docker.log')!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
         f"sys.stdout.write({state + chr(10)!r} if 'ps' in sys.argv else '')\n")  # fmt: skip
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def tn_vars(tmp_path: Path, **kw) -> dict:
    v = {
        P + "logical_id": "dns",
        "ansible_host": GUEST,
        P + "dir": str(tmp_path / "app"),
        P + "data_root": str(tmp_path / "data"),
        P + "owner": USER,
        P + "uid": os.getuid(),
        P + "gid": os.getgid(),
        P + "start": False,
        P + "validate_with_docker": False,
        P + "ctl_dir": str(tmp_path / "libexec"),
        P + "ctl_path": str(tmp_path / "libexec" / (MID + "-ctl")),
    }
    v.update({k if k.startswith((P, "hnx_", "ansible_")) else P + k: val for k, val in kw.items()})
    return v


def _live(tmp_path: Path, srv: FakeDnsAdmin, answerer: Answerer, **kw) -> dict:
    host, port = srv._httpd.server_address[:2]
    return tn_vars(tmp_path, bind=host, api_port=port,
                   dns_port=answerer.port, **kw)  # fmt: skip


def _seed(srv: FakeDnsAdmin) -> None:
    srv.add_zone("lab.example.internal", {"web": addr(10), "db": addr(11)})
    srv.add_zone("other.example.internal", {"x": addr(12)})


ANSWERS = {
    ("lab.example.internal", "SOA"): ["-"], ("other.example.internal", "SOA"): ["-"],
    ("web.lab.example.internal", "A"): [addr(10)],
}  # fmt: skip
COUNTS = {"lab.example.internal": 4, "other.example.internal": 3}


# ----------------------------------------------------------------------------------- main
def _first_main_renders_the_server_with_the_password_only_in_the_env_file(tmp_path):
    v = tn_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_the_server_with_the_password_only_in_the_env_file)
def test_main_renders_the_server_with_the_password_only_in_the_env_file(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"][MID]
    assert svc["image"] == IMAGE.split("@")[0].rsplit(":", 1)[0] + ":" + TAG + "@" + DIGEST
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert "cap_add" not in svc and not svc.get("privileged")
    # the guest's own address only, DNS on udp and tcp, the API beside it
    assert svc["ports"] == [f"{GUEST}:53:53/udp", f"{GUEST}:53:53/tcp", f"{GUEST}:5380:5380/tcp"]
    env = svc["environment"]
    assert env["DNS_SERVER_DOMAIN"] == "dns"
    assert env["DNS_SERVER_RECURSION"] == "AllowOnlyForPrivateNetworks"
    assert "DNS_SERVER_ADMIN_PASSWORD" not in env and "DNS_SERVER_FORWARDERS" not in env
    assert PASSWORD not in text
    env_file = tmp_path / "app" / "secrets" / (MID + ".env")
    assert f"DNS_SERVER_ADMIN_PASSWORD='{PASSWORD}'" in env_file.read_text()
    assert oct(env_file.stat().st_mode & 0o777) == "0o600"
    data = tmp_path / "data"
    assert oct((data / "config").stat().st_mode & 0o777) == "0o750"
    assert oct((data / "export").stat().st_mode & 0o777) == "0o700"
    assert svc["volumes"] == [
        f"{data}/config:" + VARS[P + "container_config_dir"],
        f"{data}/log:" + VARS[P + "container_log_dir"],
    ]
    tool = Path(v[P + "ctl_path"])
    assert tool.read_bytes() == CTL.read_bytes() and oct(tool.stat().st_mode & 0o777) == "0o755"
    assert PASSWORD not in r.stdout
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_main_puts_the_container_in_the_role_slice_and_passes_first_start_settings(tmp_path):
    v = tn_vars(tmp_path, hnx_module_slice=f"hnx-{MID}-server.slice",
                forwarders=[addr(1)],
                block_list_urls=["https://lists.example.internal/hosts"])  # fmt: skip
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    svc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"][MID]
    assert svc["cgroup_parent"] == f"hnx-{MID}-server.slice"
    assert svc["environment"]["DNS_SERVER_FORWARDERS"] == addr(1)
    assert (
        svc["environment"]["DNS_SERVER_BLOCK_LIST_URLS"] == "https://lists.example.internal/hosts"
    )


@pytest.mark.parametrize(
    "over, env",
    [
        ({P + "image": REPO + ":latest"}, {}),
        ({"ansible_host": ".".join(["0"] * 4)}, {}),  # all interfaces: refused
        ({"ansible_host": "dns.example.internal"}, {}),
        ({P + "api_port": 53}, {}),
        ({P + "uid": 0}, {}),
        ({P + "recursion": "Everyone"}, {}),
        ({P + "data_root": "/var/lib/../etc"}, {}),
        ({P + "dir": "relative/dir"}, {}),
        ({P + "block_list_urls": ["http://lists.example.internal/hosts"]}, {}),
        ({P + "expected_zones": {"lab.example.internal": 0}}, {}),
        ({P + "expected_zones": {"bad name": 3}}, {}),
        ({P + "health_probes": [{"name": "x.example.internal", "type": "MX"}]}, {}),
        ({}, {PW_ENV: "short"}),
        ({}, {}),  # no password at all (the env is replaced below)
    ],
)
def test_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    use = {**SECRETS, **env} if (over or env) else {}
    r = run_role(tmp_path, ROLE, "main", tn_vars(tmp_path, **over), env=use)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert PASSWORD not in r.stdout


# ---------------------------------------------------------------------------------- health
def _health(tmp_path, srv, ans, expected=COUNTS, probes=(), password=PASSWORD, **over):
    v = _live(tmp_path, srv, ans, expected_zones=expected,
              health_probes=list(probes), **over)  # fmt: skip
    env = {PW_ENV: password, **_docker(tmp_path)}
    return run_role(tmp_path, ROLE, "health", v, env=env)


def test_health_passes_when_the_server_answers_its_zones_and_probes(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        probe = {"name": "web.lab.example.internal", "type": "A", "expect": [addr(10)]}
        r = _health(tmp_path, srv, ans, probes=[probe])
    assert r.returncode == 0, r.stdout + r.stderr
    assert PASSWORD not in r.stdout


def test_health_fails_when_there_is_nothing_to_ask_the_server_about(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        r = _health(tmp_path, srv, ans, expected={})
    assert r.returncode != 0 and "nothing to prove an answer with" in r.stdout


def test_health_fails_when_the_admin_cannot_sign_in(tmp_path):
    with FakeDnsAdmin(password="another-password-fake") as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        r = _health(tmp_path, srv, ans)
    assert r.returncode != 0 and "The admin signs in" in r.stdout


@pytest.mark.parametrize("expected", [{"lab.example.internal": 5}, {"missing.example.internal": 3}])
def test_health_fails_on_a_zone_count_or_a_missing_zone(tmp_path, expected):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        r = _health(tmp_path, srv, ans, expected=expected)
    assert r.returncode != 0 and "The admin signs in" in r.stdout


def test_health_fails_when_a_server_with_no_zones_is_asked(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        r = _health(tmp_path, srv, ans)
    assert r.returncode != 0


def test_health_fails_when_the_server_does_not_answer_over_dns(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer({}) as ans:  # answers nothing
        _seed(srv)
        r = _health(tmp_path, srv, ans)
    assert r.returncode != 0 and "answers the SOA of every expected zone" in r.stdout


def test_health_fails_when_a_probe_is_answered_differently(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        probe = {"name": "web.lab.example.internal", "type": "A", "expect": [addr(99)]}
        r = _health(tmp_path, srv, ans, probes=[probe])
    assert r.returncode != 0 and "answers every probe" in r.stdout


def test_health_fails_when_the_server_recurses_for_everyone(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        srv.recursion = "Allow"  # an open resolver
        r = _health(tmp_path, srv, ans)
    assert r.returncode != 0 and "The admin signs in" in r.stdout


def test_health_passes_when_the_recursion_is_the_sites_own_setting(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        srv.recursion = "Deny"
        r = _health(tmp_path, srv, ans, recursion="Deny")
    assert r.returncode == 0, r.stdout + r.stderr


def test_health_fails_when_the_container_is_unhealthy(tmp_path):
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        v = _live(tmp_path, srv, ans, expected_zones=COUNTS)
        env = {**SECRETS, **_docker(tmp_path, health="unhealthy")}
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0 and "unhealthy" in r.stdout


# ------------------------------------------------------------------------ export and restore
def test_export_writes_a_zone_tree_and_restore_checks_and_counts_it(tmp_path):
    with (
        FakeDnsAdmin(password=PASSWORD) as src,
        FakeDnsAdmin(password=PASSWORD) as dst,
        Answerer(ANSWERS) as ans,
    ):
        _seed(src)
        v = _live(tmp_path, src, ans)
        r = run_role(tmp_path, ROLE, "export", v, env=SECRETS)
        assert r.returncode == 0, r.stdout + r.stderr
        export = tmp_path / "data" / "export"
        rows = [json.loads(x) for x in (export / "listing.jsonl").read_text().splitlines()]
        assert sorted(x["key"] for x in rows) == [
            "lab.example.internal.zone",
            "other.example.internal.zone",
            "settings.zip",
        ]
        assert {x["zone"]: x["records"] for x in rows if "zone" in x} == COUNTS
        assert oct((export / "settings.zip").stat().st_mode & 0o777) == "0o600"
        # restore into another server from a root-owned-or-ours directory copy
        host, port = dst._httpd.server_address[:2]
        vr = tn_vars(tmp_path, bind=host, api_port=port,
                     restore_source=str(export))  # fmt: skip
        ok = run_role(tmp_path, ROLE, "restore", vr, env=SECRETS)
        assert ok.returncode == 0, ok.stdout + ok.stderr
        assert {z: len(rs) for z, rs in dst.zones.items()} == COUNTS
        # a tampered file is refused before anything is imported
        dst.zones.clear()
        with open(export / "lab.example.internal.zone", "ab") as f:
            f.write(b"x")
        bad = run_role(tmp_path, ROLE, "restore", vr, env=SECRETS)
        assert bad.returncode != 0 and "not the listed size" in bad.stdout
        assert dst.zones == {}


def test_restore_refuses_a_source_that_was_not_named(tmp_path):
    r = run_role(tmp_path, ROLE, "restore", tn_vars(tmp_path), env=SECRETS)
    assert r.returncode != 0 and P + "restore_source" in r.stdout


# ---------------------------------------------------------------------------- restore_archive
def _archive(path: Path, extra: dict[str, bytes] | None = None, zones: bool = True) -> Path:
    members = {
        "config/dns.config": b"settings",
        "config/allowed.config": b"a",
        "config/blocked.config": b"b",
        "config/blocklist.config": b"l",
        "config/scopes/Default.scope": b"s",
        "config/auth.config": b"THE-OLD-ACCOUNTS",
        "config/webservice.config": b"w",
        "config/log.config": b"g",
        "config/cache.bin": b"c",
        "config/stats/2026112102.stat": b"t",
        "config/blocklists/0a1b": b"downloaded",
    }
    if zones:
        members.update(
            {
                "config/zones/lab.example.internal.zone": b"zone-1",
                "config/zones/other.example.internal.zone": b"zone-2",
            }
        )
    members.update(extra or {})
    with tarfile.open(path, "w") as tf:
        for d in (
            "config",
            "config/zones",
            "config/scopes",
            "config/stats",
            "config/blocklists",
            "config/apps",
        ):
            ti = tarfile.TarInfo(d)
            ti.type = tarfile.DIRTYPE
            tf.addfile(ti)
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return path


def test_restore_archive_places_only_the_allowlisted_files_and_counts_the_zones(tmp_path):
    tar = _archive(tmp_path / "old-config.tar")
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)  # the started server holds what the archive's zone files define
        v = _live(tmp_path, srv, ans, restore_archive=str(tar),
                  expected_zones=COUNTS)  # fmt: skip
        r = run_role(tmp_path, ROLE, "restore_archive", v, env={**SECRETS, **_docker(tmp_path)})
        assert r.returncode == 0, r.stdout + r.stderr
    config = tmp_path / "data" / "config"
    placed = sorted(str(p.relative_to(config)) for p in config.rglob("*") if p.is_file())
    assert placed == ["allowed.config", "blocked.config", "blocklist.config", "dns.config",
                      "scopes/Default.scope", "zones/lab.example.internal.zone",
                      "zones/other.example.internal.zone"]  # fmt: skip
    assert (config / "zones" / "lab.example.internal.zone").read_bytes() == b"zone-1"
    assert not list(config.glob(".restore-*"))
    calls = (tmp_path / "docker.log").read_text().splitlines()
    assert [
        c.rsplit(" ", 2)[-1] if c.endswith("up -d") else c.split()[-1]
        for c in calls
        if " stop" in c or "up -d" in c
    ] == ["stop", "-d"]
    assert "THE-OLD-ACCOUNTS" not in "".join(
        p.read_text(errors="ignore") for p in config.rglob("*") if p.is_file()
    )


def test_restore_archive_fails_on_a_wrong_record_count_but_starts_the_server_again(tmp_path):
    tar = _archive(tmp_path / "old-config.tar")
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        v = _live(tmp_path, srv, ans, restore_archive=str(tar),
                  expected_zones={**COUNTS, "lab.example.internal": 5})  # fmt: skip
        r = run_role(tmp_path, ROLE, "restore_archive", v, env={**SECRETS, **_docker(tmp_path)})
    assert r.returncode != 0 and "Every expected zone is there" in r.stdout
    calls = (tmp_path / "docker.log").read_text().splitlines()
    # started again after the swap, then stopped because the restored server failed its check
    assert any(c.endswith("up -d") for c in calls) and calls[-1].endswith(" stop")


def test_restore_archive_stops_a_server_whose_restored_config_recurses_for_everyone(tmp_path):
    """The archived dns.config carries the old server's recursion setting. Here the restored
    server says Allow (open to everyone): the hook fails and the server is stopped again."""
    tar = _archive(tmp_path / "old-config.tar")
    with FakeDnsAdmin(password=PASSWORD) as srv, Answerer(ANSWERS) as ans:
        _seed(srv)
        srv.recursion = "Allow"
        v = _live(tmp_path, srv, ans, restore_archive=str(tar), expected_zones=COUNTS)
        r = run_role(tmp_path, ROLE, "restore_archive", v, env={**SECRETS, **_docker(tmp_path)})
    assert r.returncode != 0 and "recursion setting" in r.stdout
    assert (tmp_path / "docker.log").read_text().splitlines()[-1].endswith(" stop")


def test_restore_archive_refuses_without_expected_counts_or_with_a_bad_tar(tmp_path):
    tar = _archive(tmp_path / "old-config.tar")
    r = run_role(
        tmp_path,
        ROLE,
        "restore_archive",
        tn_vars(tmp_path, restore_archive=str(tar)),
        env=SECRETS,
    )
    assert r.returncode != 0 and "a restore that is not counted is not verified" in r.stdout
    bad = _archive(tmp_path / "bad.tar", {"config/../etc/passwd": b"x"})
    log = tmp_path / "docker.log"
    r = run_role(
        tmp_path,
        ROLE,
        "restore_archive",
        tn_vars(tmp_path, restore_archive=str(bad), expected_zones=COUNTS),
        env={**SECRETS, **_docker(tmp_path)},
    )
    assert r.returncode != 0 and "climbing path" in r.stdout
    assert not log.exists() or " stop" not in log.read_text()  # refused before the server stopped


# ------------------------------------------------------------------------------- upgrade
def test_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(tmp_path):
    v = tn_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    repo = REPO
    assert (
        run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": repo + ":16"}).returncode != 0
    )
    other = "docker.io/someone/dns-server:16.0.0@sha256:" + "a" * 64
    assert run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": other}).returncode != 0
    target = repo + ":16.0.0@sha256:" + "a" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": target})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending == {"service": MID, "tag": "16.0.0", "digest": "sha256:" + "a" * 64}


# ---------------------------------------------------------------- the zone tooling, directly
def _tar(tmp_path, name, members):
    path = tmp_path / name
    with tarfile.open(path, "w") as tf:
        for m, data in members:
            if isinstance(m, tarfile.TarInfo):
                tf.addfile(m)
            else:
                ti = tarfile.TarInfo(m)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return path


def _info(name, kind, linkname=""):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.linkname = linkname
    return ti


@pytest.mark.parametrize(
    "members, why",
    [
        (
            [
                ("config/zones/a.zone", b"z"),
                (_info("config/zones/b.zone", tarfile.SYMTYPE, "/etc/x"), b""),
            ],
            "only plain files",
        ),
        (
            [
                ("config/zones/a.zone", b"z"),
                (_info("config/zones/b.zone", tarfile.LNKTYPE, "config/zones/a.zone"), b""),
            ],
            "only plain files",
        ),
        (
            [("config/zones/a.zone", b"z"), (_info("config/dev", tarfile.CHRTYPE), b"")],
            "only plain files",
        ),
        ([("config/zones/a.zone", b"z"), ("/etc/cron.d/x", b"x")], "absolute"),
        ([("config/zones/a.zone", b"z"), ("config/../x", b"x")], "climbing"),
        ([("config/zones/a.zone", b"z"), ("config/zones/sub/b.zone", b"z")], "not a path"),
        ([("config/zones/a.zone", b"z"), ("config/apps/evil.dll", b"x")], "not a path"),
        ([("config/dns.config", b"s")], "no zone file"),
        ([], "no zone file"),
    ],
)
def test_the_archive_tooling_refuses_what_an_old_config_folder_does_not_hold(
    tmp_path, members, why
):
    with pytest.raises(ctl.Refused, match=why):
        ctl._archive_plan(str(_tar(tmp_path, "t.tar", members)))


def test_the_archive_tooling_refuses_a_link_in_place_of_the_tar(tmp_path):
    real = _archive(tmp_path / "real.tar")
    (tmp_path / "link.tar").symlink_to(real)
    with pytest.raises(ctl.Refused, match="not a regular file"):
        ctl._archive_plan(str(tmp_path / "link.tar"))
    (tmp_path / "junk.tar").write_bytes(b"not a tar at all" * 100)
    with pytest.raises(ctl.Refused, match="not a readable tar"):
        ctl._archive_plan(str(tmp_path / "junk.tar"))


def test_archive_apply_refuses_to_replace_zones_unless_told_to(tmp_path):
    tar = _archive(tmp_path / "t.tar")
    config = tmp_path / "data" / "config"
    (config / "zones").mkdir(parents=True)
    (config / "zones" / "live.zone").write_bytes(b"live")
    args = ctl._parser().parse_args(
        [
            "archive-apply",
            "--tar",
            str(tar),
            "--config",
            str(config),
            "--uid",
            str(os.getuid()),
            "--gid",
            str(os.getgid()),
        ]
    )
    with pytest.raises(ctl.Refused, match="already holds zones"):
        ctl.cmd_archive_apply(args)
    assert (config / "zones" / "live.zone").read_bytes() == b"live"
    args.overwrite = True
    ctl.cmd_archive_apply(args)
    assert (config / "zones" / "lab.example.internal.zone").exists()


def test_a_shallow_or_linked_directory_is_refused_by_the_tooling(tmp_path):
    with pytest.raises(ctl.Refused):
        ctl._safe_dir("/tmp")
    with pytest.raises(ctl.Refused):
        ctl._safe_dir("/")
    real = tmp_path / "a" / "b"
    real.mkdir(parents=True)
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(ctl.Refused):
        ctl._safe_dir(str(tmp_path / "link"))


def test_check_counts_refuses_an_empty_server_and_names_each_difference():
    assert ctl.check_counts({}, {}) == ["the server has no zones at all"]
    have = {"a.example.internal": {"records": 3}, "b.example.internal": {"records": 4}}
    assert ctl.check_counts(have, {"a.example.internal": 3, "b.example.internal": 4}) == []
    assert ctl.check_counts(have, {"b.example.internal": 5, "c.example.internal": 1}) == [
        "zone b.example.internal: 4 records, expected 5",
        "zone c.example.internal: missing (expected 1 records)",
    ]
    for bad in ('{"a": 0}', '{"a": true}', '{"a": "3"}', "[]", "nope"):
        with pytest.raises(ctl.Refused):
            ctl._expect(bad)


def test_the_dns_message_codec_round_trips_names_with_compression():
    q = ctl.build_query("Web.Lab.Example.Internal.", "A", qid=7)
    name, off = ctl._name_at(q, 12)
    assert name == "web.lab.example.internal" and q[off : off + 4] == b"\x00\x01\x00\x01"
    msg = (
        q[:2]
        + struct.pack(">HHHHH", 0x8580, 1, 1, 0, 0)
        + q[12:]
        + b"\xc0\x0c"
        + struct.pack(">HHIH", 1, 1, 60, 4)
        + socket.inet_aton(addr(10))
    )
    got = ctl.parse_answer(msg, 7)
    assert got["rcode"] == 0 and got["answers"] == [{"type": "A", "value": addr(10), "ttl": 60}]
    with pytest.raises(ctl.Refused, match="not for this query"):
        ctl.parse_answer(msg, 8)
    at = len(q)  # the answer's name points at itself
    loop = (
        q[:2]
        + struct.pack(">HHHHH", 0x8580, 1, 1, 0, 0)
        + q[12:]
        + struct.pack(">H", 0xC000 | at)
        + b"\x00" * 10
    )
    with pytest.raises(ctl.Refused):
        ctl.parse_answer(loop, 7)
    with pytest.raises(ctl.Refused):
        ctl.build_query("a" * 64 + ".example.internal", "A")


def test_compare_reports_every_difference_between_two_servers(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(CTL_ENV, PASSWORD)
    with FakeDnsAdmin(password=PASSWORD) as old, FakeDnsAdmin(password=PASSWORD) as new:
        _seed(old)
        _seed(new)
        argv = ["compare", "--old-api", old.url, "--new-api", new.url]
        assert ctl.main(argv) == 0
        assert json.loads(capsys.readouterr().out)["zones"]["lab.example.internal"] == {
            "old": 4,
            "new": 4,
            "differences": 0,
        }
        new.zones["lab.example.internal"][2]["rData"]["ipAddress"] = addr(99)  # one answer differs
        del new.zones["other.example.internal"]
        assert ctl.main(argv) == 1
        err = capsys.readouterr().err
        assert addr(99) in err and addr(10) in err
        assert "zone other.example.internal: missing on the new server" in err
    with FakeDnsAdmin(password=PASSWORD) as empty, FakeDnsAdmin(password=PASSWORD) as new:
        assert ctl.main(["compare", "--old-api", empty.url, "--new-api", new.url]) == 1
        assert "nothing to compare" in capsys.readouterr().err


def test_the_password_is_never_an_argument_or_a_url(monkeypatch, capsys):
    monkeypatch.delenv(CTL_ENV, raising=False)
    with FakeDnsAdmin(password=PASSWORD) as srv:
        assert ctl.main(["inventory", "--api", srv.url]) == 1
        assert CTL_ENV in capsys.readouterr().err
        assert PASSWORD not in capsys.readouterr().err


# ------------------------------------------------- archive limits, names and links (the tooling)
def _small_tar(tmp_path, members):
    return _tar(tmp_path, "limits.tar", [(n, d) for n, d in members])


ZONE = "config/zones/a.zone"


def test_the_per_member_size_refusal_works(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, "MAX_MEMBER_BYTES", 10)
    ok = _small_tar(tmp_path, [(ZONE, b"x" * 10)])
    assert [m.name for m in ctl._archive_plan(str(ok))] == [ZONE]
    big = _small_tar(tmp_path, [(ZONE, b"x" * 11)])
    with pytest.raises(ctl.Refused, match="within 10 bytes"):
        ctl._archive_plan(str(big))


def test_the_total_restored_bytes_cap_works(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, "MAX_RESTORED_BYTES", 10)
    ok = _small_tar(tmp_path, [(ZONE, b"x" * 6), ("config/dns.config", b"x" * 4)])
    assert len(ctl._archive_plan(str(ok))) == 2
    over = _small_tar(tmp_path, [(ZONE, b"x" * 6), ("config/dns.config", b"x" * 5)])
    with pytest.raises(ctl.Refused, match="files to restore hold more than"):
        ctl._archive_plan(str(over))


def test_the_whole_archive_bytes_cap_counts_ignored_members_too(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, "MAX_ARCHIVE_BYTES", 10)
    over = _small_tar(tmp_path, [(ZONE, b"x"), ("config/cache.bin", b"x" * 10)])
    with pytest.raises(ctl.Refused, match="archive holds more than 10 bytes"):
        ctl._archive_plan(str(over))


def test_the_member_count_cap_works(tmp_path, monkeypatch):
    monkeypatch.setattr(ctl, "MAX_MEMBERS", 3)
    ok = _small_tar(tmp_path, [(ZONE, b"z"), ("config/cache.bin", b""), ("config/log.config", b"")])
    assert len(ctl._archive_plan(str(ok))) == 1
    over = _small_tar(
        tmp_path, [(ZONE, b"z")] + [(f"config/stats/{n}.stat", b"") for n in range(3)]
    )
    with pytest.raises(ctl.Refused, match="more than 3 members"):
        ctl._archive_plan(str(over))


def test_a_member_named_twice_is_refused(tmp_path):
    dup = _small_tar(tmp_path, [(ZONE, b"one"), (ZONE, b"two")])
    with pytest.raises(ctl.Refused, match="named twice"):
        ctl._archive_plan(str(dup))


@pytest.mark.parametrize("name", [ZONE + "\n", "config/dns.config\n", "config/zones/a.zone/x"])
def test_the_allowlist_matches_the_whole_name(tmp_path, name):
    # a pattern ending in $ would let a trailing newline through
    bad = _small_tar(tmp_path, [(ZONE, b"z"), (name, b"x")])
    with pytest.raises(ctl.Refused, match="not a path"):
        ctl._archive_plan(str(bad))
    assert ctl.ZONE_FILE.fullmatch("a.zone\n") is None and ctl.ZONE_NAME.fullmatch("a\n") is None


@pytest.mark.parametrize("link", ["zones", "scopes", "anything"])
def test_a_link_inside_the_config_folder_is_refused_at_restore(tmp_path, link):
    tar = _archive(tmp_path / "t.tar")
    config = tmp_path / "data" / "config"
    config.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (config / link).symlink_to(elsewhere)
    args = ctl._parser().parse_args(["archive-apply", "--tar", str(tar), "--config", str(config),
                                     "--uid", str(os.getuid()), "--gid", str(os.getgid()),
                                     "--overwrite"])  # fmt: skip
    with pytest.raises(ctl.Refused, match="a link inside the config folder"):
        ctl.cmd_archive_apply(args)
    assert list(elsewhere.iterdir()) == [] and not list(config.glob(".restore-*"))


def test_verify_checks_the_recursion_setting(monkeypatch, capsys):
    monkeypatch.setenv(CTL_ENV, PASSWORD)
    with FakeDnsAdmin(password=PASSWORD) as srv:
        _seed(srv)
        base = ["verify", "--api", srv.url, "--expect", json.dumps(COUNTS)]
        assert ctl.main([*base, "--recursion", "AllowOnlyForPrivateNetworks"]) == 0
        capsys.readouterr()
        srv.recursion = "Allow"
        assert ctl.main([*base, "--recursion", "AllowOnlyForPrivateNetworks"]) == 1
        assert "recursion is 'Allow'" in capsys.readouterr().err
