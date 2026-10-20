# SPDX-License-Identifier: Apache-2.0
"""The product roles bound to the baseline controls (ADR-0016 decision 7): wazuh_agent,
tailscale_node, suricata_enroll and greenbone_target.

The central roles run end to end on localhost against fake ``suricata``/``suricatasc``/``gvm-cli``
commands; the per-guest roles install vendor packages, so their input validation and health hooks
run here and their install path is proven only by ``--syntax-check`` of the generated playbook
(``tests/compute/test_products.py``).  Every refusal is shown failing on a bad input and passing
on a good one."""

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)
GUESTS = [
    {
        "id": "guest:bus-core",
        "name": "bus-core",
        "fqdn": "bus-core.example.internal",
        "ip": "198.51.100.50",
        "zone": "data",
    },
    {
        "id": "guest:edge-core",
        "name": "edge-core",
        "fqdn": "edge-core.example.internal",
        "ip": "203.0.113.10",
        "zone": "edge",
    },
    {
        "id": "guest:lake-core",
        "name": "lake-core",
        "fqdn": "lake-core.example.internal",
        "ip": "198.51.100.40",
        "zone": "data",
    },
]


def run_role(tmp_path, role, tasks_from, extra_vars, env=None, verbose=False):
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "tasks": [{"ansible.builtin.include_role": {"name": role, "tasks_from": tasks_from}}],
        }
    ]
    pb = tmp_path / "play.yml"
    pb.write_text(yaml.safe_dump(play))
    ev = tmp_path / "vars.json"
    ev.write_text(
        json.dumps(
            {
                "hnx_registry_file": str(ANSIBLE / "inventory/example/registry.yml"),
                "ansible_python_interpreter": sys.executable,
                **extra_vars,
            }
        )
    )
    run_env = dict(
        os.environ,
        ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
        ANSIBLE_ERROR_ON_UNDEFINED_VARS="True",
        ANSIBLE_LOCALHOST_WARNING="False",
        ANSIBLE_HOME=str(tmp_path / ".ansible"),
        ANSIBLE_NOCOLOR="1",
        **(env or {}),
    )
    cmd = ["ansible-playbook", "-i", "localhost,", "-e", f"@{ev}", str(pb)]
    if verbose:
        cmd.append("-v")
    return subprocess.run(cmd, capture_output=True, text=True, env=run_env, cwd=tmp_path)


def fake(path: Path, body: str) -> str:
    """An executable Python script at ``path`` (a stand-in for a vendor command)."""
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


# ---------------------------------------------------------------- wazuh_agent
def wazuh_vars(tmp_path, **kw):
    d = {
        "wazuh_agent_manager_id": "siem",
        "wazuh_agent_state_file": str(tmp_path / "wazuh-agentd.state"),
        "wazuh_agent_manifest_dir": str(tmp_path / "manifest"),
    }
    d.update(kw)
    return d


def test_wazuh_agent_accepts_good_inputs(tmp_path):
    r = run_role(tmp_path, "wazuh_agent", "validate", wazuh_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "over",
    [
        {"wazuh_agent_manager_id": "siem.example.internal"},
        {"wazuh_agent_version": "4.14"},
        {"wazuh_agent_version": "4.14.9\nPackage: evil"},
        {"wazuh_agent_package_revision": "1 evil"},
        {"wazuh_agent_repository": "http://mirror.example.internal"},
        {"wazuh_agent_enrollment_ref": "plain-password-fake"},
        {"wazuh_agent_enrollment_ref": "secret:../escape-token"},
        {"wazuh_agent_name": "a b"},
        {"wazuh_agent_key_fingerprints": []},
        {"wazuh_agent_key_fingerprints": ["0dcfca5547b19d2a6099506096b3ee5f29111145"]},
        {"wazuh_agent_groups": ["ok", "x,y"]},
    ],
)
def test_wazuh_agent_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "wazuh_agent", "validate", wazuh_vars(tmp_path, **over))
    assert r.returncode != 0
    assert "wazuh_agent: manager id" in r.stdout


def test_wazuh_agent_needs_a_manager(tmp_path):
    v = wazuh_vars(tmp_path)
    del v["wazuh_agent_manager_id"]
    r = run_role(tmp_path, "wazuh_agent", "main", v)
    assert r.returncode != 0 and "wazuh_agent_manager_id" in r.stdout + r.stderr


def test_wazuh_agent_health_reads_the_state_file(tmp_path):
    state = tmp_path / "wazuh-agentd.state"
    state.write_text("# State file\nstatus='connected'\nlast_keepalive='2026-10-20 10:00:00'\n")
    assert run_role(tmp_path, "wazuh_agent", "health", wazuh_vars(tmp_path)).returncode == 0
    state.write_text("# State file\nstatus='disconnected'\n")
    r = run_role(tmp_path, "wazuh_agent", "health", wazuh_vars(tmp_path))
    assert r.returncode != 0 and "not connected" in r.stdout


def test_wazuh_agent_upgrade_and_backup_hooks(tmp_path):
    v = wazuh_vars(tmp_path)
    assert run_role(tmp_path, "wazuh_agent", "backup", v).returncode == 0
    manifest = json.loads((tmp_path / "manifest" / "backup-manifest.json").read_text())
    assert manifest["paths"] == []
    ok = run_role(tmp_path, "wazuh_agent", "upgrade", {**v, "wazuh_agent_target_version": "4.15.0"})
    assert ok.returncode == 0, ok.stdout
    assert (tmp_path / "manifest" / "pending-version").read_text() == "4.15.0\n"
    bad = run_role(tmp_path, "wazuh_agent", "upgrade", {**v, "wazuh_agent_target_version": "4.9.0"})
    assert bad.returncode != 0


# ---------------------------------------------------------------- the pinned, held packages
@pytest.mark.parametrize(
    ("role", "package"), [("wazuh_agent", "wazuh-agent"), ("tailscale_node", "tailscale")]
)
def test_the_pinned_install_may_move_its_own_held_package(role, package):
    """The package is dpkg-held, so the bump path (set a new version, re-run main) needs apt to
    change that held package, for that package alone, and the hold must be set again after."""
    tasks = yaml.safe_load((ANSIBLE / "roles" / role / "tasks" / "main.yml").read_text())
    names = [t.get("ansible.builtin.apt", {}).get("name", "") for t in tasks]
    (i,) = [n for n, name in enumerate(names) if str(name).startswith(f"{package}=")]
    install = tasks[i]["ansible.builtin.apt"]
    assert install["allow_change_held_packages"] is True
    assert isinstance(install["name"], str) and "," not in install["name"]  # this package only
    holds = [n for n, t in enumerate(tasks) if "ansible.builtin.dpkg_selections" in t]
    assert holds and min(holds) > i
    hold = tasks[min(holds)]["ansible.builtin.dpkg_selections"]
    assert hold == {"name": package, "selection": "hold"}


# ---------------------------------------------------------------- the vendor signing keys
def make_key(tmp_path: Path, name: str, out: Path, armor: bool) -> str:
    """A throwaway OpenPGP key exported to ``out``; returns its primary fingerprint."""
    home = tmp_path / f"gnupg-{name}"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--batch", "--homedir", str(home), "--pinentry-mode", "loopback"]
    uid = f"Fake vendor key {name}"
    subprocess.run([*gpg, "--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign", "never"],
                   check=True, capture_output=True)  # fmt: skip
    listing = subprocess.run([*gpg, "--with-colons", "--list-keys", uid], check=True,
                             capture_output=True, text=True).stdout  # fmt: skip
    fpr = next(x.split(":")[9] for x in listing.splitlines() if x.startswith("fpr:"))
    exported = subprocess.run([*gpg, *(["--armor"] if armor else []), "--export", fpr],
                              check=True, capture_output=True).stdout  # fmt: skip
    subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(out.read_bytes() + exported if out.exists() else exported)
    return fpr


KEY_CASES = {
    # role: (served path under the repository root, armoured, keyring, extra vars)
    "wazuh_agent": ("key/GPG-KEY-WAZUH", True, "hnx-wazuh.asc", {}),
    "tailscale_node": ("bookworm.noarmor.gpg", False, "hnx-tailscale.gpg",
                       {"tailscale_node_release": "bookworm"}),
}  # fmt: skip


def key_setup(tmp_path, role, pins=None, extra_key=False):
    served, armor, keyring, extra = KEY_CASES[role]
    repo = tmp_path / "repo"
    fpr = make_key(tmp_path, "vendor", repo / served, armor)
    if extra_key:
        make_key(tmp_path, "other", repo / served, armor)
    ring = tmp_path / "keyrings" / keyring
    v = {
        f"{role}_repository": f"file://{repo}",
        f"{role}_keyring": str(ring),
        f"{role}_key_fingerprints": [fpr] if pins is None else pins,
        **extra,
    }
    return v, ring, (repo / served).read_bytes()


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
@pytest.mark.parametrize("role", sorted(KEY_CASES))
def test_the_signing_key_is_installed_only_when_it_is_the_pinned_one(tmp_path, role):
    v, ring, served = key_setup(tmp_path, role)
    ok = run_role(tmp_path, role, "signing_key", v)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert ring.read_bytes() == served
    assert sorted(p.name for p in ring.parent.iterdir()) == [ring.name]  # no staging file left
    ring.unlink()
    other = run_role(tmp_path, role, "signing_key", {**v, f"{role}_key_fingerprints": ["A" * 40]})
    assert other.returncode != 0 and "not the pinned" in other.stdout
    assert list(ring.parent.iterdir()) == []  # refused: not installed, staging file removed


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
@pytest.mark.parametrize("role", sorted(KEY_CASES))
def test_a_signing_key_file_with_an_unpinned_key_beside_the_pinned_one_is_refused(tmp_path, role):
    v, ring, _ = key_setup(tmp_path, role, extra_key=True)
    r = run_role(tmp_path, role, "signing_key", v)
    assert r.returncode != 0 and "not the pinned" in r.stdout and not ring.exists()


def test_the_pinned_fingerprints_are_the_vendor_keys():
    pins = {
        "wazuh_agent": ["0DCFCA5547B19D2A6099506096B3EE5F29111145"],  # Wazuh.com (Wazuh Signing Key)
        "tailscale_node": ["2596A99EAAB33821893C0A79458CA832957F5868"],  # Tailscale Inc. (Package repository signing key)
    }  # fmt: skip
    for role, want in pins.items():
        d = yaml.safe_load((ANSIBLE / "roles" / role / "defaults" / "main.yml").read_text())
        assert d[f"{role}_key_fingerprints"] == want


# ---------------------------------------------------------------- tailscale_node
def ts_vars(tmp_path, **kw):
    d = {"tailscale_node_auth_key_ref": "secret:remote-access/authkey-secret", "hnx_zone": "edge"}
    d.update(kw)
    return d


def test_tailscale_node_tags_the_zone(tmp_path):
    v = ts_vars(tmp_path, hnx_zone="mgmt", tailscale_node_extra_tags=["tag:dns"])
    r = run_role(tmp_path, "tailscale_node", "validate", v, verbose=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert '"tailscale_node_tags": ["tag:zone-mgmt", "tag:dns"]' in r.stdout


def test_the_role_and_the_policy_agree_on_the_zone_tag():
    from homelabnext.compute.gen.tailscale_acl import ZONE_TAG_PREFIX

    fixed = yaml.safe_load((ANSIBLE / "roles/tailscale_node/vars/main.yml").read_text())
    assert fixed["tailscale_node_zone_tag_prefix"] == ZONE_TAG_PREFIX


@pytest.mark.parametrize(
    "over",
    [
        {"hnx_zone": "Edge"},
        {"hnx_zone": "edge,tag:admin"},
        {"tailscale_node_extra_tags": ["admin"]},
        {"tailscale_node_auth_key_ref": "tskey-auth-fake"},
        {"tailscale_node_hostname": "a b"},
        {"tailscale_node_key_fingerprints": []},
        {"tailscale_node_key_fingerprints": ["458CA832957F5868"]},
        {"tailscale_node_repository": "http://mirror.example.internal/debian"},
    ],
)
def test_tailscale_node_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "tailscale_node", "validate", ts_vars(tmp_path, **over))
    assert r.returncode != 0
    assert "tailscale_node: version" in r.stdout


def status_cli(tmp_path, doc):
    out = tmp_path / "status.json"
    out.write_text(json.dumps(doc))
    return fake(tmp_path / "tailscale", f"print(open({str(out)!r}).read())\n")


@pytest.mark.parametrize(
    ("doc", "ok"),
    [
        ({"BackendState": "Running", "Self": {"Online": True, "Tags": ["tag:zone-edge"]}}, True),
        ({"BackendState": "NeedsLogin", "Self": {"Online": False}}, False),
        ({"BackendState": "Running", "Self": {"Online": True, "Tags": ["tag:zone-mgmt"]}}, False),
        ({"BackendState": "Running", "Self": {"Online": False, "Tags": ["tag:zone-edge"]}}, False),
    ],
)
def test_tailscale_node_health(tmp_path, doc, ok):
    v = ts_vars(tmp_path, tailscale_node_cli=status_cli(tmp_path, doc))
    r = run_role(tmp_path, "tailscale_node", "health", v)
    assert (r.returncode == 0) is ok, r.stdout


# ---------------------------------------------------------------- suricata_enroll
SURICATA_YAML = """%YAML 1.1
---
vars:
  address-groups:
    include: hnx-address-groups.yaml
  port-groups:
    HTTP_PORTS: "80"
"""


SURICATA_FAKE = r"""
import os, re, sys
log, fail = LOG, FAIL
args = sys.argv[1:]
line = " ".join(args)
if "-T" in args:  # name the groups file the tested configuration includes, and its HOME_NET
    conf = args[args.index("-c") + 1]
    inc = re.search(r"address-groups:\s*\n\s+include:\s*(\S+)", open(conf).read()).group(1)
    groups = open(os.path.join(os.path.dirname(conf), inc)).read()
    line += f" [{inc} {re.search(r'^HOME_NET: (.*)$', groups, re.M).group(1)}]"
open(log, "a").write(line + "\n")
sys.exit(1 if os.path.exists(fail) else 0)
"""


def suricata_setup(tmp_path, conf=SURICATA_YAML):
    etc = tmp_path / "etc"
    etc.mkdir(exist_ok=True)
    (etc / "suricata.yaml").write_text(conf)
    log = tmp_path / "calls.log"

    def cli(name):
        body = SURICATA_FAKE.replace("LOG", repr(str(log)))
        return fake(tmp_path / name, body.replace("FAIL", repr(str(tmp_path / f"{name}.fails"))))

    return {
        "suricata_enroll_guests": GUESTS,
        "suricata_enroll_config_dir": str(etc),
        "suricata_enroll_suricata_cli": cli("suricata"),
        "suricata_enroll_suricatasc_cli": cli("suricatasc"),
    }, log


TESTED = "-T -c {etc}/.suricata.yaml.hnx-test [.hnx-address-groups.yaml.hnx-staged {home}]"
ALL_HOME = '"[198.51.100.40,198.51.100.50,203.0.113.10]"'
LIVE_ONLY = ["hnx-address-groups.yaml", "suricata.yaml"]  # nothing staged or pending


def test_suricata_enroll_writes_groups_tests_and_reloads_once(tmp_path):
    v, log = suricata_setup(tmp_path)
    r = run_role(tmp_path, "suricata_enroll", "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    groups = yaml.safe_load((tmp_path / "etc" / "hnx-address-groups.yaml").read_text())
    assert groups["HOME_NET"] == "[198.51.100.40,198.51.100.50,203.0.113.10]"
    assert groups["HNX_ZONE_DATA"] == "[198.51.100.40,198.51.100.50]"
    assert groups["HNX_ZONE_EDGE"] == "[203.0.113.10]"
    assert groups["EXTERNAL_NET"] == "!$HOME_NET" and groups["HTTP_SERVERS"] == "$HOME_NET"
    calls = log.read_text().splitlines()
    assert calls == [TESTED.format(etc=tmp_path / "etc", home=ALL_HOME), "-c reload-rules"]
    assert sorted(p.name for p in (tmp_path / "etc").iterdir()) == LIVE_ONLY
    again = run_role(tmp_path, "suricata_enroll", "main", v)  # unchanged: no test, no reload
    assert again.returncode == 0 and log.read_text().splitlines() == calls


def test_suricata_enroll_never_installs_a_file_that_fails_the_test(tmp_path):
    v, log = suricata_setup(tmp_path)
    live = tmp_path / "etc" / "hnx-address-groups.yaml"
    assert run_role(tmp_path, "suricata_enroll", "main", v).returncode == 0
    good = live.read_text()
    fewer = {**v, "suricata_enroll_guests": GUESTS[:1]}
    (tmp_path / "suricata.fails").touch()
    r = run_role(tmp_path, "suricata_enroll", "main", fewer)
    assert r.returncode != 0
    assert live.read_text() == good  # the failing file never went live
    assert sorted(p.name for p in (tmp_path / "etc").iterdir()) == LIVE_ONLY
    assert log.read_text().splitlines()[-1].startswith("-T ")  # tested, never reloaded
    (tmp_path / "suricata.fails").unlink()
    log.write_text("")
    fixed = run_role(tmp_path, "suricata_enroll", "main", fewer)  # the next run tests again
    assert fixed.returncode == 0, fixed.stdout
    assert log.read_text().splitlines() == [
        TESTED.format(etc=tmp_path / "etc", home='"[198.51.100.50]"'),
        "-c reload-rules",
    ]
    assert yaml.safe_load(live.read_text())["HOME_NET"] == "[198.51.100.50]"


def test_suricata_enroll_retries_a_failed_reload(tmp_path):
    v, log = suricata_setup(tmp_path)
    (tmp_path / "suricatasc.fails").touch()
    assert run_role(tmp_path, "suricata_enroll", "main", v).returncode != 0
    assert (tmp_path / "etc" / "hnx-address-groups.yaml").exists()  # tested, so live
    (tmp_path / "suricatasc.fails").unlink()
    log.write_text("")
    again = run_role(tmp_path, "suricata_enroll", "main", v)  # file unchanged, reload still owed
    assert again.returncode == 0, again.stdout
    assert log.read_text().splitlines() == ["-c reload-rules"]
    log.write_text("")
    assert run_role(tmp_path, "suricata_enroll", "main", v).returncode == 0
    assert log.read_text() == ""  # confirmed: nothing more to do
    assert sorted(p.name for p in (tmp_path / "etc").iterdir()) == LIVE_ONLY


def test_suricata_enroll_keeps_the_reload_owed_while_reloads_are_off(tmp_path):
    v, log = suricata_setup(tmp_path)
    off = run_role(tmp_path, "suricata_enroll", "main", {**v, "suricata_enroll_reload": False})
    assert off.returncode == 0 and "-c reload-rules" not in log.read_text()
    assert run_role(tmp_path, "suricata_enroll", "main", v).returncode == 0
    assert log.read_text().splitlines()[-1] == "-c reload-rules"


def test_suricata_enroll_refuses_a_config_that_does_not_include_the_groups(tmp_path):
    v, log = suricata_setup(tmp_path, conf="vars:\n  address-groups:\n    HOME_NET: any\n")
    r = run_role(tmp_path, "suricata_enroll", "main", v)
    assert r.returncode != 0 and "must hold, in place of its own" in r.stdout
    assert not (tmp_path / "etc" / "hnx-address-groups.yaml").exists() and not log.exists()


@pytest.mark.parametrize(
    "guests",
    [
        [],
        [{**GUESTS[0], "ip": "198.51.100.50\nHOME_NET: any"}],
        [{**GUESTS[0], "ip": "any"}],
        [{**GUESTS[0], "zone": "data: x"}],
    ],
)
def test_suricata_enroll_refuses_bad_guests(tmp_path, guests):
    v, _ = suricata_setup(tmp_path)
    r = run_role(tmp_path, "suricata_enroll", "main", {**v, "suricata_enroll_guests": guests})
    assert r.returncode != 0 and "suricata_enroll: at least one guest" in r.stdout


# ---------------------------------------------------------------- greenbone_target
GVM_CLI = r"""
import json, re, sys
args = sys.argv[1:]
state_file = STATE
conf = args[args.index("--config") + 1]
assert "[gmp]" in open(conf).read() and "password=gmp-pass-fake" in open(conf).read()
assert args[args.index("--socketpath") + 1] == "/run/gvmd/gvmd.sock"
xml = args[args.index("--xml") + 1]
state = json.load(open(state_file))
state["calls"].append(xml)
if xml.startswith("<get_credentials"):
    name = re.search(r'name=([^"]+)"', xml).group(1)
    body = '<credential id="11111111-2222-3333-4444-555555555555"/>' if name == "lab-ssh" else ""
    out = '<get_credentials_response status="200" status_text="OK">' + body + "</get_credentials_response>"
elif xml.startswith("<get_targets"):
    name = re.search(r'name=([^"]+)"', xml).group(1)
    body = '<target id="t-1"/>' if name in state["targets"] else ""
    out = '<get_targets_response status="200" status_text="OK">' + body + "</get_targets_response>"
elif xml.startswith("<create_target"):
    state["targets"].append(re.search("<name>([^<]+)</name>", xml).group(1))
    out = '<create_target_response status="201" status_text="OK, resource created" id="t-2"/>'
else:
    out = '<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>'
json.dump(state, open(state_file, "w"))
print(out)
"""


def gvm_setup(tmp_path, **kw):
    state = tmp_path / "gvm-state.json"
    state.write_text(json.dumps({"calls": [], "targets": ["hnx-edge-core"]}))
    cli = fake(tmp_path / "gvm-cli", GVM_CLI.replace("STATE", repr(str(state))))
    v = {
        "greenbone_target_guests": GUESTS,
        "greenbone_target_scan_login": "lab-ssh",
        "greenbone_target_gvm_cli": cli,
        "greenbone_target_become_user": "",
        "greenbone_target_work_dir": str(tmp_path / "work"),
        **kw,
    }
    env = {"HNX_SECRET_ASSESSMENT_GMP_PASSWORD": "gmp-pass-fake"}
    return v, env, state


def test_greenbone_target_creates_the_missing_targets_only(tmp_path):
    v, env, state = gvm_setup(tmp_path)
    r = run_role(tmp_path, "greenbone_target", "main", v, env)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads(state.read_text())
    assert doc["targets"] == ["hnx-edge-core", "hnx-bus-core", "hnx-lake-core"]
    created = [c for c in doc["calls"] if c.startswith("<create_target")]
    assert len(created) == 2
    assert (
        "<hosts>198.51.100.50</hosts><comment>zone data; homelabnext baseline vuln-scan</comment>"
        '<ssh_credential id="11111111-2222-3333-4444-555555555555"/>'
        "<port_range>T:1-65535</port_range>" in created[0]
    )
    assert not (tmp_path / "work" / "gvm-tools.conf").exists()  # the login never stays behind
    assert "gmp-pass-fake" not in r.stdout
    again = run_role(tmp_path, "greenbone_target", "main", v, env)
    assert again.returncode == 0
    assert len([c for c in json.loads(state.read_text())["calls"] if "<create_" in c]) == 2


def test_greenbone_target_refuses_an_unknown_scan_login(tmp_path):
    v, env, _ = gvm_setup(tmp_path, greenbone_target_scan_login="nope")
    r = run_role(tmp_path, "greenbone_target", "main", v, env)
    assert r.returncode != 0 and "no Greenbone credential named" in r.stdout
    assert not (tmp_path / "work" / "gvm-tools.conf").exists()


def test_greenbone_target_needs_the_gmp_secret(tmp_path):
    v, _, _ = gvm_setup(tmp_path)
    r = run_role(tmp_path, "greenbone_target", "main", v, {})
    assert r.returncode != 0
    assert "secret:assessment/gmp-password is not set" in r.stdout + r.stderr


@pytest.mark.parametrize(
    "over",
    [
        {"greenbone_target_guests": [{**GUESTS[0], "name": "x</name><hosts>0.0.0.0/0"}]},
        {"greenbone_target_guests": [{**GUESTS[0], "ip": "198.51.100.0/24"}]},
        {"greenbone_target_scan_login": 'lab"/><x'},
        {"greenbone_target_port_range": "T:1-65535</port_range>"},
        {"greenbone_target_gmp_auth_ref": "plain-fake"},
    ],
)
def test_greenbone_target_refuses_values_that_would_rewrite_the_request(tmp_path, over):
    v, env, state = gvm_setup(tmp_path, **over)
    r = run_role(tmp_path, "greenbone_target", "main", v, env)
    assert r.returncode != 0 and "greenbone_target: at least one guest" in r.stdout
    assert json.loads(state.read_text())["calls"] == []


def test_greenbone_target_health(tmp_path):
    v, env, state = gvm_setup(tmp_path)
    assert run_role(tmp_path, "greenbone_target", "health", v, env).returncode == 0
    assert json.loads(state.read_text())["calls"] == ["<get_version/>"]
