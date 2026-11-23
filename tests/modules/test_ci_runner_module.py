# SPDX-License-Identifier: Apache-2.0
"""The ephemeral CI runner pool, ``modules/ci-runner`` (its README).

* The manifest: a feature (no product, no credentials, no data), one ``runner`` host role, internet
  egress only from it, no registry row.
* The defaults hold no lab value: no address, no hostname, the pinned artefacts and the feeder's
  key are required inputs with no default; the slot unit fails closed without the egress table.
* The egress table refuses every private, shared, loopback, link-local and multicast range and
  IPv6 for the slots' user, and ends in a deny.
* A fictional overlay that places it on a guest and grants its egress checks clean and renders
  ``modules.yml`` and ``checks/ci-runner.yml`` (readiness then health); without the grant it is refused.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "ci-runner"
ROLE = MODULE / "roles" / "ci_runner"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
SLOTS = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
REQUIRED = sorted(s for s, d in SLOTS.items() if d.get("required_in_core"))
MANIFEST = ld.load_yaml(MODULE / "module.yml")
DEFAULTS = ld.load_yaml(ROLE / "defaults" / "main.yml")
VARS = ld.load_yaml(ROLE / "vars" / "main.yml")
SPECS = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())["argument_specs"]


def test_the_manifest_is_a_feature_with_one_runner_role_and_internet_egress_only():
    m = MANIFEST
    assert m["kind"] == "feature" and m["id"] == "ci-runner"
    assert not {"product", "licence", "credentials", "provides", "data", "identifiers"} & set(m)
    assert [h["role"] for h in m["requires"]["hosts"]] == ["runner"]
    assert m["requires"]["hosts"][0]["roles"] == ["role:ci_runner"]
    assert m["egress"] == [
        {"host": "runner", "to": ["internet"], "purpose": m["egress"][0]["purpose"]}
    ]
    assert "services" not in m["contributes"] and not (MODULE / "registry").exists()
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["ci_runner"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))


def test_the_pins_the_key_and_the_resolvers_are_required_with_no_default():
    main = SPECS["main"]["options"]
    for name in ("logical_id", "base_image_url", "base_image_sha256", "agent_url", "agent_sha256",
                 "feed_pubkey", "resolvers"):  # fmt: skip
        key = f"ci_runner_{name}"
        assert main[key]["required"] is True and key not in DEFAULTS, key
    assert set(DEFAULTS) <= set(main)
    for hook in ("health", "readiness", "backup", "restore", "upgrade", "export"):
        assert SPECS[hook]["options"] == main, hook


def test_the_defaults_hold_no_address_and_no_lab_name():
    text = (ROLE / "defaults" / "main.yml").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", code)
    assert not re.search(r"\.(casa|local|lan|internal)\b", code)
    assert not re.search(r"https?://", code)


def _refused() -> list[ipaddress.IPv4Network]:
    out = []
    for item in VARS["ci_runner_refused_v4"]:
        nums = [int(x) for x in re.search(r"format\(([\d, ]+)\)", item)[1].split(",")]
        out.append(ipaddress.ip_network("{}.{}.{}.{}/{}".format(*nums)))
    return out


def test_the_refused_ranges_cover_every_non_global_ipv4_address_and_no_global_one():
    """A sweep of x.y.z.1 over every first two octets: whatever the standard library calls private,
    reserved or multicast, and the shared (CGNAT, tailnet) range, is refused; every global address
    is not."""
    refused = _refused()
    shared = ipaddress.IPv4Network((0x64400000, 10))
    for n in range(1 << 16):
        for z in (0, 2, 100, 113, 170):
            a = ipaddress.IPv4Address((n << 16) | (z << 8) | 1)
            hit = any(a in r for r in refused)
            if a.is_private or a.is_reserved or a.is_multicast or a in shared:
                assert hit, a
            elif a.is_global:
                assert not hit, a


def test_the_egress_table_holds_the_slots_user_and_ends_in_a_deny():
    text = (ROLE / "templates" / "egress.nft.j2").read_text()
    chain = text[text.index("chain output") :]
    lines = [
        ln.strip() for ln in chain.splitlines() if ln.strip() and not ln.strip().startswith("#")
    ]
    assert lines[2] == 'meta skuid != "{{ ci_runner_user }}" accept'
    order = [next(i for i, ln in enumerate(lines) if key in ln) for key in
             ("hnx-ci-no-ipv6", "hnx-ci-dns", "hnx-ci-refused-destination", "hnx-ci-internet-tcp",
              "hnx-ci-default-deny")]  # fmt: skip
    assert order == sorted(order)
    assert lines[-3] == 'counter drop comment "hnx-ci-default-deny"'
    assert (
        "policy accept" in lines[1]
    )  # only the slots' user is held; the host's own traffic is the hypervisor firewall's


def test_the_slot_unit_fails_closed_without_the_egress_table_and_never_shares_the_host():
    text = (ROLE / "templates" / "slot.service.j2").read_text()
    pre = [ln for ln in text.splitlines() if ln.startswith("ExecStartPre=")]
    assert pre == ["ExecStartPre=+/usr/sbin/nft list table inet {{ ci_runner_egress_table }}"]
    assert "User={{ ci_runner_user }}" in text and "NoNewPrivileges=yes" in text
    assert "CapabilityBoundingSet=\n" in text and "Restart=always" in text
    # user-mode networking: no bridge, no tap device, no host forwarding, no IPv6
    script = (ROLE / "files" / "hnx_ci_slot.py").read_text()
    assert '"user,id=n0,ipv6=off"' in script and "hostfwd" not in script and "tap" not in script


def test_the_feed_key_is_forced_to_the_feed_command():
    tasks = yaml.safe_load((ROLE / "tasks" / "config.yml").read_text())
    key = next(t for t in tasks if "feed key" in t["name"])
    content = key["ansible.builtin.copy"]["content"]
    assert content.startswith("restrict,command=") and content.rstrip().endswith(
        "{{ ci_runner_feed_pubkey }}"
    )
    assert '{{ ci_runner_slot_script }} feed"' in content


def test_the_build_seed_pins_the_agent_by_digest_and_resets_cloud_init():
    text = (ROLE / "templates" / "build-user-data.j2").read_text()
    assert "sha256sum -c -" in text and "{{ ci_runner_agent_sha256 }}" in text
    assert "cloud-init clean --logs --machine-id" in text
    assert "HNX-CI-BUILD-OK {{ ci_runner_base_image_sha256[:16] }}" in text
    assert "SuccessAction=poweroff-force" in text and "FailureAction=poweroff-force" in text
    tasks = yaml.safe_load((ROLE / "tasks" / "image.yml").read_text())
    fetch = next(t for t in tasks if "ansible.builtin.get_url" in t)
    assert (
        fetch["ansible.builtin.get_url"]["checksum"] == "sha256:{{ ci_runner_base_image_sha256 }}"
    )


def _dump(doc) -> str:
    class NoAliases(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    return yaml.dump(doc, Dumper=NoAliases, sort_keys=False)


def _args(ov: Path) -> list[str]:
    return [
        "--root", str(ROOT), "--overlay", str(ov),
        "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
        "--mcp-catalog", str(ROOT / "examples" / "mcp"),
    ]  # fmt: skip


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["ci-1"] = {"address": GUEST, "zone": "mgmt", "role": "ci"}
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "ci-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:ci-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 8, type: host}\n  memory: {size_mb: 16384}\n"
        "  disks: [{name: rootfs, size_gb: 120, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:ci-runner\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "intel-pilot",
        "hosts": {"ci": {"guest": "guest:ci-1"}},
        "slots": {},
        "features": {"ci-runner": {"placement": {"runner": "ci"}}},
        "incumbents": incumbents,
    }
    if grant:
        sel["grants"] = {"egress": {"ci-runner": {"runner": ["internet"]}}}
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def test_an_overlay_placing_it_on_a_guest_checks_clean_and_renders_its_checks(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    plays = [
        p
        for p in yaml.safe_load((dest / "modules.yml").read_text())
        if p["hosts"] == "mod_ci_runner_runner"
    ]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/ci-runner/roles/ci_runner")
    checks = yaml.safe_load((dest / "checks" / "ci-runner.yml").read_text())
    hooks = [
        t["name"].split(":")[0]
        for p in checks
        if p["hosts"] == "mod_ci_runner_runner"
        for t in p["tasks"]
    ]
    assert hooks == ["readiness", "health"]


def test_without_the_egress_grant_the_overlay_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path / "ov", grant=False)
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code != 0 and "egress" in out, out


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
