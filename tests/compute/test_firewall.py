# SPDX-License-Identifier: Apache-2.0
"""Firewall on by default: NIC flag rendering, the exemption rule, per-guest rules files."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.compute import (
    ComputeError,
    MappingZones,
    ZoneInfo,
    load_fleet,
    load_nodes,
    render,
)

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
STUB = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)
EXEMPT = {"reason": "Peers connect from changing addresses; the service authenticates itself."}


def fleet_dir(tmp_path: Path, name: str | None = None, edit=None, nodes: str | None = None) -> Path:
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    if name:
        p = d / f"{name}.yml"
        doc = yaml.safe_load(p.read_text())
        edit(doc)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    if nodes is not None:
        (d / "_nodes.yml").write_text(nodes)
    return d


def problems(d: Path) -> str:
    with pytest.raises(ComputeError) as ei:
        load_fleet(d, STUB)
    return str(ei.value)


@pytest.fixture(scope="module")
def good():
    return load_fleet(FLEET, STUB)


# ---------------------------------------------------------------- the NIC flag is always rendered
def test_every_rendered_nic_states_its_flag(good):
    tf = render(good, "terraform-proxmox")
    for name, text in tf.items():
        if name.startswith(("vm-", "ct-")):
            assert text.count("firewall = ") == 1, name


def test_absent_flag_renders_true_and_inherit_too(tmp_path):
    def drop(doc):
        doc["network"].pop("firewall", None)

    d = fleet_dir(tmp_path, "edge-core", drop)
    assert "firewall = true" in render(load_fleet(d, STUB), "terraform-proxmox")["vm-edge-core.tf"]
    d = fleet_dir(tmp_path / "b", "edge-core", lambda x: x["network"].update(firewall="inherit"))
    assert "firewall = true" in render(load_fleet(d, STUB), "terraform-proxmox")["vm-edge-core.tf"]


def test_exempt_guest_renders_false(good):
    assert "firewall = false" in render(good, "terraform-proxmox")["vm-bus-core.tf"]


def test_container_nic_gets_the_flag_too(good):
    assert "firewall = true" in render(good, "terraform-proxmox")["ct-idp-core.tf"]


# ---------------------------------------------------------------- the exemption rule
def test_flag_off_without_exemption_is_rejected(tmp_path):
    def off(doc):
        doc["network"].update(firewall="disabled")
        doc["network"].pop("firewall_exemption", None)

    out = problems(fleet_dir(tmp_path, "bus-core", off))
    assert "bus-core" in out and "firewall_exemption" in out and "hv-a" in out


def test_flag_off_with_exemption_is_accepted(tmp_path):
    d = fleet_dir(
        tmp_path,
        "infer-core",
        lambda x: (
            x["network"].update(firewall="disabled", firewall_exemption=EXEMPT),
            x.pop("firewall_rules", None),
        ),
    )
    f = load_fleet(d, STUB)
    assert "firewall = false" in render(f, "terraform-proxmox")["vm-infer-core.tf"]


def test_flag_off_is_fine_on_a_node_without_a_firewall(tmp_path):
    def off(doc):
        doc["network"].update(firewall="disabled")
        doc["network"].pop("firewall_exemption", None)

    nodes = "nodes:\n  hv-a: {firewall: disabled}\n"
    f = load_fleet(fleet_dir(tmp_path, "bus-core", off, nodes), STUB)
    assert f.node_firewall("hv-a") is False
    assert "firewall = false" in render(f, "terraform-proxmox")["vm-bus-core.tf"]


def test_unlisted_node_is_assumed_to_run_a_firewall(good):
    assert good.node_firewall("hv-a") is True and good.node_firewall("anything") is True


def test_short_exemption_reason_is_a_schema_error(tmp_path):
    d = fleet_dir(
        tmp_path,
        "bus-core",
        lambda x: x["network"].update(firewall="disabled", firewall_exemption={"reason": "no"}),
    )
    assert "firewall_exemption" in problems(d)


def test_stale_exemption_on_an_enabled_nic_is_rejected(tmp_path):
    d = fleet_dir(tmp_path, "edge-core", lambda x: x["network"].update(firewall_exemption=EXEMPT))
    assert "exemption is set but the NIC firewall is enabled" in problems(d)


def test_rules_on_a_disabled_nic_are_rejected(tmp_path):
    def edit(doc):
        doc["network"].update(firewall="disabled", firewall_exemption=EXEMPT)
        doc["firewall_rules"] = {"inbound_allow": [{"name": "x", "proto": "icmp", "source": "any"}]}

    assert "flag is disabled" in problems(fleet_dir(tmp_path, "lake-core", edit))


def test_rules_on_a_host_are_rejected(tmp_path):
    d = fleet_dir(
        tmp_path,
        "hv-a",
        lambda x: x.update(
            firewall_rules={"inbound_allow": [{"name": "x", "proto": "icmp", "source": "any"}]}
        ),
    )
    assert "vm and lxc only" in problems(d)


# ---------------------------------------------------------------- rule semantics
def rules(*rs):
    return lambda doc: doc.update(firewall_rules={"inbound_allow": list(rs)})


@pytest.mark.parametrize(
    "rule,expect",
    [
        ({"name": "a", "proto": "tcp", "source": "any"}, "ports are required"),
        ({"name": "a", "proto": "icmp", "ports": "22", "source": "any"}, "icmp takes no ports"),
        ({"name": "a", "proto": "tcp", "ports": "0", "source": "any"}, "bad port"),
        ({"name": "a", "proto": "tcp", "ports": "9000:80", "source": "any"}, "bad port"),
        ({"name": "a", "proto": "tcp", "ports": "70000", "source": "any"}, "bad port"),
        ({"name": "a", "proto": "tcp", "ports": "22", "source": "zone:nowhere"}, "does not exist"),
        ({"name": "a", "proto": "tcp", "ports": "22", "source": "192.0.2.5/24"}, "bad source CIDR"),
    ],
)
def test_bad_rules_are_rejected(tmp_path, rule, expect):
    assert expect in problems(fleet_dir(tmp_path, "edge-core", rules(rule)))


def test_duplicate_rule_names_are_rejected(tmp_path):
    r = {"name": "a", "proto": "icmp", "source": "any"}
    assert "names must be unique" in problems(fleet_dir(tmp_path, "edge-core", rules(r, dict(r))))


# ---------------------------------------------------------------- the rules-file renderer
def test_rules_file_defaults_to_drop_inbound(good):
    fw = render(good, "firewall-rules")
    text = fw["firewall/140.fw"]
    assert "policy_in: DROP" in text and "enable: 1" in text
    assert "IN ACCEPT -p tcp -dport 8443 -source 198.51.100.128/25 -log nolog # query-api" in text
    assert "IN ACCEPT -p icmp -source 192.0.2.0/24" in text  # a CIDR passes through


def test_zone_source_resolves_through_the_site_model(good):
    text = render(good, "firewall-rules")["firewall/110.fw"]
    assert "-dport 22 -source 192.0.2.0/24" in text
    assert "-dport 443 -log nolog # https-public" in text  # `any` adds no -source


def test_rule_order_follows_the_file(good):
    lines = render(good, "firewall-rules")["firewall/140.fw"].splitlines()
    assert [ln.rsplit("# ", 1)[1] for ln in lines if ln.startswith("IN ")] == [
        "query-api",
        "ssh-mgmt",
        "ping",
    ]


def test_guest_without_rules_gets_drop_and_nothing_else(good):
    text = render(good, "firewall-rules")["firewall/130.fw"]
    assert "policy_in: DROP" in text and "IN ACCEPT" not in text


def test_exempt_and_non_iac_guests_get_no_file_but_are_listed(good):
    fw = render(good, "firewall-rules")
    assert "firewall/150.fw" not in fw
    assert not any("secrets-core" in k or "hv-a" in k for k in fw)
    ex = fw["firewall/EXEMPTIONS.md"]
    assert "guest:bus-core" in ex and "2027-03-31" in ex and "authentication" in ex


def test_no_exemptions_says_none(tmp_path):
    d = fleet_dir(tmp_path, "bus-core", lambda x: x["network"].pop("firewall_exemption"))
    # drop the exemption AND re-enable the flag
    p = d / "bus-core.yml"
    doc = yaml.safe_load(p.read_text())
    doc["network"]["firewall"] = "enabled"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    out = render(load_fleet(d, STUB), "firewall-rules")["firewall/EXEMPTIONS.md"]
    assert "None." in out


def test_render_is_deterministic(good):
    assert render(good, "firewall-rules") == render(good, "firewall-rules")


# ---------------------------------------------------------------- nodes file
def test_load_nodes_validates(tmp_path):
    p = tmp_path / "n.yml"
    p.write_text("nodes:\n  a: {firewall: enabled}\n  b: {}\n")
    assert load_nodes(p) == {"a": {"firewall": "enabled"}, "b": {"firewall": "enabled"}}
    p.write_text("nodes:\n  a: {firewall: maybe}\n")
    with pytest.raises(ComputeError):
        load_nodes(p)
    p.write_text("- not a mapping\n")
    with pytest.raises(ComputeError):
        load_nodes(p)


# ---------------------------------------------------------------- what the hypervisor actually reads
def test_rules_files_are_named_by_vmid_because_that_is_what_proxmox_reads(good):
    fw = render(good, "firewall-rules")
    rule_files = sorted(k for k in fw if k.endswith(".fw"))
    assert rule_files == [
        f"firewall/{g.vmid}.fw" for g in sorted(good.iac(), key=lambda g: g.vmid) if g.nic_firewall
    ]
    assert not any(g.name in k for g in good.guests for k in rule_files)
    assert "# guest:lake-core on hv-a" in fw["firewall/140.fw"]  # the name stays readable


def _run_verify(tmp_path, fw, cluster: str | None, drop: str | None = None):
    import subprocess

    out = tmp_path / "render"
    pve = tmp_path / "pve"
    for d in (out, pve):
        d.mkdir(parents=True)
    for rel, text in fw.items():
        (out / Path(rel).name).write_text(text)
        if rel.endswith(".fw") and Path(rel).name != drop:
            (pve / Path(rel).name).write_text(text)
    if cluster is not None:
        (pve / "cluster.fw").write_text(cluster)
    return subprocess.run(
        ["sh", str(out / "verify-datacenter.sh")],
        env={"HNX_PVE_FIREWALL_DIR": str(pve), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(shutil.which("sh") is None or shutil.which("awk") is None, reason="no sh/awk")
def test_verify_script_checks_the_datacenter_switch_and_installed_files(good, tmp_path):
    fw = render(good, "firewall-rules")
    ok = _run_verify(tmp_path / "a", fw, "[OPTIONS]\nenable: 1\npolicy_in: DROP\n\n[RULES]\n")
    assert ok.returncode == 0, ok.stderr
    off = _run_verify(tmp_path / "b", fw, "[OPTIONS]\nenable: 0\n\n[RULES]\nenable: 1\n")
    assert off.returncode == 1 and "datacenter firewall is off" in off.stderr
    missing = _run_verify(tmp_path / "c", fw, None)
    assert missing.returncode == 1 and "datacenter firewall is off" in missing.stderr
    gone = _run_verify(tmp_path / "d", fw, "[OPTIONS]\nenable: 1\n", drop="140.fw")
    assert gone.returncode == 1 and "140.fw is missing or differs" in gone.stderr
    if shutil.which("shellcheck"):
        import subprocess

        script = tmp_path / "a" / "render" / "verify-datacenter.sh"
        r = subprocess.run(["shellcheck", "-s", "sh", str(script)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout


def test_egress_defaults_to_accept_and_can_be_default_deny(good, tmp_path):
    assert "policy_out: ACCEPT" in render(good, "firewall-rules")["firewall/140.fw"]

    def deny(doc):
        doc["firewall_rules"]["policy_out"] = "DROP"
        doc["firewall_rules"]["outbound_allow"] = [
            {"name": "dns", "proto": "udp", "ports": "53", "dest": "zone:mgmt"},
            {"name": "https-out", "proto": "tcp", "ports": "443", "dest": "any"},
        ]

    f = load_fleet(fleet_dir(tmp_path, "lake-core", deny), STUB)
    text = render(f, "firewall-rules")["firewall/140.fw"]
    assert "policy_out: DROP" in text and "log_level_out: nolog" in text
    assert "OUT ACCEPT -p udp -dport 53 -dest 192.0.2.0/24 -log nolog # dns" in text
    assert "OUT ACCEPT -p tcp -dport 443 -log nolog # https-out" in text
    assert text.index("IN ACCEPT") < text.index("OUT ACCEPT")


def test_outbound_rules_need_a_deny_policy_and_a_known_zone(tmp_path):
    def allow_only(doc):
        doc["firewall_rules"]["outbound_allow"] = [{"name": "x", "proto": "icmp", "dest": "any"}]

    assert "needs policy_out DROP or REJECT" in problems(
        fleet_dir(tmp_path / "a", "lake-core", allow_only)
    )

    def bad_zone(doc):
        doc["firewall_rules"]["policy_out"] = "REJECT"
        doc["firewall_rules"]["outbound_allow"] = [
            {"name": "x", "proto": "icmp", "dest": "zone:nope"}
        ]

    assert "dest zone 'nope' does not exist" in problems(
        fleet_dir(tmp_path / "b", "lake-core", bad_zone)
    )


def test_the_inventory_carries_the_same_rules_for_the_guests_own_firewall(good, tmp_path):
    """``hnx_firewall`` (read by the nftables_host role) is the rules file's content: same order,
    same policies, zones resolved to the same subnets, from the same resolver."""

    def deny(doc):
        doc["firewall_rules"]["policy_out"] = "REJECT"
        doc["firewall_rules"]["outbound_allow"] = [
            {"name": "dns", "proto": "udp", "ports": "53", "dest": "zone:mgmt"},
            {"name": "https-out", "proto": "tcp", "ports": "443", "dest": "any"},
        ]

    f = load_fleet(fleet_dir(tmp_path, "lake-core", deny), STUB)
    hv = yaml.safe_load(render(f, "inventory")["host_vars/lake-core.example.internal.yml"])
    assert hv["hnx_firewall"] == {
        "policy_out": "REJECT",
        "inbound_allow": [
            {"name": "query-api", "proto": "tcp", "ports": "8443", "source": "198.51.100.128/25"},
            {"name": "ssh-mgmt", "proto": "tcp", "ports": "22", "source": "192.0.2.0/24"},
            {"name": "ping", "proto": "icmp", "source": "192.0.2.0/24"},
        ],
        "outbound_allow": [
            {"name": "dns", "proto": "udp", "ports": "53", "dest": "192.0.2.0/24"},
            {"name": "https-out", "proto": "tcp", "ports": "443", "dest": "any"},
        ],
    }
    fw = render(f, "firewall-rules")["firewall/140.fw"]
    names = [line.rsplit("# ", 1)[1] for line in fw.splitlines() if " ACCEPT " in line]
    rows = hv["hnx_firewall"]["inbound_allow"] + hv["hnx_firewall"]["outbound_allow"]
    assert names == [r["name"] for r in rows]
    plain = yaml.safe_load(render(good, "inventory")["host_vars/hv-a.example.internal.yml"])
    assert plain["hnx_firewall"] == {
        "policy_out": "ACCEPT",
        "inbound_allow": [],
        "outbound_allow": [],
    }


# ---------------------------------------------------------------- model runtimes: default-deny egress
ACCEPTS = "firewall_rules.policy_out must be DROP or REJECT"


def test_a_model_runtime_with_open_egress_is_refused(tmp_path):
    d = fleet_dir(tmp_path, "infer-core", lambda x: x["firewall_rules"].update(policy_out="ACCEPT"))
    assert f"guest:infer-core: cap:inference runs models or model-written code: {ACCEPTS}" in (
        problems(d)
    )


def test_a_model_runtime_without_firewall_rules_is_refused(tmp_path):
    d = fleet_dir(tmp_path, "infer-core", lambda x: x.pop("firewall_rules"))
    assert ACCEPTS in problems(d)


@pytest.mark.parametrize(
    "edit",
    [
        lambda x: x.update(capability="cap:codemode-executor"),
        lambda x: x.update(capability_groups=["cap_inference"]),
        lambda x: x.update(capability_groups=["cap_codemode_executor"]),
    ],
    ids=["codemode-executor", "inference-group", "executor-group"],
)
def test_every_model_runtime_is_held_to_it(tmp_path, edit):
    d = fleet_dir(tmp_path, "idp-core", edit)  # idp-core: no firewall_rules, so ACCEPT
    msg = problems(d)
    assert "guest:idp-core: cap:" in msg and ACCEPTS in msg and "cap:idp runs" not in msg


def test_a_model_runtime_filtered_elsewhere_with_the_exemption_is_accepted(tmp_path):
    # bus-core's NIC firewall is off with an exemption naming where it is filtered
    d = fleet_dir(tmp_path, "bus-core", lambda x: x.update(capability="cap:codemode-executor"))
    assert load_fleet(d, STUB).guests


def test_a_model_runtime_filtered_elsewhere_needs_the_exemption_saying_so(tmp_path):
    def off(doc):
        doc["network"].update(firewall="disabled")
        doc["network"].pop("firewall_exemption", None)
        doc.pop("firewall_rules")

    nodes = "nodes:\n  hv-a: {firewall: disabled}\n"  # no node rule asks for an exemption
    msg = problems(fleet_dir(tmp_path, "infer-core", off, nodes))
    assert "NIC firewall is off with no network.firewall_exemption" in msg


def test_a_model_runtime_must_resolve_egress_filter_when_the_set_defines_it(tmp_path):
    d = fleet_dir(tmp_path)
    p = d / "_baselines.yml"
    doc = yaml.safe_load(p.read_text())
    doc["controls"]["egress-filter"] = {
        "layer": "network",
        "description": "Outbound traffic only to listed destinations.",
        "role": None,
        "verify": "a connection to an unlisted outside address is refused",
    }
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    assert "cap:inference runs models or model-written code: its baselines must include" in (
        problems(d)
    )
    g = d / "infer-core.yml"
    guest = yaml.safe_load(g.read_text())
    guest["baseline"]["add"] = ["egress-filter"]
    g.write_text(yaml.safe_dump(guest, sort_keys=False))
    assert load_fleet(d, STUB).guests


def test_a_guest_that_runs_no_model_keeps_its_own_egress_policy(good):
    assert any(
        g.capability != "cap:inference" and not g.raw.get("firewall_rules") for g in good.guests
    )
