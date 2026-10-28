# SPDX-License-Identifier: Apache-2.0
"""Firewall on by default: NIC flag rendering, the exemption rule, per-guest rules files."""

from __future__ import annotations

import ipaddress
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


def _host_filters(d: Path) -> None:
    """hv-a runs the host firewall a pointer at it claims (its baseline resolves host-firewall)."""
    p = d / "hv-a.yml"
    doc = yaml.safe_load(p.read_text())
    doc["baseline"] = {"names": ["base"]}
    p.write_text(yaml.safe_dump(doc, sort_keys=False))


DENY_DATA = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data",
            "198.51.100.0/25",
            "198.51.100.1",
            ("198.51.100.100", "198.51.100.126"),
            20,
            internet="deny",
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)


def problems(d: Path, zones=None) -> str:
    with pytest.raises(ComputeError) as ei:
        load_fleet(d, zones or STUB)
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
            x["network"].update(
                firewall="disabled",
                # a model runtime: the exemption names the layer that filters it, and a date
                firewall_exemption={
                    **EXEMPT,
                    "review_by": "2027-03-31",
                    "filtered_by": "guest:hv-a",
                },
            ),
            x.pop("firewall_rules", None),
        ),
    )
    _host_filters(d)
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


def test_rules_on_a_host_that_runs_no_host_ruleset_are_rejected(tmp_path):
    d = fleet_dir(
        tmp_path,
        "hv-a",
        lambda x: x.update(
            firewall_rules={"inbound_allow": [{"name": "x", "proto": "icmp", "source": "any"}]}
        ),
    )
    assert "firewall_rules on kind host need its baselines to resolve host-firewall" in problems(d)


def test_rules_on_a_host_reach_its_own_ruleset_and_no_hypervisor_file(tmp_path):
    """A host's rules go to its nftables_host ruleset (hnx_firewall), never to a .fw file."""
    d = fleet_dir(
        tmp_path,
        "hv-a",
        lambda x: x.update(
            baseline={"names": ["base"]},
            firewall_rules={"inbound_allow": [{"name": "x", "proto": "icmp", "source": "any"}]},
        ),
    )
    f = load_fleet(d, STUB)
    hv = yaml.safe_load(render(f, "inventory")["host_vars/hv-a.example.internal.yml"])
    assert hv["hnx_firewall"]["inbound_allow"] == [{"name": "x", "proto": "icmp", "source": "any"}]
    assert set(render(f, "firewall-rules")) == set(
        render(load_fleet(FLEET, STUB), "firewall-rules")
    )


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
    def executor(doc):
        doc.update(capability="cap:codemode-executor")
        doc["network"]["firewall_exemption"]["filtered_by"] = "zone:data"

    # the site model denies the data zone's internet egress at its router
    assert load_fleet(fleet_dir(tmp_path, "bus-core", executor), DENY_DATA).guests


def test_a_model_runtime_filtered_elsewhere_needs_the_exemption_saying_so(tmp_path):
    def off(doc):
        doc["network"].update(firewall="disabled")
        doc["network"].pop("firewall_exemption", None)
        doc.pop("firewall_rules")

    nodes = "nodes:\n  hv-a: {firewall: disabled}\n"  # no node rule asks for an exemption
    msg = problems(fleet_dir(tmp_path, "infer-core", off, nodes))
    assert "NIC firewall is off, so network.firewall_exemption needs filtered_by" in msg


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


@pytest.mark.parametrize(
    "exemption",
    [
        {"reason": "Filtered somewhere else, trust me."},
        {"reason": "Filtered somewhere else, trust me.", "review_by": "2027-03-31"},
        {"reason": "Filtered somewhere else, trust me.", "filtered_by": "guest:hv-a"},
    ],
    ids=["reason-only", "no-pointer", "no-review-date"],
)
def test_a_model_runtime_bare_exemption_is_refused(tmp_path, exemption):
    def off(doc):
        doc["network"].update(firewall="disabled", firewall_exemption=exemption)
        doc.pop("firewall_rules")

    assert "needs filtered_by (the guest or zone that filters it) and review_by" in problems(
        fleet_dir(tmp_path, "infer-core", off)
    )


@pytest.mark.parametrize(
    ("by", "expect"),
    [
        ("guest:nowhere", "guest:nowhere is not another guest"),
        ("guest:bus-core", "guest:bus-core is not another guest"),
        ("zone:nowhere", "zone 'nowhere' does not exist"),
    ],
    ids=["unknown-guest", "itself", "unknown-zone"],
)
def test_a_filtered_by_pointer_must_resolve(tmp_path, by, expect):
    msg = problems(
        fleet_dir(
            tmp_path,
            "bus-core",
            lambda x: x["network"]["firewall_exemption"].update(filtered_by=by),
        )
    )
    assert f"network.firewall_exemption.filtered_by: {expect}" in msg


@pytest.mark.parametrize(
    "dest",
    [
        "any",
        "0.0.0.0/0",
        "8.0.0.0/7",  # scrub-allow: a public range the rule must refuse
        "203.0.113.0/24",
        "198.51.100.0/23",
        "10.0.0.0/7",  # scrub-allow: a range wider than private the rule must refuse
    ],
    ids=["any", "default-route", "public", "documentation", "spans-out", "wider"],
)
def test_a_model_runtime_outbound_allow_never_reaches_the_internet(tmp_path, dest):
    def allow(doc):
        doc["firewall_rules"]["outbound_allow"].append(
            {"name": "wide", "proto": "tcp", "ports": "443", "dest": dest}
        )

    if dest == "203.0.113.0/24":  # documentation space is never the internet: accepted
        assert load_fleet(fleet_dir(tmp_path, "infer-core", allow), STUB).guests
        return
    assert f"firewall_rules.wide: dest {dest} reaches the internet" in problems(
        fleet_dir(tmp_path, "infer-core", allow)
    )


def test_a_model_runtime_outbound_allow_to_lab_ranges_is_accepted(tmp_path):
    def allow(doc):
        doc["firewall_rules"]["outbound_allow"] += [
            {
                "name": "lab-private",
                "proto": "tcp",
                "ports": "443",
                "dest": "10.20.0.0/16",  # scrub-allow: a private range, never the internet
            },
            {"name": "lab-zone", "proto": "tcp", "ports": "8443", "dest": "zone:compute"},
        ]

    assert load_fleet(fleet_dir(tmp_path, "infer-core", allow), STUB).guests


def test_a_guest_that_runs_no_model_may_allow_the_internet(tmp_path):
    def allow(doc):
        doc["firewall_rules"]["policy_out"] = "DROP"
        doc["firewall_rules"]["outbound_allow"] = [
            {"name": "https-out", "proto": "tcp", "ports": "443", "dest": "any"}
        ]

    assert load_fleet(fleet_dir(tmp_path, "edge-core", allow), STUB).guests


def _off(by, review="2027-03-31"):
    def off(doc):
        doc["network"].update(
            firewall="disabled",
            firewall_exemption={
                "reason": "Filtered by another layer, named here.",
                "filtered_by": by,
                "review_by": review,
            },
        )
        doc.pop("firewall_rules")

    return off


@pytest.mark.parametrize(
    ("by", "expect"),
    [
        ("guest:bus-core", "guest:bus-core is itself exempted from its firewall"),  # no chains
        ("guest:hv-a", "guest:hv-a runs no host firewall"),  # a host with no host-firewall
    ],
    ids=["exempted-target", "host-without-firewall"],
)
def test_a_filtered_by_guest_must_actually_filter(tmp_path, by, expect):
    assert f"network.firewall_exemption.filtered_by: {expect}" in problems(
        fleet_dir(tmp_path, "infer-core", _off(by))
    )


def test_a_filtered_by_host_that_runs_the_host_firewall_is_accepted(tmp_path):
    d = fleet_dir(tmp_path, "infer-core", _off("guest:hv-a"))
    _host_filters(d)
    assert load_fleet(d, STUB).guests


def test_a_guest_with_only_its_own_nic_firewall_filters_nothing_for_another(tmp_path):
    """edge-core's NIC firewall filters edge-core, not infer-core's traffic: with policy_out
    ACCEPT it lets its own traffic through; with DROP it filters only through a baseline that
    resolves host-firewall, and without one it runs no host firewall."""
    d = fleet_dir(tmp_path, "infer-core", _off("guest:edge-core"))
    assert "guest:edge-core lets its own outbound traffic through" in problems(d)
    p = d / "edge-core.yml"
    doc = yaml.safe_load(p.read_text())
    doc["firewall_rules"]["policy_out"] = "DROP"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    assert load_fleet(d, STUB).guests  # its exposed baseline resolves host-firewall
    doc.pop("baseline")
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    assert "filtered_by: guest:edge-core runs no host firewall" in problems(d)


def test_a_malformed_hnx_today_is_a_compute_error(monkeypatch):
    from homelabnext.compute import ComputeError
    from homelabnext.compute.validate import today

    monkeypatch.setenv("HNX_TODAY", "garbage")
    with pytest.raises(ComputeError, match="HNX_TODAY"):
        today()


def test_a_retired_filtered_by_guest_filters_nothing(tmp_path):
    d = fleet_dir(tmp_path, "infer-core", _off("guest:edge-core"))
    p = d / "edge-core.yml"
    doc = yaml.safe_load(p.read_text())
    doc["status"] = "retired"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    assert "filtered_by: guest:edge-core is retired" in problems(d)


@pytest.mark.parametrize("internet", [None, "allow"], ids=["not-stated", "allowed"])
def test_a_model_runtime_filtered_by_a_zone_needs_the_zone_to_deny_the_internet(tmp_path, internet):
    zones = MappingZones(
        [
            *(STUB.zone(z) for z in ("mgmt", "compute", "edge")),
            ZoneInfo("data", "198.51.100.0/25", "198.51.100.1", None, 20, internet=internet),
        ]
    )
    msg = problems(fleet_dir(tmp_path, "infer-core", _off("zone:data")), zones)
    assert "filtered_by zone:data, but the site model does not deny that zone's internet" in msg


def test_a_filtered_by_zone_that_denies_the_internet_is_accepted(tmp_path):
    assert load_fleet(fleet_dir(tmp_path, "infer-core", _off("zone:data")), DENY_DATA).guests


def test_a_review_date_must_be_a_date(tmp_path):
    def bad(doc):
        doc["network"]["firewall_exemption"]["review_by"] = "2026-13-45"

    assert "network.firewall_exemption.review_by: '2026-13-45' is not a date" in problems(
        fleet_dir(tmp_path, "bus-core", bad)
    )


def test_a_model_runtime_with_an_expired_review_is_refused(tmp_path):
    d = fleet_dir(tmp_path, "infer-core", _off("zone:data", review="2026-01-01"))
    msg = problems(d, DENY_DATA)  # HNX_TODAY is 2026-10-27 (conftest)
    assert "network.firewall_exemption.review_by 2026-01-01 has passed" in msg


def test_a_filtered_by_pointer_is_checked_on_a_host_too(tmp_path):
    def host(doc):
        doc["network"]["firewall_exemption"] = {
            "reason": "Filtered by another layer, named here.",
            "filtered_by": "guest:nowhere",
        }

    msg = problems(fleet_dir(tmp_path, "hv-a", host))
    assert "guest:hv-a: network.firewall_exemption.filtered_by: guest:nowhere" in msg


def _wan_zones() -> MappingZones:
    """The stub zones plus ``wan``, a zone whose subnet is public."""
    return MappingZones(
        [
            *(STUB.zone(z) for z in ("mgmt", "data", "compute", "edge")),
            ZoneInfo(
                "wan",
                "8.8.0.0/16",  # scrub-allow: a public zone the rule refuses
                "8.8.0.1",  # scrub-allow: its gateway
                None,
                50,
            ),
        ]
    )


def _wan_allow(doc):
    doc["firewall_rules"]["outbound_allow"].append(
        {"name": "wan", "proto": "tcp", "ports": "443", "dest": "zone:wan"}
    )


def test_a_model_runtime_zone_destination_must_be_a_lab_subnet(tmp_path):
    assert "firewall_rules.wan: dest zone:wan reaches the internet" in problems(
        fleet_dir(tmp_path, "infer-core", _wan_allow), _wan_zones()
    )


@pytest.mark.parametrize("guest", ["infer-core", "edge-core"])
def test_an_outbound_allow_never_holds_a_metadata_address(tmp_path, guest):
    def link_local(doc):
        fw = doc.setdefault("firewall_rules", {})
        fw["policy_out"] = "DROP"
        fw.setdefault("outbound_allow", []).append(
            {"name": "link-local", "proto": "tcp", "ports": "80", "dest": "169.254.0.0/16"}
        )

    assert "firewall_rules.link-local: dest 169.254.0.0/16 holds the cloud metadata address" in (
        problems(fleet_dir(tmp_path, guest, link_local))
    )


# ---------------------------------------------------------------- physical model runtimes
PHYSICAL = HERE / "physical" / "gpu-1.yml"
EGRESS = {
    "layer": "network",
    "description": "Outbound traffic only to listed destinations.",
    "role": None,
    "verify": "a connection to an unlisted outside address is refused",
}


def physical_fleet(tmp_path: Path, edit=None, *, egress: bool = True) -> Path:
    """The test fleet plus gpu-1 (tests/compute/physical), with a ``model-runtime`` baseline that
    resolves egress-filter when the set defines it (``egress=False`` leaves the control out)."""
    d = fleet_dir(tmp_path)
    p = d / "_baselines.yml"
    doc = yaml.safe_load(p.read_text())
    runtime = {"description": "A model runtime.", "extends": ["server"], "controls": []}
    if egress:
        doc["controls"]["egress-filter"] = EGRESS
        runtime["controls"] = ["egress-filter"]
        g = d / "infer-core.yml"
        guest = yaml.safe_load(g.read_text())
        guest["baseline"]["add"] = ["egress-filter"]
        g.write_text(yaml.safe_dump(guest, sort_keys=False))
    else:
        runtime["controls"] = ["host-firewall"]
    doc["baselines"]["model-runtime"] = runtime
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    host = yaml.safe_load(PHYSICAL.read_text())
    if edit:
        edit(host)
    (d / "gpu-1.yml").write_text(yaml.safe_dump(host, sort_keys=False))
    return d


def test_a_physical_model_runtime_with_egress_filter_and_lab_allows_is_accepted(tmp_path):
    f = load_fleet(physical_fleet(tmp_path), STUB)
    hv = yaml.safe_load(render(f, "inventory")["host_vars/gpu-1.example.internal.yml"])
    assert hv["hnx_kind"] == "host" and "egress-filter" in hv["hnx_controls"]
    assert hv["hnx_firewall"]["policy_out"] == "DROP"
    assert [r["dest"] for r in hv["hnx_firewall"]["outbound_allow"]] == [
        "192.0.2.0/24",
        "192.0.2.0/24",
        "198.51.100.0/25",
    ]
    assert set(render(f, "firewall-rules")) == set(
        render(load_fleet(FLEET, STUB), "firewall-rules")
    )


def test_a_physical_model_runtime_whose_set_defines_no_egress_filter_is_refused(tmp_path):
    msg = problems(physical_fleet(tmp_path, egress=False))
    assert (
        "guest:gpu-1: cap:inference runs models or model-written code on a physical host: the "
        "baseline set must define egress-filter"
    ) in msg


@pytest.mark.parametrize(
    "edit",
    [
        lambda x: x.update(baseline={"names": ["server"]}),
        lambda x: x.update(
            baseline={
                "names": ["model-runtime"],
                "remove": [{"control": "egress-filter", "reason": "Filtered by the rack switch."}],
            }
        ),
        lambda x: x.update(
            baseline={
                "exemption": {"reason": "Hardened by its vendor image instead of a baseline."}
            }
        ),
    ],
    ids=["baseline-without-it", "removed", "exempted"],
)
def test_a_physical_model_runtime_without_egress_filter_is_refused(tmp_path, edit):
    msg = problems(physical_fleet(tmp_path, edit))
    assert "on a physical host: its baselines must resolve egress-filter" in msg


def test_a_physical_model_runtime_with_open_egress_is_refused(tmp_path):
    for edit in (
        lambda x: x["firewall_rules"].update(policy_out="ACCEPT", outbound_allow=[]),
        lambda x: x.pop("firewall_rules"),
    ):
        msg = problems(physical_fleet(tmp_path / str(id(edit)), edit))
        assert f"guest:gpu-1: cap:inference runs models or model-written code: {ACCEPTS}" in msg


@pytest.mark.parametrize(
    "dest",
    ["any", "0.0.0.0/0", "8.0.0.0/7"],  # scrub-allow: a public range the rule must refuse
    ids=["any", "default-route", "public"],
)
def test_a_physical_model_runtime_internet_allow_is_refused(tmp_path, dest):
    def allow(x):
        x["firewall_rules"]["outbound_allow"].append(
            {"name": "registry", "proto": "tcp", "ports": "443", "dest": dest}
        )

    msg = problems(physical_fleet(tmp_path, allow))
    assert "guest:gpu-1: cap:inference runs models or model-written code: " in msg
    assert f"firewall_rules.registry: dest {dest} reaches the internet" in msg


def test_a_physical_model_runtime_metadata_allow_is_refused(tmp_path):
    imds = "169.254.169.254/32"  # scrub-allow: cloud metadata, refused

    def allow(x):
        x["firewall_rules"]["outbound_allow"].append(
            {"name": "imds", "proto": "tcp", "ports": "80", "dest": imds}
        )

    msg = problems(physical_fleet(tmp_path, allow))
    assert f"guest:gpu-1: firewall_rules.imds: dest {imds} holds the cloud metadata" in msg


@pytest.mark.parametrize(
    "edit",
    [
        lambda x: x.update(capability="cap:codemode-executor"),
        lambda x: x.update(capability="cap:idp", capability_groups=["cap_inference"]),
        lambda x: x["firewall_rules"].update(policy_out="REJECT"),
    ],
    ids=["codemode-executor", "inference-group", "reject"],
)
def test_every_physical_model_runtime_shape_is_accepted_when_default_deny(tmp_path, edit):
    f = load_fleet(physical_fleet(tmp_path, edit), STUB)
    hv = yaml.safe_load(render(f, "inventory")["host_vars/gpu-1.example.internal.yml"])
    assert hv["hnx_firewall"]["policy_out"] in ("DROP", "REJECT")


@pytest.mark.parametrize(
    "edit",
    [
        lambda x: x.update(capability="cap:codemode-executor"),
        lambda x: x.update(capability="cap:idp", capability_groups=["cap_inference"]),
    ],
    ids=["codemode-executor", "inference-group"],
)
def test_every_physical_model_runtime_shape_is_held_to_egress_filter(tmp_path, edit):
    def open_egress(x):
        edit(x)
        x["firewall_rules"].update(policy_out="ACCEPT", outbound_allow=[])

    msg = problems(physical_fleet(tmp_path, open_egress, egress=False))
    assert "guest:gpu-1: cap:" in msg and "on a physical host" in msg and ACCEPTS in msg


def test_a_physical_model_runtime_zone_destination_must_be_a_lab_subnet(tmp_path):
    msg = problems(physical_fleet(tmp_path, _wan_allow), _wan_zones())
    assert "guest:gpu-1: cap:inference runs models or model-written code: " in msg
    assert "firewall_rules.wan: dest zone:wan reaches the internet" in msg


def test_a_retired_physical_model_runtime_is_not_held_to_it(tmp_path):
    """As on a guest, a retired runtime runs nothing, so nothing is required of its egress."""

    def retired(x):
        x.update(status="retired")
        x["firewall_rules"].update(policy_out="ACCEPT", outbound_allow=[])

    assert load_fleet(physical_fleet(tmp_path, retired, egress=False), STUB).guests


@pytest.mark.parametrize(("policy", "ok"), [("ACCEPT", False), ("DROP", True), ("REJECT", True)])
def test_a_filtered_by_host_that_states_an_open_outbound_policy_filters_nothing(
    tmp_path, policy, ok
):
    """A host that carries firewall_rules states its own outbound policy, and is held to it
    like a vm or lxc: one that lets its own traffic through filters no one else's."""
    d = fleet_dir(tmp_path, "infer-core", _off("guest:hv-a"))
    _host_filters(d)
    p = d / "hv-a.yml"
    doc = yaml.safe_load(p.read_text())
    doc["firewall_rules"] = {"policy_out": policy}
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    if ok:
        assert load_fleet(d, STUB).guests
    else:
        msg = "filtered_by: guest:hv-a lets its own outbound traffic through (policy_out ACCEPT)"
        assert msg in problems(d)


# ---------------------------------------------------------------- a zone's IPv6 prefix (site 1.4)
MGMT6 = "2001:db8:0:10::/64"


def _zones6(**prefixes: str) -> MappingZones:
    """The stub zones, with ``subnet6`` set on the zones named."""
    import dataclasses

    return MappingZones(
        [
            dataclasses.replace(z, subnet6=prefixes.get(z.id))
            for z in (STUB.zone(i) for i in ("mgmt", "data", "compute", "edge"))
        ]
    )


def _ping_from_mgmt(doc):
    doc["firewall_rules"].setdefault("inbound_allow", []).append(
        {"name": "ping-mgmt", "proto": "icmp", "source": "zone:mgmt"}
    )


def test_a_zone_rule_reaches_the_zones_ipv6_prefix(tmp_path):
    """A rule naming a zone with a subnet6 is a line per family in the .fw file and a row per
    family in hnx_firewall, the IPv6 one right after the IPv4 one; ICMP is ICMPv6 there."""
    fleet = load_fleet(fleet_dir(tmp_path, "infer-core", _ping_from_mgmt), _zones6(mgmt=MGMT6))
    fw = render(fleet, "firewall-rules")["firewall/230.fw"].splitlines()
    i = fw.index("OUT ACCEPT -p udp -dport 53 -dest 192.0.2.0/24 -log nolog # dns")
    assert fw[i + 1] == f"OUT ACCEPT -p udp -dport 53 -dest {MGMT6} -log nolog # dns"
    assert "IN ACCEPT -p icmp -source 192.0.2.0/24 -log nolog # ping-mgmt" in fw
    assert f"IN ACCEPT -p ipv6-icmp -source {MGMT6} -log nolog # ping-mgmt" in fw
    # a zone without one (data) and a literal CIDR stay a single IPv4 line
    assert sum("# model-store" in ln for ln in fw) == 1
    hv = yaml.safe_load(render(fleet, "inventory")["host_vars/infer-core.example.internal.yml"])
    dns = [r for r in hv["hnx_firewall"]["outbound_allow"] if r["name"] == "dns"]
    assert [r["dest"] for r in dns] == ["192.0.2.0/24", MGMT6]
    assert [
        r["dest"] for r in hv["hnx_firewall"]["outbound_allow"] if r["name"] == "model-store"
    ] == ["198.51.100.0/25"]


def test_without_a_prefix_a_zone_rule_is_ipv4_only(good):
    for text in render(good, "firewall-rules").values():
        assert "ipv6-icmp" not in text
        for ln in text.splitlines():
            if ln.startswith(("IN ", "OUT ")):
                assert ":" not in ln.split("#", 1)[0], ln


def test_an_any_rule_does_not_change_meaning_with_a_prefix(tmp_path):
    """``any`` names no address in either file, prefix or not: it is not narrowed to the zones or
    widened by them."""

    def https_out(doc):
        doc["firewall_rules"]["policy_out"] = "DROP"
        doc["firewall_rules"]["outbound_allow"] = [
            {"name": "https-out", "proto": "tcp", "ports": "443", "dest": "any"}
        ]

    zones = _zones6(mgmt=MGMT6, edge="2001:db8:0:40::/64")
    fleet = load_fleet(fleet_dir(tmp_path, "edge-core", https_out), zones)
    fw = render(fleet, "firewall-rules")["firewall/110.fw"]
    assert fw.count("# https-out") == 1
    assert "OUT ACCEPT -p tcp -dport 443 -log nolog # https-out" in fw


def test_a_zone_prefix_that_does_not_read_is_refused_for_its_rules(tmp_path):
    msg = problems(fleet_dir(tmp_path), _zones6(mgmt="2001:db8:0:10:0::/64"))
    assert (
        "firewall_rules.dns: dest zone 'mgmt' has a subnet6 that is not in its canonical form"
        in (msg)
    )
    assert "firewall_rules.ssh-mgmt: source zone 'mgmt' has a subnet6" in msg


def test_a_zone_prefix_holding_a_metadata_address_is_refused(tmp_path):
    """The IPv6 metadata service sits in unique-local space, which a zone may be numbered from:
    an allow naming such a zone would hold it, so it is refused as a literal one is."""
    from homelabnext.modules.egress import METADATA

    meta6 = next(a for a in METADATA if a.version == 6)
    import ipaddress

    prefix = str(ipaddress.IPv6Network((int(meta6) >> 64 << 64, 64)))
    msg = problems(fleet_dir(tmp_path), _zones6(mgmt=prefix))
    assert f"firewall_rules.dns: dest zone:mgmt holds the cloud metadata address {meta6}" in msg


def test_a_model_runtime_zone_allow_with_a_global_prefix_reaches_the_internet(tmp_path):
    """A zone's global-unicast IPv6 prefix is judged like an IPv4 subnet in public space: nothing
    proves the site owns it (a typo or a copied prefix would open third-party space), so a model
    runtime's zone allow to it reaches the internet and is refused."""
    import ipaddress

    global6 = str(ipaddress.IPv6Network((0x2600_0010 << 96, 48)))  # a global /48, never a literal
    msg = problems(fleet_dir(tmp_path), _zones6(mgmt=global6))
    assert "firewall_rules.dns: dest zone:mgmt reaches the internet" in msg
    assert "firewall_rules.time: dest zone:mgmt reaches the internet" in msg


def test_a_global_prefix_still_renders_where_no_lab_only_rule_applies(tmp_path):
    """Only the model-runtime judgement changes: with the runtime's zone allows pointed elsewhere,
    another guest's inbound ``zone:`` rule renders the global prefix in the ``.fw`` file and the
    inventory, after the IPv4 subnet."""
    import ipaddress

    global6 = str(ipaddress.IPv6Network((0x2600_0010 << 96, 48)))

    def lab_cidr(doc):
        for r in doc["firewall_rules"]["outbound_allow"]:
            if r["dest"] == "zone:mgmt":
                r["dest"] = "192.0.2.0/24"

    fleet = load_fleet(fleet_dir(tmp_path, "infer-core", lab_cidr), _zones6(mgmt=global6))
    fw = render(fleet, "firewall-rules")["firewall/140.fw"].splitlines()
    v4 = fw.index("IN ACCEPT -p tcp -dport 22 -source 192.0.2.0/24 -log nolog # ssh-mgmt")
    assert fw[v4 + 1] == f"IN ACCEPT -p tcp -dport 22 -source {global6} -log nolog # ssh-mgmt"
    hv = yaml.safe_load(render(fleet, "inventory")["host_vars/lake-core.example.internal.yml"])
    sources = [r["source"] for r in hv["hnx_firewall"]["inbound_allow"] if r["name"] == "ssh-mgmt"]
    assert sources == ["192.0.2.0/24", global6]


def _delegated(prefix: str) -> list[dict]:
    return [{"prefix": prefix, "why": "the upstream ISP delegated it with the circuit"}]


def test_a_global_prefix_inside_a_delegated_one_is_the_labs(tmp_path):
    """A zone's global prefix inside a prefix the site declares its own (``delegated_prefixes6``,
    site 1.5) is the lab's: the model runtime's zone allow is accepted and rendered, while ``any``
    still reaches the internet."""
    import ipaddress

    global6 = str(ipaddress.IPv6Network((0x2600_0010 << 96, 48)))
    delegated = str(ipaddress.IPv6Network((0x2600_0010 << 96, 32)))  # holds global6
    zones = _zones6(mgmt=global6)
    fleet = load_fleet(fleet_dir(tmp_path), zones, delegated6=_delegated(delegated))
    hv = yaml.safe_load(render(fleet, "inventory")["host_vars/infer-core.example.internal.yml"])
    assert global6 in [r["dest"] for r in hv["hnx_firewall"]["outbound_allow"]]

    def any_out(doc):
        doc["firewall_rules"]["outbound_allow"].append(
            {"name": "wide", "proto": "tcp", "ports": "443", "dest": "any"}
        )

    with pytest.raises(ComputeError) as ei:
        load_fleet(
            fleet_dir(tmp_path / "b", "infer-core", any_out),
            zones,
            delegated6=_delegated(delegated),
        )
    assert "firewall_rules.wide: dest any reaches the internet" in str(ei.value)


def test_a_global_prefix_outside_every_delegated_one_reaches_the_internet(tmp_path):
    import ipaddress

    global6 = str(ipaddress.IPv6Network((0x2600_0010 << 96, 48)))
    elsewhere = str(ipaddress.IPv6Network((0x2A00_0020 << 96, 32)))  # holds no zone's prefix
    with pytest.raises(ComputeError) as ei:
        load_fleet(fleet_dir(tmp_path), _zones6(mgmt=global6), delegated6=_delegated(elsewhere))
    assert "firewall_rules.dns: dest zone:mgmt reaches the internet" in str(ei.value)


@pytest.mark.parametrize(
    "raw",
    [
        "not a list",
        [{"prefix": "2001:db8::/32", "why": "documentation space is never delegated"}],
        # a global /32 with a zone id, built from an integer so no such literal is in the tree
        [{"prefix": f"{ipaddress.IPv6Address(0x2600_0010 << 96)}%eth0/32", "why": "a zone id"}],
        [{"why": "no prefix at all"}],
    ],
)
def test_an_unusable_delegation_holds_nothing_as_the_labs(tmp_path, raw):
    """The site file reaches the compute path unvalidated: a declaration that does not read is a
    site problem and holds nothing, so the model runtime's zone allow to the global prefix is
    still refused (fail closed)."""
    import ipaddress

    global6 = str(ipaddress.IPv6Network((0x2600_0010 << 96, 48)))
    with pytest.raises(ComputeError) as ei:
        load_fleet(fleet_dir(tmp_path), _zones6(mgmt=global6), delegated6=raw)
    msg = str(ei.value)
    assert "delegated_prefixes6" in msg and "no prefix is held as the lab's" in msg
    assert "firewall_rules.dns: dest zone:mgmt reaches the internet" in msg


def test_a_model_runtime_zone_allow_with_a_unique_local_prefix_is_accepted(tmp_path):
    """A unique-local zone prefix is the lab's: the model runtime's zone allow is accepted and
    rendered, while ``any`` still reaches the internet."""
    import ipaddress

    ula6 = str(ipaddress.IPv6Network((0xFD00_0010 << 96, 64)))  # a unique-local /64
    zones = _zones6(mgmt=ula6)
    fleet = load_fleet(fleet_dir(tmp_path), zones)
    hv = yaml.safe_load(render(fleet, "inventory")["host_vars/infer-core.example.internal.yml"])
    assert ula6 in [r["dest"] for r in hv["hnx_firewall"]["outbound_allow"]]

    def any_out(doc):
        doc["firewall_rules"]["outbound_allow"].append(
            {"name": "wide", "proto": "tcp", "ports": "443", "dest": "any"}
        )

    assert "firewall_rules.wide: dest any reaches the internet" in problems(
        fleet_dir(tmp_path / "b", "infer-core", any_out), zones
    )
