# SPDX-License-Identifier: Apache-2.0
"""The log-pipeline provider module, ``modules/vector`` (modules/vector/README.md).

* The public tree loads clean; the module's ``roles/`` holds only its one contributed role and the
  code tree only its own package.
* The manifest fills ``log-pipeline`` with the module's own adapter, requires the secret store and
  an object store, keeps every secret in its own namespace, has no egress and no public row, and
  both images are pinned by digest.
* A fictional overlay that places it on a guest (the object store and every other required core
  slot an incumbent) passes ``hnx modules check --overlay`` and renders its play on
  ``mod_vector_aggregator``; a registry row that differs, a guest without the ``base`` baseline and
  the slot answered by both the module and an incumbent are refused.
* The conformance target binds the module's adapter, and the log-pipeline suite passes through it
  (the sidecar's own labelling path).
* role_lint passes the role and the lifecycle playbooks; the rendered aggregator configuration is
  valid YAML whose inputs are stamped from constants and source-set fields only.
"""

from __future__ import annotations

import copy
import shutil
import subprocess
import sys
from pathlib import Path

import jinja2
import pytest
import yaml
from jinja2 import sandbox

MODULE_CODE = Path(__file__).resolve().parents[2] / "modules" / "vector" / "python"
sys.path.insert(0, str(MODULE_CODE))  # the module's own package, as the deployment puts it

from conformance.suites import log_pipeline as suite
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint
from tests.modules.vector_addrs import GUEST_ADDR, MANAGER_ADDR

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "vector"
ROLE = MODULE / "roles" / "vector"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GUEST = GUEST_ADDR
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def manifest() -> dict:
    return ld.load_yaml(MODULE / "module.yml")


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["log-pipeline"]
    return {
        **copy.deepcopy(row),
        "host": "siem-1",
        "version": str(manifest()["product"]["version"]),
    }


def overlay(tmp: Path) -> Path:
    """A fictional overlay adopting the module: the example registry with the bound row, one guest,
    and a selection placing the module on it with every other required slot, and the object store
    it requires, an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["siem-1"] = {"address": GUEST, "zone": "mgmt", "role": "siem"}
    reg["services"]["log-pipeline"] = bound_row()
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core", "object-store": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "siem-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:siem-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 8192}\n"
        "  disks: [{name: rootfs, size_gb: 64, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:log-pipeline\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in [*REQUIRED, "object-store"]
        if slot != "log-pipeline"
    }
    sel = {
        "profile": "log-pipeline-pilot",
        "hosts": {"siem": {"guest": "guest:siem-1"}},
        "slots": {"log-pipeline": [{"provider": "vector", "instance": "log-pipeline",
                                    "placement": {"aggregator": "siem"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree
def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role_and_the_code_tree_only_its_package():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["vector"]
    assert sorted(p.name for p in (MODULE / "python").iterdir()) == ["hnx_modules"]
    assert sorted(p.name for p in (MODULE / "python" / "hnx_modules").iterdir()) == ["vector"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert [c["file"] for c in manifest()["contributes"]["roles"]] == ["roles/vector"]


def test_the_manifest_fills_the_slot_with_its_own_adapter_and_has_no_egress_or_public_row():
    m = manifest()
    slot = m["provides"]["slots"]["log-pipeline"]
    assert slot["adapter"] == "hnx_modules.vector.log_pipeline:make"
    assert slot["formats"] == [{"format": "ocsf", "version": "1.3.0"}]
    assert (MODULE / slot["conformance"]["target"]).is_file()
    assert m["egress"] == "none"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["log-pipeline"]
    assert "public_hostname" not in row and "version" not in row
    assert {c["cap"] for c in m["requires"]["capabilities"]} == {"cap:secrets", "cap:object-store"}


def test_every_secret_is_in_the_modules_own_namespace_and_the_role_defaults_name_them_by_reference():
    refs = {c["secret"] for c in manifest()["credentials"]}
    assert refs == {"secret:vector/s3-access-key", "secret:vector/s3-secret-key",
                    "secret:vector/tls-cert", "secret:vector/tls-key"}  # fmt: skip
    d = ld.load_yaml(ROLE / "defaults" / "main.yml")
    named = {v for k, v in d.items() if k.endswith("_ref") and v}
    assert named == refs


@pytest.mark.parametrize("var", ["vector_image", "vector_sidecar_image"])
def test_both_images_are_pinned_by_digest(var):
    image = ld.load_yaml(ROLE / "defaults" / "main.yml")[var]
    repo_tag, digest = image.split("@")
    assert digest.startswith("sha256:") and len(digest) == 71
    assert not repo_tag.endswith(":latest")


def test_the_aggregator_image_is_the_product_version():
    image = ld.load_yaml(ROLE / "defaults" / "main.yml")["vector_image"]
    assert image.split("@")[0].rsplit(":", 1)[1].startswith(str(manifest()["product"]["version"]))


def test_pin_freshness_watches_both_images():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert {"role:vector/vector_image", "role:vector/vector_sidecar_image"} <= ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []


# ----------------------------------------------------------------------------- an overlay
def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{manifest()['id']}_aggregator"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/vector/roles/vector")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {
        "hnx_module_slice": f"hnx-{manifest()['id']}-aggregator.slice"
    }
    assert (dest / "checks" / "vector.yml").is_file()


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["log-pipeline"]["port"] = 6515
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.log-pipeline.port" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "siem-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


def test_the_slot_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["log-pipeline"] = {"service": "log-pipeline", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.log-pipeline: the slot is also selected under slots" in out, (
        out
    )


# ----------------------------------------------------------------------------- conformance
def test_the_target_binds_the_modules_adapter_and_the_suite_passes_through_it():
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("log-pipeline")
    assert binding.adapter == "hnx_modules.vector.log_pipeline:make"
    results = run_checks(suite.SUITE, make_factory(binding, root=ROOT))
    assert [r.check for r in results if r.status != "pass"] == []


# ----------------------------------------------------------------------------- lint and config
def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


def render_config(**over) -> dict:
    v = ld.load_yaml(ROLE / "defaults" / "main.yml")
    v.update(ld.load_yaml(ROLE / "vars" / "main.yml"))
    v.update(vector_siem_syslog_host="192.0.2." "50", vector_s3_endpoint="http://192.0.2." "60:3900",
             vector_s3_region="region-a", vector_s3_bucket="staging-bucket", **over)  # fmt: skip
    env = sandbox.SandboxedEnvironment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["to_json"] = lambda x: __import__("json").dumps(x)
    env.filters["bool"] = bool
    text = env.from_string((ROLE / "templates" / "vector.yaml.j2").read_text()).render(**v)
    return yaml.safe_load(text)


def test_every_input_is_stamped_from_constants_and_source_set_fields_only():
    cfg = render_config()
    stamps = {k: t for k, t in cfg["transforms"].items() if k.startswith("stamp_")}
    assert set(stamps) == {"stamp_syslog_udp", "stamp_syslog_tls", "stamp_sensors",
                           "stamp_siem_alerts", "stamp_siem_archives"}  # fmt: skip
    for name, t in stamps.items():
        src = t["source"]
        assert '"route": "' in src, name  # the route is a constant of the configuration
        # the only fields read are the source's own: the peer (.host), the raw text (.message)
        # and, for the sensors' structured events, the whole event as the body, never a field of it
        for bad in (".source_ip", ".peer", ".route", ".observed", ".agent", ".labels"):
            assert bad not in src, (name, bad)
    sent = set(cfg["sinks"]["to_sidecar"]["inputs"])
    assert sent == set(stamps), "every input goes through the sidecar, and nothing else does"
    assert cfg["sinks"]["to_sidecar"]["buffer"] == {
        "type": "disk",
        "max_size": 1073741824,
        "when_full": "block",
    }
    assert cfg["sinks"]["stage"]["inputs"] == ["unwrap"]  # only what the sidecar emitted is staged
    assert cfg["sources"]["from_sidecar"]["path"].startswith("/run/")


def test_the_raw_syslog_goes_on_unchanged_to_the_managers_input():
    cfg = render_config()
    assert cfg["sinks"]["siem_syslog"]["inputs"] == ["raw_syslog"]
    assert cfg["transforms"]["raw_syslog"]["inputs"] == ["syslog_udp", "syslog_tls"]
    assert cfg["sinks"]["siem_syslog"]["address"] == f"{MANAGER_ADDR}:5514"
    assert cfg["sinks"]["siem_syslog"]["encoding"] == {"codec": "text"}
    tcp = render_config(vector_siem_syslog_protocol="tcp")["sinks"]["siem_syslog"]
    assert tcp["mode"] == "tcp" and tcp["framing"] == {"method": "newline_delimited"}


def test_the_staging_sink_writes_one_prefix_per_table_gzipped_and_drops_its_routing_field():
    stage = render_config()["sinks"]["stage"]
    assert stage["key_prefix"] == "lake-writer/staging/{{ _hnx_table }}/dt=%Y-%m-%d/hour=%H/"
    assert stage["compression"] == "gzip" and stage["encoding"]["except_fields"] == ["_hnx_table"]
    assert stage["buffer"]["when_full"] == "block"  # it never drops


def test_the_sensor_listener_asks_for_a_client_certificate_only_when_given_a_ca():
    plain = render_config()["sources"]["sensors"]["tls"]
    assert plain["enabled"] is True and "ca_file" not in plain
    mtls = render_config(vector_sensor_ca_ref="secret:vector/sensor-ca")["sources"]["sensors"][
        "tls"
    ]
    assert mtls["verify_certificate"] is True and mtls["ca_file"].endswith("sensor-ca.pem")
    assert "tls" not in render_config(vector_sensor_tls=False)["sources"]["sensors"]


def test_the_manager_contract_defaults_are_pinned():
    d = ld.load_yaml(ROLE / "defaults" / "main.yml")
    assert d["vector_siem_logs_gid"] == 999  # the manager's group
    assert d["vector_siem_alerts_file"] == "alerts/alerts.json"
    assert d["vector_siem_archives_file"] == "archives/archives.json"
    assert d["vector_siem_syslog_port"] == 5514 and d["vector_siem_syslog_protocol"] == "udp"
    assert d["vector_siem_logs_dir"] == ""  # the site names the manager's logs directory
    cfg = render_config()
    inc = cfg["sources"]["siem_alerts"]["include"] + cfg["sources"]["siem_archives"]["include"]
    assert inc == ["/var/siem-logs/alerts/alerts.json", "/var/siem-logs/archives/archives.json"]


def test_the_staging_layout_is_one_helper_and_the_sink_renders_it():
    from hnx_modules.vector import ocsf

    d = ld.load_yaml(ROLE / "defaults" / "main.yml")
    assert (d["vector_s3_bucket"], d["vector_s3_prefix"]) == ("soc-staging", "lake-writer/staging/")
    assert ocsf.staging_prefix(d["vector_s3_prefix"], "detection_finding") == (
        "lake-writer/staging/detection_finding/dt=%Y-%m-%d/hour=%H/"
    )
    sink = render_config(vector_s3_prefix=d["vector_s3_prefix"])["sinks"]["stage"]["key_prefix"]
    assert sink == ocsf.staging_prefix(d["vector_s3_prefix"], "{{ _hnx_table }}")
