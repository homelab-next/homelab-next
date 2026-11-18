# SPDX-License-Identifier: Apache-2.0
"""The LLM gateway provider module, ``modules/gateway`` (modules/gateway/README.md).

* The public tree loads clean, ``roles/`` holds only its one contributed role, every secret is in
  the module's own namespace, the row is internal (no public route) and a provider's row takes
  its version from the product.
* Its egress is one declared target (``internet``, for the cloud provider) on its one host role.
* It runs the lab's own gateway, built by ``image/Dockerfile`` from this repository: every base
  image pinned by digest, the runtime image empty of a shell, the binary the one the CI
  conformance job runs; the role has no default image (there is no published one to pin) and
  accepts an image only from the repositories the site lists (default: the build's own).
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders a play on ``mod_gateway_server``; a registry
  row that differs, a guest without the ``base`` baseline and an inference slot answered by both
  the module and an incumbent are refused.
* The conformance target binds the shared gateway adapter with the features the module proves
  without spending at a cloud provider, which are a subset of what CI proves against the same
  source (``compose/lab-in-a-box/targets/inference-own-gateway.yml``), and names every key it
  reads in the module's own namespace.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "gateway"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row() -> dict:
    """The module's row as the overlay copies it: the instance's name, the guest as host and the
    product's version."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["inference"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "apps-1", "version": version}


def overlay(tmp: Path) -> Path:
    """A fictional overlay adopting the module: the example registry with the bound row in place
    of the example's own gateway and engine rows, one guest, and a selection placing the module on
    it with every other required core slot an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    guest = str(ipaddress.ip_address(reg["hosts"]["mon-core"]["address"]) + 100)  # a free neighbour
    reg["hosts"]["apps-1"] = {"address": guest, "zone": "mgmt", "role": "apps"}
    for name in ("inference", "llm-gateway"):
        reg["services"].pop(name)
    reg["services"]["llm-gateway"] = bound_row()
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
    (lab / "guests" / "apps-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:apps-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 240, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 32, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {guest}}}\n"
        "capability: cap:inference\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot != "inference"
    }
    sel = {
        "profile": "gateway-pilot",
        "hosts": {"apps": {"guest": "guest:apps-1"}},
        "slots": {"inference": [{"provider": "gateway", "instance": "llm-gateway",
                                 "placement": {"server": "apps"}}]},
        "grants": {"egress": {"gateway": {"server": ["internet"]}}},
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


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["gateway"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/gateway"]


def test_every_secret_is_in_the_modules_own_namespace_and_the_telemetry_key_is_granted_only():
    manifest = ld.load_yaml(MODULE / "module.yml")
    creds = {c["secret"]: c for c in manifest["credentials"]}
    assert creds and all(s.split("/")[0] == "secret:gateway" for s in creds)
    assert creds["secret:gateway/key-telemetry-reader"]["holder"] == "granted"
    assert creds["secret:gateway/master-key"]["holder"] == "provider"
    assert creds["secret:gateway/key-caller"]["holder"] == "consumers"  # one key per caller


def test_the_one_egress_is_the_cloud_provider_on_the_one_host_role():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == [
        {"host": "server", "to": ["internet"], "purpose": manifest["egress"][0]["purpose"]}
    ]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["inference"]
    assert "public_hostname" not in row and row["auth"] == "own"
    assert "version" not in row  # a provider's row takes product.version
    assert row["port"] == 4100 and row["health"]["path"] == "/healthz"


def test_the_slot_features_are_the_ones_the_target_proves():
    manifest = ld.load_yaml(MODULE / "module.yml")
    slot = manifest["provides"]["slots"]["inference"]
    target = ld.load_yaml(MODULE / slot["conformance"]["target"])["capabilities"]["inference"]
    assert slot["adapter"] == target["adapter"] == "homelabnext.conform.adapters.llm_gateway:make"
    assert slot["features"] == target["features"]


# ----------------------------------------------------------------------------- the image


def _dockerfile() -> list[str]:
    return [ln for ln in (MODULE / "image" / "Dockerfile").read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]  # fmt: skip


def test_every_base_image_is_pinned_by_digest_and_the_runtime_has_no_shell():
    froms = [ln for ln in _dockerfile() if ln.startswith("FROM ")]
    assert len(froms) == 2
    build, runtime = froms
    assert re.fullmatch(r"FROM [^@ ]+:[^@ ]+@sha256:[0-9a-f]{64} AS build", build), build
    assert "latest" not in build
    assert runtime == "FROM scratch"  # nothing in it but what the next lines copy
    copies = [ln for ln in _dockerfile() if ln.startswith("COPY --from=build")]
    assert [c.split()[-1] for c in copies] == [
        "/etc/ssl/certs/ca-certificates.crt", "/usr/local/bin/llm-gateway",
        "/usr/local/bin/healthcheck",
    ]  # fmt: skip


def test_the_image_runs_the_gateway_binary_as_an_unprivileged_user():
    lines = _dockerfile()
    assert any("go build" in ln and "./cmd/gateway" in ln for ln in lines)
    assert 'ENTRYPOINT ["/usr/local/bin/llm-gateway"]' in lines
    user = next(ln for ln in lines if ln.startswith("USER "))
    assert int(user.split()[1].split(":")[0]) >= 1000
    # the Go the image builds with is the one CI builds the conformance binary with
    go = re.search(r"golang:(\d+\.\d+\.\d+)", "\n".join(lines)).group(1)
    assert f"go {go}" in (ROOT / "orchestrator" / "go.mod").read_text()


def test_the_role_has_no_default_image_and_accepts_only_the_labs_own_repository():
    defaults = ld.load_yaml(MODULE / "roles" / "gateway" / "defaults" / "main.yml")
    assert "gateway_image" not in defaults  # an own build: there is no published image to pin
    spec = yaml.safe_load(
        (MODULE / "roles" / "gateway" / "meta" / "argument_specs.yml").read_text()
    )
    assert spec["argument_specs"]["main"]["options"]["gateway_image"]["required"] is True
    # the default repository is the one the image builder's own tag names, never a registry's
    assert defaults["gateway_build_repositories"] == ["localhost/hnx-llm-gateway"]


def test_the_lifecycle_playbooks_target_the_module_group():
    for name in ("install", "upgrade", "remove"):
        (play,) = yaml.safe_load((MODULE / "playbooks" / f"{name}.yml").read_text())
        assert play["hosts"] == "mod_gateway_server" and play["become"] is True


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_gateway_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    # its container is on a bridge network: the egress policy cannot be enforced, and check says so
    assert "gateway/server on apps: egress to internet is NOT enforced" in out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_gateway_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/gateway/roles/gateway")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": "hnx-gateway-server.slice"}
    assert (dest / "limits" / "apps" / "hnx-gateway-server.slice").is_file()


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["llm-gateway"]["port"] = 8080
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert (
        "registry: services.llm-gateway.port: gateway (instance llm-gateway) contributes 4100"
        in out
    )


def test_a_row_that_gains_a_public_route_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["llm-gateway"]["public_hostname"] = "llm.example.internal"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "public_hostname" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "apps-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


def test_inference_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["inference"] = {"service": "llm-gateway", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.inference: the slot is also selected under slots" in out, out


# ----------------------------------------------------------------------------- conformance


def test_the_target_binds_the_gateway_adapter_with_keys_in_the_modules_namespace():
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("inference")
    assert binding.adapter == "homelabnext.conform.adapters.llm_gateway:make"
    config = binding.config
    secrets = [v for v in config.values() if isinstance(v, str) and v.startswith("secret:")]
    assert secrets and all(s.split("/")[0] == "secret:gateway" for s in secrets)
    assert config["throttle_requests"] == 3 and config["capability"] == "inference"
    # the factory needs the lab's role table (a path of the lab's checkout): without it, a clear error
    from homelabnext.conform.adapters._env import AdapterConfigError

    with pytest.raises((AdapterConfigError, OSError, ValueError)):
        make_factory(binding, root=ROOT)()


def test_the_target_proves_a_subset_of_what_ci_proves_against_the_same_source():
    module = ld.load_yaml(MODULE / "conformance" / "target.yml")["capabilities"]["inference"]
    ci = ld.load_yaml(ROOT / "compose" / "lab-in-a-box" / "targets" / "inference-own-gateway.yml")[
        "capabilities"
    ]["inference"]
    assert module["adapter"] == ci["adapter"]
    assert set(module["features"]) <= set(ci["features"])
    # no feature that calls the role leaving the lab: a run against a lab spends nothing there
    assert not {"tlp-ceiling", "tlp-admit"} & set(module["features"])
    assert not {"over_ceiling_key", "tlp_sender_key", "tlp_model"} & set(module["config"])


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "gateway")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
