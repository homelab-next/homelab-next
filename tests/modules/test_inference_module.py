# SPDX-License-Identifier: Apache-2.0
"""The inference provider module (the one in ``modules/`` whose slot adapter is the shared
single-server adapter; its README.md names the product): one model on one GPU behind the gateway.

* The public tree loads clean, the module has no egress, no public row and a port an unprivileged
  process may bind; the pinned image is the product version, 14 days old at least and a digest, for
  each backend.
* A fictional overlay that places it on a guest with a GPU resource (every other required core slot
  an incumbent) passes ``hnx modules check --overlay`` and renders ``modules.yml`` and its check
  playbook on the host group; a registry row that differs from the module's, a guest without the
  ``server`` baseline and a GPU the host does not name are refused.
* The conformance target binds the shared adapter; the inference suite passes through it against
  the library's fake, and against an engine that serves one model and answers any id every check
  passes but ``unknown-model-rejected``, which is what the README says.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conformance.fakes.openai_server import LOOPBACK, FakeOpenAIServer
from conformance.suites import inference as inference_suite
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.adapters.openai_compat import InferenceError
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint
from tests.modules.single_model_server import SingleModelServer

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = "homelabnext.conform.adapters.inference_server:make"


def _find() -> Path:
    """The provider this file pins: the module the environment names (HNX_INFERENCE_MODULE; default
    the one provider that runs a published image, i.e. has no image/Dockerfile). The slot has more than one
    provider; each one's own facts have their own test file."""
    hits = [
        p.parent
        for p in sorted((ROOT / "modules").glob("*/module.yml"))
        if ld.load_yaml(p).get("provides", {}).get("slots", {}).get("inference", {}).get("adapter")
        == ADAPTER
    ]
    assert hits, hits
    prebuilt = [h for h in hits if not (h / "image" / "Dockerfile").is_file()]
    assert len(prebuilt) == 1, (
        prebuilt
    )  # the default provider runs a published image; the lab-built one is named by the environment
    want = os.environ.get("HNX_INFERENCE_MODULE", prebuilt[0].name)
    (hit,) = [h for h in hits if h.name == want]
    return hit


MODULE = _find()
MID = MODULE.name
ROLE = MODULE / "roles" / MID
FIXTURES = Path(__file__).resolve().parent / "fixtures"
# the guest's address is the next one after a host the example registry carries (no literal of our own)
_infer = ipaddress.ip_address(
    ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["infer-core"]["address"]
)
GUEST = str(_infer + 1)
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip
BACKENDS = {
    "vulkan": "server-vulkan-",
    "sycl": "server-intel-",
    "cuda": "server-cuda-",
    "cpu": "server-",
}


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def manifest() -> dict:
    return ld.load_yaml(MODULE / "module.yml")


def bound_row() -> dict:
    """The module's row as the overlay copies it: the guest as host and the product's version."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["inference"]
    return {**copy.deepcopy(row), "host": "gpu-1", "version": str(manifest()["product"]["version"])}


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["gpu-1"] = {"address": GUEST, "zone": "compute", "role": "inference"}
    reg["services"]["inference"] = bound_row()
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
    (lab / "guests" / "gpu-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:gpu-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 16}\n  memory: {size_mb: 65536}\n"
        "  disks: [{name: rootfs, size_gb: 64, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: compute, ip: {GUEST}}}\n"
        "capability: cap:inference\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [server]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot != "inference"
    }
    sel = {
        "profile": "inference-pilot",
        "hosts": {"gpu-box": {"guest": "guest:gpu-1", "resources": [{"name": "gpu0", "kind": "gpu"}]}},
        "slots": {"inference": [{"provider": MID, "instance": "inference",
                                 "placement": {"server": "gpu-box"}}]},
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


@pytest.mark.static
def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


@pytest.mark.static
def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    assert [c["file"] for c in manifest()["contributes"]["roles"]] == [f"roles/{MID}"]


def test_the_manifest_has_no_egress_and_no_public_row_and_an_unprivileged_port():
    m = manifest()
    assert m["egress"] == "none"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["inference"]
    assert "public_hostname" not in row and "version" not in row
    assert row["auth"] == "none" and row["capability"] == "inference"
    assert row["health"] == {"kind": "http", "path": "/health", "expect_status": 200}
    assert row["metrics"] == {"path": "/metrics"}
    assert row["port"] >= 1024
    defaults = ld.load_yaml(ROLE / "defaults" / "main.yml")
    assert defaults[f"{MID}_port"] == row["port"]  # the row and the role publish one port


def test_the_footprint_names_one_exclusive_gpu_and_no_gpu_memory():
    """A role with gpu_memory_mb cannot be placed on a guest host (guest_hosts.py); the claim on
    the card is the exclusive resource."""
    (host,) = manifest()["requires"]["hosts"]
    fp = host["footprint"]
    assert fp["resources"] == [{"kind": "gpu", "exclusive": True}]
    assert "gpu_memory_mb" not in fp and host["kind"] == "vm"


def test_the_image_pin_is_the_product_version_a_digest_and_old_enough():
    defaults = ld.load_yaml(ROLE / "defaults" / "main.yml")
    image = defaults[f"{MID}_image"]
    repo_tag, digest = image.split("@")
    tag = repo_tag.rsplit(":", 1)[1]
    build = re.fullmatch(r"server-vulkan-b([0-9]+)", tag)
    assert build and defaults[f"{MID}_backend"] == "vulkan"
    assert manifest()["product"]["version"] == f"0.{build.group(1)}.0"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)


@pytest.mark.static
def test_the_readme_lists_each_backends_pinned_image_of_the_same_build():
    defaults = ld.load_yaml(ROLE / "defaults" / "main.yml")
    build = defaults[f"{MID}_image"].split("@")[0].rsplit("-b", 1)[1]
    readme = (MODULE / "README.md").read_text()
    for backend, prefix in BACKENDS.items():
        m = re.search(rf"\| `{backend}`[^|]*\| `([^`]+)` \|", readme)
        assert m, backend
        repo_tag, digest = m.group(1).split("@")
        assert repo_tag.rsplit(":", 1)[1] == f"{prefix}b{build}", backend
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest), backend


def test_the_default_model_digest_is_the_hash_of_its_one_line_listing():
    """The entry digest is sha256 of "<file sha256>  <path>\\n" (docs/model-serving.md); the file's
    sha256 is the one the hub reports for the pinned revision (its LFS metadata, 2026-11-16)."""
    import hashlib

    d = ld.load_yaml(ROLE / "defaults" / "main.yml")
    file_sha = "06a819954debafc9664ac6bf3898818185d21d7efe36d0f01009d9958bf6e1fd"
    listing = f"{file_sha}  {d[f'{MID}_model_file']}\n"
    assert d[f"{MID}_model_digest"] == "sha256:" + hashlib.sha256(listing.encode()).hexdigest()


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_gpu_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert "0 problem(s)" in out.rstrip().splitlines()[-1]
    assert f"{MID}/server on gpu-box: egress: none is NOT enforced: the role runs containers" in out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    group = f"mod_{MID}_server"
    plays = [p for p in books if p["hosts"] == group]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{MID}")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert (dest / "checks" / f"{MID}.yml").is_file()
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{MID}-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["inference"]["port"] = 8000
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert f"registry: services.inference.port: {MID} (instance inference) contributes 8001" in out


def test_a_guest_without_the_server_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "gpu-1.yml"
    g.write_text(g.read_text().replace("names: [server]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "server" in out, out


def test_a_host_that_names_no_gpu_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    del sel["hosts"]["gpu-box"]["resources"]
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "no gpu named" in out, out


def test_the_slot_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["inference"] = {"service": "inference", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.inference: the slot is also selected under slots" in out, out


# ----------------------------------------------------------------------------- conformance


def _target_factory(**env_free):
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("inference")
    assert binding.adapter == ADAPTER
    assert binding.config == {"features": ["streaming"]}
    return make_factory(binding, root=ROOT)


def test_the_target_matches_the_slot_entry():
    slot = manifest()["provides"]["slots"]["inference"]
    target = ld.load_yaml(MODULE / "conformance" / "target.yml")
    entry = target["capabilities"]["inference"]
    assert entry["adapter"] == slot["adapter"] and entry["features"] == slot["features"]
    assert "http" not in yaml.safe_dump(target["capabilities"])  # an endpoint is never in the file


def test_the_inference_suite_passes_through_the_target_against_the_library_fake(monkeypatch):
    with FakeOpenAIServer(models=["served"]) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_INFERENCE", srv.url)
        results = run_checks(inference_suite.SUITE, _target_factory())
    assert sorted(r.check for r in results if r.status == "fail") == []
    assert any(r.check == "stream-matches-completion" and r.status == "pass" for r in results)


def test_an_engine_that_answers_any_model_id_fails_only_unknown_model_rejected(monkeypatch):
    """The documented finding: the engine never rejects another id, the gateway does."""
    with SingleModelServer(model="served") as srv:
        monkeypatch.setenv("HNX_ENDPOINT_INFERENCE", srv.url)
        results = run_checks(inference_suite.SUITE, _target_factory())
    failed = sorted(r.check for r in results if r.status == "fail")
    assert failed == ["unknown-model-rejected"], results
    passed = {r.check for r in results if r.status == "pass"}
    assert {"models-lists-the-served-model", "chat-returns-text", "stream-matches-completion",
            "deterministic-at-temperature-zero"} <= passed  # fmt: skip


def test_the_adapter_has_no_default_endpoint(monkeypatch):
    monkeypatch.delenv("HNX_ENDPOINT_INFERENCE", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_INFERENCE"):
        _target_factory()()


def test_the_adapter_refuses_an_unknown_feature(monkeypatch):
    from homelabnext.conform.adapters import inference_server

    monkeypatch.setenv("HNX_ENDPOINT_INFERENCE", f"http://{LOOPBACK}:9")
    with pytest.raises(AdapterConfigError, match="not inference features"):
        inference_server.make(features=["telepathy"])


def test_a_keyed_server_gets_the_key_from_the_environment_at_every_call(monkeypatch):
    from homelabnext.conform.adapters import inference_server

    with FakeOpenAIServer(models=["served"], api_keys=["k-secret"]) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_INFERENCE", srv.url)
        monkeypatch.setenv("HNX_SECRET_ENGINE_KEY", "k-secret")
        client = inference_server.make(key="secret:engine/key", model="served")
        assert client.models() == ["served"] and client.model == "served"
        monkeypatch.setenv("HNX_SECRET_ENGINE_KEY", "rotated")
        with pytest.raises(InferenceError) as refused:
            client.models()
        assert refused.value.status == 401
        monkeypatch.delenv("HNX_SECRET_ENGINE_KEY")
        with pytest.raises(AdapterConfigError, match="HNX_SECRET_ENGINE_KEY"):
            client.models()


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
