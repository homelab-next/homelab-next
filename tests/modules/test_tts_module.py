# SPDX-License-Identifier: Apache-2.0
"""The speech provider module, ``modules/tts`` (modules/tts/README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: no credentials and no egress, a provisional slot with the
  voice as its data, a row with no key and no public route, the operator's 200 W rule and the idle
  unload among the role defaults, and a model store entry that is valid for the store, pinned by
  revision and digest, whose digest is the one the role defaults name.
* A fictional overlay that places it on a guest checks clean and renders ``modules.yml`` on
  ``mod_tts_server``; a registry row that differs and a guest without the ``server`` baseline are refused.
* The module's own probe reads its endpoints from the resolved endpoint only.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.models import store as model_store
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint
from tests.modules.tts_front import Server

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "tts"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
REQUIRED = sorted(
    s
    for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)
DEFAULTS = ld.load_yaml(MODULE / "roles" / "tts" / "defaults" / "main.yml")


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def _args(ov: Path) -> list[str]:
    return [
        "--root", str(ROOT), "--overlay", str(ov),
        "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
        "--mcp-catalog", str(ROOT / "examples" / "mcp"),
    ]  # fmt: skip


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["tts"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {
        **copy.deepcopy(row),
        "host": "tts-1",
        "version": version,
    }


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["tts-1"] = {"address": GUEST, "zone": "mgmt", "role": "tts"}
    reg["services"]["tts-instance"] = bound_row()
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
    (lab / "guests" / "tts-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:tts-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 8}\n  memory: {size_mb: 16384}\n"
        "  disks: [{name: rootfs, size_gb: 40, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:tts\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [server]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "tts-pilot",
        "hosts": {"tts": {"guest": "guest:tts-1"}},
        "slots": {"tts": [{"provider": "tts", "instance": "tts-instance", "placement": {"server": "tts"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


def overlay_row(ov: Path) -> dict:
    return ld.load_yaml(ov / "lab" / "services.yml")["services"]["tts-instance"]


# ----------------------------------------------------------------------------- the public tree


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["tts"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/tts"]


def test_the_manifest_holds_no_credential_and_no_egress_and_keeps_the_voice_as_data():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["credentials"] == [] and manifest["egress"] == "none"
    assert manifest["provides"]["slots"]["tts"]["provisional"] is True
    (data,) = manifest["data"]
    assert data["id"] == "voice" and data["export"]["via"] == "role:tts"
    assert manifest["lifecycle"]["remove"]["export_first"] is True  # the recordings are the voice
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["tts"]
    assert row["auth"] == "none" and row["port"] == 8091 and row["health"]["path"] == "/health"
    assert "public_hostname" not in row and "version" not in row


def test_the_role_defaults_keep_the_operators_rules():
    assert DEFAULTS["tts_power_cap_max_watts"] == 200  # the 200 W precondition
    assert (
        DEFAULTS["tts_backend"] == "cpu" and DEFAULTS["tts_idle_unload_s"] == ""
    )  # 0 cpu, 120 cuda
    assert DEFAULTS["tts_build_repositories"] == ["localhost/hnx-tts"]
    assert (
        "tts_image" not in DEFAULTS
    )  # there is no published image to pin: the site names its build
    assert len(DEFAULTS["tts_voice_files"]) == 4  # ref1.wav to ref4.wav, as the old service


def test_the_module_ships_a_voice_model_entry_that_is_valid_and_is_the_one_pinned():
    doc = json.loads(
        (ROOT / "schemas" / "platform" / "examples" / "model_store.speech.json").read_text()
    )
    store = model_store.Store.from_dict(
        doc
    )  # valid for the store: pinned revision, a sha256 per file
    (entry,) = store.entries.values() if isinstance(store.entries, dict) else store.entries
    assert entry.digest == DEFAULTS["tts_model_digest"]
    assert doc["models"]["xtts-v2"]["source"]["revision"] == DEFAULTS["tts_model_revision"]
    assert (
        entry.engines == ("tts-server",)
        and doc["models"]["xtts-v2"]["license"] == "coqui-public-model-license"
    )
    from homelabnext.tts_service.gates import REQUIRED_MODEL_FILES

    assert set(REQUIRED_MODEL_FILES) <= {f["path"] for f in doc["models"]["xtts-v2"]["files"]}


def test_the_dockerfile_pins_its_base_by_digest_and_installs_only_hashed_requirements():
    text = (MODULE / "image" / "Dockerfile").read_text()
    from_line = next(line for line in text.splitlines() if line.startswith("FROM "))
    assert "@sha256:" in from_line and len(from_line.split("@sha256:")[1]) == 64
    assert "--require-hashes" in text and "--no-deps" in text
    assert "HF_HUB_OFFLINE=1" in text and "TRANSFORMERS_OFFLINE=1" in text
    for backend in ("cpu", "cuda"):
        req = (MODULE / "image" / f"requirements-{backend}.txt").read_text()
        pins = [x for x in req.splitlines() if "==" in x and not x.startswith((" ", "#"))]
        # every pinned package carries at least one hash on the lines that follow it
        assert pins and req.count("--hash=sha256:") >= len(pins)
        assert all(x.rstrip().endswith("\\") or "--hash=sha256:" in x for x in pins)


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
    plays = [p for p in books if p["hosts"] == "mod_tts_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/tts/roles/tts")
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": "hnx-tts-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["tts-instance"]["port"] = 8092
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.tts-instance.port" in out, out


def test_a_guest_without_the_server_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "tts-1.yml"
    g.write_text(g.read_text().replace("names: [server]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "server" in out, out


def test_a_public_route_is_refused(tmp_path, capsys):
    """The module has no public route: a site cannot grant one it does not declare."""
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["grants"] = {"public_routes": {"tts": ["tts"]}}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_health_readiness_and_one_render_from_the_resolved_endpoint(monkeypatch):
    from homelabnext.conform.adapters.tts import make

    monkeypatch.delenv("HNX_ENDPOINT_TTS", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_TTS"):
        make()  # no default endpoint
    with Server() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_TTS", "http://{}:{}".format(*srv.addr))
        probe = make()
        assert probe.health()["status"] == "ok" and probe.ready()
        out = probe.synthesize("A short test.")
        assert out["sample_rate"] == 24000 and out["channels"] == 1 and out["sample_width"] == 2
        assert srv.paths == ["GET /health", "GET /ready", "POST /synthesize"]
    probe.close()


def test_the_probe_reports_a_service_that_is_not_ready(monkeypatch):
    from homelabnext.conform.adapters.tts import make

    with Server(ready=False) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_TTS", "http://{}:{}".format(*srv.addr))
        assert make().ready() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "tts")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
