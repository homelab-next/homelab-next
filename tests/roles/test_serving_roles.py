# SPDX-License-Identifier: Apache-2.0
"""The model-serving roles (ADR-0023, docs/model-serving.md): model_store, vllm_server and
open_webui, run on localhost against fakes (CI is unprivileged).

* model_store fetches from a fake ``hf`` that serves a local "remote" tree in the hub-cache layout
  (blobs plus snapshot symlinks) or a ``--local-dir``; every file is checked by sha256.
* vllm_server writes its units into a temporary directory, drives a fake ``systemctl`` and asks a
  fake ``vllm`` its version; its health hook calls the fake OpenAI server, and the verdict is held
  equal to the K-14 probe's (``homelabnext.registry.models.probe``) on the same answers.
* open_webui renders through compose_app (no docker), and its health hook reads a fake ``docker``.

Every refusal is shown failing on a bad input and passing on a good one."""

import getpass
import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from rolerun import calls, fake, first_run, logging_fake, run_cases, run_role

from conformance.fakes.openai_server import FakeOpenAIServer
from homelabnext.models import store as store_mod
from homelabnext.models.serving import load_plan
from homelabnext.registry.models import ResolvedModel, probe
from homelabnext.registry.resolver import Endpoint

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "model-serving"
pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)
# the units refuse root: as root (a container), run them as nobody; otherwise as the test's user
_ME = pwd.getpwnam("nobody") if getpass.getuser() == "root" else pwd.getpwuid(os.getuid())
USER = _ME.pw_name
GROUP = grp.getgrgid(_ME.pw_gid).gr_name


def manifest() -> dict:
    return json.loads((EXAMPLE / "model_store.json").read_text())


def content(entry_id: str, path: str) -> bytes:
    """The example store's synthetic file bodies (examples/model-serving/serving.yml)."""
    return f"fake {path} of {entry_id}\n".encode()


# ---------------------------------------------------------------- model_store
HF = r"""
import hashlib, os, shutil, sys
from pathlib import Path
open(LOG, "a").write("hf " + " ".join(sys.argv[1:]) + "\n")
a = sys.argv[1:]
if a[:1] == ["version"]:
    print("huggingface_hub version: 2.2.0"); sys.exit(0)
assert a[0] == "download", a
repo, i = a[1], a.index("--revision")
files, rev = a[2:i], a[i + 1]
src = Path(REMOTE) / repo / rev
if not src.is_dir():
    sys.exit("fake hf: no revision " + rev)
if "--cache-dir" in a:
    top = Path(a[a.index("--cache-dir") + 1]) / ("models--" + repo.replace("/", "--"))
    for f in files:
        data = (src / f).read_bytes()
        blob = top / "blobs" / hashlib.sha256(data).hexdigest()
        blob.parent.mkdir(parents=True, exist_ok=True)
        blob.write_bytes(data)
        link = top / "snapshots" / rev / f
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(os.path.relpath(blob, link.parent))
else:
    d = Path(a[a.index("--local-dir") + 1])
    for f in files:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src / f, d / f)
    (d / ".cache" / "huggingface").mkdir(parents=True, exist_ok=True)
"""


def remote_tree(tmp_path: Path, store: dict, tamper: str | None = None) -> Path:
    """What the hub would serve for every hub entry of ``store`` (``tamper``: one file changed)."""
    remote = tmp_path / "remote"
    for eid, e in store["models"].items():
        if e["format"] == "export":
            continue
        for f in e["files"]:
            p = remote / e["source"]["repo"] / e["source"]["revision"] / f["path"]
            p.parent.mkdir(parents=True, exist_ok=True)
            body = content(eid, f["path"])
            p.write_bytes(body.upper() if f["path"] == tamper else body)
    return remote


def store_vars(tmp_path: Path, store: dict, **kw) -> dict:
    body = HF.replace("LOG", repr(str(tmp_path / "calls.log")))
    body = body.replace("REMOTE", repr(str(tmp_path / "remote")))
    v = {
        "model_store_manifest": store,
        "model_store_root": str(tmp_path / "srv"),
        "model_store_hf_cli": fake(tmp_path / "hf", body),
        "model_store_owner": USER,
        "model_store_group": GROUP,
        "model_store_exports_group": GROUP,
        "model_store_export_dir": str(tmp_path / "export"),
    }
    v.update(kw)
    return v


def write_export(root: Path, store: dict) -> None:
    """An export is written by Unsloth Studio, not fetched: put the promoted one in place."""
    for eid, e in store["models"].items():
        if e["format"] == "export":
            for f in e["files"]:
                p = root / "exports" / e["source"]["run"] / f["path"]
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content(eid, f["path"]))


@pytest.fixture(scope="module")
def fetched_store(tmp_path_factory) -> Path:
    """A store ``main`` fetched from the example manifest, built once for the tests that only need
    one to start from (each takes a copy: ``fetched``).  The fetch itself is
    test_model_store_fetches_at_the_pinned_revision_and_the_store_check_passes."""
    base = tmp_path_factory.mktemp("fetched")
    store = manifest()
    remote_tree(base, store)
    r = run_role(base, "model_store", "main", store_vars(base, store))
    assert r.returncode == 0, r.stdout + r.stderr
    return base / "srv"


def fetched(tmp_path: Path, fetched_store: Path) -> dict:
    """``tmp_path/srv``: a copy of the fetched store (snapshot links copied as links); its vars."""
    shutil.copytree(fetched_store, tmp_path / "srv", symlinks=True)
    return store_vars(tmp_path, manifest())


def _first(tmp_path):
    store = manifest()
    remote_tree(tmp_path, store)
    v = store_vars(tmp_path, store)
    return {
        "role": "model_store",
        "tasks_from": "main",
        "extra_vars": v,
        "setup": {"store": store, "v": v},
    }


@first_run(_first)
def test_model_store_fetches_at_the_pinned_revision_and_the_store_check_passes(first):
    r, tmp_path = first
    store = first.setup["store"]
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    log = calls(tmp_path)
    assert len(log) == 4 and all(line.startswith("hf download ") for line in log)
    for line in log:
        argv = line.split()
        rev = argv[argv.index("--revision") + 1]
        assert len(rev) == 40 and rev != "main"  # never the CLI's default branch
    hf_line = next(x for x in log if "example-27b-fp8" in x)
    # into staging under the store root (one filesystem: the promotion is a rename), never live
    assert "--cache-dir " + str(tmp_path / "srv" / ".staging" / "example-27b-fp8") in hf_line
    gguf_line = next(x for x in log if "Q4_K_M" in x)
    assert "--local-dir " + str(tmp_path / "srv" / ".staging" / "example-4b-q4km") in gguf_line
    snap = tmp_path / "srv" / store_mod.Store.from_dict(store).entries["example-27b-fp8"].directory
    assert (snap / "config.json").is_symlink()  # the hub cache layout: blob + snapshot link
    assert (tmp_path / "srv" / "manifests" / "model_store.json").is_file()
    # sticky: a trainer may add a run to exports/, never rename or remove a promoted one
    assert oct((tmp_path / "srv" / "exports").stat().st_mode & 0o7777) == "0o3770"
    assert not (tmp_path / "srv" / ".staging").exists() or not any(
        (tmp_path / "srv" / ".staging").iterdir()
    )  # fetched into staging, verified, renamed into place
    write_export(tmp_path / "srv", store)
    st = store_mod.Store.from_dict(store)
    assert store_mod.check_disk(st, tmp_path / "srv") == []
    # idempotent: everything verified, nothing downloaded again
    (tmp_path / "calls.log").unlink()
    again = run_role(tmp_path, "model_store", "main", v)
    assert again.returncode == 0, again.stdout
    assert calls(tmp_path) == []
    # the promoted export left the trainers' write: store-owned, group read-only
    export = tmp_path / "srv" / st.entries["example-4b-triage"].directory
    for f in [export, *export.rglob("*")]:
        assert f.stat().st_mode & 0o027 == 0, (f, oct(f.stat().st_mode))
    # every entry's listing, for the engines' pre-start check, hashes to its digest
    for eid, e in st.entries.items():
        listing = (tmp_path / "srv" / "manifests" / "listings" / f"{eid}.sha256").read_bytes()
        assert "sha256:" + hashlib.sha256(listing).hexdigest() == e.digest
    assert run_role(tmp_path, "model_store", "health", v).returncode == 0
    assert run_role(tmp_path, "model_store", "verify", v).returncode == 0


def _first(tmp_path):
    store = manifest()
    remote_tree(tmp_path, store, tamper="model-00002-of-00002.safetensors")
    return {
        "role": "model_store",
        "tasks_from": "main",
        "extra_vars": store_vars(tmp_path, store),
        "setup": {"store": store},
    }


@first_run(_first)
def test_model_store_refuses_a_download_whose_sha256_is_not_the_manifests(first):
    r, tmp_path = first
    store = first.setup["store"]
    assert r.returncode != 0
    assert "model-00002-of-00002.safetensors: sha256 differs from the manifest" in r.stdout
    # verified in staging: no byte of the bad download, nor of its good siblings, reached the store
    snap = tmp_path / "srv" / store_mod.Store.from_dict(store).entries["example-27b-fp8"].directory
    assert not snap.exists() or not any(snap.iterdir())


def _floating(tmp, revision):
    store = manifest()
    store["models"]["example-4b-bf16"]["source"]["revision"] = revision
    return {"role": "model_store", "tasks_from": "main", "extra_vars": store_vars(tmp, store)}


@pytest.mark.parametrize("revision", ["main", "refs/pr/1", "174d4518", "v1.0"])
@first_run(_floating)
def test_model_store_refuses_a_floating_revision_before_running_anything(first, revision):
    r, tmp_path = first
    assert r.returncode != 0 and "must be pinned" in r.stdout, revision
    assert calls(tmp_path) == []


def _first(tmp_path):
    return {
        "role": "model_store",
        "tasks_from": "main",
        "extra_vars": store_vars(tmp_path, manifest(), model_store_fetch=False),
    }


@first_run(_first)
def test_model_store_accepts_the_pinned_example_manifest(first):
    """The good input for the refusals above and below (the same run for every parameter, so once)."""
    good, _ = first
    assert good.returncode == 0, good.stdout


@pytest.mark.parametrize(
    "over",
    [
        {"model_store_root": "relative/models"},
        {"model_store_root": "/srv/../etc"},
        {"model_store_owner": "Bad Name"},
        {"model_store_hf_endpoint": "http://mirror.example.internal"},
        {"model_store_hf_token_ref": "hf_plain-token-fake"},
        {"model_store_fetch_ids": ["not-an-entry"]},
    ],
)
@first_run(lambda tmp, over: {"role": "model_store", "tasks_from": "main",
                               "extra_vars": store_vars(tmp, manifest(), **over)})  # fmt: skip
def test_model_store_refuses_bad_settings(first, over):
    r, _ = first
    assert r.returncode != 0 and "model_store: a manifest with models" in r.stdout, over


def _first(tmp_path):
    deny = {"policy_out": "DROP", "inbound_allow": [], "outbound_allow": []}
    return {
        "runner": run_cases,
        "role": "model_store",
        "tasks_from": "validate",
        "base_vars": store_vars(tmp_path, manifest(), hnx_firewall=deny),
        "overrides": [
            {},
            {"model_store_hf_endpoint": "https://hub-mirror.example.internal"},
            {"model_store_fetch": False},
            {"hnx_firewall": {**deny, "policy_out": "ACCEPT"}},
            # the public hub's own hosts are never the mirror
            {
                "model_store_hf_endpoint": "https://huggingface.co"
            },  # scrub-allow: the public hub, refused
            {
                "model_store_hf_endpoint": "https://CDN.HuggingFace.co./models"
            },  # scrub-allow: refused
            {
                "model_store_hf_endpoint": "https://hf.co/api"
            },  # scrub-allow: the public hub, refused
            {"model_store_hf_endpoint": "https://nothf.co.example.internal"},
        ],
    }


@first_run(_first)
def test_model_store_fetches_only_through_a_mirror_on_a_default_deny_host(first):
    """A model runtime's egress is default-deny (hnx_firewall.policy_out DROP): the role never
    reaches for the public hub there, and opens no egress; the lab's mirror is the way in."""
    results, _ = first
    assert results[0][0] and "the public hub is unreachable" in results[0][1]
    assert [failed for failed, _ in results[1:4]] == [False, False, False]
    assert all(f and "never the public hub" in m for f, m in results[4:7]), results[4:7]
    assert results[7][0] is False


def _first(tmp_path):
    store = manifest()
    store["models"]["example-4b-bf16"]["files"][0]["path"] = "../../escape.json"
    return {"role": "model_store", "tasks_from": "main", "extra_vars": store_vars(tmp_path, store)}


@first_run(_first)
def test_model_store_refuses_a_file_path_that_leaves_its_entry(first):
    r, _ = first
    assert r.returncode != 0 and "must be pinned" in r.stdout


def _first(tmp_path):
    store = manifest()
    remote_tree(tmp_path, store)
    hf = logging_fake(tmp_path, "hf-env")
    body = (
        "import os, sys\nopen({!r}, 'a').write(os.environ.get('HF_TOKEN', '') + '|' + "
        "os.environ.get('HF_ENDPOINT', '') + '\\n')\nos.execv({!r}, [{!r}] + sys.argv[1:])\n"
    ).format(str(tmp_path / "env.log"), str(tmp_path / "hf"), str(tmp_path / "hf"))
    v = store_vars(tmp_path, store, model_store_hf_token_ref="secret:models/hub-token",
                   model_store_hf_endpoint="https://hub-mirror.example.internal",
                   model_store_fetch_ids=["example-4b-q4km"])  # fmt: skip
    v["model_store_hf_cli"] = fake(Path(hf).with_name("hf-wrap"), body)
    env = {"HNX_SECRET_MODELS_HUB_TOKEN": "hub-token-fake"}
    return {"role": "model_store", "tasks_from": "main", "extra_vars": v, "env": env}


@first_run(_first)
def test_model_store_passes_the_hub_token_by_reference_only(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "env.log").read_text() == (
        "hub-token-fake|https://hub-mirror.example.internal\n"
    )
    assert "hub-token-fake" not in r.stdout  # the download task is no_log when a token is used


def test_model_store_health_is_by_size_and_verify_by_sha256(tmp_path, fetched_store):
    store = manifest()
    v = fetched(tmp_path, fetched_store)
    write_export(tmp_path / "srv", store)
    target = tmp_path / "srv" / "exports" / "2026-10-01-triage" / "model.safetensors"
    target.write_bytes(target.read_bytes().upper())  # same size, other bytes
    assert run_role(tmp_path, "model_store", "health", v).returncode == 0
    bad = run_role(tmp_path, "model_store", "verify", v)
    assert bad.returncode != 0 and "model.safetensors (sha256 differs)" in bad.stdout
    target.unlink()
    gone = run_role(tmp_path, "model_store", "health", v)
    assert gone.returncode != 0 and "model.safetensors (missing)" in gone.stdout


def test_model_store_refuses_a_snapshot_link_out_of_its_blobs(tmp_path, fetched_store):
    """The right bytes behind a link out of the store still fail: nothing manages them."""
    store = manifest()
    v = fetched(tmp_path, fetched_store)
    write_export(tmp_path / "srv", store)
    assert run_role(tmp_path, "model_store", "verify", v).returncode == 0
    snap = tmp_path / "srv" / store_mod.Store.from_dict(store).entries["example-27b-fp8"].directory
    outside = tmp_path / "outside.json"
    outside.write_bytes((snap / "config.json").read_bytes())
    (snap / "config.json").unlink()
    (snap / "config.json").symlink_to(outside)
    bad = run_role(tmp_path, "model_store", "verify", v)
    assert bad.returncode != 0 and f"config.json (links to {outside})" in bad.stdout
    assert run_role(tmp_path, "model_store", "health", v).returncode != 0


def test_model_store_backup_and_export_hooks(tmp_path):
    store = manifest()
    # codepoint order (sha256sum's, and Entry.listing's): LICENSE, README.md, config.json; a
    # case-insensitive sort would put config.json first and the listing would not hash to the digest
    store["models"]["example-4b-bf16"]["files"] += [
        {"path": "README.md", "sha256": "a" * 64, "size": 1},
        {"path": "LICENSE", "sha256": "b" * 64, "size": 1},
    ]
    v = store_vars(tmp_path, store, model_store_fetch=False)
    assert run_role(tmp_path, "model_store", "main", v).returncode == 0
    assert run_role(tmp_path, "model_store", "backup", v).returncode == 0
    b = json.loads((tmp_path / "srv" / "manifests" / "backup-manifest.json").read_text())
    assert b["paths"] == [str(tmp_path / "srv" / "exports"), str(tmp_path / "srv" / "manifests")]
    assert "example-4b-triage" not in b["refetch"] and "example-27b-fp8" in b["refetch"]
    assert run_role(tmp_path, "model_store", "export", v).returncode == 0
    st = store_mod.Store.from_dict(store)
    for eid, e in st.entries.items():
        listing = (tmp_path / "export" / f"{eid}.sha256").read_text()
        assert listing == e.listing  # sha256sum format: the digest is sha256 of this file
        assert e.digest == "sha256:" + hashlib.sha256(listing.encode()).hexdigest()
    assert run_role(tmp_path, "model_store", "readiness", v).returncode == 0


# ---------------------------------------------------------------- vllm_server
def instances(tmp_path: Path) -> list[dict]:
    """The example plan's instances, with the store root moved under ``tmp_path``."""
    doc = yaml.safe_load((EXAMPLE / "vllm_server" / "instances.yml").read_text())
    out = doc["vllm_server_instances"]
    for i in out:
        i["model_path"] = i["model_path"].replace("/srv/models", str(tmp_path / "srv"))
        Path(i["model_path"]).mkdir(parents=True, exist_ok=True)
        (Path(i["model_path"]) / "config.json").write_text("{}")
    return out


ZONE_ADDRESS = "192.0.2.10"  # no-raw-endpoint: allow a documentation address for the zone


def vllm_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "vllm_server_instances": instances(tmp_path),
        "vllm_server_exposure": yaml.safe_load(
            (EXAMPLE / "vllm_server" / "instances.yml").read_text()
        )["vllm_server_exposure"],
        "vllm_server_listen_address": ZONE_ADDRESS,
        "vllm_server_store_root": str(tmp_path / "srv"),
        "vllm_server_bin": logging_fake(tmp_path, "vllm", "0.31.0\n"),
        "vllm_server_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "vllm_server_unit_dir": str(tmp_path / "units"),
        "vllm_server_verify_bin": str(tmp_path / "hnx-model-verify"),
        "vllm_server_env_dir": str(tmp_path / "env"),
        "vllm_server_cache_dir": str(tmp_path / "cache"),
        "vllm_server_state_dir": str(tmp_path / "state"),
        "vllm_server_user": USER,
        "vllm_server_group": GROUP,
    }
    (tmp_path / "units").mkdir(exist_ok=True)
    v.update(kw)
    return v


def test_the_rendered_instances_are_the_plans():
    """The checked-in instances file is what the plan renders (the role's input is generated)."""
    from homelabnext.models.serving import render

    files = render(load_plan(EXAMPLE / "serving.yml"))
    assert files["vllm_server/instances.yml"] == (EXAMPLE / "vllm_server/instances.yml").read_text()


def _first(tmp_path):
    v = vllm_vars(tmp_path)
    return {"role": "vllm_server", "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


@first_run(_first)
def test_vllm_server_writes_one_unit_per_served_model_from_the_plan(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    units = sorted(p.name for p in (tmp_path / "units").iterdir())
    assert units == ["hnx-vllm-inference-large.service", "hnx-vllm-inference-triage.service"]
    unit = (tmp_path / "units" / "hnx-vllm-inference-large.service").read_text()
    (execstart,) = [x for x in unit.splitlines() if x.startswith("ExecStart=")]
    snap = str(tmp_path / "srv") + "/hf/hub/models--example-org--example-27b-fp8/snapshots/"
    assert execstart.split()[1:3] == ["serve", snap + "174d4518adc353b21f63bbd7186645da35935aeb"]
    for flag in ("--served-model-name example-27b", "--max-model-len 131072",
                 "--scheduling-policy priority", "--tensor-parallel-size 2",
                 "--port 8000", f"--host {ZONE_ADDRESS}", "--tool-call-parser qwen3_xml",
                 "--enable-auto-tool-choice"):  # fmt: skip
        assert f" {flag}" in execstart, flag
    assert "Environment=CUDA_VISIBLE_DEVICES=0,1\n" in unit
    assert "Environment=CUDA_DEVICE_ORDER=PCI_BUS_ID\n" in unit
    assert "Environment=HF_HUB_OFFLINE=1\n" in unit
    assert f"ReadOnlyPaths={tmp_path / 'srv'}\n" in unit
    assert "NCCL_P2P_DISABLE" not in unit and "EnvironmentFile" not in unit
    assert "User=root" not in unit and "CapabilityBoundingSet=\n" in unit
    # this instance's GPUs and nothing else: a char-nvidia-frontend rule would open every card
    allowed = [x for x in unit.splitlines() if x.startswith("DeviceAllow=")]
    assert allowed == [
        "DeviceAllow=/dev/nvidia0 rw", "DeviceAllow=/dev/nvidia1 rw",
        "DeviceAllow=/dev/nvidiactl rw", "DeviceAllow=/dev/nvidia-uvm rw",
        "DeviceAllow=/dev/nvidia-uvm-tools rw",
    ]  # fmt: skip
    assert "DevicePolicy=closed\n" in unit
    triage = (tmp_path / "units" / "hnx-vllm-inference-triage.service").read_text()
    assert "DeviceAllow=/dev/nvidia2 rw\n" in triage and "/dev/nvidia0 " not in triage
    log = calls(tmp_path)
    assert log[0] == "vllm --version"
    assert "systemctl daemon-reload" in log
    assert "systemctl restart hnx-vllm-inference-large.service" in log
    # unchanged on a second run: nothing restarted, both kept enabled and running
    (tmp_path / "calls.log").unlink()
    assert run_role(tmp_path, "vllm_server", "main", v).returncode == 0
    assert sorted(calls(tmp_path)[1:]) == [
        "systemctl enable --now hnx-vllm-inference-large.service",
        "systemctl enable --now hnx-vllm-inference-triage.service",
    ]


def _first(tmp_path):
    v = vllm_vars(tmp_path, vllm_server_verify_bin=str(tmp_path / "bin" / "hnx-model-verify"))
    (tmp_path / "bin").mkdir()
    return {"role": "vllm_server", "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


@first_run(_first)
def test_vllm_server_units_verify_the_bytes_before_every_start(first):
    """ExecStartPre runs the installed check: the store's listing must hash to the pinned digest
    and the model directory must match it, so Restart=on-failure never serves unverified bytes."""
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    unit = (tmp_path / "units" / "hnx-vllm-inference-triage.service").read_text()
    inst = v["vllm_server_instances"][1]
    (pre,) = [x for x in unit.splitlines() if x.startswith("ExecStartPre=")]
    argv = pre.removeprefix("ExecStartPre=").split()
    listing = tmp_path / "srv" / "manifests" / "listings" / "example-4b-triage.sha256"
    assert argv == [v["vllm_server_verify_bin"], str(listing), inst["digest"], inst["model_path"]]
    assert unit.index("ExecStartPre=") < unit.index("ExecStart=")
    # run it as systemd would, against a store built from the manifest
    e = store_mod.Store.from_dict(manifest()).entries["example-4b-triage"]
    for f in e.files:
        (Path(inst["model_path"]) / f.path).write_bytes(content(e.id, f.path))
    listing.parent.mkdir(parents=True, exist_ok=True)
    listing.write_text(e.listing)

    def check(digest=inst["digest"]):
        return subprocess.run([*argv[:2], digest, argv[3]], capture_output=True, text=True)

    assert check().returncode == 0, check().stderr
    assert check("sha256:" + "0" * 64).returncode == 1  # the listing is not the pinned one
    target = Path(inst["model_path"]) / e.files[0].path
    target.write_bytes(target.read_bytes().upper())  # same size, other bytes
    bad = check()
    assert bad.returncode == 1 and "refusing to serve" in bad.stderr


def _first(tmp_path):
    v = vllm_vars(tmp_path)
    stale = tmp_path / "units" / "hnx-vllm-gpu0.service"
    stale.write_text("[Service]\n")
    return {"role": "vllm_server", "tasks_from": "main", "extra_vars": v, "setup": {"stale": stale}}


@first_run(_first)
def test_vllm_server_retires_a_unit_the_plan_no_longer_has(first):
    r, tmp_path = first
    stale = first.setup["stale"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert not stale.exists()
    assert "systemctl disable --now hnx-vllm-gpu0.service" in calls(tmp_path)


def _first(tmp_path):
    v = vllm_vars(tmp_path)
    logging_fake(tmp_path, "vllm", "0.30.0\n")  # the installed one is not the pin
    return {"role": "vllm_server", "tasks_from": "main", "extra_vars": v}


@first_run(_first)
def test_vllm_server_refuses_a_vllm_that_is_not_the_pinned_one(first):
    r, tmp_path = first
    assert r.returncode != 0 and "the pin is 0.31.0" in r.stdout
    assert not any(c.startswith("systemctl") for c in calls(tmp_path))


def _first(tmp_path):
    v = vllm_vars(tmp_path)
    (Path(v["vllm_server_instances"][1]["model_path"]) / "config.json").unlink()
    return {"role": "vllm_server", "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


@first_run(_first)
def test_vllm_server_refuses_a_model_missing_from_the_store(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode != 0 and "model_store fetches and verifies it" in r.stdout
    ready = run_role(tmp_path, "vllm_server", "readiness", v)
    assert ready.returncode != 0 and "example-4b-triage" in ready.stdout


def _bad(tmp_path, field, value):
    v = vllm_vars(tmp_path)
    v["vllm_server_instances"][0][field] = value
    return v


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("served_model_name", "example 27b"),
        ("served_model_name", "example-%n"),
        ("model_path", "/etc/passwd-dir"),
        ("max_model_len", 0),
        ("port", 80),
        ("gpus", [0]),  # tp 2 x pp 1 is two GPUs
        ("args", ["--served-model-name", "other"]),
        ("args", ["--x", "a\nExecStartPre=/bin/evil"]),
        ("args", ["-tp=4"]),  # a single-dash option
        ("args", ["--tensor-parallel-size=4"]),  # an owned flag, = form
        ("args", ["--hos", "0.0.0.0"]),  # an argparse abbreviation of --host
        ("args", ["--trust-remote"]),  # an abbreviation of --trust-remote-code
        ("args", ["--trust-remote-code"]),
        ("args", ["--load-format", "dummy"]),
        ("args", ["--config", "/tmp/x.yaml"]),
        ("args", ["--allowed-local-media-path", "/"]),
        ("args", ["--middleware", "evil.mod"]),
        ("args", ["--enforce-eager", "--trust-remote-code"]),  # a value smuggled as a flag
        ("args", ["--tool-call-parser", "--trust-remote-code"]),
        ("args", ["--max-num-seqs"]),  # a value the rule needs is missing
        ("args", ["--max-num-seqs", "24\n"]),
        ("args", ["--enforce-eager", "1"]),  # a bare flag given a value
        ("digest", "sha256:abc"),
    ],
)
@first_run(lambda tmp, field, value: {"role": "vllm_server", "tasks_from": "main",
                                      "extra_vars": _bad(tmp, field, value)})  # fmt: skip
def test_vllm_server_refuses_an_edited_instance(first, field, value):
    r, _ = first
    assert r.returncode != 0 and "must be what `hnx models serving render`" in r.stdout, field


@pytest.mark.parametrize(
    ("exposure", "address", "ok"),
    [
        ("zone", ZONE_ADDRESS, True),
        ("zone", "127.0.0.1", False),  # no-raw-endpoint: allow the gateway could never reach it
        ("zone", "0.0.0.0", False),  # no-raw-endpoint: allow a wildcard is refused
        ("loopback", "127.0.0.1", True),  # no-raw-endpoint: allow loopback for bring-up
        ("loopback", ZONE_ADDRESS, False),
    ],
)
@first_run(
    lambda tmp, exposure, address, ok: {
        "role": "vllm_server",
        "tasks_from": "main",
        "extra_vars": vllm_vars(
            tmp, vllm_server_exposure=exposure, vllm_server_listen_address=address
        ),
    }
)
def test_vllm_server_holds_the_listen_address_to_the_plans_exposure(first, exposure, address, ok):
    r, _ = first
    assert (r.returncode == 0) is ok, r.stdout
    if not ok:
        assert "the plan's exposure is" in r.stdout


def _first(tmp_path):
    v = vllm_vars(tmp_path)
    v["vllm_server_instances"][1]["gpus"] = [1]
    return {"role": "vllm_server", "tasks_from": "main", "extra_vars": v}


@first_run(_first)
def test_vllm_server_refuses_two_instances_on_one_gpu_or_port(first):
    r, tmp_path = first
    assert r.returncode != 0 and "distinct names, ports and GPUs" in r.stdout
    v = vllm_vars(tmp_path)
    v["vllm_server_instances"][1]["port"] = 8000
    assert run_role(tmp_path, "vllm_server", "main", v).returncode != 0


def _first(tmp_path):
    v = vllm_vars(tmp_path, vllm_server_api_key_ref="secret:llm-gateway/backend-key",
                  vllm_server_nccl_p2p_disable=True)  # fmt: skip
    env = {"HNX_SECRET_LLM_GATEWAY_BACKEND_KEY": "backend-key-fake"}
    return {"role": "vllm_server", "tasks_from": "main", "extra_vars": v, "env": env}


@first_run(_first)
def test_vllm_server_api_key_and_p2p_settings(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert "backend-key-fake" not in r.stdout
    unit = (tmp_path / "units" / "hnx-vllm-inference-triage.service").read_text()
    assert f"EnvironmentFile={tmp_path / 'env'}/inference-triage.env\n" in unit
    assert "Environment=NCCL_P2P_DISABLE=1\n" in unit
    envfile = tmp_path / "env" / "inference-triage.env"
    assert envfile.read_text() == "VLLM_API_KEY=backend-key-fake\n"
    assert oct(envfile.stat().st_mode & 0o777) == "0o600"


# K-14 on the host: the health hook's verdict and the probe's are the same on the same answers
MODELS_CASES = [
    # (what the fake serves, its loaded context, healthy)
    (["example-27b"], 131072, True),
    (["example-27b"], 65536, False),  # loaded with another context length
    (["example-27b"], None, False),  # context not reported: cannot be verified
    (["other-model"], 131072, False),  # another model
    (["example-27b", "extra"], 131072, True),
]


@pytest.mark.parametrize(("served", "ctx", "healthy"), MODELS_CASES)
def test_vllm_server_health_agrees_with_the_k14_probe(tmp_path, served, ctx, healthy):
    inst = instances(tmp_path)[0]
    with FakeOpenAIServer(models=served, context_length=ctx) as srv:
        host, port = srv.address
        inst["port"] = port
        v = vllm_vars(tmp_path, vllm_server_instances=[inst], vllm_server_health_host=host)
        r = run_role(tmp_path, "vllm_server", "health", v)
        rm = ResolvedModel(
            role="main-reasoner", asked="main-reasoner", kind="chat",
            model_id=inst["served_model_name"], backend="inference-large",
            endpoint=Endpoint("inference-large", "http", host, port, "env"), params={},
            max_context_tokens=inst["max_model_len"],
        )  # fmt: skip
        verdict = probe(rm)
    assert verdict.ok is healthy, verdict
    assert (r.returncode == 0) is healthy, r.stdout
    if not healthy:
        assert (
            "vllm_server: inference-large should serve example-27b with context 131072" in r.stdout
        )


def test_vllm_server_health_fails_when_health_is_down(tmp_path):
    inst = instances(tmp_path)[0]
    with FakeOpenAIServer(models=["example-27b"], context_length=131072) as srv:
        inst["port"] = srv.address[1]
        v = vllm_vars(
            tmp_path, vllm_server_instances=[inst], vllm_server_health_host=srv.address[0]
        )
        assert run_role(tmp_path, "vllm_server", "health", v).returncode == 0
    r = run_role(tmp_path, "vllm_server", "health", v)  # the server is gone
    assert r.returncode != 0


def test_vllm_server_health_presents_the_api_key(tmp_path):
    inst = instances(tmp_path)[0]
    with FakeOpenAIServer(models=["example-27b"], context_length=131072,
                          api_keys=["backend-key-fake"]) as srv:  # fmt: skip
        inst["port"] = srv.address[1]
        v = vllm_vars(tmp_path, vllm_server_instances=[inst], vllm_server_health_host=srv.address[0],
                      vllm_server_api_key_ref="secret:llm-gateway/backend-key")  # fmt: skip
        ok = run_role(tmp_path, "vllm_server", "health", v,
                      env={"HNX_SECRET_LLM_GATEWAY_BACKEND_KEY": "backend-key-fake"})  # fmt: skip
        wrong = run_role(tmp_path, "vllm_server", "health", v,
                         env={"HNX_SECRET_LLM_GATEWAY_BACKEND_KEY": "other-key-fake"})  # fmt: skip
    assert ok.returncode == 0, ok.stdout
    assert wrong.returncode != 0 and "other-key-fake" not in wrong.stdout


def _first(tmp_path):
    v = vllm_vars(tmp_path)
    return {
        "role": "vllm_server",
        "tasks_from": "upgrade",
        "extra_vars": {**v, "vllm_server_target_version": "0.32.0"},
        "setup": {"v": v},
    }


@first_run(_first)
def test_vllm_server_upgrade_hook(first):
    ok, tmp_path = first
    v = first.setup["v"]
    assert ok.returncode == 0, ok.stdout
    assert (tmp_path / "state" / "pending-version").read_text() == "0.32.0\n"
    for target in ("0.30.0", "0.31.0", "latest"):
        bad = run_role(
            tmp_path, "vllm_server", "upgrade", {**v, "vllm_server_target_version": target}
        )
        assert bad.returncode != 0, target
    for hook in ("backup", "restore", "export"):
        assert run_role(tmp_path, "vllm_server", hook, v).returncode == 0


# ---------------------------------------------------------------- open_webui
SECRETS = {
    "HNX_SECRET_LLM_GATEWAY_KEY_CHAT_UI": "chat-ui-key-fake",
    "HNX_SECRET_OPEN_WEBUI_SESSION_KEY": "session-key-fake",
}


def webui_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "open_webui_gateway_id": "llm-gateway",
        "open_webui_dir": str(tmp_path / "app"),
        "open_webui_export_dir": str(tmp_path / "export"),
        "open_webui_owner": USER,
        "open_webui_group": GROUP,
        "open_webui_start": False,
        "open_webui_validate_with_docker": False,
    }
    v.update(kw)
    return v


def _first(tmp_path):
    return {
        "role": "open_webui",
        "tasks_from": "main",
        "extra_vars": webui_vars(tmp_path),
        "env": SECRETS,
    }


@first_run(_first)
def test_open_webui_points_at_the_gateway_with_its_own_key(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    svc = doc["services"]["open-webui"]
    assert svc["image"] == (
        "ghcr.io/open-webui/open-webui:v0.11.4@sha256:"
        "9591b13f13843c7721c2b8eaf7382846c81b3ffe126526d1888d1fed50c6a33f"
    )
    env = svc["environment"]
    gateway = "https://gateway-01.example.internal:4000"  # no-raw-endpoint: allow the stub registry
    assert env["OPENAI_API_BASE_URLS"] == gateway + "/v1"
    assert env["ENABLE_OLLAMA_API"] == "false" and env["ENABLE_DIRECT_CONNECTIONS"] == "false"
    assert env["ENABLE_SIGNUP"] == "false" and env["OFFLINE_MODE"] == "true"
    assert env["ENABLE_PERSISTENT_CONFIG"] == "false"  # the environment wins on every start
    assert not any("KEY" in k for k in env)  # the keys are only in the env_file
    published = "127.0.0.1:3000:8080"  # no-raw-endpoint: allow the published loopback port
    assert svc["ports"] == [published]
    secrets = (tmp_path / "app" / "secrets" / "open-webui.env").read_text()
    assert secrets == "OPENAI_API_KEYS='chat-ui-key-fake'\nWEBUI_SECRET_KEY='session-key-fake'\n"
    assert "chat-ui-key-fake" not in r.stdout and "session-key-fake" not in r.stdout


@pytest.mark.parametrize(
    "over",
    [
        {"open_webui_gateway_id": "inference-large"},  # a model backend, not the gateway
        {"open_webui_gateway_id": "vllm-a"},
        {"open_webui_gateway_key_ref": "sk-plain-key-fake"},
        {"open_webui_session_key_ref": "secret:llm-gateway/key-chat-ui"},  # one secret, two uses
        {"open_webui_image": "ghcr.io/open-webui/open-webui:main"},
        {
            "open_webui_extra_env": {
                "OLLAMA_BASE_URL": "http://inference-small.svc.example.internal:11434"  # no-raw-endpoint: allow a refused input
            }
        },
        {
            "open_webui_extra_env": {
                "OPENAI_API_BASE_URL": "http://vllm.svc.example.internal:8000/v1"  # no-raw-endpoint: allow a refused input
            }
        },
        {"open_webui_extra_env": {"ENABLE_DIRECT_CONNECTIONS": "true"}},
        # tool servers, web search, RAG, images and audio each call out to an endpoint of their own
        {"open_webui_extra_env": {"TOOL_SERVER_CONNECTIONS": "[]"}},
        {"open_webui_extra_env": {"RAG_OPENAI_API_BASE_URL": "http://gpu-01.example.internal"}},
        {"open_webui_extra_env": {"RAG_EMBEDDING_ENGINE": "openai"}},
        {"open_webui_extra_env": {"ENABLE_WEB_SEARCH": "true"}},
        {"open_webui_extra_env": {"WEB_SEARCH_ENGINE": "searxng"}},
        {"open_webui_extra_env": {"IMAGES_OPENAI_API_KEY": "key-fake"}},
        {"open_webui_extra_env": {"AUDIO_STT_ENGINE": "openai"}},
        {"open_webui_extra_env": {"ENABLE_PERSISTENT_CONFIG": "true"}},
        {"open_webui_extra_env": {"openai_api_base_url": "http://gpu-01.example.internal"}},
    ],
)
@first_run(lambda tmp, over: {"role": "open_webui", "tasks_from": "main",
                               "extra_vars": webui_vars(tmp, **over), "env": SECRETS})  # fmt: skip
def test_open_webui_refuses_anything_but_the_gateway(first, over):
    r, tmp_path = first
    assert r.returncode != 0 and "Open WebUI talks to the LLM" in r.stdout, over
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _registry_row(tmp, row, ok):
    reg = yaml.safe_load((ROOT / "ansible/inventory/example/registry.yml").read_text())
    reg["services"]["gpu-01"] = row
    (tmp / "registry.yml").write_text(yaml.safe_dump(reg))
    v = webui_vars(tmp, open_webui_gateway_id="gpu-01",
                   hnx_registry_file=str(tmp / "registry.yml"))  # fmt: skip
    return {"role": "open_webui", "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@pytest.mark.parametrize(
    ("row", "ok"),
    [
        ({"host": "gpu-01.example.internal", "port": 8000, "scheme": "http"}, False),
        (
            {"host": "gpu-01.example.internal", "port": 8000, "scheme": "http",
             "capability": "inference-large"},
            False,
        ),
        (
            {"host": "gw-02.example.internal", "port": 4000, "scheme": "https",
             "capability": "llm-gateway"},
            True,
        ),
    ],
)  # fmt: skip
@first_run(_registry_row)
def test_open_webui_resolves_its_target_through_the_registry(first, row, ok):
    """A name is not a check: gpu-01 passes the backend-name pattern, so the id is resolved and
    its registry service must be the gateway."""
    r, tmp_path = first
    assert (r.returncode == 0) is ok, r.stdout
    if not ok:
        assert "Open WebUI talks to the LLM gateway only" in r.stdout
        assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first(tmp_path):
    v = webui_vars(tmp_path, open_webui_extra_env={"DEFAULT_MODELS": "main-reasoner"})
    return {"role": "open_webui", "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@first_run(_first)
def test_open_webui_keeps_extra_settings_that_do_not_re_point_it(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["services"]["open-webui"]["environment"]["DEFAULT_MODELS"] == "main-reasoner"


def test_open_webui_health_reads_the_container_and_the_port(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    state = tmp_path / "state.json"
    fake(bindir / "docker", f"import sys\nsys.stdout.write(open({str(state)!r}).read())\n")
    path = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    with FakeOpenAIServer(models=["x"]) as srv:
        host, port = srv.address
        v = webui_vars(tmp_path, open_webui_bind=host, open_webui_port=port)
        state.write_text(
            json.dumps({"Service": "open-webui", "State": "running", "Health": "healthy"}) + "\n"
        )
        ok = run_role(tmp_path, "open_webui", "health", v, env=path)
        state.write_text(
            json.dumps({"Service": "open-webui", "State": "running", "Health": "unhealthy"}) + "\n"
        )
        sick = run_role(tmp_path, "open_webui", "health", v, env=path)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert sick.returncode != 0 and "open-webui is running / unhealthy" in sick.stdout


def _first(tmp_path):
    v = webui_vars(tmp_path)
    return {
        "role": "open_webui",
        "tasks_from": "main",
        "extra_vars": v,
        "env": SECRETS,
        "setup": {"v": v},
    }


@first_run(_first)
def test_open_webui_upgrade_backup_export_hooks(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    target = "ghcr.io/open-webui/open-webui:v0.11.5@sha256:" + "a" * 64
    up = run_role(tmp_path, "open_webui", "upgrade", {**v, "open_webui_target_image": target})
    assert up.returncode == 0, up.stdout + up.stderr
    bad = run_role(tmp_path, "open_webui", "upgrade",
                   {**v, "open_webui_target_image": "ghcr.io/open-webui/open-webui:latest"})  # fmt: skip
    assert bad.returncode != 0
    assert run_role(tmp_path, "open_webui", "backup", v).returncode == 0
    (tmp_path / "app" / "data" / "webui.db").write_text("fake")
    assert run_role(tmp_path, "open_webui", "export", v).returncode == 0
