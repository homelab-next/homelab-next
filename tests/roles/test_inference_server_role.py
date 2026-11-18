# SPDX-License-Identifier: Apache-2.0
"""The role of the inference provider module (the module in ``modules/`` whose slot adapter is the
shared single-server adapter), run on localhost against fakes (CI is unprivileged):

* ``main`` renders one compose_app container for the backend (its GPU device and the groups by
  number, the weights read-only, the context per slot times the slots, offline, no web UI), a
  unit that is the container's only starter with the power-cap and byte check before it, and a
  second run is ``changed=0``; bad inputs, an image that is not the backend's, a missing weight
  file and a root group are refused before a file is written;
* the pre-start check refuses a power cap that is above the limit, unset, unreadable or not a
  number, and weights that are not the pinned bytes, and passes the ones that are;
* ``health`` passes against a stand-in of the engine and fails for each thing it checks;
* ``readiness``, ``upgrade`` and the data hooks.
The product's name never appears here: the role's variables are the module id's prefix."""

from __future__ import annotations

import hashlib
import os
import pwd
import subprocess
from pathlib import Path

import pytest
import yaml
from rolerun import fake, logging_fake, run_role

from conformance.fakes.openai_server import LOOPBACK
from tests.modules.single_model_server import SingleModelServer

ROOT = Path(__file__).resolve().parents[2]


def _find() -> Path:
    hits = [
        p.parent
        for p in sorted((ROOT / "modules").glob("*/module.yml"))
        if yaml.safe_load(p.read_text())["provides"]["slots"].get("inference", {}).get("adapter")
        == "homelabnext.conform.adapters.inference_server:make"
    ]
    assert len(hits) == 1, hits
    return hits[0]


MODULE = _find()
MID = MODULE.name
ROLE = str(MODULE / "roles" / MID)
SCRIPT = MODULE / "roles" / MID / "files" / f"hnx-{MID}-precheck"
DEFAULTS = yaml.safe_load((MODULE / "roles" / MID / "defaults" / "main.yml").read_text())
USER = pwd.getpwuid(os.getuid()).pw_name
# the guest's address is one the example registry already carries (no literal of our own)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["infer-core"][
    "address"
]
UID = os.getuid() if os.getuid() >= 1000 else 61000
GID = os.getgid() if os.getgid() >= 1000 else 61000
RENDER_GID, MODELS_GID = 4101, 4102
UNIT = f"hnx-{MID}.service"
MODEL_FILE = DEFAULTS[f"{MID}_model_file"]
REPO = DEFAULTS[f"{MID}_model_repo"]
STORE_ID = DEFAULTS[f"{MID}_model_store_id"]
CTX, SLOTS = 4096, 2
IMAGES = {
    "vulkan": DEFAULTS[f"{MID}_image"],
}


def image_for(backend: str, build: int = 12033) -> str:
    prefix = {
        "vulkan": "server-vulkan-",
        "sycl": "server-intel-",
        "cuda": "server-cuda-",
        "cpu": "server-",
    }
    repo = DEFAULTS[f"{MID}_image"].split("@")[0].rsplit(":", 1)[0]
    return f"{repo}:{prefix[backend]}b{build}@sha256:{'ab' * 32}"


def store(tmp_path: Path, content: bytes = b"weights") -> str:
    """The model store with one entry (its file and listing), as model_store writes it; returns
    the entry's digest."""
    root = tmp_path / "store"
    mdir = root / "gguf" / REPO
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / MODEL_FILE).write_bytes(content)
    listing = f"{hashlib.sha256(content).hexdigest()}  {MODEL_FILE}\n"
    (root / "manifests" / "listings").mkdir(parents=True, exist_ok=True)
    (root / "manifests" / "listings" / f"{STORE_ID}.sha256").write_text(listing)
    return "sha256:" + hashlib.sha256(listing.encode()).hexdigest()


def sysfs(tmp_path: Path, microwatts: str | None = "150000000", attr: str = "power1_cap") -> Path:
    root = tmp_path / "sys"
    d = root / "class" / "drm" / "renderD128" / "device" / "hwmon" / "hwmon3"
    d.mkdir(parents=True, exist_ok=True)
    if microwatts is not None:
        (d / attr).write_text(microwatts + "\n")
    return root


def role_vars(tmp_path: Path, **kw) -> dict:
    """The role's inputs, pointed into tmp_path; keys are the names without the role prefix."""
    digest = store(tmp_path) if not (tmp_path / "store").exists() else None
    (tmp_path / "dev" / "dri").mkdir(parents=True, exist_ok=True)
    (tmp_path / "dev" / "dri" / "renderD128").touch()
    (tmp_path / "units").mkdir(exist_ok=True)  # /etc/systemd/system exists on a guest
    v = {
        "logical_id": "inference-small",
        "dir": str(tmp_path / "app"),
        "data_root": str(tmp_path / "data"),
        "owner": USER,
        "uid": UID,
        "gid": GID,
        "store_root": str(tmp_path / "store"),
        "model_digest": digest or kw.pop("model_digest", None) or _digest(tmp_path),
        "dev_root": str(tmp_path / "dev"),
        "sysfs_root": str(sysfs(tmp_path) if not (tmp_path / "sys").exists() else tmp_path / "sys"),
        "unit_dir": str(tmp_path / "units"),
        "precheck_bin": str(tmp_path / "bin" / "precheck"),
        "context_size": CTX,
        "parallel": SLOTS,
        "render_gid": RENDER_GID,
        "models_gid": MODELS_GID,
        "start": False,
        "validate_with_docker": False,
    }
    v.update(kw)
    out = {f"{MID}_{k}": val for k, val in v.items()}
    out["ansible_host"] = GUEST
    return out


def _digest(tmp_path: Path) -> str:
    listing = (tmp_path / "store" / "manifests" / "listings" / f"{STORE_ID}.sha256").read_bytes()
    return "sha256:" + hashlib.sha256(listing).hexdigest()


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"][MID]


# ----------------------------------------------------------------------------- main


def test_main_renders_the_container_the_unit_and_converges(tmp_path):
    v = role_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    svc = compose(tmp_path)
    assert svc["image"] == DEFAULTS[f"{MID}_image"]
    assert svc["user"] == f"{UID}:{GID}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert "privileged" not in svc and "cap_add" not in svc
    assert svc["devices"] == ["/dev/dri/renderD128"]
    assert svc["group_add"] == [str(RENDER_GID), str(MODELS_GID)]
    assert svc["ports"] == [f"{GUEST}:{DEFAULTS[f'{MID}_port']}:8080"]
    # the unit is the one starter: docker never restarts the container by itself
    assert svc["restart"] == "no"
    store_dir = tmp_path / "store" / "gguf" / REPO
    assert svc["volumes"] == [f"{store_dir}:/models:ro", f"{tmp_path / 'data' / 'cache'}:/cache"]
    cmd = svc["command"]
    assert cmd[cmd.index("-m") + 1] == f"/models/{MODEL_FILE}"
    assert cmd[cmd.index("-a") + 1] == DEFAULTS[f"{MID}_served_model_name"]
    assert cmd[cmd.index("-c") + 1] == str(CTX * SLOTS) and cmd[cmd.index("-np") + 1] == str(SLOTS)
    assert "--no-kv-unified" in cmd and cmd[cmd.index("-ngl") + 1] == "99"
    assert {"--metrics", "--no-webui", "--no-slots", "--offline"} <= set(cmd)
    assert (
        cmd[cmd.index("--host") + 1] == "0.0.0.0"
    )  # inside the container; published on the guest only
    assert svc["environment"]["XDG_CACHE_HOME"] == "/cache"
    assert not any(k for k in svc["environment"] if "KEY" in k or "TOKEN" in k)
    # the unit: the check first, with the pinned digest and the power rule, then the foreground up
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    pre = next(line for line in unit.splitlines() if line.startswith("ExecStartPre="))
    assert str(tmp_path / "bin" / "precheck") in pre
    assert f"--digest {v[f'{MID}_model_digest']}" in pre
    assert "--backend vulkan --max-watts 200 --render-node renderD128 --attrs power1_cap" in pre
    assert (
        f"--model-file {MODEL_FILE} --listing {tmp_path}/store/manifests/listings/{STORE_ID}.sha256"
        in pre
    )
    assert "up --no-color --no-log-prefix --abort-on-container-exit" in unit
    assert "Restart=on-failure" in unit and "TimeoutStartSec=1800" in unit
    assert oct((tmp_path / "bin" / "precheck").stat().st_mode & 0o777) == "0o755"
    assert oct((tmp_path / "data" / "cache").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_main_starts_through_the_unit_and_restarts_it_only_when_it_changed(tmp_path):
    bindir = tmp_path / "fakes"
    bindir.mkdir()
    logging_fake(bindir, "systemctl")
    v = role_vars(tmp_path, start=True, systemctl_cli=str(bindir / "systemctl"),
                  validate_with_docker=False)  # fmt: skip
    # compose_app does not start the project (the unit does), so it needs no docker here
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (
        (bindir.parent / "calls.log")
        if (bindir.parent / "calls.log").exists()
        else bindir / "calls.log"
    )
    first = log.read_text().splitlines()
    assert [c.split(" ", 1)[1] for c in first] == [
        "daemon-reload", f"restart {UNIT}", f"enable --now {UNIT}"
    ]  # fmt: skip
    log.unlink()
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert [c.split(" ", 1)[1] for c in log.read_text().splitlines()] == [f"enable --now {UNIT}"]
    # a different context changes the compose file: the unit's recorded checksum moves, and it restarts
    log.unlink()
    v[f"{MID}_context_size"] = CTX * 2
    third = run_role(tmp_path, ROLE, "main", v)
    assert third.returncode == 0, third.stdout + third.stderr
    assert f"restart {UNIT}" in log.read_text()


def test_main_puts_the_container_in_the_role_slice_the_module_play_names(tmp_path):
    v = role_vars(tmp_path, **{})
    v["hnx_module_slice"] = f"hnx-{MID}-server.slice"
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert compose(tmp_path)["cgroup_parent"] == f"hnx-{MID}-server.slice"


def test_main_hands_a_cuda_container_its_card_by_cdi_name_and_a_cpu_one_nothing(tmp_path):
    v = role_vars(tmp_path, backend="cuda", image=image_for("cuda"), gpu_index=1)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    svc = compose(tmp_path)
    assert svc["devices"] == ["nvidia.com/gpu=1"] and svc["group_add"] == [str(MODELS_GID)]
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    assert "--backend cuda --max-watts 200 --gpu-index 1 --proc-root /proc --dev-root " in unit
    assert f"--dev-root {tmp_path / 'dev'} --model-file" in unit
    cpu = tmp_path / "cpu"
    cpu.mkdir()
    store(cpu)
    v = role_vars(cpu, backend="cpu", image=image_for("cpu"))
    assert run_role(cpu, ROLE, "main", v).returncode == 0
    svc = compose(cpu)
    assert "devices" not in svc and svc["group_add"] == [str(MODELS_GID)]
    assert svc["command"][svc["command"].index("-ngl") + 1] == "0"


def test_main_serves_a_split_model_from_a_quant_subdirectory_by_its_first_shard(tmp_path):
    digest = split_store(tmp_path)
    v = role_vars(tmp_path, model_file=shard(1), model_digest=digest)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    svc = compose(tmp_path)
    cmd = svc["command"]
    assert cmd[cmd.index("-m") + 1] == f"/models/{shard(1)}"
    # the entry's directory is the one mount: the shards sit beside the first one inside it
    assert svc["volumes"][0] == f"{tmp_path / 'store' / 'gguf' / REPO}:/models:ro"
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    assert f"--model-file {shard(1)} --listing" in unit
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    # the unit's check passes on these bytes, as written
    pre = next(line for line in unit.splitlines() if line.startswith("ExecStartPre="))
    args = pre.split(" ")[1:]
    assert precheck(*args).returncode == 0


def test_main_refuses_a_split_model_with_a_shard_missing_or_a_linked_subdirectory(tmp_path):
    digest = split_store(tmp_path)
    v = role_vars(tmp_path, model_file=shard(1), model_digest=digest)
    mdir = tmp_path / "store" / "gguf" / REPO
    (mdir / shard(2)).unlink()  # llama-server would fail mid-load, after the precheck
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0 and not list((tmp_path / "units").glob("*.service"))
    linked = tmp_path / "linked"
    digest = split_store(linked)
    v = role_vars(linked, model_file=shard(1), model_digest=digest)
    mdir = linked / "store" / "gguf" / REPO
    (mdir / SPLIT_DIR).rename(linked / "elsewhere")
    (mdir / SPLIT_DIR).symlink_to(linked / "elsewhere")
    r = run_role(linked, ROLE, "main", v)
    assert r.returncode != 0 and not list((linked / "units").glob("*.service"))


def test_main_hands_a_cuda_container_every_card_or_a_list_and_checks_each_cap(tmp_path):
    v = role_vars(tmp_path, backend="cuda", image=image_for("cuda"), gpu_indices="all")
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    assert compose(tmp_path)["devices"] == ["nvidia.com/gpu=all"]
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    assert "--backend cuda --max-watts 200 --gpu-index all --proc-root /proc --dev-root" in unit
    v[f"{MID}_gpu_indices"] = [0, 1, 2, 3]
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    assert compose(tmp_path)["devices"] == [f"nvidia.com/gpu={i}" for i in range(4)]
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    assert "--gpu-index 0,1,2,3 --proc-root" in unit


def test_main_passes_the_allow_listed_throughput_settings_by_name(tmp_path):
    extra = {"batch_size": 4096, "ubatch_size": 2048, "kv_unified": True,
             "split_mode": "layer", "tensor_split": [1, 1, 1.5, 1],
             "threads": 48, "threads_batch": 48}  # fmt: skip
    v = role_vars(tmp_path, backend="cuda", image=image_for("cuda"), gpu_indices="all",
                  parallel=16, extra_args=extra)  # fmt: skip
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    cmd = compose(tmp_path)["command"]
    # one cache of CTX tokens shared by the 16 slots: -c is the total, not CTX x 16
    assert cmd[cmd.index("-c") + 1] == str(CTX) and cmd[cmd.index("-np") + 1] == "16"
    assert "--kv-unified" in cmd and "--no-kv-unified" not in cmd
    assert cmd[cmd.index("-b") + 1] == "4096" and cmd[cmd.index("-ub") + 1] == "2048"
    assert cmd[cmd.index("-sm") + 1] == "layer" and cmd[cmd.index("-ts") + 1] == "1,1,1.5,1"
    assert cmd.count("-b") == 1 and cmd.count("-ub") == 1
    assert cmd[cmd.index("-t") + 1] == "48" and cmd[cmd.index("-tb") + 1] == "48"
    # kv_unified false is the default's per-slot cache
    v[f"{MID}_extra_args"] = {"kv_unified": False, "batch_size": 512}
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    cmd = compose(tmp_path)["command"]
    assert cmd[cmd.index("-c") + 1] == str(CTX * 16) and "--no-kv-unified" in cmd
    assert cmd[cmd.index("-b") + 1] == "512" and "-ub" not in cmd and "-sm" not in cmd
    assert "-t" not in cmd and "-tb" not in cmd  # llama-server's own count unless one is set


def test_main_reads_the_groups_from_the_store_and_the_render_node(tmp_path):
    v = role_vars(tmp_path)
    del v[f"{MID}_render_gid"], v[f"{MID}_models_gid"]
    if os.getgid() < 1000:
        pytest.skip("the test's own group is root's or a system group the role refuses to hand on")
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert compose(tmp_path)["group_add"] == [str(os.getgid()), str(os.getgid())]


REFUSED = {
    "image latest": {"image": DEFAULTS[f"{MID}_image"].split("@")[0].rsplit(":", 1)[0] + ":latest"},
    "image without a digest": {"image": DEFAULTS[f"{MID}_image"].split("@")[0]},
    "another backend's build": {"image": image_for("cuda")},
    "an unknown backend": {"backend": "metal"},
    "bind all interfaces": {"bind": "0.0.0.0"},
    "bind a hostname": {"bind": "engine.example.internal"},
    "a privileged port": {"port": 80},
    "uid root": {"uid": 0},
    "gid under 1000": {"gid": 100},
    "a relative directory": {"dir": "relative/dir"},
    "a traversal in the store root": {"store_root": "/srv/../etc"},
    "a model file that is not gguf": {"model_file": "weights.bin"},
    "a model repository with a traversal": {"model_repo": "../etc"},
    "a malformed digest": {"model_digest": "sha256:abc"},
    "a served name with a space": {"served_model_name": "my model"},
    "a context under 256": {"context_size": 100},
    "no slots": {"parallel": 0},
    "layers that are not a count": {"n_gpu_layers": "lots"},
    "a flash attention setting that is not one": {"flash_attn": "yes"},
    "a render node that is the whole directory": {"render_node": "dri"},
    "a render group that is root's": {"render_gid": 0},
    "a models group that is root's": {"models_gid": 0},
    "a power limit of zero": {"power_cap_max_watts": 0},
    "a power limit above the operator's 200 W": {"power_cap_max_watts": 201},
    "a power limit far above it": {"power_cap_max_watts": 1000},
    "a render group over 2^32-1": {"render_gid": 4294967296},
    "a models group over 2^32-1": {"models_gid": 9999999999},
    "a power attribute that is a path": {"power_cap_attrs": ["../power1_cap"]},
    "no power attribute": {"power_cap_attrs": []},
    # the model file: a path inside the entry, a split model by its first shard
    "an absolute model file": {"model_file": "/srv/models/x.gguf"},
    "a model file with a traversal": {"model_file": "../x.gguf"},
    "a model file with a traversal inside": {"model_file": "Q8_0/../../x.gguf"},
    "a model file in a dot directory": {"model_file": ".hidden/x.gguf"},
    "a model file with an empty segment": {"model_file": "Q8_0//x.gguf"},
    "a model file five directories deep": {"model_file": "a/b/c/d/e/x.gguf"},
    "a later shard": {"model_file": "Q8_0/m-00002-of-00003.gguf"},
    "a shard of no series": {"model_file": "m-00001-of-00000.gguf"},
    "a series too long to check": {"model_file": "m-00001-of-99999.gguf"},
    # the cards: cuda only, "all" or distinct indices
    "cards on a render-node backend": {"gpu_indices": [0, 1]},
    "all cards on the cpu backend": {
        "backend": "cpu",
        "image": image_for("cpu"),
        "gpu_indices": "all",
    },
    "a card twice": {"backend": "cuda", "image": image_for("cuda"), "gpu_indices": [0, 0]},
    "a card index above 15": {"backend": "cuda", "image": image_for("cuda"), "gpu_indices": [16]},
    "a card index as a string": {
        "backend": "cuda",
        "image": image_for("cuda"),
        "gpu_indices": ["1"],
    },
    "a card index that is a boolean": {
        "backend": "cuda",
        "image": image_for("cuda"),
        "gpu_indices": [True],
    },
    "cards named by a word": {
        "backend": "cuda",
        "image": image_for("cuda"),
        "gpu_indices": "every",
    },
    "cards as a mapping": {"backend": "cuda", "image": image_for("cuda"), "gpu_indices": {"0": 1}},
    # the throughput settings: the allow-list's names and types only
    "an extra flag that is not allow-listed": {"extra_args": {"mlock": True}},
    "threads as a string": {"extra_args": {"threads": "48"}},
    "threads that is a boolean": {"extra_args": {"threads": True}},
    "no threads": {"extra_args": {"threads": 0}},
    "more threads than a footprint has vCPUs": {"extra_args": {"threads": 257}},
    "batch threads that are negative": {"extra_args": {"threads_batch": -1}},
    "an extra raw flag": {"extra_args": {"--mlock": True}},
    "extra arguments as a string": {"extra_args": "-b 4096"},
    "a batch size as a string": {"extra_args": {"batch_size": "4096"}},
    "a batch size that is a boolean": {"extra_args": {"batch_size": True}},
    "a batch size of zero": {"extra_args": {"batch_size": 0}},
    "a micro-batch above the batch": {"extra_args": {"batch_size": 512, "ubatch_size": 1024}},
    "a unified cache that is not a boolean": {"extra_args": {"kv_unified": "yes"}},
    "a split mode that is not one": {"extra_args": {"split_mode": "column"}},
    "an empty tensor split": {"extra_args": {"tensor_split": []}},
    "a negative tensor split": {"extra_args": {"tensor_split": [1, -1]}},
    "an all-zero tensor split": {"extra_args": {"tensor_split": [0, 0]}},
    "a tensor split as a string": {"extra_args": {"tensor_split": "1,1"}},
    "a tensor split of booleans": {"extra_args": {"tensor_split": [True, True]}},
    "an infinite tensor split": {"extra_args": {"tensor_split": [1, float("inf")]}},
    "a tensor split that is not a number": {"extra_args": {"tensor_split": [1, float("nan")]}},
    "a tensor split of another length than the cards": {
        "backend": "cuda",
        "image": image_for("cuda"),
        "gpu_indices": [0, 1],
        "extra_args": {"tensor_split": [1, 1, 1]},
    },
    "a micro-batch alone above the default batch": {"extra_args": {"ubatch_size": 4096}},
    "a batch size in decision mode": {"mode": "decision", "extra_args": {"batch_size": 4096}},
    "a unified cache in decision mode": {"mode": "decision", "extra_args": {"kv_unified": True}},
    "a split mode on the cpu backend": {
        "backend": "cpu",
        "image": image_for("cpu"),
        "extra_args": {"split_mode": "layer"},
    },
}


def test_main_warns_but_does_not_refuse_threads_above_the_placed_cpu(tmp_path):
    extra = {"threads": 8, "threads_batch": 2}
    placed = {"hnx_module_footprint": {"cpu": 4, "memory_mb": 8192, "disk_gb": 50}}
    r = run_role(tmp_path, ROLE, "main", {**role_vars(tmp_path, extra_args=extra), **placed})
    assert r.returncode == 0, r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert "exceeds the placement's cpu" in out and "(8)" in out and "cpu" in out
    # a raise that covers the threads, threads within the cpu, no threads, and no placed footprint: silent
    for name, ex, fp in [
        ("raised", extra, {"cpu": 8}),
        ("within", {"threads": 4, "threads_batch": 4}, {"cpu": 4}),
        ("unset", {}, {"cpu": 1}),
    ]:
        v = {**role_vars(tmp_path, extra_args=ex), "hnx_module_footprint": fp}
        r = run_role(tmp_path, ROLE, "main", v)
        assert r.returncode == 0 and "exceeds the placement's cpu" not in r.stdout + r.stderr, name
    r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path, extra_args=extra))
    assert r.returncode == 0 and "exceeds the placement's cpu" not in r.stdout + r.stderr


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_main_refuses_bad_inputs_before_writing_anything(tmp_path, case):
    r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path, **REFUSED[case]))
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert not list((tmp_path / "units").glob("*.service"))


def test_main_refuses_when_the_weights_are_not_in_the_store(tmp_path):
    v = role_vars(tmp_path)
    (tmp_path / "store" / "gguf" / REPO / MODEL_FILE).unlink()
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0 and not list((tmp_path / "units").glob("*.service"))


def _docker_with_image(tmp_path: Path, has_image: bool) -> dict:
    bindir = tmp_path / "dbin"
    bindir.mkdir(exist_ok=True)
    flag, log = tmp_path / "image-present", tmp_path / "docker.log"
    if has_image:
        flag.touch()
    fake(
        bindir / "docker",
        "import os, sys\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        f"flag = {str(flag)!r}\n"
        "if sys.argv[1:3] == ['image', 'inspect']:\n    sys.exit(0 if os.path.exists(flag) else 1)\n"
        "if sys.argv[1] == 'load':\n    open(flag, 'w').close()\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def test_main_loads_the_pinned_image_from_the_archive_only_when_the_daemon_lacks_it(tmp_path):
    archive = tmp_path / "image.tar.zst"
    archive.write_bytes(b"not read by the fake")
    v = role_vars(tmp_path, image_archive=str(archive))
    env = _docker_with_image(tmp_path, has_image=False)
    assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
    assert f"load -i {archive}" in (tmp_path / "docker.log").read_text()
    (tmp_path / "docker.log").unlink()
    assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0  # present now: no load
    assert "load" not in (tmp_path / "docker.log").read_text()


def test_main_refuses_an_archive_that_is_missing(tmp_path):
    v = role_vars(tmp_path, image_archive=str(tmp_path / "absent.tar.zst"))
    r = run_role(tmp_path, ROLE, "main", v, env=_docker_with_image(tmp_path, has_image=False))
    assert r.returncode != 0 and "not a regular file" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- the pre-start check


def precheck(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True,
                          env={**os.environ, **(env or {})})  # fmt: skip


def intel(tmp_path: Path, microwatts: str | None, *extra: str, attr: str = "power1_cap"):
    return precheck("--backend", "vulkan", "--max-watts", "200", "--render-node", "renderD128",
                    "--sysfs-root", str(sysfs(tmp_path, microwatts, attr)), "--power-only", *extra)  # fmt: skip


@pytest.mark.parametrize(
    "uw, ok",
    [("150000000", True), ("200000000", True), ("200000001", False), ("250000000", False),
     ("0", False), ("", False), ("junk", False), ("-5", False), ("1e8", False)],
)  # fmt: skip
def test_precheck_judges_an_intel_cards_power_cap_in_microwatts(tmp_path, uw, ok):
    r = intel(tmp_path, uw)
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    if not ok:
        assert r.returncode == 1 and "refusing to load the model" in r.stderr


def test_precheck_refuses_a_card_whose_cap_cannot_be_read(tmp_path):
    r = intel(tmp_path, None)  # a hwmon directory with no power1_cap
    assert r.returncode == 1 and "cannot be read" in r.stderr
    r = precheck("--backend", "vulkan", "--max-watts", "200", "--render-node", "renderD129",
                 "--sysfs-root", str(tmp_path / "sys"), "--power-only")  # fmt: skip
    assert r.returncode == 1 and "cannot be read" in r.stderr  # no such card


def test_precheck_holds_every_listed_attribute_to_the_limit(tmp_path):
    root = sysfs(tmp_path, "150000000", "power1_cap")
    (root / "class/drm/renderD128/device/hwmon/hwmon3/power1_max").write_text("300000000\n")
    base = ["--backend", "vulkan", "--max-watts", "200", "--render-node", "renderD128",
            "--sysfs-root", str(root), "--power-only"]  # fmt: skip
    assert precheck(*base, "--attrs", "power1_cap").returncode == 0
    r = precheck(*base, "--attrs", "power1_cap,power1_max")
    assert r.returncode == 1 and "power1_max is 300 W, above the 200 W limit" in r.stderr
    assert precheck(*base, "--attrs", "power9_cap").returncode == 1  # an attribute that is absent


def _smi(tmp_path: Path, out: str, rc: int = 0) -> dict:
    d = tmp_path / "smi"
    d.mkdir(exist_ok=True)
    fake(d / "nvidia-smi", f"import sys\nsys.stdout.write({out!r})\nsys.exit({rc})\n")
    return {"PATH": f"{d}:{os.environ['PATH']}"}


def driver_up(
    tmp_path: Path,
    modules: str = "nvidia_uvm 1 0 - Live 0x0\nnvidia 2 1 nvidia_uvm, Live 0x0\n",
    ctl: bool = True,
) -> list[str]:
    """--proc-root and --dev-root of a guest whose driver is loaded (or, by the arguments, not)."""
    proc, dev = tmp_path / "proc", tmp_path / "devroot"
    proc.mkdir(exist_ok=True)
    dev.mkdir(exist_ok=True)
    (proc / "modules").write_text(modules)
    if ctl:
        (dev / "nvidiactl").write_text("")
    return ["--proc-root", str(proc), "--dev-root", str(dev)]


@pytest.mark.parametrize(
    "modules, ctl",
    [("", True), ("nvidia_uvm 1 0 - Live 0x0\ndrm 2 0 - Live 0x0\n", True),
     ("nvidia 2 0 - Live 0x0\n", False)],
)  # fmt: skip
def test_precheck_never_runs_nvidia_smi_unless_the_driver_is_already_loaded(tmp_path, modules, ctl):
    """nvidia-smi as root loads the nvidia module when it is absent: a warm-card load on a guest
    whose cards must not be initialised that way. Without the module and its control device the
    check refuses before calling it."""
    env = _smi(tmp_path, _rows(("180.00", "180.00")))
    log = tmp_path / "smi.log"
    fake(tmp_path / "smi" / "nvidia-smi",
         f"import sys\nopen({str(log)!r}, 'a').write('ran')\nsys.stdout.write({_rows(('180.00', '180.00'))!r})\n")  # fmt: skip
    r = precheck("--backend", "cuda", "--max-watts", "200", "--gpu-index", "all", "--power-only",
                 *driver_up(tmp_path, modules, ctl), env=env)  # fmt: skip
    assert r.returncode == 1 and "nvidia-smi is not run" in r.stderr, r.stderr
    assert not log.exists()
    ok = tmp_path / "ok"
    ok.mkdir()
    r = precheck("--backend", "cuda", "--max-watts", "200", "--gpu-index", "all", "--power-only",
                 *driver_up(ok), env=env)  # fmt: skip
    assert r.returncode == 0 and log.read_text() == "ran", r.stderr


def test_the_unit_passes_the_driver_seams_as_fixed_paths():
    fixed = yaml.safe_load((MODULE / "roles" / MID / "vars" / "main.yml").read_text())
    assert fixed[f"{MID}_proc_root"] == "/proc" and fixed[f"{MID}_dev_root"] == "/dev"
    assert f"{MID}_proc_root" not in DEFAULTS


def _rows(*limits: tuple[str, str]) -> str:
    """nvidia-smi --query-gpu=index,power.limit,enforced.power.limit csv, one card per pair."""
    return "".join(f"{i}, {lim}, {enf}\n" for i, (lim, enf) in enumerate(limits))


@pytest.mark.parametrize(
    "limit, enforced, rc, ok",
    [("180.00", "180.00", 0, True), ("200", "200", 0, True), (" 200.00 ", "200.00", 0, True),
     ("200.01", "200.00", 0, False), ("300.00", "300.00", 0, False), ("[N/A]", "180.00", 0, False),
     ("0.00", "0.00", 0, False), ("", "", 0, False), ("180.00", "180.00", 9, False),
     # the limit set is within, the one the card enforces is not (or cannot be read)
     ("180.00", "250.00", 0, False), ("180.00", "[N/A]", 0, False), ("180.00", "[Not Supported]", 0, False)],
)  # fmt: skip
def test_precheck_judges_an_nvidia_cards_power_limit_in_watts(tmp_path, limit, enforced, rc, ok):
    r = precheck("--backend", "cuda", "--max-watts", "200", "--gpu-index", "0", "--power-only",
                 *driver_up(tmp_path),
                 env=_smi(tmp_path, _rows((limit, enforced)), rc))  # fmt: skip
    assert (r.returncode == 0) is ok, r.stdout + r.stderr


FOUR = _rows(("200.00", "200.00"), ("180.00", "180.00"), ("200.00", "200.00"), ("150.00", "150.00"))


@pytest.mark.parametrize(
    "gpus, out, ok, needle",
    [("all", FOUR, True, "GPU 3 power limit"),
     ("0,1,2,3", FOUR, True, "GPU 2 power limit"),
     ("1,3", FOUR, True, "GPU 3 power limit"),
     # one card of four above the cap, by its limit or by the one it enforces
     ("all", FOUR.replace("2, 200.00, 200.00", "2, 250.00, 250.00"), False, "GPU 2's power.limit is 250.00 W"),
     ("all", FOUR.replace("3, 150.00, 150.00", "3, 150.00, 201.00"), False, "GPU 3's enforced.power.limit"),
     ("0,2", FOUR.replace("2, 200.00, 200.00", "2, 250.00, 250.00"), False, "GPU 2's"),
     # a card that is not there, no card at all, a card listed twice
     ("0,4", FOUR, False, "GPU 4 is not listed once"),
     ("all", "", False, "lists no GPU"),
     ("0", FOUR + "0, 180.00, 180.00\n", False, "GPU 0 is not listed once"),
     # a card's cap that is not read is not skipped, also when another card names it
     ("all", FOUR.replace("1, 180.00, 180.00", "1, [N/A], [N/A]"), False, "GPU 1's power.limit")],
)  # fmt: skip
def test_precheck_holds_every_card_a_multi_gpu_container_gets_to_the_cap(
    tmp_path, gpus, out, ok, needle
):
    r = precheck("--backend", "cuda", "--max-watts", "200", "--gpu-index", gpus, "--power-only",
                 *driver_up(tmp_path),
                 env=_smi(tmp_path, out))  # fmt: skip
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    assert needle in (r.stdout if ok else r.stderr), r.stdout + r.stderr
    if ok:  # every card named was judged, one line each
        n = 4 if gpus == "all" else len(gpus.split(","))
        assert r.stdout.count("within 200 W") == n


@pytest.mark.parametrize("gpus", ["", "0,", ",1", "0,,1", "all,1", "one", "0;1", "-1"])
def test_precheck_refuses_a_malformed_card_list(tmp_path, gpus):
    r = precheck("--backend", "cuda", "--max-watts", "200", "--gpu-index", gpus, "--power-only",
                 *driver_up(tmp_path),
                 env=_smi(tmp_path, FOUR))  # fmt: skip
    assert r.returncode == 2, (gpus, r.stderr)


def test_precheck_passes_a_cpu_backend_and_refuses_bad_usage(tmp_path):
    assert precheck("--backend", "cpu", "--max-watts", "200", "--power-only").returncode == 0
    for args in (["--backend", "metal", "--max-watts", "200"],
                 ["--backend", "cpu", "--max-watts", "lots"],
                 ["--backend", "cpu", "--max-watts", "0"],
                 ["--backend", "cpu", "--max-watts", "200"],  # no listing, digest or directory
                 ["--backend", "vulkan", "--max-watts", "200", "--power-only"],  # no render node
                 ["--nonsense"]):  # fmt: skip
        r = precheck(*args)
        assert r.returncode == 2, (args, r.stderr)


def _bytes_args(tmp_path: Path, digest: str) -> list[str]:
    root = tmp_path / "store"
    return ["--backend", "cpu", "--max-watts", "200", "--model-file", MODEL_FILE, "--listing",
            str(root / "manifests" / "listings" / f"{STORE_ID}.sha256"),
            "--digest", digest, "--model-dir", str(root / "gguf" / REPO)]  # fmt: skip


def test_precheck_passes_the_pinned_bytes_and_refuses_anything_else(tmp_path):
    digest = store(tmp_path)
    assert precheck(*_bytes_args(tmp_path, digest)).returncode == 0
    # the wrong digest: the listing is not the one the module pins
    r = precheck(*_bytes_args(tmp_path, "sha256:" + "0" * 64))
    assert r.returncode == 1 and "the module pins" in r.stderr
    # a file that changed after model_store verified it
    (tmp_path / "store" / "gguf" / REPO / MODEL_FILE).write_bytes(b"tampered")
    r = precheck(*_bytes_args(tmp_path, digest))
    assert r.returncode == 1 and "does not match" in r.stderr
    # the file is gone, then the listing is gone
    (tmp_path / "store" / "gguf" / REPO / MODEL_FILE).unlink()
    assert precheck(*_bytes_args(tmp_path, digest)).returncode == 1
    (tmp_path / "store" / "manifests" / "listings" / f"{STORE_ID}.sha256").unlink()
    r = precheck(*_bytes_args(tmp_path, digest))
    assert r.returncode == 1 and "run model_store" in r.stderr


def test_precheck_requires_the_served_file_to_be_in_the_pinned_listing(tmp_path):
    """A listing whose digest matches but that omits the file the server loads pins nothing about
    it: the swapped file used to pass."""
    mdir = tmp_path / "store" / "gguf" / REPO
    mdir.mkdir(parents=True)
    (mdir / "other.bin").write_bytes(b"other")
    (mdir / MODEL_FILE).write_bytes(b"swapped for anything")
    listing = f"{hashlib.sha256(b'other').hexdigest()}  other.bin\n"
    lst = tmp_path / "store" / "manifests" / "listings"
    lst.mkdir(parents=True)
    (lst / f"{STORE_ID}.sha256").write_text(listing)
    digest = "sha256:" + hashlib.sha256(listing.encode()).hexdigest()
    r = precheck(*_bytes_args(tmp_path, digest))
    assert r.returncode == 1 and "is not in" in r.stderr and "not pinned" in r.stderr
    # a listed file passes, whatever sits beside it; a prefix or a path of another name does not count
    good = store(tmp_path / "ok")
    assert precheck(*_bytes_args(tmp_path / "ok", good)).returncode == 0
    for name in (MODEL_FILE[:-2], "sub/" + MODEL_FILE, MODEL_FILE + "x"):
        (lst / f"{STORE_ID}.sha256").write_text(f"{'0' * 64}  {name}\n")
        digest = "sha256:" + hashlib.sha256((lst / f"{STORE_ID}.sha256").read_bytes()).hexdigest()
        assert precheck(*_bytes_args(tmp_path, digest)).returncode == 1, name
    # an unlisted file swapped in beside a correctly pinned one is still refused as unlisted
    (mdir / "other.bin").write_bytes(b"other")
    assert precheck(*_bytes_args(tmp_path, "sha256:" + "0" * 64)).returncode == 1


SPLIT_DIR, SPLIT_STEM = "Q8_0", "model-Q8_0"


def shard(n: int, total: int = 3) -> str:
    return f"{SPLIT_DIR}/{SPLIT_STEM}-{n:05d}-of-{total:05d}.gguf"


def split_store(tmp_path: Path, total: int = 3, listed=None) -> str:
    """The model store with one split entry: ``total`` shards in a quant subdirectory, all on disk,
    ``listed`` (default all) in the listing; returns the listing's digest."""
    root = tmp_path / "store"
    mdir = root / "gguf" / REPO
    (mdir / SPLIT_DIR).mkdir(parents=True, exist_ok=True)
    lines = []
    for n in range(1, total + 1):
        body = f"shard {n}".encode()
        (mdir / shard(n, total)).write_bytes(body)
        if listed is None or n in listed:
            lines.append(f"{hashlib.sha256(body).hexdigest()}  {shard(n, total)}\n")
    listing = "".join(sorted(lines, key=lambda line: line.split("  ", 1)[1]))
    (root / "manifests" / "listings").mkdir(parents=True, exist_ok=True)
    (root / "manifests" / "listings" / f"{STORE_ID}.sha256").write_text(listing)
    return "sha256:" + hashlib.sha256(listing.encode()).hexdigest()


def _split_args(tmp_path: Path, digest: str, mfile: str | None = None) -> list[str]:
    root = tmp_path / "store"
    return ["--backend", "cpu", "--max-watts", "200", "--model-file", mfile or shard(1),
            "--listing", str(root / "manifests" / "listings" / f"{STORE_ID}.sha256"),
            "--digest", digest, "--model-dir", str(root / "gguf" / REPO)]  # fmt: skip


def test_precheck_passes_a_split_model_whose_every_shard_is_pinned(tmp_path):
    digest = split_store(tmp_path)
    r = precheck(*_split_args(tmp_path, digest))
    assert r.returncode == 0, r.stderr
    assert f"all 3 shards of {SPLIT_DIR}/{SPLIT_STEM} are listed" in r.stdout
    # a shard changed on disk after model_store verified it
    (tmp_path / "store" / "gguf" / REPO / shard(3)).write_bytes(b"shard X")
    r = precheck(*_split_args(tmp_path, digest))
    assert r.returncode == 1 and "does not match" in r.stderr


def test_precheck_refuses_a_split_model_with_an_unpinned_shard_or_a_later_shard_named(tmp_path):
    # the listing pins shards 1 and 2 only: llama-server would open shard 3 unchecked
    digest = split_store(tmp_path, listed={1, 2})
    r = precheck(*_split_args(tmp_path, digest))
    assert r.returncode == 1 and f"{shard(3)} (shard 3 of 00003) is not in" in r.stderr
    ok = tmp_path / "ok"
    digest = split_store(ok)
    r = precheck(*_split_args(ok, digest, shard(2)))
    assert r.returncode == 1 and "must be given the first shard" in r.stderr


@pytest.mark.parametrize(
    "mfile",
    ["/etc/x.gguf", "../x.gguf", "Q8_0/../x.gguf", "./x.gguf", "Q8_0//x.gguf", "Q8_0/./x.gguf"],
)
def test_precheck_refuses_a_model_file_that_is_not_a_path_inside_the_entry(tmp_path, mfile):
    digest = split_store(tmp_path)
    r = precheck(*_split_args(tmp_path, digest, mfile))
    assert r.returncode == 1 and "is not a path inside" in r.stderr, r.stderr


def test_precheck_refuses_shards_that_resolve_out_of_the_entry(tmp_path):
    """The right bytes behind a link out of the store still refuse: nothing manages them."""
    digest = split_store(tmp_path)
    mdir = tmp_path / "store" / "gguf" / REPO
    outside = tmp_path / "outside"
    (mdir / SPLIT_DIR).rename(outside)
    (mdir / SPLIT_DIR).symlink_to(outside)  # the quant subdirectory is a link
    r = precheck(*_split_args(tmp_path, digest))
    assert r.returncode == 1 and "resolves outside" in r.stderr, r.stderr
    (mdir / SPLIT_DIR).unlink()
    (mdir / SPLIT_DIR).mkdir()
    for n in (1, 2, 3):
        (mdir / shard(n)).write_bytes((outside / Path(shard(n)).name).read_bytes())
    assert precheck(*_split_args(tmp_path, digest)).returncode == 0
    (mdir / shard(2)).unlink()
    (mdir / shard(2)).symlink_to(outside / Path(shard(2)).name)  # one shard is a link
    r = precheck(*_split_args(tmp_path, digest))
    assert r.returncode == 1 and f"{shard(2)} resolves outside" in r.stderr, r.stderr


def test_precheck_refuses_a_limit_above_the_operators_200_w(tmp_path):
    r = precheck("--backend", "cpu", "--max-watts", "201", "--power-only")
    assert r.returncode == 2


def test_the_check_trees_are_not_settings_and_the_ceiling_is_fixed():
    spec = yaml.safe_load((MODULE / "roles" / MID / "meta" / "argument_specs.yml").read_text())
    for hook in spec["argument_specs"].values():
        assert not {f"{MID}_sysfs_root", f"{MID}_dev_root"} & set(hook["options"])
    assert not {f"{MID}_sysfs_root", f"{MID}_dev_root"} & set(DEFAULTS)
    fixed = yaml.safe_load((MODULE / "roles" / MID / "vars" / "main.yml").read_text())
    assert fixed[f"{MID}_sysfs_root"] == "/sys" and fixed[f"{MID}_power_cap_ceiling_watts"] == 200


def test_precheck_checks_the_power_before_it_reads_the_weights(tmp_path):
    digest = store(tmp_path)
    r = precheck("--backend", "vulkan", "--max-watts", "100", "--render-node", "renderD128",
                 "--sysfs-root", str(sysfs(tmp_path, "150000000")), "--model-file", MODEL_FILE,
                 "--listing", "/nonexistent",
                 "--digest", digest, "--model-dir", str(tmp_path))  # fmt: skip
    assert r.returncode == 1 and "above the 100 W limit" in r.stderr  # not "listing is missing"


# ----------------------------------------------------------------------------- health


def _fakes(tmp_path: Path, *, unit: str = "active", health: str = "healthy") -> dict:
    d = tmp_path / "fakes"
    d.mkdir(exist_ok=True)
    state = f'{{"Service": "{MID}", "State": "running", "Health": "{health}"}}\\n'
    fake(d / "docker", f"import sys\nsys.stdout.write('{state}')\n")
    fake(
        d / "systemctl",
        f"import sys\nprint({unit!r})\nsys.exit(0 if {unit!r} == 'active' else 3)\n",
    )
    return {"PATH": f"{d}:{os.environ['PATH']}"}


def health_vars(tmp_path: Path, srv: SingleModelServer, **kw) -> dict:
    v = role_vars(
        tmp_path,
        bind=LOOPBACK,
        port=srv.port,
        precheck_bin=str(SCRIPT),
        systemctl_cli=str(tmp_path / "fakes" / "systemctl"),
        **kw,
    )
    return v


def engine(**kw) -> SingleModelServer:
    return SingleModelServer(
        model=DEFAULTS[f"{MID}_served_model_name"], n_ctx=CTX, metric_prefix=MID, **kw
    )


def test_health_passes_when_every_check_holds(tmp_path):
    env = _fakes(tmp_path)
    with engine() as srv:
        r = run_role(tmp_path, ROLE, "health", health_vars(tmp_path, srv), env=env)
        paths = [p for _, p in srv.requests]
    assert r.returncode == 0, r.stdout + r.stderr
    # the readiness wait's /health comes first, then the checks, the warm-up and the timed probe
    assert paths == ["/health", "/health", "/v1/models", "/metrics"] + ["/v1/chat/completions"] * 2


def test_health_survives_a_cold_first_request_slower_than_the_steady_state_timeout(tmp_path):
    """A cold load makes the first request slow (25.5 s measured against a 20 s timeout). A
    separate warm-up with its own timeout absorbs it; the timed probe then runs warm."""
    env = _fakes(tmp_path)
    with engine(first_chat_delay=3.0) as srv:
        v = health_vars(tmp_path, srv, health_timeout=1, first_request_timeout=30)
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr


def test_health_still_fails_a_server_that_is_slow_on_every_request(tmp_path):
    """The steady-state timeout is not loosened: a server slow on every call fails the timed probe
    even though the warm-up allowed for its first."""
    env = _fakes(tmp_path)
    with engine(chat_delay=3.0) as srv:
        v = health_vars(tmp_path, srv, health_timeout=1, first_request_timeout=30)
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0


def test_health_fails_when_the_warm_up_itself_outlasts_its_timeout(tmp_path):
    env = _fakes(tmp_path)
    with engine(first_chat_delay=4.0) as srv:
        v = health_vars(tmp_path, srv, health_timeout=1, first_request_timeout=1)
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0


def test_health_waits_for_a_model_that_is_still_loading(tmp_path):
    """The unit is active once the container starts, but the model loads for a while longer: health
    retries /health until it answers 200 instead of failing on the first 503."""
    env = _fakes(tmp_path)
    with engine(loading_for=2.5) as srv:
        v = health_vars(tmp_path, srv, load_timeout=30, load_poll_s=1)
        r = run_role(tmp_path, ROLE, "health", v, env=env)
        health_calls = [p for _, p in srv.requests if p == "/health"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(health_calls) >= 3  # at least one 503 was retried, then the 200 and the final check


def test_health_fails_naming_loading_when_the_model_never_loads_in_time(tmp_path):
    env = _fakes(tmp_path)
    with engine(loading=True) as srv:
        v = health_vars(tmp_path, srv, load_timeout=2, load_poll_s=1)
        r = run_role(tmp_path, ROLE, "health", v, env=env)
        calls = [p for _, p in srv.requests]
    out = r.stdout + r.stderr
    assert r.returncode != 0
    assert "still loading" in out and "503" in out and "_load_timeout" in out, out[-2000:]
    assert "/v1/models" not in calls  # nothing after the wait ran


def test_health_waits_for_containers_that_are_still_starting(tmp_path):
    """A container whose healthcheck has not passed yet fails the unchanged strict check once the
    wait ends, naming the container's state."""
    env = _fakes(tmp_path, health="starting")
    with engine() as srv:
        v = health_vars(tmp_path, srv, load_timeout=2, load_poll_s=1)
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0 and "starting" in r.stdout + r.stderr


def test_main_in_check_mode_on_a_first_install_reports_instead_of_failing(tmp_path):
    """Nothing wrote the compose file yet, so its checksum cannot be read: --check must say what
    it would change, not fail on the missing file."""
    r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path), check=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


@pytest.mark.parametrize(
    "what, srv_kw, fakes_kw, power",
    [
        ("the model is still loading", {"loading": True}, {}, "150000000"),
        (
            "a different context from the one the role declares",
            {"n_ctx": CTX // 2},
            {},
            "150000000",
        ),
        ("a context the engine does not report", {"reports_ctx": False}, {}, "150000000"),
        ("no metrics route", {"metrics": False}, {}, "150000000"),
        ("the unit is not active", {}, {"unit": "failed"}, "150000000"),
        ("the container is unhealthy", {}, {"health": "unhealthy"}, "150000000"),
        ("the power cap was raised after the start", {}, {}, "250000000"),
        ("the power cap was lifted", {}, {}, "0"),
    ],
)
def test_health_fails_for_each_thing_it_checks(tmp_path, what, srv_kw, fakes_kw, power):
    env = _fakes(tmp_path, **fakes_kw)
    kw = {"model": DEFAULTS[f"{MID}_served_model_name"], "n_ctx": CTX, "metric_prefix": MID}
    kw.update(srv_kw)
    with SingleModelServer(**kw) as srv:
        v = health_vars(
            tmp_path, srv, sysfs_root=str(sysfs(tmp_path, power)), load_timeout=1, load_poll_s=1
        )
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0, what


def test_health_with_a_unified_cache_holds_each_slot_to_the_shared_total(tmp_path):
    """With kv_unified the slots share one cache of the context size, and each may use all of it:
    the engine reports that total as a slot's n_ctx, which health compares as before."""
    env = _fakes(tmp_path)
    extra = {"kv_unified": True, "batch_size": 2048, "ubatch_size": 512}
    with engine() as srv:
        v = health_vars(tmp_path, srv, parallel=16, extra_args=extra)
        assert run_role(tmp_path, ROLE, "health", v, env=env).returncode == 0
    with SingleModelServer(model=DEFAULTS[f"{MID}_served_model_name"], n_ctx=CTX // 16,
                           metric_prefix=MID) as srv:  # fmt: skip
        v = health_vars(tmp_path, srv, parallel=16, extra_args=extra)
        assert run_role(tmp_path, ROLE, "health", v, env=env).returncode != 0


def test_health_fails_when_another_model_is_served(tmp_path):
    env = _fakes(tmp_path)
    with SingleModelServer(model="someone-else", n_ctx=CTX, metric_prefix=MID) as srv:
        r = run_role(tmp_path, ROLE, "health", health_vars(tmp_path, srv), env=env)
    assert r.returncode != 0


# ----------------------------------------------------------------------------- the other hooks


def test_readiness_needs_the_engine_the_weights_their_listing_and_the_render_node(tmp_path):
    d = tmp_path / "fakes"
    d.mkdir()
    fake(d / "docker", 'import sys\nsys.stdout.write(\'{"ServerVersion": "29.0.0"}\')\n')
    fake(d / "systemctl", "print('active')\n")
    v = role_vars(tmp_path, **{})
    v["docker_engine_cli"], v["docker_engine_systemctl_cli"] = (
        str(d / "docker"),
        str(d / "systemctl"),
    )
    v["docker_engine_state_dir"] = str(tmp_path / "state")
    ok = run_role(tmp_path, ROLE, "readiness", v)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    for gone in (tmp_path / "store" / "gguf" / REPO / MODEL_FILE,
                 tmp_path / "store" / "manifests" / "listings" / f"{STORE_ID}.sha256",
                 tmp_path / "dev" / "dri" / "renderD128"):  # fmt: skip
        keep = gone.read_bytes() if gone.is_file() else b""
        gone.unlink()
        r = run_role(tmp_path, ROLE, "readiness", v)
        assert r.returncode != 0, gone
        gone.write_bytes(keep)


def test_upgrade_records_a_newer_build_of_the_same_backend_and_refuses_the_rest(tmp_path):
    v = role_vars(tmp_path)
    (tmp_path / "app").mkdir()  # the project directory main created
    v[f"{MID}_target_image"] = image_for("vulkan", 12100)
    r = run_role(tmp_path, ROLE, "upgrade", v)
    assert r.returncode == 0, r.stdout + r.stderr
    for target in (image_for("vulkan", 12033),  # not newer
                   image_for("vulkan", 12000),  # older
                   image_for("cuda", 12100),  # another backend's build
                   DEFAULTS[f"{MID}_image"].split("@")[0].rsplit(":", 1)[0] + ":latest",
                   "docker.io/other/engine:server-vulkan-b12100@sha256:" + "ab" * 32):  # fmt: skip
        v[f"{MID}_target_image"] = target
        assert run_role(tmp_path, ROLE, "upgrade", v).returncode != 0, target


@pytest.mark.parametrize("hook", ["backup", "restore", "export"])
def test_the_data_hooks_say_there_is_nothing_to_do(tmp_path, hook):
    r = run_role(tmp_path, ROLE, hook, role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not list((tmp_path / "units").glob("*.service"))
