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
    assert "--backend cuda --max-watts 200 --gpu-index 1 --model-file" in unit
    cpu = tmp_path / "cpu"
    cpu.mkdir()
    store(cpu)
    v = role_vars(cpu, backend="cpu", image=image_for("cpu"))
    assert run_role(cpu, ROLE, "main", v).returncode == 0
    svc = compose(cpu)
    assert "devices" not in svc and svc["group_add"] == [str(MODELS_GID)]
    assert svc["command"][svc["command"].index("-ngl") + 1] == "0"


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
}


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


@pytest.mark.parametrize(
    "out, rc, ok",
    [("180.00\n", 0, True), ("200\n", 0, True), (" 200.00 \n", 0, True), ("200.01\n", 0, False),
     ("300.00\n", 0, False), ("[N/A]\n", 0, False), ("0.00\n", 0, False), ("", 0, False),
     ("180.00\n", 9, False)],
)  # fmt: skip
def test_precheck_judges_an_nvidia_cards_power_limit_in_watts(tmp_path, out, rc, ok):
    r = precheck("--backend", "cuda", "--max-watts", "200", "--gpu-index", "0", "--power-only",
                 env=_smi(tmp_path, out, rc))  # fmt: skip
    assert (r.returncode == 0) is ok, r.stdout + r.stderr


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
    assert paths == ["/health", "/v1/models", "/metrics", "/v1/chat/completions"]


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
        v = health_vars(tmp_path, srv, sysfs_root=str(sysfs(tmp_path, power)))
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0, what


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
