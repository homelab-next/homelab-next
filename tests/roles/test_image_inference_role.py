# SPDX-License-Identifier: Apache-2.0
"""The role of the inference provider that builds its own image (``modules/<id>``), run on localhost against fakes
(CI is unprivileged). The sibling of ``test_inference_server_role.py``; the same posture, the
engine's own settings:

* ``main`` renders one compose_app container (the card by CDI name, the model store's group by
  number, the weights read-only, no capability, no restart policy), the settings as environment
  variables of named keys only, a unit that is the container's only starter with the card and byte
  check before it, and a second run is ``changed=0``; bad inputs are refused before a file is written;
* the pre-start check refuses a power cap above the limit, a wrong GPU count, a stale CDI spec and
  weights (any shard, the direction file) that are not the pinned bytes;
* ``health`` passes against a stand-in of the server and fails for each thing it checks;
* ``readiness``, ``upgrade``, the archive's sha256 and the data hooks."""

from __future__ import annotations

import hashlib
import os
import pwd
import subprocess
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from conformance.fakes.openai_server import LOOPBACK
from tests.modules.single_model_server import SingleModelServer

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = "homelabnext.conform.adapters.inference_server:make"


def _find() -> Path:
    """The inference provider that builds its own image (it has an image/Dockerfile): the one this
    file is for. The product's name never appears in a test: the role's variables are the module
    id's prefix."""
    hits = [
        p.parent
        for p in sorted((ROOT / "modules").glob("*/module.yml"))
        if (yaml.safe_load(p.read_text()).get("provides") or {})
        .get("slots", {})
        .get("inference", {})
        .get("adapter")
        == ADAPTER
        and (p.parent / "image" / "Dockerfile").is_file()
    ]
    assert len(hits) == 1, hits
    return hits[0]


MODULE = _find()
MID = MODULE.name
ENV = f"HNX_{MID.upper()}_"  # the environment the image's starter reads
ROLE = str(MODULE / "roles" / MID)
SCRIPT = MODULE / "roles" / MID / "files" / f"hnx-{MID}-precheck"
DEFAULTS = yaml.safe_load((MODULE / "roles" / MID / "defaults" / "main.yml").read_text())
FIXED = yaml.safe_load((MODULE / "roles" / MID / "vars" / "main.yml").read_text())
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["infer-core"][
    "address"
]
UID = os.getuid() if os.getuid() >= 1000 else 61001
GID = os.getgid() if os.getgid() >= 1000 else 61001
MODELS_GID = 4102
UNIT = f"hnx-{MID}.service"
FILES = DEFAULTS[f"{MID}_model_files"]
REPO = DEFAULTS[f"{MID}_model_repo"]
STORE_ID = DEFAULTS[f"{MID}_model_store_id"]
IMAGE = DEFAULTS[f"{MID}_image"]
DIRECTION = "refusal-direction.gguf"
CTX = 4096


def store(tmp_path: Path, direction: bool = False, files: list[str] | None = None) -> str:
    """The model store with one entry (its shards, the direction file when asked, and the listing),
    as model_store writes it; returns the entry's digest."""
    root = tmp_path / "store"
    mdir = root / "gguf" / REPO
    mdir.mkdir(parents=True, exist_ok=True)
    names = list(files or FILES) + ([DIRECTION] if direction else [])
    lines = ""
    for n in sorted(names):
        content = f"bytes of {n}".encode()
        (mdir / n).write_bytes(content)
        lines += f"{hashlib.sha256(content).hexdigest()}  {n}\n"
    (root / "manifests" / "listings").mkdir(parents=True, exist_ok=True)
    (root / "manifests" / "listings" / f"{STORE_ID}.sha256").write_text(lines)
    return "sha256:" + hashlib.sha256(lines.encode()).hexdigest()


def _digest(tmp_path: Path) -> str:
    listing = (tmp_path / "store" / "manifests" / "listings" / f"{STORE_ID}.sha256").read_bytes()
    return "sha256:" + hashlib.sha256(listing).hexdigest()


def role_vars(tmp_path: Path, **kw) -> dict:
    """The role's inputs, pointed into tmp_path; keys are the names without the role prefix."""
    if not (tmp_path / "store").exists():
        store(tmp_path, direction=bool(kw.get("direction_file")))
    (tmp_path / "units").mkdir(exist_ok=True)  # /etc/systemd/system exists on a guest
    v = {
        "logical_id": "inference-moe",
        "dir": str(tmp_path / "app"),
        "data_root": str(tmp_path / "data"),
        "owner": USER,
        "uid": UID,
        "gid": GID,
        "store_root": str(tmp_path / "store"),
        "model_digest": _digest(tmp_path),
        "unit_dir": str(tmp_path / "units"),
        "precheck_bin": str(tmp_path / "bin" / "precheck"),
        "context_size": CTX,
        "models_gid": MODELS_GID,
        "start": False,
        "validate_with_docker": False,
    }
    v.update(kw)
    out = {f"{MID}_{k}": val for k, val in v.items()}
    out["ansible_host"] = GUEST
    return out


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"][MID]


# ----------------------------------------------------------------------------- main


def test_main_renders_the_container_the_unit_and_converges(tmp_path):
    v = role_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    svc = compose(tmp_path)
    assert svc["image"] == IMAGE
    assert svc["user"] == f"{UID}:{GID}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert "privileged" not in svc and "cap_add" not in svc
    assert svc["devices"] == ["nvidia.com/gpu=0"] and svc["group_add"] == [str(MODELS_GID)]
    assert svc["ports"] == [f"{GUEST}:{DEFAULTS[f'{MID}_port']}:8080"]
    # the unit is the one starter: docker never restarts the container by itself
    assert svc["restart"] == "no"
    store_dir = tmp_path / "store" / "gguf" / REPO
    assert svc["volumes"][0] == f"{store_dir}:/models:ro"  # the weights, read-only
    assert svc["volumes"][1] == f"{tmp_path / 'data' / 'data'}:/data"  # the one writable path
    assert "command" not in svc  # the image's starter owns the command line
    env = svc["environment"]
    assert not any(k for k in env if "KEY" in k or "TOKEN" in k)
    # what a placement that sets nothing new gets: the settings of a 64 GiB card with every expert resident
    assert {k: v for k, v in env.items() if k.startswith(ENV)} == {
        ENV + "MODEL_DIR": "/models",
        ENV + "MODEL_FILE": FILES[0],
        ENV + "SERVED_NAME": DEFAULTS[f"{MID}_served_model_name"],
        ENV + "CONTEXT": str(CTX),
        ENV + "KV": "k8v4",
        ENV + "PARALLEL": "1",
        ENV + "GPU": "0",
        ENV + "SPEC": "4",
        ENV + "DRAFTING": "off",
        ENV + "KV_STREAMING": "off",
        ENV + "MMAP_EXPERTS": "1",
        ENV + "PCIE_FRAC": "0",
    }
    # the unit: the check first, with the pinned digest, the card rules and every file, then the foreground up
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    pre = next(line for line in unit.splitlines() if line.startswith("ExecStartPre="))
    assert str(tmp_path / "bin" / "precheck") in pre
    assert f"--digest {v[f'{MID}_model_digest']}" in pre
    assert "--max-watts 200 --gpu-index 0 --expect-gpus 1 --proc-root /proc --dev-root /dev" in pre
    assert "--cdi-spec /etc/cdi/nvidia.yaml" in pre
    assert (
        f"--model-file {FILES[0]} --listing {tmp_path}/store/manifests/listings/{STORE_ID}.sha256"
        in pre
    )
    assert f"--also-file {FILES[1]}" in pre
    assert "up --no-color --no-log-prefix --abort-on-container-exit" in unit
    assert "stop --timeout 120" in unit  # the model gets two minutes to unload the card
    assert "Restart=on-failure" in unit and "TimeoutStartSec=1800" in unit
    assert oct((tmp_path / "bin" / "precheck").stat().st_mode & 0o777) == "0o755"
    assert oct((tmp_path / "data" / "data").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_main_gives_the_container_shared_memory_and_no_other_writable_path(tmp_path):
    r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    svc = compose(tmp_path)
    shm = [v for v in svc["volumes"] if isinstance(v, dict)]
    assert shm == [{"type": "tmpfs", "target": "/dev/shm", "tmpfs": {"size": 2147483648}}]
    assert "network_mode" not in svc
    assert svc["ulimits"] == {"memlock": {"soft": -1, "hard": -1}}
    assert [v for v in svc["volumes"] if isinstance(v, str) and not v.endswith(":ro")] == [
        f"{tmp_path / 'data' / 'data'}:/data"
    ]


def test_main_starts_through_the_unit_and_restarts_it_only_when_it_changed(tmp_path):
    bindir = tmp_path / "fakes"
    bindir.mkdir()
    log = bindir / "calls.log"
    fake(
        bindir / "systemctl",
        f"import sys\nopen({str(log)!r}, 'a').write('systemctl ' + ' '.join(sys.argv[1:]) + '\\n')\n",
    )
    v = role_vars(tmp_path, start=True, systemctl_cli=str(bindir / "systemctl"))
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert [c.split(" ", 1)[1] for c in log.read_text().splitlines()] == [
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
    v = role_vars(tmp_path)
    v["hnx_module_slice"] = f"hnx-{MID}-server.slice"
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert compose(tmp_path)["cgroup_parent"] == f"hnx-{MID}-server.slice"


def test_main_hands_the_container_the_card_it_is_placed_on(tmp_path):
    v = role_vars(tmp_path, gpu_index=1, expected_gpus=2)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert compose(tmp_path)["devices"] == ["nvidia.com/gpu=1"]
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    assert "--gpu-index 1 --expect-gpus 2 " in unit
    # the container sees ONE card, its own index 0, whichever the guest's index is
    assert compose(tmp_path)["environment"][ENV + "GPU"] == "0"


def test_main_passes_the_named_settings_and_the_direction_file_as_environment(tmp_path):
    extra = {
        "kv_streaming": "on",
        "mmap_experts": "off",
        "pcie_frac": 0.25,
        "threads": 12,
        "vram_reserve_mib": 1024,
    }
    v = role_vars(
        tmp_path, direction_file=DIRECTION, direction_scale=0.8, direction_layers=[4, 44],
        extra_args=extra, spec_depth=3, kv_mode="q4_0", parallel=2, drafting="auto", context_size=262144,
    )  # fmt: skip
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    env = compose(tmp_path)["environment"]
    assert env[ENV + "KV_STREAMING"] == "on" and env[ENV + "MMAP_EXPERTS"] == "0"
    assert env[ENV + "PCIE_FRAC"] == "0.25" and env[ENV + "POOL_WORKERS"] == "12"
    assert env[ENV + "VRAM_RESERVE_MIB"] == "1024" and env[ENV + "SPEC"] == "3"
    assert env[ENV + "KV"] == "q4_0" and env[ENV + "PARALLEL"] == "2"
    assert env[ENV + "DRAFTING"] == "auto" and env[ENV + "CONTEXT"] == "262144"
    assert env[ENV + "DIRECTION"] == DIRECTION
    assert env[ENV + "DIRECTION_SCALE"] == "0.8" and env[ENV + "DIRECTION_LAYERS"] == "4,44"
    # the direction file is pinned like a shard: the unit's check names it
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    assert f"--also-file {DIRECTION}" in unit and f"--also-file {FILES[1]}" in unit


def test_no_setting_reaches_the_engine_as_a_raw_flag(tmp_path):
    """The other inference provider refuses raw flags by design; so does this one: an unknown key, a flag-shaped key or
    a value that smuggles one is refused before a file is written."""
    for extra in (
        {"--rope-scaling": "yarn"},
        {"raw_args": "--api-key x"},
        {"threads": "8 --x"},
        {"kv_streaming": "--no-api-key"},
    ):
        r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path, extra_args=extra))
        assert r.returncode != 0, extra
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


REFUSED = {
    "image latest": {"image": IMAGE.split("@")[0].rsplit(":", 1)[0] + ":latest"},
    "image without a digest": {"image": IMAGE.split("@")[0]},
    "another repository's image": {"image": f"docker.io/other/{MID}:0.2.22-b28ca95e3e68@sha256:" + "ab" * 32},
    "a tag that is not a release and a commit": {"image": f"localhost/hnx-{MID}:v0.2.22@sha256:" + "ab" * 32},
    "bind all interfaces": {"bind": "0.0.0.0"},
    "bind a hostname": {"bind": "engine.example.internal"},
    "a privileged port": {"port": 80},
    "uid root": {"uid": 0},
    "gid under 1000": {"gid": 100},
    "a relative directory": {"dir": "relative/dir"},
    "a traversal in the store root": {"store_root": "/srv/../etc"},
    "a model repository with a traversal": {"model_repo": "../etc"},
    "a malformed digest": {"model_digest": "sha256:abc"},
    "a served name with a space": {"served_model_name": "my model"},
    "a context under 256": {"context_size": 100},
    "a context over 1M": {"context_size": 2000000},
    "no slots": {"parallel": 0},
    "too many slots": {"parallel": 17},
    "a draft depth above 8": {"spec_depth": 9},
    "a draft depth that is a string": {"spec_depth": "four"},
    "a KV mode that is not one": {"kv_mode": "fp8"},
    "a drafter that is not one": {"drafting": "dflash2"},
    "a models group that is root's": {"models_gid": 0},
    "a models group over 2^32-1": {"models_gid": 9999999999},
    "a power limit of zero": {"power_cap_max_watts": 0},
    "a power limit above the operator's 200 W": {"power_cap_max_watts": 201},
    "a card index above 15": {"gpu_index": 16, "expected_gpus": 16},
    "a card the guest is not to have": {"gpu_index": 1, "expected_gpus": 1},
    "no expected cards": {"expected_gpus": 0},
    # the model files: names inside the entry, a split model by its first shard and exactly its series
    "no model files": {"model_files": []},
    "a model file that is not gguf": {"model_files": ["weights.bin"]},
    "an absolute model file": {"model_files": ["/srv/models/x.gguf"]},
    "a model file with a traversal": {"model_files": ["../x.gguf"]},
    "a model file in a directory": {"model_files": ["Q8_0/x.gguf"]},
    "a model file in a dot directory": {"model_files": [".hidden.gguf"]},
    "a later shard first": {"model_files": ["m-00002-of-00002.gguf", "m-00001-of-00002.gguf"]},
    "a series that is short": {"model_files": ["m-00001-of-00003.gguf", "m-00002-of-00003.gguf"]},
    "a series of other stems": {"model_files": ["a-00001-of-00002.gguf", "b-00002-of-00002.gguf"]},
    "two files that are no series": {"model_files": ["a.gguf", "b.gguf"]},
    "a series too long to check": {"model_files": ["m-00001-of-99999.gguf"]},
    "a file listed twice": {"model_files": [FILES[0], FILES[0]]},
    "a direction file that is also a shard": {"direction_file": FILES[1]},
    "a direction file with a traversal": {"direction_file": "../d.gguf"},
    "a direction scale of zero": {"direction_file": DIRECTION, "direction_scale": 0},
    "a direction scale above 4": {"direction_file": DIRECTION, "direction_scale": 9},
    "a direction scale that is a boolean": {"direction_file": DIRECTION, "direction_scale": True},
    "layers in the wrong order": {"direction_file": DIRECTION, "direction_layers": [44, 4]},
    "three layers": {"direction_file": DIRECTION, "direction_layers": [4, 20, 44]},
    # the named settings, each of its own type and range
    "a setting that is no name of the list": {"extra_args": {"api_key": "x"}},
    "kv_streaming of another word": {"extra_args": {"kv_streaming": "always"}},
    "a pcie_frac above 0.95": {"extra_args": {"pcie_frac": 1}},
    "a negative pcie_frac": {"extra_args": {"pcie_frac": -0.1}},
    "a pcie_frac that is a string": {"extra_args": {"pcie_frac": "0.5"}},
    "threads of zero": {"extra_args": {"threads": 0}},
    "threads above 256": {"extra_args": {"threads": 257}},
    "threads that are a boolean": {"extra_args": {"threads": True}},
    "a vram reserve above 64 GiB": {"extra_args": {"vram_reserve_mib": 65537}},
    "a vram reserve that is negative": {"extra_args": {"vram_reserve_mib": -1}},
    "an archive without its sha256": {"image_archive": f"/var/lib/images/{MID}.oci.tar"},
    "an archive sha256 that is short": {"image_archive": f"/var/lib/images/{MID}.oci.tar", "image_archive_sha256": "abc"},
}  # fmt: skip


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_main_refuses_bad_inputs_before_writing_anything(tmp_path, case):
    kw = dict(REFUSED[case])
    r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path, **kw))
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert not list((tmp_path / "units").glob("*.service"))


def test_main_takes_a_split_model_whose_series_is_listed_in_order(tmp_path):
    files = [f"m-0000{n}-of-00003.gguf" for n in (1, 2, 3)]
    store(tmp_path, files=files)
    r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path, model_files=files))
    assert r.returncode == 0, r.stdout + r.stderr
    assert compose(tmp_path)["environment"][ENV + "MODEL_FILE"] == files[0]
    unit = next((tmp_path / "units").glob("*.service")).read_text()
    assert unit.count("--also-file") == 2
    single = tmp_path / "single"
    single.mkdir()
    store(single, files=["one.gguf"])
    r = run_role(single, ROLE, "main", role_vars(single, model_files=["one.gguf"]))
    assert r.returncode == 0, r.stdout + r.stderr


def test_main_refuses_when_a_shard_or_the_direction_file_is_not_in_the_store(tmp_path):
    v = role_vars(tmp_path)
    (tmp_path / "store" / "gguf" / REPO / FILES[1]).unlink()
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0 and not list((tmp_path / "units").glob("*.service"))
    other = tmp_path / "other"
    other.mkdir()
    store(other)  # no direction file in the store
    r = run_role(other, ROLE, "main", role_vars(other, direction_file=DIRECTION))
    assert r.returncode != 0 and not list((other / "units").glob("*.service"))


def test_main_refuses_a_model_file_that_is_a_link_out_of_the_store(tmp_path):
    v = role_vars(tmp_path)
    shard = tmp_path / "store" / "gguf" / REPO / FILES[0]
    target = tmp_path / "elsewhere.gguf"
    target.write_bytes(shard.read_bytes())
    shard.unlink()
    shard.symlink_to(target)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0 and not list((tmp_path / "units").glob("*.service"))


def test_main_in_check_mode_on_a_first_install_reports_instead_of_failing(tmp_path):
    r = run_role(tmp_path, ROLE, "main", role_vars(tmp_path), check=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


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


def test_main_loads_the_archive_only_when_its_sha256_is_the_pinned_one_and_the_daemon_lacks_the_image(
    tmp_path,
):
    archive = tmp_path / "image.oci.tar"
    archive.write_bytes(b"not read by the fake")
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    v = role_vars(tmp_path, image_archive=str(archive), image_archive_sha256=sha)
    env = _docker_with_image(tmp_path, has_image=False)
    assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
    assert f"load -i {archive}" in (tmp_path / "docker.log").read_text()
    (tmp_path / "docker.log").unlink()
    assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0  # present now: no load
    assert "load" not in (tmp_path / "docker.log").read_text()


def test_main_refuses_an_archive_whose_sha256_is_not_the_pinned_one_before_loading_it(tmp_path):
    archive = tmp_path / "image.oci.tar"
    archive.write_bytes(b"swapped")
    v = role_vars(tmp_path, image_archive=str(archive), image_archive_sha256="ab" * 32)
    r = run_role(tmp_path, ROLE, "main", v, env=_docker_with_image(tmp_path, has_image=False))
    assert r.returncode != 0 and "whose sha256 is the pinned" in r.stdout + r.stderr
    assert "load" not in (tmp_path / "docker.log").read_text()
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_main_refuses_an_archive_that_is_missing(tmp_path):
    v = role_vars(
        tmp_path, image_archive=str(tmp_path / "absent.oci.tar"), image_archive_sha256="ab" * 32
    )
    r = run_role(tmp_path, ROLE, "main", v, env=_docker_with_image(tmp_path, has_image=False))
    assert r.returncode != 0
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- the pre-start check


def precheck(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([str(SCRIPT), *args], capture_output=True, text=True,
                          env={**os.environ, **(env or {})})  # fmt: skip


def _smi(tmp_path: Path, out: str, rc: int = 0) -> dict:
    d = tmp_path / "smi"
    d.mkdir(exist_ok=True)
    fake(d / "nvidia-smi", f"import sys\nsys.stdout.write({out!r})\nsys.exit({rc})\n")
    return {"PATH": f"{d}:{os.environ['PATH']}"}


def _rows(*limits: tuple[str, str]) -> str:
    """nvidia-smi --query-gpu=index,power.limit,enforced.power.limit csv, one card per pair."""
    return "".join(f"{i}, {lim}, {enf}\n" for i, (lim, enf) in enumerate(limits))


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


BASE = ("--max-watts", "200", "--gpu-index", "0", "--expect-gpus", "1", "--power-only")
ONE = _rows(("180.00", "180.00"))


@pytest.mark.parametrize(
    "limit, enforced, rc, ok",
    [("180.00", "180.00", 0, True), ("200", "200", 0, True), (" 200.00 ", "200.00", 0, True),
     ("200.01", "200.00", 0, False), ("300.00", "300.00", 0, False), ("[N/A]", "180.00", 0, False),
     ("0.00", "0.00", 0, False), ("", "", 0, False), ("180.00", "180.00", 9, False),
     # the limit set is within, the one the card enforces is not (or cannot be read)
     ("180.00", "250.00", 0, False), ("180.00", "[N/A]", 0, False), ("180.00", "[Not Supported]", 0, False)],
)  # fmt: skip
def test_precheck_judges_the_cards_power_limit_in_watts(tmp_path, limit, enforced, rc, ok):
    r = precheck(*BASE, *driver_up(tmp_path), env=_smi(tmp_path, _rows((limit, enforced)), rc))
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    if not ok:
        assert r.returncode == 1 and "refusing to load the model" in r.stderr


@pytest.mark.parametrize(
    "out, expect, idx, ok, needle",
    [(ONE, 1, 0, True, "exactly 1 GPU(s) listed"),
     (_rows(("180.00", "180.00"), ("180.00", "180.00")), 2, 1, True, "GPU 1 power limit"),
     # a card fell off the bus: the guest lists fewer than the placement expects
     ("", 1, 0, False, "lists 0 GPU(s), the placement expects exactly 1"),
     (ONE, 2, 0, False, "lists 1 GPU(s), the placement expects exactly 2"),
     # one more than the site placed
     (_rows(("180.00", "180.00"), ("180.00", "180.00")), 1, 0, False, "lists 2 GPU(s), the placement expects exactly 1"),
     # the card the container is given is not one of those listed
     (_rows(("180.00", "180.00"), ("180.00", "180.00")), 2, 3, False, "GPU 3 is not listed once"),
     # a card that is not the one handed over is still counted, but its own cap is not what is judged
     (_rows(("180.00", "180.00"), ("400.00", "400.00")), 2, 0, True, "GPU 0 power limit")],
)  # fmt: skip
def test_precheck_holds_the_guest_to_exactly_the_expected_number_of_cards(
    tmp_path, out, expect, idx, ok, needle
):
    r = precheck("--max-watts", "200", "--gpu-index", str(idx), "--expect-gpus", str(expect), "--power-only",
                 *driver_up(tmp_path), env=_smi(tmp_path, out))  # fmt: skip
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    assert needle in (r.stdout if ok else r.stderr), r.stdout + r.stderr


@pytest.mark.parametrize(
    "args",
    [(), ("--max-watts", "200"), ("--max-watts", "0", "--gpu-index", "0", "--expect-gpus", "1"),
     ("--max-watts", "201", "--gpu-index", "0", "--expect-gpus", "1"),  # above the operator's 200 W rule
     ("--max-watts", "200", "--gpu-index", "all", "--expect-gpus", "1"),
     ("--max-watts", "200", "--gpu-index", "0,1", "--expect-gpus", "2"),
     ("--max-watts", "200", "--gpu-index", "0", "--expect-gpus", "0"),
     ("--max-watts", "200", "--gpu-index", "0", "--expect-gpus", "x"),
     ("--max-watts", "200", "--gpu-index", "-1", "--expect-gpus", "1"),
     ("--bogus",)],
)  # fmt: skip
def test_precheck_refuses_bad_usage(tmp_path, args):
    r = precheck(*args, "--power-only", *driver_up(tmp_path), env=_smi(tmp_path, ONE))
    assert r.returncode == 2 and "usage" in r.stderr, r.stdout + r.stderr


@pytest.mark.parametrize(
    "modules, ctl",
    [("", True), ("nvidia_uvm 1 0 - Live 0x0\ndrm 2 0 - Live 0x0\n", True), ("nvidia 2 0 - Live 0x0\n", False)],
)  # fmt: skip
def test_precheck_never_runs_nvidia_smi_unless_the_driver_is_already_loaded(tmp_path, modules, ctl):
    """nvidia-smi as root loads the nvidia module when it is absent: a warm-card load on a guest
    whose cards must not be initialised that way."""
    log = tmp_path / "smi.log"
    env = _smi(tmp_path, ONE)
    fake(
        tmp_path / "smi" / "nvidia-smi",
        f"import sys\nopen({str(log)!r}, 'a').write('ran')\nsys.stdout.write({ONE!r})\n",
    )
    r = precheck(*BASE, *driver_up(tmp_path, modules, ctl), env=env)
    assert r.returncode == 1 and "nvidia-smi is not run" in r.stderr, r.stderr
    assert not log.exists()
    ok = tmp_path / "ok"
    ok.mkdir()
    r = precheck(*BASE, *driver_up(ok), env=env)
    assert r.returncode == 0 and log.read_text() == "ran", r.stderr


def _cdi_world(tmp_path: Path, spec_majors: dict[str, int], live_majors: dict[str, int | None]):
    """A CDI spec recording device majors and a dev root whose nodes are fake files; the precheck
    reads a node's major with ``stat``, so a fake ``stat`` answers from a table."""
    spec = tmp_path / "nvidia.yaml"
    spec.write_text("devices:\n- name: all\n  containerEdits:\n    deviceNodes:\n" + "".join(
        f"    - path: /dev/{n}\n      major: {m}\n      fileMode: 438\n" for n, m in spec_majors.items()
    ) + "    - path: /dev/nvidia0\n      fileMode: 438\n")  # fmt: skip
    args = driver_up(tmp_path)
    dev = Path(args[3])
    table = {}
    for n, m in live_majors.items():
        if m is not None:
            (dev / n).write_text("")
            table[str(dev / n)] = f"{m:x}"
    env = _smi(tmp_path, ONE)
    fake(tmp_path / "smi" / "stat", f"import sys\nprint({table!r}[sys.argv[-1]])\n")
    return [*args, "--cdi-spec", str(spec)], env


@pytest.mark.parametrize(
    "spec, live, ok, msg",
    [({"nvidia-uvm": 235, "nvidia-uvm-tools": 235}, {"nvidia-uvm": 235, "nvidia-uvm-tools": 235}, True, ""),
     ({"nvidia-uvm": 234, "nvidia-uvm-tools": 234}, {"nvidia-uvm": 235, "nvidia-uvm-tools": 235}, False, "nvidia-uvm is major 235 here, the spec says 234"),
     ({"nvidia-uvm": 235}, {"nvidia-uvm": None}, False, "nvidia-uvm is not on this host")],
)  # fmt: skip
def test_precheck_refuses_a_cdi_spec_whose_device_majors_differ_from_the_live_nodes(
    tmp_path, spec, live, ok, msg
):
    """nvidia-uvm's major is assigned at module load: a spec from before a reboot hands the container
    the wrong node, cuInit fails (CUDA error 999) and the model silently runs on the CPU."""
    args, env = _cdi_world(tmp_path, spec, live)
    r = precheck(*BASE, *args, env=env)
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    if ok:
        assert "device majors match" in r.stdout
    else:
        assert "stale" in r.stderr and msg in r.stderr


def test_precheck_refuses_a_missing_cdi_spec_and_ignores_it_without_the_flag(tmp_path):
    env = _smi(tmp_path, ONE)
    r = precheck(*BASE, *driver_up(tmp_path), "--cdi-spec", str(tmp_path / "absent.yaml"), env=env)
    assert r.returncode == 1 and "missing or empty" in r.stderr
    assert precheck(*BASE, *driver_up(tmp_path), env=env).returncode == 0


@pytest.mark.static
def test_the_unit_passes_the_driver_seams_as_fixed_paths():
    assert FIXED[f"{MID}_proc_root"] == "/proc" and FIXED[f"{MID}_dev_root"] == "/dev"
    assert f"{MID}_proc_root" not in DEFAULTS and f"{MID}_dev_root" not in DEFAULTS
    assert FIXED[f"{MID}_power_cap_ceiling_watts"] == 200


def _entry(tmp_path: Path, direction: bool = True) -> tuple[Path, Path, str]:
    """A store entry and its listing; returns (model dir, listing, digest)."""
    digest = store(tmp_path, direction=direction)
    return (tmp_path / "store" / "gguf" / REPO,
            tmp_path / "store" / "manifests" / "listings" / f"{STORE_ID}.sha256", digest)  # fmt: skip


def _bytes_args(
    tmp_path: Path, mdir: Path, listing: Path, digest: str, *also: str, mfile: str | None = None
) -> list[str]:
    a = ["--max-watts", "200", "--gpu-index", "0", "--expect-gpus", "1", *driver_up(tmp_path),
         "--model-file", mfile or FILES[0], "--listing", str(listing), "--digest", digest,
         "--model-dir", str(mdir)]  # fmt: skip
    for f in also:
        a += ["--also-file", f]
    return a


def test_precheck_passes_the_pinned_bytes_of_every_shard_and_the_direction_file(tmp_path):
    mdir, listing, digest = _entry(tmp_path)
    r = precheck(
        *_bytes_args(tmp_path, mdir, listing, digest, FILES[1], DIRECTION), env=_smi(tmp_path, ONE)
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "all 2 shards" in r.stdout and "are the pinned bytes" in r.stdout


@pytest.mark.parametrize("victim", [FILES[0], FILES[1], DIRECTION])
def test_precheck_refuses_any_file_whose_bytes_changed(tmp_path, victim):
    mdir, listing, digest = _entry(tmp_path)
    (mdir / victim).write_bytes(b"tampered")
    r = precheck(
        *_bytes_args(tmp_path, mdir, listing, digest, FILES[1], DIRECTION), env=_smi(tmp_path, ONE)
    )
    assert r.returncode == 1 and "does not match" in r.stderr, r.stderr


def test_precheck_refuses_a_listing_that_is_not_the_pinned_digest(tmp_path):
    mdir, listing, digest = _entry(tmp_path)
    r = precheck(
        *_bytes_args(tmp_path, mdir, listing, "sha256:" + "0" * 64, FILES[1]),
        env=_smi(tmp_path, ONE),
    )
    assert r.returncode == 1 and "the module pins" in r.stderr
    r = precheck(
        *_bytes_args(tmp_path, mdir, tmp_path / "absent.sha256", digest), env=_smi(tmp_path, ONE)
    )
    assert r.returncode == 1 and "is missing" in r.stderr


def test_precheck_requires_every_file_it_is_told_of_to_be_in_the_pinned_listing(tmp_path):
    mdir, listing, digest = _entry(tmp_path, direction=False)
    (mdir / DIRECTION).write_bytes(b"not in the listing")  # on disk, never pinned
    env = _smi(tmp_path, ONE)
    r = precheck(*_bytes_args(tmp_path, mdir, listing, digest, FILES[1], DIRECTION), env=env)
    assert r.returncode == 1 and f"{DIRECTION} is not in" in r.stderr, r.stderr
    r = precheck(
        *_bytes_args(tmp_path, mdir, listing, digest, FILES[1], mfile="extra.gguf"), env=env
    )
    assert r.returncode == 1 and "extra.gguf is not in" in r.stderr, r.stderr


def test_precheck_refuses_a_split_model_with_an_unpinned_shard_or_a_later_shard_named(tmp_path):
    files = [f"m-0000{n}-of-00003.gguf" for n in (1, 2, 3)]
    mdir, listing, digest = _entry(tmp_path, direction=False)
    # the entry lists two of the three shards of the series the server is given the first of
    digest = store(tmp_path, files=files[:2])
    env = _smi(tmp_path, ONE)
    r = precheck(*_bytes_args(tmp_path, mdir, listing, digest, mfile=files[0]), env=env)
    assert r.returncode == 1 and "m-00003-of-00003.gguf (shard 3 of 00003) is not in" in r.stderr, (
        r.stderr
    )
    digest = store(tmp_path, files=files)
    r = precheck(*_bytes_args(tmp_path, mdir, listing, digest, mfile=files[1]), env=env)
    assert r.returncode == 1 and "must be given the first shard" in r.stderr


@pytest.mark.parametrize(
    "name", ["/abs.gguf", "../x.gguf", "a/../x.gguf", "./x.gguf", "a//x.gguf", ".."]
)
def test_precheck_refuses_a_file_that_is_not_a_path_inside_the_entry(tmp_path, name):
    mdir, listing, digest = _entry(tmp_path, direction=False)
    r = precheck(*_bytes_args(tmp_path, mdir, listing, digest, mfile=name), env=_smi(tmp_path, ONE))
    assert r.returncode == 1 and "not a path inside" in r.stderr, r.stderr
    r = precheck(*_bytes_args(tmp_path, mdir, listing, digest, name), env=_smi(tmp_path, ONE))
    assert r.returncode == 1 and "not a path inside" in r.stderr, r.stderr


def test_precheck_refuses_shards_that_resolve_out_of_the_entry(tmp_path):
    mdir, listing, digest = _entry(tmp_path, direction=False)
    outside = tmp_path / "outside.gguf"
    outside.write_bytes((mdir / FILES[1]).read_bytes())
    (mdir / FILES[1]).unlink()
    (mdir / FILES[1]).symlink_to(outside)  # the bytes still match the listing, but live elsewhere
    r = precheck(*_bytes_args(tmp_path, mdir, listing, digest, FILES[1]), env=_smi(tmp_path, ONE))
    assert r.returncode == 1 and "resolves outside" in r.stderr, r.stderr


def test_precheck_checks_the_card_before_it_reads_the_weights(tmp_path):
    mdir, listing, digest = _entry(tmp_path, direction=False)
    (mdir / FILES[0]).write_bytes(b"tampered")
    r = precheck(
        *_bytes_args(tmp_path, mdir, listing, digest, FILES[1]),
        env=_smi(tmp_path, _rows(("250.00", "250.00"))),
    )
    assert r.returncode == 1 and "not within 0 to 200 W" in r.stderr  # not "does not match"


# ----------------------------------------------------------------------------- health


class EngineServer(SingleModelServer):
    """The server's own /health as its documentation gives it: 200 from the moment the API is up, with
    "loaded" false until the model is."""

    def _handler(self):
        srv = self
        base = super()._handler()

        class Handler(base):
            def do_GET(self) -> None:
                if self.path == "/health":
                    srv.requests.append(("GET", self.path))
                    srv._health_polls += 1
                    loaded = not (srv.loading or srv._health_polls <= srv.loading_polls)
                    self._send(200, {"status": "ok", "loaded": loaded, "service": MID})
                else:
                    super().do_GET()

        return Handler


def _fakes(
    tmp_path: Path, *, unit: str = "active", health: str = "healthy", smi: str = ONE
) -> dict:
    d = tmp_path / "fakes"
    d.mkdir(exist_ok=True)
    state = f'{{"Service": "{MID}", "State": "running", "Health": "{health}"}}\\n'
    fake(d / "docker", f"import sys\nsys.stdout.write('{state}')\n")
    fake(
        d / "systemctl",
        f"import sys\nprint({unit!r})\nsys.exit(0 if {unit!r} == 'active' else 3)\n",
    )
    fake(d / "nvidia-smi", f"import sys\nsys.stdout.write({smi!r})\n")
    return {"PATH": f"{d}:{os.environ['PATH']}"}


def health_vars(tmp_path: Path, srv: SingleModelServer, **kw) -> dict:
    drv = driver_up(tmp_path)
    return role_vars(
        tmp_path, bind=LOOPBACK, port=srv.port, precheck_bin=str(SCRIPT),
        systemctl_cli=str(tmp_path / "fakes" / "systemctl"), proc_root=drv[1], dev_root=drv[3],
        cdi_spec="/nonexistent-is-not-read-by-the-fake",
        **kw,
    )  # fmt: skip


def engine(**kw) -> EngineServer:
    kw.setdefault("n_ctx", CTX)
    return EngineServer(model="qwen3.8-flash-next-iq3_xxs", **kw)


def _run_health(tmp_path: Path, srv: EngineServer, env: dict, **kw):
    """health with the seams pointed at fakes; the card rule runs against a CDI spec that is a real file."""
    spec = tmp_path / "cdi.yaml"
    spec.write_text("devices: []\n")
    v = health_vars(tmp_path, srv, **kw)
    v[f"{MID}_cdi_spec"] = str(spec)
    return run_role(tmp_path, ROLE, "health", v, env=env)


def test_health_passes_when_every_check_holds(tmp_path):
    env = _fakes(tmp_path)
    with engine() as srv:
        r = _run_health(tmp_path, srv, env)
        paths = [p for _, p in srv.requests]
    assert r.returncode == 0, r.stdout + r.stderr
    # the readiness wait's /health comes first, then the checks, the warm-up and the timed probe
    assert paths == ["/health", "/v1/models", "/metrics"] + ["/v1/chat/completions"] * 2


def test_health_waits_for_a_model_that_is_still_loading(tmp_path):
    """The server answers /health 200 the moment its API is up, with loaded false until the model is:
    health retries until it says loaded instead of failing on the first answer."""
    env = _fakes(tmp_path)
    with engine(loading_polls=2) as srv:
        r = _run_health(tmp_path, srv, env, load_timeout=30, load_poll_s=1)
        health_calls = [p for _, p in srv.requests if p == "/health"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(health_calls) >= 3


def test_health_survives_a_cold_first_request_slower_than_the_steady_state_timeout(tmp_path):
    env = _fakes(tmp_path)
    with engine(first_chat_delay=3.0) as srv:
        r = _run_health(tmp_path, srv, env, health_timeout=1, first_request_timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr


def test_health_still_fails_a_server_that_is_slow_on_every_request(tmp_path):
    env = _fakes(tmp_path)
    with engine(chat_delay=3.0) as srv:
        r = _run_health(tmp_path, srv, env, health_timeout=1, first_request_timeout=30)
    assert r.returncode != 0


@pytest.mark.parametrize(
    "what, srv_kw, fakes_kw, kw",
    [
        ("the model is still loading", {"loading": True}, {}, {}),
        ("a context larger than the one the role declares", {"n_ctx": CTX * 2}, {}, {}),
        ("a context the engine does not report", {"reports_ctx": False}, {}, {}),
        ("no metrics route", {"metrics": False}, {}, {}),
        ("the unit is not active", {}, {"unit": "failed"}, {}),
        ("the container is unhealthy", {}, {"health": "unhealthy"}, {}),
        ("the power cap was raised after the start", {}, {"smi": _rows(("250.00", "250.00"))}, {}),
        ("a card fell off the bus", {}, {"smi": ""}, {}),
        ("a second card appeared", {}, {"smi": _rows(("180.00", "180.00"), ("180.00", "180.00"))}, {}),
    ],
)  # fmt: skip
def test_health_fails_for_each_thing_it_checks(tmp_path, what, srv_kw, fakes_kw, kw):
    env = _fakes(tmp_path, **fakes_kw)
    with engine(**srv_kw) as srv:
        r = _run_health(tmp_path, srv, env, load_timeout=1, load_poll_s=1, **kw)
    assert r.returncode != 0, what


# ----------------------------------------------------------------------------- the other hooks


def test_readiness_needs_the_engine_the_weights_their_listing_and_the_cdi_spec(tmp_path):
    d = tmp_path / "fakes"
    d.mkdir()
    fake(d / "docker", 'import sys\nsys.stdout.write(\'{"ServerVersion": "29.0.0"}\')\n')
    fake(d / "systemctl", "print('active')\n")
    spec = tmp_path / "nvidia.yaml"
    spec.write_text("devices: []\n")
    v = role_vars(tmp_path, direction_file=DIRECTION, cdi_spec=str(spec))
    v["docker_engine_cli"], v["docker_engine_systemctl_cli"] = (
        str(d / "docker"),
        str(d / "systemctl"),
    )
    v["docker_engine_state_dir"] = str(tmp_path / "state")
    ok = run_role(tmp_path, ROLE, "readiness", v)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    for gone in (tmp_path / "store" / "gguf" / REPO / FILES[0],
                 tmp_path / "store" / "gguf" / REPO / FILES[1],
                 tmp_path / "store" / "gguf" / REPO / DIRECTION,
                 tmp_path / "store" / "manifests" / "listings" / f"{STORE_ID}.sha256",
                 spec):  # fmt: skip
        keep = gone.read_bytes()
        gone.unlink()
        r = run_role(tmp_path, ROLE, "readiness", v)
        assert r.returncode != 0, gone
        gone.write_bytes(keep)


def _release(tag: str, digest: str = "ab" * 32, repo: str | None = None) -> str:
    return f"{repo or IMAGE.split('@')[0].rsplit(':', 1)[0]}:{tag}@sha256:{digest}"


def test_upgrade_records_a_newer_release_of_the_labs_build_and_refuses_the_rest(tmp_path):
    v = role_vars(tmp_path)
    (tmp_path / "app").mkdir()  # the project directory main created
    v[f"{MID}_target_image"] = _release("0.2.23-0123456789ab")
    r = run_role(tmp_path, ROLE, "upgrade", v)
    assert r.returncode == 0, r.stdout + r.stderr
    for target in (_release("0.2.22-0123456789ab"),  # not newer
                   _release("0.2.21-0123456789ab"),  # older
                   _release("0.1.99-0123456789ab"),  # an older minor
                   _release("latest"), _release("0.2.23"),  # no commit in the tag
                   f"docker.io/other/{MID}:0.2.23-0123456789ab@sha256:" + "ab" * 32,
                   IMAGE.split("@")[0] + "-x"):  # fmt: skip
        v[f"{MID}_target_image"] = target
        assert run_role(tmp_path, ROLE, "upgrade", v).returncode != 0, target


@pytest.mark.parametrize("hook", ["backup", "restore", "export"])
def test_the_data_hooks_say_there_is_nothing_to_do(tmp_path, hook):
    r = run_role(tmp_path, ROLE, hook, role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not list((tmp_path / "units").glob("*.service"))


def test_a_yaml_boolean_is_accepted_for_the_on_off_settings(tmp_path):
    """An unquoted on or off is a boolean to YAML 1.1: true means on, false means off."""
    r = run_role(
        tmp_path,
        ROLE,
        "main",
        role_vars(tmp_path, extra_args={"kv_streaming": True, "mmap_experts": False}),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    env = compose(tmp_path)["environment"]
    assert env[ENV + "KV_STREAMING"] == "on" and env[ENV + "MMAP_EXPERTS"] == "0"
    other = tmp_path / "other"
    other.mkdir()
    r = run_role(
        other,
        ROLE,
        "main",
        role_vars(other, extra_args={"kv_streaming": False, "mmap_experts": True}),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    env = compose(other)["environment"]
    assert env[ENV + "KV_STREAMING"] == "off" and env[ENV + "MMAP_EXPERTS"] == "1"


def test_health_fails_when_the_container_log_says_the_engine_ran_out_of_pinned_memory(tmp_path):
    env = _fakes(tmp_path)
    fake(
        tmp_path / "fakes" / "docker",
        "import sys\n"
        "if 'logs' in sys.argv:\n    print('[pinned-memory-exhausted]')\n"
        f'else:\n    sys.stdout.write(\'{{"Service": "{MID}", "State": "running", "Health": "healthy"}}\\n\')\n',
    )
    with engine() as srv:
        r = _run_health(tmp_path, srv, env, load_timeout=1, load_poll_s=1)
    assert r.returncode != 0 and "pinned-memory-exhausted" in r.stdout
