# SPDX-License-Identifier: Apache-2.0
"""Role ``tts`` (modules/tts/roles/tts), run on localhost against fakes (CI is unprivileged): main
renders the speech container through compose_app (weights, listing and voice read-only, the state and
the cache the only writable paths, a card only by its CDI device, no secrets) and a second run is
``changed=0``; malformed inputs, a missing voice, weights or listing, another image and a power cap
limit above the operator's 200 W are refused; health proves the shape of /health, /ready and one real
synthesis; export and restore round-trip the voice and refuse a tampered or unsafe archive; upgrade
refuses an unpinned target."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import tarfile
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from tests.modules.tts_front import REFS, Server

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "tts" / "roles" / "tts")
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULTS = yaml.safe_load(
    (ROOT / "modules" / "tts" / "roles" / "tts" / "defaults" / "main.yml").read_text()
)
REPO = "localhost/hnx-tts"
DIGEST = "sha256:" + "a" * 64
IMAGE = f"{REPO}:0.1.0-abc123def456-cpu@{DIGEST}"
CUDA_IMAGE = f"{REPO}:0.1.0-abc123def456-cuda@{DIGEST}"
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["dns-core"][
    "address"
]
REVISION = DEFAULTS["tts_model_revision"]
MODELS_GID = 1234


def tts_vars(tmp_path: Path, voice=True, store=True, **kw) -> dict:
    """A store entry and the voice on disk, and the variables that point at them."""
    store_root = tmp_path / "store"
    top = store_root / "hf" / "hub" / "models--coqui--XTTS-v2"
    if store:
        (top / "snapshots" / REVISION).mkdir(parents=True, exist_ok=True)
        (top / "snapshots" / REVISION / "model.pth").write_bytes(b"w")
        (store_root / "manifests" / "listings").mkdir(parents=True, exist_ok=True)
        (store_root / "manifests" / "listings" / "xtts-v2.sha256").write_text("")
    if voice:
        (tmp_path / "data" / "voice").mkdir(parents=True, exist_ok=True)
        for n in REFS:
            (tmp_path / "data" / "voice" / n).write_bytes(b"RIFF" + n.encode())
    v = {
        "tts_logical_id": "tts",
        "tts_image": IMAGE,
        "ansible_host": GUEST,
        "tts_dir": str(tmp_path / "app"),
        "tts_data_root": str(tmp_path / "data"),
        "tts_cache_dir": str(tmp_path / "cache"),
        "tts_store_root": str(store_root),
        "tts_models_gid": MODELS_GID,
        "tts_owner": USER,
        "tts_uid": os.getuid(),
        "tts_gid": os.getgid(),
        "tts_start": False,
        "tts_validate_with_docker": False,
    }
    v.update(kw)
    return v


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]["tts"]


def _first_main_renders_read_only_weights_and_voice_one_state_and_no_secrets(tmp_path):
    v = tts_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


@first_run(_first_main_renders_read_only_weights_and_voice_one_state_and_no_secrets)
def test_main_renders_read_only_weights_and_voice_one_state_and_no_secrets(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    svc = compose(tmp_path)
    assert svc["image"] == IMAGE and "@sha256:" in svc["image"]
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert [str(g) for g in svc["group_add"]] == [str(MODELS_GID)]
    assert svc["ports"] == [GUEST + ":8091:8091"]
    top = f"{tmp_path}/store/hf/hub/models--coqui--XTTS-v2"
    assert svc["volumes"] == [
        f"{top}:/models:ro",
        f"{tmp_path}/store/manifests/listings/xtts-v2.sha256:/listing.sha256:ro",
        f"{tmp_path}/data/voice:/voice:ro",
        f"{tmp_path}/data/state:/state",
        f"{tmp_path}/cache:/cache",
    ]
    env = svc["environment"]
    assert env["TTS_MODEL_DIR"] == f"/models/snapshots/{REVISION}"
    assert env["TTS_MODEL_DIGEST"] == DEFAULTS["tts_model_digest"]
    assert env["TTS_REF_FILES"] == ",".join(REFS) and env["TTS_BACKEND"] == "cpu"
    assert env["TTS_IDLE_UNLOAD_S"] == "0"  # the model stays in memory on a cpu
    assert env["TTS_POWER_CAP_MAX_WATTS"] == "200"
    assert env["TTS_MAX_TEXT_CHARS"] == "200000" and env["TTS_JOB_TIMEOUT_S"] == "7200"
    # a cpu backend: no device, no privilege; nothing to fetch, nothing secret
    assert "devices" not in svc and not svc.get("privileged")
    assert not (tmp_path / "app" / "secrets").exists()
    assert svc["healthcheck"]["test"][:2] == ["CMD", "python"]
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_the_state_belongs_to_the_container_and_the_voice_is_never_its_to_write(tmp_path):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": tts_vars(tmp_path)}


@first_run(_first_the_state_belongs_to_the_container_and_the_voice_is_never_its_to_write)
def test_the_state_belongs_to_the_container_and_the_voice_is_never_its_to_write(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    mode = lambda p: oct((tmp_path / p).stat().st_mode & 0o777)  # noqa: E731
    assert mode("data/state") == "0o700" and mode("data/export") == "0o700"
    assert mode("data/voice") == "0o750"


def _first_a_cuda_backend_hands_over_the_card_by_its_device_and_unloads_when_idle(tmp_path):
    v = tts_vars(
        tmp_path,
        tts_backend="cuda",
        tts_image=CUDA_IMAGE,
        tts_gpu_index=2,
        tts_power_cap_max_watts=180,
    )
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_a_cuda_backend_hands_over_the_card_by_its_device_and_unloads_when_idle)
def test_a_cuda_backend_hands_over_the_card_by_its_device_and_unloads_when_idle(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    svc = compose(tmp_path)
    assert svc["devices"] == ["nvidia.com/gpu=2"]
    env = svc["environment"]
    assert env["TTS_BACKEND"] == "cuda" and env["TTS_GPU_INDEX"] == "2"
    assert env["TTS_IDLE_UNLOAD_S"] == "120"  # the card is free between jobs
    assert env["TTS_POWER_CAP_MAX_WATTS"] == "180"


def _first_the_idle_timeout_can_be_set(tmp_path):
    v = tts_vars(tmp_path, tts_idle_unload_s=30)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_the_idle_timeout_can_be_set)
def test_the_idle_timeout_can_be_set(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    assert compose(tmp_path)["environment"]["TTS_IDLE_UNLOAD_S"] == "30"


def _first_the_container_joins_the_role_slice_the_module_play_names(tmp_path):
    v = tts_vars(tmp_path, hnx_module_slice="hnx-tts-server.slice")
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_the_container_joins_the_role_slice_the_module_play_names)
def test_the_container_joins_the_role_slice_the_module_play_names(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    assert compose(tmp_path)["cgroup_parent"] == "hnx-tts-server.slice"


def _first_main_refuses_bad_inputs(tmp_path, over):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": tts_vars(tmp_path, **over)}


@pytest.mark.parametrize(
    "over",
    [
        {"tts_image": REPO + ":0.1.0-x-cpu"},  # a tag without a digest
        {"tts_image": f"{REPO}:latest@{DIGEST}"},
        {"tts_image": f"{REPO}:0.1.0-abc-cuda@{DIGEST}"},  # the cuda build on a cpu backend
        {"tts_image": f"docker.io/someone/else:0.1.0-abc-cpu@{DIGEST}"},  # not the lab's own build
        {"tts_backend": "vulkan"},
        {"ansible_host": "tts.example.internal"},
        {"ansible_host": "0.0.0.0"},
        {"tts_port": 80},
        {"tts_uid": 0},
        {"tts_power_cap_max_watts": 201},  # the operator's 200 W rule cannot be loosened
        {"tts_power_cap_max_watts": 0},
        {"tts_gpu_index": -1},
        {"tts_model_digest": "sha256:short"},
        {"tts_model_revision": "main"},
        {"tts_model_repo": "no-org"},
        {"tts_idle_unload_s": "soon"},
        {"tts_voice_files": []},
        {"tts_voice_files": ["../ref.wav"]},
        {"tts_voice_files": ["a.wav", "a.wav"]},
        {"tts_voice_files": ["voice.mp3"]},
        {"tts_voice_expected_sha256": {"ref1.wav": "not-a-hash"}},
        {"tts_voice_expected_sha256": {"other.wav": "a" * 64}},  # a file that is not in the voice
        {"tts_mem_limit": "lots"},
        {"tts_max_text_chars": 0},
        {"tts_job_timeout_s": -1},
        {"tts_restore_max_bytes": 10},
        {"tts_store_root": "relative/store"},
        {"tts_data_root": "/var/lib/../etc"},
        {"tts_check_min_seconds": 9, "tts_check_max_seconds": 2},
    ],
)
@first_run(_first_main_refuses_bad_inputs)
def test_main_refuses_bad_inputs(first, over):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_main_refuses_an_image_that_is_not_set(tmp_path):
    v = tts_vars(tmp_path)
    del v["tts_image"]
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0 and "tts_image" in (r.stdout + r.stderr)
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_main_refuses_a_data_root_inside_the_model_store(tmp_path):
    v = tts_vars(tmp_path, tts_data_root=str(tmp_path / "store" / "hf" / "data"))
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_main_refuses_a_data_root_inside_the_model_store)
def test_main_refuses_a_data_root_inside_the_model_store(first):
    r, tmp_path = first
    assert r.returncode != 0 and not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_main_refuses_when_the_weights_are_not_in_the_store(tmp_path):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": tts_vars(tmp_path, store=False)}


@first_run(_first_main_refuses_when_the_weights_are_not_in_the_store)
def test_main_refuses_when_the_weights_are_not_in_the_store(first):
    r, tmp_path = first
    assert r.returncode != 0 and not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_main_refuses_when_the_listing_is_not_in_the_store(tmp_path):
    v = tts_vars(tmp_path)
    (tmp_path / "store" / "manifests" / "listings" / "xtts-v2.sha256").unlink()
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_main_refuses_when_the_listing_is_not_in_the_store)
def test_main_refuses_when_the_listing_is_not_in_the_store(first):
    r, tmp_path = first
    assert r.returncode != 0 and not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_main_refuses_to_start_without_the_voice(tmp_path):
    v = tts_vars(tmp_path, tts_start=True)
    (tmp_path / "data" / "voice" / "ref3.wav").unlink()
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_main_refuses_to_start_without_the_voice)
def test_main_refuses_to_start_without_the_voice(first):
    """A service started without the recordings answers 503 to every job."""
    r, tmp_path = first
    assert r.returncode != 0 and "ref3.wav" in r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_main_refuses_to_start_on_an_empty_recording(tmp_path):
    v = tts_vars(tmp_path, tts_start=True)
    (tmp_path / "data" / "voice" / "ref2.wav").write_bytes(b"")
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_main_refuses_to_start_on_an_empty_recording)
def test_main_refuses_to_start_on_an_empty_recording(first):
    r, _ = first
    assert r.returncode != 0 and "ref2.wav" in r.stdout


def test_a_pinned_recording_must_be_exactly_those_bytes(tmp_path):
    good = hashlib.sha256(b"RIFF" + b"ref1.wav").hexdigest()
    with Server() as srv:
        ok = _health(tmp_path, srv, tts_voice_expected_sha256={"ref1.wav": good})
        bad = _health(tmp_path, srv, tts_voice_expected_sha256={"ref1.wav": "0" * 64})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert bad.returncode != 0 and "is not the recording the site pinned" in bad.stdout


# ----------------------------------------------------------------------------- image archive


def _fake_docker_image(tmp_path: Path, loads: bool) -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    state = tmp_path / "loaded"
    fake(
        bindir / "docker",
        "import os, sys\n"
        f"state = {str(state)!r}\n"
        "a = sys.argv[1:]\n"
        "if a[:2] == ['image', 'inspect']:\n"
        "    sys.exit(0 if os.path.exists(state) else 1)\n"
        f"if a[:1] == ['load'] and {loads!r}:\n"
        "    open(state, 'w').write('x')\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _first_the_image_is_loaded_from_its_archive_when_the_daemon_lacks_it(tmp_path):
    archive = tmp_path / "hnx-tts.tar"
    archive.write_bytes(b"x")
    v = tts_vars(tmp_path, tts_image_archive=str(archive))
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": _fake_docker_image(tmp_path, True),
    }


@first_run(_first_the_image_is_loaded_from_its_archive_when_the_daemon_lacks_it)
def test_the_image_is_loaded_from_its_archive_when_the_daemon_lacks_it(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "loaded").exists()


def _first_main_refuses_when_the_archive_does_not_hold_the_pinned_digest(tmp_path):
    archive = tmp_path / "hnx-tts.tar"
    archive.write_bytes(b"x")
    v = tts_vars(tmp_path, tts_image_archive=str(archive))
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": _fake_docker_image(tmp_path, False),
    }


@first_run(_first_main_refuses_when_the_archive_does_not_hold_the_pinned_digest)
def test_main_refuses_when_the_archive_does_not_hold_the_pinned_digest(first):
    r, _ = first
    assert r.returncode != 0 and "The pinned digest is there now" in r.stdout


def _first_main_refuses_an_archive_that_is_not_a_file(tmp_path):
    (tmp_path / "an-archive").mkdir()
    v = tts_vars(tmp_path, tts_image_archive=str(tmp_path / "an-archive"))
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": _fake_docker_image(tmp_path, True),
    }


@first_run(_first_main_refuses_an_archive_that_is_not_a_file)
def test_main_refuses_an_archive_that_is_not_a_file(first):
    r, _ = first
    assert r.returncode != 0 and "is not a regular file" in r.stdout


# ----------------------------------------------------------------------------- health


def _docker(
    tmp_path: Path, health: str = "healthy", check: dict | None = None, check_rc: int = 0
) -> dict:
    """compose ps says the container is running with this health; compose exec prints a check."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    ps = json.dumps({"Service": "tts", "State": "running", "Health": health})
    out = json.dumps(
        check if check is not None
        else {"ok": True, "sample_rate": 24000, "channels": 1, "seconds": 2.7, "bytes": 129100}
    )  # fmt: skip
    log = tmp_path / "docker.log"
    fake(
        bindir / "docker",
        "import sys\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        "if 'exec' in sys.argv:\n"
        f"    sys.stdout.write({out + chr(10)!r})\n"
        f"    sys.exit({check_rc})\n"
        f"sys.stdout.write({ps + chr(10)!r})\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _health(tmp_path, srv, env=None, **kw):
    host, port = srv.addr
    v = tts_vars(tmp_path, tts_bind=host, tts_port=port, tts_start=True, **kw)
    return run_role(tmp_path, ROLE, "health", v, env=env or _docker(tmp_path))


def test_health_passes_asks_for_one_real_synthesis_and_calls_nothing_else(tmp_path):
    with Server() as srv:
        r = _health(tmp_path, srv)
        paths = list(srv.paths)
    assert r.returncode == 0, r.stdout + r.stderr
    assert paths == ["GET /health", "GET /ready"]  # the synthesis runs inside the container
    calls = (tmp_path / "docker.log").read_text().splitlines()
    exec_call = next(c for c in calls if " exec " in c)
    assert "python -m tts_service check" in exec_call
    assert "--min-seconds 0.8 --max-seconds 15 --timeout 900" in exec_call


def test_health_fails_when_a_gate_does_not_hold(tmp_path):
    with Server(ready=False) as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "is not ready" in r.stdout


def test_health_fails_when_the_ready_backend_is_not_the_configured_one(tmp_path):
    with Server(backend="cuda") as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "is not ready" in r.stdout


def test_health_fails_when_health_is_not_in_the_old_shape(tmp_path):
    with Server(status="starting") as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "/health did not answer" in r.stdout
    with Server(refs=["ref1.wav", "ref2.wav"]) as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "/health did not answer" in r.stdout


def test_health_fails_when_the_synthesis_is_not_a_24k_wav(tmp_path):
    with Server() as srv:
        env = _docker(
            tmp_path, check={"ok": False, "sample_rate": 22050, "seconds": 0.2}, check_rc=1
        )
        r = _health(tmp_path, srv, env=env)
    assert r.returncode != 0 and "the check synthesis failed" in r.stdout


def test_health_fails_when_the_check_says_ok_with_another_sample_rate(tmp_path):
    with Server() as srv:
        env = _docker(tmp_path, check={"ok": True, "sample_rate": 16000})
        r = _health(tmp_path, srv, env=env)
    assert r.returncode != 0 and "the check synthesis failed" in r.stdout


def test_health_fails_when_the_container_is_unhealthy(tmp_path):
    with Server() as srv:
        r = _health(tmp_path, srv, env=_docker(tmp_path, "unhealthy"))
    assert r.returncode != 0


def test_health_fails_when_the_voice_went_away(tmp_path):
    with Server() as srv:
        host, port = srv.addr
        v = tts_vars(tmp_path, tts_bind=host, tts_port=port)
        (tmp_path / "data" / "voice" / "ref4.wav").unlink()
        r = run_role(tmp_path, ROLE, "health", v, env=_docker(tmp_path))
    assert r.returncode != 0 and "ref4.wav" in r.stdout


# ----------------------------------------------------------------------------- export, restore


def _docker_log(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n",
    )
    return log


def _env(tmp_path) -> dict:
    return {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}


def _state(root: Path) -> None:
    (root / "state").mkdir(parents=True, exist_ok=True)
    (root / "state" / "latents-0123.pt").write_bytes(b"embedding")


def _first_export_archives_the_voice_and_the_embeddings_and_restore_checks_it(tmp_path):
    v = tts_vars(tmp_path)
    _state(tmp_path / "data")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "scratch").write_text("noise")
    log = _docker_log(tmp_path)
    return {"role": ROLE, "tasks_from": "export", "extra_vars": v, "setup": {"log": log, "v": v}}


@first_run(_first_export_archives_the_voice_and_the_embeddings_and_restore_checks_it)
def test_export_archives_the_voice_and_the_embeddings_and_restore_checks_it(first):
    r, tmp_path = first
    log = first.setup["log"]
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    export = tmp_path / "data" / "export"
    with tarfile.open(export / "tts-data.tar.gz") as t:
        names = sorted(t.getnames())
    assert {"voice/ref1.wav", "voice/ref4.wav", "state/latents-0123.pt"} <= set(names)
    assert not any(
        "scratch" in n or "export" in n for n in names
    )  # the cache and the export are left out
    listing = json.loads((export / "listing.jsonl").read_text())
    assert (
        listing["sha256"] == hashlib.sha256((export / "tts-data.tar.gz").read_bytes()).hexdigest()
    )
    assert not log.exists()  # the service keeps running: it only reads the recordings
    # restore into a data root whose voice was lost
    src = tmp_path / "src"
    src.mkdir()
    for p in export.iterdir():
        (src / p.name).write_bytes(p.read_bytes())
    (tmp_path / "data" / "voice" / "ref1.wav").write_bytes(b"damaged")
    ok = run_role(
        tmp_path, ROLE, "restore", {**v, "tts_restore_source": str(src)}, env=_env(tmp_path)
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert (tmp_path / "data" / "voice" / "ref1.wav").read_bytes() == b"RIFFref1.wav"
    assert (tmp_path / "data" / "voice.before-restore" / "ref1.wav").read_bytes() == b"damaged"
    assert (tmp_path / "data" / "state" / "latents-0123.pt").read_bytes() == b"embedding"
    assert not (tmp_path / "data" / "restoring").exists()
    # a tampered archive is refused before anything is stopped or moved
    log.unlink(missing_ok=True)
    (tmp_path / "data" / "voice.before-restore").rename(tmp_path / "aside-voice")
    (tmp_path / "data" / "state.before-restore").rename(tmp_path / "aside-state")
    with open(src / "tts-data.tar.gz", "ab") as f:
        f.write(b"x")
    bad = run_role(
        tmp_path, ROLE, "restore", {**v, "tts_restore_source": str(src)}, env=_env(tmp_path)
    )
    assert bad.returncode != 0 and "not intact" in bad.stdout
    assert not log.exists()


def _write_archive(src: Path, add, files=tuple(REFS)) -> None:
    archive = src / "tts-data.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        for n in files:
            data = b"RIFFnew" + n.encode()
            info = tarfile.TarInfo("voice/" + n)
            info.size = len(data)
            t.addfile(info, __import__("io").BytesIO(data))
        add(t)
    (src / "listing.jsonl").write_text(
        json.dumps(
            {"key": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        )
        + "\n"
    )


def _restore(tmp_path, add=lambda t: None, files=tuple(REFS), **kw):
    v = tts_vars(tmp_path, **kw)
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    _write_archive(src, add, files)
    log = _docker_log(tmp_path)
    r = run_role(
        tmp_path, ROLE, "restore", {**v, "tts_restore_source": str(src)}, env=_env(tmp_path)
    )
    return r, log


def test_restore_accepts_an_archive_of_just_the_four_recordings(tmp_path):
    """The old lab's recordings arrive as voice/ref1-4.wav alone (README, "The voice")."""
    r, log = _restore(tmp_path, tts_start=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "data" / "voice" / "ref2.wav").read_bytes() == b"RIFFnewref2.wav"
    assert (tmp_path / "data" / "state").is_dir()  # an archive without embeddings: they are rebuilt
    calls = log.read_text().splitlines()
    assert calls[0].endswith(" stop") and calls[-1].endswith(" up -d")


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_restore_refuses_link_and_special_members_before_stopping_anything(tmp_path, kind):
    def add(t):
        info = tarfile.TarInfo("voice/evil")
        info.type = kind
        info.linkname = "voice/ref1.wav" if kind == tarfile.LNKTYPE else "/etc/passwd"
        t.addfile(info)

    r, log = _restore(tmp_path, add)
    assert r.returncode != 0 and "link or special file" in r.stdout
    assert not log.exists() and not (tmp_path / "data" / "restoring").exists()


@pytest.mark.parametrize("name", ["../escape", "/abs/path", "elsewhere/file", "cache/x"])
def test_restore_refuses_members_outside_the_data(tmp_path, name):
    def add(t):
        info = tarfile.TarInfo(name)
        info.size = 1
        t.addfile(info, __import__("io").BytesIO(b"x"))

    r, log = _restore(tmp_path, add)
    assert r.returncode != 0 and "leaves its directory" in r.stdout
    assert not log.exists()


def _first_the_text_limit_and_the_job_timeout_reach_the_container(tmp_path):
    v = tts_vars(tmp_path, tts_max_text_chars=5000, tts_job_timeout_s=0)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v}


@first_run(_first_the_text_limit_and_the_job_timeout_reach_the_container)
def test_the_text_limit_and_the_job_timeout_reach_the_container(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    env = compose(tmp_path)["environment"]
    assert env["TTS_MAX_TEXT_CHARS"] == "5000" and env["TTS_JOB_TIMEOUT_S"] == "0"


def test_restore_refuses_an_archive_that_extracts_to_more_than_the_cap_before_extracting(tmp_path):
    def add(t):
        data = b"x" * 2_000_000
        info = tarfile.TarInfo("state/big.pt")
        info.size = len(data)
        t.addfile(info, __import__("io").BytesIO(data))

    r, log = _restore(tmp_path, add, tts_restore_max_bytes=1_048_576)
    assert r.returncode != 0 and "more than tts_restore_max_bytes" in r.stdout
    assert not log.exists() and not (tmp_path / "data" / "restoring").exists()
    ok, _ = _restore_again(tmp_path)
    assert ok.returncode == 0, ok.stdout


def _restore_again(tmp_path):
    v = tts_vars(tmp_path)
    src = tmp_path / "src"
    _write_archive(src, lambda t: None)  # four small recordings, under the default cap
    log = _docker_log(tmp_path)
    return run_role(
        tmp_path, ROLE, "restore", {**v, "tts_restore_source": str(src)}, env=_env(tmp_path)
    ), log


def test_restore_refuses_an_archive_that_lacks_a_recording_and_changes_nothing(tmp_path):
    r, log = _restore(tmp_path, files=REFS[:3])
    assert r.returncode != 0 and "lacks one of the recordings" in r.stdout
    assert not log.exists()  # never stopped
    assert (
        tmp_path / "data" / "voice" / "ref1.wav"
    ).read_bytes() == b"RIFFref1.wav"  # the live voice is alone
    assert not (tmp_path / "data" / "voice.before-restore").exists()


def test_restore_refuses_a_recording_that_is_not_the_pinned_bytes(tmp_path):
    r, log = _restore(tmp_path, tts_voice_expected_sha256={"ref1.wav": "0" * 64})
    assert r.returncode != 0 and "is not the recording the site pinned" in r.stdout
    assert not log.exists()
    assert (tmp_path / "data" / "voice" / "ref1.wav").read_bytes() == b"RIFFref1.wav"


def test_restore_refuses_to_move_the_live_data_over_an_earlier_aside(tmp_path):
    v = tts_vars(tmp_path)
    (tmp_path / "data" / "voice.before-restore").mkdir(parents=True)
    r, log = _restore(tmp_path)
    assert r.returncode != 0 and "left from an earlier restore" in r.stdout
    assert not log.exists()
    assert v  # the live voice is untouched
    assert (tmp_path / "data" / "voice" / "ref1.wav").read_bytes() == b"RIFFref1.wav"


def _first_backup_names_the_data_root_not_the_weights(tmp_path):
    return {"role": ROLE, "tasks_from": "backup", "extra_vars": tts_vars(tmp_path)}


@first_run(_first_backup_names_the_data_root_not_the_weights)
def test_backup_names_the_data_root_not_the_weights(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    manifest = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert manifest == {"app": "tts", "paths": [str(tmp_path / "data")]}


# ----------------------------------------------------------------------------- upgrade


def _first_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(tmp_path):
    v = tts_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "setup": {"v": v}}


@first_run(_first_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one)
def test_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    new = "b" * 64
    for bad in (
        f"{REPO}:0.2.0-x-cpu",  # no digest
        f"{REPO}:latest@sha256:{new}",
        f"{REPO}:0.2.0-x-cuda@sha256:{new}",  # another backend
        f"docker.io/someone/other:0.2.0-x-cpu@sha256:{new}",  # another repository
    ):
        assert (
            run_role(tmp_path, ROLE, "upgrade", {**v, "tts_target_image": bad}).returncode != 0
        ), bad
    target = f"{REPO}:0.2.0-x-cpu@sha256:{new}"
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "tts_target_image": target})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending == {"service": "tts", "tag": "0.2.0-x-cpu", "digest": "sha256:" + new}
