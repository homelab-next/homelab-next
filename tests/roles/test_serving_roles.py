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
from pathlib import Path

import pytest
import yaml
from rolerun import calls, fake, logging_fake, run_role

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


def test_model_store_fetches_at_the_pinned_revision_and_the_store_check_passes(tmp_path):
    store = manifest()
    remote_tree(tmp_path, store)
    v = store_vars(tmp_path, store)
    r = run_role(tmp_path, "model_store", "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    log = calls(tmp_path)
    assert len(log) == 4 and all(line.startswith("hf download ") for line in log)
    for line in log:
        argv = line.split()
        rev = argv[argv.index("--revision") + 1]
        assert len(rev) == 40 and rev != "main"  # never the CLI's default branch
    hf_line = next(x for x in log if "example-27b-fp8" in x)
    assert "--cache-dir " + str(tmp_path / "srv" / "hf" / "hub") in hf_line
    gguf_line = next(x for x in log if "Q4_K_M" in x)
    assert (
        "--local-dir " + str(tmp_path / "srv" / "gguf" / "example-org" / "example-4b-gguf")
        in gguf_line
    )
    snap = tmp_path / "srv" / store_mod.Store.from_dict(store).entries["example-27b-fp8"].directory
    assert (snap / "config.json").is_symlink()  # the hub cache layout: blob + snapshot link
    assert (tmp_path / "srv" / "manifests" / "model_store.json").is_file()
    assert oct((tmp_path / "srv" / "exports").stat().st_mode & 0o7777) == "0o2770"
    write_export(tmp_path / "srv", store)
    st = store_mod.Store.from_dict(store)
    assert store_mod.check_disk(st, tmp_path / "srv") == []
    # idempotent: everything verified, nothing downloaded again
    (tmp_path / "calls.log").unlink()
    again = run_role(tmp_path, "model_store", "main", v)
    assert again.returncode == 0, again.stdout
    assert calls(tmp_path) == []
    assert run_role(tmp_path, "model_store", "health", v).returncode == 0
    assert run_role(tmp_path, "model_store", "verify", v).returncode == 0


def test_model_store_refuses_a_download_whose_sha256_is_not_the_manifests(tmp_path):
    store = manifest()
    remote_tree(tmp_path, store, tamper="model-00002-of-00002.safetensors")
    r = run_role(tmp_path, "model_store", "main", store_vars(tmp_path, store))
    assert r.returncode != 0
    assert "example-27b-fp8 does not match its manifest" in r.stdout
    assert "model-00002-of-00002.safetensors (sha256 differs)" in r.stdout


@pytest.mark.parametrize("revision", ["main", "refs/pr/1", "174d4518", "v1.0"])
def test_model_store_refuses_a_floating_revision_before_running_anything(tmp_path, revision):
    store = manifest()
    store["models"]["example-4b-bf16"]["source"]["revision"] = revision
    r = run_role(tmp_path, "model_store", "main", store_vars(tmp_path, store))
    assert r.returncode != 0 and "must be pinned" in r.stdout
    assert calls(tmp_path) == []
    good = run_role(
        tmp_path, "model_store", "main", store_vars(tmp_path, manifest(), model_store_fetch=False)
    )
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
def test_model_store_refuses_bad_settings(tmp_path, over):
    r = run_role(tmp_path, "model_store", "main", store_vars(tmp_path, manifest(), **over))
    assert r.returncode != 0 and "model_store: a manifest with models" in r.stdout


def test_model_store_refuses_a_file_path_that_leaves_its_entry(tmp_path):
    store = manifest()
    store["models"]["example-4b-bf16"]["files"][0]["path"] = "../../escape.json"
    r = run_role(tmp_path, "model_store", "main", store_vars(tmp_path, store))
    assert r.returncode != 0 and "must be pinned" in r.stdout


def test_model_store_passes_the_hub_token_by_reference_only(tmp_path):
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
    r = run_role(tmp_path, "model_store", "main", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "env.log").read_text() == (
        "hub-token-fake|https://hub-mirror.example.internal\n"
    )
    assert "hub-token-fake" not in r.stdout  # the download task is no_log when a token is used


def test_model_store_health_is_by_size_and_verify_by_sha256(tmp_path):
    store = manifest()
    remote_tree(tmp_path, store)
    v = store_vars(tmp_path, store)
    assert run_role(tmp_path, "model_store", "main", v).returncode == 0
    write_export(tmp_path / "srv", store)
    target = tmp_path / "srv" / "exports" / "2026-10-01-triage" / "model.safetensors"
    target.write_bytes(target.read_bytes().upper())  # same size, other bytes
    assert run_role(tmp_path, "model_store", "health", v).returncode == 0
    bad = run_role(tmp_path, "model_store", "verify", v)
    assert bad.returncode != 0 and "model.safetensors (sha256 differs)" in bad.stdout
    target.unlink()
    gone = run_role(tmp_path, "model_store", "health", v)
    assert gone.returncode != 0 and "model.safetensors (missing)" in gone.stdout


def test_model_store_backup_and_export_hooks(tmp_path):
    store = manifest()
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


def vllm_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "vllm_server_instances": instances(tmp_path),
        "vllm_server_store_root": str(tmp_path / "srv"),
        "vllm_server_bin": logging_fake(tmp_path, "vllm", "0.31.0\n"),
        "vllm_server_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "vllm_server_unit_dir": str(tmp_path / "units"),
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


def test_vllm_server_writes_one_unit_per_served_model_from_the_plan(tmp_path):
    v = vllm_vars(tmp_path)
    r = run_role(tmp_path, "vllm_server", "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    units = sorted(p.name for p in (tmp_path / "units").iterdir())
    assert units == ["hnx-vllm-inference-large.service", "hnx-vllm-inference-triage.service"]
    unit = (tmp_path / "units" / "hnx-vllm-inference-large.service").read_text()
    (execstart,) = [x for x in unit.splitlines() if x.startswith("ExecStart=")]
    snap = str(tmp_path / "srv") + "/hf/hub/models--example-org--example-27b-fp8/snapshots/"
    assert execstart.split()[1:3] == ["serve", snap + "174d4518adc353b21f63bbd7186645da35935aeb"]
    for flag in ("--served-model-name example-27b", "--max-model-len 131072",
                 "--scheduling-policy priority", "--tensor-parallel-size 2",
                 "--port 8000", "--host 127.0.0.1", "--tool-call-parser qwen3_xml",  # no-raw-endpoint: allow the rendered unit
                 "--enable-auto-tool-choice"):  # fmt: skip
        assert f" {flag}" in execstart, flag
    assert "Environment=CUDA_VISIBLE_DEVICES=0,1\n" in unit
    assert "Environment=CUDA_DEVICE_ORDER=PCI_BUS_ID\n" in unit
    assert "Environment=HF_HUB_OFFLINE=1\n" in unit
    assert f"ReadOnlyPaths={tmp_path / 'srv'}\n" in unit
    assert "NCCL_P2P_DISABLE" not in unit and "EnvironmentFile" not in unit
    assert "User=root" not in unit and "CapabilityBoundingSet=\n" in unit
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


def test_vllm_server_retires_a_unit_the_plan_no_longer_has(tmp_path):
    v = vllm_vars(tmp_path)
    stale = tmp_path / "units" / "hnx-vllm-gpu0.service"
    stale.write_text("[Service]\n")
    assert run_role(tmp_path, "vllm_server", "main", v).returncode == 0
    assert not stale.exists()
    assert "systemctl disable --now hnx-vllm-gpu0.service" in calls(tmp_path)


def test_vllm_server_refuses_a_vllm_that_is_not_the_pinned_one(tmp_path):
    v = vllm_vars(tmp_path)
    logging_fake(tmp_path, "vllm", "0.30.0\n")  # the installed one is not the pin
    r = run_role(tmp_path, "vllm_server", "main", v)
    assert r.returncode != 0 and "the pin is 0.31.0" in r.stdout
    assert not any(c.startswith("systemctl") for c in calls(tmp_path))


def test_vllm_server_refuses_a_model_missing_from_the_store(tmp_path):
    v = vllm_vars(tmp_path)
    (Path(v["vllm_server_instances"][1]["model_path"]) / "config.json").unlink()
    r = run_role(tmp_path, "vllm_server", "main", v)
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
        ("digest", "sha256:abc"),
    ],
)
def test_vllm_server_refuses_an_edited_instance(tmp_path, field, value):
    r = run_role(tmp_path, "vllm_server", "main", _bad(tmp_path, field, value))
    assert r.returncode != 0 and "must be what `hnx models serving render`" in r.stdout


def test_vllm_server_refuses_two_instances_on_one_gpu_or_port(tmp_path):
    v = vllm_vars(tmp_path)
    v["vllm_server_instances"][1]["gpus"] = [1]
    r = run_role(tmp_path, "vllm_server", "main", v)
    assert r.returncode != 0 and "distinct names, ports and GPUs" in r.stdout
    v = vllm_vars(tmp_path)
    v["vllm_server_instances"][1]["port"] = 8000
    assert run_role(tmp_path, "vllm_server", "main", v).returncode != 0


def test_vllm_server_api_key_and_p2p_settings(tmp_path):
    v = vllm_vars(tmp_path, vllm_server_api_key_ref="secret:llm-gateway/backend-key",
                  vllm_server_nccl_p2p_disable=True)  # fmt: skip
    env = {"HNX_SECRET_LLM_GATEWAY_BACKEND_KEY": "backend-key-fake"}
    r = run_role(tmp_path, "vllm_server", "main", v, env=env)
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


def test_vllm_server_upgrade_hook(tmp_path):
    v = vllm_vars(tmp_path)
    ok = run_role(tmp_path, "vllm_server", "upgrade", {**v, "vllm_server_target_version": "0.32.0"})
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


def test_open_webui_points_at_the_gateway_with_its_own_key(tmp_path):
    r = run_role(tmp_path, "open_webui", "main", webui_vars(tmp_path), env=SECRETS)
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
    ],
)
def test_open_webui_refuses_anything_but_the_gateway(tmp_path, over):
    r = run_role(tmp_path, "open_webui", "main", webui_vars(tmp_path, **over), env=SECRETS)
    assert r.returncode != 0 and "Open WebUI talks to the LLM" in r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_open_webui_keeps_extra_settings_that_do_not_re_point_it(tmp_path):
    v = webui_vars(tmp_path, open_webui_extra_env={"DEFAULT_MODELS": "main-reasoner"})
    assert run_role(tmp_path, "open_webui", "main", v, env=SECRETS).returncode == 0
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


def test_open_webui_upgrade_backup_export_hooks(tmp_path):
    v = webui_vars(tmp_path)
    assert run_role(tmp_path, "open_webui", "main", v, env=SECRETS).returncode == 0
    target = "ghcr.io/open-webui/open-webui:v0.11.5@sha256:" + "a" * 64
    up = run_role(tmp_path, "open_webui", "upgrade", {**v, "open_webui_target_image": target})
    assert up.returncode == 0, up.stdout + up.stderr
    bad = run_role(tmp_path, "open_webui", "upgrade",
                   {**v, "open_webui_target_image": "ghcr.io/open-webui/open-webui:latest"})  # fmt: skip
    assert bad.returncode != 0
    assert run_role(tmp_path, "open_webui", "backup", v).returncode == 0
    (tmp_path / "app" / "data" / "webui.db").write_text("fake")
    assert run_role(tmp_path, "open_webui", "export", v).returncode == 0
