# SPDX-License-Identifier: Apache-2.0
"""The model_store role's ``model_store_files`` module: one call reads every file of an entry,
with the meaning of ``ansible.builtin.stat`` followed (exists, size, sha256) and unfollowed
(islnk, lnk_source) that fetch_entry.yml and verify_entry.yml read."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("ansible", reason="ansible not installed")

MODULE = (
    Path(__file__).resolve().parents[2] / "ansible/roles/model_store/library/model_store_files.py"
)


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("model_store_files", MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def entry(tmp_path: Path) -> tuple[Path, Path]:
    """A hub-cache repository: blobs/ plus a snapshot whose config.json links to its blob."""
    top = tmp_path / "models--example-org--example"
    blobs, snap = top / "blobs", top / "snapshots" / ("a" * 40)
    blobs.mkdir(parents=True)
    snap.mkdir(parents=True)
    body = b"fake config of example\n"
    blob = blobs / hashlib.sha256(body).hexdigest()
    blob.write_bytes(body)
    (snap / "config.json").symlink_to(Path("../../blobs") / blob.name)
    (snap / "model.safetensors").write_bytes(b"fake weights" * 1000)
    return top, snap


def test_a_regular_file_and_a_link_into_its_blobs(mod, tmp_path):
    top, snap = entry(tmp_path)
    files = [{"path": "config.json", "size": 23}, {"path": "model.safetensors"}]
    cfg, weights = mod.read_entry(str(snap), files, checksum=True)
    assert cfg["item"] == files[0]  # echoed, so the tasks read r.item as they did from a loop
    body = b"fake config of example\n"
    assert cfg["stat"] == {
        "exists": True,
        "size": len(body),
        "checksum": hashlib.sha256(body).hexdigest(),
    }
    blob = top / "blobs" / hashlib.sha256(body).hexdigest()
    assert cfg["link"] == {"exists": True, "islnk": True, "lnk_source": str(blob.resolve())}
    data = (snap / "model.safetensors").read_bytes()
    assert weights["stat"]["checksum"] == hashlib.sha256(data).hexdigest()
    assert weights["link"] == {"exists": True, "islnk": False}


def test_a_snapshot_link_out_of_its_blobs_reports_where_it_resolves(mod, tmp_path):
    """The bytes match, but the link leaves the store: lnk_source names the outside file, which
    verify_entry.yml refuses (it is not under the entry's directory or its blobs/)."""
    top, snap = entry(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes((snap / "config.json").read_bytes())
    (snap / "config.json").unlink()
    (snap / "config.json").symlink_to(outside)
    (r,) = mod.read_entry(str(snap), [{"path": "config.json"}], checksum=True)
    assert (
        r["stat"]["exists"]
        and r["stat"]["checksum"] == hashlib.sha256(outside.read_bytes()).hexdigest()
    )
    assert r["link"]["islnk"] and r["link"]["lnk_source"] == str(outside.resolve())
    assert not r["link"]["lnk_source"].startswith((str(snap) + "/", str(top / "blobs") + "/"))


def test_sizes_only_reads_no_bytes(mod, tmp_path, monkeypatch):
    _, snap = entry(tmp_path)

    def boom(path):
        raise AssertionError(f"hashed {path} in a sizes-only pass")

    monkeypatch.setattr(mod, "sha256_file", boom)
    out = mod.read_entry(str(snap), [{"path": "config.json"}, {"path": "model.safetensors"}], False)
    assert [r["stat"] for r in out] == [
        {"exists": True, "size": 23, "checksum": None},
        {"exists": True, "size": 12000, "checksum": None},
    ]


def test_missing_and_dangling_files_do_not_exist(mod, tmp_path):
    _, snap = entry(tmp_path)
    (snap / "dangling").symlink_to(tmp_path / "nowhere")
    gone, dangling = mod.read_entry(str(snap), [{"path": "gone"}, {"path": "dangling"}], True)
    assert gone["stat"] == {"exists": False} and gone["link"] == {"exists": False}
    # followed: absent (stat follow:true says so); unfollowed: a link to where it would resolve
    assert dangling["stat"] == {"exists": False}
    assert dangling["link"] == {
        "exists": True,
        "islnk": True,
        "lnk_source": str((tmp_path / "nowhere").resolve()),
    }


def test_a_directory_has_no_checksum(mod, tmp_path):
    _, snap = entry(tmp_path)
    (snap / "sub").mkdir()
    (r,) = mod.read_entry(str(snap), [{"path": "sub"}], True)
    assert r["stat"]["exists"] and r["stat"]["checksum"] is None


def test_hashing_is_in_blocks(mod, tmp_path, monkeypatch):
    big = tmp_path / "big"
    big.write_bytes(bytes(range(256)) * 41)
    monkeypatch.setattr(mod, "BLOCK", 1000)  # 10496 bytes: eleven reads, the last one short
    assert mod.sha256_file(str(big)) == hashlib.sha256(big.read_bytes()).hexdigest()


def test_an_absolute_path_never_replaces_the_entry_dir(mod, tmp_path):
    _, snap = entry(tmp_path)
    (r,) = mod.read_entry(str(snap), [{"path": str(snap / "model.safetensors")}], False)
    assert r["stat"] == {"exists": False}  # <dir>//abs/path, as the template joined it


def run_module(tmp_path: Path, args: dict) -> tuple[int, dict]:
    a = tmp_path / "args.json"
    a.write_text(json.dumps({"ANSIBLE_MODULE_ARGS": args}))
    p = subprocess.run([sys.executable, str(MODULE), str(a)], capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)


def test_the_module_answers_in_one_call(tmp_path):
    _, snap = entry(tmp_path)
    files = [{"path": "config.json"}, {"path": "model.safetensors"}, {"path": "gone"}]
    rc, out = run_module(tmp_path, {"dir": str(snap), "files": files, "checksum": False})
    assert rc == 0 and out["changed"] is False
    assert [r["stat"]["exists"] for r in out["results"]] == [True, True, False]
    rc, out = run_module(tmp_path, {"dir": str(snap), "files": [{"size": 1}]})
    assert rc != 0 and out["failed"] and "without a path" in out["msg"]
