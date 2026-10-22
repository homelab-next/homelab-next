# SPDX-License-Identifier: Apache-2.0
"""The model store manifest (homelabnext.models.store, ADR-0023): validation, binding
resolution, the entry digest and ``hnx models store check`` against tiny fake files on disk."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

from homelabnext.cli import main as hnx
from homelabnext.models import store as sm
from homelabnext.registry.models import RoleTable

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "model-serving"
SCHEMAS = ROOT / "schemas" / "platform"


def doc() -> dict:
    return json.loads((EXAMPLE / "model_store.json").read_text())


def roles() -> dict:
    return json.loads((EXAMPLE / "model_roles.json").read_text())


def build(root: Path, store: dict) -> None:
    """Write every file of ``store`` under ``root`` with the example's synthetic bodies."""
    st = sm.Store.from_dict(store)
    for eid, e in st.entries.items():
        for f in e.files:
            p = root / e.directory / f.path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(f"fake {f.path} of {eid}\n".encode())


def problems_of(store: dict) -> list[str]:
    with pytest.raises(sm.StoreError) as exc:
        sm.Store.from_dict(store)
    return exc.value.problems


# ---------------------------------------------------------------- the manifest
def test_the_example_store_is_valid_and_lays_entries_out_as_the_hub_does():
    st = sm.Store.from_dict(doc())
    assert sorted(st.entries) == [
        "example-27b-fp8", "example-4b-bf16", "example-4b-q4km", "example-4b-q8",
        "example-4b-triage",
    ]  # fmt: skip
    e = st.entries["example-27b-fp8"]
    assert e.directory == (
        "hf/hub/models--example-org--example-27b-fp8/snapshots/"
        "174d4518adc353b21f63bbd7186645da35935aeb"
    )
    assert st.entries["example-4b-q4km"].directory == "gguf/example-org/example-4b-gguf"
    assert st.entries["example-4b-triage"].directory == "exports/2026-10-01-triage"
    assert str(st.path_of(e)).startswith("/srv/models/hf/hub/")


def test_the_digest_is_sha256_of_the_sha256sum_listing():
    e = sm.Store.from_dict(doc()).entries["example-4b-bf16"]
    listing = "".join(f"{f.sha256}  {f.path}\n" for f in sorted(e.files, key=lambda f: f.path))
    assert e.listing == listing
    assert e.digest == "sha256:" + hashlib.sha256(listing.encode()).hexdigest()
    # the order the manifest lists files in does not change it
    d = doc()
    d["models"]["example-4b-bf16"]["files"].reverse()
    assert sm.Store.from_dict(d).entries["example-4b-bf16"].digest == e.digest


@pytest.mark.parametrize("revision", ["main", "v1.0", "174d4518", "refs/pr/1", "A" * 40])
def test_a_floating_or_short_revision_is_refused(revision):
    d = doc()
    d["models"]["example-4b-bf16"]["source"]["revision"] = revision
    assert any("40-hex commit" in p for p in problems_of(d))


def test_two_entries_for_the_same_source_revision_and_quant_are_refused():
    d = doc()
    twin = copy.deepcopy(d["models"]["example-4b-q8"])
    twin["files"][0]["path"] = "copy-of-Q8_0.gguf"
    twin["served_model_name"] = "example-4b-q8-copy"
    d["models"]["example-4b-q8-copy"] = twin
    (p,) = [p for p in problems_of(d) if "one copy of each" in p]
    assert "example-4b-q8" in p and "q8_0" in p
    # another quant of the same repository and revision is a different entry: accepted
    assert "example-4b-q4km" in sm.Store.from_dict(doc()).entries


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda m: m["example-4b-q4km"]["engines"].append("vllm"), "engine vllm cannot serve gguf"),
        (lambda m: m["example-27b-fp8"]["engines"].append("llama-server"), "llama-server cannot"),
        (lambda m: m["example-4b-triage"].pop("base"), "names the store entry it was trained"),
        (lambda m: m["example-4b-triage"].__setitem__("base", "nope"), "base 'nope' is not"),
        (lambda m: m["example-4b-triage"].pop("layout"), "an export needs layout"),
        (lambda m: m["example-4b-bf16"].__setitem__("base", "example-4b-bf16"), "only an export"),
        (
            lambda m: m["example-4b-q4km"]["files"].append(
                {"path": "split-00002.gguf", "sha256": "0" * 64, "size": 1}
            ),
            "exactly one",
        ),
        (
            lambda m: m["example-4b-bf16"]["files"][0].__setitem__("path", "../x.json"),
            "without '..'",
        ),
        (lambda m: m["example-4b-bf16"]["files"][0].__setitem__("path", "/etc/x"), "relative"),
        (lambda m: m["example-4b-bf16"]["files"][0].__setitem__("sha256", "abc"), "64 lowercase"),
        (lambda m: m["example-4b-bf16"]["files"][0].__setitem__("size", -1), "whole number"),
        (
            lambda m: m["example-4b-bf16"]["files"].append(dict(m["example-4b-bf16"]["files"][0])),
            "listed twice",
        ),
        (lambda m: m["example-4b-bf16"].pop("license"), "license"),
        (lambda m: m["example-4b-bf16"].__setitem__("engines", []), "engines must list"),
        (lambda m: m["example-4b-bf16"].__setitem__("format", "exl2"), "format must be"),
        (lambda m: m["example-4b-bf16"].__setitem__("mirror", "x"), "unknown key"),
        (lambda m: m["example-4b-bf16"]["source"].__setitem__("repo", "no-org"), "<org>/<name>"),
        (lambda m: m.__setitem__("Bad_ID", m["example-4b-q8"]), "lowercase slug"),
    ],
)
def test_malformed_entries_are_refused(mutate, needle):
    d = doc()
    mutate(d["models"])
    assert any(needle in p for p in problems_of(d)), problems_of(d)


def test_the_schema_and_the_library_agree_on_the_schema_examples_and_negatives():
    """Every schema negative is also refused by the library, and the example accepted."""
    sm.Store.from_dict(json.loads((SCHEMAS / "examples" / "model_store.valid.json").read_text()))
    negs = sorted((SCHEMAS / "negative").glob("model_store.*.json"))
    assert len(negs) >= 5
    for n in negs:
        with pytest.raises(sm.StoreError):
            sm.Store.from_dict(json.loads(n.read_text()))


# ---------------------------------------------------------------- bindings
def test_every_example_binding_resolves_to_a_store_entry():
    assert sm.bindings_problems(sm.Store.from_dict(doc()), RoleTable.from_dict(roles())) == []


def test_a_binding_without_a_store_entry_fails():
    r = roles()
    r["roles"]["main-reasoner"]["bindings"][0]["model_id"] = "example-70b"
    (p,) = sm.bindings_problems(sm.Store.from_dict(doc()), RoleTable.from_dict(r))
    assert "mdl:main-reasoner" in p and "no store entry serves model id 'example-70b'" in p


def test_a_pinned_digest_must_name_the_entry():
    r = roles()
    r["roles"]["fast-classifier"]["bindings"][0]["digest"] = "sha256:" + "1" * 64
    (p,) = sm.bindings_problems(sm.Store.from_dict(doc()), RoleTable.from_dict(r))
    assert "pinned digest sha256:1111111111" in p and "example-4b-q4km" in p


def test_a_pinned_commit_version_must_be_the_entrys_revision():
    r = roles()
    r["roles"]["main-reasoner"]["bindings"][0]["version"] = "f" * 40
    (p,) = sm.bindings_problems(sm.Store.from_dict(doc()), RoleTable.from_dict(r))
    assert "is not the store entry example-27b-fp8's revision" in p


def test_the_engine_decides_which_entry_a_shared_model_id_is():
    d = doc()
    d["models"]["example-4b-q8"]["served_model_name"] = "example-4b"  # two quants, one id
    st = sm.Store.from_dict(d)
    entry, _ = sm.resolve_binding(st, "example-4b", engine="llama-server")
    assert entry.id == "example-4b-q4km"  # q8 is studio-only
    entry, why = sm.resolve_binding(st, "example-4b", engine="unsloth-studio")
    assert entry is None and "ambiguous" in why
    entry, _ = sm.resolve_binding(st, "example-4b", engine="unsloth-studio",
                                  digest=st.entries["example-4b-q8"].digest)  # fmt: skip
    assert entry.id == "example-4b-q8"
    entry, why = sm.resolve_binding(st, "example-27b", engine="llama-server")
    assert entry is None and "may be served by llama-server" in why


# ---------------------------------------------------------------- on disk
def test_store_check_passes_on_the_manifests_files_and_fails_on_a_changed_byte(tmp_path, capsys):
    build(tmp_path, doc())
    args = ["models", "store", "check", str(EXAMPLE / "model_store.json"), "--root", str(tmp_path)]
    assert hnx(args) == 0
    assert "5 store entries match the manifest by sha256" in capsys.readouterr().out
    target = tmp_path / sm.Store.from_dict(doc()).entries["example-4b-triage"].directory
    blob = target / "model.safetensors"
    blob.write_bytes(blob.read_bytes().upper())  # same size, other bytes
    assert hnx(args) == 1
    err = capsys.readouterr().err
    assert "example-4b-triage: exports/2026-10-01-triage/model.safetensors: sha256 differs" in err
    assert hnx([*args, "--sizes-only"]) == 0  # the fast pass cannot see it; the sha256 pass does
    assert hnx([*args, "--only", "example-27b-fp8"]) == 0


def test_store_check_reports_missing_resized_and_unlisted_files(tmp_path):
    build(tmp_path, doc())
    st = sm.Store.from_dict(doc())
    snap = tmp_path / st.entries["example-27b-fp8"].directory
    (snap / "tokenizer.json").unlink()
    (snap / "config.json").write_text("{}")
    (snap / "stray.safetensors").write_text("fake stray")
    meta = tmp_path / st.entries["example-4b-q4km"].directory / ".cache" / "huggingface"
    meta.mkdir(parents=True)
    (meta / "download.json").write_text("{}")  # the hub client's metadata: not a model file
    found = sm.check_disk(st, tmp_path)
    assert found == [
        "example-27b-fp8: " + st.entries["example-27b-fp8"].directory + "/config.json: size 2, "
        "manifest says 36",
        "example-27b-fp8: " + st.entries["example-27b-fp8"].directory + "/tokenizer.json: missing",
        "example-27b-fp8: "
        + st.entries["example-27b-fp8"].directory
        + "/stray.safetensors: not in the manifest",
    ]
    assert sm.check_disk(st, tmp_path, only=["nope"]) == ["nope: not a store entry"]


def test_store_check_follows_the_hub_cache_symlinks(tmp_path):
    st = sm.Store.from_dict(doc())
    e = st.entries["example-4b-bf16"]
    blobs = tmp_path / "hf/hub/models--example-org--example-4b/blobs"
    blobs.mkdir(parents=True)
    snap = tmp_path / e.directory
    snap.mkdir(parents=True)
    for f in e.files:
        (blobs / f.sha256).write_bytes(f"fake {f.path} of {e.id}\n".encode())
        (snap / f.path).symlink_to(Path("../../blobs") / f.sha256)
    assert sm.check_disk(st, tmp_path, only=[e.id]) == []


def test_the_cli_validates_lists_and_resolves(tmp_path, capsys):
    store = str(EXAMPLE / "model_store.json")
    assert (
        hnx(["models", "store", "validate", store, "--roles", str(EXAMPLE / "model_roles.json")])
        == 0
    )
    assert hnx(["models", "store", "list", store, "--json"]) == 0
    rows = json.loads(capsys.readouterr().out.split("\n", 1)[1])
    assert {r["id"]: r["digest"] for r in rows}["example-4b-q4km"].startswith("sha256:")
    bad = tmp_path / "store.json"
    d = doc()
    d["models"]["example-4b-bf16"]["source"]["revision"] = "main"
    bad.write_text(json.dumps(d))
    assert hnx(["models", "store", "validate", str(bad)]) == 1
    r = roles()
    r["roles"]["triage"]["bindings"][0]["model_id"] = "example-4b-unknown"
    rp = tmp_path / "roles.json"
    rp.write_text(json.dumps(r))
    assert hnx(["models", "store", "validate", store, "--roles", str(rp)]) == 1
    assert "example-4b-unknown" in capsys.readouterr().err
    assert hnx(["models", "store", "check", str(tmp_path / "absent.json")]) == 2


def test_the_store_library_is_standard_library_only():
    src = (ROOT / "homelabnext" / "models" / "store.py").read_text()
    imports = {
        line.split()[1].split(".")[0]
        for line in src.splitlines()
        if line.startswith(("import ", "from ")) and not line.startswith("from __future__")
    }
    assert imports <= set(sys.stdlib_module_names)
