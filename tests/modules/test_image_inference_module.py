# SPDX-License-Identifier: Apache-2.0
"""The inference provider that builds its own image (``modules/<id>``, the second provider of the
slot beside the one ``test_inference_module.py`` pins by default; its README names the product). The
facts every provider of the slot shares (the tree loads clean, no egress, one exclusive GPU, an
overlay that places it checks and renders, a differing registry row is named, the inference suite
passes through its target, role_lint) are ``tests/modules/test_inference_module.py`` run against this
module; this file adds what is its own:

* the image pin: the release, the commit and the digest agree across the Dockerfile, the role's
  default, the manifest's product version and the README's recipe; both base images and the source
  are pinned; one GPU architecture; non-root;
* the role's arguments and the image's starter agree on every environment variable, and the starter
  lets no raw flag through and fetches nothing;
* the argument specs match the role's defaults and carry the named settings only.
The product's name never appears here: everything is the module id or read from its files."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = "homelabnext.conform.adapters.inference_server:make"


def _find() -> Path:
    hits = [
        p.parent
        for p in sorted((ROOT / "modules").glob("*/module.yml"))
        if ld.load_yaml(p).get("provides", {}).get("slots", {}).get("inference", {}).get("adapter")
        == ADAPTER
        and (p.parent / "image" / "Dockerfile").is_file()
    ]
    assert len(hits) == 1, hits
    return hits[0]


MODULE = _find()
MID = MODULE.name
ROLE = MODULE / "roles" / MID
IMAGE_DIR = MODULE / "image"
STARTER_DIR = (
    ROLE / "files" / "image"
)  # the image's starter and probe: the role's variables are their contract
ENV = f"HNX_{MID.upper()}_"
P = f"{MID}_"


def _shared():
    """tests/modules/test_inference_module.py, loaded for this module (HNX_INFERENCE_MODULE)."""
    prev = os.environ.get("HNX_INFERENCE_MODULE")
    os.environ["HNX_INFERENCE_MODULE"] = MID
    try:
        name = "inference_module_tests_for_the_image_provider"
        path = ROOT / "tests" / "modules" / "test_inference_module.py"
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        if prev is None:
            del os.environ["HNX_INFERENCE_MODULE"]
        else:
            os.environ["HNX_INFERENCE_MODULE"] = prev


_base = _shared()
assert _base.MID == MID

# the facts the providers of the slot share, run against this module
test_the_public_tree_loads_clean = _base.test_the_public_tree_loads_clean
test_roles_holds_only_the_contributed_role = _base.test_roles_holds_only_the_contributed_role
test_the_footprint_names_one_exclusive_gpu_and_no_gpu_memory = (
    _base.test_the_footprint_names_one_exclusive_gpu_and_no_gpu_memory
)
test_an_overlay_placing_the_module_on_a_gpu_guest_checks_clean_and_renders = (
    _base.test_an_overlay_placing_the_module_on_a_gpu_guest_checks_clean_and_renders
)
test_a_registry_row_that_differs_is_named = _base.test_a_registry_row_that_differs_is_named
test_a_guest_without_the_server_baseline_is_refused = (
    _base.test_a_guest_without_the_server_baseline_is_refused
)
test_a_host_that_names_no_gpu_is_refused = _base.test_a_host_that_names_no_gpu_is_refused
test_the_slot_cannot_be_both_the_module_and_an_incumbent = (
    _base.test_the_slot_cannot_be_both_the_module_and_an_incumbent
)
test_the_target_matches_the_slot_entry = _base.test_the_target_matches_the_slot_entry
test_the_inference_suite_passes_through_the_target_against_the_library_fake = (
    _base.test_the_inference_suite_passes_through_the_target_against_the_library_fake
)
test_an_engine_that_answers_any_model_id_fails_only_unknown_model_rejected = (
    _base.test_an_engine_that_answers_any_model_id_fails_only_unknown_model_rejected
)
test_role_lint_passes_the_role_and_the_lifecycle_playbooks = (
    _base.test_role_lint_passes_the_role_and_the_lifecycle_playbooks
)

DOCKERFILE = (IMAGE_DIR / "Dockerfile").read_text()
README = (MODULE / "README.md").read_text()
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
MANIFEST = ld.load_yaml(MODULE / "module.yml")


def _arg(name: str) -> str:
    m = re.search(rf"^ARG {name}=(\S+)$", DOCKERFILE, re.M)
    assert m, name
    return m.group(1)


# ----------------------------------------------------------------------------- the manifest and the row


def test_the_manifest_has_no_egress_and_no_public_row_and_an_unprivileged_port():
    assert MANIFEST["egress"] == "none"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["inference"]
    assert "public_hostname" not in row and "version" not in row
    assert row["auth"] == "none" and row["capability"] == "inference" and row["impl"] == MID
    assert row["health"] == {"kind": "http", "path": "/health", "expect_status": 200}
    assert row["metrics"] == {"path": "/metrics"}
    assert row["port"] >= 1024 and DEFAULTS[f"{P}port"] == row["port"]


def test_the_module_is_a_provider_of_the_same_slot_and_adapter_as_the_other_inference_module():
    slot = MANIFEST["provides"]["slots"]["inference"]
    assert slot["adapter"] == ADAPTER and slot["features"] == ["streaming"]
    assert MANIFEST["kind"] == "provider" and MANIFEST["licence"]["spdx"] == "MIT"
    assert MANIFEST["requires"]["hosts"][0]["roles"] == [f"role:{MID}"]


# ----------------------------------------------------------------------------- the image pin


@pytest.mark.static
def test_the_release_the_commit_and_the_digest_agree_across_the_files_that_name_them():
    tag, commit = _arg(f"{MID.upper()}_TAG"), _arg(f"{MID.upper()}_COMMIT")
    assert re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) and re.fullmatch(r"[0-9a-f]{40}", commit)
    release = tag[1:]
    assert MANIFEST["product"]["version"] == release
    image = DEFAULTS[f"{P}image"]
    repo_tag, digest = image.split("@")
    repo, role_tag = repo_tag.rsplit(":", 1)
    assert repo == f"localhost/hnx-{MID}" and role_tag == f"{release}-{commit[:12]}"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest) and digest != "sha256:" + "0" * 64
    for needle in (tag, commit, role_tag, digest):
        assert needle in README, needle
    # the argument specs carry the same default
    specs = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())
    assert specs["argument_specs"]["main"]["options"][f"{P}image"]["default"] == image


@pytest.mark.static
def test_the_dockerfile_pins_both_base_images_by_digest_and_the_source_by_tag_and_commit():
    for arg in ("CUDA_IMAGE", "RUNTIME_BASE"):
        assert re.search(r"@sha256:[0-9a-f]{64}$", _arg(arg)), arg
    # the build stops unless the tag resolves to the pinned commit
    assert f'[ "$got" = "${{{MID.upper()}_COMMIT}}" ]' in DOCKERFILE and "rev-parse" in DOCKERFILE
    assert "git fetch -q --depth 1 origin" in DOCKERFILE
    # the engine is compiled for the one architecture of the card (sm_80), nothing else, and the picture
    # reader and the other shape engines are not built
    assert _arg("CUDA_ARCHITECTURES").strip('"') == "80"
    assert "_BUILD_HY4=OFF" in DOCKERFILE and "_BUILD_INKLING=OFF" in DOCKERFILE
    assert "_PORTABLE=ON" in DOCKERFILE
    # the runtime image runs as the module's container id, not root, and nothing is downloaded at start
    uid, gid = DEFAULTS[f"{P}uid"], DEFAULTS[f"{P}gid"]
    assert re.search(rf"^USER {uid}:{gid}$", DOCKERFILE, re.M)
    assert uid >= 1000 and gid >= 1000
    assert "HF_HUB_OFFLINE=1" in DOCKERFILE


@pytest.mark.static
def test_the_readme_gives_the_reproducible_build_recipe():
    for needle in (
        "docker buildx build", "--provenance=false", "--sbom=false", "SOURCE_DATE_EPOCH",
        "rewrite-timestamp=true", "unpack=false", "sha256sum", "docker load",
    ):  # fmt: skip
        assert needle in README, needle


@pytest.mark.static
def test_the_image_files_are_in_the_build_context_and_executable():
    assert sorted(p.name for p in IMAGE_DIR.iterdir()) == ["Dockerfile", "Dockerfile.dockerignore"]
    assert sorted(p.name for p in STARTER_DIR.iterdir()) == ["entrypoint.sh", "healthcheck.py"]
    # the context is the module directory; the ignore file lets in only the starter and the probe
    ignore = (IMAGE_DIR / "Dockerfile.dockerignore").read_text().split()
    assert ignore == ["*", f"!roles/{MID}/files/image"]
    copy = (
        f"COPY roles/{MID}/files/image/entrypoint.sh roles/{MID}/files/image/healthcheck.py /opt/"
    )
    assert copy in DOCKERFILE
    for name in ("entrypoint.sh", "healthcheck.py"):
        assert os.access(STARTER_DIR / name, os.X_OK), name
    r = subprocess.run(
        ["sh", "-n", str(STARTER_DIR / "entrypoint.sh")], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
    probe = f"/opt/{MID}/healthcheck.py"
    assert probe in (ROLE / "tasks" / "app.yml").read_text() and probe in DOCKERFILE


# ----------------------------------------------------------------------------- the role and the image agree


@pytest.mark.static
def test_every_variable_the_role_sets_is_one_the_starter_reads_and_the_other_way_round():
    entry = (STARTER_DIR / "entrypoint.sh").read_text()
    read = set(re.findall(rf"{ENV}[A-Z_]+", entry))
    fixed = (ROLE / "vars" / "main.yml").read_text()
    set_by_role = set(re.findall(rf"'({ENV}[A-Z_]+)'", fixed))
    assert set_by_role == read, set_by_role ^ read


@pytest.mark.static
def test_the_starter_never_lets_a_raw_flag_through_and_never_fetches():
    entry = (STARTER_DIR / "entrypoint.sh").read_text()
    code = "\n".join(line for line in entry.splitlines() if not line.lstrip().startswith("#"))
    # the launcher's command line is built from named variables; nothing the environment holds is
    # expanded as a whole word list, and the drafter that downloads a layer is the site's explicit choice
    assert f"${ENV}EXTRA" not in code and f"${{{ENV}ARGS" not in code
    assert "--no-api-key" in code and "--vision off" in code and "--yes" in code
    assert not re.search(r"\b(curl|wget|pip install|git clone)\b", code)
    assert DEFAULTS[f"{P}drafting"] == "off"


@pytest.mark.static
def test_the_argument_specs_match_the_defaults_and_each_hook_names_the_same_options():
    specs = yaml.safe_load((ROLE / "meta" / "argument_specs.yml").read_text())["argument_specs"]
    main = specs["main"]["options"]
    required = {k for k, v in main.items() if v.get("required")}
    assert required == {
        f"{P}logical_id",
        f"{P}model_digest",
    }  # the digest is the site's: its store's listing
    for name, opt in main.items():
        if name in required:
            assert name not in DEFAULTS, name
        else:
            assert opt["default"] == DEFAULTS[name], name
    assert set(DEFAULTS) - set(main) == set(), set(DEFAULTS) - set(main)
    for hook in ("health", "readiness"):
        assert set(specs[hook]["options"]) == set(main), hook
    assert set(specs["upgrade"]["options"]) == set(main) | {f"{P}target_image"}
    for hook in ("backup", "restore", "export"):
        assert specs[hook]["options"] == {}


@pytest.mark.static
def test_the_defaults_are_the_first_target_a_two_shard_pack_on_one_card():
    assert DEFAULTS[f"{P}model_repo"] == "ISTA-DASLab/Qwen3.8-Flash-Next-GSQ-RCO-GGUF"
    assert DEFAULTS[f"{P}model_files"] == [
        "Qwen3.8-Flash-Next-GSQ-RCO-IQ3_XXS-00001-of-00002.gguf",
        "Qwen3.8-Flash-Next-GSQ-RCO-IQ3_XXS-00002-of-00002.gguf",
    ]
    assert DEFAULTS[f"{P}direction_file"] == ""  # the stock model unless the site names a file
    assert DEFAULTS[f"{P}power_cap_max_watts"] == 200
    assert DEFAULTS[f"{P}expected_gpus"] == 1 and DEFAULTS[f"{P}gpu_index"] == 0
    assert DEFAULTS[f"{P}extra_args"] == {}  # the named settings' own defaults are the role's vars
    assert DEFAULTS[f"{P}kv_mode"] == "k8v4" and DEFAULTS[f"{P}spec_depth"] == 4
