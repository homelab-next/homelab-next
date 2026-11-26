# SPDX-License-Identifier: Apache-2.0
"""The enrichment provider module, the module that provides the ``enrichment`` slot.

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: five secrets by reference (the application secret, the
  database password, the admin password, the API token, the optional key), egress to the internet,
  no public route, local accounts, pinned images of which the application's and its front's tag is
  the product's version.
* A fictional overlay that places it on a guest (with the egress grant, no public route) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_<id>_server``; a registry
  row that differs and a guest without the ``base`` baseline are refused.
* The module's own probe reads the liveness and the refused anonymous API call from the resolved
  endpoint only.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.enrichment_front import Server
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _provider(slot: str) -> str:
    """The id of the module that provides ``slot``: the tests name the slot, never the product."""
    found = [
        d.name
        for d in (ROOT / "modules").iterdir()
        if (d / "module.yml").is_file()
        and slot in (ld.load_yaml(d / "module.yml").get("provides") or {}).get("slots", {})
    ]
    assert len(found) == 1, found
    return found[0]


ID = _provider(
    "enrichment"
)  # the module's id: its role's name, its variables' prefix, its secrets' folder
MODULE = ROOT / "modules" / ID
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
REQUIRED = sorted(
    s
    for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)


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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["enrichment"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "enrich-1", "version": version}


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["enrich-1"] = {"address": GUEST, "zone": "mgmt", "role": "enrichment"}
    reg["services"]["intel-enrichment"] = bound_row()
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
    (lab / "guests" / "enrich-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:enrich-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 6144}\n"
        "  disks: [{name: rootfs, size_gb: 30, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:enrichment\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "enrichment-pilot",
        "hosts": {"enrichment": {"guest": "guest:enrich-1"}},
        "slots": {"enrichment": [{"provider": ID, "instance": "intel-enrichment", "placement": {"server": "enrichment"}}]},
        "grants": {"egress": {ID: {"server": ["internet"]}}},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


@pytest.mark.static
def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


@pytest.mark.static
def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [ID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{ID}"]


def test_the_manifest_names_its_secrets_internet_egress_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [
        f"secret:{ID}/django-secret",
        f"secret:{ID}/db-password",
        f"secret:{ID}/admin-password",
        f"secret:{ID}/api-token",
        f"secret:{ID}/otx-key",
    ]
    token = next(c for c in manifest["credentials"] if c["secret"].endswith("/api-token"))
    assert token["holder"] == "granted"  # the consumers' enrichment calls are granted this one
    assert [e["to"] for e in manifest["egress"]] == [["internet"]]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["enrichment"]
    assert row["auth"] == "own" and row["port"] == 8080
    assert row["health"]["path"] == "/hc"  # the front's liveness: no credential, no application
    assert "public_hostname" not in row  # private by default: the site adds a route if it wants one
    assert "version" not in row  # a provider's row takes product.version


def test_the_role_defaults_carry_the_same_references_and_the_optional_key_is_off():
    d = ld.load_yaml(MODULE / "roles" / ID / "defaults" / "main.yml")
    refs = {
        d[f"{ID}_signing_ref"],
        d[f"{ID}_db_login_ref"],
        d[f"{ID}_admin_login_ref"],
        d[f"{ID}_api_login_ref"],
    }
    manifest = ld.load_yaml(MODULE / "module.yml")
    named = {c["secret"] for c in manifest["credentials"]}
    assert refs < named and named - refs == {f"secret:{ID}/otx-key"}
    assert (
        d[f"{ID}_otx_key_ref"] == ""
    )  # keyless by default: no key is read unless a site names one
    assert d[f"{ID}_restore_keep_keys"] is False  # and a restore clears the source's stored keys


def test_the_image_pins_are_the_product_version_and_digests():
    defaults = ld.load_yaml(MODULE / "roles" / ID / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    for key in (
        f"{ID}_image",
        f"{ID}_nginx_image",
        f"{ID}_postgres_image",
        f"{ID}_redis_image",
    ):
        image = defaults[key]
        assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71, key
    # the application and its front are one release, and the manifest's version is that release
    for key in (f"{ID}_image", f"{ID}_nginx_image"):
        assert defaults[key].split("@")[0].endswith(":v" + version), key


def test_the_required_analyzers_are_registered_names_never_the_bare_name_that_broke_hash_enrichment():
    """An unknown analyzer name makes the application answer 400 to the WHOLE submit. The bare name
    of the abuse-feed hash analyzer is not registered (its registered name has a suffix); a list that
    held it killed every hash enrichment for eleven days before it was found."""
    d = ld.load_yaml(MODULE / "roles" / ID / "defaults" / "main.yml")
    wanted = d[f"{ID}_required_analyzers"]
    assert sorted(wanted) == ["domain", "generic", "hash", "ip", "url"]
    assert "MalwareBazaar" not in [n for names in wanted.values() for n in names]
    assert "MalwareBazaar_Get_Observable" in wanted["hash"]
    assert all(wanted[c] for c in wanted)  # every class has at least one analyzer


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
    plays = [p for p in books if p["hosts"] == f"mod_{ID}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{ID}/roles/{ID}")
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{ID}-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["intel-enrichment"]["auth"] = "idp"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.intel-enrichment.auth" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "enrich-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_the_liveness_and_the_refused_api_call_from_the_resolved_endpoint(
    monkeypatch,
):
    from homelabnext.conform.adapters.enrichment import make

    monkeypatch.delenv("HNX_ENDPOINT_ENRICHMENT", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_ENRICHMENT"):
        make()  # no default endpoint
    with Server() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_ENRICHMENT", "http://{}:{}".format(*srv.addr))
        probe = make()
        assert probe.health() and probe.api_is_private()
        assert srv.paths == ["/hc", "/api/analyzer"]
        assert srv.tokens == []  # no credential is ever sent
    probe.close()


def test_the_probe_says_so_when_the_api_is_open_to_anonymous_callers(monkeypatch):
    from homelabnext.conform.adapters.enrichment import make

    with Server(anonymous=200) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_ENRICHMENT", "http://{}:{}".format(*srv.addr))
        assert make().api_is_private() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / ID)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
