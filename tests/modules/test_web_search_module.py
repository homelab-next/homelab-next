# SPDX-License-Identifier: Apache-2.0
"""The web-search provider module, ``modules/<id>`` (its README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: the one secret by reference (an identity key, 32 or more
  characters), internet egress for the searches, no public route, an image pinned by tag and digest
  whose tag is the product's version, the slot stateless (nothing to export).
* A fictional overlay that places it on a guest (an egress grant, no public route) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_<id>_server``; a registry row
  that differs, a missing egress grant and a guest without the ``base`` baseline are refused.
* The module's own probe reads the health path and one real JSON search from the resolved endpoint
  only, and says so when the search returns nothing or the JSON format is refused.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint
from tests.modules.web_search_front import Server
from tests.modules.web_search_module import MID, MODULE, P, ref

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["web-search"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "search-1", "version": version}


def overlay(tmp: Path, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["search-1"] = {"address": GUEST, "zone": "mgmt", "role": "search"}
    reg["services"]["search"] = bound_row()
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
    (lab / "guests" / "search-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:search-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 1024}\n"
        "  disks: [{name: rootfs, size_gb: 10, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:web-search\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "search-pilot",
        "hosts": {"search": {"guest": "guest:search-1"}},
        "slots": {"web-search": [{"provider": MID, "instance": "search", "placement": {"server": "search"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    if grant:
        sel["grants"] = {"egress": {MID: {"server": ["internet"]}}}
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{MID}"]


def test_the_slot_is_provisional_and_stateless():
    slots = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    assert slots["web-search"]["contract"] is None and slots["web-search"]["stateful"] is False
    entry = ld.load_yaml(MODULE / "module.yml")["provides"]["slots"]["web-search"]
    assert entry["provisional"] is True and "migration" not in entry  # stateless: nothing migrates


def test_the_manifest_names_the_one_secret_and_internet_egress_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["kind"] == "provider" and manifest["id"] == MID
    assert [(c["secret"], c["identity"], c["holder"]) for c in manifest["credentials"]] == [
        (ref("secret-key"), "key", "provider")
    ]
    assert manifest["identifiers"] == [{"kind": "secret-name", "name": MID, "on_remove": "keep"}]
    assert manifest["egress"] == [
        {"host": "server", "to": ["internet"], "purpose": manifest["egress"][0]["purpose"]}
    ]
    host = manifest["requires"]["hosts"][0]
    assert (
        host["role"] == "server" and host["kind"] == "vm" and host["guest"]["baselines"] == ["base"]
    )
    assert host["footprint"] == {"cpu": 1, "memory_mb": 1024, "disk_gb": 5}
    assert "data" not in manifest  # nothing to export
    assert manifest["lifecycle"]["remove"]["export_first"] is False
    assert manifest["lifecycle"]["remove"]["discard_reason"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["web-search"]
    assert row["capability"] == "web-search" and row["protocol"] == "http"
    assert row["port"] == 8095 and row["auth"] == "own" and row["tls"] == "none"
    assert row["health"] == {"kind": "http", "path": "/healthz", "expect_status": 200}
    assert "public_hostname" not in row  # private: a site may add an edge route later
    assert "version" not in row  # a provider's row takes product.version


def test_the_image_is_pinned_by_tag_and_digest_and_the_tag_is_the_product_version():
    defaults = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    repo, tag, _digest = re.fullmatch(
        r"([^@:]+(?:/[^@:]+)*):([^@:]+)@(sha256:[0-9a-f]{64})", defaults[P + "image"]
    ).groups()
    assert tag == version and repo.startswith("docker.io/")


def test_the_defaults_are_the_ported_settings():
    d = ld.load_yaml(MODULE / "roles" / MID / "defaults" / "main.yml")
    assert d[P + "port"] == 8095 and d[P + "safe_search"] == 0 and d[P + "request_timeout"] == 3.0
    assert d[P + "engines_disabled"] == [] and d[P + "health_require_results"] is True
    assert d[P + "health_query"] == "debian"
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert d[P + "key_ref"] in {c["secret"] for c in manifest["credentials"]}


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
    plays = [p for p in books if p["hosts"] == f"mod_{MID}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{MID}")
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{MID}-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["search"]["auth"] = "idp"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.search.auth" in out, out


def test_the_searches_egress_needs_the_sites_grant(tmp_path, capsys):
    code, out = _check(overlay(tmp_path, grant=False), capsys)
    assert code == 1 and "egress" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "search-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_the_health_path_and_one_json_search_from_the_resolved_endpoint(
    monkeypatch,
):
    from homelabnext.conform.adapters.web_search import make

    monkeypatch.delenv("HNX_ENDPOINT_WEB_SEARCH", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_WEB_SEARCH"):
        make()  # no default endpoint
    with Server() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_WEB_SEARCH", "http://{}:{}".format(*srv.addr))
        probe = make()
        assert probe.health() and probe.search_returns_results("debian")
        assert srv.paths == ["/healthz", "/search?q=debian&format=json"]
    probe.close()


def test_the_probe_says_so_when_the_search_returns_nothing(monkeypatch):
    from homelabnext.conform.adapters.web_search import make

    with Server(results=0) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_WEB_SEARCH", "http://{}:{}".format(*srv.addr))
        assert make().search_returns_results("debian") is False  # never a vacuous pass


@pytest.mark.parametrize("kw", [{"json_status": 403}, {"body": "not json"}, {"body": {"x": 1}}])
def test_the_probe_says_so_when_the_json_format_is_refused_or_not_a_result_list(monkeypatch, kw):
    from homelabnext.conform.adapters.web_search import make

    with Server(**kw) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_WEB_SEARCH", "http://{}:{}".format(*srv.addr))
        assert make().search_returns_results("debian") is False


def test_the_probe_says_so_when_the_health_path_does_not_answer(monkeypatch):
    from homelabnext.conform.adapters.web_search import make

    with Server(healthz=500) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_WEB_SEARCH", "http://{}:{}".format(*srv.addr))
        assert make().health() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / MID)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
