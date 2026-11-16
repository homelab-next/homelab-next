# SPDX-License-Identifier: Apache-2.0
"""The dataflow provider module (the directory of the module that fills the ``dataflow`` slot: its
README.md).

* The manifest fills the (provisional) ``dataflow`` slot with the shared read-only probe, pins its
  image by digest at the product version, keeps its secrets in its own namespace and declares every
  secret reference its role reads; it asks for no internet egress and names no workstation.
* The registry row is the one the README describes (HTTPS, a port that does not collide with the
  query engine's on the same guest, a refusal as its liveness, no public route).
* A fictional overlay placing it beside the three lake modules on one guest passes
  ``hnx modules check --overlay`` and renders its play; a registry row that differs is named, and
  it cannot be placed without the lake or the bus it requires.
* The probe reads the controller's version, cluster summary, status and bulletins from the resolved
  endpoint, sends its credential only as a bearer header, and refuses what it must.
* The events contract the README documents is the repository's own envelope.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters import dataflow as adapter
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.events import build_event
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.registry.model import secret_env_name

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
STATUS = ROOT / "tests" / "status" / "fixtures"
SLOT = "dataflow"
PORT = 9443
SELF = "https://dataflow.example.internal:" + str(PORT)


def _module_for(slot: str) -> str:
    """The id of the module that fills ``slot`` (this test names slots, not products)."""
    found = [
        d.name
        for d in sorted((ROOT / "modules").iterdir())
        if (d / "module.yml").is_file()
        and slot
        in (yaml.safe_load((d / "module.yml").read_text()).get("provides", {}).get("slots") or {})
    ]
    assert len(found) == 1, (slot, found)
    return found[0]


MID = _module_for(SLOT)
MODULE = ROOT / "modules" / MID
ROLE = MODULE / "roles" / MID
P = MID  # the role's variable prefix is the module's id
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
BEARER_REF = f"secret:{MID}/api-bearer"
BEARER_ENV = secret_env_name(BEARER_REF)
LAKE = {
    _module_for(slot): {"slot": slot, "row": slot}
    for slot in ("object-store", "lake-catalog", "lake-query")
}
ALL = {**LAKE, MID: {"slot": SLOT, "row": SLOT}}
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


def manifest(mid: str = MID) -> dict:
    return ld.load_yaml(ROOT / "modules" / mid / "module.yml")


def defaults() -> dict:
    return ld.load_yaml(ROLE / "defaults" / "main.yml")


def role_vars() -> dict:
    return ld.load_yaml(ROLE / "vars" / "main.yml")


# ----------------------------------------------------------------------------- the manifest


def test_the_module_fills_the_dataflow_slot_with_the_shared_probe():
    m = manifest()
    assert m["kind"] == "provider" and m["egress"] == "none"
    assert list(m["provides"]["slots"]) == ["dataflow"]
    slot = m["provides"]["slots"]["dataflow"]
    assert slot["adapter"] == "homelabnext.conform.adapters.dataflow:make"
    assert slot["provisional"] is True and "conformance" not in slot  # no contract, so no suite
    assert [c["file"] for c in m["contributes"]["roles"]] == [f"roles/{MID}"]
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    slots = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    assert slots["dataflow"]["stateful"] is True
    assert slots["dataflow"]["export_formats"] == ["json"]
    assert m["data"][0]["export"]["formats"] == ["json"]
    assert m["lifecycle"]["remove"]["export_first"] is True


def test_the_row_is_https_on_its_own_port_and_its_liveness_is_a_refusal():
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"][SLOT]
    assert row["capability"] == SLOT and row["impl"] == manifest()["product"]["name"]
    assert row["protocol"] == "https" and row["tls"] == "internal" and row["auth"] == "own"
    assert "version" not in row and "public_hostname" not in row  # internal only
    # the query engine publishes 8443 on the same guest's address
    query_row = ld.load_yaml(
        ROOT / "modules" / _module_for("lake-query") / "registry" / "services.yml"
    )["services"]
    assert row["port"] == defaults()[f"{P}_port"] == 9443
    assert row["port"] != query_row["lake-query"]["port"]
    # the service answers nothing without a credential, so the probe expects the refusal
    assert row["health"]["expect_status"] == 401
    assert set(row["upstreams"]) == {"object-store", "lake-catalog", "lake-query", "events"}


def test_the_image_is_pinned_by_digest_at_the_product_version():
    d = defaults()
    repo_tag, digest = d[f"{P}_image"].split("@")
    assert digest.startswith("sha256:") and len(digest) == 71
    tag = repo_tag.rsplit(":", 1)[1]
    assert tag != "latest" and tag == str(manifest()["product"]["version"])
    # the version the health hook expects is the product's, written once in the role's vars
    assert role_vars()[f"{P}_product_version"] == tag


def test_every_secret_is_in_the_modules_own_namespace_and_the_role_reads_exactly_these():
    refs = [c["secret"] for c in manifest()["credentials"]]
    assert refs and all(r.startswith(f"secret:{MID}/") for r in refs)
    assert len(set(refs)) == len(refs)
    d = defaults()
    default_refs = {v for k, v in d.items() if k.endswith("_ref") and v}
    # an optional reference (the registry's token) defaults to empty and is declared all the same
    assert default_refs == set(refs) - {f"secret:{MID}/registry-token"}
    assert d[f"{P}_registry_auth_ref"] == ""
    # the defaults name every secret by reference and carry no value
    for k, v in d.items():
        if k.endswith("_ref") and v:
            assert re.fullmatch(r"secret:[a-z0-9][a-z0-9/_.-]*", v), k


def test_the_data_root_holds_every_directory_the_service_writes():
    text = (ROLE / "tasks" / "app.yml").read_text()
    for part in ("conf", "state", "flowfile_repository", "content_repository",
                 "database_repository", "provenance_repository", "logs", "smoke"):  # fmt: skip
        assert "{{ " + P + "_data_root }}/" + part + ":" in text, part
    # nothing is mounted from anywhere else on the host but the project's own certificate files
    mounts = re.findall(r'- "(\{\{ [a-z_]+ \}\})/', text)
    assert set(mounts) == {"{{ " + P + "_dir }}", "{{ " + P + "_data_root }}"}


def test_nothing_in_the_module_names_the_operators_workstation():
    for f in MODULE.rglob("*"):
        if f.is_file():
            assert not re.search(r"192\.168\.20\.150|wsl", f.read_text().lower()), f


def test_the_smoke_flow_is_a_clean_export_with_no_instance_identity_and_no_secret():
    flow = json.loads((ROLE / "files" / "hnx-smoke.json").read_text())
    assert flow["flowContents"]["name"] == "hnx-smoke"
    text = json.dumps(flow)
    assert "instanceIdentifier" not in text
    kinds = sorted(p["type"].rsplit(".", 1)[1] for p in flow["flowContents"]["processors"])
    assert kinds == ["GenerateFlowFile", "PutFile", "UpdateAttribute"]
    # PutFile writes where the role mounts the smoke directory, and its failure is retried
    put = next(p for p in flow["flowContents"]["processors"] if p["type"].endswith("PutFile"))
    assert put["properties"]["Directory"].endswith("/smoke")
    assert put["autoTerminatedRelationships"] == ["success"]
    retry = [c for c in flow["flowContents"]["connections"]
             if c["source"]["id"] == c["destination"]["id"] == put["identifier"]]  # fmt: skip
    assert [c["selectedRelationships"] for c in retry] == [["failure"]]
    assert not re.search(r"(?i)password|secret|token", text.replace("sensitive", ""))


# ----------------------------------------------------------------------------- an overlay


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row(mid: str) -> dict:
    row = ld.load_yaml(ROOT / "modules" / mid / "registry" / "services.yml")["services"][
        ALL[mid]["row"]
    ]
    return {
        **copy.deepcopy(row),
        "host": "lake-1",
        "version": str(manifest(mid)["product"]["version"]),
    }


def overlay(tmp: Path, mods=ALL) -> Path:
    """A fictional overlay placing the lake modules and this one on one guest, every other
    required core slot an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["lake-1"] = {"address": GUEST, "zone": "mgmt", "role": "lake"}
    for mid in mods:
        reg["services"][mods[mid]["row"]] = bound_row(mid)
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
    (lab / "guests" / "lake-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:lake-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 12}\n  memory: {size_mb: 49152}\n"
        "  disks: [{name: rootfs, size_gb: 400, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:lake-query\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    taken = {m["slot"] for m in mods.values()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot not in taken
    }
    sel = {
        "profile": "lake-pilot",
        "hosts": {"lake": {"guest": "guest:lake-1"}},
        "slots": {m["slot"]: [{"provider": mid, "instance": m["row"], "placement": {"server": "lake"}}]
                  for mid, m in mods.items()},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_an_overlay_placing_it_beside_the_lake_checks_clean_and_renders_its_play(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{MID}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{MID}")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert (dest / "limits" / "lake").is_dir()  # the four containers share the guest's slices


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"][SLOT]["port"] = 8443  # the query engine's
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 1 and "services.dataflow.port" in out, out


@pytest.mark.parametrize("slot", ["lake-catalog", "object-store", "lake-query"])
def test_it_cannot_be_placed_without_a_lake_slot_it_requires(slot, tmp_path, capsys):
    mods = {k: v for k, v in ALL.items() if v["slot"] != slot}
    ov = overlay(tmp_path, mods)
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 1 and slot in out, out


def test_the_module_asks_for_no_internet_egress_so_no_grant_is_owed(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["grants"] = {"egress": {MID: {"server": ["internet"]}}}  # a grant nothing asks for
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 1 and "internet" in out, out  # refused: a grant waiting for a target


# ----------------------------------------------------------------------------- the probe


class Fake:
    """A stand-in for the controller's four read endpoints, refusing a request with no bearer."""

    def __init__(self, token="tok-0123456789abcdef0123"):
        outer = self
        self.token, self.seen = token, []
        about = {"about": {"title": "x", "version": "2.12.0"}}
        cluster = {"clusterSummary": {"clustered": False, "connectedToCluster": False}}
        status = json.loads((next(STATUS.glob("*-flow-status.json"))).read_text())
        bulletins = json.loads((next(STATUS.glob("*-bulletin-board.json"))).read_text())
        self.routes = {
            "/x-api/flow/about": about,
            "/x-api/flow/cluster/summary": cluster,
            "/x-api/flow/status": status,
            "/x-api/flow/bulletin-board": bulletins,
        }

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.seen.append((self.path, self.headers.get("Authorization")))
                path = self.path.split("?")[0]
                if self.headers.get("Authorization") != f"Bearer {outer.token}":
                    self.send_error(401)
                    return
                if path not in outer.routes:
                    self.send_error(404)
                    return
                body = json.dumps(outer.routes[path]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._httpd = ThreadingHTTPServer(("localhost", 0), H)

    def __enter__(self):
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def url(self):
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"


def _make(monkeypatch, url, **config):
    monkeypatch.setenv("HNX_ENDPOINT_DATAFLOW", url)
    return adapter.make(api_root="/x-api", **config)


def test_the_probe_reads_version_cluster_status_and_bulletins_with_a_bearer(monkeypatch):
    monkeypatch.setenv(BEARER_ENV, "tok-0123456789abcdef0123")
    with Fake() as f:
        t = _make(monkeypatch, f.url, credential=BEARER_REF)
        assert t.version() == "2.12.0"
        assert t.cluster_summary()["clustered"] is False
        assert "flowFilesQueued" in t.status() or "queued" in t.status()
        assert t.bulletins(limit=5) and all(isinstance(b, dict) for b in t.bulletins())
        assert ("/x-api/flow/bulletin-board?limit=5", "Bearer tok-0123456789abcdef0123") in f.seen


def test_the_probe_does_not_pass_a_request_the_service_refused(monkeypatch):
    with Fake() as f:
        t = _make(monkeypatch, f.url)  # no credential: the service says 401
        with pytest.raises(adapter.DataflowError, match="HTTP 401"):
            t.version()
        monkeypatch.setenv(BEARER_ENV, "wrong-token-0123456789ab")
        t = _make(monkeypatch, f.url, credential=BEARER_REF)
        with pytest.raises(adapter.DataflowError, match="HTTP 401"):
            t.status()
        f.token = "wrong-token-0123456789ab"
        f.routes["/x-api/flow/about"] = {"about": "not an object"}
        with pytest.raises(adapter.DataflowError, match="no about section"):
            t.version()


@pytest.mark.parametrize(
    "config, why",
    [
        ({"credential": "tok-0123456789abcdef0123"}, "secret name"),
        ({"credential": "Bad/Name"}, "secret name"),
        ({"token": "x"}, "unknown setting"),
        ({"api_root": "x-api/"}, "api_root"),
    ],
)
def test_the_probe_refuses_a_credential_that_is_a_value_and_a_bad_setting(monkeypatch, config, why):
    monkeypatch.setenv("HNX_ENDPOINT_DATAFLOW", SELF)
    monkeypatch.setenv(BEARER_ENV, "tok-0123456789abcdef0123")
    config = {"api_root": "/x-api", **config}
    with pytest.raises((ValueError, AdapterConfigError), match=why):
        adapter.make(**config)


def test_the_probe_needs_an_api_root_an_endpoint_and_a_credential_that_is_set(monkeypatch):
    monkeypatch.setenv("HNX_ENDPOINT_DATAFLOW", SELF)
    with pytest.raises(AdapterConfigError, match="api_root"):
        adapter.make()
    monkeypatch.delenv("HNX_ENDPOINT_DATAFLOW")
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_DATAFLOW"):
        adapter.make(api_root="/x-api")
    monkeypatch.setenv("HNX_ENDPOINT_DATAFLOW", SELF.replace("https", "ftp"))
    with pytest.raises(AdapterConfigError):
        adapter.make(api_root="/x-api")
    monkeypatch.setenv("HNX_ENDPOINT_DATAFLOW", SELF)
    monkeypatch.delenv(BEARER_ENV, raising=False)
    with pytest.raises(AdapterConfigError, match=BEARER_ENV):
        adapter.make(api_root="/x-api", credential=BEARER_REF)


def test_the_probe_never_sends_a_header_a_newline_could_split(monkeypatch):
    monkeypatch.setenv(BEARER_ENV, "tok\r\nX-Evil: 1")
    with Fake() as f:
        t = _make(monkeypatch, f.url, credential=BEARER_REF)
        with pytest.raises(adapter.DataflowError, match="cannot be sent"):
            t.version()
        assert f.seen == []


# ----------------------------------------------------------------------------- the events contract


def test_the_documented_event_envelope_is_the_repositorys_own():
    readme = (MODULE / "README.md").read_text()
    types = [f"{MID}.flow.completed", f"{MID}.flow.failed", "cti.feed.batch"]
    for t in types:
        assert f"homelabnext.{t}" in readme  # the full type, as sent
        event = build_event(
            f"homelabnext.{t}", "svc:dataflow", {"flow": "hnx-smoke"}, subject="hnx-smoke",
            id=f"{MID}-" + "ab" * 32, time="2026-11-16T00:00:00Z",
        )  # fmt: skip
        assert event["type"] == f"homelabnext.{t}" and event["id"].startswith(f"{MID}-")
    # a type without the prefix, which the flows' logical names are, is what the bus refuses
    with pytest.raises(Exception, match="homelabnext"):
        build_event(
            f"{MID}.flow.completed", "svc:dataflow", {}, id=f"{MID}-1", time="2026-11-16T00:00:00Z"
        )


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
