# SPDX-License-Identifier: Apache-2.0
"""The endpoint-forensics role's host script (the server role's files):

* the allow-list catalog loads, and a catalog (or a running server's definition) that would hand
  the module's hunt principal an EXECVE artifact, a write, an artifact upload or an
  administrative permission is refused;
* the gate refuses an artifact that is not on the list and every kind of upload or execution;
* the hunt cycle starts one hunt per interval, collects it once, writes JSONL for the log
  pipeline atomically, and a failing server stops it with a non-zero exit;
* the export is a listed copy, the import refuses a tampered, linked or foreign source and never
  deletes what it replaces;
* the check reads the status file and tells could-not-measure (100) from fail (1).
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
import yaml

from tests.modules.endpoint_forensics_module import MID
from tests.modules.endpoint_forensics_script import (
    CATALOG,
    CHECK,
    CYCLE,
    FakeServer,
    catalog_doc,
    catalog_names,
    load,
)

vr = load("hnx_cycle", CYCLE)
chk = load("hnx_check", CHECK)

NOW = 1_800_000_000.0
HUNT_ARTIFACTS = {"Linux.Sys.Crontab": [{"ClientId": "C.1", "Fqdn": "host-a", "User": "root"}]}


def write_catalog(tmp_path: Path, doc: dict) -> Path:
    p = tmp_path / "catalog.yml"
    p.write_text(yaml.safe_dump(doc))
    return p


def cfg(tmp_path: Path, **kw) -> dict:
    c = {
        "docker_cli": "docker",
        "compose_file": str(tmp_path / "app" / "docker-compose.yml"),
        "service": MID,
        "api_config": f"/etc/{MID}/hunt.api.config.yaml",
        "server_config": f"/etc/{MID}/server.config.yaml",
        "principal": "hnx-hunt",
        "catalog": str(CATALOG),
        "state_dir": str(tmp_path / "state"),
        "results_dir": str(tmp_path / "results" / "hunts"),
        "status_file": str(tmp_path / "status" / "fleet.json"),
        "stale_after_minutes": 15,
        "min_clients": 1,
        "hunt_interval_hours": 24,
        "collect_after_minutes": 60,
    }
    c.update(kw)
    return c


# --- the catalog ---------------------------------------------------------------------------


def test_the_shipped_catalog_loads_and_names_only_collectable_artifacts():
    doc = vr.load_catalog(CATALOG)
    assert set(doc["principal"]["permissions"]) == {
        "ANY_QUERY", "COLLECT_CLIENT", "READ_RESULTS", "START_HUNT",
    }  # fmt: skip
    assert catalog_names() and len(catalog_names()) == len(set(catalog_names()))
    for entry in doc["artifacts"]:
        assert entry["required_permissions"] == []


@pytest.mark.parametrize(
    "mutate, why",
    [
        (lambda d: d["principal"]["permissions"].append("EXECVE"), "EXECVE"),
        (lambda d: d["principal"]["permissions"].append("FILESYSTEM_WRITE"), "FILESYSTEM_WRITE"),
        (lambda d: d["principal"]["permissions"].append("ARTIFACT_WRITER"), "ARTIFACT_WRITER"),
        (lambda d: d["principal"]["permissions"].append("SERVER_ADMIN"), "SERVER_ADMIN"),
        (lambda d: d["principal"]["permissions"].append("MADE_UP"), "MADE_UP"),
        (lambda d: d["artifacts"][0].update(required_permissions=["EXECVE"]), "EXECVE"),
        (lambda d: d["artifacts"].append(dict(d["artifacts"][0])), "twice"),
        (lambda d: d["artifacts"][0].update(name="not a name; rm -rf"), "name"),
        (lambda d: d["artifacts"][0].update(sources=["bad source'"]), "source"),
        (lambda d: d.update(schema="other/1"), "schema"),
        (lambda d: d.update(artifacts=[]), "artifacts"),
    ],
)
def test_a_catalog_that_widens_the_principal_is_refused(tmp_path, mutate, why):
    doc = copy.deepcopy(catalog_doc())
    mutate(doc)
    with pytest.raises(vr.CatalogError) as e:
        vr.load_catalog(write_catalog(tmp_path, doc))
    assert why in str(e.value)


def test_a_catalog_that_is_not_a_regular_file_is_refused(tmp_path):
    link = tmp_path / "link.yml"
    link.symlink_to(CATALOG)
    with pytest.raises(vr.CatalogError):
        vr.load_catalog(link)
    with pytest.raises(vr.CatalogError):
        vr.load_catalog(tmp_path / "missing.yml")


# --- the gate: collect only ------------------------------------------------------------------


def test_the_gate_allows_a_listed_artifact_and_refuses_everything_else():
    doc = vr.load_catalog(CATALOG)
    assert vr.gate(doc, "Linux.Sys.Crontab", "collect") == (True, "")
    assert vr.gate(doc, "Linux.Sys.Crontab", "hunt")[0] is True
    ok, why = vr.gate(doc, "Linux.Sys.BashShell", "collect")  # an EXECVE artifact, not listed
    assert not ok and "allow-list" in why
    for op in ("upload", "define", "exec", "write", "admin", "anything-else"):
        ok, why = vr.gate(doc, "Linux.Sys.Crontab", op)
        assert not ok, op


def test_the_live_definitions_must_not_need_more_than_the_principal_holds():
    doc = vr.load_catalog(CATALOG)
    clean = [
        {"name": n, "required_permissions": [], "implied_permissions": []} for n in catalog_names()
    ]
    assert vr.live_problems(doc, clean) == []
    exec_def = [dict(r) for r in clean]
    exec_def[0]["required_permissions"] = ["EXECVE"]
    assert any("EXECVE" in p for p in vr.live_problems(doc, exec_def))
    implied = [dict(r) for r in clean]
    implied[1]["implied_permissions"] = ["FILESYSTEM_WRITE"]
    assert any("FILESYSTEM_WRITE" in p for p in vr.live_problems(doc, implied))
    missing = clean[1:]
    assert any(
        catalog_names()[0] in p and "not defined" in p for p in vr.live_problems(doc, missing)
    )
    assert vr.live_problems(doc, []) and "no definitions" in vr.live_problems(doc, [])[0]


# --- the fleet --------------------------------------------------------------------------------


def test_summarize_counts_enrolled_and_recently_seen_clients():
    rows = [
        {"client_id": "C.1", "last_seen_at": int((NOW - 60) * 1e6)},
        {"client_id": "C.2", "last_seen_at": int((NOW - 7200) * 1e6)},
        {"client_id": "C.3", "last_seen_at": 0},
    ]
    s = vr.summarize_clients(rows, NOW, 15 * 60)
    assert s["clients_total"] == 3 and s["clients_fresh"] == 1
    assert s["newest_seen_age_s"] == 60
    assert vr.summarize_clients([], NOW, 900) == {
        "clients_total": 0, "clients_fresh": 0, "newest_seen_age_s": None,
    }  # fmt: skip


# --- the cycle ---------------------------------------------------------------------------------


def run_cycle(tmp_path, srv, now, **kw):
    return vr.cycle(cfg(tmp_path, **kw), srv, now)


def test_the_cycle_starts_one_hunt_and_records_the_fleet(tmp_path):
    srv = FakeServer(clients=[{"client_id": "C.1", "last_seen_at": int((NOW - 30) * 1e6)}])
    rc = run_cycle(tmp_path, srv, NOW)
    assert rc == 0
    status = json.loads((tmp_path / "status" / "fleet.json").read_text())
    assert status["schema"] == vr.STATUS_SCHEMA
    assert status["clients_total"] == 1 and status["clients_fresh"] == 1
    assert status["checked_at"] == NOW
    assert srv.hunts == 1
    hunt_vql = next(c for c in srv.calls if "hunt(description" in c)
    for name in catalog_names():
        assert name in hunt_vql
    # a second cycle inside the interval starts no hunt
    assert run_cycle(tmp_path, srv, NOW + 600) == 0
    assert srv.hunts == 1
    # one after the interval does
    assert run_cycle(tmp_path, srv, NOW + 25 * 3600) == 0
    assert srv.hunts == 2


def test_the_cycle_collects_a_finished_hunt_once_into_atomic_jsonl(tmp_path):
    srv = FakeServer(
        clients=[{"client_id": "C.1", "last_seen_at": int(NOW * 1e6)}],
        hunt_rows={"Linux.Sys.Crontab": HUNT_ARTIFACTS["Linux.Sys.Crontab"]},
    )
    assert run_cycle(tmp_path, srv, NOW) == 0
    out = tmp_path / "results" / "hunts"
    assert not list(out.glob("*.jsonl"))  # not collectable yet
    assert run_cycle(tmp_path, srv, NOW + 61 * 60, hunt_interval_hours=240) == 0
    (f,) = sorted(out.glob("*.jsonl"))
    assert f.name == "hunts-H.TEST1.jsonl"
    rows = [json.loads(line) for line in f.read_text().splitlines()]
    assert rows and all(r["hunt_id"] == "H.TEST1" for r in rows)
    r = next(r for r in rows if r["artifact"] == "Linux.Sys.Crontab")
    assert r["client_id"] == "C.1" and r["hostname"] == "host-a" and r["row"]["User"] == "root"
    assert oct(f.stat().st_mode & 0o777) == "0o640"
    assert not [p for p in out.iterdir() if p.name.startswith(".")]  # no temp file left
    before = f.read_text()
    calls = len(srv.calls)
    assert run_cycle(tmp_path, srv, NOW + 120 * 60, hunt_interval_hours=240) == 0
    assert f.read_text() == before
    assert not any("FROM hunt_results" in c for c in srv.calls[calls:])  # collected once


def test_a_hunt_is_refused_when_the_server_defines_an_artifact_that_needs_exec(tmp_path):
    defs = [
        {"name": n, "required_permissions": [], "implied_permissions": []} for n in catalog_names()
    ]
    defs[0]["required_permissions"] = ["EXECVE"]
    srv = FakeServer(definitions=defs, clients=[])
    assert run_cycle(tmp_path, srv, NOW) == 1
    assert srv.hunts == 0
    status = json.loads((tmp_path / "status" / "fleet.json").read_text())
    assert any("EXECVE" in p for p in status["problems"])


def test_a_failing_server_is_a_failing_cycle_and_the_status_says_so(tmp_path):
    srv = FakeServer(fail=True)
    assert run_cycle(tmp_path, srv, NOW) == 1
    status = json.loads((tmp_path / "status" / "fleet.json").read_text())
    assert status["service_up"] is False and status["clients_total"] is None


def test_the_cycle_never_writes_through_a_link(tmp_path):
    srv = FakeServer(clients=[])
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    (tmp_path / "status").mkdir()
    (tmp_path / "status" / "fleet.json").symlink_to(target)
    assert run_cycle(tmp_path, srv, NOW) == 1
    assert target.read_text() == "{}"


# --- the criteria --------------------------------------------------------------------------------


def status(**kw) -> dict:
    s = {"schema": chk.STATUS_SCHEMA, "checked_at": NOW - 60, "service_up": True,
         "clients_total": 3, "clients_fresh": 3, "newest_seen_age_s": 30, "problems": [],
         "stale_after_s": 900, "min_clients": 1, "max_age_s": 1800}  # fmt: skip
    s.update(kw)
    return s


@pytest.mark.parametrize(
    "name, st, rc",
    [
        ("service-up", status(), 0),
        ("service-up", status(service_up=False), 1),
        ("clients-enrolled", status(), 0),
        ("clients-enrolled", status(clients_total=0), 1),
        ("clients-fresh", status(), 0),
        ("clients-fresh", status(newest_seen_age_s=901), 1),
        ("clients-fresh", status(clients_total=0, newest_seen_age_s=None, clients_fresh=0), 1),
        ("service-up", status(checked_at=NOW - 7200), 100),  # the cycle stopped: cannot measure
        ("clients-enrolled", status(clients_total=None), 100),
        ("clients-fresh", status(schema="other"), 100),
    ],
)
def test_the_check_tells_fail_from_could_not_measure(tmp_path, name, st, rc):
    p = tmp_path / "fleet.json"
    p.write_text(json.dumps(st))
    assert chk.criterion(name, p, NOW)[0] == rc


def test_the_check_cannot_measure_without_a_status_file(tmp_path):
    assert chk.criterion("service-up", tmp_path / "none.json", NOW)[0] == 100
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert chk.criterion("service-up", p, NOW)[0] == 100
    assert chk.criterion("no-such-criterion", p, NOW)[0] == 2


# --- the export and the import -----------------------------------------------------------------


def tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_the_export_is_a_listed_copy_and_the_import_restores_it_without_deleting(tmp_path):
    etc = tree(
        tmp_path / "var" / "lib" / "etc",
        {"server.config.yaml": "ca: one\n", "hunt.api.config.yaml": "k: v\n"},
    )
    ds = tree(
        tmp_path / "var" / "lib" / "ds", {"clients/C.1/ping.json": "{}", "users/admin.db": "x"}
    )
    dest = tmp_path / "out" / "export" / "20261122T000000Z"
    listing = vr.export_tree({"etc": etc, "datastore": ds}, dest)
    assert {r["key"] for r in listing} == {
        "etc/server.config.yaml", "etc/hunt.api.config.yaml",
        "datastore/clients/C.1/ping.json", "datastore/users/admin.db",
    }  # fmt: skip
    assert (dest / "listing.jsonl").is_file()
    with pytest.raises(vr.TreeError):  # a second export never overwrites
        vr.export_tree({"etc": etc, "datastore": ds}, dest)
    vr.check_export(dest, ("etc", "datastore"))
    new_etc = tmp_path / "var" / "lib" / "new-etc"
    new_ds = tmp_path / "var" / "lib" / "new-ds"
    vr.import_tree(
        dest, {"etc": new_etc, "datastore": new_ds}, uid=os.getuid(), gid=os.getgid(), stamp="s1"
    )
    assert (new_etc / "server.config.yaml").read_text() == "ca: one\n"
    assert (new_ds / "clients" / "C.1" / "ping.json").read_text() == "{}"
    # a populated target is moved aside, never deleted
    (new_etc / "server.config.yaml").write_text("ca: two\n")
    vr.import_tree(
        dest, {"etc": new_etc, "datastore": new_ds}, uid=os.getuid(), gid=os.getgid(), stamp="s2"
    )
    assert (new_etc / "server.config.yaml").read_text() == "ca: one\n"
    aside = tmp_path / "var" / "lib" / "new-etc.replaced-s2"
    assert (aside / "server.config.yaml").read_text() == "ca: two\n"


def test_the_import_refuses_a_source_that_is_not_the_listed_export(tmp_path):
    etc = tree(tmp_path / "var" / "lib" / "etc", {"server.config.yaml": "ca: one\n"})
    ds = tree(tmp_path / "var" / "lib" / "ds", {"a": "1"})
    dest = tmp_path / "out" / "export" / "x"
    vr.export_tree({"etc": etc, "datastore": ds}, dest)
    targets = {
        "etc": tmp_path / "var" / "lib" / "t-etc",
        "datastore": tmp_path / "var" / "lib" / "t-ds",
    }

    def refused(sub):
        with pytest.raises(vr.TreeError):
            vr.check_export(sub, ("etc", "datastore"))
        with pytest.raises(vr.TreeError):
            vr.import_tree(sub, targets, uid=os.getuid(), gid=os.getgid(), stamp="s")
        assert not any(t.exists() for t in targets.values())

    tampered = tmp_path / "tampered"
    vr.export_tree({"etc": etc, "datastore": ds}, tampered)
    (tampered / "etc" / "server.config.yaml").write_text("ca: evil\n")
    refused(tampered)
    extra = tmp_path / "extra"
    vr.export_tree({"etc": etc, "datastore": ds}, extra)
    (extra / "datastore" / "unlisted").write_text("x")
    refused(extra)
    linked = tmp_path / "linked"
    vr.export_tree({"etc": etc, "datastore": ds}, linked)
    (linked / "datastore" / "a").unlink()
    (linked / "datastore" / "a").symlink_to("/etc/hostname")
    refused(linked)
    nolisting = tmp_path / "nolisting"
    (nolisting / "etc").mkdir(parents=True)
    refused(nolisting)
    empty = tmp_path / "empty"
    empty_etc = tmp_path / "var" / "lib" / "empty-etc"
    empty_etc.mkdir()
    with pytest.raises(vr.TreeError):  # an export of nothing is an error, not a pass
        vr.export_tree({"etc": empty_etc, "datastore": empty_etc}, empty)


@pytest.mark.parametrize("bad", ["/", "/etc", "relative/dir", "/var/lib/../etc/x", "/a/b"])
def test_paths_that_could_reach_outside_the_data_root_are_refused(tmp_path, bad):
    with pytest.raises(vr.TreeError):
        vr.safe_path(bad)


def test_a_source_with_no_file_is_still_a_directory_of_the_export_and_round_trips(tmp_path):
    etc = tree(tmp_path / "var" / "lib" / "etc", {"server.config.yaml": "ca: one\n"})
    ds = tmp_path / "var" / "lib" / "ds"
    ds.mkdir(parents=True)
    dest = tmp_path / "out" / "export" / "x"
    rows = vr.export_tree({"etc": etc, "datastore": ds}, dest)
    assert [r["key"] for r in rows] == ["etc/server.config.yaml"]
    assert (dest / "datastore").is_dir()
    vr.check_export(dest, ("etc", "datastore"))
    targets = {
        "etc": tmp_path / "var" / "lib" / "n-etc",
        "datastore": tmp_path / "var" / "lib" / "n-ds",
    }
    vr.import_tree(dest, targets, uid=os.getuid(), gid=os.getgid(), stamp="s")
    assert (targets["datastore"]).is_dir() and not list(targets["datastore"].iterdir())
