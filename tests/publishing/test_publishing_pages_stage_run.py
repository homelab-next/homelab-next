# SPDX-License-Identifier: Apache-2.0
"""The pinned deploy tool, stage-only mode (no network), and the run in each mode."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from homelabnext.publishing import config as cf
from homelabnext.publishing import pages as pg
from homelabnext.publishing import run as rn
from homelabnext.publishing.transport import NetworkForbidden, NoNetwork, ReadOnly, Request
from tests.publishing.helpers import DENY, FakeBucket, episode, make_item

VERSION = "4.157.0"
INTEGRITY = "sha512-" + "A" * 86 + "=="


def lock_text(version=VERSION, integrity=INTEGRITY) -> str:
    return json.dumps(
        {"packages": {"node_modules/wrangler": {"version": version, "integrity": integrity}}}
    )


PIN = hashlib.sha256(lock_text().encode()).hexdigest()


def install(tmp_path, version=VERSION, integrity=INTEGRITY, installed=None, lock=None) -> Path:
    d = tmp_path / "wr"
    (d / "node_modules/wrangler").mkdir(parents=True)
    (d / "package-lock.json").write_text(
        lock if lock is not None else lock_text(version, integrity)
    )
    (d / "node_modules/wrangler/package.json").write_text(
        json.dumps({"version": installed or version})
    )
    return d


def dist(tmp_path) -> Path:
    d = tmp_path / "dist"
    d.mkdir(exist_ok=True)
    return d


def pcfg(d, version=VERSION):
    return pg.PagesConfig("site-x", "pages", version, PIN, d)


class Runner:
    def __init__(self, version=VERSION, code=0):
        self.calls, self.version, self.code = [], version, code

    def __call__(self, argv, env, timeout, cwd):
        self.calls.append((argv, env, cwd))
        return (0, f"wrangler {self.version}\n") if argv[-1] == "--version" else (self.code, "ok")


# ---- the pin
@pytest.mark.parametrize(
    "bad", ["latest", "^4.157.0", "4", "4.157", "4.157.0-beta.1", "", "4.157.0 ", "@latest"]
)
def test_only_an_exact_version_is_a_pin(tmp_path, bad):
    with pytest.raises(pg.PagesError):
        pcfg(install(tmp_path), bad)


def test_a_valid_pin_deploys_with_the_installed_binary_and_never_npx(tmp_path):
    d, r = install(tmp_path), Runner()
    pg.deploy(
        pcfg(d),
        dist(tmp_path),
        token="t" * 5,
        account_id="a1",
        home=tmp_path,
        runner=r,
    )
    argv = r.calls[-1][0]
    assert argv[0] == str(pcfg(d).node) and argv[1].endswith("wrangler")
    assert "--branch=pages" in argv and r.calls[-1][2].startswith(tempfile.gettempdir())
    assert not any("npx" in a or "@latest" in a for c in r.calls for a in c[0])


def test_a_lockfile_that_is_not_the_pinned_one_is_refused(tmp_path):
    # another version in a lockfile whose hash was pinned for it: the version still has to match
    other = lock_text(version="4.160.0")
    cfg = pg.PagesConfig(
        "site-x",
        "pages",
        VERSION,
        hashlib.sha256(other.encode()).hexdigest(),
        install(tmp_path, lock=other),
    )
    with pytest.raises(pg.PagesError, match="lockfile pins"):
        pg.verify_pin(cfg)
    # the right version but a lockfile whose bytes differ from the reviewed ones (a swapped dependency)
    with pytest.raises(pg.PagesError, match="not the pinned one"):
        pg.verify_pin(pcfg(install(tmp_path / "b", integrity="sha512-" + "B" * 86 + "==")))
    with pytest.raises(pg.PagesError, match="lockfile pin"):
        pg.PagesConfig("site-x", "pages", VERSION, "nothex", tmp_path)


def test_an_installed_package_that_is_not_the_pin_is_refused(tmp_path):
    with pytest.raises(pg.PagesError, match="installed"):
        pg.verify_pin(pcfg(install(tmp_path, installed="4.165.0")))


def test_a_binary_that_reports_another_version_is_refused_before_any_deploy(tmp_path):
    r = Runner(version="4.165.0")
    with pytest.raises(pg.PagesError, match="--version"):
        pg.deploy(
            pcfg(install(tmp_path)),
            dist(tmp_path),
            token="t",
            account_id="",
            home=tmp_path,
            runner=r,
        )
    assert len(r.calls) == 1


def test_a_failed_deploy_does_not_leak_the_token(tmp_path):
    tok = "tok-" + "z" * 12

    def run(argv, env, t, cwd):
        return (0, f"wrangler {VERSION}") if argv[-1] == "--version" else (1, f"denied {tok}")

    with pytest.raises(pg.PagesError) as e:
        pg.deploy(
            pcfg(install(tmp_path)),
            dist(tmp_path),
            token=tok,
            account_id="",
            home=tmp_path,
            runner=run,
        )
    assert tok not in str(e.value)


# ---- credentials
def test_credentials_must_be_0600_and_non_empty(tmp_path):
    f = tmp_path / "deny-list"
    previous = os.umask(0o027)  # a file created under this umask is group-readable: refused
    try:
        f.write_text("x")
    finally:
        os.umask(previous)
    assert f.stat().st_mode & 0o040
    with pytest.raises(cf.ConfigError, match="0600"):
        cf.read_credential(tmp_path, "deny-list")
    os.chmod(f, 0o600)
    assert cf.read_credential(tmp_path, "deny-list") == "x"
    f.write_text(" \n")
    with pytest.raises(cf.ConfigError, match="empty"):
        cf.read_credential(tmp_path, "deny-list")
    with pytest.raises(cf.ConfigError):
        cf.read_credential(tmp_path, "absent")


# ---- the run
def setup_lab(tmp_path, mode, wrangler=True, deny=DENY, creds=("deny-list",)):
    base = tmp_path / "srv" / "lab" / "pub"
    pubdir, creddir = base / "publishable", base / "creds"
    creddir.mkdir(parents=True)
    contents = {
        "deny-list": deny,
        "cloudflare-api-token": "tk-" + "1" * 8,
        "r2-access-key-id": "id" * 4,
        "r2-secret-access-key": "s" * 20,
    }
    for n in creds:
        (creddir / n).write_text(contents[n])
        os.chmod(creddir / n, 0o600)
    doc = {
        "mode": mode,
        "publishable_dir": str(pubdir),
        "staging_dir": str(base / "staging"),
        "state_dir": str(base / "state"),
        "credentials_dir": str(creddir),
        "pages": {
            "project": "site-x",
            "branch": "pages",
            "wrangler_version": VERSION,
            "lock_sha256": PIN,
            "install_dir": str(install(base)),
            "account_id": "acct",
        },
        "r2": {"account_id": "acct", "bucket": "b", "endpoint": "https://store.example.test"},
        "feed": {
            "public_base_url": "https://cdn.example.test",
            "title": "T",
            "description": "D",
            "author": "A",
            "owner_email": "a@example.test",
        },
    }
    (base / "config.json").write_text(json.dumps(doc))
    return base, pubdir, cf.load(base / "config.json")


class Recorder:
    def __init__(self):
        self.calls = []

    def send(self, req: Request):
        self.calls.append(req)
        raise AssertionError("no request expected")


def test_stage_mode_makes_no_network_call_and_reads_no_hosting_credential(tmp_path):
    base, pub, cfg = setup_lab(tmp_path, "stage")  # only the deny-list credential exists
    make_item(pub, "site", "b1", {"index.html": "<p>ok</p>"})
    episode(pub)
    rec = Recorder()
    runner = Runner()
    rep = rn.run(cfg, transport=rec, runner=runner)
    assert rep.code == 0 and rec.calls == [] and runner.calls == []
    assert {d["result"] for d in rep.done} == {"staged"}
    staged = sorted((base / "staging").glob("*/*"))
    assert len(staged) == 2 and all((s / "plan.json").exists() for s in staged)


def test_stage_mode_refuses_any_request_even_if_asked(tmp_path):
    with pytest.raises(NetworkForbidden):
        NoNetwork().send(Request("GET", "https://x.example.test/"))
    with pytest.raises(NetworkForbidden):
        ReadOnly(Recorder()).send(Request("PUT", "https://x.example.test/", {}, b""))


def test_staging_twice_leaves_one_directory_and_removes_nothing(tmp_path):
    base, pub, cfg = setup_lab(tmp_path, "stage")
    make_item(pub, "site", "b1", {"index.html": "<p>ok</p>"})
    rn.run(cfg)
    first = sorted((base / "staging").glob("*/*"))
    rn.run(cfg)
    assert sorted((base / "staging").glob("*/*")) == first


def test_a_blocked_item_is_not_staged_logged_without_the_match_and_notified(tmp_path):
    base, pub, cfg = setup_lab(tmp_path, "dry-run")  # a page is a network call: never in stage
    make_item(pub, "site", "b1", {"index.html": "<p>vault.example.internal</p>"})
    sent = []

    class Sender:
        def send(self, m):
            sent.append(m.title)

    from homelabnext.notify import Notifier
    from homelabnext.state import StateStore

    n = Notifier(Sender(), StateStore(base / "state" / "n.json"))
    n.register_module_pairs([(rn.PROBLEM, rn.RECOVERY)], module="publishing")
    rep = rn.run(cfg, notifier=n)
    assert rep.blocked == ["b1"] and rep.code == 1 and not (base / "staging").exists()
    log = (base / "state" / "gate.jsonl").read_text()
    assert "deny-list" in log and "vault.example" not in log
    assert sent == [rn.PROBLEM]
    rn.run(cfg, notifier=n)
    assert sent == [rn.PROBLEM]  # state-diffed: once
    import shutil

    shutil.rmtree(pub / "site" / "b1")
    rn.run(cfg, notifier=n)
    assert sent == [rn.PROBLEM, rn.RECOVERY]


def test_a_missing_or_empty_deny_list_stops_the_run(tmp_path):
    _, _, cfg = setup_lab(tmp_path, "stage", creds=())
    with pytest.raises(cf.ConfigError):
        rn.run(cfg)


def test_only_the_newest_site_build_is_the_site(tmp_path):
    _, pub, cfg = setup_lab(tmp_path, "stage")
    make_item(pub, "site", "b1", {"index.html": "<p>old</p>"})
    make_item(pub, "site", "b2", {"index.html": "<p>new</p>"})
    rep = rn.run(cfg)
    assert {d["item"]: d["result"] for d in rep.done} == {"b1": "superseded", "b2": "staged"}


def test_dry_run_reads_but_never_writes_and_never_deploys(tmp_path):
    _, pub, cfg = setup_lab(
        tmp_path, "dry-run", creds=("deny-list", "r2-access-key-id", "r2-secret-access-key")
    )
    make_item(pub, "site", "b1", {"index.html": "<p>ok</p>"})
    episode(pub)
    bucket, runner = FakeBucket(), Runner()
    rep = rn.run(cfg, transport=bucket, runner=runner)
    assert rep.code == 0 and runner.calls == []
    assert "PUT" not in bucket.methods() and bucket.methods()
    assert {d["result"] for d in rep.done} == {"would-deploy", "would-publish"}


def test_live_publishes_once_then_nothing_changes(tmp_path):
    base, pub, cfg = setup_lab(
        tmp_path,
        "live",
        creds=("deny-list", "cloudflare-api-token", "r2-access-key-id", "r2-secret-access-key"),
    )
    make_item(pub, "site", "b1", {"index.html": "<p>ok</p>"})
    episode(pub)
    bucket, runner = FakeBucket(), Runner()
    first = rn.run(cfg, transport=bucket, runner=runner)
    assert {d["result"] for d in first.done} == {"deployed", "published"}
    deploys, objs = len(runner.calls), {k: v[0] for k, v in bucket.objects.items()}
    second = rn.run(cfg, transport=bucket, runner=runner)
    assert {d["result"] for d in second.done} == {"unchanged"}
    assert len(runner.calls) == deploys and {k: v[0] for k, v in bucket.objects.items()} == objs
    assert "DELETE" not in bucket.methods()
    manifest = (base / "state" / "published-manifest.jsonl").read_text().splitlines()
    assert len(manifest) == 2  # one record per real publish, none for the no-op run
    assert runner.calls[-1][1]["CLOUDFLARE_API_TOKEN"].startswith("tk-")


def test_a_blocked_item_is_never_pushed_in_live_mode(tmp_path):
    _, pub, cfg = setup_lab(
        tmp_path,
        "live",
        creds=("deny-list", "cloudflare-api-token", "r2-access-key-id", "r2-secret-access-key"),
    )
    make_item(pub, "site", "b1", {"index.html": "<p>ok</p>"}, tlp="amber")
    bucket, runner = FakeBucket(), Runner()
    rep = rn.run(cfg, transport=bucket, runner=runner)
    assert rep.blocked == ["b1"] and runner.calls == [] and bucket.calls == []


def test_the_cli_exits_nonzero_on_a_blocked_item(tmp_path, capsys):
    base, pub, _ = setup_lab(tmp_path, "stage")
    make_item(pub, "site", "b1", {"a.html": "x"}, tlp="red")
    assert rn.main(["--config", str(base / "config.json")]) == 1
    assert json.loads(capsys.readouterr().out)["blocked"] == ["b1"]
