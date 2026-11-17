# SPDX-License-Identifier: Apache-2.0
"""The ``context`` service (homelabnext/context_service): configuration, git sources, the TLP
ceiling at query time, reindex, the judge gate, the HTTP routes and the commands.

Hermetic: sources are local git repositories made here, the embedder and BM25 are the semantic
adapter's test seams, and the gateway is the fake model server (a decision role)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from conformance.fakes.openai_server import FakeOpenAIServer
from homelabnext import tlp
from homelabnext.context import Query
from homelabnext.context.judge import Verdict
from homelabnext.context_semantic import SemanticContextStore
from homelabnext.context_service import cli, config, sources
from homelabnext.context_service.server import ApiError, Routes, make_server
from homelabnext.context_service.service import ContextService, ReindexBusy, make_judge
from tests.context.test_semantic import _FakeBm25, _FakeEmbedder

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
ADMIN = "a" * 40  # the admin token, built short so nothing looks like a key
READER = "r" * 40
GREEN_READER = "g" * 40
LOOP = ".".join(["127", "0", "0", "1"])  # the loopback a stand-in listens on


def _sha(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.internal",
         *args], check=True, capture_output=True, text=True, env=env,
    ).stdout.strip()  # fmt: skip


LESSONS = """\
lessons:
  - id: LL-001
    title: The dashboard build needs the same-origin flag
    status: controlled
    symptom: the dashboard is blank after a plain build
    root_cause: the build defaulted to a cross-origin API
  - id: LL-002
    title: Disk filled overnight by the archive
    status: open
    symptom: the indexer disk filled up overnight
    tlp: red
  - id: LL-003
    title: Retired note
    status: retired
    symptom: nothing
"""


def make_repo(tmp: Path) -> Path:
    repo = tmp / "origin"
    (repo / "docs" / "adr").mkdir(parents=True)
    (repo / "dev").mkdir()
    (repo / "docs" / "adr" / "0001-search.md").write_text(
        "# Use semantic search\n\nWe search lessons by meaning. TLP:CLEAR\n"
    )
    (repo / "docs" / "adr" / "0002-secret.md").write_text(
        "# Proxy restart\n\nRestart the proxy when the certificate rotates. TLP:AMBER\n"
    )
    (repo / "docs" / "adr" / "has space.md").write_text("# skipped\n")
    (repo / "dev" / "lessons.yml").write_text(LESSONS)
    git(repo, "init", "--quiet", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "one")
    return repo


def cfg_raw(tmp: Path, repo: Path, **kw) -> dict:
    raw = {
        "port": 18094,
        "model_dir": "/opt/hnx/model",
        "data_dir": str(tmp / "data"),
        "allow_file_sources": True,
        "sources": [
            {"name": "adr", "url": str(repo), "ref": "main", "kind": "doc", "tlp": "green",
             "paths": ["docs/adr/*.md"]},
            {"name": "lessons", "url": str(repo), "ref": "main", "kind": "lesson", "tlp": "green",
             "format": "yaml-records", "records_key": "lessons", "paths": ["dev/lessons.yml"]},
        ],
        "callers": [
            {"name": "agents", "sha256": _sha(READER), "ceiling": "amber", "scopes": ["query"]},
            {"name": "outside", "sha256": _sha(GREEN_READER), "ceiling": "green",
             "scopes": ["query", "reindex"]},
        ],
        "health": {"text": "dashboard blank after build", "expect": "lesson:lessons/LL-001",
                   "ceiling": "green"},
    }  # fmt: skip
    raw.update(kw)
    return raw


def store_factory(fail: list[bool] | None = None):
    def build(tlp_of):
        emb = _FakeEmbedder()
        if fail is not None:
            orig = emb.batchtransform

            def maybe(texts):
                if fail[0]:
                    raise RuntimeError("embedder down")
                return orig(texts)

            emb.batchtransform = maybe
        return SemanticContextStore(
            ceiling="red", tlp_of=tlp_of, embedder=emb, sparse_factory=_FakeBm25
        )

    return build


def service(tmp, repo, judge=None, fail=None, **kw) -> ContextService:
    cfg = config.parse(cfg_raw(tmp, repo, **kw))
    return ContextService(cfg, env={}, store_factory=store_factory(fail), judge=judge)


ALL = ["doc:", "lesson:"]


def q(text, allowed=ALL, **kw):
    return Query(allowed=frozenset(allowed), text=text, **kw)


# ----------------------------------------------------------------------------- configuration


def test_a_valid_configuration_parses(tmp_path):
    c = config.parse(cfg_raw(tmp_path, tmp_path / "r"))
    assert [s.name for s in c.sources] == ["adr", "lessons"]
    assert c.sources[1].format == "yaml-records" and c.sources[1].label == tlp.Label.GREEN
    assert c.callers[0].ceiling == tlp.Label.AMBER and c.judge is None
    assert c.health.expect == "lesson:lessons/LL-001"


@pytest.mark.parametrize(
    "patch,needle",
    [
        ({"extra": 1}, "unknown key"),
        ({"allow_file_sources": False}, "allow_file_sources"),
        ({"sources": []}, "at least one source"),
        (
            {
                "callers": [
                    {"name": "admin", "sha256": "0" * 64, "ceiling": "red", "scopes": ["query"]}
                ]
            },
            "none is admin",
        ),
        (
            {
                "callers": [
                    {"name": "x", "sha256": "0" * 64, "ceiling": "red", "scopes": ["health"]}
                ]
            },
            "scopes",
        ),
        (
            {
                "callers": [
                    {"name": "x", "sha256": "0" * 64, "ceiling": "TLP:BLUE", "scopes": ["query"]}
                ]
            },
            "not a TLP label",
        ),
        ({"health": {"text": "t", "expect": "doc:other/x", "ceiling": "red"}}, "no configured"),
        ({"model_dir": "relative"}, "absolute"),
        ({"judge": {"url": "http://gw.example.internal", "key_env": "K"}}, "plain http"),
        (
            {"judge": {"url": "https://gw.example.internal", "key_env": "K", "on_error": "x"}},
            "on_error",
        ),
    ],
)
def test_malformed_configuration_is_refused_by_name(tmp_path, patch, needle):
    with pytest.raises(config.ConfigError, match=needle):
        config.parse(cfg_raw(tmp_path, tmp_path / "r", **patch))


@pytest.mark.parametrize(
    "src,needle",
    [
        ({"url": "http://git.example.internal/r.git"}, "plain http"),
        ({"url": "https://user:pw@git.example.internal/r.git"}, "no credential"),
        ({"ref": "../main"}, "ref"),
        ({"ref": "main.lock"}, "ref"),
        ({"paths": ["/etc/*"]}, "relative glob"),
        ({"paths": ["../x/*"]}, "relative glob"),
        ({"tlp": "blue"}, "tlp"),
        ({"format": "json"}, "format"),
        ({"name": "Bad Name"}, "name"),
        ({"credential_env": "lower"}, "credential_env"),
    ],
)
def test_a_malformed_source_is_refused(tmp_path, src, needle):
    raw = cfg_raw(tmp_path, tmp_path / "r", allow_file_sources=False)
    raw["sources"] = [{**raw["sources"][0], "url": "https://git.example.internal/r.git", **src}]
    raw["health"]["expect"] = "doc:adr/x"
    with pytest.raises(config.ConfigError, match=needle):
        config.parse(raw)


def test_config_load_refuses_an_unreadable_file(tmp_path):
    with pytest.raises(config.ConfigError, match="cannot read"):
        config.load(tmp_path / "missing.json")


# ----------------------------------------------------------------------------- sources


@needs_git
def test_sync_fetches_a_branch_and_a_pinned_commit(tmp_path):
    repo = make_repo(tmp_path)
    c = config.parse(cfg_raw(tmp_path, repo))
    root = tmp_path / "data" / "sources"
    out, commit = sources.sync(c.sources[0], root, env=os.environ)
    assert out == root / "adr" and (out / "docs" / "adr" / "0001-search.md").is_file()
    assert commit == git(repo, "rev-parse", "HEAD")
    first = commit
    (repo / "docs" / "adr" / "0003.md").write_text("# Third\n")
    git(repo, "add", "-A")
    git(repo, "commit", "--quiet", "-m", "two")
    pinned = config.Source(**{**c.sources[0].__dict__, "ref": first})
    out, commit = sources.sync(pinned, root, env=os.environ)
    assert commit == first and not (out / "docs" / "adr" / "0003.md").exists()
    out, commit = sources.sync(c.sources[0], root, env=os.environ)
    assert (out / "docs" / "adr" / "0003.md").exists()
    left = sorted(p.name for p in root.iterdir() if p.name != ".gitconfig-local")
    assert left == ["adr"]  # no staging or old copy left


@needs_git
def test_a_failed_fetch_leaves_the_last_good_checkout(tmp_path):
    repo = make_repo(tmp_path)
    c = config.parse(cfg_raw(tmp_path, repo))
    root = tmp_path / "data" / "sources"
    sources.sync(c.sources[0], root, env=os.environ)
    bad = config.Source(**{**c.sources[0].__dict__, "ref": "no-such-branch"})
    with pytest.raises(sources.SourceError, match="git fetch exited"):
        sources.sync(bad, root, env=os.environ)
    assert (root / "adr" / "docs" / "adr" / "0001-search.md").is_file()
    assert sorted(p.name for p in root.iterdir() if p.name != ".gitconfig-local") == ["adr"]


def test_the_credential_travels_in_gits_environment_never_its_arguments(tmp_path):
    seen = []

    def runner(argv, env, **kw):
        seen.append((argv, env))
        out = "f" * 40 + "\n" if argv[-2:] == ["rev-parse", "HEAD"] else ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    src = config.Source("lessons", "https://git.example.internal/r.git", "main", "lesson",
                        tlp.Label.AMBER, ("x",), credential_env="SRC_TOKEN")  # fmt: skip
    token = "t" * 30
    sources.sync(src, tmp_path / "a" / "b" / "src", env={"SRC_TOKEN": token}, runner=runner)
    assert all(token not in " ".join(a) for a, _ in seen)
    env = seen[0][1]
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
             for i in range(int(env["GIT_CONFIG_COUNT"]))}  # fmt: skip
    assert pairs["http.extraHeader"] == f"Authorization: Bearer {token}"
    assert pairs["core.symlinks"] == "false" and env["GIT_TERMINAL_PROMPT"] == "0"
    with pytest.raises(sources.SourceError, match="credential is not set"):
        sources.sync(src, tmp_path / "a" / "b" / "src", env={}, runner=runner)


def test_a_pinned_commit_that_is_not_what_was_fetched_is_refused(tmp_path):
    def runner(argv, env, **kw):
        out = "e" * 40 + "\n" if argv[-2:] == ["rev-parse", "HEAD"] else ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    src = config.Source("s", "https://git.example.internal/r.git", "f" * 40, "doc",
                        tlp.Label.AMBER, ("x",))  # fmt: skip
    root = tmp_path / "a" / "b" / "src"
    with pytest.raises(sources.SourceError, match="pinned commit"):
        sources.sync(src, root, env={}, runner=runner)
    assert list(root.iterdir()) == []


def test_safe_remove_refuses_every_unsafe_target(tmp_path):
    root = tmp_path / "data" / "sources"
    (root / "ok").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside)
    for target, needle in [
        (root / "link", "symlink"),
        (root, "outside"),
        (outside, "outside"),
        (root / ".." / "outside", "with \\.\\."),
        (Path("/"), "shallow"),
        (Path("/tmp"), "shallow"),
    ]:
        with pytest.raises(sources.SourceError, match=needle):
            sources.safe_remove(target, root)
    assert outside.is_dir()
    with pytest.raises(sources.SourceError, match="shallow"):
        sources.safe_remove(Path("/a/b/c"), Path("/a"))
    sources.safe_remove(root / "ok", root)
    assert not (root / "ok").exists()


@needs_git
def test_collect_labels_every_item_and_raises_to_its_strictest_marker(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "docs" / "adr" / "0004-link.md").symlink_to("/etc/hostname")
    c = config.parse(cfg_raw(tmp_path, repo))
    adr = sources.collect(repo, c.sources[0])
    got = {d.id: (d.title, str(label)) for d, label in adr.documents}
    assert got == {
        # a looser marker is not honoured: the source declares green
        "doc:adr/docs/adr/0001-search.md": ("Use semantic search", "green"),
        "doc:adr/docs/adr/0002-secret.md": ("Proxy restart", "amber"),
    }
    assert adr.skipped == 1  # the file whose name has a space; the symlink is never read
    honour = config.Source(**{**c.sources[0].__dict__, "honour_item_labels": True})
    labels = {d.id: str(lb) for d, lb in sources.collect(repo, honour).documents}
    assert labels["doc:adr/docs/adr/0001-search.md"] == "clear"
    lessons = {d.id: (d, str(lb)) for d, lb in sources.collect(repo, c.sources[1]).documents}
    assert sorted(lessons) == ["lesson:lessons/LL-001", "lesson:lessons/LL-002",
                               "lesson:lessons/LL-003"]  # fmt: skip
    d, label = lessons["lesson:lessons/LL-001"]
    assert d.title.startswith("The dashboard build") and d.status == "controlled"
    assert "symptom: the dashboard is blank" in d.content and label == "green"
    assert lessons["lesson:lessons/LL-002"][1] == "red"  # the record's own tlp field
    assert lessons["lesson:lessons/LL-003"][0].status == "retired"


def test_collect_refuses_vacuous_or_ambiguous_sources(tmp_path):
    repo = tmp_path / "r"
    (repo / "dev").mkdir(parents=True)
    (repo / "dev" / "l.yml").write_text("lessons: {}\n")
    src = config.Source("s", "https://git.example.internal/r.git", "main", "lesson",
                        tlp.Label.AMBER, ("dev/*.yml",), format="yaml-records",
                        records_key="lessons")  # fmt: skip
    with pytest.raises(sources.SourceError, match="holds no list"):
        sources.collect(repo, src)
    (repo / "dev" / "l.yml").write_text("lessons:\n  - {id: A}\n  - {id: A}\n")
    with pytest.raises(sources.SourceError, match="share an id"):
        sources.collect(repo, src)
    files = config.Source("s", "https://git.example.internal/r.git", "main", "doc",
                          tlp.Label.AMBER, ("nothing/*",))  # fmt: skip
    with pytest.raises(sources.SourceError, match="matched no document"):
        sources.collect(repo, files)
    (repo / "dev" / "l.yml").write_text("lessons: [\n")
    with pytest.raises(sources.SourceError, match="not YAML"):
        sources.collect(repo, src)


# ----------------------------------------------------------------------------- the service


@needs_git
def test_reindex_indexes_every_source_and_reads_at_the_callers_ceiling(tmp_path):
    repo = make_repo(tmp_path)
    s = service(tmp_path, repo)
    rep = s.reindex()
    assert rep["ok"] and rep["documents"] == 5 and rep["added"] == 5
    assert rep["sources"]["adr"]["commit"] == git(repo, "rev-parse", "HEAD")
    record = json.loads((tmp_path / "data" / "state" / "last-reindex.json").read_text())
    assert record["ok"] and record["documents"] == 5
    hits, labels = s.query(q("proxy certificate restart"), tlp.Label.AMBER)
    assert hits[0].id == "doc:adr/docs/adr/0002-secret.md" and labels[0] == tlp.Label.AMBER
    hits, _ = s.query(q("proxy certificate restart"), tlp.Label.GREEN)
    assert "doc:adr/docs/adr/0002-secret.md" not in {h.id for h in hits}  # above the ceiling
    hits, _ = s.query(q("disk filled overnight"), tlp.Label.AMBER)
    assert "lesson:lessons/LL-002" not in {h.id for h in hits}  # red: no reader sees it
    hits, _ = s.query(q("Retired note"), tlp.Label.AMBER)
    assert "lesson:lessons/LL-003" not in {h.id for h in hits}  # inactive
    from homelabnext.context import NotFound

    with pytest.raises(NotFound):
        s.get("doc:adr/docs/adr/0002-secret.md", frozenset(ALL), tlp.Label.GREEN)
    hit, label = s.get("doc:adr/docs/adr/0002-secret.md", frozenset(ALL), tlp.Label.AMBER)
    assert label == tlp.Label.AMBER and "Restart the proxy" in hit.content
    assert s.check() == {"ok": True, "judge": {"on": False}, "rank": 1}
    assert s.ready()["ready"] and s.ready()["documents"] == 5


@needs_git
def test_a_raised_source_label_takes_effect_on_unchanged_documents(tmp_path):
    repo = make_repo(tmp_path)
    s = service(tmp_path, repo)
    assert s.reindex()["ok"]
    hits, _ = s.query(q("dashboard blank build"), tlp.Label.GREEN)
    assert "lesson:lessons/LL-001" in {h.id for h in hits}
    raw = cfg_raw(tmp_path, repo)
    raw["sources"][1]["tlp"] = "amber"
    s.cfg = config.parse(raw)
    rep = s.reindex(fetch=False)
    assert rep["ok"] and rep["relabelled"] == 2  # LL-001 and LL-003; LL-002 stays red
    hits, _ = s.query(q("dashboard blank build"), tlp.Label.GREEN)
    assert "lesson:lessons/LL-001" not in {h.id for h in hits}


@needs_git
def test_a_failure_leaves_the_index_exactly_as_it_was(tmp_path):
    repo = make_repo(tmp_path)
    fail = [False]
    s = service(tmp_path, repo, fail=fail)
    assert s.reindex()["ok"]
    before = [h.id for h in s.query(q("semantic search lessons"), tlp.Label.AMBER)[0]]
    (repo / "docs" / "adr" / "0001-search.md").write_text("# Changed\n\nbread\n")
    git(repo, "commit", "--quiet", "-am", "change")
    fail[0] = True
    rep = s.reindex()
    assert not rep["ok"] and rep["error"] == "indexing failed (RuntimeError)"
    fail[0] = False
    assert [h.id for h in s.query(q("semantic search lessons"), tlp.Label.AMBER)[0]] == before
    shutil.rmtree(repo)
    rep = s.reindex()
    assert not rep["ok"] and "git fetch exited" in rep["error"]
    assert s.documents == 5
    assert not json.loads((tmp_path / "data" / "state" / "last-reindex.json").read_text())["ok"]


@needs_git
def test_a_removed_document_is_gone_after_the_next_reindex(tmp_path):
    repo = make_repo(tmp_path)
    s = service(tmp_path, repo)
    assert s.reindex()["ok"]
    (repo / "docs" / "adr" / "0002-secret.md").unlink()
    git(repo, "commit", "--quiet", "-am", "rm")
    rep = s.reindex()
    assert rep["ok"] and rep["removed"] == 1 and s.documents == 4


def test_one_reindex_at_a_time_and_none_from_disk_before_a_fetch(tmp_path):
    s = service(tmp_path, tmp_path / "r")
    rep = s.reindex(fetch=False)
    assert not rep["ok"] and "no checkout on disk" in rep["error"]
    assert not s.ready()["ready"] and s.check()["reason"] == "not indexed yet"
    s._reindexing.acquire()
    with pytest.raises(ReindexBusy):
        s.reindex()


class _Judge:
    def __init__(self, p):
        self.p, self.calls = p, []

    def judge(self, question, hit, label):
        self.calls.append((hit.id, label))
        return Verdict(self.p >= 0.10, self.p)


@needs_git
def test_the_judge_gates_without_reordering_and_never_sees_above_its_ceiling(tmp_path):
    repo = make_repo(tmp_path)
    judge_cfg = {"url": "https://gw.example.internal", "key_env": "GW_KEY", "ceiling": "green"}
    yes = _Judge(0.9)
    s = ContextService(config.parse(cfg_raw(tmp_path, repo, judge=judge_cfg)), env={},
                       store_factory=store_factory(), judge=yes)  # fmt: skip
    assert s.reindex()["ok"] and s.judge_on
    plain = service(tmp_path / "p", repo)
    assert plain.reindex()["ok"]
    want = [h.id for h in plain.query(q("dashboard blank build"), tlp.Label.GREEN)[0]]
    got = [h.id for h in s.query(q("dashboard blank build"), tlp.Label.GREEN)[0]]
    assert got == want and yes.calls
    no = _Judge(0.01)
    s._judged._judge = s._judge = no
    assert s.query(q("dashboard blank build"), tlp.Label.GREEN)[0] == []  # abstains
    # an amber passage is above the judge's green ceiling: never sent, the store's order kept
    no.calls.clear()
    hits, _ = s.query(q("proxy certificate restart"), tlp.Label.AMBER)
    assert hits and all(lb == tlp.Label.GREEN for _, lb in no.calls)
    assert s.check()["ok"] is False  # the judge does not clear the canned item
    s._judge = yes
    assert s.check()["judge"] == {"on": True, "answers": True, "confidence": 0.9}


@needs_git
def test_the_gateway_judge_asks_the_decision_role_with_its_key(tmp_path):
    repo = make_repo(tmp_path)
    key = "k" * 24
    with FakeOpenAIServer(
        decision_models=["fast-classifier"],
        api_keys=[key],
        decision_rules={"Does this passage": 0.9},
    ) as gw:
        judge_cfg = {"url": gw.url, "key_env": "GW_KEY", "allow_plaintext": True}
        cfg = config.parse(cfg_raw(tmp_path, repo, judge=judge_cfg, allow_plain_http=True))
        with pytest.raises(ValueError, match="key is not set"):
            make_judge(cfg, {})
        s = ContextService(cfg, env={"GW_KEY": key}, store_factory=store_factory())
        assert s.reindex()["ok"]
        assert s.check()["ok"] and s.check()["judge"]["answers"]
        assert s.query(q("dashboard blank build"), tlp.Label.GREEN)[0]
        gw.decision_rules["Does this passage"] = 0.01
        assert s.query(q("dashboard blank build"), tlp.Label.GREEN)[0] == []


# ----------------------------------------------------------------------------- the routes


@pytest.fixture
def routes(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    repo = make_repo(tmp_path)
    s = service(tmp_path, repo)
    return Routes(s, {"CONTEXT_ADMIN_TOKEN": ADMIN})


def _call(routes, path, token=None, body=None, method="POST"):
    auth = None if token is None else f"Bearer {token}"
    try:
        return routes.handle(method, path, auth, body)
    except ApiError as exc:
        return exc.status, {"error": exc.message}


def test_routes_authenticate_and_hold_each_caller_to_its_scope(routes):
    assert _call(routes, "/health", method="GET") == (200, {"status": "ok"})
    assert _call(routes, "/ready", method="GET")[0] == 503
    assert _call(routes, "/v1/query", body={"allowed": ALL})[0] == 401
    assert _call(routes, "/v1/query", "x" * 40, {"allowed": ALL})[0] == 401
    assert _call(routes, "/v1/reindex", READER)[0] == 403  # query only
    assert _call(routes, "/v1/query", ADMIN, {"allowed": ALL})[0] == 403  # admin reads nothing
    assert _call(routes, "/v1/check", READER)[0] == 403
    assert _call(routes, "/v1/nope", READER)[0] == 404
    assert _call(routes, "/v1/query", READER, method="GET")[0] == 405
    status, rep = _call(routes, "/v1/reindex", GREEN_READER)
    assert status == 200 and rep["ok"]
    assert _call(routes, "/ready", method="GET")[0] == 200
    assert _call(routes, "/v1/check", ADMIN)[0] == 200


def test_a_query_reads_at_the_callers_ceiling_and_may_only_lower_it(routes):
    assert _call(routes, "/v1/reindex", ADMIN)[0] == 200
    body = {"text": "proxy certificate restart", "allowed": ALL}
    status, doc = _call(routes, "/v1/query", READER, body)
    assert status == 200 and doc["ceiling"] == "amber" and doc["judged"] is False
    top = doc["hits"][0]
    assert top["id"] == "doc:adr/docs/adr/0002-secret.md" and top["tlp"] == "amber"
    assert set(top) == {"id", "kind", "title", "path", "score", "snippet", "content", "digest",
                        "tlp"}  # fmt: skip
    _, doc = _call(routes, "/v1/query", READER, {**body, "ceiling": "green"})
    assert doc["ceiling"] == "green" and top["id"] not in {h["id"] for h in doc["hits"]}
    _, doc = _call(routes, "/v1/query", GREEN_READER, {**body, "ceiling": "red"})
    assert doc["ceiling"] == "green" and top["id"] not in {h["id"] for h in doc["hits"]}
    assert _call(routes, "/v1/get", GREEN_READER, {"id": top["id"], "allowed": ALL})[0] == 404
    status, doc = _call(routes, "/v1/get", READER, {"id": top["id"], "allowed": ALL})
    assert status == 200 and doc["hit"]["tlp"] == "amber"
    assert _call(routes, "/v1/get", READER, {"id": "doc:none", "allowed": ALL})[0] == 404


@pytest.mark.parametrize(
    "body",
    [
        {"text": "x"},
        {"text": "x", "allowed": ["*"]},
        {"text": "x", "allowed": ALL, "budget": "ten"},
        {"text": "x" * 20000, "allowed": ALL},
        {"text": "x", "allowed": ALL, "ceiling": "blue"},
        {"text": "x", "allowed": ALL, "ceiling": 3},
        {"text": "x", "allowed": [["nested"]]},
    ],
)
def test_a_malformed_query_is_400_and_never_echoes_the_text(routes, body):
    status, doc = _call(routes, "/v1/query", READER, body)
    assert status == 400 and "x" * 5 not in doc["error"]


def test_reindex_reports_failure_and_busy(routes, tmp_path):
    shutil.rmtree(tmp_path / "origin")
    status, rep = _call(routes, "/v1/reindex", ADMIN)
    assert status == 500 and not rep["ok"]
    routes.service._reindexing.acquire()
    assert _call(routes, "/v1/reindex", ADMIN)[0] == 409


def test_the_admin_token_must_be_long_and_its_own(tmp_path):
    s = service(tmp_path, tmp_path / "r")
    with pytest.raises(ValueError, match="32 characters"):
        Routes(s, {"CONTEXT_ADMIN_TOKEN": "short"})
    with pytest.raises(ValueError, match="also a caller"):
        Routes(s, {"CONTEXT_ADMIN_TOKEN": READER})


def _http(url, token=None, body=None, raw=None):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="GET" if data is None else "POST")  # fmt: skip
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_the_http_server_and_the_commands(routes, tmp_path):
    srv = make_server(routes, LOOP, 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://{LOOP}:{port}"
    try:
        assert _http(base + "/health") == (200, {"status": "ok"})
        assert _http(base + "/v1/query", READER, raw=b"not json")[0] == 400
        assert _http(base + "/v1/query", READER, raw=b"[1]")[0] == 400
        big = json.dumps({"allowed": ALL, "text": "y" * 70000}).encode()
        assert _http(base + "/v1/query", READER, raw=big)[0] == 413
        status, _ = _http(base + "/v1/query", raw=b"{}")
        assert status == 401
        cfgfile = tmp_path / "config.json"
        raw = cfg_raw(tmp_path, tmp_path / "origin", port=port)
        cfgfile.write_text(json.dumps(raw))
        env = {"CONTEXT_CONFIG": str(cfgfile), "CONTEXT_ADMIN_TOKEN": ADMIN}
        assert cli.main(["check"], env) == 1  # not indexed yet: 503
        assert cli.main(["reindex"], env) == 0
        assert cli.main(["check"], env) == 0
        assert cli.main(["reindex"], {**env, "CONTEXT_ADMIN_TOKEN": "z" * 40}) == 2  # 401
        status, doc = _http(base + "/v1/query", READER,
                            {"text": "dashboard blank build", "allowed": ["lesson:"]})  # fmt: skip
        assert status == 200 and doc["hits"][0]["id"] == "lesson:lessons/LL-001"
    finally:
        srv.shutdown()
        srv.server_close()
    assert cli.main(["reindex"], env) == 2  # unreachable


def test_the_commands_refuse_usage_and_configuration_errors(tmp_path, capsys):
    assert cli.main([], {}) == 2
    assert cli.main(["nope"], {}) == 2
    assert cli.main(["check"], {"CONTEXT_CONFIG": str(tmp_path / "none.json")}) == 2
    assert "cannot read" in capsys.readouterr().err


def test_the_initial_index_falls_back_to_the_checkouts_on_disk(tmp_path):
    calls = []

    class S:
        def reindex(self, fetch=True):
            calls.append(fetch)
            return {"ok": not fetch}

    cli.initial_index(S())
    assert calls == [True, False]
