# SPDX-License-Identifier: Apache-2.0
"""The read-only MCP server: every tool on the real repository, its refusals, the profile scope
that a call cannot widen, the size caps, the read-only tool list, and the SDK binding (in memory
and over stdio; skipped without the ``mcp`` extra)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from homelabnext.agent.compiler import profile_digest
from homelabnext.identity.aliases import load_aliases
from homelabnext.mcp import (
    MAX_RESULT_CHARS,
    SERVER_NAME,
    TOOLS,
    Catalog,
    CatalogError,
    ScopeError,
    intersect,
    load_profile_scope,
    profile_scope,
)
from homelabnext.mcp import catalog as catalog_mod
from homelabnext.mcp.cli import main as cli_main
from homelabnext.mcp.clients import load_lock, load_policy
from homelabnext.sop.capabilities import collect, render_page

ROOT = Path(__file__).resolve().parents[2]
READER = ROOT / "schemas" / "agent" / "examples" / "profile.reader.json"

#: the whole tool list, pinned: every tool reads; adding one is a reviewed change to this set
READ_ONLY_ALLOWLIST = {
    "context_for",
    "find_services",
    "get_contract",
    "get_schema",
    "invariants_status",
    "lessons_due",
    "list_capabilities",
    "outline",
    "related",
    "section",
    "terms",
}


@pytest.fixture(scope="module")
def cat() -> Catalog:
    return Catalog(ROOT)


def _call(c: Catalog, name: str, **args) -> dict:
    text = c.call(name, args)
    assert len(text) <= MAX_RESULT_CHARS
    return json.loads(text)


def _policy_and_lock(tmp_path: Path, profile: Path) -> tuple[Path, Path]:
    """The ceiling policy the reader example is judged against (its own ceiling, written by the
    policy owner) and a lock pinning ``profile``'s digest."""
    doc = json.loads(profile.read_text(encoding="utf-8"))
    pol, lock = tmp_path / "ceilings.yml", tmp_path / "profiles.lock.yml"
    entry = {**doc["ceiling"], "data_tier": doc["data_tier"], "reads_untrusted": True}
    pol.write_text(json.dumps({"ceilings": {doc["id"]: entry}}), encoding="utf-8")
    lock.write_text(json.dumps({"profiles": {doc["id"]: doc["digest"]}}), encoding="utf-8")
    return pol, lock


def _scope(cat, path: Path, pinned: Path | None = None):
    """load_profile_scope against the policy and a lock pinning ``pinned`` (default ``path``)."""
    pol, lock = _policy_and_lock(path.parent, pinned or path)
    return load_profile_scope(path, cat.registry, policy=load_policy(pol), lock=load_lock(lock))


def _granted_profile(tmp_path: Path, grant: bool = True) -> Path:
    """The reader example with ``hnx-catalog`` granted (and within its ceiling), re-digested."""
    p = copy.deepcopy(json.loads(READER.read_text(encoding="utf-8")))
    if grant:
        p["grants"]["mcp"] = sorted({*p["grants"]["mcp"], SERVER_NAME})
        p["ceiling"]["mcp"] = sorted({*p["ceiling"]["mcp"], SERVER_NAME})
    p["digest"] = profile_digest(p)
    out = tmp_path / "profile.json"
    out.write_text(json.dumps(p), encoding="utf-8")
    return out


# -- the tool list ----------------------------------------------------------------------------


def test_tool_list_is_the_read_only_allowlist():
    assert set(TOOLS) == READ_ONLY_ALLOWLIST
    assert all(callable(getattr(Catalog, name)) for name in TOOLS)


def test_unknown_tool_and_bad_arguments_are_refused(cat):
    with pytest.raises(CatalogError, match="no such tool"):
        cat.call("run_shell", {"cmd": "id"})
    with pytest.raises(CatalogError, match="unexpected or missing arguments"):
        cat.call("get_schema", {"path": "x", "extra": 1})


# -- catalog tools on the real repository ------------------------------------------------------


def test_list_capabilities_matches_the_capability_model(cat):
    caps = {c["name"]: c for c in _call(cat, "list_capabilities")["capabilities"]}
    assert len(caps) == 18
    ctx = caps["context"]
    assert (ctx["operations"], ctx["must"], ctx["should"]) == (4, 13, 3)
    assert ctx["implementations"]["fake"] == "FakeContextStore"
    assert {a["target_file"] for a in ctx["implementations"]["adapters"]} == {
        "conformance/targets/context-reference.yml"
    }
    assert caps["lake-query"]["implementations"]["services"] == ["lake-query"]


def test_get_contract_carries_what_the_page_shows(cat):
    c = _call(cat, "get_contract", capability="cap:context")
    assert [o["name"] for o in c["operations"]] == ["index", "query", "get", "delete"]
    get = next(o for o in c["operations"] if o["name"] == "get")
    assert [p["name"] for p in get["params"]] == ["doc_id", "allowed"]
    assert get["raises"] == ["NotFound", "InvalidQuery"]
    assert get["signature"].startswith("def get(doc_id: str")
    query = next(s for s in c["data_shapes"] if s["name"] == "Query")
    allowed = next(f for f in query["fields"] if f["name"] == "allowed")
    assert allowed["default"] == "required" and "frozenset" in allowed["type"]
    assert {"name": "MAX_BUDGET", "value": "200"} in c["constants"]
    assert {e["name"] for e in c["errors"]} >= {"NotFound", "InvalidQuery", "InvalidDocument"}
    checks = {ch["id"]: ch for ch in c["checks"]}
    assert checks["scope-is-mandatory"]["level"] == "MUST"
    assert checks["semantic-recall"] == {
        "id": "semantic-recall",
        "level": "SHOULD",
        "assertion": checks["semantic-recall"]["assertion"],
        "requires": ["semantic"],
    }
    assert c["features"] == [{"name": "semantic", "kind": "product", "checks": ["semantic-recall"]}]
    assert {m["name"] for m in c["mutants"]} >= {"scope-blind", "hidden-bridge"}
    lake = _call(cat, "get_contract", capability="lake-query")
    real = [a for a in lake["adapters"] if a["real"]]
    assert real and all("limits" in a for a in real)
    assert lake["services"]["providers"] == [{"name": "lake-query", "impl": "trino"}]


def test_contracts_and_pages_come_from_one_model(cat):
    """Every check and operation a tool returns is on the generated page, for every capability."""
    for c in collect(ROOT, cat.registry):
        page = render_page(c, ROOT)
        assert page == (ROOT / "docs" / "capabilities" / f"{c.name}.md").read_text(encoding="utf-8")
        data = _call(cat, "get_contract", capability=c.name)
        assert all(f"`{ch['id']}`" in page for ch in data["checks"])
        assert all(f"`{o['protocol']}.{o['name']}`" in page for o in data["operations"])


def test_get_contract_unknown_capability(cat):
    with pytest.raises(CatalogError, match=r"no such capability; known: .*context"):
        cat.call("get_contract", {"capability": "nope"})


@pytest.mark.parametrize(
    "ref",
    [
        "schema:schemas/agent/profile.schema.json",
        "schemas/agent/profile.schema.json",
        "agent/profile.schema.json",
        "agent/profile",
        "$id",  # the schema's current $id, read from the file (it moves with every minor version)
    ],
)
def test_get_schema_resolves_every_reference_form(cat, ref):
    if ref == "$id":
        ref = json.loads((ROOT / "schemas/agent/profile.schema.json").read_text(encoding="utf-8"))[
            "$id"
        ]
    out = _call(cat, "get_schema", id_or_path=ref)
    assert out["path"] == "schemas/agent/profile.schema.json"
    assert out["schema"] == json.loads((ROOT / out["path"]).read_text(encoding="utf-8"))
    assert out["id"] == out["schema"]["$id"]


@pytest.mark.parametrize(
    "ref",
    [
        "../pyproject.toml",
        "schemas/../pyproject.toml",
        "schema:schemas/../../etc/passwd",
        "/etc/passwd",
        "~/.ssh/id_fake",
        "schemas\\agent\\profile.schema.json",
        "pyproject.toml",
        "examples/services.yml",
        "schemas/README.md",
        "schemas/agent/no-such.schema.json",
        "agent/profile\x00.json",
        "",
    ],
)
def test_get_schema_refuses_anything_but_a_schema_file(cat, ref):
    with pytest.raises(CatalogError):
        cat.get_schema(ref)


def test_get_schema_refuses_symlinks_out_of_schemas(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"fake": "secret-looking value, not a schema"}', encoding="utf-8")
    root = tmp_path / "checkout"
    (root / "homelabnext").mkdir(parents=True)
    (root / "schemas" / "real").mkdir(parents=True)
    (root / "schemas" / "real" / "ok.schema.json").write_text('{"$id": "x"}', encoding="utf-8")
    (root / "schemas" / "evil.json").symlink_to(outside)
    (root / "schemas" / "linked").symlink_to(tmp_path)
    c = Catalog(root)
    assert c.get_schema("real/ok")["schema"] == {"$id": "x"}
    for ref in ("evil.json", "schemas/evil.json", "linked/outside.json"):
        with pytest.raises(CatalogError, match="symbolic link"):
            c.get_schema(ref)


def test_find_services_names_only(cat):
    allowed_keys = {"name", "capability", "impl", "owner", "tags", "depends_on", "mcp"}
    every = _call(cat, "find_services")["services"]
    assert len(every) == len(cat.registry.services)
    assert all(set(s) == allowed_keys for s in every)
    (lq,) = _call(cat, "find_services", capability="cap:lake-query")["services"]
    assert lq["impl"] == "trino" and lq["mcp"] == "lake"
    data = _call(cat, "find_services", tag="data")["services"]
    assert data and all("data" in s["tags"] for s in data)
    assert _call(cat, "find_services", capability="lake-query", tag="ui")["services"] == []


def test_related_ranks_the_graph_neighbourhood(cat):
    out = _call(
        cat, "related", ids_or_paths=["cap:context", "conformance/suites/context.py", "no-such"]
    )
    assert "cap:context" in out["seeds"]
    assert "check:context/scope-is-mandatory" in out["seeds"]  # defined by the suite file
    assert out["unresolved"] == ["no-such"]
    ids = [r["id"] for r in out["related"]]
    assert "doc:docs/capabilities/context.md" in ids
    dist = [r["distance"] for r in out["related"]]
    assert dist == sorted(dist)
    assert len(_call(cat, "related", ids_or_paths=["cap:context"], budget=3)["related"]) == 3
    with pytest.raises(CatalogError):
        cat.related(["../etc"])
    with pytest.raises(CatalogError):
        cat.related([], depth=2)
    with pytest.raises(CatalogError):
        cat.related(["cap:context"], depth=9)


def test_lessons_due_and_invariants_status(cat):
    due = _call(cat, "lessons_due", today="2026-01-01")
    assert due["today"] == "2026-01-01"
    assert set(due["due"]) == {"review", "retire", "incorporate", "supersede", "update", "keep"}
    for bad in ("tomorrow", "2026-13-01", "2026-01-01; rm"):
        with pytest.raises(CatalogError, match="YYYY-MM-DD"):
            cat.lessons_due(bad)
    inv = _call(cat, "invariants_status")
    assert sum(inv["counts"].values()) == len(inv["criteria"]) > 0
    for row in inv["criteria"]:
        assert ("remediation" in row) == (row["status"] != "pass")
    assert inv["all_hold"] is False  # most criteria have no committed result: untested counts


def _page(src: Path) -> dict:
    from homelabnext.registers.render import load_sources, render_invariants

    s = load_sources(src)
    return render_invariants(s["invariants"], s["results"])[1]


def test_terms_is_the_packaged_terms_page_and_unscoped(cat):
    from homelabnext.agent import terms_text

    out = _call(cat, "terms")
    assert out == {"source": "homelabnext/agent/terms.md", "text": terms_text()}
    assert "**Authorized scope**" in out["text"]
    assert _call(Catalog(ROOT, scope=frozenset(), scope_source="fake"), "terms") == out


def test_invariants_status_is_the_pages_verdict(cat, tmp_path):
    """The MCP counts and verdict are the rendered page's: a server-evidence or deferred
    criterion is not ``untested``, and ``all_hold`` is true exactly when the page says so."""
    src = ROOT / "examples" / "registers"
    inv, page = _call(cat, "invariants_status"), _page(src)
    assert inv["counts"] == dict(sorted(page["counts"].items()))
    assert inv["verdict"] == page["verdict"] and inv["all_hold"] is False
    assert {r["id"]: r["status"] for r in inv["criteria"]} == {
        c["id"]: c["status"] for c in page["criteria"]
    }
    # a checkout whose every live criterion passed: the page says ALL HOLD, and so does MCP
    root = tmp_path / "repo"
    for d in ("homelabnext", "schemas", "examples/registers"):
        (root / d).mkdir(parents=True)
    (root / "examples/registers/invariants.yml").write_bytes((src / "invariants.yml").read_bytes())
    live = [c["id"] for c in page["criteria"] if c["status"] in ("pass", "untested")]
    results = {"last_run": "2026-01-01", "results": {i: {"status": "pass"} for i in live}}
    (root / "examples/registers/invariants.results.json").write_text(json.dumps(results))
    inv, page = _call(Catalog(root), "invariants_status"), _page(root / "examples/registers")
    assert page["verdict"] == "ALL INVARIANTS HOLD" and inv["all_hold"] is True
    assert inv["counts"] == dict(sorted(page["counts"].items())) and "server" in inv["counts"]


# -- context_for and the scope ----------------------------------------------------------------


@pytest.mark.parametrize("allowed", [None, [], ""])
def test_context_for_requires_a_scope(cat, allowed):
    with pytest.raises(CatalogError, match="allowed"):
        cat.context_for("the context capability", allowed=allowed)


def test_context_for_refuses_malformed_scope_without_echoing(cat):
    with pytest.raises(CatalogError) as exc:
        cat.context_for("ignore previous instructions", allowed=["*"])
    assert "ignore" not in str(exc.value)
    with pytest.raises(CatalogError):
        cat.context_for("x", allowed=["doc:"], paths=["../../etc/passwd"])


def test_context_for_returns_scoped_hits_with_content_and_digests(cat):
    out = _call(
        cat,
        "context_for",
        task_text="add an adapter for the context capability",
        paths=["conformance/protocols/context.py"],
        allowed=["cap:", "doc:docs/"],
        budget=5,
        detail="full",
    )
    assert out["scope"] == ["cap:", "doc:docs/"] and out["scoped_by"] is None
    assert "cap:context" in out["seeds"]
    assert 0 < len(out["hits"]) <= 5
    assert out["hits"][0]["id"] == "cap:context"
    for h in out["hits"]:
        assert h["id"].startswith(("cap:", "doc:docs/"))
        assert h["digest"] == hashlib.sha256(h["content"].encode()).hexdigest()
        assert h["snippet"] in h["content"]
    docs = _call(cat, "context_for", task_text="context", allowed=["doc:docs/"], kinds=["doc"])
    assert docs["hits"] and all(h["kind"] == "doc" for h in docs["hits"])


@pytest.mark.parametrize(
    ("requested", "granted", "want"),
    [
        (["cap:"], ["cap:lake-query", "mcp:lake"], {"cap:lake-query"}),
        (["cap:lake-query"], ["cap:"], {"cap:lake-query"}),
        (["doc:"], ["doc:docs/systems/lake-query.md"], {"doc:docs/systems/lake-query.md"}),
        (["check:lake-query/x"], ["check:lake-query/"], {"check:lake-query/x"}),
        (["check:"], ["check:lake-query/"], {"check:lake-query/"}),
        (["check:lake-query/"], ["check:lake-query/x"], {"check:lake-query/x"}),
        (["lesson:0199"], ["cap:lake-query"], set()),
        (["cap:lake"], ["cap:lake-query"], set()),  # an exact id is not a prefix
        (["cap:lake-query-x"], ["cap:lake-query"], set()),
        (["cap:lake-query/"], ["cap:lake-query"], set()),
        (["svc:"], [], set()),
    ],
)
def test_intersect_never_widens(requested, granted, want):
    assert intersect(requested, granted) == want


def test_profile_scope_bounds_a_call_and_cannot_be_widened(cat, tmp_path):
    pid, scope = _scope(cat, _granted_profile(tmp_path))
    assert pid == "profile:reader"
    assert scope >= {
        "profile:reader",
        "cap:lake-query",
        "check:lake-query/",
        "doc:docs/capabilities/lake-query.md",
        "mcp:lake",
        f"mcp:{SERVER_NAME}",
        "svc:lake-query",
        "doc:docs/systems/lake-query.md",
    }
    assert not any(e.startswith(("lesson:", "runbook:", "cap:context")) for e in scope)
    scoped = Catalog(ROOT, scope=scope, scope_source=pid)
    wide = ["cap:", "doc:", "lesson:", "runbook:", "svc:", "check:"]
    out = _call(scoped, "context_for", task_text="lake-query SQL", allowed=wide, budget=50)
    assert out["scoped_by"] == "profile:reader"
    assert set(out["scope"]) <= scope
    assert out["hits"] and all(_visible(scope, h["id"]) for h in out["hits"])
    assert all(_visible(scope, s) for s in out["seeds"])
    unscoped = _call(cat, "context_for", task_text="lake-query SQL", allowed=wide, budget=50)
    assert any(not _visible(scope, h["id"]) for h in unscoped["hits"])  # the scope did narrow it
    nothing = _call(scoped, "context_for", task_text="lessons", allowed=["lesson:"], budget=5)
    assert nothing["scope"] == [] and nothing["hits"] == []
    rel = _call(scoped, "related", ids_or_paths=["cap:lake-query", "cap:context"])
    assert rel["scoped"] is True and rel["seeds"] == ["cap:lake-query"]
    assert rel["unresolved"] == ["cap:context"]  # outside the scope reads as unknown
    assert rel["related"] and all(_visible(scope, r["id"]) for r in rel["related"])


def test_related_resolves_a_path_however_it_is_spelled(cat):
    """``./docs/graph.md`` is the same path as ``docs/graph.md``: a seed, not ``unresolved``."""
    for spelling in ("./docs/graph.md", "docs/graph.md"):
        out = _call(cat, "related", ids_or_paths=[spelling, "./no/such/file.md"])
        assert out["seeds"] == ["doc:docs/graph.md"]
        assert out["unresolved"] == ["./no/such/file.md"]


def test_profile_scope_bounds_the_catalog_tools(cat, tmp_path):
    """``find_services``, ``get_contract``, ``list_capabilities`` and ``lessons_due`` return only
    what the profile scope covers; an out-of-scope capability reads like an unknown one."""
    pid, scope = _scope(cat, _granted_profile(tmp_path))
    scoped = Catalog(ROOT, scope=scope, scope_source=pid)
    caps = _call(scoped, "list_capabilities")["capabilities"]
    assert caps and all(f"cap:{c['name']}" in scope for c in caps)
    assert len(caps) < len(_call(cat, "list_capabilities")["capabilities"])
    for c in caps:
        assert all(f"svc:{s}" in scope for s in c["implementations"]["services"])
    contract = _call(scoped, "get_contract", capability="cap:lake-query")
    svcs = [p["name"] for p in contract["services"]["providers"]]
    svcs += contract["services"]["consumers"]
    assert all(f"svc:{s}" in scope for s in svcs)
    with pytest.raises(CatalogError, match=r"no such capability; known: lake-query$"):
        scoped.call("get_contract", {"capability": "cap:secrets"})
    assert _call(cat, "get_contract", capability="cap:secrets")["name"] == "secrets"  # unscoped
    found = _call(scoped, "find_services")["services"]
    assert found and all(f"svc:{s['name']}" in scope for s in found)
    assert all(f"svc:{d}" in scope for s in found for d in s["depends_on"])
    assert _call(scoped, "find_services", capability="secrets")["services"] == []
    assert len(_call(cat, "find_services")["services"]) > len(found)
    due = _call(scoped, "lessons_due", today="2027-06-01")
    assert not any(due["due"].values())  # lessons and runbooks are not in a reader's scope
    assert any(_call(cat, "lessons_due", today="2027-06-01")["due"].values())
    u = load_aliases(ROOT / "examples/registers").codes
    with_lessons = Catalog(ROOT, scope=scope | {f"lesson:{u['LL-001']}"}, scope_source=pid)
    ids = {d["id"] for v in _call(with_lessons, "lessons_due", today="2027-06-01")["due"].values()
           for d in v}  # fmt: skip
    assert ids == {u["LL-001"]}


def test_scoped_lessons_due_reasons_name_no_out_of_scope_record(cat, tmp_path):
    """Regression: a due row's ``reason`` named other records (LL 5's "candidate runbook(s)
    RB 1") whatever the scope; a record the scope does not cover is now withheld -- its number
    in the reason, its uid in ``refs`` and in ``labels``."""
    u = load_aliases(ROOT / "examples/registers").codes
    pid, scope = _scope(cat, _granted_profile(tmp_path))
    unscoped = _call(cat, "lessons_due", today="2027-06-01")
    row = unscoped["due"]["incorporate"][0]
    assert "RB 1" in row["reason"] and row["refs"] == [u["RB-001"]] and row["label"] == "LL 5"
    assert unscoped["labels"][u["RB-001"]] == "RB 1"
    scoped = Catalog(ROOT, scope=scope | {f"lesson:{u['LL-005']}"}, scope_source=pid)
    out = _call(scoped, "lessons_due", today="2027-06-01")
    rows = [d for v in out["due"].values() for d in v]
    assert [d["id"] for d in rows] == [u["LL-005"]]
    dumped = json.dumps(out)
    assert "RB 1" not in dumped and u["RB-001"] not in dumped
    assert "out of scope" in rows[0]["reason"]
    both = Catalog(
        ROOT, scope=scope | {f"lesson:{u['LL-005']}", f"runbook:{u['RB-001']}"}, scope_source=pid
    )
    reasons = [d["reason"] for v in _call(both, "lessons_due", today="2027-06-01")["due"].values()
               for d in v]  # fmt: skip
    assert any("RB 1" in r for r in reasons)


def test_related_takes_a_uid_or_a_legacy_code(cat):
    from homelabnext.identity.aliases import LegacyRecordCode

    u = load_aliases(ROOT / "examples/registers").codes
    assert _call(cat, "related", ids_or_paths=[u["LL-001"]])["seeds"] == [f"lesson:{u['LL-001']}"]
    with pytest.warns(LegacyRecordCode):
        got = _call(cat, "related", ids_or_paths=["lesson:LL-001"])
    assert got["seeds"] == [f"lesson:{u['LL-001']}"] and got["unresolved"] == []


def _visible(scope, doc_id):
    from homelabnext.context import in_scope

    return doc_id if in_scope(doc_id, scope) else ""


def test_profile_scope_refuses_an_ungranted_or_tampered_profile(cat, tmp_path):
    with pytest.raises(ScopeError, match="not granted the hnx-catalog"):
        _scope(cat, _granted_profile(tmp_path, grant=False))
    p = _granted_profile(tmp_path)
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["grants"]["capabilities"].append("cap:records-propose")  # widened, digest kept
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ScopeError, match="does not verify"):
        _scope(cat, p)
    (tmp_path / "bad.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ScopeError):
        _scope(cat, tmp_path / "bad.json", pinned=_granted_profile(tmp_path))
    with pytest.raises(ScopeError, match="cannot read"):
        _scope(cat, tmp_path / "missing.json", pinned=_granted_profile(tmp_path))


def test_a_profile_rewritten_with_its_own_ceiling_and_digest_does_not_widen_the_scope(
    cat, tmp_path
):
    """Whoever can write the profile file can widen grants and ceiling together and recompute
    the digest; only the policy and the lock, owned elsewhere, refuse it."""
    honest = _granted_profile(tmp_path)
    pol, lock = _policy_and_lock(tmp_path, honest)
    forged = json.loads(honest.read_text(encoding="utf-8"))
    caps = sorted({f"cap:{s.capability}" for s in cat.registry.sorted_services()})
    for part in ("grants", "ceiling"):
        forged[part]["capabilities"] = sorted({*forged[part]["capabilities"], *caps})
    forged["digest"] = profile_digest(forged)
    f = tmp_path / "forged.json"
    f.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(ScopeError, match="only against the ceiling policy and the lock"):
        load_profile_scope(f, cat.registry, policy=None, lock=None)
    with pytest.raises(ScopeError, match="does not verify"):
        load_profile_scope(f, cat.registry, policy=load_policy(pol), lock=load_lock(lock))
    # a lock alone is not enough either: the policy's ceiling is what the grants are held to
    pinned = tmp_path / "forged.lock.yml"
    pinned.write_text(json.dumps({"profiles": {forged["id"]: forged["digest"]}}))
    with pytest.raises(ScopeError, match="does not verify"):
        load_profile_scope(f, cat.registry, policy=load_policy(pol), lock=load_lock(pinned))


def test_profile_scope_is_derived_from_grants_only(cat):
    profile = {"id": "profile:x", "grants": {"capabilities": ["cap:notify"], "mcp": []}}
    assert profile_scope(profile, cat.registry) == {
        "profile:x",
        "cap:notify",
        "check:notify/",
        "doc:docs/capabilities/notify.md",
        "svc:notify",
        "doc:docs/systems/notify.md",
    }


# -- size caps --------------------------------------------------------------------------------


def test_dump_drops_trailing_items_to_fit_and_says_so():
    items = [{"n": i, "pad": "x" * 1000} for i in range(1000)]
    text = Catalog.dump({"hits": items}, "hits")
    assert len(text) <= MAX_RESULT_CHARS
    out = json.loads(text)
    assert out["hits"] == items[: len(out["hits"])]
    assert out["truncated"] == {"dropped": 1000 - len(out["hits"]), "reason": "result size cap"}
    assert json.loads(Catalog.dump({"hits": items[:3]}, "hits")) == {"hits": items[:3]}
    with pytest.raises(CatalogError, match="cap"):
        Catalog.dump({"blob": "x" * (MAX_RESULT_CHARS + 1)})


def test_hit_content_is_capped_with_its_full_digest(cat, monkeypatch):
    monkeypatch.setattr(catalog_mod, "MAX_HIT_CONTENT_CHARS", 50)
    out = cat.context_for(
        "context", allowed=["doc:docs/capabilities/context.md"], budget=1, detail="full"
    )
    (h,) = out["hits"]
    full = (ROOT / "docs" / "capabilities" / "context.md").read_text(encoding="utf-8")
    assert h["content"] == full[:50] and h["content_truncated"] is True
    assert h["content_chars"] == len(full)
    assert h["digest"] == hashlib.sha256(full.encode()).hexdigest()


def test_every_tool_result_fits_the_cap(cat):
    for name, args in [
        ("list_capabilities", {}),
        ("get_contract", {"capability": "lake-query"}),
        ("find_services", {}),
        ("related", {"ids_or_paths": ["doc:README.md"], "budget": 200, "depth": 3}),
        ("context_for", {"task_text": "the lab", "allowed": ["doc:"], "budget": 200}),
        (
            "context_for",
            {"task_text": "the lab", "allowed": ["doc:"], "budget": 200, "detail": "full"},
        ),
        ("outline", {"id_or_path": "README.md", "allowed": ["doc:"]}),
        ("section", {"id_or_path": "docs/mcp.md", "heading": "tools", "allowed": ["doc:"]}),
        ("invariants_status", {}),
        ("terms", {}),
    ]:
        assert len(cat.call(name, args)) <= MAX_RESULT_CHARS


# -- command line -----------------------------------------------------------------------------


def test_cli_tools_and_call(capsys):
    assert cli_main(["tools"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert {line.split(":", 1)[0] for line in lines} == READ_ONLY_ALLOWLIST
    assert cli_main(["call", "get_schema", "--args", '{"id_or_path": "agent/profile"}']) == 0
    assert json.loads(capsys.readouterr().out)["path"] == "schemas/agent/profile.schema.json"
    assert cli_main(["call", "get_schema", "--args", '{"id_or_path": "../x.json"}']) == 1
    assert "refused" in capsys.readouterr().err
    assert cli_main(["call", "shell"]) == 2
    assert cli_main(["call", "list_capabilities", "--args", "[1]"]) == 2
    assert cli_main(["call", "list_capabilities", "--args", "{"]) == 2
    assert cli_main(["call", "list_capabilities", "--root", "/nonexistent-fake"]) == 2


def test_cli_scope_from_profile(tmp_path, capsys):
    pol, lock = _policy_and_lock(tmp_path, READER)
    pl = ["--policy", str(pol), "--lock", str(lock)]
    assert cli_main(["serve", "--scope-from-profile", str(READER), *pl]) == 1
    assert "not granted" in capsys.readouterr().err
    prof = _granted_profile(tmp_path)
    pol, lock = _policy_and_lock(tmp_path, prof)
    args = '{"task_text": "lake", "allowed": ["lesson:", "cap:"]}'
    for partial in ([], ["--policy", str(pol)], ["--lock", str(lock)]):
        call = ["call", "context_for", "--args", args, "--scope-from-profile", str(prof)]
        assert cli_main([*call, *partial]) == 2
        assert "needs --policy and --lock" in capsys.readouterr().err
    assert cli_main(["call", "list_capabilities", "--policy", str(pol)]) == 2
    assert "go with --scope-from-profile" in capsys.readouterr().err
    pl = ["--policy", str(pol), "--lock", str(lock)]
    assert (
        cli_main(["call", "context_for", "--args", args, "--scope-from-profile", str(prof), *pl])
        == 0
    )
    out = json.loads(capsys.readouterr().out)
    assert out["scope"] == ["cap:lake-query"] and out["scoped_by"] == "profile:reader"


# -- the SDK binding --------------------------------------------------------------------------


def _client(server):
    """An in-memory client session for ``server`` on either SDK major."""
    import mcp

    if hasattr(mcp, "Client"):  # 2.x
        return mcp.Client(server)
    from mcp.shared.memory import create_connected_server_and_client_session

    return create_connected_server_and_client_session(server)


def _is_error(result) -> bool:
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


def _schema(tool) -> dict:
    return getattr(tool, "input_schema", None) or tool.inputSchema


def test_sdk_server_lists_exactly_the_read_only_tools(cat):
    pytest.importorskip("mcp")
    import anyio

    from homelabnext.mcp.server import build_server

    async def run():
        async with _client(build_server(cat)) as s:
            tools = (await s.list_tools()).tools
            assert {t.name for t in tools} == READ_ONLY_ALLOWLIST
            for t in tools:
                hints = t.annotations.model_dump(by_alias=True)
                assert hints["readOnlyHint"] is True and hints["destructiveHint"] is False
                assert hints["openWorldHint"] is False
            ctx = next(t for t in tools if t.name == "context_for")
            assert set(_schema(ctx)["required"]) == {"task_text", "allowed"}
            assert _schema(ctx)["properties"]["detail"]["default"] == "summary"
            sec = next(t for t in tools if t.name == "section")
            assert set(_schema(sec)["required"]) == {"id_or_path", "heading", "allowed"}
            ok = await s.call_tool(
                "outline", {"id_or_path": "docs/mcp.md", "allowed": ["doc:docs/"]}
            )
            assert not _is_error(ok)
            assert ok.content[0].text == cat.call(
                "outline", {"id_or_path": "docs/mcp.md", "allowed": ["doc:docs/"]}
            )
            bad = await s.call_tool(
                "section", {"id_or_path": "docs/mcp.md", "heading": "x", "allowed": ["doc:"]}
            )
            assert _is_error(bad) and "unknown heading" in bad.content[0].text
            ok = await s.call_tool("get_contract", {"capability": "context"})
            assert not _is_error(ok)
            assert ok.content[0].text == cat.call("get_contract", {"capability": "context"})
            bad = await s.call_tool("context_for", {"task_text": "x", "allowed": []})
            assert _is_error(bad) and "allowed is required" in bad.content[0].text
            bad = await s.call_tool("get_schema", {"id_or_path": "../pyproject.toml"})
            assert _is_error(bad) and "inside the checkout" in bad.content[0].text

    anyio.run(run)


def test_server_starts_on_stdio_and_lists_tools():
    pytest.importorskip("mcp")
    import anyio
    from mcp import ClientSession, StdioServerParameters, stdio_client

    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "homelabnext.cli", "mcp", "serve", "--root", str(ROOT)],
        env=env,
        cwd=str(ROOT),
    )

    async def run():
        import mcp

        with anyio.fail_after(60):
            if hasattr(mcp, "Client"):  # 2.x
                async with mcp.Client(params) as s:
                    names = {t.name for t in (await s.list_tools()).tools}
            else:
                async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
                    await s.initialize()
                    names = {t.name for t in (await s.list_tools()).tools}
        assert names == READ_ONLY_ALLOWLIST

    anyio.run(run)
