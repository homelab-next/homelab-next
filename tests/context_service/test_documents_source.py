# SPDX-License-Identifier: Apache-2.0
"""The ``documents`` source kind (homelabnext/context_service/docsource.py): the document store's
REST API indexed by tag, nothing copied.

Hermetic: the store is a fake HTTP server on loopback (pagination, a tag filter, a token check, a
Host check, a redirect), the embedder and BM25 are the semantic adapter's test seams."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from homelabnext import tlp
from homelabnext.context import Query
from homelabnext.context_service import config
from homelabnext.context_service.docsource import slug
from homelabnext.context_service.service import ContextService
from tests.context_service.test_context_service import store_factory

LOOP = ".".join(["127", "0", "0", "1"])
TOKEN = "t0ken" + "x" * 30
HOST = "docs.example.internal"


class FakeStore:
    """tags: name -> list of documents; counts and records what the service asked."""

    def __init__(self) -> None:
        self.docs: dict[str, list[dict]] = {}
        self.requests: list[dict] = []
        self.redirect = False
        self.srv: ThreadingHTTPServer | None = None

    def start(self) -> str:
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silent
                pass

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                outer.requests.append(
                    {
                        "path": u.path,
                        "q": q,
                        "host": self.headers["Host"],
                        "auth": self.headers["Authorization"],
                    }
                )
                if self.headers["Host"] != HOST:
                    return self._send(400, {"detail": "bad host"})
                if self.headers["Authorization"] != f"Token {TOKEN}":
                    return self._send(401, {"detail": "no"})
                if outer.redirect:
                    self.send_response(302)
                    self.send_header("Location", "http://" + LOOP + ":9/elsewhere")
                    self.end_headers()
                    return
                rows = outer.docs.get(q.get("tags__name__iexact", ""), [])
                size, page = int(q["page_size"]), int(q["page"])
                chunk = rows[(page - 1) * size : page * size]
                nxt = f"http://x/?page={page + 1}" if page * size < len(rows) else None
                self._send(200, {"count": len(rows), "next": nxt, "results": chunk})

            def _send(self, code: int, body: dict) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.srv = ThreadingHTTPServer((LOOP, 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return f"http://{LOOP}:{self.srv.server_address[1]}"

    def stop(self) -> None:
        assert self.srv is not None
        self.srv.shutdown()
        self.srv.server_close()


def doc(i: int, title: str, text: str) -> dict:
    return {
        "id": i,
        "title": title,
        "content": text,
        "created": "2024-03-05T10:00:00Z",
        "modified": "2024-03-06T10:00:00Z",
    }


@pytest.fixture
def fake():
    f = FakeStore()
    f.url = f.start()
    f.docs = {
        "tax-library": [
            doc(1, "Form 1040 Instructions", "How to file the annual return. Schedule C."),
            doc(2, "Rental depreciation", "Residential rental property is depreciated 27.5 years."),
            doc(3, "Estimated payments", "Quarterly estimated tax payments are due in April."),
        ],
        "yardi": [doc(10, "Voyager Report Guide", "Run the aged receivables report in Voyager.")],
    }
    yield f
    f.stop()


def raw_cfg(tmp, fake, **src):
    s = {
        "name": "taxlib",
        "type": "documents",
        "url": fake.url,
        "kind": "tax",
        "tlp": "amber",
        "tags": ["tax-library"],
        "credential_env": "CTX_TOKEN",
        "credential_scheme": "token",
        "host_header": HOST,
        "page_size": 2,
    }
    s.update(src)
    return {
        "port": 18094,
        "model_dir": "/opt/hnx/model",
        "data_dir": str(tmp / "data"),
        "allow_plain_http": True,
        "sources": [s],
        "callers": [
            {"name": "agents", "sha256": "a" * 64, "ceiling": "amber", "scopes": ["query"]}
        ],
        "health": {
            "text": "depreciation",
            "expect": "tax:taxlib/2-rental-depreciation",
            "ceiling": "amber",
        },
    }


def svc(tmp, fake, **src) -> ContextService:
    cfg = config.parse(raw_cfg(tmp, fake, **src))
    return ContextService(cfg, env={"CTX_TOKEN": TOKEN}, store_factory=store_factory())


def ids(s: ContextService) -> set[str]:
    with s._lock:
        return set(s._ids)


def test_ids_have_the_kind_source_docid_slug_shape_and_cover_every_page(tmp_path, fake):
    s = svc(tmp_path, fake)
    rep = s.reindex()
    assert rep["ok"], rep
    assert ids(s) == {
        "tax:taxlib/1-form-1040-instructions",
        "tax:taxlib/2-rental-depreciation",
        "tax:taxlib/3-estimated-payments",
    }
    assert rep["sources"]["taxlib"] == {"type": "documents", "documents": 3, "skipped": 0}
    # page_size 2 over 3 documents: two pages, the tag filter sent, the lab's fields only
    assert [r["q"]["page"] for r in fake.requests] == ["1", "2"]
    assert all(r["q"]["tags__name__iexact"] == "tax-library" for r in fake.requests)
    assert all(r["path"] == "/api/documents/" and r["host"] == HOST for r in fake.requests)
    hit = s.get("tax:taxlib/2-rental-depreciation", frozenset({"tax:"}), tlp.Label.AMBER)[0]
    assert hit.title == "Rental depreciation" and "created: 2024-03-05" in hit.content
    assert hit.kind == "tax" and "27.5" in hit.content


def test_a_query_scoped_to_the_kind_prefix_finds_the_document(tmp_path, fake):
    s = svc(tmp_path, fake)
    assert s.reindex()["ok"]
    hits, labels = s.query(
        Query(allowed=frozenset({"tax:"}), text="rental property depreciation"), tlp.Label.AMBER
    )
    assert hits and hits[0].id == "tax:taxlib/2-rental-depreciation"
    assert labels[0] == tlp.Label.AMBER
    # the yardi namespace is not reachable with a tax: scope, and a tlp above the ceiling is absent
    assert (
        s.query(Query(allowed=frozenset({"yardi:"}), text="depreciation"), tlp.Label.AMBER)[0] == []
    )
    assert (
        s.query(Query(allowed=frozenset({"tax:"}), text="depreciation"), tlp.Label.GREEN)[0] == []
    )


def test_a_second_reindex_embeds_nothing_unchanged_and_follows_edits_and_deletions(tmp_path, fake):
    s = svc(tmp_path, fake)
    assert s.reindex()["ok"]
    again = s.reindex()
    assert (again["added"], again["replaced"], again["unchanged"], again["removed"]) == (0, 0, 3, 0)
    # doc 3 edited, doc 1 deleted (or untagged: the store no longer lists it), doc 4 added
    rows = fake.docs["tax-library"]
    rows[2] = doc(3, "Estimated payments", "Quarterly payments are due in April, June, September.")
    del rows[0]
    rows.append(doc(4, "Home office", "The home office deduction needs exclusive use."))
    third = s.reindex()
    assert third["ok"], third
    assert (third["added"], third["replaced"], third["unchanged"], third["removed"]) == (1, 1, 1, 1)
    assert "tax:taxlib/1-form-1040-instructions" not in ids(s)
    assert "tax:taxlib/4-home-office" in ids(s)


def test_a_retitled_document_moves_to_its_new_slug_and_the_old_id_is_gone(tmp_path, fake):
    s = svc(tmp_path, fake)
    assert s.reindex()["ok"]
    fake.docs["tax-library"][1] = doc(2, "Rental property depreciation", "Residential rental ...")
    assert s.reindex()["ok"]
    assert "tax:taxlib/2-rental-property-depreciation" in ids(s)
    assert "tax:taxlib/2-rental-depreciation" not in ids(s)


def test_several_tags_are_one_union_without_duplicates(tmp_path, fake):
    fake.docs["yardi"].append(fake.docs["tax-library"][0])  # tagged with both
    s = svc(tmp_path, fake, tags=["tax-library", "yardi"], kind="tax")
    assert s.reindex()["ok"]
    assert len(ids(s)) == 4  # 3 + 1 distinct, the shared one once


def test_a_tag_with_no_documents_fails_the_reindex_and_keeps_the_index(tmp_path, fake):
    s = svc(tmp_path, fake)
    assert s.reindex()["ok"]
    fake.docs["tax-library"] = []  # a wrong tag name looks the same: it must not empty the index
    rep = s.reindex()
    assert rep["ok"] is False and "no document carries its tags" in rep["error"]
    assert len(ids(s)) == 3


def test_oversized_empty_and_label_raising_documents(tmp_path, fake):
    fake.docs["tax-library"] = [
        doc(1, "Big", "x" * 5000),
        doc(2, "Empty", "   "),
        doc(3, "Marked", "Client names and SSNs. TLP:RED"),
        doc(4, "Fine", "Ordinary text."),
    ]
    s = svc(tmp_path, fake, max_doc_bytes=1000)
    rep = s.reindex()
    assert rep["ok"] and rep["sources"]["taxlib"]["skipped"] == 2
    assert ids(s) == {"tax:taxlib/3-marked", "tax:taxlib/4-fine"}
    with s._lock:
        assert s._store.tlp("tax:taxlib/3-marked") == tlp.Label.RED  # a marker only raises
        assert s._store.tlp("tax:taxlib/4-fine") == tlp.Label.AMBER


def test_the_token_is_sent_as_a_token_header_and_never_appears_in_a_report_or_error(tmp_path, fake):
    s = svc(tmp_path, fake)
    rep = s.reindex()
    assert fake.requests[0]["auth"] == f"Token {TOKEN}"
    assert (
        TOKEN not in json.dumps(rep)
        and TOKEN not in (tmp_path / "data/state/last-reindex.json").read_text()
    )
    # a refused token: the error names the status, never the token
    bad = ContextService(
        config.parse(raw_cfg(tmp_path, fake)),
        env={"CTX_TOKEN": "w" * 40},
        store_factory=store_factory(),
    )
    r = bad.reindex()
    assert r["ok"] is False and "401" in r["error"] and "w" * 40 not in json.dumps(r)
    # an unset credential is refused before any request
    n = len(fake.requests)
    unset = ContextService(
        config.parse(raw_cfg(tmp_path, fake)), env={}, store_factory=store_factory()
    )
    assert "credential is not set" in unset.reindex()["error"] and len(fake.requests) == n


def test_the_bearer_scheme_and_an_explicit_host_header(tmp_path, fake):
    # the fake accepts the Token scheme only: Bearer is refused (401)
    assert "401" in svc(tmp_path, fake, credential_scheme="bearer").reindex()["error"]
    # no explicit host: the URL's own host (a bare address) is not one the store knows: 400
    assert "400" in svc(tmp_path, fake, host_header="").reindex()["error"]


def test_a_redirect_is_never_followed_so_the_token_cannot_travel(tmp_path, fake):
    fake.redirect = True
    s = svc(tmp_path, fake)
    rep = s.reindex()
    assert rep["ok"] is False and "302" in rep["error"]
    assert len(fake.requests) == 1  # nothing asked of the redirect's target


def test_a_store_that_does_not_answer_fails_without_leaking(tmp_path, fake):
    s = svc(tmp_path, fake, url=f"http://{LOOP}:1", timeout=1.0)  # nothing listens on port 1
    rep = s.reindex()
    assert rep["ok"] is False and "did not answer" in rep["error"] and TOKEN not in json.dumps(rep)


def test_a_documents_source_has_no_copy_on_disk_to_fall_back_to(tmp_path, fake):
    rep = svc(tmp_path, fake).reindex(fetch=False)
    assert rep["ok"] is False and "no copy on disk" in rep["error"]


def test_slug():
    assert slug("Form 1040 / Instructions (2023)!") == "form-1040-instructions-2023"
    assert slug("   ") == "untitled" and slug("ÄÖ") == "untitled"
    assert len(slug("a" * 200)) == 60 and not slug("a" * 59 + " b").endswith("-")


@pytest.mark.parametrize(
    "patch,why",
    [
        ({"tags": []}, "tags"),
        ({"tags": "tax"}, "tags"),
        ({"credential_env": ""}, "credential_env is required"),
        ({"credential_scheme": "basic"}, "bearer or token"),
        ({"url": "http://docs.example.internal"}, None),  # fine only with allow_plain_http: set
        ({"ref": "main"}, "unknown key"),
        ({"paths": ["*.md"]}, "unknown key"),
        ({"host_header": "bad host"}, "host_header"),
        ({"ca_file": "../etc/ca.pem"}, "ca_file"),
        ({"page_size": 0}, "page_size"),
        ({"type": "ftp"}, "type must be"),
        ({"tlp": "blue"}, "TLP"),
    ],
)
def test_the_source_is_validated(tmp_path, fake, patch, why):
    raw = raw_cfg(tmp_path, fake, **patch)
    if why is None:
        config.parse(raw)
        return
    with pytest.raises(config.ConfigError, match=why):
        config.parse(raw)


def test_the_token_scheme_belongs_to_documents_sources_only(tmp_path, fake):
    raw = raw_cfg(tmp_path, fake)
    raw["sources"] = [
        {
            "name": "adr",
            "url": "https://git.example.internal/r.git",
            "ref": "main",
            "kind": "doc",
            "tlp": "clear",
            "paths": ["a/*.md"],
            "credential_scheme": "token",
        }
    ]
    raw["health"] = {"text": "x", "expect": "doc:adr/a.md", "ceiling": "clear"}
    with pytest.raises(config.ConfigError, match="documents source"):
        config.parse(raw)
