# SPDX-License-Identifier: Apache-2.0
"""The census of lake tables (docs/modules.md, "Lake tables, from the catalog"): ``hnx modules
catalog-tables`` lists the tables the Iceberg REST catalog on its own host holds, with GET requests
only, to a loopback address, the token read on the host from a file its user's alone and never
printed; only names leave the host."""

from __future__ import annotations

import itertools
import json
import os
import threading
import types
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from homelabnext.modules import census
from homelabnext.modules import cli as mcli

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback only
TOKEN = "census-catalog-token-0003"
#: the catalog's namespaces and their tables: one namespace and one table of no inventory shape
#: (left out and counted), one namespace nested in another (left out and counted, never listed),
#: and the lab's own namespace; four at the top, so the second page holds ``a``
CATALOG = {
    ("ocsf",): ["authentication", "dns_activity", "Mixed"],
    ("lab_own",): ["x"],
    ("Upper",): ["t"],
    ("a",): ["t"],
    ("a", "b"): ["t"],
}


@pytest.fixture(autouse=True)
def _token_dir(tmp_path, monkeypatch):
    # the token's directory, for the tests (on a host it is /etc/homelabnext)
    monkeypatch.setattr(census, "TOKEN_DIR", str(tmp_path))


class FakeCatalog:
    """An Iceberg REST catalog on loopback that pages its listings two at a time, wants
    ``Bearer TOKEN`` (when ``token`` is set; ``echo``: its refusal repeats the credential it
    got) and records every request's method and path; the tables of a namespace in ``gone`` are
    a 404 (dropped after it was listed)."""

    def __init__(
        self,
        token: str | None = TOKEN,
        redirect: str | None = None,
        *,
        catalog: dict = CATALOG,
        echo: bool = False,
        gone: frozenset = frozenset(),
    ):
        self.token, self.redirect = token, redirect
        self.catalog, self.echo, self.gone = catalog, echo, gone
        self.seen: list[tuple[str, str, str | None]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer._get(self)

            def do_POST(self):
                outer.seen.append(("POST", self.path, None))
                self.send_response(405)
                self.end_headers()

        self._srv = ThreadingHTTPServer((LOOPBACK, 0), H)
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()

    def _json(self, h, status, doc):
        body = json.dumps(doc).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)

    def _page(self, items, q, key):
        start = int(q.get("pageToken", "0"))
        doc = {key: items[start : start + 2]}
        if start + 2 < len(items):
            doc["next-page-token"] = str(start + 2)
        return doc

    def _get(self, h):
        auth = h.headers.get("Authorization")
        self.seen.append(("GET", h.path, auth))
        if self.redirect is not None:
            h.send_response(302)
            h.send_header("Location", self.redirect)
            h.end_headers()
            return
        if self.token is not None and auth != f"Bearer {self.token}":
            said = f"credential {auth} refused" if self.echo else "no"
            return self._json(h, 401, {"error": {"type": "NotAuthorized", "message": said}})
        u = urllib.parse.urlsplit(h.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        parts = [urllib.parse.unquote(p) for p in u.path.split("/")[3:]]
        if parts == ["config"] and q.get("warehouse") == "lab":
            return self._json(h, 200, {"defaults": {}, "overrides": {"prefix": "wh"}})
        if parts == ["wh", "namespaces"]:
            parent = tuple(q["parent"].split("\x1f")) if "parent" in q else ()
            names = [
                list(n)
                for n in self.catalog
                if len(n) == len(parent) + 1 and n[: len(parent)] == parent
            ]
            return self._json(h, 200, self._page(names, q, "namespaces"))
        if len(parts) == 4 and parts[:2] == ["wh", "namespaces"] and parts[3] == "tables":
            ns = tuple(parts[2].split("\x1f"))
            if ns not in self.catalog or ns in self.gone:
                return self._json(h, 404, {"error": {"type": "NoSuchNamespace", "message": "no"}})
            ids = [{"namespace": list(ns), "name": t} for t in self.catalog[ns]]
            return self._json(h, 200, self._page(ids, q, "identifiers"))
        return self._json(h, 404, {"error": {"type": "NoSuchNamespace", "message": "no"}})


def _token(tmp_path, text=TOKEN + "\n"):
    path = tmp_path / "catalog.token"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with open(fd, "w") as fh:
        fh.write(text)
    return path


def test_the_listing_is_names_only_by_get_with_the_token_sent_to_the_catalog_alone(tmp_path):
    with FakeCatalog() as cat:
        found = census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))
    assert found == {
        # a.t is on the second page of namespaces: the page tokens were followed
        "tables": ["a.t", "lab_own.x", "ocsf.authentication", "ocsf.dns_activity"],
        # ocsf.Mixed, the namespace Upper and a.b nested in a: never asked for tables
        "left_out": 3,
    }
    assert {m for m, _, _ in cat.seen} == {"GET"}
    assert {a for _, _, a in cat.seen} == {f"Bearer {TOKEN}"}
    # the namespaces of no inventory shape are never asked for their tables, nor a nested one
    # for its own children
    assert not any("Upper" in p or "a%1Fb" in p for _, p, _ in cat.seen)
    assert any(p.endswith("/namespaces?pageToken=2") for _, p, _ in cat.seen)
    assert any(p.endswith("/namespaces?parent=a") for _, p, _ in cat.seen)


def test_nested_namespaces_are_counted_page_by_page_never_listed(tmp_path):
    nested = {("lab_own",): ["x"], **{("lab_own", f"n{i}"): ["t"] for i in range(5)}}
    with FakeCatalog(catalog=nested) as cat:
        found = census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))
    assert found == {"tables": ["lab_own.x"], "left_out": 5}
    assert any(p.endswith("/namespaces?parent=lab_own&pageToken=4") for _, p, _ in cat.seen)
    assert not any("n0" in p for _, p, _ in cat.seen)


def test_a_namespace_gone_before_its_tables_are_listed_is_left_out(tmp_path):
    with FakeCatalog(gone=frozenset({("lab_own",)})) as cat:
        found = census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))
    assert found == {
        "tables": ["a.t", "ocsf.authentication", "ocsf.dns_activity"],
        "left_out": 4,
    }


def test_the_listing_stops_at_its_deadline(tmp_path):
    clock = itertools.count(0, 50).__next__  # fifty seconds pass at every look
    with FakeCatalog() as cat, pytest.raises(census.CensusError, match="past its deadline"):
        census.catalog_tables(
            cat.url, "lab", token_file=_token(tmp_path), deadline=120.0, clock=clock
        )
    # the deadline is the listing's, not one request's: two were sent before it ran out
    assert len(cat.seen) == 2


def test_the_proxy_the_environment_names_is_never_used(tmp_path, monkeypatch):
    with FakeCatalog() as proxy, FakeCatalog() as cat:
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
            monkeypatch.setenv(name, proxy.url)
        for name in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        found = census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))
    assert found["tables"][0] == "a.t"
    assert proxy.seen == []


def test_a_catalog_without_a_token_is_listed_without_one(tmp_path):
    with FakeCatalog(token=None) as cat:
        found = census.catalog_tables(cat.url, "lab")
    assert found["tables"][0] == "a.t"
    assert {a for _, _, a in cat.seen} == {None}


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8181",  # no-raw-endpoint: allow a name, refused: an IP literal only
        "http://192.0.2.8:8181",  # no-raw-endpoint: allow RFC 5737, not loopback
        "http://catalog.example.internal:8181",  # no-raw-endpoint: allow refused, never contacted
        "ftp://127.0.0.1:8181",  # no-raw-endpoint: allow loopback, never contacted
        "https://127.0.0.1:8181",  # no-raw-endpoint: allow loopback, http only (never leaves)
        "http://user@127.0.0.1:8181",  # no-raw-endpoint: allow loopback, never contacted
        "http://[unclosed",  # urlsplit refuses it
        "",
    ],
)
def test_a_catalog_off_loopback_is_refused_before_any_request(tmp_path, url):
    with pytest.raises(census.CensusError, match="not http on a loopback address"):
        census.catalog_tables(url, "lab", token_file=_token(tmp_path))


def test_a_redirect_is_never_followed_with_the_token(tmp_path):
    with FakeCatalog() as other, FakeCatalog(redirect=None) as cat:
        cat.redirect = other.url + "/catalog/v1/config?warehouse=lab"
        with pytest.raises(census.CensusError) as exc:
            census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))
    assert other.seen == []
    assert TOKEN not in str(exc.value)


def test_a_catalog_that_refuses_the_token_fails_and_never_shows_it(tmp_path):
    with (
        FakeCatalog(token="another") as cat,
        pytest.raises(census.CensusError, match="HTTP 401") as exc,
    ):
        census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))
    assert TOKEN not in str(exc.value)


def test_a_refusal_that_echoes_the_token_never_shows_it_nor_the_catalogs_words(tmp_path, capsys):
    path = _token(tmp_path)
    with FakeCatalog(token="another", echo=True) as cat:
        with pytest.raises(census.CensusError) as exc:
            census.catalog_tables(cat.url, "lab", token_file=path)
        argv = ["catalog-tables", "--url", cat.url, "--warehouse", "lab"]
        assert mcli.main([*argv, "--token-file", str(path)]) == 2
    said = str(exc.value)
    assert said == "catalog GET /v1/config: HTTP 401"
    err = capsys.readouterr().err
    assert TOKEN not in err and "refused" not in err and "HTTP 401" in err


def test_an_error_is_reported_without_the_token_control_characters_or_length():
    said = census._plain(f"cannot reach {TOKEN}\x1b[2J\n" + "x" * 500, TOKEN)
    assert said.startswith("cannot reach <token>[2J") and len(said) == census.ERROR_MAX


@pytest.mark.parametrize("where", ["sub/catalog.token", "../catalog.token", "-catalog.token"])
def test_a_token_file_outside_its_directory_is_refused_unread(tmp_path, where):
    (tmp_path / "sub").mkdir()
    _token(tmp_path / "sub")
    url = "http://127.0.0.1:1"  # no-raw-endpoint: allow loopback, never contacted
    with pytest.raises(census.CensusError, match="not a plain name in"):
        census.catalog_tables(url, "lab", token_file=f"{tmp_path}/{where}")


def test_too_many_namespaces_fail_never_cut_short(tmp_path, monkeypatch):
    monkeypatch.setattr(census, "MAX_LINES", 3)
    with FakeCatalog() as cat, pytest.raises(census.CensusError, match="over 3 namespaces"):
        census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))


@pytest.mark.parametrize(
    "catalog, said",
    [
        ({("n",): ["a", "b", "c"]}, "over 2 tables"),  # one namespace's
        ({("m",): ["a", "b"], ("n",): ["c"]}, "lists over 2 tables"),  # the warehouse's
    ],
)
def test_too_many_tables_fail_never_cut_short(tmp_path, monkeypatch, catalog, said):
    monkeypatch.setattr(census, "MAX_LINES", 2)
    with FakeCatalog(catalog=catalog) as cat, pytest.raises(census.CensusError, match=said):
        census.catalog_tables(cat.url, "lab", token_file=_token(tmp_path))


@pytest.mark.parametrize(
    "text",
    ["", "\n", "two words\n", "a\nb\n", "tok\x00en", "é", "t" * 4097],
)
def test_a_token_file_of_another_shape_is_refused(tmp_path, text):
    with pytest.raises(census.CensusError, match="token file") as exc:
        census.read_token(_token(tmp_path, text))
    assert text.strip() == "" or text.strip() not in str(exc.value)


def test_a_token_is_read_never_through_a_link_and_from_a_plain_file(tmp_path):
    path = _token(tmp_path)
    assert census.read_token(path) == TOKEN
    (tmp_path / "link").symlink_to(path)
    with pytest.raises(census.CensusError, match="cannot be opened"):
        census.read_token(tmp_path / "link")
    os.link(path, tmp_path / "second")
    with pytest.raises(census.CensusError, match="a single link"):
        census.read_token(path)
    os.mkfifo(tmp_path / "fifo", 0o600)
    with pytest.raises(census.CensusError, match="not a regular file"):
        census.read_token(tmp_path / "fifo")  # opened without blocking, then refused
    with pytest.raises(census.CensusError, match="cannot be opened"):
        census.read_token(tmp_path / "absent")


@pytest.mark.parametrize(
    "mode, uid, refused",
    [
        (0o100600, None, False),
        (0o100400, None, False),
        (0o100640, None, True),
        (0o100604, None, True),
        (0o100620, None, True),
        (0o100600, -1, True),  # another user's
    ],
)
def test_a_token_file_must_be_its_readers_alone(tmp_path, monkeypatch, mode, uid, refused):
    # the reader's own rule, on reported modes: no real file is made readable by others
    path = _token(tmp_path)
    real = os.fstat
    owner = os.geteuid() if uid is None else os.geteuid() + 1

    def fstat(fd):
        st = real(fd)
        return types.SimpleNamespace(
            st_mode=mode, st_uid=owner, st_nlink=st.st_nlink, st_size=st.st_size
        )

    monkeypatch.setattr(census.os, "fstat", fstat)
    if refused:
        with pytest.raises(census.CensusError, match="not this user's alone"):
            census.read_token(path)
    else:
        assert census.read_token(path) == TOKEN


def test_hnx_modules_catalog_tables_prints_the_listing_as_json(tmp_path, capsys):
    with FakeCatalog() as cat:
        argv = ["catalog-tables", "--url", cat.url, "--warehouse", "lab"]
        assert mcli.main([*argv, "--token-file", str(_token(tmp_path))]) == 0
        out = capsys.readouterr().out
        assert json.loads(out)["left_out"] == 3 and TOKEN not in out
        # a catalog that cannot be listed is exit 2, never an empty listing
        assert mcli.main(argv) == 2
        err = capsys.readouterr().err
        assert "catalog-tables: catalog GET" in err and "HTTP 401" in err
        assert "NotAuthorized" not in err
    off = "http://192.0.2.8:1"  # no-raw-endpoint: allow RFC 5737 documentation address
    assert mcli.main(["catalog-tables", "--url", off, "--warehouse", "lab"]) == 2
