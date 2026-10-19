# SPDX-License-Identifier: Apache-2.0
"""The S3 (Garage) object-store adapter against a loopback, signature-checking fake."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fake_s3 import FakeS3

from conformance.protocols.object_store import NoSuchBucket, NoSuchKey, ObjectStoreError
from homelabnext.conform.adapters import s3 as s3mod
from homelabnext.conform.adapters.s3 import S3ObjectStore, make_object_store
from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_suite
from homelabnext.conform.target import load_target

ACCESS = "GKfade0000000000000000face"
SECRET = "fake-secret-" + "fade" * 13
REGION = "garage"
CLOCK = datetime(2026, 3, 1, 8, 0, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
DOC_URL = "http://192.0.2.7:3900"  # no-raw-endpoint: allow RFC 5737 documentation address


def _store(server, secret=SECRET, prefix="t-"):
    return S3ObjectStore(
        server.url,
        credentials=lambda: (ACCESS, secret),
        region=REGION,
        bucket_prefix=prefix,
        clock=lambda: CLOCK,
    )


@pytest.fixture
def server():
    with FakeS3(ACCESS, SECRET, REGION) as s:
        yield s


def test_the_object_store_suite_passes_through_the_adapter(server):
    suite = load_suite("object-store", ROOT)
    res = run_checks(suite, lambda: _store(server))
    bad = [(r.check, r.evidence) for r in res if r.status != "pass"]
    assert not bad, bad
    assert len(res) == len(suite.specs)


def test_the_suite_fails_when_the_server_breaks_pagination(server):
    """Fail-before evidence: the same suite catches a server that ignores the token."""

    def tamper(h, srv):
        if "continuation-token" in h.path:
            h.path = h.path.split("&continuation-token")[0]
            srv._list(h, srv.buckets[h.path[1:].split("?")[0]], {"max-keys": "4", "prefix": "p/"})
            return True
        return None

    server.tamper = tamper
    res = run_checks(load_suite("object-store", ROOT), lambda: _store(server))
    failed = {r.check for r in res if not r.ok}
    assert "list-pagination-complete" in failed


def test_dot_segments_are_encoded_and_stored_verbatim(server):
    st = _store(server)
    st.create_bucket("dots")
    st.put("dots", "../x", b"1")
    st.put("dots", "a/./b", b"2")
    paths = [p for m, p in server.requests if m == "PUT"]
    assert "/t-dots/%2E%2E/x" in paths and "/t-dots/a/%2E/b" in paths
    assert set(server.buckets["t-dots"]) == {"../x", "a/./b"}


def test_a_wrong_secret_is_refused_and_never_echoed(server):
    st = _store(server, secret="fake-wrong-secret")
    with pytest.raises(ObjectStoreError) as e:
        st.create_bucket("b1")
    assert "SignatureDoesNotMatch" in str(e.value)
    assert "fake-wrong-secret" not in str(e.value) and "fake-wrong-secret" not in repr(st)


def test_create_bucket_without_permission_names_the_s3_code():
    with (
        FakeS3(ACCESS, SECRET, REGION, allow_create=False) as s,
        pytest.raises(ObjectStoreError, match="AccessDenied"),
    ):
        _store(s).create_bucket("b2")


def test_head_distinguishes_missing_bucket_from_missing_key(server):
    st = _store(server)
    with pytest.raises(NoSuchBucket):
        st.head("ghost", "k")
    st.create_bucket("hb")
    with pytest.raises(NoSuchKey):
        st.head("hb", "k")
    with pytest.raises(NoSuchBucket):
        st.delete("ghost", "k")


def test_truncated_list_without_a_token_is_an_error():
    body = b'<ListBucketResult xmlns="x"><IsTruncated>true</IsTruncated></ListBucketResult>'
    with pytest.raises(ObjectStoreError, match="continuation"):
        s3mod._parse_list(body)
    with pytest.raises(ObjectStoreError, match="not XML"):
        s3mod._parse_list(b"<<")


def test_bad_names_metadata_and_urls_are_refused_before_any_request(server):
    st = _store(server)
    for bad in ("UPPER", "x-", "under_score", "x" * 70):
        with pytest.raises(ValueError):
            st.create_bucket(bad)
    with pytest.raises(ValueError):
        st.put("ok-bucket", "", b"")
    with pytest.raises(ValueError):
        st.put("ok-bucket", "k", b"", metadata={"owner": "line\nbreak"})
    with pytest.raises(ValueError):
        st.list("ok-bucket", limit=0)
    assert server.requests == []
    with pytest.raises(ValueError, match="plaintext"):
        S3ObjectStore(DOC_URL, credentials=lambda: ("a", "b"), region="r")
    with pytest.raises(ValueError):
        S3ObjectStore("ftp://h", credentials=lambda: ("a", "b"), region="r")


def test_transport_errors_are_object_store_errors(server):
    url = server.url
    server.__exit__()
    st = S3ObjectStore(url, credentials=lambda: (ACCESS, SECRET), region=REGION, timeout=1)
    with pytest.raises(ObjectStoreError, match="transport"):
        st.get("abc", "k")


def test_factory_reads_endpoint_and_credentials_from_the_environment(server, monkeypatch):
    monkeypatch.setenv("HNX_ENDPOINT_OBJECT_STORE", server.url)
    monkeypatch.setenv("LAB_S3_ACCESS_KEY", ACCESS)
    monkeypatch.setenv("LAB_S3_SECRET_KEY", SECRET)
    monkeypatch.setenv("LAB_S3_REGION", REGION)
    st = make_object_store(domain="example.internal")
    st.create_bucket("envb")
    assert any(name.startswith("hnx-") and name.endswith("-envb") for name in server.buckets)
    assert SECRET not in json.dumps(vars(st), default=str)
    monkeypatch.delenv("LAB_S3_SECRET_KEY")
    with pytest.raises(LookupError, match="LAB_S3_SECRET_KEY"):
        make_object_store(domain="example.internal")
    with pytest.raises(LookupError, match="no default"):
        make_object_store()


def test_the_lab_target_file_names_this_adapter():
    t = load_target(str(ROOT / "compose" / "lab-in-a-box" / "targets" / "object-store.yml"))
    b = t.binding("object-store")
    assert b.adapter == "homelabnext.conform.adapters.s3:make_object_store"
    assert "metadata" in b.features
