# SPDX-License-Identifier: Apache-2.0
"""The SigV4 signer against AWS's published test suite.

``fixtures/sigv4/<case>/`` are copied verbatim from the AWS signing test suite (aws-c-auth,
``tests/aws-signing-test-suite/v4``, Apache-2.0).  Each case gives the request, the expected
canonical request, string to sign and signature for the suite's documented example credentials
(``AKIDEXAMPLE``).  All cases used here need no path normalisation, which S3 never does.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

import pytest

from homelabnext.conform.adapters import sigv4

CASES = Path(__file__).parent / "fixtures" / "sigv4"
NAMES = sorted(p.name for p in CASES.iterdir() if p.is_dir())


def _load(name: str):
    d = CASES / name
    ctx = json.loads((d / "context.json").read_text(encoding="utf-8"))
    raw = (d / "request.txt").read_text(encoding="utf-8")
    head, _, body = raw.partition("\n\n")
    first, *lines = head.split("\n")
    method, target, _ = first.split(" ")
    path, _, query = target.partition("?")
    headers = []
    for line in lines:
        if line:
            name, _, value = line.partition(":")
            headers.append((name, value))
    pairs = []
    for part in query.split("&") if query else []:
        k, _, v = part.partition("=")
        pairs.append((unquote(k), unquote(v)))
    when = datetime.fromisoformat(ctx["timestamp"].replace("Z", "+00:00"))
    return ctx, method, path, pairs, headers, body.encode("utf-8"), when, d


def test_every_vector_is_present():
    assert len(NAMES) >= 10, NAMES


@pytest.mark.parametrize("name", NAMES)
def test_aws_signing_test_suite(name):
    ctx, method, path, pairs, headers, body, when, d = _load(name)
    payload = sigv4.hashlib.sha256(body).hexdigest()
    region, service = ctx["region"], ctx["service"]
    added = {"x-amz-date": f"{when:%Y%m%dT%H%M%SZ}"}
    if ctx["sign_body"]:
        added["x-amz-content-sha256"] = payload
    uri = sigv4.uri_encode(path, keep_slash=True)
    canonical = sigv4.canonical_request(method, uri, pairs, headers + list(added.items()), payload)
    assert canonical == (d / "header-canonical-request.txt").read_text(encoding="utf-8")
    sts = sigv4.string_to_sign(when, sigv4.credential_scope(when, region, service), canonical)
    assert sts == (d / "header-string-to-sign.txt").read_text(encoding="utf-8")
    out = sigv4.sign(
        method,
        uri,
        pairs,
        headers,
        payload,
        access_key=ctx["credentials"]["access_key_id"],
        secret_key=ctx["credentials"]["secret_access_key"],
        region=region,
        service=service,
        when=when,
        content_sha256_header=ctx["sign_body"],
    )
    want = (d / "header-signature.txt").read_text(encoding="utf-8").strip()
    assert out["Authorization"].endswith(f"Signature={want}")
    assert out["x-amz-date"] == "20150830T123600Z"


def test_a_wrong_signer_fails_the_vectors():
    """The vectors bite: a signer that forgets to sort the query gets a different signature."""
    _ctx, method, path, pairs, headers, _body, _when, d = _load("get-vanilla-query-order-key-case")
    want = (d / "header-canonical-request.txt").read_text(encoding="utf-8")
    unsorted = sigv4.canonical_request(
        method, path, [], [*headers, ("x-amz-date", "20150830T123600Z")], sigv4.EMPTY_SHA256
    ).replace("\n\n", "\n" + "&".join(f"{k}={v}" for k, v in pairs) + "\n", 1)
    assert unsorted != want


def test_unreserved_characters_are_never_encoded():
    import string

    keep = string.ascii_letters + string.digits + "-._~"
    assert sigv4.uri_encode(keep, keep_slash=False) == keep
    assert sigv4.canonical_query([(keep, keep)]) == f"{keep}={keep}"


def test_uri_encode_rules():
    assert sigv4.uri_encode("a b/c+d~", keep_slash=True) == "a%20b/c%2Bd~"
    assert sigv4.uri_encode("a/b", keep_slash=False) == "a%2Fb"
    assert sigv4.uri_encode("é", keep_slash=False) == "%C3%A9"


def test_sign_requires_host_and_an_aware_clock():
    when = datetime(2026, 1, 1, tzinfo=UTC)
    kw = {
        "access_key": "fake-id",
        "secret_key": "fake-secret",
        "region": "r",
        "service": "s3",
        "when": when,
    }
    with pytest.raises(ValueError, match="host"):
        sigv4.sign("GET", "/", [], {}, sigv4.EMPTY_SHA256, **kw)
    with pytest.raises(ValueError, match="aware"):
        sigv4.sign(
            "GET",
            "/",
            [],
            {"host": "h"},
            sigv4.EMPTY_SHA256,
            **{**kw, "when": datetime(2026, 1, 1)},
        )


def test_the_secret_never_appears_in_the_output():
    out = sigv4.sign(
        "PUT",
        "/b/k",
        [],
        {"host": "h"},
        sigv4.EMPTY_SHA256,
        access_key="fake-id",
        secret_key="fake-secret-value",
        region="r",
        service="s3",
        when=datetime(2026, 1, 1, tzinfo=UTC),
        content_sha256_header=True,
    )
    assert "fake-secret-value" not in json.dumps(out)
    assert out["x-amz-content-sha256"] == sigv4.EMPTY_SHA256
