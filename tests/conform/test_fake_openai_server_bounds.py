# SPDX-License-Identifier: Apache-2.0
"""The fake inference server's own guards: it listens on loopback unless told otherwise, and it
refuses a request body it would not read whole (no authentication, so it must stay small)."""

from __future__ import annotations

import http.client

import pytest

from conformance.fakes import openai_server
from conformance.fakes.openai_server import FakeOpenAIServer

# a documentation address (RFC 5737) and a name: neither is loopback
DOC_ADDRESS = "192.0.2.10"  # no-raw-endpoint: allow an RFC 5737 address the fake must refuse
NOT_LOOPBACK = [DOC_ADDRESS, "example.org"]
LOOPBACK = ["127.0.0.1", "::1", "localhost"]  # no-raw-endpoint: allow loopback the guard accepts


@pytest.mark.parametrize("host", NOT_LOOPBACK)
def test_a_host_other_than_loopback_is_refused(host, capsys):
    assert openai_server.main(["--host", host]) == 2
    assert "not loopback" in capsys.readouterr().err


@pytest.mark.parametrize("host", LOOPBACK)
def test_loopback_is_loopback(host):
    assert openai_server._loopback(host)


def _post(srv, headers, body=b""):
    host, port = srv.address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.putrequest("POST", "/v1/chat/completions")
        for k, v in headers.items():
            conn.putheader(k, v)
        conn.endheaders()
        if body:
            conn.send(body)
        return conn.getresponse().status
    finally:
        conn.close()


def test_an_oversized_or_malformed_body_length_is_refused():
    with FakeOpenAIServer() as srv:
        big = str(openai_server.MAX_BODY_BYTES + 1)
        assert _post(srv, {"Content-Length": big}) == 413
        assert _post(srv, {"Content-Length": "-5"}) == 400
        assert _post(srv, {"Content-Length": "lots"}) == 400
        # str.isdigit() accepts a superscript two, which int() then refuses
        assert _post(srv, {"Content-Length": "\u00b2"}) == 400
        ok = b'{"model": "example-model", "messages": [{"role": "user", "content": "hi"}]}'
        assert _post(srv, {"Content-Length": str(len(ok))}, ok) == 200
