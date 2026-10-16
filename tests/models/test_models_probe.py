# SPDX-License-Identifier: Apache-2.0
"""The /v1/models probe flags a mismatch between the alias and what the backend serves."""

import pytest
from models_support import role_doc

from conformance.fakes.openai_server import FakeOpenAIServer, Fault
from homelabnext.registry.models import ModelClient, ModelError, probe, probe_all


def test_probe_ok(make_resolver):
    res = probe(make_resolver().resolve("main-reasoner"))
    assert res.ok and res.served == ("example-27b",)


def test_probe_flags_mismatch(make_resolver):
    r = make_resolver(role_doc(large_model="example-70b"))  # alias says 70b, backend serves 27b
    res = probe(r.resolve("main-reasoner"))
    assert res.status == "mismatch" and not res.ok
    assert "example-70b" in res.detail and "example-27b" in res.detail


def test_probe_mismatch_can_be_waived_per_role(make_resolver):
    doc = role_doc(large_model="example-70b")
    doc["roles"]["main-reasoner"]["probe"] = {"require_model_served": False}
    assert probe(make_resolver(doc).resolve("main-reasoner")).status == "ok"


def test_probe_unreachable_backend(make_resolver):
    gone = FakeOpenAIServer().start()
    url = gone.url
    gone.stop()
    r = make_resolver(env={"HNX_ENDPOINT_INFERENCE_LARGE": url})
    assert probe(r.resolve("main-reasoner"), timeout=1).status == "unreachable"


def test_probe_http_error_is_error_not_ok(make_resolver, servers):
    servers[0].faults.append(Fault("http_error", path="/v1/models", status=500))
    assert probe(make_resolver().resolve("main-reasoner")).status == "error"


def test_probe_all_reports_every_role(make_resolver):
    got = {p.role: p.status for p in probe_all(make_resolver())}
    assert got == {"embedder": "ok", "fast-classifier": "ok", "main-reasoner": "ok"}


def test_client_errors_are_typed(make_resolver, servers):
    large = servers[0]
    client = ModelClient(make_resolver().resolve("main-reasoner"), timeout=0.3)
    msgs = [{"role": "user", "content": "x"}]
    for fault, kind in [
        (Fault("http_error", status=503, count=1), "http"),
        (Fault("malformed", count=1), "malformed"),
        (Fault("bad_shape", count=1), "malformed"),
        (Fault("hang", hang_s=0.8, count=1), "timeout"),
    ]:
        large.faults[:] = [fault]
        with pytest.raises(ModelError) as ei:
            client.chat(msgs)
        assert ei.value.kind == kind, fault.kind


def test_embedder_role_and_logprobs(make_resolver):
    r = make_resolver()
    vec = ModelClient(r.resolve("embedder")).embed(["alpha", "beta", "alpha"])
    assert len(vec[0]) == 8 and vec[0] == vec[2] and vec[0] != vec[1]
    res = ModelClient(r.resolve("fast-classifier")).chat([{"role": "user", "content": "x"}])
    assert res.mean_prob is not None and 0.94 < res.mean_prob < 0.96
