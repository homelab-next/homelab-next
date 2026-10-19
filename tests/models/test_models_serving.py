# SPDX-License-Identifier: Apache-2.0
"""K-14: the health check reads the loaded model id and context length and alerts on mismatch."""

import pytest
from models_support import role_doc

from homelabnext.notify import FakeSender, Notifier
from homelabnext.registry.models import probe, served_context
from homelabnext.registry.serving import KEY_PREFIX, check_serving
from homelabnext.state import StateStore


def ctx_doc(declared=131072):
    doc = role_doc()
    doc["roles"]["main-reasoner"]["max_context_tokens"] = declared
    return doc


@pytest.fixture
def notifier(tmp_path):
    sender = FakeSender()
    return Notifier(sender, StateStore(tmp_path / "notify.json"), clock=lambda: 1000.0), sender


def test_probe_reads_the_loaded_context_length(make_resolver, servers):
    servers[0].context_length = 131072
    res = probe(make_resolver(ctx_doc()).resolve("main-reasoner"))
    assert res.ok and (res.context_length, res.expected_context) == (131072, 131072)


def test_probe_flags_a_context_length_mismatch(make_resolver, servers):
    servers[0].context_length = {"example-27b": 8192}  # loaded with a far smaller window
    res = probe(make_resolver(ctx_doc()).resolve("main-reasoner"))
    assert res.status == "mismatch" and not res.ok
    assert "8192" in res.detail and "131072" in res.detail


def test_probe_cannot_verify_an_unreported_context_length(make_resolver, servers):
    servers[0].context_length = None
    res = probe(make_resolver(ctx_doc()).resolve("main-reasoner"))
    assert res.status == "mismatch" and "does not report" in res.detail


def test_roles_without_a_declared_context_only_check_the_model_id(make_resolver, servers):
    servers[0].context_length = 4096
    res = probe(make_resolver().resolve("main-reasoner"))
    assert res.ok and res.context_length == 4096 and res.expected_context is None


@pytest.mark.parametrize(
    ("entry", "want"),
    [
        ({"id": "m", "max_model_len": 4096}, 4096),
        ({"id": "m", "loaded_context_length": 8192, "max_context_length": 32768}, 8192),
        ({"id": "m", "context_length": 2048}, 2048),
        ({"id": "m", "meta": {"n_ctx": 1024}}, 1024),
        ({"id": "m", "max_model_len": True}, None),
        ({"id": "m", "max_model_len": "4096"}, None),
        ({"id": "m"}, None),
    ],
)
def test_served_context_understands_common_engines(entry, want):
    assert served_context(entry) == want


def test_mismatch_alerts_once_then_recovers_once(make_resolver, servers, notifier):
    n, sender = notifier
    large = servers[0]
    resolver = make_resolver(ctx_doc())
    large.context_length = 8192
    check_serving(resolver, n)
    assert sender.titles == ["Model serving config mismatch"]
    assert sender.sent[0].level == "crit" and "8192" in sender.sent[0].body
    assert sender.sent[0].key == KEY_PREFIX + "main-reasoner"
    check_serving(resolver, n)  # still wrong: state-diffed, no second page
    assert len(sender.sent) == 1
    large.context_length = 131072
    check_serving(resolver, n)
    assert sender.titles[1:] == ["Model serving config matches"]
    check_serving(resolver, n)
    assert len(sender.sent) == 2


def test_wrong_model_and_unreachable_backends_alert_too(make_resolver, servers, notifier):
    n, sender = notifier
    check_serving(make_resolver(role_doc(large_model="example-70b")), n)
    assert sender.titles == ["Model serving config mismatch"]
    gone = servers[1]
    gone.stop()
    check_serving(make_resolver(role_doc(large_model="example-70b")), n, timeout=1)
    assert "Model backend unreachable" in sender.titles
    assert n.state_of(KEY_PREFIX + "fast-classifier") == "unreachable"
