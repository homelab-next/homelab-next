# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from conformance.fakes.openai_server import Fault
from conftest import SUITE, good_rules
from homelabnext.golden import client_completer, load_suite, run_suite

DATA = Path(__file__).parent / "data"


def run(resolver, role="fast-classifier"):
    suite = load_suite(SUITE)
    completer, model_id = client_completer(resolver, role)
    return run_suite(suite, completer, role=role, model_id=model_id)


def test_report_matches_golden_file(build_resolver):
    resolver, *_ = build_resolver(good_rules())
    rep = run(resolver)
    assert rep.ok
    want = json.loads((DATA / "classifier_smoke.report.json").read_text())
    assert rep.to_dict() == want


def test_runner_sends_task_prompts_and_params(build_resolver):
    resolver, small, _ = build_resolver(good_rules())
    run(resolver)
    first = small.requests[0]["body"]
    assert first["model"] == "example-4b" and first["temperature"] == 0
    assert first["messages"][0]["role"] == "system"


def test_alias_swap_changes_score_not_the_runner(build_resolver):
    resolver, *_ = build_resolver(good_rules())
    good = run(resolver)
    # point the same suite at the large backend, which answers nothing useful
    doc = {
        "version": 1,
        "roles": {
            "fast-classifier": {
                "tier": "fast",
                "bindings": [{"backend": "svc:inference-large", "model_id": "example-27b"}],
            }
        },
    }
    from homelabnext.registry.models import RoleTable

    resolver.table = RoleTable.from_dict(doc)
    worse = run(resolver)
    assert good.weighted_score > worse.weighted_score
    assert worse.model_id == "example-27b" and not worse.ok
    assert [r.passed for r in worse.results] == [False, False, True]


def test_backend_failure_is_a_failed_task_not_a_crash(build_resolver):
    resolver, small, _ = build_resolver(good_rules())
    small.faults.append(Fault("http_error", status=503, path="chat", count=2))
    rep = run(resolver)
    assert rep.errors == 2 and rep.passed == 1 and not rep.ok
    assert "http" in rep.results[0].error


def test_text_render_lists_failures(build_resolver):
    resolver, *_ = build_resolver([])
    text = run(resolver).render_text()
    assert text.startswith("golden suite classifier-smoke on mdl:fast-classifier")
    assert "FAIL rollback-present" in text and "PASS greeting-short" in text
