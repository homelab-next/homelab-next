# SPDX-License-Identifier: Apache-2.0
"""CI's gateway-conformance job (ADR-0026 decision 9, ADR-0038 decision 7 as amended) and its
script, tools/gateway_conformance.sh: the job always runs and its last step is the suite run, and
the ports and models the script hard-codes are the conformance spec's, so a change to the spec
that the script does not follow fails here rather than as a confusing red run."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
SCRIPT = (ROOT / "tools" / "gateway_conformance.sh").read_text(encoding="utf-8")
SPEC_DIR = ROOT / "compose" / "lab-in-a-box" / "config" / "llm-gateway-conformance"
SPEC = yaml.safe_load((SPEC_DIR / "gateway.yml").read_text(encoding="utf-8"))
RENDERED = json.loads((SPEC_DIR / "gateway" / "gateway.json").read_text(encoding="utf-8"))


def _assignment(name: str) -> str:
    (value,) = re.findall(rf"^{name}=(\S+)", SCRIPT, re.M)
    return value


def _fake_models() -> list[str]:
    (body,) = re.findall(r"^fake_models=\(([^)]*)\)", SCRIPT, re.M)
    return body.split()


def test_the_job_always_runs_and_ends_with_the_suite():
    job = CI["jobs"]["gateway-conformance"]
    assert "if" not in job and "continue-on-error" not in job
    assert not any("continue-on-error" in step or "if" in step for step in job["steps"])
    on = CI.get("on") or CI[True]  # PyYAML reads the bare key `on` as True
    for event in ("push", "pull_request"):
        assert not {"paths", "paths-ignore"} & set(on[event] or {}), event
    last = job["steps"][-1]["run"]
    assert "tools/gateway_conformance.sh run" in last
    # loopback only, as the runner user under no_new_privs
    assert "unshare --net" in last and "setpriv --no-new-privs --reuid=" in last
    deps = [s for s in job["steps"] if "tools/gateway_conformance.sh deps" in s.get("run", "")]
    assert len(deps) == 1


def test_go_ok_requires_the_job():
    ok = CI["jobs"]["go-ok"]
    assert "gateway-conformance" in ok["needs"] and ok["if"] == "always()"
    (step,) = ok["steps"]
    assert step["env"]["GATEWAY"] == "${{ needs.gateway-conformance.result }}"
    assert '[ "$GATEWAY" = success ]' in step["run"]


def test_the_fake_port_is_the_spec_s():
    port = int(_assignment("fake_port"))
    assert SPEC["backends"]["svc:inference-small"]["port"] == port
    assert urlsplit(SPEC["conformance"]["cloud_base_url"]).port == port


def test_the_fake_serves_exactly_the_backend_ids_on_its_port():
    """Every deployment the render points at the fake's port is a model the fake serves, and
    every other deployment is on a port nothing listens on (the failover's connection error)."""
    port = int(_assignment("fake_port"))
    down = {b["port"] for b in SPEC["backends"].values() if "port" in b} - {port}
    on_fake, elsewhere = set(), set()
    for role in RENDERED["roles"].values():
        for dep in role["deployments"]:
            dep_port = urlsplit(dep["base_url"]).port
            if dep_port == port:
                on_fake.add(dep["model"])
            else:
                elsewhere.add(dep_port)
    assert on_fake == set(_fake_models())
    assert elsewhere <= down


def test_the_gateway_port_is_the_binary_s_default_and_differs_from_the_fake_s():
    main = (ROOT / "orchestrator" / "cmd" / "gateway" / "main.go").read_text(encoding="utf-8")
    (default,) = re.findall(r'"listen", "[^"]*:(\d+)"', main)
    assert _assignment("gw_port") == default != _assignment("fake_port")
