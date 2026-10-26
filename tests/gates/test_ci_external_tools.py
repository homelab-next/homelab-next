# SPDX-License-Identifier: Apache-2.0
"""CI's external-tools job: the linters it installs are built with the workflow's one Go version,
pinned by module sum, and checked against the build info of the binary that was installed."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
JOB = CI["jobs"]["external-tools"]


def _install() -> str:
    (step,) = [s for s in JOB["steps"] if s.get("name", "").startswith("install actionlint")]
    return step["run"]


def test_the_job_uses_the_workflows_go_version():
    (go,) = [s for s in JOB["steps"] if s.get("uses", "").startswith("actions/setup-go@")]
    assert go["with"]["go-version"] == "${{ env.GO_VERSION }}"
    assert "TOOLS_GO_VERSION" not in JOB.get("env", {})
    assert JOB["env"]["GOTOOLCHAIN"] == "local"


def test_each_go_tool_is_pinned_then_checked_against_its_build_info():
    run = _install()
    for binary, module, version, digest in (
        ("actionlint", "github.com/rhysd/actionlint", "ACTIONLINT_VERSION", "ACTIONLINT_SUM_SHA256"),
        ("nats-server", "github.com/nats-io/nats-server/v2", "NATS_SERVER_VERSION", "NATS_SERVER_SUM_SHA256"),
    ):  # fmt: skip
        pin = f'pinned {module} "${version}" "${digest}"'
        built = f'built_from "$bin/{binary}" {module} "${version}" "${digest}"'
        assert pin in run and built in run, binary
        install = next(line for line in run.splitlines() if "go install" in line and binary in line)
        assert run.index(pin) < run.index(install) < run.index(built), binary
    assert 'go version -m "$1"' in run and "grep -qxF" in run


def test_the_tests_require_the_installed_tools():
    (step,) = [s for s in JOB["steps"] if "HNX_REQUIRE_TOOLS" in (s.get("env") or {})]
    assert set(step["env"]["HNX_REQUIRE_TOOLS"].split(",")) == {
        "actionlint", "zizmor", "nats-server", "docker",
    }  # fmt: skip
