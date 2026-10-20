# SPDX-License-Identifier: Apache-2.0
"""The ``hnx_secret`` lookup plugin, called directly (the product roles exercise it end to end)."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("ansible.errors")  # the repo's own ansible/ dir also imports as "ansible"
from ansible.errors import AnsibleLookupError

from homelabnext.registry.model import secret_env_name

PLUGIN = Path(__file__).resolve().parents[2] / "ansible/plugins/lookup/hnx_secret.py"


@pytest.fixture
def mod():
    spec = importlib.util.spec_from_file_location("hnx_secret", PLUGIN)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_env_name_matches_the_registry_rule(mod):
    for ref in ("secret:siem/enrollment-password", "secret:a.b_c/d-token"):
        assert mod.env_name(ref) == secret_env_name(ref)


def test_environment_first_then_the_secrets_dir(mod, tmp_path, monkeypatch):
    (tmp_path / "siem").mkdir()
    (tmp_path / "siem" / "enrollment-password").write_text("from-file-fake\n")
    run = mod.LookupModule().run
    assert run(["secret:siem/enrollment-password"], {"hnx_secrets_dir": str(tmp_path)}) == [
        "from-file-fake"
    ]
    monkeypatch.setenv("HNX_SECRET_SIEM_ENROLLMENT_PASSWORD", "from-env-fake")
    assert run(["secret:siem/enrollment-password"], {"hnx_secrets_dir": str(tmp_path)}) == [
        "from-env-fake"
    ]


@pytest.mark.parametrize(
    ("ref", "message"),
    [
        ("plain-value-fake", "is not a secret reference"),
        ("secret:../etc/passwd", "is not a secret reference"),
        ("secret:a/../../b-token", "is not a secret reference"),
        ("secret:missing/token", "secret:missing/token is not set"),
    ],
)
def test_refusals(mod, tmp_path, ref, message):
    with pytest.raises(AnsibleLookupError, match=message):
        mod.LookupModule().run([ref], {"hnx_secrets_dir": str(tmp_path)})


def test_an_empty_secret_is_not_set(mod, tmp_path):
    (tmp_path / "blank").write_text("\n")
    with pytest.raises(AnsibleLookupError, match="is not set"):
        mod.LookupModule().run(["secret:blank-token"], {"hnx_secrets_dir": str(tmp_path)})
