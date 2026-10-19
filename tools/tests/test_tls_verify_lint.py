# SPDX-License-Identifier: Apache-2.0
"""tools/tls_verify_lint.py (checklist F-07): clients with certificate verification off."""

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tls_verify_lint as lint

REPO = Path(__file__).resolve().parents[2]


def _py(src: str) -> list[str]:
    return [f.rule for f in lint.lint_python(textwrap.dedent(src))]


def _cfg(src: str) -> list[str]:
    return [f.detail for f in lint.lint_config(textwrap.dedent(src))]


@pytest.mark.parametrize(
    ("src", "rule"),
    [
        ("import requests\nrequests.get(u, verify=False)\n", "verify-false"),
        ("import httpx\nhttpx.Client(verify=0)\n", "verify-false"),
        ("import ssl\nctx = ssl._create_unverified_context()\n", "unverified-context"),
        (
            "import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n",
            "unverified-context",
        ),
        ("from ssl import _create_unverified_context as u\nu()\n", "unverified-context"),
        ("import ssl\nctx.verify_mode = ssl.CERT_NONE\n", "cert-none"),
        ("from ssl import CERT_NONE\nwrap(cert_reqs=CERT_NONE)\n", "cert-none"),
        (
            "import ssl\nctx = ssl.create_default_context()\nctx.check_hostname = False\n",
            "no-hostname-check",
        ),
        ("conn = make(check_hostname=False)\n", "no-hostname-check"),
        ("import urllib3\nurllib3.disable_warnings()\n", "warnings-silenced"),
    ],
)
def test_python_disabling_verification_is_flagged(src, rule):
    assert rule in _py(src), src


@pytest.mark.parametrize(
    "src",
    [
        "import requests\nrequests.get(u, verify='/etc/ssl/internal-ca.pem')\n",
        "import requests\nrequests.get(u, verify=True)\n",
        "import ssl\nctx = ssl.create_default_context(cafile=ca)\n",
        "import ssl\nctx.verify_mode = ssl.CERT_REQUIRED\nctx.check_hostname = True\n",
        "run(verify=False)  # tls-verify: allow fake reviewed lab-only probe\n",
        "x = 'verify=False in a string is not a call'\n",
    ],
)
def test_python_verified_or_waived_is_clean(src):
    assert _py(src) == [], src


@pytest.mark.parametrize(
    "src",
    [
        "- uri: {url: x, validate_certs: false}\n",
        "proxmox:\n  verify_ssl: 'no'\n",
        "tls:\n  insecure_skip_verify: true\n",
        "clients:\n  - name: a\n    tls_skip_verify: yes\n",
        '{"http": {"insecure": true}}\n',
        "---\na: 1\n---\nexporter:\n  verify: False\n",
        "x: !vault |\n  fake\nsslVerify: off\n",
    ],
)
def test_config_disabling_verification_is_flagged(src):
    assert _cfg(src), src


@pytest.mark.parametrize(
    "src",
    [
        "validate_certs: true\n",
        "validate_certs: '{{ lab_validate_certs }}'\n",
        "insecure: false\n",
        "tls_verify: /etc/ssl/internal-ca.pem\n",
        "verify_ssl: false  # tls-verify: allow fake reviewed exception\n",
        "description: set validate_certs to false and it fails\n",
    ],
)
def test_config_verified_templated_or_waived_is_clean(src):
    assert _cfg(src) == [], src


def test_tree_fails_then_allowlist_passes(tmp_path, capsys):
    (tmp_path / "roles" / "x" / "defaults").mkdir(parents=True)
    (tmp_path / "roles" / "x" / "defaults" / "main.yml").write_text("x_verify_ssl: false\n")
    (tmp_path / "client.py").write_text("import requests\nrequests.get(u, verify=False)\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_fixture.py").write_text("requests.get(u, verify=False)\n")
    assert lint.main([str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "client.py:2" in err and "verify-false" in err
    allow = tmp_path / "allow.yml"
    allow.write_text(
        "allow:\n  - {path: '*.py', reason: fake}\n  - {path: 'roles/**', reason: fake}\n"
    )
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 0
    allow.write_text("allow:\n  - {path: '*.py'}\n")
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 2


def test_the_repository_verifies_tls_everywhere():
    assert lint.main([str(REPO)]) == 0
