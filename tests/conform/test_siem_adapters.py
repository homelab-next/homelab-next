# SPDX-License-Identifier: Apache-2.0
"""The provisional ``siem-source`` and ``hot-index`` probes (homelabnext.conform.adapters.siem):
they take their endpoint from the registry resolver's override (no default), ask one read-only
question each, and never turn TLS verification off."""

from __future__ import annotations

import socket
import subprocess

import pytest

from homelabnext.conform.adapters import siem
from homelabnext.conform.adapters._env import AdapterConfigError


@pytest.fixture
def ca_file(tmp_path):
    path = tmp_path / "ca.pem"
    subprocess.run(  # a throwaway self-signed certificate: the probe only needs a loadable CA file
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=test-ca", "-days", "1",
         "-keyout", str(tmp_path / "k.pem"), "-out", str(path)],
        check=True, capture_output=True,
    )  # fmt: skip
    return str(path)


def test_the_event_port_probe_reads_a_listening_port_and_a_closed_one(monkeypatch):
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        monkeypatch.setenv("HNX_ENDPOINT_SIEM_SOURCE", f"tcp://127.0.0.1:{port}")
        probe = siem.make_siem_source()
        assert probe.health() is True
    assert probe.health() is False  # the listener is gone
    probe.close()


def test_there_is_no_default_endpoint(monkeypatch, ca_file):
    monkeypatch.delenv("HNX_ENDPOINT_SIEM_SOURCE", raising=False)
    monkeypatch.delenv("HNX_ENDPOINT_HOT_INDEX", raising=False)
    with pytest.raises(AdapterConfigError):
        siem.make_siem_source()
    with pytest.raises(ValueError, match="ca_file"):
        siem.make_hot_index({})
    with pytest.raises(AdapterConfigError):
        siem.make_hot_index({"ca_file": ca_file})


def test_the_index_probe_is_https_only_and_unreachable_is_not_healthy(monkeypatch, ca_file):
    with pytest.raises(ValueError, match="https"):
        siem.HotIndexProbe("http://127.0.0.1:9", ca_file)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    monkeypatch.setenv("HNX_ENDPOINT_HOT_INDEX", f"https://127.0.0.1:{dead}")
    probe = siem.make_hot_index({"ca_file": ca_file, "timeout": 2})
    assert probe.health() is False
    probe.close()
