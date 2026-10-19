# SPDX-License-Identifier: Apache-2.0
"""The suite-wide network guard (``tests/network_guard.py``, loaded by the root conftest)."""

import socket
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from tests import network_guard
from tests.network_guard import NetworkAccessBlocked, is_local_address, is_local_host

ROOT = str(Path(__file__).resolve().parents[2])
TEST_NET = "192.0.2.1"  # RFC 5737 documentation range: never routed


@pytest.mark.parametrize(
    ("host", "local"),
    [
        ("127.0.0.1", True),
        ("127.8.9.10", True),
        ("::1", True),
        ("[::1]", True),
        ("::ffff:127.0.0.1", True),
        ("0.0.0.0", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("app.localhost", True),
        (b"localhost", True),
        (TEST_NET, False),
        ("2001:db8::1", False),
        ("example.invalid", False),
        ("svc.example.internal", False),
        (None, False),
    ],
)
def test_is_local_host(host, local):
    assert is_local_host(host) is local


def test_unix_sockets_are_local():
    assert is_local_address(socket.AF_UNIX, "/run/fake.sock")
    assert not is_local_address(socket.AF_INET, (TEST_NET, 80))


def test_the_guard_is_installed_for_this_suite():
    # socket methods by identity; getaddrinfo may since have been wrapped (ansible patches it on
    # import), so the blocking test below checks it by behaviour
    assert socket.socket.connect is network_guard._guarded_connect
    assert socket.socket.sendto is network_guard._guarded_sendto


def test_routable_connect_and_dns_are_blocked_and_recorded():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with pytest.raises(NetworkAccessBlocked):
            s.connect((TEST_NET, 9))
        with pytest.raises(NetworkAccessBlocked):
            s.connect_ex((TEST_NET, 9))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u, pytest.raises(NetworkAccessBlocked):
        u.sendto(b"x", (TEST_NET, 53))
    with pytest.raises(NetworkAccessBlocked):
        socket.getaddrinfo("example.invalid", 443)
    seen = network_guard.drain_violations()  # drained, so this test itself does not fail
    assert len(seen) == 4 and all("mark the test @pytest.mark.live" in v for v in seen)


def test_loopback_traffic_and_numeric_lookups_are_allowed():
    with socket.create_server(("127.0.0.1", 0)) as srv:
        port = srv.getsockname()[1]
        t = threading.Thread(target=lambda: srv.accept()[0].close())
        t.start()
        with socket.create_connection(("localhost", port), timeout=5):
            pass
        t.join(5)
    assert socket.getaddrinfo(TEST_NET, 80)  # numeric: no lookup leaves the host
    assert network_guard.drain_violations() == []


def test_end_to_end_fails_unmarked_and_passes_live_and_loopback(tmp_path):
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers =\n    live: real systems\n")
    (tmp_path / "test_sample.py").write_text(
        textwrap.dedent(
            f"""
            import socket
            import pytest
            from tests import network_guard

            def test_swallowed_routable_connect():
                try:
                    socket.create_connection(("{TEST_NET}", 9), timeout=1)
                except Exception:
                    pass  # a client that reads failure as "target down"

            def test_loopback_server():
                with socket.create_server(("127.0.0.1", 0)) as srv:
                    socket.create_connection(srv.getsockname(), timeout=1).close()

            @pytest.mark.live
            def test_live_lifts_the_guard():
                assert network_guard._allowed
            """
        )
    )
    argv = ["-p", "tests.network_guard", "-p", "no:cacheprovider", "-q", "-rA"]
    argv += ["-c", str(tmp_path / "pytest.ini"), "--rootdir", str(tmp_path)]
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *argv, str(tmp_path / "test_sample.py")],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={"PYTHONPATH": ROOT, "PATH": "/usr/bin:/bin"},
        check=False,
    )
    out = proc.stdout
    assert proc.returncode == 1, out
    assert "ERROR test_sample.py::test_swallowed_routable_connect" in out, out
    assert "network access in a test not marked live" in out
    assert "PASSED test_sample.py::test_loopback_server" in out
    assert "PASSED test_sample.py::test_live_lifts_the_guard" in out
