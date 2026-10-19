# SPDX-License-Identifier: Apache-2.0
"""Pytest plugin: a test that reaches past loopback fails unless it is marked ``live``.

Loaded for the whole suite by the root ``conftest.py``.  The fakes run real servers on the
loopback interface, so loopback (IPv4 and IPv6), ``localhost`` and Unix sockets stay allowed.  Anything
else -- a ``connect``/``connect_ex``/``sendto`` to a routable address, or a DNS lookup of a name
that is not ``localhost`` -- raises :class:`NetworkAccessBlocked` and is recorded, and the test
then fails at teardown even if the code under test swallowed the exception (a client that treats
"connection failed" as "target down" would otherwise pass quietly).

``@pytest.mark.live`` lifts the guard for that test; CI runs ``-m "not live"``.  The guard is a
process-level patch of :mod:`socket`, so it does not see subprocesses (``ansible``, ``dnsmasq``)
or C extensions that open their own sockets.
"""

from __future__ import annotations

import ipaddress
import socket
import threading

import pytest

LIVE_MARKER = "live"
_LOCAL_NAMES = {"", "localhost", "ip6-localhost", "ip6-loopback"}

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_sendto = socket.socket.sendto
_real_getaddrinfo = socket.getaddrinfo

_lock = threading.Lock()
_allowed = False  # True while a ``live`` test runs; process-wide so server threads see it
_violations: list[str] = []


class NetworkAccessBlocked(RuntimeError):
    """A non-loopback network operation from a test not marked ``live``."""


def is_local_host(host: object) -> bool:
    """True for loopback/unspecified addresses and the ``localhost`` names."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    name = host.strip("[]").split("%", 1)[0].lower()
    if name in _LOCAL_NAMES or name.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_loopback or ip.is_unspecified


def is_local_address(family: int, address: object) -> bool:
    """True when ``address`` (as passed to ``connect``) stays on this host."""
    if family == getattr(socket, "AF_UNIX", object()) or isinstance(address, (str, bytes)):
        return True
    if family not in (socket.AF_INET, socket.AF_INET6):
        return True  # netlink and friends never leave the host
    if not isinstance(address, tuple) or not address:
        return False
    return is_local_host(address[0])


def _is_numeric(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    try:
        ipaddress.ip_address(str(host).strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return True


def _block(what: str) -> None:
    msg = (
        f"{what}: tests must not use the network beyond loopback "
        f"(mark the test @pytest.mark.live if it needs a real system)"
    )
    with _lock:
        _violations.append(msg)
    raise NetworkAccessBlocked(msg)


def _guarded_connect(self, address):
    if not _allowed and not is_local_address(self.family, address):
        _block(f"connect to {address!r}")
    return _real_connect(self, address)


def _guarded_connect_ex(self, address):
    if not _allowed and not is_local_address(self.family, address):
        _block(f"connect_ex to {address!r}")
    return _real_connect_ex(self, address)


def _guarded_sendto(self, data, *args):
    address = args[-1] if args else None
    if not _allowed and address is not None and not is_local_address(self.family, address):
        _block(f"sendto {address!r}")
    return _real_sendto(self, data, *args)


def _guarded_getaddrinfo(host, *args, **kwargs):
    if not _allowed and host is not None and not is_local_host(host) and not _is_numeric(host):
        _block(f"DNS lookup of {host!r}")
    return _real_getaddrinfo(host, *args, **kwargs)


def drain_violations() -> list[str]:
    """The blocked operations recorded since the last drain, oldest first, without repeats."""
    with _lock:
        seen = list(dict.fromkeys(_violations))
        _violations.clear()
    return seen


def install() -> None:
    socket.socket.connect = _guarded_connect
    socket.socket.connect_ex = _guarded_connect_ex
    socket.socket.sendto = _guarded_sendto
    socket.getaddrinfo = _guarded_getaddrinfo


def uninstall() -> None:
    socket.socket.connect = _real_connect
    socket.socket.connect_ex = _real_connect_ex
    socket.socket.sendto = _real_sendto
    socket.getaddrinfo = _real_getaddrinfo


def pytest_configure(config):
    install()


def pytest_unconfigure(config):
    uninstall()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item, nextitem):
    global _allowed
    _allowed = item.get_closest_marker(LIVE_MARKER) is not None
    drain_violations()
    try:
        return (yield)
    finally:
        _allowed = False


@pytest.fixture(autouse=True)
def _no_network_beyond_loopback():
    """Fail the test at teardown when it attempted (and perhaps swallowed) a blocked operation."""
    yield
    seen = drain_violations()
    if seen:
        pytest.fail("network access in a test not marked live:\n  " + "\n  ".join(seen))
