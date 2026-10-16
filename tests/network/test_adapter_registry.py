# SPDX-License-Identifier: Apache-2.0
"""The adapter registry rejects what it does not know and never touches a network."""

from __future__ import annotations

import socket

import pytest

from homelabnext.network import adapters
from homelabnext.network.adapters.base import AdapterDeferred, ServerOnly, UnknownAdapter


def test_unknown_adapter_is_rejected_with_the_known_names():
    with pytest.raises(UnknownAdapter) as exc:
        adapters.get("acmerouter")
    assert "acmerouter" in str(exc.value)
    assert exc.value.known == ["dnsmasq", "linux", "opnsense", "unifi", "zonefile"]


@pytest.mark.parametrize("bad", ["", "LINUX", "linux ", "../linux", "unifi;rm"])
def test_near_misses_are_unknown_too(bad):
    with pytest.raises(UnknownAdapter):
        adapters.get(bad)


def test_opnsense_is_registered_but_deferred(ir):
    ad = adapters.get("opnsense")
    assert ad.status == "deferred"
    with pytest.raises(AdapterDeferred, match="deferred"):
        ad.render(ir)


def test_listing_marks_status():
    rows = {n: s for n, s, _ in adapters.listing()}
    assert rows == {
        "dnsmasq": "ready",
        "linux": "ready",
        "opnsense": "deferred",
        "unifi": "ready",
        "zonefile": "ready",
    }


@pytest.mark.parametrize("name", ["linux", "dnsmasq", "zonefile", "unifi", "opnsense"])
def test_apply_is_server_only_for_every_adapter(name, ir):
    with pytest.raises(ServerOnly, match="SERVER-only"):
        adapters.get(name).apply(ir)


def test_rendering_opens_no_sockets(ir, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for name in ("linux", "dnsmasq", "zonefile", "unifi"):
        assert adapters.get(name).render(ir)
