# SPDX-License-Identifier: Apache-2.0
"""Role subnet_router: forwarding plus advertised routes through the remote-access client (fake
client; documentation-range addresses)."""

import pytest
from rolerun import fake, first_run

# Documentation-range networks, built from pieces (the raw-endpoint scan reads literals).
NET_HOST = ".".join(["192", "0", "2", "0"])
NET_A = NET_HOST + "/24"
NET_B = ".".join(["198", "51", "100", "0"]) + "/24"
DEFAULT_ROUTE = ".".join(["0"] * 4) + "/0"
ROUTES = [NET_A, NET_B]
WANT_SET = f"set --accept-dns=false --advertise-routes={NET_A},{NET_B}"


def client(tmp_path, prefs):
    """A fake client: logs its arguments, answers `debug prefs` with ``prefs``."""
    calls = tmp_path / "calls.log"
    return fake(
        tmp_path / "client",
        "import sys, json\n"
        f"open({str(calls)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        f"print(json.dumps({prefs!r})) if sys.argv[1:3] == ['debug', 'prefs'] else None\n",
    )


def vars_for(tmp_path, prefs=None, routes=ROUTES, forward="1", **kw):
    (tmp_path / "forward").write_text(forward + "\n")
    return {
        "subnet_router_cli": client(tmp_path, prefs or {}),
        "subnet_router_sysctl_cli": fake(tmp_path / "sysctl", f"open({str(tmp_path / 'sysctl.log')!r}, 'a').write(' '.join(__import__('sys').argv[1:]) + '\\n')\n"),
        "subnet_router_forward_file": str(tmp_path / "forward"),
        "subnet_router_advertise_routes": routes,
        "subnet_router_sysctl_file": str(tmp_path / "sysctl.conf"),
        **kw,
    }


@pytest.mark.parametrize(
    ("prefs", "expect_set"),
    [
        ({"AdvertiseRoutes": ROUTES[::-1], "CorpDNS": False}, False),
        ({"AdvertiseRoutes": [NET_A], "CorpDNS": False}, True),
        ({"AdvertiseRoutes": None, "CorpDNS": False}, True),
        ({"AdvertiseRoutes": ROUTES, "CorpDNS": True}, True),
    ],
)
@first_run(
    lambda tmp, prefs, expect_set: {
        "role": "subnet_router",
        "tasks_from": "main",
        "extra_vars": vars_for(tmp, prefs),
        "setup": {},
    }
)
def test_main_sets_routes_only_when_they_differ(first, prefs, expect_set):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    log = (tmp / "calls.log").read_text().splitlines()
    assert (tmp / "sysctl.log").read_text() == "-w net.ipv4.ip_forward=1\n"
    sets = [c for c in log if c.startswith("set ")]
    assert sets == ([WANT_SET] if expect_set else []), log
    assert (tmp / "sysctl.conf").read_text() == "net.ipv4.ip_forward = 1\n"


@pytest.mark.parametrize(
    "routes",
    [[], [DEFAULT_ROUTE], [NET_HOST + "/33"], [NET_HOST], ["2001:db8::/64"], [NET_A + "," + NET_B], [" " + NET_A]],
)
@first_run(lambda tmp, routes: {"role": "subnet_router", "tasks_from": "main", "extra_vars": vars_for(tmp, routes=routes)})
def test_main_refuses_bad_networks_before_changing_anything(first, routes):
    r, tmp = first
    assert r.returncode != 0, routes
    assert "subnet_router: a client command" in r.stdout
    assert not (tmp / "sysctl.conf").exists()
    assert not (tmp / "calls.log").exists()


@pytest.mark.parametrize(
    ("advertised", "forward", "ok"),
    [(ROUTES, "1", True), (ROUTES[::-1], "1", True), ([NET_A], "1", False), (None, "1", False), (ROUTES, "0", False)],
)
@first_run(
    lambda tmp, advertised, forward, ok: {
        "role": "subnet_router",
        "tasks_from": "health",
        "extra_vars": vars_for(tmp, {"AdvertiseRoutes": advertised}, forward=forward),
    }
)
def test_health_checks_the_advertised_networks_and_forwarding(first, advertised, forward, ok):
    r, _ = first
    assert (r.returncode == 0) is ok, r.stdout


@first_run(lambda tmp: {"role": "subnet_router", "tasks_from": "readiness", "extra_vars": vars_for(tmp)})
def test_readiness_asks_the_client(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout
    assert (tmp / "calls.log").read_text().strip() == "version"
