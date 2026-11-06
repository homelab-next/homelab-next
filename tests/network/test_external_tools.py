# SPDX-License-Identifier: Apache-2.0
"""Syntax checks with the real tools: nft and dnsmasq.

Where the tools are missing the tests skip, unless HNX_REQUIRE_TOOLS names ``nft``, ``unshare`` or
``dnsmasq`` (CI's real-tools job does), which makes a missing or unusable tool a failure.

``nft -c`` needs a network namespace; ``unshare -rn`` provides one without privileges.  These
never apply anything: both tools are asked to check only.
"""

from __future__ import annotations

import subprocess

from netutil import render

from homelabnext.network.plan import write_rendered
from tests.suite_policy import require_dnsmasq, require_nft_check


def test_nftables_file_passes_nft_check(ir, tmp_path):
    nft = require_nft_check()
    write_rendered(render("linux", ir), tmp_path / "root")
    f = tmp_path / "root/etc/nftables.d/50-hnx-site.nft"
    r = subprocess.run(["unshare", "-rn", nft, "-c", "-f", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_nft_check_would_catch_a_broken_file(ir, tmp_path):
    nft = require_nft_check()
    broken = render("linux", ir)["etc/nftables.d/50-hnx-site.nft"].replace(
        "accept comment", "acceptt comment"
    )
    f = tmp_path / "broken.nft"
    f.write_text(broken)
    r = subprocess.run(["unshare", "-rn", nft, "-c", "-f", str(f)], capture_output=True, text=True)
    assert r.returncode != 0


def test_dnsmasq_files_pass_dnsmasq_test(ir, tmp_path):
    dnsmasq = require_dnsmasq()
    write_rendered(render("dnsmasq", ir), tmp_path)
    r = subprocess.run(
        [dnsmasq, "--test", "--conf-file=/dev/null", f"--conf-dir={tmp_path}/etc/dnsmasq.d"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
