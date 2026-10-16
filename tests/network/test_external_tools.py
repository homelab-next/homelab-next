# SPDX-License-Identifier: Apache-2.0
"""Optional syntax checks with the real tools when they are installed (skipped otherwise).

``nft -c`` needs a network namespace; ``unshare -rn`` provides one without privileges.  These
never apply anything: both tools are asked to check only.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from netutil import render

from homelabnext.network.plan import write_rendered


def _nft_can_check(tmp_path) -> bool:
    if not (shutil.which("nft") and shutil.which("unshare")):
        return False
    probe = tmp_path / "probe.nft"
    probe.write_text("table inet probe {\n}\n")
    r = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", str(probe)], capture_output=True, text=True
    )
    return r.returncode == 0


def test_nftables_file_passes_nft_check(ir, tmp_path):
    if not _nft_can_check(tmp_path):
        pytest.skip("nft with an unprivileged network namespace is not available")
    write_rendered(render("linux", ir), tmp_path / "root")
    f = tmp_path / "root/etc/nftables.d/50-hnx-site.nft"
    r = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", str(f)], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr


def test_nft_check_would_catch_a_broken_file(ir, tmp_path):
    if not _nft_can_check(tmp_path):
        pytest.skip("nft with an unprivileged network namespace is not available")
    broken = render("linux", ir)["etc/nftables.d/50-hnx-site.nft"].replace(
        "accept comment", "acceptt comment"
    )
    f = tmp_path / "broken.nft"
    f.write_text(broken)
    r = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", str(f)], capture_output=True, text=True
    )
    assert r.returncode != 0


def test_dnsmasq_files_pass_dnsmasq_test(ir, tmp_path):
    if not shutil.which("dnsmasq"):
        pytest.skip("dnsmasq is not installed")
    write_rendered(render("dnsmasq", ir), tmp_path)
    r = subprocess.run(
        ["dnsmasq", "--test", "--conf-file=/dev/null", f"--conf-dir={tmp_path}/etc/dnsmasq.d"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
