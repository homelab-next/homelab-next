# SPDX-License-Identifier: Apache-2.0
"""``hnx guests render --out`` into a directory that already holds an earlier render: a removed
guest's firewall file must not stay behind to apply to the next guest that takes its vmid."""

from __future__ import annotations

import shutil
from pathlib import Path

from homelabnext import cli as hnx

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
SITE = HERE / "site.yml"


def _render(guests: Path, out: Path, *extra: str) -> int:
    args = ["guests", "render", str(guests), "--site", str(SITE), "--target", "firewall-rules"]
    return hnx.main([*args, "--out", str(out), *extra])


def _two_renders(tmp_path: Path) -> tuple[Path, Path, Path]:
    guests, out = tmp_path / "guests", tmp_path / "out"
    shutil.copytree(FLEET, guests)
    assert _render(guests, out) == 0
    gone = out / "firewall" / "140.fw"
    assert gone.is_file()
    (guests / "lake-core.yml").unlink()
    hand = out / "HANDWRITTEN.txt"
    hand.write_text("kept: written by hand\n", encoding="utf-8")
    return guests, out, gone


def test_a_removed_guests_file_is_kept_and_named_without_prune(tmp_path, capsys):
    guests, out, gone = _two_renders(tmp_path)
    assert _render(guests, out) == 0
    assert gone.is_file()
    err = capsys.readouterr().err
    assert "no longer rendered (firewall/140.fw); --prune deletes them" in err


def test_prune_deletes_a_removed_guests_file_and_nothing_hand_written(tmp_path, capsys):
    guests, out, gone = _two_renders(tmp_path)
    capsys.readouterr()
    assert _render(guests, out, "--prune") == 0
    assert not gone.exists()
    assert (out / "HANDWRITTEN.txt").read_text(encoding="utf-8") == "kept: written by hand\n"
    assert "pruned 1 stale files: firewall/140.fw" in capsys.readouterr().out
    # a second run finds nothing left to prune and nothing to warn about
    assert _render(guests, out, "--prune") == 0
    captured = capsys.readouterr()
    assert "pruned" not in captured.out and "warning" not in captured.err
