# SPDX-License-Identifier: Apache-2.0
"""tools/allowlist_ratchet.py: each suppression list is held to its reviewed count; growth needs a
raised count in a human-tier code-owned file, a shrink must lower the count."""

import io
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import allowlist_ratchet as ar

REPO = Path(__file__).resolve().parents[2]
GIT = ["git", "-c", "user.email=t@example.org", "-c", "user.name=t"]
# the markers are built here, so this file carries none of its own
SCRUB = "scrub" + "-allow: a reviewed example"
ENDPOINT = "no-raw" + "-endpoint: allow a reviewed example"
OWNED = "*  @owner\n/tools/  @owner\n"


def _tree(tmp_path: Path, *, globs=2, endpoints=1, scripts=1, scrub=1, inline=1, owners=OWNED):
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    allow = "".join(f'  - {{path: "p{i}/*", reason: r}}\n' for i in range(globs))
    (root / "tools/product_names.yml").write_text(
        f"products: []\nallow:\n{allow}" if globs else "products: []\n"
    )
    rows = "".join(f'  - {{path: "e{i}/*", reason: r}}\n' for i in range(endpoints))
    (root / "tools/no_raw_endpoints.allow.yml").write_text(
        f"allow:\n{rows}" if endpoints else "allow: []\n"
    )
    keys = "".join(f"  s{i}: why\n" for i in range(scripts))
    (root / "tools/scripts.allow.yml").write_text(
        f"registers: []\nuncalled:\n{keys}" if scripts else "registers: []\n"
    )
    (root / "src.txt").write_text("".join(f"x = 1  # {SCRUB}\n" for _ in range(scrub)) + "plain\n")
    (root / "other.txt").write_text("".join(f"y = 2  # {ENDPOINT}\n" for _ in range(inline)))
    if owners is not None:
        (root / "CODEOWNERS").write_text(owners)
    return root


def _write_counts(root: Path, **over) -> None:
    counts = ar.measure(root)
    counts.update({k.replace("_", "-"): v for k, v in over.items()})
    ar.write_counts(root / ar.COUNTS, counts)


def _run(*args) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    rc = ar.main([str(a) for a in args], out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


def test_every_list_at_its_count_passes(tmp_path):
    root = _tree(tmp_path, globs=2, endpoints=3, scripts=1, scrub=2, inline=1)
    assert ar.measure(root) == {
        "product-names-allow": 2,
        "no-raw-endpoints-allow": 3,
        "scripts-allow": 1,
        "scrub-allow-markers": 2,
        "no-raw-endpoint-markers": 1,
    }
    _write_counts(root)
    rc, out, _ = _run(root)
    assert rc == 0, out
    assert "0 problem(s)" in out


GROW = {
    "product-names-allow": {"globs": 3},
    "no-raw-endpoints-allow": {"endpoints": 2},
    "scripts-allow": {"scripts": 2},
    "scrub-allow-markers": {"scrub": 2},
    "no-raw-endpoint-markers": {"inline": 2},
}


@pytest.mark.parametrize("name", list(GROW))
def test_a_list_above_its_count_fails_until_the_count_is_raised(tmp_path, name):
    base = _tree(tmp_path / "a")
    _write_counts(base)
    counts = (base / ar.COUNTS).read_text()
    grown = _tree(tmp_path / "b", **GROW[name])
    (grown / ar.COUNTS).write_text(counts)
    was, now = ar.measure(base)[name], ar.measure(grown)[name]
    assert now == was + 1
    rc, out, _ = _run(grown)
    assert rc == 1
    assert f"{name}: {now} entries, the reviewed count is {was}" in out
    assert "raise the count" in out
    _write_counts(grown)  # the reviewed raise, in the same change
    assert _run(grown)[0] == 0


@pytest.mark.parametrize("name", list(GROW))
def test_a_list_below_its_count_fails_with_the_count_to_lower_it_to(tmp_path, name):
    root = _tree(tmp_path)
    have = ar.measure(root)
    _write_counts(root, **{name.replace("-", "_"): have[name] + 4})
    rc, out, _ = _run(root)
    assert rc == 1
    assert (
        f"{name}: {have[name]} entries, the count is {have[name] + 4}: lower it to {have[name]}"
        in out
    )
    rc, out, _ = _run("--update", root)  # lowering needs no --grow
    assert rc == 0 and f"{name} {have[name] + 4} -> {have[name]}" in out
    assert _run(root)[0] == 0


def test_update_refuses_to_raise_a_count_without_grow(tmp_path):
    root = _tree(tmp_path, globs=4)
    _write_counts(root, product_names_allow=2)
    before = (root / ar.COUNTS).read_text()
    rc, _, err = _run("--update", root)
    assert rc == 2
    assert "product-names-allow would rise 2 -> 4" in err
    assert (root / ar.COUNTS).read_text() == before
    assert _run("--update", "--grow", root)[0] == 0
    assert ar.load_counts(root / ar.COUNTS)["product-names-allow"] == 4
    assert _run("--grow", root)[0] == 2  # --grow alone is a usage error


@pytest.mark.parametrize(
    "owners",
    [
        None,  # no CODEOWNERS at all
        "*  @owner\n",  # only the catch-all owns it
        "*  @owner\n/tools/  @owner\n/tools/allowlist_counts.yml\n",  # a later rule unowns it
        "/tools/  @owner\n*  @owner\n",  # the catch-all comes last and wins
    ],
)
def test_the_counts_file_must_be_under_a_human_tier_rule(tmp_path, owners):
    root = _tree(tmp_path, owners=owners)
    _write_counts(root)
    rc, out, _ = _run(root)
    assert rc == 1
    assert "no human-tier CODEOWNERS rule" in out


def test_human_tier_reads_codeowners_like_github():
    assert ar.human_tier(OWNED, ar.COUNTS)
    assert ar.human_tier("/tools/allowlist_counts.yml @owner\n", ar.COUNTS)
    assert not ar.human_tier("/docs/ @owner\n", ar.COUNTS)
    assert not ar.human_tier("/tools/ not-an-owner\n", ar.COUNTS)


def test_endpoint_markers_are_counted_with_the_raw_endpoint_scans_own_read(tmp_path):
    """A NUL between bytes 4096 and 8192: the leak scan reads the file as binary, the raw-endpoint
    scan does not, so the markers in it suppress findings and must be counted."""
    root = _tree(tmp_path, inline=0)
    marked = f"probe = 1  # {ENDPOINT}\n" * 20
    (root / "late_nul.txt").write_bytes(b"a" * 5000 + b"\0\n" + marked.encode())
    assert ar.measure(root)["no-raw-endpoint-markers"] == 20
    _write_counts(root, no_raw_endpoint_markers=0)
    rc, out, _ = _run(root)
    assert rc == 1 and "no-raw-endpoint-markers: 20 entries, the reviewed count is 0" in out


@pytest.mark.parametrize(
    "text",
    [
        "counts: [1]\n",
        "other: {}\n",
        "counts: {product-names-allow: -1}\n",
        "counts: {product-names-allow: yes}\n",
        "counts: {product-names-allow: 1}\n",  # the other lists have no count
        ": [\n",
    ],
)
def test_a_malformed_counts_file_is_an_error(tmp_path, text):
    root = _tree(tmp_path)
    (root / ar.COUNTS).write_text(text)
    assert _run(root)[0] == 2


def test_an_unknown_list_in_the_counts_file_is_an_error(tmp_path):
    root = _tree(tmp_path)
    _write_counts(root)
    with (root / ar.COUNTS).open("a") as fh:
        fh.write("  some-other-list: 3\n")
    rc, _, err = _run(root)
    assert rc == 2 and "some-other-list" in err


def test_a_malformed_allowlist_is_an_error(tmp_path):
    root = _tree(tmp_path)
    _write_counts(root)
    (root / "tools/product_names.yml").write_text("allow: just-a-string\n")
    assert _run(root)[0] == 2


# ----------------------------------------------------------------------------- against the base


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        [*GIT, "-C", str(root), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _repo(tmp_path: Path, owners=OWNED) -> tuple[Path, str]:
    root = _tree(tmp_path, owners=owners)
    _write_counts(root)
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root, _git(root, "rev-parse", "HEAD")


def _grow(root: Path) -> None:
    with (root / "src.txt").open("a") as fh:
        fh.write(f"z = 3  # {SCRUB}\n")
    _write_counts(root)


def test_a_count_raised_against_the_base_is_printed_for_review(tmp_path):
    root, base = _repo(tmp_path)
    _grow(root)
    rc, out, _ = _run("--base", base, root)
    assert rc == 0, out
    assert f"scrub-allow-markers: the count rises 1 -> 2 against {base[:12]}" in out
    assert "code owner" in out


def test_equal_or_lower_counts_against_the_base_say_nothing(tmp_path):
    root, base = _repo(tmp_path)
    rc, out, _ = _run("--base", base, root)
    assert rc == 0 and "rises" not in out
    (root / "src.txt").write_text("plain\n")
    _write_counts(root)
    rc, out, _ = _run("--base", base, root)
    assert rc == 0 and "rises" not in out


def test_a_raise_fails_when_the_bases_codeowners_does_not_own_the_counts_file(tmp_path):
    root, base = _repo(tmp_path, owners="*  @owner\n")
    (root / "CODEOWNERS").write_text(OWNED)  # adding the rule in the same change does not count
    _grow(root)
    rc, out, _ = _run("--base", base, root)
    assert rc == 1
    assert "no human-tier CODEOWNERS rule at the base" in out


def test_a_base_without_a_counts_file_is_the_adoption(tmp_path):
    root, _ = _repo(tmp_path)
    _git(root, "rm", "-q", ar.COUNTS)
    _git(root, "commit", "-qm", "no counts")
    adoption = _git(root, "rev-parse", "HEAD")
    _grow(root)
    rc, out, _ = _run("--base", adoption, root)
    assert rc == 0 and "its adoption" in out


def test_an_unusable_base_is_an_error(tmp_path):
    root, _ = _repo(tmp_path)
    assert _run("--base", "0" * 40, root)[0] == 2
    assert _run("--base", " ", root)[0] == 2


# ----------------------------------------------------------------------------- this repository


def test_this_repository_is_at_its_counts():
    rc, out, _ = _run(REPO)
    assert rc == 0, out


def test_the_ratchet_runs_in_make_gates_and_ci():
    make = (REPO / "Makefile").read_text()
    gates = make[make.index("\ngates:\n") :].split("\n\n", 1)[0]
    assert "$(PY) tools/allowlist_ratchet.py ." in gates
    ci = (REPO / ".github/workflows/ci.yml").read_text()
    assert "run: python tools/allowlist_ratchet.py ." in ci
