# SPDX-License-Identifier: Apache-2.0
"""tools/licence_check.py: ADR-0011's licence rule against what constraints/ pins and compose/
runs, through the reviewed register tools/licences.yml."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import licence_check as lc
from test_licence_policy import _refused_families

PINS = "pip==1.0 \\\n    --hash=sha256:00\nfoo_bar==2.0\n"
COMPOSE = (
    "services:\n"
    "  a:\n    image: example.invalid/team/app:1.2@sha256:" + "0" * 64 + "\n"
    "  b:\n    image: plain:3\n"
)
REGISTER = """\
python:
  pip: {spdx: MIT, kind: linked}
  foo-bar: {spdx: Apache-2.0, kind: linked}
images:
  example.invalid/team/app: {spdx: AGPL-3.0-only, kind: service, reason: "run as its own service"}
  plain: {spdx: MIT, kind: service, reason: "the project's LICENSE"}
"""


def _tree(tmp_path: Path, register: str = REGISTER, compose: str = COMPOSE) -> Path:
    (tmp_path / "constraints").mkdir(parents=True)
    (tmp_path / "constraints" / "ci.txt").write_text(PINS)
    (tmp_path / "compose" / "lab").mkdir(parents=True)
    (tmp_path / "compose" / "lab" / "docker-compose.yml").write_text(compose)
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "licences.yml").write_text(register)
    return tmp_path


def test_this_repository_lists_every_pin_and_image():
    assert lc.check(lc.REPO_ROOT) == []


def test_a_listed_tree_passes_and_a_copyleft_service_is_allowed(tmp_path):
    assert lc.check(_tree(tmp_path)) == []
    assert lc.main(["--root", str(tmp_path)]) == 0


def test_an_unlisted_pin_or_image_fails(tmp_path):
    root = _tree(tmp_path, REGISTER.replace("  foo-bar: {spdx: Apache-2.0, kind: linked}\n", ""))
    assert lc.check(root) == ["python: foo-bar (constraints/) has no entry in tools/licences.yml"]
    root = _tree(tmp_path / "b", compose=COMPOSE + "  c:\n    image: other:1\n")
    assert lc.check(root) == [
        "images: other (compose/lab/docker-compose.yml) has no entry in tools/licences.yml"
    ]
    assert lc.main(["--root", str(root)]) == 1


def test_an_entry_nothing_pins_is_stale(tmp_path):
    root = _tree(
        tmp_path, REGISTER.replace("python:\n", "python:\n  gone: {spdx: MIT, kind: linked}\n")
    )
    assert lc.check(root) == [
        "tools/licences.yml: python.gone: nothing pins or runs it; remove the entry"
    ]


@pytest.mark.parametrize(
    ("spdx", "refused"),
    [
        ("GPL-3.0-only", True),
        ("AGPL-3.0-or-later", True),
        ("SSPL-1.0", True),
        ("MIT AND GPL-2.0-only", True),
        ("GPL-2.0-only OR AGPL-3.0-only", True),
        ("MIT OR GPL-2.0-only", False),
        ("LGPL-3.0-or-later", False),
        ("MPL-2.0", False),
        ("Apache-2.0 AND BSD-3-Clause", False),
    ],
)
def test_a_linked_package_may_not_be_copyleft(tmp_path, spdx, refused):
    root = _tree(
        tmp_path, REGISTER.replace("{spdx: MIT, kind: linked}", f"{{spdx: {spdx}, kind: linked}}")
    )
    problems = lc.check(root)
    assert bool(problems) is refused, problems
    if refused:
        assert "copyleft, which ADR-0011 refuses for linked code" in problems[0]


def test_a_copyleft_tool_needs_a_reason(tmp_path):
    tool = "{spdx: GPL-3.0-or-later, kind: tool, reason: run as its own program}"
    assert lc.check(_tree(tmp_path, REGISTER.replace("{spdx: MIT, kind: linked}", tool))) == []
    bare = "{spdx: GPL-3.0-or-later, kind: tool}"
    root = _tree(tmp_path / "b", REGISTER.replace("{spdx: MIT, kind: linked}", bare))
    assert lc.check(root) == ["tools/licences.yml: python.pip: a tool needs a reason"]


@pytest.mark.parametrize(
    ("entry", "words"),
    [
        ("{spdx: (MIT OR BSD-3-Clause), kind: linked}", "is not ids joined by AND or OR"),
        ("{spdx: MIT or Apache, kind: linked}", "is not ids joined by AND or OR"),
        ("{spdx: MIT, kind: service, reason: x}", "kind must be one of linked, tool"),
        ("{spdx: MIT, kind: linked, owner: x}", "must be {spdx, kind, reason}"),
    ],
)
def test_a_malformed_entry_fails(tmp_path, entry, words):
    root = _tree(tmp_path, REGISTER.replace("{spdx: MIT, kind: linked}", entry))
    problems = lc.check(root)
    assert len(problems) == 1 and words in problems[0], problems


def test_an_interpolated_image_cannot_be_listed(tmp_path):
    root = _tree(tmp_path, compose=COMPOSE + "  c:\n    image: ${LAB_IMAGE:-other:1}\n")
    assert lc.check(root) == [
        "compose/lab/docker-compose.yml: image ${LAB_IMAGE:-other:1} is interpolated; "
        "name it literally"
    ]


@pytest.mark.parametrize(
    ("ref", "repo"),
    [
        ("plain", "plain"),
        ("plain:3", "plain"),
        ("team/app:1.2@sha256:" + "0" * 64, "team/app"),
        ("registry.example:5000/team/app:1.2", "registry.example:5000/team/app"),
        ("hnx-lab-fakes:local", "hnx-lab-fakes"),
    ],
)
def test_an_image_is_listed_by_its_repository(ref, repo):
    assert lc.repository(ref) == repo


def test_an_unreadable_register_is_exit_2(tmp_path):
    root = _tree(tmp_path, "python: [\n")
    assert lc.main(["--root", str(root)]) == 2
    assert lc.main(["--root", str(_tree(tmp_path / "b", "owners: {}\n"))]) == 2


def test_the_refused_families_are_the_adr_s():
    assert set(lc.REFUSED) == set(_refused_families())


def test_a_dockerfile_base_image_is_listed_too(tmp_path):
    root = _tree(tmp_path)
    (root / "compose" / "lab" / "app").mkdir()
    dockerfile = root / "compose" / "lab" / "app" / "Dockerfile"
    dockerfile.write_text(
        "FROM --platform=$BUILDPLATFORM plain:3@sha256:" + "0" * 64 + " AS build\n"
        "FROM build AS test\nFROM scratch\nFROM base:1.0\n"
    )
    # an earlier stage and scratch are not images; the unlisted base is named with its file
    assert lc.check(root) == [
        "images: base (compose/lab/app/Dockerfile) has no entry in tools/licences.yml"
    ]
    dockerfile.write_text("FROM plain:3\n")
    assert lc.check(root) == []


GO_MOD = """\
module example.com/mod/tools

go 1.27.3

tool example.com/lint/cmd/lint

require example.com/lint v1.2.3 // indirect

require (
\texample.com/dep v0.4.0 // indirect
\texample.org/x/y v0.0.0-20260101000000-000000000000
)
"""


def test_every_module_a_go_mod_requires_needs_an_entry(tmp_path):
    root = _tree(tmp_path)
    (root / "mod" / "tools").mkdir(parents=True)
    (root / "mod" / "tools" / "go.mod").write_text(GO_MOD)
    (root / "build" / "x").mkdir(parents=True)  # build output is never read
    (root / "build" / "x" / "go.mod").write_text("module b\n\nrequire example.net/ignored v1.0.0\n")
    assert lc.go_requires(root) == dict.fromkeys(
        ("example.com/lint", "example.com/dep", "example.org/x/y"), "mod/tools/go.mod"
    )
    where = "(mod/tools/go.mod) has no entry in tools/licences.yml"
    assert lc.check(root) == [f"go: {p} {where}" for p in sorted(lc.go_requires(root))]
    listed = (
        REGISTER
        + "go:\n"
        + "".join(
            f'  {p}: {{spdx: BSD-3-Clause, kind: tool, reason: "a linter"}}\n'
            for p in ("example.com/lint", "example.com/dep", "example.org/x/y", "example.com/gone")
        )
    )
    (root / "tools" / "licences.yml").write_text(listed)
    assert lc.check(root) == [
        "tools/licences.yml: go.example.com/gone: nothing pins or runs it; remove the entry"
    ]


def test_a_linked_go_module_may_not_be_copyleft(tmp_path):
    root = _tree(tmp_path)
    (root / "go.mod").write_text("module m\n\ngo 1.27\n\nrequire example.com/gpl v1.0.0\n")
    (root / "tools" / "licences.yml").write_text(
        REGISTER + "go:\n  example.com/gpl: {spdx: GPL-3.0-only, kind: linked}\n"
    )
    (problem,) = lc.check(root)
    assert "go.example.com/gpl: GPL-3.0-only is copyleft" in problem
