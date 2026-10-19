# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hermetic_lint


def _reasons(src: str) -> list[str]:
    return [r for _, r in hermetic_lint.lint_source(textwrap.dedent(src))]


@pytest.mark.parametrize(
    "src",
    [
        "import time\ntime.time()\n",
        "import time as t\nt.time_ns()\n",
        "from time import time\ntime()\n",
        "import datetime\ndatetime.datetime.now()\n",
        "from datetime import datetime\ndatetime.now(tz=None)\n",
        "from datetime import datetime as dt\ndt.utcnow()\n",
        "from datetime import date\ndate.today()\n",
        "import random\nrandom.choice([1, 2])\n",
        "from random import shuffle\nshuffle([])\n",
        "import random\nrandom.Random()\n",
        "import random\nrandom.SystemRandom().random()\n",
        "import secrets\nsecrets.token_hex(8)\n",
        "import os\nos.urandom(8)\n",
        "import uuid\nuuid.uuid4()\n",
    ],
)
def test_flags_wall_clock_and_unseeded_randomness(src):
    assert len(_reasons(src)) == 1, src


@pytest.mark.parametrize(
    "src",
    [
        "import random\nrandom.Random(7).choice([1, 2])\n",
        "import random\nrandom.Random(x=1)\n",
        "import time\ntime.monotonic(); time.perf_counter(); time.sleep(0)\n",
        "from datetime import datetime, timezone\ndatetime(2026, 1, 1, tzinfo=timezone.utc)\n",
        "from datetime import datetime\ndatetime.fromisoformat('2026-01-01T00:00:00')\n",
        "import uuid\nuuid.uuid5(uuid.NAMESPACE_URL, 'fake')\n",
        "def now():\n    return 0\nnow()\n",  # a local helper named like the clock
        "import time\ntime.time()  # hermetic: allow measures a real-server timeout\n",
        "x = 'time.time() in a string is not a call'\n",
    ],
)
def test_allows_seeded_injected_and_waived_uses(src):
    assert _reasons(src) == [], src


def test_bad_file_fails_and_clean_file_passes(tmp_path, capsys):
    bad = tmp_path / "test_bad.py"
    bad.write_text("import time\n\n\ndef test_x():\n    assert time.time() > 0\n")
    good = tmp_path / "test_good.py"
    good.write_text("def test_x():\n    assert True\n")
    assert hermetic_lint.main([str(bad)]) == 1
    assert f"{bad}:5: wall clock time.time()" in capsys.readouterr().err
    assert hermetic_lint.main([str(good)]) == 0


def test_scope_is_test_code_only(tmp_path):
    for rel in ("tests/a/helper.py", "tools/tests/test_t.py", "conformance/x/test_c.py",
                "conformance/conftest.py", "conformance/suites/dns.py", "homelabnext/m.py"):  # fmt: skip
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("")
    got = {p.relative_to(tmp_path).as_posix() for p in hermetic_lint.test_files(tmp_path)}
    assert got == {
        "tests/a/helper.py",
        "tools/tests/test_t.py",
        "conformance/x/test_c.py",
        "conformance/conftest.py",
    }


def test_this_repo_is_clean():
    assert hermetic_lint.main([]) == 0


# ---------------------------------------------------------------- library pass
def _lib(tmp_path, **modules):
    """Write ``pkg/<name>.py`` modules and lint them as library code; returns the reasons."""
    files = []
    for name, src in {"__init__": "", **modules}.items():
        f = tmp_path / "pkg" / f"{name}.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(textwrap.dedent(src))
        files.append(f)
    return [r for _, _, r in hermetic_lint.lint_library(files, tmp_path)]


LIB_FLAGGED = [
    "import time\ndef f(x):\n    return time.time() + x\n",
    "import time\ndef f(deadline):\n    return time.monotonic() > deadline\n",
    "from datetime import datetime, UTC\ndef f():\n    x = datetime.now(UTC)\n    return x\n",
    "import time\ndef f(x):\n    return x + time.strftime('%Y')\n",  # implicit: no time tuple
    "import time\ndef f(x):\n    return x, time.gmtime()\n",
    # a provider called unconditionally
    "from datetime import datetime, UTC\ndef _now():\n    return datetime.now(UTC)\n"
    "def f(x):\n    return x, _now()\n",
    # a fallback on something that is not a parameter of the function
    "import time\nCLOCK = None\ndef f(x):\n    return CLOCK or time.time()\n",
    # the wrong arm of the conditional
    "import time\ndef f(now=None):\n    return time.time() if now is not None else now\n",
    "import time\nclass C:\n    def f(self):\n        return time.time()\n",
    "import time\nclass C:\n    started: float = time.time()\n",  # evaluated at import
    "import time\nSTARTED = time.time()\n",
    # a parameterless wrapper is a provider too, so its unconditional caller is flagged
    "import time\ndef _now():\n    return time.time()\ndef stamp():\n    return int(_now())\n"
    "def f(x):\n    return x, stamp()\n",
]


@pytest.mark.parametrize("src", LIB_FLAGGED)
def test_library_clock_reads_without_injection_are_flagged(tmp_path, src):
    assert len(_lib(tmp_path, m=src)) == 1, src


LIB_ALLOWED = [
    "import time\ndef f(clock=time.time):\n    return clock()\n",
    "import time\ndef f(*, clock=time.monotonic):\n    return clock()\n",
    "from datetime import datetime, UTC\ndef f(clock=lambda: datetime.now(UTC)):\n"
    "    return clock()\n",
    "from datetime import datetime, UTC\ndef f(clock=None):\n"
    "    clock = clock or (lambda: datetime.now(UTC))\n    return clock()\n",
    "from datetime import datetime, UTC\ndef _now():\n    return datetime.now(UTC).isoformat()\n"
    "def f(now=None):\n    return now or _now()\n",
    "import time\ndef f(now=None):\n    return time.time() if now is None else now\n",
    "import time\ndef f(now=None):\n    return now if now is not None else time.time()\n",
    "import time\nfrom dataclasses import dataclass\n@dataclass\nclass C:\n"
    "    clock: object = time.time\n",
    "import time\ndef f(clock=time.time):\n    return time.gmtime(clock())\n",  # explicit time
    "import time\ndef f():\n    time.sleep(0)\n",  # waiting is not reading the clock
    "import time\ndef f():\n    return time.time()  # hermetic: allow measures a real timeout\n",
    "def now():\n    return 0\ndef f():\n    return now()\n",  # not a clock provider
]


@pytest.mark.parametrize("src", LIB_ALLOWED)
def test_library_clock_reads_with_injection_are_allowed(tmp_path, src):
    assert _lib(tmp_path, m=src) == [], src


def test_a_provider_imported_from_another_module_is_still_a_clock_read(tmp_path):
    clock = "from datetime import datetime, UTC\ndef utcnow():\n    return datetime.now(UTC)\n"
    bad = "from .clock import utcnow\ndef f(x):\n    return x, utcnow()\n"
    good = "from pkg.clock import utcnow\ndef f(clock=utcnow):\n    return clock()\n"
    reasons = _lib(tmp_path, clock=clock, bad=bad, good=good)
    assert reasons == [
        "library clock read pkg.clock.utcnow() outside a parameter's default or fallback "
        "(take an injectable clock or now)"
    ]


def test_library_flag_and_whole_repo_scope(tmp_path, capsys):
    f = tmp_path / "pkg" / "m.py"
    f.parent.mkdir()
    f.write_text("import time\n\n\ndef f(x):\n    return time.time() + x\n")
    assert hermetic_lint.main(["--root", str(tmp_path), "--library", str(f)]) == 1
    assert f"{f}:5: library clock read time.time()" in capsys.readouterr().err
    (tmp_path / "homelabnext" / "sub").mkdir(parents=True)
    (tmp_path / "homelabnext" / "sub" / "a.py").write_text("")
    got = [p.relative_to(tmp_path).as_posix() for p in hermetic_lint.library_files(tmp_path)]
    assert got == ["homelabnext/sub/a.py"]
