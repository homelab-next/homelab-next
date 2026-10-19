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
