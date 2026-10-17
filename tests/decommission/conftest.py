# SPDX-License-Identifier: Apache-2.0
"""A fixture lab with one LIVE guest (``app-core``) and one RETIRED guest (``old-core``).

Everything is fictional (RFC 5737 addresses, example names).  ``old-core`` has been torn down
properly, so every plane is clean for it; ``app-core`` is still wired into every plane.
"""

from __future__ import annotations

import pytest
from labdata import FILES, SNAPSHOT

from homelabnext.decommission import Adapters, MemTree


@pytest.fixture
def files():
    return dict(FILES)


@pytest.fixture
def adapters(files):
    return Adapters.from_snapshot(SNAPSHOT, MemTree(files))
