# SPDX-License-Identifier: Apache-2.0
"""``python -m homelabnext.context_service serve | reindex | check``."""

import sys

from .cli import main

sys.exit(main(sys.argv[1:]))
