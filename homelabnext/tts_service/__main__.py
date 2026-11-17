# SPDX-License-Identifier: Apache-2.0
"""``python -m tts_service serve|check`` (the image's entry point)."""

import sys

from .server import main

sys.exit(main())
