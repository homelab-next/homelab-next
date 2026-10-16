# SPDX-License-Identifier: Apache-2.0
"""HomelabNext: contracts, libraries and conformance tests for a modular security-and-AI lab.

This root ``__init__`` is owned by the repository skeleton.  Sub-packages
(``ids``, ``registry``, ``lake`` ...) are owned by the task listed in ``docs/interfaces.md``.
"""

from importlib import metadata as _metadata

try:
    __version__ = _metadata.version("homelabnext")
except _metadata.PackageNotFoundError:  # running from a source checkout without install
    __version__ = "0.0.0+local"

__all__ = ["__version__"]
