# SPDX-License-Identifier: Apache-2.0
"""HomelabNext: contracts, libraries and conformance tests for a modular security-and-AI lab.

This root ``__init__`` is owned by the repository skeleton.  Sub-packages
(``ids``, ``registry``, ``lake`` ...) are owned by the task listed in ``docs/interfaces.md``.
"""

from importlib import metadata as _metadata

try:
    __version__ = _metadata.version("homelabnext")
except _metadata.PackageNotFoundError:  # a source checkout that is not installed
    # the checkout's own version (the one packaging stamps and the changelog gate reads), so
    # anything that looks the version up in CHANGELOG.md finds its section
    try:
        from homelabnext._version import VERSION as __version__
    except ImportError:  # a partial copy (config_leak_scan ships only __init__ and shapes)
        __version__ = "0.0.0+local"

__all__ = ["__version__"]
