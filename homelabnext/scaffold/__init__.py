# SPDX-License-Identifier: Apache-2.0
"""Scaffolds behind ``hnx new <kind> <name>``; every output passes its own checker."""

from .core import KINDS, main, new, verify  # noqa: F401
