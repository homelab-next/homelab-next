# SPDX-License-Identifier: Apache-2.0
"""Modules (ADR-0027, proposed; docs/modules.md): the loader and its rules.

:mod:`homelabnext.modules.loader` discovers the manifests and runs :mod:`homelabnext.modules.rules`
(``hnx modules check``), the loader's rules as pure functions; the contract tests
(``tests/schemas/test_module_1_0.py``) apply them to the fictional examples.
"""
