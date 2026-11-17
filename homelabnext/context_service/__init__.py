# SPDX-License-Identifier: Apache-2.0
"""The ``context`` retrieval service (modules/context): the semantic adapter of the ``context``
contract run as an HTTP service, its index built from configured git sources, each item carrying
its TLP label, every read at the caller's ceiling, and an optional judge as an abstention gate.

``python -m homelabnext.context_service serve | reindex | check`` (the image's entry point).
"""
