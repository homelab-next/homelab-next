# SPDX-License-Identifier: Apache-2.0
"""The model store and the serving plan (docs/model-serving.md, ADR-0023).

:mod:`.store` is the manifest of the one model store (each model once, pinned by commit and
sha256); :mod:`.serving` joins it with the role table into what each engine serves.  The
role aliases themselves live in :mod:`homelabnext.registry.models`.
"""
