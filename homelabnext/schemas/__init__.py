# SPDX-License-Identifier: Apache-2.0
"""Generators for the schemas that are too large to keep consistent by hand.

The module manifest (``platform/module``, ADR-0027, a draft) has some sixty definitions that share
patterns (paths, code references, secret names, slot references), and its negatives are the
shipped examples with one rule broken each.  Both are generated so that a change to one rule
changes every place it applies:

* :mod:`homelabnext.schemas.module_manifest` writes the drafts
  ``schemas/platform/{module,lake_table,module_selection,interface}.schema.json``;
* :mod:`homelabnext.schemas.module_negatives` writes the schema-directory copies of the examples
  (``schemas/platform/examples/{module,module_selection,lake_table,interface}.*.yml``) and one
  negative per rule (``schemas/platform/negative/`` of the same four) from ``examples/modules/``.

``tools/tests/test_generated_files_have_checks.py`` (``SCHEMA_GENERATOR_GLOBS``) compares these
globs with :func:`homelabnext.schemas.__main__.outputs`.

``python -m homelabnext.schemas`` regenerates both; ``--check`` exits 1 when a committed file
differs from what the generators produce (``make schemas`` runs it, and
``tests/schemas/test_module_generators.py`` asserts it).  The committed JSON stays the source the
validators read: the generators only make it reproducible.
"""
