<!-- SPDX-License-Identifier: Apache-2.0 -->
# schemas/conform

The conformance harness's input files (docs/conformance.md).

| File | `$id` | What |
|---|---|---|
| `target.schema.json` | `.../conform/target/1.0` | a target file: `name` and, per capability, one binding (`adapter` with `config`, `features`, `waive`; or `builtin: fake \| broken[:mutant]`; or `fake: true`) |
| `capabilities.schema.json` | `.../conform/capabilities/1.0` | `capabilities.yml`: the non-empty list of distinct capability names a tree declares |

`homelabnext.conform.target.load_target` and `homelabnext.conform.registry.declared_capabilities`
validate every file they read against these, so a misspelt key is refused (`ConformError`, exit 2)
instead of being ignored.
