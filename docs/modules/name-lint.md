---
summary: 'Module manifest reference: the product-name lint (rule 1), its vocabulary, allowlist and shrinking baseline.'
summary_of: outline:sha256:08cfa44ea9698fc0
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: the product-name lint

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## The product-name lint (rule 1)

Implemented as `tools/product_name_lint.py`, modelled on `tools/no_raw_endpoints.py`, run by
`make gates`, the CI `schemas` job (with `--ci-base`) and invariant X-11.

- **Vocabulary**: every provider's `product.name`, `display` and `aliases`, from
  `examples/modules/`, the public `modules/` and an overlay's `lab/modules/` (`--overlay`);
  `tools/product_names.yml` `products:` for products without a provider module yet (each with a
  `why`; unambiguous names only); and **model identifiers** from the role table
  (`examples/model_roles.json`, `--roles`). Each name must be lower-case words of at most 128
  characters, and a manifest that is not well formed is an error, never skipped.
- **Where allowed**: a provider module's directory, **for its own product only** (claiming
  `kind: provider` does not open a directory to every product); site configuration
  (`examples/modules/sites/`, `examples/private-overlay/`, an overlay's `lab/`); the role table;
  Markdown prose (ADRs and the changelog included); and the reviewed globs of
  `tools/product_names.yml` `allow:`, each with a reason (generated catalogues and other gates'
  path lists, whose paths are counted where they live).
- **What is linted**: the files `git ls-files` lists under the root (tracked, plus untracked but
  not ignored; a directory walk outside a git work tree). Python string and bytes constants as
  Python reads them (escapes decoded, implicit concatenation joined, f-string parts) and
  identifiers; every key and string value of YAML (sets, ordered maps and binaries included) and
  JSON, except the string value of a prose key (`description`, `title`, `$comment`, `summary`,
  `reason`, `why`, `purpose`, `help`); the lines of every other text file, whatever its suffix
  (`Dockerfile`, `Makefile`, `.env`, `.html`, `.sql` included) or encoding (UTF-8; UTF-16 or
  UTF-32 by BOM or byte pattern; otherwise Latin-1); every file, directory and submodule name; and
  a symbolic link's target text and, for a link into the tree, the target's content under the
  link's path. A binary (a NUL byte in a suffix not known as text) is skipped whatever its size; a
  text file over 20 MB is an error.
- **Skipped**: comments (Python, and `#` or `//` lines in the formats that use them), docstrings
  (as nodes, so code on the same line is still read) and prose.
- **Matching**: one pass of one pattern per file (about 5 seconds over this tree). A file is parsed
  only when its letters and digits contain some name's, or it holds an escape or a line
  continuation, so the prefilter never skips a file a parse would match in. Case-insensitive after
  compatibility normalisation with combining marks and invisible format characters removed; `-`,
  `_`, `.`, a space or nothing between a name's parts; bounded by a non-alphanumeric or a
  camel-case, upper-case-run or letter/digit seam, so `NorthwindObjectsClient`,
  `NORTHWINDOBJECTSClient` and `getNorthwindObjects` count and a longer word containing the name
  does not (`OPENBAOADDR`, all capitals glued, is a known miss). It finds ordinary spellings, not
  deliberate obfuscation (`"open" + "bao"`, an encoded string): that is what review of a change is
  for.
- **Baseline**: `tools/product_names.baseline.json` holds today's counts per path and product
  (the core still names its reference products in about 530 paths). A count above it fails, and so
  does an entry above what is there. `make product-names-baseline` (`--update`) rewrites it to what
  is there and is refused when any product's total would rise. In CI `--ci-base` also compares the
  committed baseline and vocabulary with the base commit's (the same base rule as
  `tools/schema_check.py --ci-base`): no path's count may rise above its count there (a file git
  sees as renamed or copied keeps its old path's counts, and a split records its new path under
  `tools/product_names.yml` `moved:` with a reason, so a new file never takes on debt freed
  elsewhere), no product's total may rise (so a copy never doubles debt), and no spelling linted
  there (a product, an alias, a provider's display name, a model id) may stop being linted unless
  `retired:` says why (each retirement is printed in the CI log). Neither file can be loosened by
  hand. Moving product code into a provider module is how it shrinks.
- **Exit**: 0 clean, 1 violations, 2 a bad input, 100 the lint itself failed (X-11 reports that
  as "could not measure", not as a failure).
