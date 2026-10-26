<!-- SPDX-License-Identifier: Apache-2.0 -->
# lab/: the real lab (placeholder)

Lay this directory out like the public `examples/` tree so the same commands work on it:
`services.yml` (the registry), `site.yml` (the site and network model), `modules.yml` (the module
selection, with the site's network scope: trusted, target and excluded addresses), `guests/`,
`registers/`, `strategy/`, `status/`, `model_roles.json`. The deploy workflow sets
`HNX_EXAMPLES_DIR=lab`, so a command that reads the default example data reads this instead;
commands that take a path are given `lab/...` explicitly.

Plain text is the default: the repository's access control protects it, and plain text keeps
diffs reviewable. Seal a file with SOPS only when its content would hurt if the repository
leaked (see `sealed/`). Credentials never live here: a role names one as `secret:<name>`.
