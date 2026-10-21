<!-- SPDX-License-Identifier: Apache-2.0 -->
# requirements/ (placeholder)

`deploy.in` lists the deploy job's own tools; lock it with hashes and commit `deploy.txt`
(`uv pip compile requirements/deploy.in --generate-hashes --universal -o requirements/deploy.txt`).
The deploy workflow installs it with `--require-hashes`.
