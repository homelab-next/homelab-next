<!-- SPDX-License-Identifier: Apache-2.0 -->
# locks/ (placeholder)

`deploy.in` lists the deploy job's own tools; lock it with hashes and commit `deploy.txt`
(`uv pip compile locks/deploy.in --generate-hashes --universal -o locks/deploy.txt`).
The deploy workflow installs it with `--require-hashes`.
