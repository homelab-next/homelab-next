<!-- SPDX-License-Identifier: Apache-2.0 -->
# locks/ (placeholder)

`hnx-ref` is HNX_REF: the full SHA of the homelab-next commit the checks and the deploy check
out into `hnx/`. Both workflows refuse a value that is not one full SHA, or a commit that is not
on homelab-next's `main`. Move it by a pull request of its own (docs/private-overlay.md, "The
pinned homelab-next commit").

`deploy.in` lists the deploy job's own tools; lock it with hashes and commit `deploy.txt`
(`uv pip compile locks/deploy.in --generate-hashes --universal -o locks/deploy.txt`).
The deploy workflow installs it with `--require-hashes`.
