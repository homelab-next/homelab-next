<!-- SPDX-License-Identifier: Apache-2.0 -->
# ansible/inventory/production/ (placeholder)

`hosts.yml` in the capability-group layout of the public `ansible/inventory/example/`, and
`group_vars/` / `host_vars/`. A variable that must stay confidential but is not in OpenBao goes in
a `vault.yml` next to the plain `main.yml` and is encrypted with ansible-vault
(`ansible-vault encrypt ansible/inventory/production/group_vars/all/vault.yml`).
