<!-- SPDX-License-Identifier: Apache-2.0 -->
# group_vars/all/ (placeholder)

`main.yml` (plain) points at vaulted values by name, the Ansible convention:

```yaml
smtp_relay_password: "{{ vaulted_smtp_relay_password }}"
```

`vault.yml` holds the vaulted values and is always vault-encrypted: the marker's
`ansible_vault_files` glob makes `private_leak_check.py private` fail on a `vault.yml` without the ansible-vault header.
Prefer an OpenBao reference (`secret:<name>` through the `hnx_secret` lookup) for anything a role
already accepts as a reference; the vault is for the rest.
