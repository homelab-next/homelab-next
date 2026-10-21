<!-- SPDX-License-Identifier: Apache-2.0 -->
# Private overlay skeleton (fictional)

A template for the **private** repository that holds one real lab: its site, registry, guests,
registers, strategy and customizations in plain text under the repository's access control
(sealed per file with SOPS where you choose), its Ansible inventory with vaulted variables, and
the workflow that deploys it. The public homelab-next repository holds the code; this one holds
the lab. The full guide is [docs/private-overlay.md](../../docs/private-overlay.md); the decision
is [ADR-0021](../../docs/adr/0021-public-and-private-repositories.md).

Everything here is fictional: the age recipients in `.sops.yaml` are marked fake, the marker says
`fictional: true`, and the data directories hold only READMEs.

```text
lab-private/                       (a new PRIVATE repository; copy this directory's contents)
├── .hnx-private-overlay.yml       marker: enables `private_leak_check.py private`, lists vault files
├── .sops.yaml                     which paths are sealed, to which age recipients
├── .gitignore                     keys and decrypted scratch copies never get added
├── .github/workflows/
│   ├── checks.yml                 every pull request: private_leak_check (no secrets)
│   └── deploy.yml                 main only, protected Environment `production`
├── ansible.cfg                    roles from ./hnx, vault password from bin/vault-pass-client.py
├── ansible/
│   ├── inventory/production/      hosts.yml, group_vars/all/{main,vault}.yml (vault.yml vaulted)
│   ├── known_hosts                the hosts' PUBLIC keys (or an SSH host CA line)
│   └── playbooks/site.yml         applies hnx roles to the inventory
├── bin/vault-pass-client.py       password from HNX_VAULT_PASSWORD or OpenBao, never a file
├── lab/                           the lab, laid out like the public examples/ (HNX_EXAMPLES_DIR)
│   ├── services.yml  site.yml  guests/  registers/  strategy/  customizations/
│   └── sealed/*.sops.yaml         sealed per file (.sops.yaml rule)
└── requirements/deploy.in, deploy.txt   the deploy job's own tools, locked with hashes
```

To start one: create an empty private repository, copy these files in, delete `fictional: true`
from the marker, replace the fake recipients with yours, and follow the runbook "First deploy
from the private repository" (`examples/registers/runbooks/`).
