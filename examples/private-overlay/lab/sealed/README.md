<!-- SPDX-License-Identifier: Apache-2.0 -->
# lab/sealed/ (placeholder)

Files here named `*.sops.yaml` must be SOPS-encrypted: the `.sops.yaml` rule covers them and
`private_leak_check.py private` fails CI on one committed in the clear. Create one with
`sops lab/sealed/wan.sops.yaml` (the editor encrypts on save); never `sops -d` into a file you
might add. hnx decrypts them in memory when it reads them (`sops` on PATH or `HNX_SOPS`, the age
identity in `SOPS_AGE_KEY` or `SOPS_AGE_KEY_FILE`).

Sensitive data that is not a credential goes here. A credential (a password, a token, a key) does
not: it lives in OpenBao and is referenced by name (`secret:<name>`).
