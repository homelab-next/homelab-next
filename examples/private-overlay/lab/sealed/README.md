<!-- SPDX-License-Identifier: Apache-2.0 -->
# lab/sealed/ (placeholder)

Every file here except this README must be SOPS-encrypted throughout, whatever its name and
whatever `.sops.yaml` says: `private_leak_check.py private` pins this directory and fails CI on a
file committed in the clear, on metadata that is not real, on any value that is not a well-formed
`ENC[...]` token (a key ending in the file's `unencrypted_suffix` excepted) and on a file sealed
only in part (`encrypted_regex` and the like). Create one with
`sops lab/sealed/wan.sops.yaml` (the editor encrypts on save); never `sops -d` into a file you
might add. hnx decrypts them in memory when it reads them (`sops` on PATH or `HNX_SOPS`, the age
identity in `SOPS_AGE_KEY` or `SOPS_AGE_KEY_FILE`).

Sensitive data that is not a credential goes here. A credential (a password, a token, a key) does
not: it lives in OpenBao and is referenced by name (`secret:<name>`).
