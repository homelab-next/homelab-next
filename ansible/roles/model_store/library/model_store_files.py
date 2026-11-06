# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: model-store-files
#   kind: tool
#   purpose: Read every file of one model-store entry (exists, size, sha256, where a link resolves) in one module call.
#   owner: platform
#   trigger: [role:model_store]
#   inputs: the entry's directory, its manifest files, whether to hash them
#   outputs: one result per file, in manifest order (JSON, as an Ansible module)
#   exit:
#     "0": every file was read (a missing file is a result, not a failure)
#     "1": a file could not be read (permission, a link loop); the role stops
"""Ansible module (role-local): stat every file of one model-store entry in one round trip.

``ansible.builtin.stat`` in a loop costs one module transfer per file, and an entry holds dozens
of shards; this reads them all at once and returns, per file, what the role's tasks read from a
followed and an unfollowed stat (fetch_entry.yml, verify_entry.yml).  Standard library plus
Ansible's own module_utils.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
module: model_store_files
short_description: Stat (and optionally sha256) every file of one model-store entry
description:
  - For each manifest file, the followed stat (C(stat.exists), C(stat.size), C(stat.checksum))
    and the unfollowed one (C(link.exists), C(link.islnk), C(link.lnk_source)), with the same
    meaning as M(ansible.builtin.stat) with C(follow=true) and C(follow=false).
  - C(stat.checksum) is the sha256 of a readable regular file when I(checksum) is true, else
    null.  Files are hashed in blocks, never read whole into memory.
  - Read-only; supports check mode.
options:
  dir:
    description: The entry's directory; each file is read at C(<dir>/<path>).
    type: str
    required: true
  files:
    description: The entry's manifest files (each a dict with at least C(path)), echoed back as C(item).
    type: list
    elements: dict
    required: true
  checksum:
    description: Compute each file's sha256.
    type: bool
    default: true
"""

EXAMPLES = r"""
- name: Read the entry's files
  model_store_files:
    dir: "{{ model_store_entry_dir }}"
    files: "{{ model_store_entry.value.files }}"
    checksum: true
  register: model_store_files_read
"""

RETURN = r"""
results:
  description: One per input file, in order.
  returned: always
  type: list
  elements: dict
  contains:
    item: {description: The input file dict., type: dict}
    stat: {description: "Followed: exists, and when it exists size and checksum (sha256 or null).", type: dict}
    link: {description: "Unfollowed: exists, and when it exists islnk and lnk_source (realpath, links only).", type: dict}
"""

BLOCK = 8 << 20


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(BLOCK)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _stat(path: str, follow: bool) -> os.stat_result | None:
    """``ansible.builtin.stat``'s rule: absent is a result, any other error is a failure."""
    try:
        return os.stat(path) if follow else os.lstat(path)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None
        raise


def read_file(path: str, checksum: bool) -> dict:
    """The followed and unfollowed stat of ``path``, as the role reads them."""
    out: dict = {}
    st = _stat(path, follow=True)
    if st is None:
        out["stat"] = {"exists": False}
    else:
        digest = None
        if checksum and stat.S_ISREG(st.st_mode) and os.access(path, os.R_OK):
            digest = sha256_file(path)
        out["stat"] = {"exists": True, "size": st.st_size, "checksum": digest}
    lst = _stat(path, follow=False)
    if lst is None:
        out["link"] = {"exists": False}
    else:
        islnk = stat.S_ISLNK(lst.st_mode)
        out["link"] = {"exists": True, "islnk": islnk}
        if islnk:
            out["link"]["lnk_source"] = os.path.realpath(path)
    return out


def read_entry(directory: str, files: list[dict], checksum: bool) -> list[dict]:
    # joined as the tasks did ("{{ dir }}/{{ path }}"): an absolute path never replaces dir
    return [{"item": f, **read_file(f"{directory}/{f['path']}", checksum)} for f in files]


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "dir": {"type": "str", "required": True},
            "files": {"type": "list", "elements": "dict", "required": True},
            "checksum": {"type": "bool", "default": True},
        },
        supports_check_mode=True,
    )
    p = module.params
    bad = [f for f in p["files"] if not isinstance(f.get("path"), str) or not f["path"]]
    if bad:
        module.fail_json(msg=f"model_store_files: a file without a path: {bad[0]!r}")
    try:
        results = read_entry(p["dir"], p["files"], p["checksum"])
    except OSError as exc:
        module.fail_json(msg=f"model_store_files: {exc.filename}: {exc.strerror}")
    module.exit_json(changed=False, results=results)


if __name__ == "__main__":
    main()
