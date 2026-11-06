# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: model-store-files
#   kind: tool
#   purpose: Read every file of one model-store entry (exists, size, sha256, where a link resolves) in one module call, and list what else the entry holds.
#   owner: platform
#   trigger: [role:model_store]
#   inputs: the entry's directory, its manifest files, whether to hash them, whether to walk it
#   outputs: one result per file, in manifest order, and the strays a walk found (JSON, as an Ansible module)
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
  - With I(walk), also C(strays), from a walk of the entry that never follows a link: the entry
    directory itself when it is a link or not a directory, and below it every link, every special
    file (device, FIFO, socket), every regular file the manifest does not list and every listed
    file with another hard link. An export is written by the trainers' group, so before the role
    takes ownership of one it refuses anything it would otherwise chown or chmod on their behalf.
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
  walk:
    description: Walk the entry (links never followed) and return C(strays).
    type: bool
    default: false
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
strays:
  description: >-
    With walk, what the entry holds besides its listed regular files and their directories, each
    "<path> (<why>)", sorted; empty when the entry directory is absent.
  returned: when walk is true
  type: list
  elements: str
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


def walk_entry(directory: str, files: list[dict]) -> list[str]:
    """Everything under ``directory`` that is not a listed regular file or a directory.

    Nothing is followed (``os.walk`` lists a link to a directory but never enters it, and every
    name is read with ``lstat``), so a link planted beside an export is reported, never chased.
    """
    top = _stat(directory, follow=False)
    if top is None:
        return []
    if stat.S_ISLNK(top.st_mode):
        return [". (the entry directory is a link)"]
    if not stat.S_ISDIR(top.st_mode):
        return [". (the entry is not a directory)"]
    listed = {f["path"] for f in files}
    strays: list[str] = []

    def unreadable(exc: OSError) -> None:
        raise exc

    for root, dirs, names in os.walk(directory, onerror=unreadable):
        rel_root = os.path.relpath(root, directory)
        for name in dirs + names:
            rel = name if rel_root == "." else f"{rel_root}/{name}"
            st = os.lstat(os.path.join(root, name))
            if stat.S_ISLNK(st.st_mode):
                strays.append(f"{rel} (a link)")
            elif stat.S_ISDIR(st.st_mode):
                continue
            elif not stat.S_ISREG(st.st_mode):
                strays.append(f"{rel} (a special file)")
            elif rel not in listed:
                strays.append(f"{rel} (not in the manifest)")
            elif st.st_nlink > 1:
                strays.append(f"{rel} (hard-linked: {st.st_nlink} links)")
    return sorted(strays)


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "dir": {"type": "str", "required": True},
            "files": {"type": "list", "elements": "dict", "required": True},
            "checksum": {"type": "bool", "default": True},
            "walk": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
    )
    p = module.params
    bad = [f for f in p["files"] if not isinstance(f.get("path"), str) or not f["path"]]
    if bad:
        module.fail_json(msg=f"model_store_files: a file without a path: {bad[0]!r}")
    try:
        results = read_entry(p["dir"], p["files"], p["checksum"])
        extra = {"strays": walk_entry(p["dir"], p["files"])} if p["walk"] else {}
    except OSError as exc:
        module.fail_json(msg=f"model_store_files: {exc.filename}: {exc.strerror}")
    module.exit_json(changed=False, results=results, **extra)


if __name__ == "__main__":
    main()
