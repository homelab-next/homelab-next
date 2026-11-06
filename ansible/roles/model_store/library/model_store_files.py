# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: model-store-files
#   kind: tool
#   purpose: Read every file of one model-store entry (exists, size, sha256, where a link resolves) in one module call, and list what else the entry holds.
#   owner: platform
#   trigger: [role:model_store]
#   inputs: the entry's directory, its manifest files, the paths listed for that directory, whether to hash, walk or lock it
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
import grp
import hashlib
import os
import pwd
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
  - With I(lock), takes ownership of the entry for I(owner):I(group) without ever resolving a
    path twice: every directory and file is opened with C(O_NOFOLLOW) relative to its parent's
    descriptor and changed with C(fchown)/C(fchmod), and each directory is closed to everyone
    but I(owner) (0700) before it is listed, so nothing can be planted in it after it is read.
    Strays are found by the same walk; if there are any, no file is touched and the directories
    stay closed, else files become 0640 (0750 if executable) and directories 0750. A link is
    never followed, chowned or chmodded. Implies I(walk). In check mode nothing is changed.
  - Read-only without I(lock); supports check mode.
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
  listed:
    description: >-
      The paths any manifest entry lists in this directory (two export entries may share one
      run); a walk refuses every other regular file. Default: the paths of I(files).
    type: list
    elements: str
  lock:
    description: Take ownership of the entry as described above (needs I(owner) and I(group)).
    type: bool
    default: false
  owner:
    description: The account that owns the entry after I(lock).
    type: str
  group:
    description: The group of the entry after I(lock).
    type: str
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
    With walk or lock, what the entry holds besides its listed regular files and their
    directories, each "<path> (<why>)", sorted; empty when the entry directory is absent.
  returned: when walk or lock is true
  type: list
  elements: str
"""

BLOCK = 8 << 20
DIR_MODE = 0o750  # u=rwX,g=rX,o= on a directory (setgid cleared, as ansible.builtin.file does)
CLOSED = 0o700  # a directory being read: nobody but the owner may add to it
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC


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


def _listed(files: list[dict], listed: list[str] | None) -> set[str]:
    return set(listed) if listed is not None else {f["path"] for f in files}


def walk_entry(directory: str, files: list[dict], listed: list[str] | None = None) -> list[str]:
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
    wanted = _listed(files, listed)
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
            elif rel not in wanted:
                strays.append(f"{rel} (not in the manifest)")
            elif st.st_nlink > 1:
                strays.append(f"{rel} (hard-linked: {st.st_nlink} links)")
    return sorted(strays)


def _file_mode(st: os.stat_result) -> int:
    """u=rwX,g=rX,o= on a regular file: X only when someone could already execute it."""
    return 0o750 if st.st_mode & 0o111 else 0o640


def _same(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _open_at(name: str, flags: int, dir_fd: int, seen: os.stat_result) -> int | None:
    """``name`` in ``dir_fd``, opened without following it; None unless it is still ``seen``
    (swapped for a link, removed or replaced since it was read)."""
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT, errno.ENXIO):
            return None
        raise
    if _same(os.fstat(fd), seen):
        return fd
    os.close(fd)
    return None


def lock_entry(
    directory: str,
    files: list[dict],
    uid: int,
    gid: int,
    *,
    listed: list[str] | None = None,
    apply: bool = True,
) -> tuple[list[str], bool]:
    """Take ``directory`` for ``uid``:``gid`` by descriptor, refusing what ``walk_entry`` refuses.

    Returns ``(strays, changed)``.  The entry directory is opened with ``O_NOFOLLOW`` and closed
    (``fchown`` + ``fchmod`` 0700) before it is listed, and so is every directory below it, each
    opened relative to its parent's descriptor.  Once a directory is listed nobody else can add,
    rename or remove a name in it, so the walk sees what is locked, and swapping a directory for
    a link after a check cannot redirect a chown: no path is resolved twice.  A link is never
    opened, so its target is never chowned or chmodded, even for a moment.  Each listed regular
    file is opened ``O_NOFOLLOW | O_NONBLOCK`` (a FIFO swapped in cannot block) and changed only
    when its descriptor is still the file the walk saw, with one link (so a hard link to a host
    file is refused whether or not ``fs.protected_hardlinks`` is set).  With any stray no file is
    changed and the directories stay closed (0700, the store's): an operator removes what does not
    belong.  ``apply=False`` (check mode) changes nothing.
    """
    wanted = _listed(files, listed)
    try:
        top = os.open(directory, DIR_FLAGS)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return [], False
        if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
            raise
        lst = _stat(directory, follow=False)
        if lst is not None and stat.S_ISLNK(lst.st_mode):
            return [". (the entry directory is a link)"], False
        return [". (the entry is not a directory)"], False
    strays: list[str] = []
    dirs: list[int] = []
    regular: list[tuple[int, str, str, os.stat_result]] = []
    changed = False

    def take(fd: int, st: os.stat_result, mode: int) -> None:
        nonlocal changed
        owned = (st.st_uid, st.st_gid) == (uid, gid)
        if owned and stat.S_IMODE(st.st_mode) == mode:
            return
        changed = True
        if apply:
            if not owned:
                os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)  # after the chown, which may clear set-id bits

    def close_dir(fd: int) -> None:
        dirs.append(fd)
        st = os.fstat(fd)
        # already the store's at its final mode: nobody else can write it, nothing to close
        if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, DIR_MODE):
            take(fd, st, CLOSED)

    def visit(fd: int, rel_root: str) -> None:
        for name in sorted(os.listdir(fd)):
            rel = f"{rel_root}{name}"
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                strays.append(f"{rel} (a link)")
            elif stat.S_ISDIR(st.st_mode):
                child = _open_at(name, DIR_FLAGS, fd, st)
                if child is None:
                    strays.append(f"{rel} (changed while it was read)")
                    continue
                close_dir(child)
                visit(child, f"{rel}/")
            elif not stat.S_ISREG(st.st_mode):
                strays.append(f"{rel} (a special file)")
            elif rel not in wanted:
                strays.append(f"{rel} (not in the manifest)")
            elif st.st_nlink > 1:
                strays.append(f"{rel} (hard-linked: {st.st_nlink} links)")
            else:
                regular.append((fd, name, rel, st))

    try:
        close_dir(top)
        visit(top, "")
        if strays:
            return sorted(strays), changed
        for fd, name, rel, st in regular:
            ffd = _open_at(name, FILE_FLAGS, fd, st)
            if ffd is None:
                strays.append(f"{rel} (changed while it was read)")
                continue
            try:
                fst = os.fstat(ffd)
                if stat.S_ISREG(fst.st_mode) and fst.st_nlink == 1:
                    take(ffd, fst, _file_mode(fst))
                else:
                    strays.append(f"{rel} (changed while it was read)")
            finally:
                os.close(ffd)
        if not strays and apply:
            for fd in dirs:
                take(fd, os.fstat(fd), DIR_MODE)
        return sorted(strays), changed
    finally:
        for fd in dirs:
            os.close(fd)


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "dir": {"type": "str", "required": True},
            "files": {"type": "list", "elements": "dict", "required": True},
            "checksum": {"type": "bool", "default": True},
            "walk": {"type": "bool", "default": False},
            "listed": {"type": "list", "elements": "str"},
            "lock": {"type": "bool", "default": False},
            "owner": {"type": "str"},
            "group": {"type": "str"},
        },
        required_if=[("lock", True, ("owner", "group"))],
        supports_check_mode=True,
    )
    p = module.params
    bad = [f for f in p["files"] if not isinstance(f.get("path"), str) or not f["path"]]
    if bad:
        module.fail_json(msg=f"model_store_files: a file without a path: {bad[0]!r}")
    changed, extra = False, {}
    try:
        if p["lock"]:
            try:
                uid, gid = pwd.getpwnam(p["owner"]).pw_uid, grp.getgrnam(p["group"]).gr_gid
            except KeyError as exc:
                module.fail_json(msg=f"model_store_files: no such account or group: {exc}")
            strays, changed = lock_entry(
                p["dir"], p["files"], uid, gid, listed=p["listed"], apply=not module.check_mode
            )
            extra = {"strays": strays}
        elif p["walk"]:
            extra = {"strays": walk_entry(p["dir"], p["files"], p["listed"])}
        results = read_entry(p["dir"], p["files"], p["checksum"])
    except OSError as exc:
        module.fail_json(msg=f"model_store_files: {exc.filename}: {exc.strerror}")
    module.exit_json(changed=changed, results=results, **extra)


if __name__ == "__main__":
    main()
