// SPDX-License-Identifier: Apache-2.0

//go:build linux

package safefs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// mountID identifies the mount an object lives on. st_dev alone does not tell a bind mount of
// another directory on the same filesystem apart, so on Linux the statx mount id is compared too.
type mountID struct {
	dev   uint64
	mnt   uint64
	hasID bool
}

func (a mountID) same(b mountID) bool {
	if a.dev != b.dev {
		return false
	}
	if a.hasID && b.hasID {
		return a.mnt == b.mnt
	}
	return true
}

func fileMount(f *os.File) (mountID, error) {
	var stx unix.Statx_t
	err := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &stx)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			var st unix.Stat_t
			if err := unix.Fstat(int(f.Fd()), &st); err != nil {
				return mountID{}, err
			}
			return mountID{dev: uint64(st.Dev)}, nil
		}
		return mountID{}, err
	}
	return mountID{
		dev:   unix.Mkdev(stx.Dev_major, stx.Dev_minor),
		mnt:   stx.Mnt_id,
		hasID: stx.Mask&unix.STATX_MNT_ID != 0,
	}, nil
}

// remoteFSMagic maps the statfs f_type of each filesystem whose namespace another host or a
// userspace server controls (the kernel's linux/magic.h and the filesystems' own sources) to a
// name for the error. virtiofs reports FUSE's magic.
var remoteFSMagic = map[int64]string{
	0x6969:     "nfs",
	0x65735546: "fuse (incl. virtiofs)",
	0x01021997: "9p",
	0x517b:     "smb",
	0xff534d42: "cifs",
	0xfe534d42: "smb2",
	0x00c36400: "ceph",
	0x5346414f: "afs",
	0x6b414653: "kafs",
	0x73757245: "coda",
	0x564c:     "ncp",
	0x0bd00bd0: "lustre",
	0x01161970: "gfs2",
	0x7461636f: "ocfs2",
	0x47504653: "gpfs",
	0x19830326: "fhgfs/beegfs",
	0xaad7aaea: "panfs",
}

// statfsType returns the filesystem magic of f. It is a variable so a test can stand in a remote
// filesystem.
var statfsType = func(f *os.File) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return int64(st.Type) & 0xffffffff, nil
}

// CheckLocalFS refuses a root on a network, cluster or FUSE filesystem unless AllowRemoteFSEnv is
// "1" (package doc, "Local filesystems only").
func CheckLocalFS(f *os.File) error {
	magic, err := statfsType(f)
	if err != nil {
		return err
	}
	name, remote := remoteFSMagic[magic]
	if !remote || os.Getenv(AllowRemoteFSEnv) == "1" {
		return nil
	}
	return fmt.Errorf("%w: root is on a %s filesystem (statfs magic %#x); the read verification holds only on a local filesystem -- set %s=1 to accept that", ErrRemoteFS, name, magic, AllowRemoteFSEnv)
}

// renameNoReplace publishes tmp as name only if name does not exist (renameat2
// RENAME_NOREPLACE). A filesystem without it falls back to link(2) then unlink.
func renameNoReplace(dir *os.Root, tmp, name string) error {
	d, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	fd := int(d.Fd())
	err = unix.Renameat2(fd, tmp, fd, name, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) {
		return linkNoReplace(dir, tmp, name)
	}
	if err != nil {
		return &os.LinkError{Op: "renameat2", Old: tmp, New: name, Err: err}
	}
	return nil
}

// VerifyOpened decides, after a read, whether the bytes read from fh may be trusted. fh was
// opened as dir/name, and an fstat right after the open found a regular file with st_nlink == 1.
// The case it closes: a hard link to an outside file placed at name before the open and removed
// right after it, so that the fstat counts one link.
//
//  1. A getdents on dir takes the directory's lock shared. unlink(2) and rename(2) hold it
//     exclusively from the moment they drop the link count until the dentry is removed, so an
//     unlink that was in flight when the caller's fstat ran has finished by now.
//  2. The kernel's path for the descriptor (/proc/self/fd/N) names the dentry it was opened
//     through, and an unlinked dentry stays unlinked (a later link makes a new one):
//     - exactly <dir>/<name>: the name was linked from the open through the fstat, so the
//     fstat's count of one counted it as the only link. The count must not have grown since;
//     - "... (deleted)": the name was unlinked or renamed over after the open. This is never
//     trusted. With links left elsewhere it is the attack itself and is refused. With no links
//     left it is not proof of innocence either: the count drops to zero also when the name was
//     a hard link to an outside file whose original was then replaced. So it returns
//     ErrReplaced, and the caller discards the bytes and opens the name again (a legitimate
//     atomic replace then reads the new content);
//     - anything else (the file was renamed elsewhere): refused.
//
// Every non-nil return means what was read is discarded. ErrReplaced (errors.Is) means "open the
// name and try again"; anything else is a refusal the caller wraps in its own sentinel.
func VerifyOpened(dir *os.Root, name string, fh *os.File) error {
	d, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err := d.ReadDir(1); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	dirPath, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(d.Fd())))
	if err != nil {
		return err
	}
	filePath, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fh.Fd())))
	if err != nil {
		return err
	}
	want := dirPath + "/" + name
	if dirPath == "/" {
		want = "/" + name
	}
	got, err := fh.Stat()
	if err != nil {
		return err
	}
	switch {
	case filePath == want:
		// linked now means linked without a break since the open, so the caller's fstat (a count
		// of one) counted this name as the only link. A count of zero here is a replace that
		// landed after the readlink: still the earlier content of this name, which is fine
		if nlink(got) > 1 {
			return errors.New("file gained a hard link while it was being read")
		}
		return nil
	case strings.HasSuffix(filePath, " (deleted)"):
		if nlink(got) != 0 {
			return errors.New("name was unlinked while the file is still linked elsewhere")
		}
		return ErrReplaced
	default:
		return errors.New("file was renamed while it was being read")
	}
}
