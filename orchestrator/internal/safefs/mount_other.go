// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package safefs

import (
	"os"
	"syscall"
)

// mountID outside Linux is st_dev only: there is no portable mount id.
type mountID struct{ dev uint64 }

func (a mountID) same(b mountID) bool { return a.dev == b.dev }

func fileMount(f *os.File) (mountID, error) {
	fi, err := f.Stat()
	if err != nil {
		return mountID{}, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return mountID{dev: uint64(st.Dev)}, nil
	}
	return mountID{}, nil
}

func renameNoReplace(dir *os.Root, tmp, name string) error { return linkNoReplace(dir, tmp, name) }

// VerifyOpened without /proc is best effort: the name must still Lstat to the inode that was
// read, with one link, twice. The dentry-level proof is Linux-only (mount_linux.go).
func VerifyOpened(dir *os.Root, name string, fh *os.File) error {
	got, err := fh.Stat()
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		now, err := dir.Lstat(name)
		if err != nil {
			return err
		}
		if !os.SameFile(now, got) || nlink(now) != 1 {
			if nlink(got) == 0 {
				return ErrReplaced
			}
			return os.ErrInvalid
		}
	}
	if nlink(got) != 1 {
		return os.ErrInvalid
	}
	return nil
}

// CheckLocalFS is Linux-only (it reads the statfs magic); elsewhere it accepts every filesystem.
func CheckLocalFS(*os.File) error { return nil }
