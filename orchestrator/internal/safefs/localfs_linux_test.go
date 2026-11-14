// SPDX-License-Identifier: Apache-2.0

//go:build linux

package safefs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// VerifyOpened's argument holds only on a local filesystem, so a Root on a network or FUSE one is
// refused when it is opened, unless AllowRemoteFSEnv is "1".
func TestRemoteFilesystemRootIsRefused(t *testing.T) {
	root, f, _ := raceFixture(t)
	os.WriteFile(filepath.Join(root, "work/a.md"), []byte("a"), 0o644)
	if _, err := f.ReadFile("work/a.md", 0); err != nil {
		t.Fatalf("local root: %v", err)
	}
	t.Cleanup(func() { statfsType = realStatfsType })
	for magic, name := range map[int64]string{0x6969: "nfs", 0x65735546: "fuse", 0x01021997: "9p", 0xfe534d42: "smb2"} {
		statfsType = func(*os.File) (int64, error) { return magic, nil }
		if _, err := f.ReadFile("work/a.md", 0); !errors.Is(err, ErrRemoteFS) {
			t.Errorf("%s: ReadFile = %v, want ErrRemoteFS", name, err)
		}
		if _, err := f.ListFiles("work"); !errors.Is(err, ErrRemoteFS) {
			t.Errorf("%s: ListFiles = %v, want ErrRemoteFS", name, err)
		}
		if err := f.WriteFile("work/b.md", []byte("b")); !errors.Is(err, ErrRemoteFS) {
			t.Errorf("%s: WriteFile = %v, want ErrRemoteFS", name, err)
		}
	}
	t.Setenv(AllowRemoteFSEnv, "1")
	if b, err := f.ReadFile("work/a.md", 0); err != nil || string(b) != "a" {
		t.Fatalf("opted-out remote root: %q, %v", b, err)
	}
}

var realStatfsType = statfsType

// The real statfs of a local temporary directory is not in the remote table.
func TestLocalRootPassesRealStatfs(t *testing.T) {
	d, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := CheckLocalFS(d); err != nil {
		t.Fatal(err)
	}
}

// bindMount bind-mounts src at dst for the rest of the test. It needs root, so the tests that
// call it are registered as privileged in the module's skips.yml: they skip in the unprivileged
// run and must pass in CI's root run.
func bindMount(t *testing.T, src, dst string) {
	t.Helper()
	if err := exec.Command("mount", "--bind", src, dst).Run(); err != nil {
		t.Skip("bind mounts not available (needs root)")
	}
	t.Cleanup(func() { exec.Command("umount", dst).Run() })
}

// A bind mount of another directory inside Root is on the same filesystem (the same st_dev), so
// only the mount id tells it apart. Read, list and write across it are refused.
func TestBindMountedDirectoryIsRefused(t *testing.T) {
	root, f, _ := raceFixture(t)
	m := filepath.Join(root, "work/m")
	if err := os.MkdirAll(m, 0o755); err != nil {
		t.Fatal(err)
	}
	bindMount(t, filepath.Join(root, "protected"), m)
	if b, err := f.ReadFile("work/m/x.md", 0); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("read across a bind mount = %q, %v; want ErrUnsafe", b, err)
	}
	if _, err := f.ListFiles("work/m"); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("list across a bind mount = %v; want ErrUnsafe", err)
	}
	if err := f.WriteFile("work/m/y.md", []byte("x")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("write across a bind mount = %v; want ErrUnsafe", err)
	}
}

// A single bind-mounted file is caught on the opened descriptor.
func TestBindMountedFileIsRefused(t *testing.T) {
	root, f, protected := raceFixture(t)
	fm := filepath.Join(root, "work/f.md")
	if err := os.WriteFile(fm, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bindMount(t, protected, fm)
	if b, err := f.ReadFile("work/f.md", 0); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("read of a bind-mounted file = %q, %v; want ErrUnsafe", b, err)
	}
}
