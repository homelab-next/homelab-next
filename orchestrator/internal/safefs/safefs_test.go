// SPDX-License-Identifier: Apache-2.0

package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The package's own surface: default sentinels, labels, listing Root, and the refusals of a path
// that is not inside Root. race_test.go covers the link and swap races.

func TestDefaultSentinelsLabelAndRootList(t *testing.T) {
	root := t.TempDir()
	f := FS{Root: root}
	if err := f.WriteFile("d/a.txt", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("T"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "d"), filepath.Join(root, "dl")); err != nil {
		t.Fatal(err)
	}

	names, err := f.ListRoot()
	if err != nil || strings.Join(names, ",") != "top.txt" {
		t.Fatalf("ListRoot = %v, %v; want only the regular file", names, err)
	}
	if _, err := f.ReadFile("dl/a.txt", 0); !errors.Is(err, ErrUnsafe) || !f.IsUnsafe(err) {
		t.Fatalf("ReadFile via symlinked dir = %v, want ErrUnsafe", err)
	}
	if _, err := f.ReadFile("d/a.txt", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadFile("top.txt", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "big.txt"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadFile("big.txt", 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadFile over limit = %v, want ErrTooLarge", err)
	}
	for _, p := range []string{"", ".", "..", "../x", "a/../../x", "a\x00b"} {
		if _, err := f.ReadFile(p, 0); err == nil {
			t.Errorf("ReadFile(%q) must be refused", p)
		}
	}

	custom := errors.New("custom")
	g := FS{Root: root, Label: "box", Unsafe: custom}
	_, err = g.ReadFile("dl/a.txt", 0)
	if !errors.Is(err, custom) || errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "box") {
		t.Fatalf("custom sentinel/label not applied: %v", err)
	}
	if _, err := g.ReadFile("missing.txt", 0); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("error %v must not name the root", err)
	}
}

func TestExistsNeverFollowsALink(t *testing.T) {
	root := t.TempDir()
	f := FS{Root: root}
	if err := f.WriteFile("d/a.txt", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "d"), filepath.Join(root, "dl")); err != nil {
		t.Fatal(err)
	}
	if !f.Exists("d/a.txt") || f.Exists("d/b.txt") || f.Exists("../x") {
		t.Fatal("Exists disagrees with the tree")
	}
	if !f.Exists("dl/a.txt") {
		t.Fatal("a path through a linked component must count as existing (so it is never chosen)")
	}
	if err := f.WriteFile("dl/b.txt", []byte("B")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("WriteFile through a linked component = %v, want ErrUnsafe", err)
	}
}
