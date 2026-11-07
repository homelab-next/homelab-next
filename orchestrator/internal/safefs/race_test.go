// SPDX-License-Identifier: Apache-2.0

package safefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The link and swap races. The tree has a protected file outside the caller's scope
// (protected/x.md) and a working directory inside it (work/). An attacker who can create names in
// work/ links the protected file into it and removes the link around the open; a read must never
// return the protected bytes, and a write must never change them.
//
// The deterministic tests inject the race at the exact window through testHook; the stress tests
// run a real concurrent link/unlink loop for a bounded time.

const protectedBytes = "PROTECTED ORIGINAL"

func raceFixture(t *testing.T) (root string, f FS, protected string) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"protected", "work"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	protected = filepath.Join(root, "protected/x.md")
	if err := os.WriteFile(protected, []byte(protectedBytes), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, FS{Root: root, Label: "tree"}, protected
}

func setHook(t *testing.T, h func(stage, rel string)) {
	t.Helper()
	testHook = h
	t.Cleanup(func() { testHook = nil })
}

func mustLink(t *testing.T, old, new string) {
	t.Helper()
	if err := os.Link(old, new); err != nil {
		t.Fatal(err)
	}
}

func protectedIntact(t *testing.T, protected string) {
	t.Helper()
	b, err := os.ReadFile(protected)
	if err != nil || string(b) != protectedBytes {
		t.Fatalf("protected/x.md changed: %q, %v", b, err)
	}
}

// The extra name is unlinked between the open and the fstat, which then reports one link.
func TestReadFile_HardlinkUnlinkedAfterOpenIsRefused(t *testing.T) {
	root, f, protected := raceFixture(t)
	name := filepath.Join(root, "work/f.md")
	mustLink(t, protected, name)
	setHook(t, func(stage, rel string) {
		if stage == "read-opened" {
			os.Remove(name)
		}
	})
	b, err := f.ReadFile("work/f.md", 0)
	if !errors.Is(err, ErrUnsafe) || strings.Contains(string(b), "PROTECTED") {
		t.Fatalf("read through a hard link unlinked mid-read = %q, %v; want ErrUnsafe and no bytes", b, err)
	}
}

// The extra name is unlinked at the open and linked again during the read: the name resolves to
// the right inode, but it has two links again.
func TestReadFile_HardlinkRelinkedDuringReadIsRefused(t *testing.T) {
	root, f, protected := raceFixture(t)
	name := filepath.Join(root, "work/f.md")
	mustLink(t, protected, name)
	setHook(t, func(stage, rel string) {
		switch stage {
		case "read-opened":
			os.Remove(name)
		case "read-done":
			os.Link(protected, name)
		}
	})
	b, err := f.ReadFile("work/f.md", 0)
	if !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("read = %q, %v; want ErrUnsafe", b, err)
	}
}

// The name is replaced by an innocent file after the read: what was read is no longer what the
// name names, so it is discarded.
func TestReadFile_NameReplacedDuringReadIsRefused(t *testing.T) {
	root, f, protected := raceFixture(t)
	name := filepath.Join(root, "work/f.md")
	mustLink(t, protected, name)
	setHook(t, func(stage, rel string) {
		switch stage {
		case "read-opened":
			os.Remove(name)
		case "read-done":
			os.WriteFile(name, []byte("innocent"), 0o644)
		}
	})
	if b, err := f.ReadFile("work/f.md", 0); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("read = %q, %v; want ErrUnsafe", b, err)
	}
}

func TestReadFile_UnchangedFileStillReads(t *testing.T) {
	root, f, _ := raceFixture(t)
	os.WriteFile(filepath.Join(root, "work/ok.md"), []byte("fine"), 0o644)
	calls := 0
	setHook(t, func(string, string) { calls++ })
	if b, err := f.ReadFile("work/ok.md", 0); err != nil || string(b) != "fine" {
		t.Fatalf("read = %q, %v", b, err)
	}
	if calls != 2 {
		t.Fatalf("hook fired %d times, want read-opened + read-done", calls)
	}
}

// The writer saw the target as a hard link to the protected file, and that extra name vanishes
// during the write window. Nothing may reach the protected inode.
func TestWriteFile_HardlinkRemovedDuringWriteNeverTouchesProtected(t *testing.T) {
	root, f, protected := raceFixture(t)
	name := filepath.Join(root, "work/w.md")
	mustLink(t, protected, name)
	setHook(t, func(stage, rel string) {
		if stage == "write-checked" {
			os.Remove(name)
		}
	})
	_ = f.WriteFile("work/w.md", []byte("OVERWRITE"))
	protectedIntact(t, protected)
}

// A hard link planted after the target was checked (absent), at each later window, is replaced by
// the rename: the write lands on a fresh inode and the protected file keeps its bytes.
func TestWriteFile_HardlinkPlantedAfterCheckIsReplacedNotWrittenThrough(t *testing.T) {
	for _, stage := range []string{"write-checked", "write-staged"} {
		t.Run(stage, func(t *testing.T) {
			root, f, protected := raceFixture(t)
			name := filepath.Join(root, "work/w.md")
			setHook(t, func(s, rel string) {
				if s == stage {
					os.Link(protected, name)
				}
			})
			if err := f.WriteFile("work/w.md", []byte("OVERWRITE")); err != nil {
				t.Fatal(err)
			}
			protectedIntact(t, protected)
			b, _ := os.ReadFile(name)
			fi, _ := os.Stat(name)
			if string(b) != "OVERWRITE" || nlink(fi) != 1 {
				t.Fatalf("target = %q nlink %d, want a fresh single-link file", b, nlink(fi))
			}
		})
	}
}

func TestCreateFile_NeverClobbers(t *testing.T) {
	root, f, _ := raceFixture(t)
	name := filepath.Join(root, "work/n.md")
	if err := f.CreateFile("work/n.md", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := f.CreateFile("work/n.md", []byte("second")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second CreateFile = %v, want ErrExist", err)
	}
	// a file that appears between the check and the publish is not replaced either
	setHook(t, func(stage, rel string) {
		if stage == "write-staged" {
			os.WriteFile(filepath.Join(root, "work/m.md"), []byte("theirs"), 0o644)
		}
	})
	if err := f.CreateFile("work/m.md", []byte("mine")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("CreateFile racing a creator = %v, want ErrExist", err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "work/m.md")); string(b) != "theirs" {
		t.Fatalf("racing creator's file replaced: %q", b)
	}
	if b, _ := os.ReadFile(name); string(b) != "first" {
		t.Fatalf("first file clobbered: %q", b)
	}
	assertNoTemp(t, filepath.Join(root, "work"))
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteFile_TempNotListedAndCleanedUp(t *testing.T) {
	root, f, _ := raceFixture(t)
	var listed []string
	setHook(t, func(stage, rel string) {
		if stage == "write-staged" {
			listed, _ = f.ListFiles("work")
		}
	})
	if err := f.WriteFile("work/a.md", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("in-flight temp listed: %v", listed)
	}
	assertNoTemp(t, filepath.Join(root, "work"))
	if err := f.WriteFile("work/"+tmpPrefix+"x", []byte("A")); err == nil {
		t.Fatal("reserved temp name must be refused")
	}
}

func TestErrorsClipCallerPath(t *testing.T) {
	_, f, _ := raceFixture(t)
	long := "work/" + strings.Repeat("A", 200000)
	_, err := f.ReadFile(long, 0)
	if err == nil || len(err.Error()) > 1024 {
		t.Fatalf("error for a 200KB path is %d bytes", len(err.Error()))
	}
	_, err = f.ReadFile(strings.Repeat("../", 70000), 0)
	if err == nil || len(err.Error()) > 1024 {
		t.Fatalf("split error is %d bytes", len(err.Error()))
	}
}

// --- real races, bounded so each stays within a second or two under -race ------------------

func linkFlipper(t *testing.T, protected, name string) (stop func()) {
	t.Helper()
	var done atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !done.Load() {
			os.Link(protected, name)
			os.Remove(name)
		}
	}()
	return func() { done.Store(true); wg.Wait() }
}

func TestStress_ReadNeverReturnsHardlinkedBytes(t *testing.T) {
	root, f, protected := raceFixture(t)
	stop := linkFlipper(t, protected, filepath.Join(root, "work/f.md"))
	defer stop()
	deadline := time.Now().Add(time.Second)
	leaks, served := 0, 0
	for i := 0; i < 20000 && time.Now().Before(deadline); i++ {
		b, err := f.ReadFile("work/f.md", 0)
		if err == nil {
			served++
			if string(b) == protectedBytes {
				leaks++
			}
		}
	}
	if leaks > 0 {
		t.Fatalf("%d reads returned the protected file's bytes (%d served)", leaks, served)
	}
}

func TestStress_WriteNeverReachesHardlinkedInode(t *testing.T) {
	root, f, protected := raceFixture(t)
	stop := linkFlipper(t, protected, filepath.Join(root, "work/w.md"))
	deadline := time.Now().Add(time.Second)
	for i := 0; i < 20000 && time.Now().Before(deadline); i++ {
		_ = f.WriteFile("work/w.md", []byte("OVERWRITE"))
	}
	stop()
	protectedIntact(t, protected)
}

// The check after a read must not turn an ordinary concurrent replace (WriteFile renames over the
// name) into a refusal: the reader gets the old or the new content, never an error.
func TestReadDuringConcurrentWriteFileIsNeverRefused(t *testing.T) {
	_, f, _ := raceFixture(t)
	if err := f.WriteFile("work/r.md", []byte("v0")); err != nil {
		t.Fatal(err)
	}
	var done atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			if err := f.WriteFile("work/r.md", []byte("v"+strings.Repeat("x", i%7))); err != nil {
				t.Error(err)
				return
			}
		}
		done.Store(true)
	}()
	for !done.Load() {
		b, err := f.ReadFile("work/r.md", 0)
		if err != nil || !strings.HasPrefix(string(b), "v") {
			done.Store(true)
			wg.Wait()
			t.Fatalf("read during replace = %q, %v", b, err)
		}
	}
	wg.Wait()
}

// A descriptor whose name is gone and whose inode has no links left is not proof of an innocent
// replace: the count is zero also when the name was a hard link to the protected file and the
// protected file was then atomically replaced (an ordinary save). Here the extra name is unlinked
// after the open (the fstat then counts one) and the original is replaced before the check, so
// the reader holds the old protected inode with no links. It must not be served.
func TestReadFile_DeletedDescriptorWithOriginalReplacedIsNotServed(t *testing.T) {
	root, f, protected := raceFixture(t)
	name := filepath.Join(root, "work/f.md")
	mustLink(t, protected, name)
	setHook(t, func(stage, rel string) {
		switch stage {
		case "read-opened":
			os.Remove(name)
		case "read-done":
			tmp := protected + ".new"
			if err := os.WriteFile(tmp, []byte("PROTECTED v2"), 0o644); err != nil {
				t.Error(err)
			}
			if err := os.Rename(tmp, protected); err != nil {
				t.Error(err)
			}
		}
	})
	b, err := f.ReadFile("work/f.md", 0)
	if err == nil || len(b) != 0 {
		t.Fatalf("read = %q, %v; want a refusal and no bytes", b, err)
	}
}

// The same case under real concurrency: four link/unlink goroutines and one goroutine replacing
// the original by rename.
//
// The RWMutex keeps the replacer from renaming over the original while an extra name exists. That
// case leaves the old inode linked only at work/f.md, so work/f.md then really is a single-link
// file holding those bytes (as if they had been copied there), which no read-time check can or
// should tell apart (package doc). What this holds is the verifier's own rule: a descriptor opened
// through a link that is gone before the original is replaced is never served.
func TestStress_ReadNeverServesDeletedInodeWhileOriginalIsRewritten(t *testing.T) {
	root, f, protected := raceFixture(t)
	name := filepath.Join(root, "work/f.md")
	if err := os.WriteFile(name, []byte("benign"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var mu sync.RWMutex
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				mu.RLock()
				os.Link(protected, name)
				os.Remove(name)
				mu.RUnlock()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tmp := protected + ".new"
		for !stop.Load() {
			os.WriteFile(tmp, []byte(protectedBytes), 0o644)
			mu.Lock()
			os.Rename(tmp, protected)
			mu.Unlock()
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	leaks, reads := 0, 0
	for ; reads < 40000 && time.Now().Before(deadline); reads++ {
		if b, _ := f.ReadFile("work/f.md", 0); strings.Contains(string(b), "PROTECTED") {
			leaks++
		}
	}
	stop.Store(true)
	wg.Wait()
	if leaks > 0 {
		t.Fatalf("%d of %d reads served the protected file's bytes", leaks, reads)
	}
}

// A writer that dies between creating its temporary file and the rename leaves the file behind. A
// write into the directory removes regular temporary files older than an hour, and never follows
// or removes a link or a directory with that prefix, nor one in another directory.
func TestWriteFile_SweepsStaleTempFiles(t *testing.T) {
	root, f, protected := raceFixture(t)
	dir := filepath.Join(root, "work")
	old := time.Now().Add(-2 * time.Hour)
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk(tmpPrefix + "stale")
	os.Chtimes(stale, old, old)
	fresh := mk(tmpPrefix + "fresh")
	link := filepath.Join(dir, tmpPrefix+"link")
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(protected, old, old) // the link's target is old too: still not touched
	sub := filepath.Join(dir, tmpPrefix+"dir")
	os.Mkdir(sub, 0o755)
	os.Chtimes(sub, old, old)
	other := filepath.Join(root, "protected", tmpPrefix+"elsewhere")
	os.WriteFile(other, []byte("x"), 0o644)
	os.Chtimes(other, old, old)

	if err := f.WriteFile("work/a.md", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale temp file not removed: %v", err)
	}
	for _, p := range []string{fresh, link, sub, other} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s removed: %v", filepath.Base(p), err)
		}
	}
	protectedIntact(t, protected)
}
