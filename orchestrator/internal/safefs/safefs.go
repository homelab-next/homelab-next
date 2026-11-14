// SPDX-License-Identifier: Apache-2.0

// Package safefs reads, lists and writes files under one fixed root so that the object reached
// is the object the caller's relative path names. No symbolic link, hard link, mount or swapped
// path component can redirect an operation to something else. It is meant for tools that take a
// path from a model or another untrusted caller and must stay inside a configured tree.
//
// Cleaning the path string and checking only its last component is not enough: an intermediate
// directory that is a symbolic link escapes the root, a hard link redirects with nothing to
// detect on the name, and a component swapped between the check and the open defeats both.
//
// Every operation here:
//
//  1. opens Root as an [os.Root], which resolves nothing outside it;
//  2. walks the cleaned relative path one component at a time. Each component is Lstat-ed (a
//     symbolic link, or a non-directory before the last component, is refused), opened as an
//     [os.Root], and the opened handle is checked to be the inode that was Lstat-ed and to sit on
//     Root's own mount (st_dev, and on Linux the statx mount id, so a bind mount of another tree
//     on the same filesystem is refused too). A component swapped between the Lstat and the open
//     opens a different inode and is refused;
//  3. reads the final file from its parent's handle. The opened descriptor is fstat-ed (a
//     regular file, the inode that was Lstat-ed, st_nlink == 1, Root's mount), read, and then
//     re-verified with [VerifyOpened]. A check of the descriptor alone is not enough: a hard
//     link to an outside file can be placed at the name and removed again around the open, and
//     the fstat then reports one link. VerifyOpened proves on Linux that the name the descriptor
//     was opened through was still linked, and was the only link, when the fstat ran. A
//     descriptor whose name has since been unlinked is never trusted: if the inode is still
//     linked elsewhere the read is refused; if it has no links left it may be an ordinary atomic
//     replace, or a hard link to an outside file whose original was replaced in turn, so the
//     bytes are discarded and the name is opened again ([ErrReplaced], retried within
//     [RetryBudget]);
//  4. never opens an existing inode for writing. The content goes to a fresh temporary file
//     created with O_EXCL in the opened parent (O_EXCL follows no link and opens no existing
//     object), is synced, and is renamed over the name with [os.Root.Rename]. A rename replaces
//     the directory entry and never touches the inode it named, so a hard link planted at the
//     name at any moment cannot route the write into another file. [FS.CreateFile] is the
//     no-clobber variant (renameat2 RENAME_NOREPLACE, or link(2) then unlink where that is not
//     supported). A writer killed between the create and the rename leaves its temporary file
//     behind, so a write into a directory removes that directory's temporary files older than
//     an hour (regular files only, never through a link, at most one scan per directory per hour
//     per process).
//
// Every symbolic link is refused, including one that resolves inside Root. [os.Root] alone stops
// an escape, but callers decide scope on the path string (package pathscope), and an in-root link
// makes the string lie about where the bytes live. A regular file with more than one link is
// refused for the same reason, and so is any mount crossing below Root.
//
// Local filesystems only. The proof in step 3 rests on the local VFS: unlink and rename hold the
// parent directory's lock from the link-count drop to the dentry removal, /proc/self/fd/N names
// the dentry a descriptor was opened through, and st_nlink is the inode's own count. On a network
// or cluster filesystem another client's link, unlink or rename is not serialised by this host's
// lock and st_nlink is a cached attribute; on FUSE (virtiofs included) and 9p a server answers
// those calls however it likes. The checks would then prove nothing, so a Root on such a
// filesystem is refused when it is opened ([CheckLocalFS]) instead of being served with a check
// that silently stopped holding. Setting [AllowRemoteFSEnv] to "1" accepts that risk (for
// example one writer and no untrusted clients of the export). The refusal is Linux-only; other
// platforms are best effort.
//
// Errors never carry the absolute Root: path and link errors are unwrapped to their errno and
// labelled with the caller's relative path, clipped so a huge caller-supplied path is not echoed
// in full. Nothing that reaches a tool response names a host path.
//
// What no read-time check can see is a hard link that has become the only link to an inode: if an
// outside file is linked into the tree and the original is then replaced by a rename, the name in
// the tree is the sole link to the old content, which is indistinguishable from a copy. That is
// accepted: with fs.protected_hardlinks=1 (the kernel default) creating the link needs read and
// write access to the file, so whoever can do it could copy it anyway. The scope enforced here is
// the one given to tools; it is not a boundary against a local user who can already read the
// file. Keep protected_hardlinks on.
package safefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// ErrUnsafe is the default sentinel every refusal wraps: a symbolic link, a hard link, a mount
// crossing or a swapped component.
var ErrUnsafe = errors.New("path refused: unsafe filesystem object (symlink, hard link, mount crossing, or swapped path component)")

// ErrRemoteFS is returned when Root is on a network, cluster or FUSE filesystem (CheckLocalFS).
var ErrRemoteFS = errors.New("safefs root refused: not a local filesystem")

// AllowRemoteFSEnv, set to "1", lets a Root on such a filesystem be opened anyway.
const AllowRemoteFSEnv = "SAFEFS_ALLOW_REMOTE_FS"

// ErrReplaced is what VerifyOpened returns when the descriptor's name was unlinked or replaced
// after the open and the inode has no links left. An ordinary atomic replace looks like that, and
// so does a hard link to an outside file whose original was replaced too, so the bytes are never
// trusted: callers discard them and open the name again (see Retry).
var ErrReplaced = errors.New("file was replaced or removed while it was being read")

// RetryBudget bounds how long a read keeps opening again a name that is being replaced under it.
// It is a time budget, not a count: a writer renaming over the file in a tight loop can collide
// with several attempts in a row, and that must not surface as an error.
const RetryBudget = 250 * time.Millisecond

// ErrTooLarge is the default sentinel for ReadFile's maxBytes refusal.
var ErrTooLarge = errors.New("file larger than the allowed size")

// tmpPrefix names the temporary files of a write in flight. Listings skip it, so a concurrent
// list never shows a half-written file under its temporary name.
const tmpPrefix = ".safefs-tmp-"

// maxEchoedPath bounds the caller-supplied path echoed into any error.
const maxEchoedPath = 256

// testHook, when non-nil, is called at the named race windows: "read-opened" (the final file is
// open, not yet fstat-ed), "read-done" (its content is read, not yet re-verified),
// "write-checked" (the target name is Lstat-ed, the temporary file not yet created) and
// "write-staged" (the temporary file is written, not yet renamed). Tests use it to make the
// races deterministic; it is nil in production.
var testHook func(stage, rel string)

func hook(stage, rel string) {
	if testHook != nil {
		testHook(stage, rel)
	}
}

// FS is one fixed root. Root comes from configuration, never from the caller of a tool.
type FS struct {
	Root string
	// Label prefixes every error (the name a caller knows the tree by). Empty means "safefs".
	Label string
	// Unsafe and TooLarge, when non-nil, replace ErrUnsafe and ErrTooLarge as the wrapped
	// sentinel, so a calling package can keep its own errors.Is target.
	Unsafe   error
	TooLarge error
}

func (f FS) label() string {
	if f.Label == "" {
		return "safefs"
	}
	return f.Label
}

func (f FS) unsafeErr() error {
	if f.Unsafe != nil {
		return f.Unsafe
	}
	return ErrUnsafe
}

func (f FS) tooLargeErr() error {
	if f.TooLarge != nil {
		return f.TooLarge
	}
	return ErrTooLarge
}

// IsUnsafe reports whether err is one of this FS's unsafe-object refusals.
func (f FS) IsUnsafe(err error) bool { return errors.Is(err, f.unsafeErr()) }

func (f FS) errUnsafe(format string, a ...any) error {
	return fmt.Errorf("%w: %s", f.unsafeErr(), fmt.Sprintf(format, a...))
}

// ClipPath bounds a caller-supplied path for an error message: at most maxEchoedPath bytes, cut
// on a rune boundary, with a marker giving the full length.
func ClipPath(rel string) string {
	if len(rel) <= maxEchoedPath {
		return rel
	}
	cut := maxEchoedPath
	for cut > 0 && !utf8.RuneStart(rel[cut]) {
		cut--
	}
	return fmt.Sprintf("%s...[%d bytes]", rel[:cut], len(rel))
}

// relErr drops the absolute path a *PathError or *LinkError carries and labels the bare errno
// with the caller's relative path.
func (f FS) relErr(op, rel string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	return fmt.Errorf("%s %s %s: %w", f.label(), op, ClipPath(rel), err)
}

// split cleans rel (a leading "/" removed, then path.Clean) and returns its components. Root
// itself, anything that climbs out of it and a NUL byte are refused.
func (f FS) split(rel string) ([]string, error) {
	clean := path.Clean(strings.TrimPrefix(rel, "/"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsRune(clean, 0) {
		return nil, fmt.Errorf("%s path %q is not a path inside the %s", f.label(), ClipPath(rel), f.label())
	}
	return strings.Split(clean, "/"), nil
}

// nlink returns st_nlink, or 1 when the platform does not report it.
func nlink(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}

// dirChain holds the handles opened along a walk, and the mount identity of Root.
type dirChain struct {
	roots []*os.Root
	mount mountID
}

func (c *dirChain) close() {
	for i := len(c.roots) - 1; i >= 0; i-- {
		c.roots[i].Close()
	}
}

func (c *dirChain) last() *os.Root { return c.roots[len(c.roots)-1] }

func checkRootFS(r *os.Root) error {
	d, err := r.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return CheckLocalFS(d)
}

// handleInfo fstat-s an opened os.Root through a "." descriptor and returns its FileInfo and
// mount identity.
func handleInfo(r *os.Root) (fs.FileInfo, mountID, error) {
	d, err := r.Open(".")
	if err != nil {
		return nil, mountID{}, err
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return nil, mountID{}, err
	}
	m, err := fileMount(d)
	return fi, m, err
}

// openDirs opens Root and descends through dirs: no symbolic links, every component the inode
// that was Lstat-ed, every component on Root's mount. With create, missing components are made
// (mode 0755), for writes.
func (f FS) openDirs(dirs []string, rel string, create bool) (*dirChain, error) {
	top, err := os.OpenRoot(f.Root)
	if err != nil {
		return nil, fmt.Errorf("%s root unavailable: %w", f.label(), errors.Unwrap(err))
	}
	c := &dirChain{roots: []*os.Root{top}}
	if _, c.mount, err = handleInfo(top); err != nil {
		c.close()
		return nil, fmt.Errorf("%s root unavailable: %w", f.label(), errors.Unwrap(err))
	}
	// every component below is checked to be on Root's own mount, so checking Root's filesystem
	// covers them all
	if err := checkRootFS(top); err != nil {
		c.close()
		return nil, fmt.Errorf("%s: %w", f.label(), err)
	}
	for _, name := range dirs {
		cur := c.last()
		fi, err := cur.Lstat(name)
		if err != nil && create && errors.Is(err, fs.ErrNotExist) {
			if merr := cur.Mkdir(name, 0o755); merr != nil && !errors.Is(merr, fs.ErrExist) {
				c.close()
				return nil, f.relErr("mkdir", rel, merr)
			}
			fi, err = cur.Lstat(name)
		}
		if err != nil {
			c.close()
			return nil, f.relErr("open", rel, err)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			c.close()
			return nil, f.errUnsafe("%s has a symlink component (%s); the %s refuses to traverse symlinks", ClipPath(rel), ClipPath(name), f.label())
		}
		if !fi.IsDir() {
			c.close()
			return nil, fmt.Errorf("%s open %s: %s is not a directory", f.label(), ClipPath(rel), ClipPath(name))
		}
		next, err := cur.OpenRoot(name)
		if err != nil {
			c.close()
			return nil, f.relErr("open", rel, err)
		}
		got, m, err := handleInfo(next)
		if err != nil || !os.SameFile(fi, got) {
			next.Close()
			c.close()
			return nil, f.errUnsafe("%s: directory %s changed while it was being opened", ClipPath(rel), ClipPath(name))
		}
		if !m.same(c.mount) {
			next.Close()
			c.close()
			return nil, f.errUnsafe("%s: directory %s is a mount point (bind or other mount); the %s refuses to cross mounts", ClipPath(rel), ClipPath(name), f.label())
		}
		c.roots = append(c.roots, next)
	}
	return c, nil
}

// checkRegular applies the rules for the final object to an fstat of the opened descriptor.
func (f FS) checkRegular(rel string, pre, got fs.FileInfo) error {
	if !got.Mode().IsRegular() {
		return fmt.Errorf("%s open %s: not a regular file", f.label(), ClipPath(rel))
	}
	if pre != nil && !os.SameFile(pre, got) {
		return f.errUnsafe("%s changed while it was being opened", ClipPath(rel))
	}
	if n := nlink(got); n > 1 {
		return f.errUnsafe("%s has %d hard links; the %s refuses multiply-linked files", ClipPath(rel), n, f.label())
	}
	return nil
}

// ReadFile reads one regular file under Root from the opened descriptor and re-verifies the name
// after the read (package doc, step 3). With maxBytes > 0, a file whose fstat size exceeds it is
// refused (TooLarge) before any content is read.
func (f FS) ReadFile(rel string, maxBytes int64) ([]byte, error) {
	parts, err := f.split(rel)
	if err != nil {
		return nil, err
	}
	c, err := f.openDirs(parts[:len(parts)-1], rel, false)
	if err != nil {
		return nil, err
	}
	defer c.close()
	dir, name := c.last(), parts[len(parts)-1]
	// writes replace by rename, so a name can legitimately move to a new inode between the Lstat
	// and the open, or be replaced while it is read: both discard what was read and open the
	// name again, within RetryBudget, before the refusal is reported
	var data []byte
	err = Retry(func() (bool, error) {
		var retry bool
		data, retry, err = f.readOnce(c, dir, name, rel, maxBytes)
		return retry, err
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Retry runs attempt until it reports retry == false, or until RetryBudget has passed, and
// returns the last attempt's error. At least three attempts are always made, so a scheduling
// stall cannot use up the whole budget. Between attempts it yields, then backs off up to 1 ms,
// so a reader does not starve the writer it is waiting for.
func Retry(attempt func() (retry bool, err error)) error {
	deadline := time.Now().Add(RetryBudget)
	backoff := 10 * time.Microsecond
	for n := 1; ; n++ {
		retry, err := attempt()
		if !retry || (n >= 3 && time.Now().After(deadline)) {
			return err
		}
		if n > 2 {
			time.Sleep(backoff)
			if backoff < time.Millisecond {
				backoff *= 2
			}
		} else {
			runtime.Gosched()
		}
	}
}

func (f FS) readOnce(c *dirChain, dir *os.Root, name, rel string, maxBytes int64) (data []byte, retry bool, err error) {
	pre, err := dir.Lstat(name)
	if err != nil {
		return nil, false, f.relErr("read", rel, err)
	}
	if pre.Mode()&fs.ModeSymlink != 0 {
		return nil, false, f.errUnsafe("%s is a symlink, refusing to read through it", ClipPath(rel))
	}
	if pre.IsDir() {
		return nil, false, fmt.Errorf("%s read %s: is a directory, use list instead", f.label(), ClipPath(rel))
	}
	if !pre.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s read %s: not a regular file", f.label(), ClipPath(rel))
	}
	// O_NONBLOCK: a FIFO swapped in after the Lstat must not hang the open (the fstat below then
	// refuses it as not regular)
	fh, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, f.relErr("read", rel, err)
	}
	defer fh.Close()
	hook("read-opened", rel)
	got, err := fh.Stat()
	if err != nil {
		return nil, false, f.relErr("read", rel, err)
	}
	if got.Mode().IsRegular() && !os.SameFile(pre, got) && nlink(got) <= 1 {
		return nil, true, f.errUnsafe("%s changed while it was being opened", ClipPath(rel))
	}
	if err := f.checkRegular(rel, pre, got); err != nil {
		return nil, false, err
	}
	if m, err := fileMount(fh); err != nil || !m.same(c.mount) {
		return nil, false, f.errUnsafe("%s is on a different mount than the %s root", ClipPath(rel), f.label())
	}
	if maxBytes > 0 && got.Size() > maxBytes {
		return nil, false, fmt.Errorf("%w: %s is %d bytes (limit %d)", f.tooLargeErr(), ClipPath(rel), got.Size(), maxBytes)
	}
	limit := got.Size() + 1
	if maxBytes > 0 && limit > maxBytes+1 {
		limit = maxBytes + 1
	}
	data, err = io.ReadAll(io.LimitReader(fh, limit))
	if err != nil {
		return nil, false, f.relErr("read", rel, err)
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return nil, false, fmt.Errorf("%w: %s grew past %d bytes while being read", f.tooLargeErr(), ClipPath(rel), maxBytes)
	}
	hook("read-done", rel)
	if err := VerifyOpened(dir, name, fh); err != nil {
		if errors.Is(err, ErrReplaced) {
			return nil, true, f.errUnsafe("%s kept being replaced while it was being read; refusing what was read", ClipPath(rel))
		}
		return nil, false, f.errUnsafe("%s changed while it was being read (%v); refusing what was read", ClipPath(rel), err)
	}
	return data, false, nil
}

// ListFiles returns the names, unsorted, of the regular files directly inside the directory rel
// (no links, directories, devices or temporary files of a write in flight), walking by the rules
// above. rel must name a directory below Root; ListRoot lists Root itself.
func (f FS) ListFiles(rel string) ([]string, error) {
	parts, err := f.split(rel)
	if err != nil {
		return nil, err
	}
	return f.list(parts, rel)
}

// ListRoot is ListFiles for Root itself.
func (f FS) ListRoot() ([]string, error) { return f.list(nil, ".") }

func (f FS) list(parts []string, rel string) ([]string, error) {
	c, err := f.openDirs(parts, rel, false)
	if err != nil {
		return nil, err
	}
	defer c.close()
	d, err := c.last().Open(".")
	if err != nil {
		return nil, f.relErr("list", rel, err)
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, f.relErr("list", rel, err)
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), tmpPrefix) {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// WriteFile creates or replaces rel with content (package doc, step 4). Missing directories are
// created, never through a link; an existing target that is a link, not a regular file or
// multiply linked is refused; the bytes go to a fresh O_EXCL temporary file renamed over the
// name, so no existing inode is ever opened for writing.
func (f FS) WriteFile(rel string, content []byte) error { return f.write(rel, content, false) }

// CreateFile is WriteFile that never replaces anything: if rel exists, as anything, it returns
// an error wrapping fs.ErrExist and writes nothing. The final link is atomic (renameat2
// RENAME_NOREPLACE, or link(2) where that is not supported), so of two concurrent creators only
// one wins.
func (f FS) CreateFile(rel string, content []byte) error { return f.write(rel, content, true) }

func (f FS) write(rel string, content []byte, noClobber bool) error {
	parts, err := f.split(rel)
	if err != nil {
		return err
	}
	c, err := f.openDirs(parts[:len(parts)-1], rel, true)
	if err != nil {
		return err
	}
	defer c.close()
	dir, name := c.last(), parts[len(parts)-1]
	if strings.HasPrefix(name, tmpPrefix) {
		return fmt.Errorf("%s write %s: reserved name", f.label(), ClipPath(rel))
	}
	f.sweepStaleTemps(dir, path.Join(parts[:len(parts)-1]...))

	pre, err := dir.Lstat(name)
	switch {
	case err == nil:
		if pre.Mode()&fs.ModeSymlink != 0 {
			return f.errUnsafe("%s already exists as a symlink, refusing to write through it", ClipPath(rel))
		}
		if !pre.Mode().IsRegular() {
			return fmt.Errorf("%s write %s: exists and is not a regular file", f.label(), ClipPath(rel))
		}
		if n := nlink(pre); n > 1 {
			return f.errUnsafe("%s has %d hard links; the %s refuses multiply-linked files", ClipPath(rel), n, f.label())
		}
		if noClobber {
			return fmt.Errorf("%s write %s: %w", f.label(), ClipPath(rel), fs.ErrExist)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return f.relErr("write", rel, err)
	}
	hook("write-checked", rel)

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return f.relErr("write", rel, err)
	}
	tmp := tmpPrefix + hex.EncodeToString(nonce[:])
	fh, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return f.relErr("write", rel, err)
	}
	staged := true
	defer func() {
		if staged {
			dir.Remove(tmp)
		}
	}()
	_, err = fh.Write(content)
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return f.relErr("write", rel, err)
	}
	hook("write-staged", rel)
	if noClobber {
		err = renameNoReplace(dir, tmp, name)
	} else {
		err = dir.Rename(tmp, name)
	}
	if err != nil {
		return f.relErr("write", rel, err)
	}
	staged = false
	if d, err := dir.Open("."); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// staleTempAge: a temporary file this old was left by a writer that died between the create and
// the rename (its deferred remove never ran); a live one exists for milliseconds.
const staleTempAge = time.Hour

// swept records, per Root and directory, when sweepStaleTemps last scanned it, so a directory is
// listed at most once per staleTempAge per process rather than on every write.
var swept sync.Map

// sweepStaleTemps removes this directory's tmpPrefix files older than staleTempAge, best effort:
// errors are ignored, each entry is Lstat-ed through the verified directory handle (a link, a
// directory or anything else that is not a regular file is left alone, nothing is followed), and
// only the name is unlinked.
func (f FS) sweepStaleTemps(dir *os.Root, rel string) {
	key := f.Root + "\x00" + rel
	now := time.Now()
	if last, ok := swept.Load(key); ok && now.Sub(last.(time.Time)) < staleTempAge {
		return
	}
	swept.Store(key, now)
	d, err := dir.Open(".")
	if err != nil {
		return
	}
	defer d.Close()
	for {
		ents, err := d.ReadDir(256)
		for _, e := range ents {
			if !strings.HasPrefix(e.Name(), tmpPrefix) {
				continue
			}
			fi, err := dir.Lstat(e.Name())
			if err != nil || !fi.Mode().IsRegular() || now.Sub(fi.ModTime()) < staleTempAge {
				continue
			}
			dir.Remove(e.Name())
		}
		if err != nil || len(ents) == 0 {
			return
		}
	}
}

// linkNoReplace is the portable no-clobber publish: link(2) fails with EEXIST when the name
// exists, then the temporary name is removed. The file has two links for that instant, so a
// concurrent reader refuses it rather than reading through it.
func linkNoReplace(dir *os.Root, tmp, name string) error {
	if err := dir.Link(tmp, name); err != nil {
		return err
	}
	return dir.Remove(tmp)
}

// Exists reports whether rel exists as any filesystem object, without following a link anywhere
// along it. A path through a symbolically linked component counts as existing, so a caller
// choosing a fresh name skips it; WriteFile refuses it regardless.
func (f FS) Exists(rel string) bool {
	parts, err := f.split(rel)
	if err != nil {
		return false
	}
	c, err := f.openDirs(parts[:len(parts)-1], rel, false)
	if err != nil {
		return f.IsUnsafe(err)
	}
	defer c.close()
	_, err = c.last().Lstat(parts[len(parts)-1])
	return err == nil
}
