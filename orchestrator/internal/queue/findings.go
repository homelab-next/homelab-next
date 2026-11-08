// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

// findingWrittenMargin tolerates a filesystem's coarse modification times (some keep whole
// seconds) and a small clock skew with whatever wrote the file.
const findingWrittenMargin = 5 * time.Second

// findingWritten is the findings check: whether the job's lane wrote at least one file, newer
// than its dispatch, directly in its profile's findings prefix under the tree root. A clean exit is
// not proof the job did its work, and a profile with a findings prefix files exactly one finding
// per run, even a clean one. checked is false when the check does not apply (no tree root, no
// prefix for the lane) or the directory could not be read for another reason than its absence: an
// infrastructure fault unrelated to this run never fails it. A missing directory is unwritten:
// the write tool creates it on its first write.
//
// The directory is opened through an os.Root at the tree root, so the prefix cannot lead outside
// it, and a link in place of the prefix's own directory fails the check. A file dated later than
// now (plus the margin) does not count. A prefix several runs share (concurrent runs of one
// profile, or two profiles whose scopes name one directory) is checked as a whole: a sibling's
// file counts, so a site gives each profile its own findings directory.
func (sch *Scheduler) findingWritten(prof *profile.Profile, shadow bool, start time.Time) (ok, checked bool) {
	if sch.cfg.TreeRoot == "" {
		return true, false
	}
	prefix := prof.FindingsPrefix(shadow)
	if prefix == "" {
		return true, false
	}
	root, err := os.OpenRoot(sch.cfg.TreeRoot)
	if err != nil {
		sch.logf("queue: findings check skipped: cannot open the tree root: %v", err)
		return true, false
	}
	defer root.Close()
	clean := strings.TrimSuffix(prefix, "/")
	switch fi, err := root.Lstat(clean); {
	case errors.Is(err, fs.ErrNotExist):
		return false, true
	case err == nil && !fi.IsDir():
		// A link (or anything else) in place of the directory could point the check at files
		// the run did not write: it fails the check.
		sch.logf("queue: findings check: %s is not a directory (a link?): treated as unwritten", prefix)
		return false, true
	}
	dir, err := root.Open(clean)
	if errors.Is(err, fs.ErrNotExist) {
		return false, true
	}
	if err != nil {
		sch.logf("queue: findings check skipped: cannot open %s: %v", prefix, err)
		return true, false
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		sch.logf("queue: findings check skipped: cannot read %s: %v", prefix, err)
		return true, false
	}
	cutoff, future := start.Add(-findingWrittenMargin), time.Now().Add(findingWrittenMargin)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		// A file dated in the future (a touched timestamp) proves nothing about this run.
		info, err := e.Info()
		if err == nil && !info.ModTime().Before(cutoff) && !info.ModTime().After(future) {
			return true, true
		}
	}
	return false, true
}
