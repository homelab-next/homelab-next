// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"errors"
	"io/fs"
	"os"
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
// it. A prefix several concurrent runs share is checked as a whole: a sibling's file counts.
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
	dir, err := root.Open(prefix)
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
	cutoff := start.Add(-findingWrittenMargin)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err == nil && !info.ModTime().Before(cutoff) {
			return true, true
		}
	}
	return false, true
}
