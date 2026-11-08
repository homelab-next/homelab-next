// SPDX-License-Identifier: Apache-2.0

package prompt

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

// defaultFactsPreamble opens a facts block when the profile names no facts_preamble_file.
const defaultFactsPreamble = "[deterministic-facts] The following is machine-gathered ground truth from this profile's facts command, not something you need to re-derive with your own queries. Prefer it over an ad-hoc query for the same facts, and say so when you go beyond it."

// maxFactsBytes bounds what a facts command may print; more is a failure, not a truncation, so
// a runaway command cannot fill a prompt.
const maxFactsBytes = 256 << 10

// Facts runs a facts command (an entry of the controller's facts_commands catalog: argv, no
// shell) and returns its trimmed stdout as a [deterministic-facts] block, under preamble ("" =
// the default first line): facts a script gathers once, the same way every run, instead of the
// model reconstructing them with queries of its own.
//
// The command's environment is fc.Environ(os.Environ()): PATH, HOME, LANG, LC_*, TZ and the
// names the catalog entry lists, nothing else of the controller's (its credentials stay one
// step removed from a prompt). Its stdin is empty and its stderr is discarded.
//
// It returns "" on any failure, logged: a missing program, a non-zero exit, a timeout, output
// that is empty or larger than 256 KiB. timeout and ctx (the dispatch's) bound the whole process
// group: when either ends, every process in it is killed, and the wait for an output pipe a
// descendant kept open is bounded too, so a lingering child cannot stall the dispatch.
func Facts(ctx context.Context, fc profile.FactsCommand, preamble string, timeout time.Duration) string {
	argv := fc.Argv
	if len(argv) == 0 || argv[0] == "" {
		return ""
	}
	if preamble == "" {
		preamble = defaultFactsPreamble
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = fc.Environ(os.Environ())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// the group: the command and every descendant that did not leave it
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	var out limitedBuffer
	out.max = maxFactsBytes
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		log.Printf("facts command %s: %v (the [deterministic-facts] block is left out)", argv[0], err)
		return ""
	}
	if out.over {
		log.Printf("facts command %s: more than %d bytes of output (the [deterministic-facts] block is left out)", argv[0], maxFactsBytes)
		return ""
	}
	raw := strings.TrimSpace(out.b.String())
	if raw == "" {
		log.Printf("facts command %s: no output (the [deterministic-facts] block is left out)", argv[0])
		return ""
	}
	return preamble + "\n" + raw + "\n"
}

// limitedBuffer keeps the first max bytes written and notes whether more came. It never returns
// an error, so the command is not killed by a broken pipe before the limit is judged.
type limitedBuffer struct {
	b    strings.Builder
	max  int
	over bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); len(p) > room {
		l.over = true
		if room > 0 {
			l.b.Write(p[:room])
		}
		return len(p), nil
	}
	l.b.Write(p)
	return len(p), nil
}

var _ io.Writer = (*limitedBuffer)(nil)
