// SPDX-License-Identifier: Apache-2.0

package prompt

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
)

func script(t *testing.T, body string) string {
	t.Helper()
	return writeFile(t, filepath.Join(t.TempDir(), "facts.sh"), "#!/bin/sh\n"+body, 0o755)
}

func facts(argv []string, timeout time.Duration) string {
	return Facts(context.Background(), profile.FactsCommand{Argv: argv}, "", timeout)
}

func TestFacts_EveryFailureLeavesTheBlockOut(t *testing.T) {
	for name, argv := range map[string][]string{
		"no argv":         nil,
		"empty argv":      {},
		"empty program":   {""},
		"missing program": {filepath.Join(t.TempDir(), "absent")},
		"non-zero exit":   {script(t, "echo partial; exit 1\n")},
		"no output":       {script(t, "printf '  \\n\\n'\n")},
		"too much output": {script(t, "head -c 300000 /dev/zero | tr '\\0' x\n")},
	} {
		if got := facts(argv, 5*time.Second); got != "" {
			t.Errorf("%s: %q, want no block", name, got)
		}
	}
}

func TestFacts_OutputUnderThePreamble(t *testing.T) {
	sh := script(t, "printf '%s\\n' \"$1\" '{\"freshness\": {\"example\": \"2026-01-01T06:00:34Z\"}}'\n")
	if got := facts([]string{sh, "--json"}, 5*time.Second); got != defaultFactsPreamble+"\n--json\n{\"freshness\": {\"example\": \"2026-01-01T06:00:34Z\"}}\n" {
		t.Errorf("default preamble: %q", got)
	}
	got := Facts(context.Background(), profile.FactsCommand{Argv: []string{sh}}, "[deterministic-facts] Site preamble.", 5*time.Second)
	if !strings.HasPrefix(got, "[deterministic-facts] Site preamble.\n") {
		t.Errorf("profile preamble: %q", got)
	}
}

// A command that outlives its timeout is killed with its whole process group, and a descendant
// holding the output pipe open cannot keep the dispatch waiting.
func TestFacts_TimeoutKillsTheGroup(t *testing.T) {
	for name, body := range map[string]string{
		"sleeps":         "sleep 30\n",
		"child has pipe": "sleep 30 &\nsleep 30\n",
	} {
		start := time.Now()
		if got := facts([]string{script(t, body)}, 300*time.Millisecond); got != "" {
			t.Errorf("%s: %q", name, got)
		}
		if el := time.Since(start); el > 10*time.Second {
			t.Errorf("%s: returned %v after a 300ms timeout", name, el)
		}
	}
}

// The dispatch's own context stops the command long before its timeout.
func TestFacts_DispatchCancelStopsTheCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	if got := Facts(ctx, profile.FactsCommand{Argv: []string{"sleep", "30"}}, "", 30*time.Second); got != "" {
		t.Errorf("a cancelled command gave %q", got)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Errorf("the cancel took %v", el)
	}
}

// The command sees a scrubbed environment: the controller's credentials are not in it, a name
// the catalog entry lists is passed through, and nothing else beyond the base set is.
func TestFacts_EnvironmentIsScrubbed(t *testing.T) {
	t.Setenv("ZZ_CONTROLLER_ONLY", "controller-only-value")
	t.Setenv("ZZ_EXAMPLE_ENDPOINT", "https://facts.example.internal")
	t.Setenv("LC_EXAMPLE", "kept")
	argv := []string{"sh", "-c", "echo KEY=$ZZ_CONTROLLER_ONLY END=$ZZ_EXAMPLE_ENDPOINT LC=$LC_EXAMPLE; env"}
	got := Facts(context.Background(), profile.FactsCommand{Argv: argv}, "[deterministic-facts] x", 5*time.Second)
	if strings.Contains(got, "controller-only-value") || strings.Contains(got, "facts.example.internal") {
		t.Fatalf("the controller's environment reached the command: %q", got)
	}
	if !strings.Contains(got, "KEY= END= LC=kept") {
		t.Fatalf("got %q", got)
	}
	for _, line := range strings.Split(got, "\n")[2:] {
		if name, _, ok := strings.Cut(line, "="); ok {
			switch {
			case name == "PATH", name == "HOME", name == "LANG", name == "TZ", strings.HasPrefix(name, "LC_"),
				name == "PWD", name == "SHLVL", name == "_", name == "OLDPWD": // the last four sh sets itself
			default:
				t.Errorf("the command saw %s", name)
			}
		}
	}
	got = Facts(context.Background(), profile.FactsCommand{Argv: argv, Env: []string{"ZZ_EXAMPLE_ENDPOINT"}}, "", 5*time.Second)
	if !strings.Contains(got, "KEY= END=https://facts.example.internal") {
		t.Fatalf("a listed name must pass through: %q", got)
	}
}

// The command reads nothing: its stdin is empty, so one that waits for input ends at once.
func TestFacts_StdinIsEmpty(t *testing.T) {
	start := time.Now()
	if got := facts([]string{script(t, "cat; echo done\n")}, 10*time.Second); got != defaultFactsPreamble+"\ndone\n" {
		t.Errorf("got %q", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the command waited on stdin")
	}
}
