// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
)

// check is `controller check --config FILE` (ADR-0026 decision 17): the Go loader's judgement of a
// site's configuration, every profile it names and their grants, without opening the database,
// binding a port or reaching the network. A secret file (the tokens file) is checked to be a
// regular file this process may read; its contents are never read. Exit 0 clean, 1 one line per
// problem, 2 a usage error or an unreadable file.
func check(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controller check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "the controller's configuration (required)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "controller check: unexpected arguments")
		return exitUsage
	}
	s, problems := loadSite(*cfgPath)
	if s != nil {
		for _, n := range s.notes {
			fmt.Fprintln(stderr, "note:", n)
		}
	}
	if len(problems) == 0 {
		fmt.Fprintf(stdout, "controller config ok: %d profiles\n", len(s.profiles.All()))
		return exitOK
	}
	code := exitProblem
	for _, p := range problems {
		fmt.Fprintln(stdout, oneLine(p.Error()))
		if isUnreadable(p) {
			code = exitUsage
		}
	}
	return code
}

// oneLine keeps a problem on one line, so each line of the output is one problem.
func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			r = ' '
		}
		if r < 0x20 && r != '\t' {
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
