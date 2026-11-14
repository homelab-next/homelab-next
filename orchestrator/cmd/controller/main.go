// SPDX-License-Identifier: Apache-2.0

// Command controller is the orchestration controller (ADR-0026): it queues agent jobs, admits them
// to the backend pool and runs each on the configured runner, behind the job API. See
// docs/orchestration-controller.md.
//
//	controller serve   --config FILE [--migrate-backup PATH]
//	controller check   --config FILE
//	controller migrate --config FILE [--site-renames FILE] [--profile-aliases FILE] [--scope FILE]
//	                   [--engine-metrics FILE] [--allow-unauthenticated-api] --out FILE
//
// Exit statuses: 0 success; 1 a problem with the configuration, its files or the service; 2 a usage
// error or an unreadable file; 3 (serve) the database needs a migration and no --migrate-backup
// was given, which the service unit lists in RestartPreventExitStatus= so it does not crash-loop.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit statuses.
const (
	exitOK             = 0
	exitProblem        = 1
	exitUsage          = 2
	exitBackupRequired = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usageText = `usage:
  controller serve   --config FILE [--migrate-backup PATH]
  controller check   --config FILE
  controller migrate --config FILE --out FILE [--site-renames FILE] [--profile-aliases FILE]
                     [--scope FILE] [--engine-metrics FILE] [--allow-unauthenticated-api]
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stderr, nil)
	case "check":
		return check(args[1:], stdout, stderr)
	case "migrate":
		return migrate(args[1:], stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usageText)
		return exitOK
	}
	fmt.Fprintf(stderr, "controller: unknown command %q\n%s", args[0], usageText)
	return exitUsage
}
