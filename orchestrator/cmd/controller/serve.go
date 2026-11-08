// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	osexec "os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/api"
	"github.com/homelab-next/homelab-next/orchestrator/internal/backends"
	"github.com/homelab-next/homelab-next/orchestrator/internal/events"
	"github.com/homelab-next/homelab-next/orchestrator/internal/metrics"
	"github.com/homelab-next/homelab-next/orchestrator/internal/profile"
	"github.com/homelab-next/homelab-next/orchestrator/internal/queue"
	execrunner "github.com/homelab-next/homelab-next/orchestrator/internal/runner/exec"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// tickInterval is how often the scheduler runs an admission pass.
const tickInterval = time.Second

// shutdownGrace bounds the API's drain at a stop; running jobs are cancelled after it.
const shutdownGrace = 30 * time.Second

// serveHooks are a test's seams; nil in the command.
type serveHooks struct {
	// listener, when set, is served instead of listening on http_addr (which NewServer still
	// checks).
	listener net.Listener
	// signals, when set, replaces the process's SIGHUP, SIGTERM and SIGINT.
	signals chan os.Signal
	// server, when set, is given the API's server before it serves.
	server func(*http.Server)
	// reloaded, when set, is called after each SIGHUP's reload with its error.
	reloaded func(error)
}

// serve is `controller serve`: load the site, open the database (refusing a pending migration
// unless --migrate-backup takes a backup first), build the pool, the runner, the scheduler and the
// API, and serve until SIGTERM or SIGINT. SIGHUP reloads the API's tokens file.
func serve(args []string, stderr io.Writer, hooks *serveHooks) int {
	if hooks == nil {
		hooks = &serveHooks{}
	}
	fs := flag.NewFlagSet("controller serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "the controller's configuration (required)")
	backup := fs.String("migrate-backup", "", "when the database needs a migration: back it up to this new file (in an owner-only directory) and migrate behind it")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "controller serve: unexpected arguments")
		return exitUsage
	}
	lg := log.New(stderr, "", log.LstdFlags|log.LUTC)

	s, problems := loadSite(*cfgPath)
	if len(problems) > 0 {
		code := exitProblem
		for _, p := range problems {
			lg.Printf("controller: %s", oneLine(p.Error()))
			if isUnreadable(p) {
				code = exitUsage
			}
		}
		return code
	}
	for _, n := range s.notes {
		lg.Printf("controller: note: %s", n)
	}
	cfg := s.cfg
	if s.runner == nil {
		lg.Printf("controller: runner.kind is not set: there is no runner to serve with")
		return exitProblem
	}
	if cfg.DBPath == "" {
		lg.Printf("controller: db_path is required")
		return exitProblem
	}
	dbPath := s.path(cfg.DBPath)

	st, releaseLock, code := openStore(dbPath, *backup, lg)
	if st == nil {
		return code
	}
	defer func() {
		st.Close()
		releaseLock()
	}()

	var sender *events.OutboxSender
	if cfg.Events.ForwarderURL != "" {
		token := ""
		if cfg.Events.TokenEnv != "" {
			token = os.Getenv(cfg.Events.TokenEnv)
		}
		var err error
		sender, err = events.NewOutboxSender(events.Config{URL: cfg.Events.ForwarderURL, BearerToken: token}, st, 0)
		if err != nil {
			lg.Printf("controller: events: %v", err)
			return exitProblem
		}
		source := cfg.Events.Source
		if source == "" {
			source = events.DefaultSource
		}
		st.EnableOutbox(queue.OutboxEventBuilder(source, cfg.Events.GatewayTagPrefix), cfg.Events.QueueSize, sender.Nudge)
	}
	if requeued, failed, err := st.ReconcileOrphans(); err != nil {
		lg.Printf("controller: reconcile the jobs a restart left: %v", err)
		return exitProblem
	} else if requeued+failed > 0 {
		lg.Printf("controller: after a restart: %d admitted jobs back to the queue, %d unfinished jobs failed", requeued, failed)
	}

	pool, err := buildPool(cfg, s.runner, st, st)
	if err != nil {
		lg.Printf("controller: backends: %v", err)
		return exitProblem
	}
	pool.Log = lg.Printf
	if err := pool.RestoreDrains(); err != nil {
		lg.Printf("controller: restore the operators' drains: %v", err)
		return exitProblem
	}
	if err := execrunner.BecomeSubreaper(); err != nil {
		lg.Printf("controller: cannot become the child subreaper (an orphaned session process escapes the reaper): %v", err)
	}

	orphanGrace := time.Duration(cfg.OrphanGraceSeconds) * time.Second
	if cfg.OrphanGraceSeconds < 0 {
		orphanGrace = -1
	}
	sch, err := queue.New(queue.Config{
		Store: st, Pool: pool, Profiles: s.profiles, Lessons: s.lessons, Contracts: s.contracts, Grants: s.catalog,
		Concurrency: max(cfg.Concurrency, 1), UsageDir: filepath.Join(filepath.Dir(dbPath), "usage"),
		TreeRoot: cfg.TreeRoot, GatewayTagPrefix: cfg.Events.GatewayTagPrefix, OrphanGrace: orphanGrace, Log: lg.Printf,
	})
	if err != nil {
		lg.Printf("controller: scheduler: %v", err)
		return exitProblem
	}

	var auth *api.Authenticator
	if cfg.APIAuth.On() {
		if auth, err = api.LoadAuthenticator(s.path(cfg.APIAuth.TokensFile)); err != nil {
			lg.Printf("controller: api_auth.tokens_file: %v", err)
			return exitProblem
		}
	}
	srv, err := api.NewServer(cfg.HTTPAddr, apiConfig(s, st, sch, pool, sender, auth, lg))
	if err != nil {
		lg.Printf("controller: api: %v", err)
		return exitProblem
	}
	if hooks.server != nil {
		hooks.server(srv)
	}
	ln := hooks.listener
	if ln == nil {
		if ln, err = net.Listen("tcp", srv.Addr); err != nil {
			lg.Printf("controller: listen: %v", err)
			return exitProblem
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := hooks.signals
	if sigs == nil {
		sigs = make(chan os.Signal, 4)
		signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(sigs)
	}
	go pool.RunHealthProber(ctx, time.Duration(cfg.BackendHealthIntervalSeconds)*time.Second)
	schedDone := make(chan struct{})
	go func() { defer close(schedDone); sch.Run(ctx, tickInterval) }()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	lg.Printf("controller: serving on %s (%d profiles, auth %v)", ln.Addr(), len(s.profiles.All()), auth != nil)

	code = exitOK
loop:
	for {
		select {
		case err := <-serveErr:
			lg.Printf("controller: api: %v", err)
			code = exitProblem
			break loop
		case sig := <-sigs:
			if sig != syscall.SIGHUP {
				lg.Printf("controller: %v: stopping", sig)
				break loop
			}
			err := errors.New("authentication is off: no tokens file to reload")
			if auth != nil {
				err = auth.Reload()
			}
			if err != nil {
				lg.Printf("controller: SIGHUP: the tokens file was not reloaded, the previous tokens stay: %v", err)
			} else {
				lg.Printf("controller: SIGHUP: the tokens file was reloaded")
			}
			if hooks.reloaded != nil {
				hooks.reloaded(err)
			}
		}
	}
	sctx, scancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		lg.Printf("controller: api shutdown: %v", err)
	}
	cancel()
	<-schedDone
	if sender != nil {
		sender.Close(sctx)
	}
	return code
}

// openStore opens the database at path. A database whose schema must change is refused
// (exitBackupRequired, naming the pending steps) unless backup names a new file: then, under the
// instance lock, the backup is written and verified, and the database migrated behind it. It
// returns the store and the release of the lock it holds, or a nil store and an exit status.
func openStore(path, backup string, lg *log.Logger) (*store.Store, func(), int) {
	none := func() {}
	pending, err := store.PendingMigrations(path)
	if err != nil {
		lg.Printf("controller: the database: %v", err)
		return nil, none, exitProblem
	}
	if len(pending) == 0 {
		if backup != "" {
			lg.Printf("controller: note: no migration is pending; --migrate-backup takes no backup")
		}
		st, err := store.Open(path)
		if err != nil {
			return nil, none, storeRefusal(err, lg)
		}
		return st, none, exitOK
	}
	if backup == "" {
		lg.Printf("controller: the database needs a migration (%s): take its backup and migrate with --migrate-backup PATH, a new file in a directory only the service's user can write; until then the controller does not start",
			strings.Join(pending, "; "))
		return nil, none, exitBackupRequired
	}
	lock, err := store.LockInstance(path)
	if err != nil {
		lg.Printf("controller: the database's instance lock: %v", err)
		return nil, none, exitProblem
	}
	if err := store.BackupForMigration(path, backup); err != nil {
		lock.Release()
		lg.Printf("controller: the migration's backup: %v", err)
		return nil, none, exitProblem
	}
	st, err := store.OpenWith(path, store.Options{MigrationBackup: backup, Lock: lock})
	if err != nil {
		lock.Release()
		return nil, none, storeRefusal(err, lg)
	}
	lg.Printf("controller: the database was migrated (%s) behind the backup %s; keep it, owner-only, until this release has run", strings.Join(pending, "; "), backup)
	return st, func() { lock.Release() }, exitOK
}

// storeRefusal logs why the store refused the database and returns the exit status.
func storeRefusal(err error, lg *log.Logger) int {
	switch {
	case errors.Is(err, store.ErrBackupRequired):
		lg.Printf("controller: %v: start once with --migrate-backup PATH", err)
		return exitBackupRequired
	case errors.Is(err, store.ErrDatabasePermissions):
		lg.Printf("controller: %v: make the database and its -wal and -shm files owner-only (chmod 0600)", err)
	default:
		lg.Printf("controller: the database: %v", err)
	}
	return exitProblem
}

// apiConfig wires the API to the scheduler, the pool and the store. The API imports neither the
// scheduler nor the pool: each route takes a function.
func apiConfig(s *site, st *store.Store, sch *queue.Scheduler, pool *backends.Policy, sender *events.OutboxSender, auth *api.Authenticator, lg *log.Logger) api.Config {
	cfg := s.cfg
	c := api.Config{
		Store: st, AgentKnown: sch.HasProfile, Auth: auth, Unauthenticated: auth == nil, Pprof: cfg.APIPprof,
		MaxUnfinishedPerCaller: cfg.APIMaxUnfinishedPerCaller,
		CancelRun:              sch.CancelRun,
		ReloadProfiles: func() error {
			reg, err := profile.LoadRegistry(s.path(cfg.ProfilesDir), s.opts)
			if err != nil {
				return err
			}
			if err := reg.CheckGrants(s.catalog); err != nil {
				return err
			}
			sch.SetProfiles(reg)
			lg.Printf("controller: profiles reloaded: %d", len(reg.All()))
			return nil
		},
		BackendEligibility: func(backend string) ([]api.BackendEligibilityEntry, error) {
			entries, err := sch.BackendEligibility(backend)
			if errors.Is(err, queue.ErrBackendNotConfigured) {
				return nil, api.ErrBackendNotFound
			}
			if err != nil {
				return nil, err
			}
			out := make([]api.BackendEligibilityEntry, len(entries))
			for i, e := range entries {
				out[i] = api.BackendEligibilityEntry(e)
			}
			return out, nil
		},
		BackendHealth: func(full bool) any {
			snap := pool.HealthSnapshot()
			if !full {
				for i := range snap {
					snap[i] = snap[i].Redacted()
				}
			}
			return snap
		},
		BackendDrain: func(name string, drain bool) (any, error) {
			status, err := pool.SetDrained(name, drain)
			if errors.Is(err, backends.ErrUnknownBackend) {
				return nil, api.ErrBackendNotFound
			}
			return status, err
		},
		BackendInFlight: func() any { return pool.InFlightSnapshot() },
		Metrics:         func(w io.Writer) error { return writeMetrics(w, sch, pool, st, sender) },
	}
	if cmd := cfg.BackendStatusCommand; len(cmd) > 0 {
		c.BackendStatus = func(ctx context.Context) ([]byte, error) { return runStatusCommand(ctx, cmd) }
	}
	return c
}

// statusTimeout and statusMaxBytes bound the backend status command.
const (
	statusTimeout  = 30 * time.Second
	statusMaxBytes = 1 << 20
)

// runStatusCommand runs the site's backend status command (argv, no shell) and returns its stdout.
func runStatusCommand(ctx context.Context, argv []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	cmd := osexec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	out := &limitedBuffer{max: statusMaxBytes}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if out.over {
		return nil, fmt.Errorf("the status command's output is larger than %d bytes", statusMaxBytes)
	}
	return out.buf, nil
}

type limitedBuffer struct {
	buf  []byte
	max  int
	over bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - len(l.buf); len(p) > room {
		l.buf = append(l.buf, p[:max(room, 0)]...)
		l.over = true
		return len(p), nil
	}
	l.buf = append(l.buf, p...)
	return len(p), nil
}

// writeMetrics writes GET /metrics: the scheduler's totals, each backend's health and load, and
// the event outbox.
func writeMetrics(w io.Writer, sch *queue.Scheduler, pool *backends.Policy, st *store.Store, sender *events.OutboxSender) error {
	m := metrics.NewWriter(w)
	c := sch.Counters()
	m.Family(metrics.Name("jobs_admitted_total"), "counter", "Jobs admitted since the controller started.")
	m.Sample(metrics.Name("jobs_admitted_total"), float64(c.Admitted))
	m.Family(metrics.Name("jobs_finished_total"), "counter", "Jobs that reached each terminal state since the controller started.")
	for _, state := range store.AllStates {
		if n, ok := c.Finished[state]; ok {
			m.Sample(metrics.Name("jobs_finished_total"), float64(n), metrics.Label{Name: "state", Value: string(state)})
		}
	}
	m.Family(metrics.Name("backend_up"), "gauge", "Whether the backend's last health probe answered (1) or not (0).")
	m.Family(metrics.Name("backend_in_flight"), "gauge", "Sessions the controller has running on the backend.")
	for _, h := range pool.HealthSnapshot() {
		m.Sample(metrics.Name("backend_up"), metrics.Bool(h.Up), metrics.Label{Name: "backend", Value: h.Backend})
		m.Sample(metrics.Name("backend_in_flight"), float64(pool.InFlight(h.Backend)), metrics.Label{Name: "backend", Value: h.Backend})
	}
	if sender != nil {
		if n, err := st.OutboxLen(); err == nil {
			m.Family(metrics.Name("outbox_events"), "gauge", "Undelivered events in the durable outbox.")
			m.Sample(metrics.Name("outbox_events"), float64(n))
		}
		m.Family(metrics.Name("outbox_dropped_total"), "counter", "Events dropped because the outbox was full.")
		m.Sample(metrics.Name("outbox_dropped_total"), float64(st.OutboxDropped()))
	}
	return m.Err()
}
