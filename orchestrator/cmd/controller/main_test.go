// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/homelab-next/homelab-next/orchestrator/internal/config"
	"github.com/homelab-next/homelab-next/orchestrator/internal/runner"
	"github.com/homelab-next/homelab-next/orchestrator/internal/store"
)

// examples is the repository's examples directory, read in place.
var examples = func() string {
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "examples"))
	if err != nil {
		panic(err)
	}
	return p
}()

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// digest is a token's tokens-file digest.
func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// siteConfig is a fictional site's configuration in a temporary directory: the example's
// profiles, catalog and registers read in place, a database and a tokens file of its own. edit,
// when set, changes the text before it is written.
func siteConfig(t *testing.T, edit func(string) string) (cfgPath, dir string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "api-tokens.yaml"), "tokens:\n  - {caller: operator, sha256: "+digest("token-one")+", scopes: [jobs, admin]}\n", 0o600)
	body := `db_path: state/controller.db
http_addr: ` + loopbackBind + `
runner:
  kind: exec
  exec: {argv: [/bin/true]}
backends:
  local: {name: engine-a, home: home-a, needs_interlock: false}
profiles_dir: EX/mcp/clients/orchestrator/profiles
grants_catalog: EX/mcp/clients/orchestrator/mcp_catalog.yaml
lessons_path: EX/registers/lessons
runbooks_path: EX/registers/runbooks
api_auth: {tokens_file: api-tokens.yaml}
scope:
  denied_roots: [owner]
  findings_root: notes/findings/
  shared_write: [inbox/]
  reserved_names: [operator]
`
	body = strings.ReplaceAll(body, "EX/", examples+"/")
	if edit != nil {
		body = edit(body)
	}
	cfgPath = filepath.Join(dir, "controller.yaml")
	writeFile(t, cfgPath, body, 0o600)
	return cfgPath, dir
}

// loopback is the address every test binds: the sites' API address (loopbackBind; a test serves
// on its own listener) and those listeners.
const loopback = "127.0.0.1" // no-raw-endpoint: allow the loopback address the tests bind, never a dial elsewhere

const loopbackBind = loopback + ":8088"

func replace(old, new string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, old) {
			panic("fixture edit misses: " + old)
		}
		return strings.Replace(s, old, new, 1)
	}
}

// The repository's example passes the check, as `make controller-check` runs it.
func TestCheck_TheExamplePasses(t *testing.T) {
	code, out, errs := runCmd(t, "check", "--config", filepath.Join("..", "..", "deploy", "examples", "controller.yaml"))
	if code != exitOK || !strings.Contains(out, "ok: 1 profiles") {
		t.Fatalf("check = %d\n%s%s", code, out, errs)
	}
}

// Each refusal of the check, broken once: exit 1 and one line naming it.
func TestCheck_EachRefusal(t *testing.T) {
	badProfiles := t.TempDir()
	writeFile(t, filepath.Join(badProfiles, "x.yaml"), "agent_key: x\nnot_a_key: 1\n", 0o600)
	ungranted := t.TempDir()
	writeFile(t, filepath.Join(ungranted, "x.yaml"), "agent_key: x\ngrants:\n  real: [{name: n, kind: no-such-kind}]\n  shadow: [{name: n, kind: no-such-kind}]\n", 0o600)
	openDir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		edit func(string) string
		want string
	}{
		"unknown key":          {func(s string) string { return s + "not_a_key: 1\n" }, "not_a_key"},
		"profile refused":      {replace(examples+"/mcp/clients/orchestrator/profiles", badProfiles), "profiles:"},
		"grant refused":        {replace(examples+"/mcp/clients/orchestrator/profiles", ungranted), "grants:"},
		"registers refused":    {replace("lessons_path: "+examples+"/registers/lessons", "lessons_disabled: true"), "lessons_disabled"},
		"tokens file a folder": {replace("tokens_file: api-tokens.yaml", "tokens_file: state"), "not a regular file"},
		"open lock directory": {replace("needs_interlock: false}", "needs_interlock: true}\nlock_path: "+openDir+"/interlock.lock"),
			"writable by group or others"},
		"unknown exit class": {replace("{argv: [/bin/true]}", "{argv: [/bin/true], exit_classes: {9: no-such-class}}"), "names no runner class"},
		"pool refused": {replace("needs_interlock: false}", "needs_interlock: false, load_probe_urls: [http://engine-a.example.internal/metrics]}"),
			"backends:"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := siteConfig(t, c.edit)
			code, out, errs := runCmd(t, "check", "--config", cfg)
			if code != exitProblem || !strings.Contains(out, c.want) {
				t.Fatalf("check = %d, want 1 naming %q\n%s%s", code, c.want, out, errs)
			}
			for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
				if l == "" {
					t.Error("an empty problem line")
				}
			}
		})
	}
}

// The check reads no secret: a tokens file it could not even parse passes, and nothing of it is
// printed.
func TestCheck_ReadsNoSecretFile(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	writeFile(t, filepath.Join(dir, "api-tokens.yaml"), "SECRET-MARKER: [unparsed\n", 0o600)
	code, out, errs := runCmd(t, "check", "--config", cfg)
	if code != exitOK || strings.Contains(out+errs, "SECRET-MARKER") {
		t.Fatalf("check = %d\n%s%s", code, out, errs)
	}
}

// The check opens no database: the configured one is never created.
func TestCheck_OpensNoDatabase(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	if code, out, errs := runCmd(t, "check", "--config", cfg); code != exitOK {
		t.Fatalf("check = %d\n%s%s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "controller.db")); !os.IsNotExist(err) {
		t.Fatalf("the check created the database: %v", err)
	}
}

func TestCheck_UsageAndUnreadable(t *testing.T) {
	if code, _, _ := runCmd(t, "check"); code != exitUsage {
		t.Errorf("no --config: %d", code)
	}
	if code, _, _ := runCmd(t, "check", "--config", filepath.Join(t.TempDir(), "absent.yaml")); code != exitUsage {
		t.Errorf("an absent file: %d", code)
	}
	if code, _, _ := runCmd(t, "frobnicate"); code != exitUsage {
		t.Errorf("an unknown command: %d", code)
	}
}

// A configuration without a runner loads (a migrated one has none until its runner lands) and
// says so; serve refuses it.
func TestCheck_NoRunnerIsANote(t *testing.T) {
	cfg, _ := siteConfig(t, replace("runner:\n  kind: exec\n  exec: {argv: [/bin/true]}\n", ""))
	code, out, errs := runCmd(t, "check", "--config", cfg)
	if code != exitOK || !strings.Contains(errs, "runner.kind is not set") {
		t.Fatalf("check = %d\n%s%s", code, out, errs)
	}
	var b bytes.Buffer
	if code := serve([]string{"--config", cfg}, &b, nil); code != exitProblem || !strings.Contains(b.String(), "no runner") {
		t.Fatalf("serve = %d: %s", code, b.String())
	}
}

// The migration of an old configuration: written owner-only to --out, refused over an existing
// file, and never turning authentication off unless asked.
func TestMigrate(t *testing.T) {
	dir := t.TempDir()
	old := "backend_status_script: /usr/local/libexec/status.py\nbackends:\n  local: {name: engine-a, base_url: http://engine-a.example.internal/v1, home: /h}\n"
	writeFile(t, filepath.Join(dir, "old.yaml"), old, 0o600)
	scope := filepath.Join(dir, "scope.yaml")
	writeFile(t, scope, "denied_roots: [owner]\nfindings_root: ''\nshared_write: []\nreserved_names: []\n", 0o600)
	out := filepath.Join(dir, "new.yaml")
	args := []string{"migrate", "--config", filepath.Join(dir, "old.yaml"), "--out", out, "--scope", scope}
	if code, _, errs := runCmd(t, args...); code != exitProblem || !strings.Contains(errs, "tokens_file") {
		t.Fatalf("no auth, no flag: %d %s", code, errs)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a refused migration wrote --out")
	}
	code, stdout, errs := runCmd(t, append(args, "--allow-unauthenticated-api")...)
	if code != exitOK || !strings.Contains(stdout, "written") {
		t.Fatalf("migrate = %d\n%s%s", code, stdout, errs)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("--out: %v %v", fi, err)
	}
	data, _ := os.ReadFile(out)
	for _, want := range []string{"engine-a.example.internal", "backend_status_command", "enabled: false", "denied_roots"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("migrated config lacks %q:\n%s", want, data)
		}
	}
	if code, _, _ := runCmd(t, append(args, "--allow-unauthenticated-api")...); code != exitProblem {
		t.Errorf("a second run over an existing --out: %d", code)
	}
	if code, _, _ := runCmd(t, "migrate", "--config", filepath.Join(dir, "old.yaml")); code != exitUsage {
		t.Errorf("no --out: %d", code)
	}
}

// --engine-metrics and --site-renames feed the migration; --profile-aliases migrates the profiles
// with the migrated configuration's own load options.
func TestMigrate_SiteFiles(t *testing.T) {
	dir := t.TempDir()
	profiles := filepath.Join(dir, "profiles")
	if err := os.Mkdir(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(profiles, "w.yaml"), "agent_key: w\nold_task: Watch.\n", 0o600)
	tokens := filepath.Join(dir, "t.yaml")
	writeFile(t, tokens, "tokens: []\n", 0o600)
	old := "legacy_turns: 9\nprofiles_dir: profiles\napi_auth: {tokens_file: " + tokens + "}\nbackends:\n  local: {name: engine-a, base_url: http://engine-a.example.internal, home: /h, load_probe_urls: [http://engine-a.example.internal/metrics]}\n" +
		"scope: {denied_roots: [owner], findings_root: '', shared_write: [], reserved_names: []}\n"
	writeFile(t, filepath.Join(dir, "old.yaml"), old, 0o600)
	writeFile(t, filepath.Join(dir, "renames.yaml"), "legacy_turns: runner.max_turns\n", 0o600)
	writeFile(t, filepath.Join(dir, "engine.yaml"), "load: [engine:requests_running]\n", 0o600)
	writeFile(t, filepath.Join(dir, "aliases.yaml"), "old_task: default_task_description\n", 0o600)
	out := filepath.Join(dir, "new.yaml")
	code, stdout, errs := runCmd(t, "migrate", "--config", filepath.Join(dir, "old.yaml"), "--out", out,
		"--site-renames", filepath.Join(dir, "renames.yaml"), "--engine-metrics", filepath.Join(dir, "engine.yaml"),
		"--profile-aliases", filepath.Join(dir, "aliases.yaml"))
	if code != exitOK {
		t.Fatalf("migrate = %d\n%s%s", code, stdout, errs)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "max_turns: 9") || !strings.Contains(string(data), "engine:requests_running") {
		t.Errorf("migrated:\n%s", data)
	}
	prof, _ := os.ReadFile(filepath.Join(profiles, "w.yaml"))
	if !strings.Contains(string(prof), "default_task_description: Watch.") {
		t.Errorf("the profile was not migrated:\n%s", prof)
	}
}

// serveSite starts serve on a loopback listener the test owns and returns the base URL, the
// signal channel and a channel with serve's exit status.
func serveSite(t *testing.T, cfg string, extra ...string) (base string, sigs chan os.Signal, done chan int, reloaded chan error, srv chan *http.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", loopback+":0")
	if err != nil {
		t.Fatal(err)
	}
	sigs = make(chan os.Signal, 1)
	done = make(chan int, 1)
	reloaded = make(chan error, 1)
	srv = make(chan *http.Server, 1)
	hooks := &serveHooks{listener: ln, signals: sigs, reloaded: func(err error) { reloaded <- err }, server: func(s *http.Server) { srv <- s }}
	var logs syncBuffer
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- serve(append([]string{"--config", cfg}, extra...), &logs, hooks)
	}()
	t.Cleanup(func() {
		select {
		case sigs <- syscall.SIGTERM:
		default:
		}
		// serve must have stopped before the test's directories go: wait for it, bounded
		select {
		case <-finished:
		case <-time.After(60 * time.Second):
			t.Error("serve did not stop within 60s of SIGTERM")
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	return "http://" + ln.Addr().String(), sigs, done, reloaded, srv
}

func get(t *testing.T, url, token string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// SIGHUP reloads the tokens file without a restart: the old token stops working and the new one
// works.
func TestServe_SIGHUPReloadsTheTokens(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	base, sigs, done, reloaded, _ := serveSite(t, cfg)
	if code := get(t, base+"/jobs", "token-one"); code != http.StatusOK {
		t.Fatalf("token-one before the reload: %d", code)
	}
	writeFile(t, filepath.Join(dir, "api-tokens.yaml"), "tokens:\n  - {caller: operator, sha256: "+digest("token-two")+", scopes: [jobs]}\n", 0o600)
	sigs <- syscall.SIGHUP
	if err := <-reloaded; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if code := get(t, base+"/jobs", "token-one"); code != http.StatusUnauthorized {
		t.Errorf("token-one after the reload: %d", code)
	}
	if code := get(t, base+"/jobs", "token-two"); code != http.StatusOK {
		t.Errorf("token-two after the reload: %d", code)
	}
	// a broken file keeps the tokens that were loaded
	writeFile(t, filepath.Join(dir, "api-tokens.yaml"), "tokens: []\n", 0o600)
	sigs <- syscall.SIGHUP
	if err := <-reloaded; err == nil {
		t.Error("an empty tokens file was loaded")
	}
	if code := get(t, base+"/jobs", "token-two"); code != http.StatusOK {
		t.Errorf("token-two after a refused reload: %d", code)
	}
	sigs <- syscall.SIGTERM
	if code := <-done; code != exitOK {
		t.Fatalf("serve = %d", code)
	}
}

var probeOnce sync.Once

// The binary serves api.NewServer's handler and never http.DefaultServeMux, where importing
// net/http/pprof registers the profiles: a handler on the default mux is not reachable.
func TestServe_NeverServesTheDefaultMux(t *testing.T) {
	probeOnce.Do(func() {
		http.HandleFunc("/hnx-default-mux-probe", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	})
	cfg, _ := siteConfig(t, nil)
	base, _, _, _, srv := serveSite(t, cfg)
	s := <-srv
	if s.Handler == nil || s.Handler == http.DefaultServeMux {
		t.Fatalf("the server's handler is the default mux (%v)", s.Handler)
	}
	for _, path := range []string{"/hnx-default-mux-probe", "/debug/pprof/"} {
		if code := get(t, base+path, ""); code == http.StatusTeapot || code == http.StatusOK {
			t.Errorf("%s answered %d without a token", path, code)
		}
	}
}

// The API is built with api.NewServer, which checks the bind: an unauthenticated API off loopback
// is refused (api.NewHandler alone would serve it).
func TestServe_RefusesAnUnauthenticatedNonLoopbackBind(t *testing.T) {
	cfg, _ := siteConfig(t, func(s string) string {
		s = replace("api_auth: {tokens_file: api-tokens.yaml}", "api_auth: {enabled: false}")(s)
		return replace("http_addr: "+loopbackBind, "http_addr: :8088")(s) // every interface, which an unauthenticated API must refuse
	})
	var b bytes.Buffer
	if code := serve([]string{"--config", cfg}, &b, &serveHooks{}); code != exitProblem || !strings.Contains(b.String(), "api:") {
		t.Fatalf("serve = %d: %s", code, b.String())
	}
}

// A database with a pending migration is refused with its own exit status and its steps, and no
// change; --migrate-backup takes the backup and migrates behind it.
func TestServe_APendingMigrationNeedsTheBackupFlag(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	db := filepath.Join(dir, "state", "controller.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateJob(&store.Job{RunID: "r1", AgentKey: "collector", Priority: 50, State: store.StateDone}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	dropIndex(t, db)
	var b bytes.Buffer
	if code := serve([]string{"--config", cfg}, &b, &serveHooks{}); code != exitBackupRequired || !strings.Contains(b.String(), "--migrate-backup") || !strings.Contains(b.String(), "create index") {
		t.Fatalf("serve = %d: %s", code, b.String())
	}
	if steps, _ := store.PendingMigrations(db); len(steps) == 0 {
		t.Fatal("the refused start migrated the database")
	}
	backups := t.TempDir()
	backup := filepath.Join(backups, "controller.db.bak")
	base, sigs, done, _, _ := serveSite(t, cfg, "--migrate-backup", backup)
	if code := get(t, base+"/healthz", ""); code != http.StatusOK { // serving: the migration is done
		t.Fatalf("healthz = %d", code)
	}
	sigs <- syscall.SIGTERM
	if code := <-done; code != exitOK {
		t.Fatalf("serve --migrate-backup = %d", code)
	}
	if steps, _ := store.PendingMigrations(db); len(steps) != 0 {
		t.Fatalf("still pending: %v", steps)
	}
	if fi, err := os.Stat(backup); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup: %v %v", fi, err)
	}
}

// A database readable by others is refused, with the remedy.
func TestServe_RefusesAWorldReadableDatabase(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	db := filepath.Join(dir, "state", "controller.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := os.Chmod(db, 0o644); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if code := serve([]string{"--config", cfg}, &b, &serveHooks{}); code != exitProblem || !strings.Contains(b.String(), "chmod 0600") {
		t.Fatalf("serve = %d: %s", code, b.String())
	}
}

// A lock directory others may write is refused before anything starts.
func TestServe_RefusesAnOpenLockDirectory(t *testing.T) {
	open := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o1777); err != nil {
		t.Fatal(err)
	}
	cfg, dir := siteConfig(t, replace("needs_interlock: false}", "needs_interlock: true}\nlock_path: "+open+"/interlock.lock"))
	var b bytes.Buffer
	if code := serve([]string{"--config", cfg}, &b, &serveHooks{}); code != exitProblem || !strings.Contains(b.String(), "lock_path") {
		t.Fatalf("serve = %d: %s", code, b.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "controller.db")); !os.IsNotExist(err) {
		t.Fatal("the database was opened before the lock directory was checked")
	}
}

// dropIndex removes one index from the database at path, so its next open has a migration
// pending.
func dropIndex(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP INDEX idx_jobs_state`); err != nil {
		t.Fatal(err)
	}
}

// syncBuffer is a bytes.Buffer safe for serve's goroutines and the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The event forwarder's token never reaches a session: an allowlist entry covering it is refused
// by the check, and the runner strips it whatever the list says.
func TestRunner_TheForwarderTokenNeverReachesASession(t *testing.T) {
	cfg, _ := siteConfig(t, func(s string) string {
		s = replace("exec: {argv: [/bin/true]}", "exec: {argv: [/bin/true]}\n  env_allowlist: [HNX_EV*]")(s)
		return s + "events: {token_env: HNX_EVENTS_TOKEN}\n"
	})
	code, out, errs := runCmd(t, "check", "--config", cfg)
	if code != exitProblem || !strings.Contains(out, "covers HNX_EVENTS_TOKEN") {
		t.Fatalf("check = %d\n%s%s", code, out, errs)
	}
	t.Setenv("HNX_EVENTS_TOKEN", "the-forwarder-secret")
	t.Setenv("HNX_EVENTS_OTHER", "kept")
	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Runner.Exec.Argv = []string{"/usr/bin/env"}
	r, err := newRunner(c)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background(), runner.Session{RunID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Response, "the-forwarder-secret") || !strings.Contains(res.Response, "HNX_EVENTS_OTHER=kept") {
		t.Fatalf("the session's environment:\n%s", res.Response)
	}
}

// The controller is not the child subreaper of what it starts: it waits only for the processes
// os/exec started, so an orphan reparented to it would stay a zombie. Orphans go to init, and the
// unit's KillMode ends them with the service.
func TestServe_DoesNotBecomeASubreaper(t *testing.T) {
	cfg, _ := siteConfig(t, nil)
	base, _, _, _, _ := serveSite(t, cfg)
	if code := get(t, base+"/jobs", "token-one"); code != http.StatusOK {
		t.Fatalf("serve is not up: %d", code)
	}
	var on int32
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&on)), 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if on != 0 {
		t.Fatal("serve made the process a child subreaper")
	}
}

// The signals are caught first: before the database is opened (so a migration is never ended by
// a SIGHUP's default action).
func TestServe_CatchesSignalsBeforeTheDatabase(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	db := filepath.Join(dir, "state", "controller.db")
	caught := false
	hooks := &serveHooks{signals: make(chan os.Signal, 1)}
	hooks.signalsCaught = func() {
		if _, err := os.Stat(db); !os.IsNotExist(err) {
			t.Error("the database was opened before the signals were caught")
		}
		caught = true
	}
	hooks.signals <- syscall.SIGTERM // an early stop: serve starts and stops at once
	var b bytes.Buffer
	if code := serve([]string{"--config", cfg}, &b, hooks); code != exitOK || !caught {
		t.Fatalf("serve = %d, caught %v: %s", code, caught, b.String())
	}
}

// A stop ends admission while the API still answers: no new session starts during the drain.
func TestServe_AStopEndsAdmissionBeforeTheAPI(t *testing.T) {
	cfg, _ := siteConfig(t, nil)
	ln, err := net.Listen("tcp", loopback+":0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	sigs := make(chan os.Signal, 1)
	apiUp := -1
	hooks := &serveHooks{listener: ln, signals: sigs}
	hooks.admissionStopped = func() { apiUp = get(t, base+"/jobs", "token-one") }
	done := make(chan int, 1)
	var logs syncBuffer
	go func() { done <- serve([]string{"--config", cfg}, &logs, hooks) }()
	if code := get(t, base+"/jobs", "token-one"); code != http.StatusOK {
		t.Fatalf("serve is not up: %d", code)
	}
	sigs <- syscall.SIGTERM
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("serve = %d: %s", code, logs.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("serve did not stop")
	}
	if apiUp != http.StatusOK {
		t.Fatalf("when admission stopped the API answered %d, want it still serving", apiUp)
	}
}

// An existing --out is refused before anything changes: the profiles are left as they were.
func TestMigrate_AnExistingOutChangesNothing(t *testing.T) {
	dir := t.TempDir()
	profiles := filepath.Join(dir, "profiles")
	if err := os.Mkdir(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	const prof = "agent_key: w\nold_task: Watch.\n"
	writeFile(t, filepath.Join(profiles, "w.yaml"), prof, 0o600)
	tokens := filepath.Join(dir, "t.yaml")
	writeFile(t, tokens, "tokens: []\n", 0o600)
	writeFile(t, filepath.Join(dir, "old.yaml"), "backend_status_script: /s.py\nprofiles_dir: profiles\napi_auth: {tokens_file: "+tokens+"}\n"+
		"scope: {denied_roots: [owner], findings_root: '', shared_write: [], reserved_names: []}\n", 0o600)
	writeFile(t, filepath.Join(dir, "aliases.yaml"), "old_task: default_task_description\n", 0o600)
	out := filepath.Join(dir, "new.yaml")
	writeFile(t, out, "keep\n", 0o600)
	code, _, errs := runCmd(t, "migrate", "--config", filepath.Join(dir, "old.yaml"), "--out", out, "--profile-aliases", filepath.Join(dir, "aliases.yaml"))
	if code != exitProblem {
		t.Fatalf("migrate over an existing --out = %d: %s", code, errs)
	}
	if got, _ := os.ReadFile(filepath.Join(profiles, "w.yaml")); string(got) != prof {
		t.Fatalf("a refused migration rewrote the profiles:\n%s", got)
	}
	if got, _ := os.ReadFile(out); string(got) != "keep\n" {
		t.Fatal("a refused migration changed --out")
	}
}

// The lock directory is judged by itself, never through a link, and must be the controller's
// user's or root's.
func TestCheckLockDir_NoLinkAndAnOwnOwner(t *testing.T) {
	real := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkLockDir(filepath.Join(real, "interlock.lock")); err != nil {
		t.Fatalf("an owner-only directory: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := checkLockDir(filepath.Join(link, "interlock.lock")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a linked directory = %v", err)
	}
}

func TestCheckLockDir_RefusesAForeignOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 4242, 4242); err != nil {
		t.Skip("chown to another user needs root")
	}
	if err := checkLockDir(filepath.Join(dir, "interlock.lock")); err == nil || !strings.Contains(err.Error(), "owned by uid 4242") {
		t.Fatalf("a foreign owner = %v", err)
	}
}

// Each named file that is there but wrong is a problem (exit 1); each that is missing or cannot be
// read is exit 2, whichever key names it.
func TestCheck_WrongFilesAndMissingFiles(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	writeFile(t, notADir, "x\n", 0o600)
	badCatalog := filepath.Join(t.TempDir(), "catalog.yaml")
	writeFile(t, badCatalog, "kinds: [not, a, mapping]\n", 0o600)
	cat := examples + "/mcp/clients/orchestrator/mcp_catalog.yaml"
	for name, c := range map[string]struct {
		edit func(string) string
		code int
		want string
	}{
		"catalog refused":         {replace(cat, badCatalog), exitProblem, "grants catalog"},
		"lock path not a dir":     {replace("needs_interlock: false}", "needs_interlock: true}\nlock_path: "+notADir+"/interlock.lock"), exitProblem, "not a directory"},
		"catalog missing":         {replace(cat, cat+".missing"), exitUsage, "grants catalog"},
		"contracts missing":       {func(s string) string { return s + "prompt_contracts: [missing.txt]\n" }, exitUsage, "prompt contracts"},
		"lock dir missing":        {replace("needs_interlock: false}", "needs_interlock: true}\nlock_path: /nonexistent-dir/interlock.lock"), exitUsage, "lock_path"},
		"tokens file missing":     {replace("tokens_file: api-tokens.yaml", "tokens_file: missing.yaml"), exitUsage, "api_auth.tokens_file"},
		"tokens file unopenable":  {replace("tokens_file: api-tokens.yaml", "tokens_file: api-tokens.yaml/t.yaml"), exitUsage, "api_auth.tokens_file"},
		"profiles folder missing": {replace(examples+"/mcp/clients/orchestrator/profiles", "/nonexistent-profiles"), exitUsage, "profiles"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := siteConfig(t, c.edit)
			code, out, errs := runCmd(t, "check", "--config", cfg)
			if code != c.code || !strings.Contains(out, c.want) {
				t.Fatalf("check = %d, want %d naming %q\n%s%s", code, c.code, c.want, out, errs)
			}
		})
	}
}

// --migrate-only migrates behind the backup and exits without serving: the hand migration the
// unit's comment gives ends by itself.
func TestServe_MigrateOnlyExitsAfterTheMigration(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	db := filepath.Join(dir, "state", "controller.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateJob(&store.Job{RunID: "r1", AgentKey: "collector", Priority: 50, State: store.StateDone}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	dropIndex(t, db)
	backup := filepath.Join(t.TempDir(), "controller.db.bak")
	var b bytes.Buffer
	if code := serve([]string{"--config", cfg, "--migrate-only", "--migrate-backup", backup}, &b, &serveHooks{signals: make(chan os.Signal, 1)}); code != exitOK || !strings.Contains(b.String(), "not serving") {
		t.Fatalf("serve --migrate-only = %d: %s", code, b.String())
	}
	if steps, _ := store.PendingMigrations(db); len(steps) != 0 {
		t.Fatalf("still pending: %v", steps)
	}
}

// A facts command given the event forwarder's token would put it in the prompt: refused.
func TestCheck_AFactsCommandIsNeverGivenTheForwarderToken(t *testing.T) {
	cfg, _ := siteConfig(t, func(s string) string {
		return s + "events: {token_env: HNX_EVENTS_TOKEN}\nfacts_commands:\n  disk: {argv: [/bin/df], env: [HNX_EVENTS_TOKEN]}\n"
	})
	code, out, errs := runCmd(t, "check", "--config", cfg)
	if code != exitProblem || !strings.Contains(out, "facts_commands.disk.env names HNX_EVENTS_TOKEN") {
		t.Fatalf("check = %d\n%s%s", code, out, errs)
	}
}

// A Ctrl-C during the start ends it before the database is touched: --migrate-only migrates
// nothing, rather than carrying on with the signal held for later.
func TestServe_AnInterruptDuringTheStartStopsIt(t *testing.T) {
	cfg, dir := siteConfig(t, nil)
	db := filepath.Join(dir, "state", "controller.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateJob(&store.Job{RunID: "r1", AgentKey: "collector", Priority: 50, State: store.StateDone}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	dropIndex(t, db)
	hooks := &serveHooks{signals: make(chan os.Signal, 2)}
	hooks.signals <- syscall.SIGINT
	var b bytes.Buffer
	backup := filepath.Join(t.TempDir(), "controller.db.bak")
	code := serve([]string{"--config", cfg, "--migrate-only", "--migrate-backup", backup}, &b, hooks)
	if code != exitOK || !strings.Contains(b.String(), "stopping before serving") {
		t.Fatalf("serve = %d: %s", code, b.String())
	}
	if steps, _ := store.PendingMigrations(db); len(steps) == 0 {
		t.Fatal("the interrupted start migrated the database")
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("the interrupted start took a backup")
	}
}
