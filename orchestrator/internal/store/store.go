// SPDX-License-Identifier: Apache-2.0

// Package store is the controller's durable state: the jobs table, the event outbox and the
// operators' backend drains, in one SQLite database (modernc.org/sqlite, no cgo). Every lifecycle
// transition is a compare-and-swap on the row's state; a submit's checks and insert share one
// write transaction; and a schema change to an existing database runs only after a verified
// backup (backup.go).
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // the database/sql driver "sqlite"
)

// ErrDuplicateIdempotencyKey: a job already holds this idempotency key. Keys are never
// released (Job.IdempotencyKey), so the caller should look the first run up instead.
var ErrDuplicateIdempotencyKey = errors.New("job with this idempotency key already exists")

// ErrNotFound: no job has this run id.
var ErrNotFound = errors.New("job not found")

// ErrShadowBackpressure: the agent already has an unfinished shadow job. The caller skips this
// sample and tries again at its next firing.
var ErrShadowBackpressure = errors.New("agent already has an unfinished shadow job")

// ErrStateConflict: the row's state no longer equals the `from` the caller observed. The
// transition lost a race (a concurrent cancel, say) and was not applied.
var ErrStateConflict = errors.New("job state changed concurrently, transition aborted")

// Store is the controller's database.
type Store struct {
	db *sql.DB
	// lock is the instance lock OpenWith took; nil when the caller holds it.
	lock *InstanceLock
	// outbox, once EnableOutbox has run, makes lifecycle transitions enqueue their events in
	// the same transaction (outbox.go).
	outbox atomic.Pointer[outboxConfig]
	// outboxDropped counts events dropped because the outbox was full.
	outboxDropped atomic.Uint64
}

// Options are Open's choices.
type Options struct {
	// MigrationBackup is the path of a backup of this database in its current state, written
	// by BackupForMigration. Open needs it only when the database already holds data and its
	// schema has to change; it verifies the backup then (VerifyBackup), inside the migration's
	// own transaction, and ignores it otherwise.
	MigrationBackup string
	// Lock is the caller's own LockInstance(dbPath), as it must hold one while it takes the
	// backup a migration needs and opens the database behind it. OpenWith then takes no lock of
	// its own and refuses a lock that was released or is another database's; Close leaves it to
	// the caller. nil: OpenWith takes the lock itself and Close releases it.
	Lock *InstanceLock
	// AllowSharedPermissions accepts a database file that grants its group or others any
	// permission. Without it such a file is refused: the database holds every job's task and
	// output, and is protected like the service's other state (owner-only).
	AllowSharedPermissions bool
}

// ErrDatabasePermissions: the database file grants its group or others a permission.
var ErrDatabasePermissions = errors.New("store: the database file is readable or writable beyond its owner")

// Open opens the database at dbPath with no options: a new database is created, a current one
// opened, and one that needs a migration refused (ErrBackupRequired).
func Open(dbPath string) (*Store, error) {
	return OpenWith(dbPath, Options{})
}

// OpenWith opens (creating if absent) the SQLite database at dbPath in WAL mode and brings its
// schema up to date, in one write transaction: a new database gets the whole schema; an existing
// one gets the steps PendingMigrations lists, and only once opts.MigrationBackup verifies against
// it, so a failed migration leaves the database as it was and the backup as its copy. Opening
// the same file again after a restart is how jobs survive one.
//
// It holds the instance lock (LockInstance) for the life of the Store, or checks that the lock the
// caller gives (opts.Lock) is held and is this database's. A new database file is created owner-only (0600) before SQLite opens
// it, and SQLite gives its -wal and -shm files the same mode; an existing one that grants its
// group or others anything is refused unless opts.AllowSharedPermissions.
//
// Every write transaction on the handle begins IMMEDIATE (_txlock=immediate): it takes the write
// lock up front. A deferred transaction takes it only at its first write, and under concurrent
// writers its read snapshot can go stale in between (SQLITE_BUSY_SNAPSHOT), which busy_timeout
// does not retry; an IMMEDIATE one waits on the lock instead, which busy_timeout does.
func OpenWith(dbPath string, opts Options) (s *Store, err error) {
	if strings.ContainsAny(dbPath, "?#") {
		return nil, fmt.Errorf("store: database path %q holds '?' or '#', which SQLite's file name parsing treats as special", dbPath)
	}
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	var lock *InstanceLock
	if opts.Lock != nil {
		if err := opts.Lock.heldFor(abs); err != nil {
			return nil, err
		}
	} else {
		if lock, err = LockInstance(abs); err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				lock.Release()
			}
		}()
	}
	if err := ensureDatabaseFile(abs, opts.AllowSharedPermissions); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", abs+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := prepareSchema(db, abs, opts); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, lock: lock}, nil
}

// ensureDatabaseFile creates a missing database file owner-only, so that SQLite never creates it
// (or its -wal and -shm files, which take its mode) under the process umask, and refuses an
// existing one, or an existing side file, that grants its group or others anything.
func ensureDatabaseFile(path string, allowShared bool) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := f.Close(); err != nil {
			return fmt.Errorf("store: create %s: %w", path, err)
		}
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("store: create %s: %w", path, err)
	}
	if allowShared {
		return nil
	}
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) && p != path {
			continue
		}
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return fmt.Errorf("%w: %s is %v; chmod it 0600 (and run the service with UMask=0077), or set AllowSharedPermissions", ErrDatabasePermissions, p, perm)
		}
	}
	return nil
}

func prepareSchema(db *sql.DB, dbPath string, opts Options) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin schema transaction: %w", err)
	}
	defer tx.Rollback()
	st, err := inspectSchema(tx)
	if err != nil {
		return err
	}
	if st.empty {
		if err := createSchema(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	steps, err := planMigration(st)
	if err != nil {
		return err
	}
	if len(steps) == 0 {
		return nil
	}
	if opts.MigrationBackup == "" {
		return fmt.Errorf("%w: %s needs: %s", ErrBackupRequired, dbPath, describeSteps(steps))
	}
	backup, err := filepath.Abs(opts.MigrationBackup)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := checkBackupPaths(dbPath, backup); err != nil {
		return err
	}
	if err := verifyBackupAgainst(tx, dbPath, backup, nil); err != nil {
		return err
	}
	if err := applyMigration(tx, steps); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migration: %w", err)
	}
	return nil
}

// PendingMigrations lists, without changing anything, the schema changes Open would make to
// the existing database at dbPath; none for a current database, and none for a missing file
// (Open creates a new one, which needs no backup). It refuses a database Open would refuse.
func PendingMigrations(dbPath string) ([]string, error) {
	if !fileExists(dbPath) {
		return nil, nil
	}
	db, err := openPlain(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	st, err := inspectSchema(db)
	if err != nil {
		return nil, err
	}
	if st.empty {
		return nil, nil
	}
	steps, err := planMigration(st)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.describe
	}
	return out, nil
}

func describeSteps(steps []migrationStep) string {
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.describe
	}
	return strings.Join(names, "; ")
}

// Close closes the database and releases the instance lock OpenWith took (never one the caller
// gave it).
func (s *Store) Close() error {
	err := s.db.Close()
	if uerr := s.lock.Release(); err == nil {
		err = uerr
	}
	s.lock = nil
	return err
}

// CreateJob persists a new job and assigns its Seq inside the same write transaction, so Seq is
// increasing and never reused without a sequence table. It refuses, creating nothing:
//   - a non-empty IdempotencyKey already in use (ErrDuplicateIdempotencyKey);
//   - a shadow job while its agent has an unfinished shadow job (ErrShadowBackpressure); the
//     check and the insert share the transaction, so concurrent submitters on separate
//     connections cannot exceed one;
//   - a job with RetryOfRunID whose parent already has a retry or is one (a *ResubmitRefusal):
//     a run is retried at most once, by the scheduler or a caller alike.
func (s *Store) CreateJob(j *Job) error {
	return s.createJob(j, nil)
}

func (s *Store) createJob(j *Job, check *ResubmitCheck) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := insertJobTx(tx, j, check); err != nil {
		return err
	}
	return tx.Commit()
}

// insertJobTx is createJob's checks and insert inside the caller's transaction.
func insertJobTx(tx *sql.Tx, j *Job, check *ResubmitCheck) error {
	if len(j.IdempotencyKey) > MaxIdempotencyKeyLen {
		return ErrIdempotencyKeyTooLong
	}
	if j.IdempotencyKey != "" {
		owner, err := keyOwner(tx, j, check)
		if err != nil {
			return err
		}
		if _, err := findByKey(tx, owner, j.IdempotencyKey); err == nil {
			return ErrDuplicateIdempotencyKey
		} else if !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("check idempotency key: %w", err)
		}
	}
	if j.RetryOfRunID != "" {
		if err := checkResubmit(tx, j, check); err != nil {
			return err
		}
	}
	if j.Shadow {
		var active bool
		if err := tx.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM jobs WHERE agent_key = ? AND shadow = 1 AND state IN (?, ?, ?, ?)
		)`, j.AgentKey, StateQueued, StateAdmitted, StateRunning, StateAwaitingInference).Scan(&active); err != nil {
			return fmt.Errorf("check shadow backpressure: %w", err)
		}
		if active {
			return ErrShadowBackpressure
		}
	}
	var maxSeq sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(seq) FROM jobs`).Scan(&maxSeq); err != nil {
		return fmt.Errorf("compute next seq: %w", err)
	}
	j.Seq = maxSeq.Int64 + 1

	_, err := tx.Exec(`
		INSERT INTO jobs (
			run_id, agent_key, profile_id, profile_revision, priority, seq, state,
			shadow, local_attempts, cloud_fallback_used, local_failed_reason,
			session_id, idempotency_key, created_at, started_at, deadline,
			finished_at, result_path, evidence_refs, task_description, response_body,
			retry_of_run_id, submitted_by, resubmits, parent_profile_revision
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.RunID, j.AgentKey, j.ProfileID, j.ProfileRevision, j.Priority, j.Seq, string(j.State),
		boolToInt(j.Shadow), j.LocalAttempts, boolToInt(j.CloudFallbackUsed), j.LocalFailedReason,
		j.SessionID, nullIfEmpty(j.IdempotencyKey), j.CreatedAt.Format(time.RFC3339Nano),
		timePtrToString(j.StartedAt), timePtrToString(j.Deadline), timePtrToString(j.FinishedAt),
		j.ResultPath, j.EvidenceRefs, j.TaskDescription, nullIfEmpty(j.ResponseBody),
		nullIfEmpty(j.RetryOfRunID), nullIfEmpty(j.SubmittedBy), j.Resubmits, nullIfEmpty(j.ParentProfileRevision),
	)
	if err != nil {
		if j.IdempotencyKey != "" && strings.Contains(err.Error(), "idempotency") {
			return ErrDuplicateIdempotencyKey // the unique index, below the check above
		}
		if j.RetryOfRunID != "" && strings.Contains(err.Error(), "retry_of_run_id") {
			// The unique index. Unreachable while every writer takes the write lock first, as
			// above; kept as the last line of defence.
			return &ResubmitRefusal{Kind: RefusalConflict, Reason: RefuseAlreadyRetried,
				Detail: "run " + j.RetryOfRunID + " was already retried"}
		}
		return fmt.Errorf("insert job: %w", err)
	}
	return nil
}

// MaxIdempotencyKeyLen bounds an idempotency key, in bytes.
const MaxIdempotencyKeyLen = 128

// ErrIdempotencyKeyTooLong: the key is longer than MaxIdempotencyKeyLen.
var ErrIdempotencyKeyTooLong = fmt.Errorf("idempotency key longer than %d bytes", MaxIdempotencyKeyLen)

// keyOwner is the submitter j's idempotency key is scoped to: the submitter the row will be
// stored with. A caller's resubmit is stored under its parent's owner (checkCallerResubmit), so
// its key is looked up there too, once the caller may see the parent; when it may not, the
// caller's own name is used and checkResubmit refuses the resubmit as an unknown run.
func keyOwner(tx *sql.Tx, j *Job, check *ResubmitCheck) (string, error) {
	if j.RetryOfRunID == "" || check == nil {
		return j.SubmittedBy, nil
	}
	var owner sql.NullString
	err := tx.QueryRow(`SELECT submitted_by FROM jobs WHERE run_id = ?`, j.RetryOfRunID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return j.SubmittedBy, nil
	}
	if err != nil {
		return "", fmt.Errorf("read retry parent: %w", err)
	}
	if check.MayAccess != nil && !check.MayAccess(owner.String) {
		return j.SubmittedBy, nil
	}
	return owner.String, nil
}

func findByKey(q queryer, submittedBy, key string) (*Job, error) {
	j, err := scanJob(q.QueryRow(`SELECT `+jobColumns+` FROM jobs WHERE COALESCE(submitted_by, '') = ? AND idempotency_key = ?`, submittedBy, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}

// FindByIdempotencyKey returns the job submittedBy submitted with key ("" for a job submitted
// with the API's auth off), or ErrNotFound: what a replayed submit should be answered with.
func (s *Store) FindByIdempotencyKey(submittedBy, key string) (*Job, error) {
	if key == "" {
		return nil, ErrNotFound
	}
	return findByKey(s.db, submittedBy, key)
}

// GetJob returns the job runID, or ErrNotFound.
func (s *Store) GetJob(runID string) (*Job, error) {
	j, err := scanJob(s.db.QueryRow(`SELECT `+jobColumns+` FROM jobs WHERE run_id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get job %s: %w", runID, err)
	}
	return j, nil
}

// admissionColumns is jobColumns with the columns admission never reads sent as NULL: the
// answer, the failure reason, the auxiliary usage and the evidence. A queued row holds no answer
// anyway; the task stays (admission's duplicate check and the dispatch read it), bounded at submit.
var admissionColumns = strings.NewReplacer(
	"local_failed_reason,", "NULL,", "response_body,", "NULL,", "aux_by_task,", "NULL,", "evidence_refs,", "NULL,",
).Replace(jobColumns)

// ListForAdmission is ListByState with admissionColumns: what a scheduler pass and its executors
// read of the queue, without the text they never use.
func (s *Store) ListForAdmission(state State) ([]*Job, error) {
	rows, err := s.db.Query(`SELECT `+admissionColumns+` FROM jobs WHERE state = ? ORDER BY seq ASC`, string(state))
	if err != nil {
		return nil, fmt.Errorf("list for admission: %w", err)
	}
	return collectJobs(rows, "list for admission "+string(state))
}

// ListByState returns every job in state, oldest submission first.
func (s *Store) ListByState(state State) ([]*Job, error) {
	rows, err := s.db.Query(`SELECT `+jobColumns+` FROM jobs WHERE state = ? ORDER BY seq ASC`, string(state))
	if err != nil {
		return nil, fmt.Errorf("list by state: %w", err)
	}
	return collectJobs(rows, "list by state "+string(state))
}

func collectJobs(rows *sql.Rows, what string) ([]*Job, error) {
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan row: %w", what, err)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return out, nil
}

// jobColumns is the scanJob column list, in scanJob's order. The last one is the run that
// retries this one, derived from the retry's retry_of_run_id.
const jobColumns = `run_id, agent_key, profile_id, profile_revision, priority, seq, state,
		shadow, local_attempts, cloud_fallback_used, local_failed_reason,
		session_id, idempotency_key, created_at, started_at, deadline,
		finished_at, result_path, evidence_refs, task_description, response_body,
		local_backend_used, input_tokens, output_tokens, reasoning_tokens, api_calls, retry_of_run_id,
		completed, failed, turn_exit_reason, cost_usd, cache_read_tokens, aux_by_task,
		injected_lessons, injected_runbooks, prompt_sha256, prompt_bytes, attempts, submitted_by,
		failure_class, resubmits, parent_profile_revision, model,
		(SELECT c.run_id FROM jobs c WHERE c.retry_of_run_id = jobs.run_id ORDER BY c.seq ASC LIMIT 1)`

// MaxListLimit bounds one ListJobs page.
const MaxListLimit = 500

// ListFilter selects jobs for ListJobs. A zero field does not filter.
type ListFilter struct {
	State    State
	AgentKey string
	// SubmittedBy, when not empty, keeps only that caller's jobs.
	SubmittedBy string
	// BeforeSeq, when > 0, keeps only jobs with seq < BeforeSeq: the cursor of the next, older
	// page.
	BeforeSeq int64
	// Limit is clamped to [1, MaxListLimit].
	Limit int
}

// ListJobs returns jobs newest first (seq descending). seq is unique and assigned in submission
// order, so the order is stable across calls and a BeforeSeq cursor never skips or repeats a job.
func (s *Store) ListJobs(f ListFilter) ([]*Job, error) {
	limit := min(max(f.Limit, 1), MaxListLimit)
	q := `SELECT ` + jobColumns + ` FROM jobs WHERE 1=1`
	var args []any
	if f.State != "" {
		q += ` AND state = ?`
		args = append(args, string(f.State))
	}
	if f.AgentKey != "" {
		q += ` AND agent_key = ?`
		args = append(args, f.AgentKey)
	}
	if f.SubmittedBy != "" {
		q += ` AND submitted_by = ?`
		args = append(args, f.SubmittedBy)
	}
	if f.BeforeSeq > 0 {
		q += ` AND seq < ?`
		args = append(args, f.BeforeSeq)
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	return collectJobs(rows, "list jobs")
}

// UpdateState is a compare-and-swap transition: the row changes only while its state still
// equals `from`, and ErrStateConflict says it did not. The caller passes the state it last
// observed and has already checked with CanTransition. Entering running stamps started_at (once),
// and entering a terminal state stamps finished_at.
func (s *Store) UpdateState(runID string, from, to State) error {
	return s.UpdateStateClass(runID, from, to, "")
}

// UpdateStateClass is UpdateState that also records class (a Failure* constant) as the run's
// failure_class in the same statement, so the failed event the outbox builds in that transaction
// carries it. An empty class leaves failure_class alone.
func (s *Store) UpdateStateClass(runID string, from, to State, class string) error {
	if ob := s.outbox.Load(); ob != nil && emitsEvent(from, to) {
		return s.updateStateWithEvent(ob, runID, from, to, class)
	}
	res, err := execStateUpdate(s.db, runID, from, to, class)
	if err != nil {
		return fmt.Errorf("update state %s to %s: %w", runID, to, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update state %s to %s: rows affected: %w", runID, to, err)
	}
	if n == 0 {
		return ErrStateConflict
	}
	return nil
}

func execStateUpdate(db execer, runID string, from, to State, class string) (sql.Result, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	switch to {
	case StateRunning:
		return db.Exec(`UPDATE jobs SET state = ?, started_at = COALESCE(started_at, ?) WHERE run_id = ? AND state = ?`, string(to), now, runID, string(from))
	case StateDone, StateFailed, StateBudgetKilled, StateCancelled:
		if class != "" {
			return db.Exec(`UPDATE jobs SET state = ?, finished_at = ?, failure_class = ? WHERE run_id = ? AND state = ?`, string(to), now, class, runID, string(from))
		}
		return db.Exec(`UPDATE jobs SET state = ?, finished_at = ? WHERE run_id = ? AND state = ?`, string(to), now, runID, string(from))
	default:
		return db.Exec(`UPDATE jobs SET state = ? WHERE run_id = ? AND state = ?`, string(to), runID, string(from))
	}
}

// UpdateExecutionResult records how the run's attempt chain went: whether it fell back to the
// cloud, its local attempts and the last local failure, and what the run produced (responseBody;
// "" stores NULL, for a run with nothing to keep).
func (s *Store) UpdateExecutionResult(runID string, usedCloud bool, localAttempts int, localFailedReason, responseBody string) error {
	_, err := s.db.Exec(
		`UPDATE jobs SET cloud_fallback_used = ?, local_attempts = ?, local_failed_reason = ?, response_body = ? WHERE run_id = ?`,
		boolToInt(usedCloud), localAttempts, localFailedReason, nullIfEmpty(responseBody), runID,
	)
	return err
}

// BackendThroughput is a backend's output rate over its recent finished jobs.
type BackendThroughput struct {
	Backend           string  `json:"backend"`
	TokensPerSecond   float64 `json:"tokens_per_second"`
	SampleCount       int     `json:"sample_count"`
	TotalOutputTokens int     `json:"total_output_tokens"`
	TotalDurationSecs float64 `json:"total_duration_seconds"`
}

// BackendThroughput is the output rate the backend gave its most recent `limit` (default 20)
// done jobs, as the jobs experienced it: sum(output_tokens) / sum(wall-clock seconds), queueing
// and tool time included, so it is not the engine's raw decode speed. It is a weighted average,
// never an average of per-job rates, which one short fast job would dominate. A job with no
// recorded output tokens or with no positive duration is left out, never counted as a zero
// sample; with no sample at all the rate is 0 and the error nil.
func (s *Store) BackendThroughput(backendName string, limit int) (*BackendThroughput, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(
		`SELECT output_tokens, started_at, finished_at FROM jobs
		 WHERE local_backend_used = ? AND state = ? AND output_tokens > 0
		   AND started_at IS NOT NULL AND finished_at IS NOT NULL
		 ORDER BY seq DESC LIMIT ?`,
		backendName, string(StateDone), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("backend throughput: %w", err)
	}
	defer rows.Close()
	out := &BackendThroughput{Backend: backendName}
	var total float64
	for rows.Next() {
		var outputTokens int
		var startedAt, finishedAt string
		if err := rows.Scan(&outputTokens, &startedAt, &finishedAt); err != nil {
			return nil, fmt.Errorf("backend throughput: scan: %w", err)
		}
		start, err1 := time.Parse(time.RFC3339Nano, startedAt)
		finish, err2 := time.Parse(time.RFC3339Nano, finishedAt)
		if err1 != nil || err2 != nil {
			continue
		}
		dur := finish.Sub(start).Seconds()
		if dur <= 0 {
			continue
		}
		out.SampleCount++
		out.TotalOutputTokens += outputTokens
		total += dur
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backend throughput: %w", err)
	}
	out.TotalDurationSecs = total
	if total > 0 {
		out.TokensPerSecond = float64(out.TotalOutputTokens) / total
	}
	return out, nil
}

// QueueSummaryEntry is one (agent key, state) count of QueueSummary.Active. A slice of these,
// not a map, so the JSON order is stable.
type QueueSummaryEntry struct {
	AgentKey string `json:"agent_key"`
	State    string `json:"state"`
	Count    int    `json:"count"`
}

// QueueSummary is the queue at a glance.
type QueueSummary struct {
	// ByState counts every job by state, whatever its agent.
	ByState map[string]int `json:"by_state"`
	// Active breaks queued and running jobs down by agent key.
	Active []QueueSummaryEntry `json:"active"`
	// OldestQueuedRunID and OldestQueuedAgeSeconds name the longest-waiting queued job; zero
	// when nothing is queued. A large age with nothing running says the queue is stuck.
	OldestQueuedRunID      string  `json:"oldest_queued_run_id,omitempty"`
	OldestQueuedAgeSeconds float64 `json:"oldest_queued_age_seconds,omitempty"`
}

// QueueSummary counts the jobs by state, breaks the active ones down by agent and names the
// oldest queued one.
func (s *Store) QueueSummary() (*QueueSummary, error) {
	out := &QueueSummary{ByState: make(map[string]int)}
	rows, err := s.db.Query(`SELECT state, count(*) FROM jobs GROUP BY state`)
	if err != nil {
		return nil, fmt.Errorf("queue summary: by state: %w", err)
	}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("queue summary: by state: %w", err)
		}
		out.ByState[state] = count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("queue summary: by state: %w", err)
	}
	rows.Close()

	rows, err = s.db.Query(`SELECT agent_key, state, count(*) FROM jobs WHERE state IN (?, ?) GROUP BY agent_key, state`,
		string(StateQueued), string(StateRunning))
	if err != nil {
		return nil, fmt.Errorf("queue summary: active: %w", err)
	}
	for rows.Next() {
		var e QueueSummaryEntry
		if err := rows.Scan(&e.AgentKey, &e.State, &e.Count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("queue summary: active: %w", err)
		}
		out.Active = append(out.Active, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("queue summary: active: %w", err)
	}
	rows.Close()

	var runID, createdAt string
	err = s.db.QueryRow(`SELECT run_id, created_at FROM jobs WHERE state = ? ORDER BY seq ASC LIMIT 1`,
		string(StateQueued)).Scan(&runID, &createdAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("queue summary: oldest queued: %w", err)
	}
	if err == nil {
		if t, perr := time.Parse(time.RFC3339Nano, createdAt); perr == nil {
			out.OldestQueuedRunID = runID
			out.OldestQueuedAgeSeconds = time.Since(t).Seconds()
		}
	}
	return out, nil
}

// TokenCounts are the usage report's main counters, summed over a run's attempts. nil = the
// report did not carry the key: stored as NULL (unknown), never as 0.
type TokenCounts struct {
	InputTokens     *int
	OutputTokens    *int
	ReasoningTokens *int
	APICalls        *int
}

// UpdateTelemetry records the backend a run landed on and its token counts, once the attempt
// chain returns, failed or not. It is best effort: the caller logs an error and never fails the
// job over it.
func (s *Store) UpdateTelemetry(runID, localBackendUsed string, c TokenCounts) error {
	_, err := s.db.Exec(
		`UPDATE jobs SET local_backend_used = ?, input_tokens = ?, output_tokens = ?, reasoning_tokens = ?, api_calls = ? WHERE run_id = ?`,
		nullIfEmpty(localBackendUsed), intPtrToNull(c.InputTokens), intPtrToNull(c.OutputTokens),
		intPtrToNull(c.ReasoningTokens), intPtrToNull(c.APICalls), runID,
	)
	return err
}

// UsageFields is the part of the runner's usage report beyond TokenCounts. A nil pointer is a key
// the report lacked, kept apart from a real false or 0: a gate on Completed must never fire on a
// report without it, and a usage record must never show a missing cost as zero.
type UsageFields struct {
	Completed       *bool
	Failed          *bool
	TurnExitReason  string
	CostUSD         *float64
	CacheReadTokens *int
	// CacheReadUnknown says the report's cache-read count is not to be trusted for this run (an
	// engine that reports 0 when it does not count cache hits at all), so NULL is stored instead
	// of a 0 that reads as "no cache hits". CacheReadTokens is ignored when it is set.
	CacheReadUnknown bool
	AuxByTaskJSON    string
	// SessionID, when not empty, is stored as the run's session id; empty leaves the stored one.
	SessionID string
	// Model is the model the last attempt asked its backend for; "" = unknown.
	Model string
}

// UpdateUsageFields records UsageFields, best effort like UpdateTelemetry.
func (s *Store) UpdateUsageFields(runID string, u UsageFields) error {
	var cacheRead any
	if !u.CacheReadUnknown {
		cacheRead = intPtrToNull(u.CacheReadTokens)
	}
	_, err := s.db.Exec(
		`UPDATE jobs SET completed = ?, failed = ?, turn_exit_reason = ?, cost_usd = ?,
			cache_read_tokens = ?, aux_by_task = ?, model = ?,
			session_id = CASE WHEN ? != '' THEN ? ELSE session_id END
		 WHERE run_id = ?`,
		boolPtrToNull(u.Completed), boolPtrToNull(u.Failed), nullIfEmpty(u.TurnExitReason), floatPtrToNull(u.CostUSD),
		cacheRead, nullIfEmpty(u.AuxByTaskJSON), nullIfEmpty(u.Model), u.SessionID, u.SessionID, runID,
	)
	return err
}

// CallSizing is one job's per-call token footprint and why it waited. A nil field is unknown and
// leaves the stored value alone, so a partial update never erases an earlier one.
type CallSizing struct {
	// LastCallPromptTokens is the prompt size of the run's last model call: the context only
	// grows within a run, short of compaction, so it is the run's peak.
	LastCallPromptTokens *int
	// MaxCallPromptTokens is the largest single call's prompt.
	MaxCallPromptTokens *int
	// MaxTokensRequested is the max_tokens the run asked for; nil = none sent (the engine's
	// default applied).
	MaxTokensRequested *int
	// WaitCause is why the job sat queued: slot, token_budget, exclusive or backend_down.
	WaitCause string
}

// UpdateCallSizing records CallSizing, best effort like UpdateTelemetry.
func (s *Store) UpdateCallSizing(runID string, c CallSizing) error {
	_, err := s.db.Exec(
		`UPDATE jobs SET
			last_call_prompt_tokens = COALESCE(?, last_call_prompt_tokens),
			max_call_prompt_tokens = COALESCE(?, max_call_prompt_tokens),
			max_tokens_requested = COALESCE(?, max_tokens_requested),
			wait_cause = COALESCE(?, wait_cause)
		 WHERE run_id = ?`,
		intPtrToNull(c.LastCallPromptTokens), intPtrToNull(c.MaxCallPromptTokens), intPtrToNull(c.MaxTokensRequested),
		nullIfEmpty(c.WaitCause), runID,
	)
	return err
}

// GetCallSizing reads a job's CallSizing back (nil = unknown), or ErrNotFound.
func (s *Store) GetCallSizing(runID string) (CallSizing, error) {
	var last, largest, req sql.NullInt64
	var cause sql.NullString
	err := s.db.QueryRow(
		`SELECT last_call_prompt_tokens, max_call_prompt_tokens, max_tokens_requested, wait_cause FROM jobs WHERE run_id = ?`,
		runID).Scan(&last, &largest, &req, &cause)
	if errors.Is(err, sql.ErrNoRows) {
		return CallSizing{}, ErrNotFound
	}
	if err != nil {
		return CallSizing{}, err
	}
	return CallSizing{
		LastCallPromptTokens: nullIntPtr(last),
		MaxCallPromptTokens:  nullIntPtr(largest),
		MaxTokensRequested:   nullIntPtr(req),
		WaitCause:            cause.String,
	}, nil
}

// AgentLastCallPromptP90 returns the nearest-rank 90th percentile of last_call_prompt_tokens over
// agentKey's most recent `limit` (default 200) done jobs that recorded one, and how many samples
// it rests on. n == 0 means no history, and the caller must fall back to a neutral default rather
// than read a size of 0. The token-weighted admission reads it.
func (s *Store) AgentLastCallPromptP90(agentKey string, limit int) (p90 int, n int, err error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT last_call_prompt_tokens FROM jobs
		 WHERE agent_key = ? AND state = ? AND last_call_prompt_tokens IS NOT NULL AND last_call_prompt_tokens > 0
		 ORDER BY seq DESC LIMIT ?`, agentKey, string(StateDone), limit)
	if err != nil {
		return 0, 0, fmt.Errorf("agent p90: %w", err)
	}
	defer rows.Close()
	var vals []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return 0, 0, fmt.Errorf("agent p90: scan: %w", err)
		}
		vals = append(vals, v)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if len(vals) == 0 {
		return 0, 0, nil
	}
	sort.Ints(vals)
	rank := max((len(vals)*90+99)/100, 1) // ceil(0.9 n)
	return vals[rank-1], len(vals), nil
}

// UpdatePromptProvenance records what a dispatch was fed: the lesson and runbook ids put into the
// prompt and the final prompt's SHA-256 and length. It runs before the runner starts.
func (s *Store) UpdatePromptProvenance(runID string, lessonIDs, runbookIDs []string, promptSHA256 string, promptBytes int) error {
	_, err := s.db.Exec(
		`UPDATE jobs SET injected_lessons = ?, injected_runbooks = ?, prompt_sha256 = ?, prompt_bytes = ? WHERE run_id = ?`,
		nullIfEmpty(strings.Join(lessonIDs, ",")), nullIfEmpty(strings.Join(runbookIDs, ",")),
		nullIfEmpty(promptSHA256), promptBytes, runID,
	)
	return err
}

// UpdateAttempts records how many times a job's attempt chain has run.
func (s *Store) UpdateAttempts(runID string, attempts int) error {
	_, err := s.db.Exec(`UPDATE jobs SET attempts = ? WHERE run_id = ?`, attempts, runID)
	return err
}

// UpdateProfileRevision records the content revision of the profile a job resolved, once it is
// resolved and before the runner starts, so a profile edited while the job was in flight can be
// told apart from the version that ran. "" stores NULL.
func (s *Store) UpdateProfileRevision(runID, revision string) error {
	_, err := s.db.Exec(`UPDATE jobs SET profile_revision = ? WHERE run_id = ?`, nullIfEmpty(revision), runID)
	return err
}

// ReconcileFailedReason is the local_failed_reason of a job that startup reconciliation failed,
// so it reads apart from any other failure with no attempt. Monitoring that counts restarts
// matches this exact string.
const ReconcileFailedReason = "controller-restart-reconciliation"

// OrphanFailedReason is the local_failed_reason the scheduler's orphan sweep gives a running job
// that has had no live executor for longer than its grace period (FailOrphan).
const OrphanFailedReason = "orphaned-no-executor"

// reconcileFailStates are the states startup reconciliation fails: an executor was, or may have
// been, mid-flight, and none survives a restart. awaiting_inference is in flight like running (it
// leaves only to running or failed, and it counts against shadow back-pressure), so a row left
// there would hold its agent's shadow slot forever.
var reconcileFailStates = []State{StateRunning, StateAwaitingInference}

// ReconcileOrphans runs once at startup, before the scheduler admits anything, to recover the jobs
// a crash left between queued and a terminal state. Admitted jobs go back to queued: nothing ran
// for them yet. Running and awaiting_inference jobs become failed, with finished_at and
// ReconcileFailedReason: nobody knows whether their model call completed, so failed, which can be
// retried, is the safe answer, never done. It returns the count of each, for the startup log.
func (s *Store) ReconcileOrphans() (requeued, failed int, err error) {
	if ob := s.outbox.Load(); ob != nil {
		return s.reconcileOrphansWithEvents(ob)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("reconcile: begin: %w", err)
	}
	defer tx.Rollback()
	n1, n2, _, err := reconcileTx(tx)
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("reconcile: commit: %w", err)
	}
	return n1, n2, nil
}

// reconcileTx is ReconcileOrphans' updates in tx; it returns the failed run ids too.
func reconcileTx(tx *sql.Tx) (requeued, failed int, failedIDs []string, err error) {
	res, err := tx.Exec(`UPDATE jobs SET state = ? WHERE state = ?`, string(StateQueued), string(StateAdmitted))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("reconcile admitted: %w", err)
	}
	n, _ := res.RowsAffected()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, st := range reconcileFailStates {
		ids, err := runIDsIn(tx, `SELECT run_id FROM jobs WHERE state = ? ORDER BY seq ASC`, string(st))
		if err != nil {
			return 0, 0, nil, fmt.Errorf("reconcile %s: %w", st, err)
		}
		if _, err := tx.Exec(`UPDATE jobs SET state = ?, finished_at = ?, local_failed_reason = CASE WHEN COALESCE(local_failed_reason, '') = '' THEN ? ELSE local_failed_reason END WHERE state = ?`,
			string(StateFailed), now, ReconcileFailedReason, string(st)); err != nil {
			return 0, 0, nil, fmt.Errorf("reconcile %s: %w", st, err)
		}
		failedIDs = append(failedIDs, ids...)
	}
	return int(n), len(failedIDs), failedIDs, nil
}

func runIDsIn(q queryer, query string, args ...any) ([]string, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// FailOrphan moves runID from `from` to failed, class unknown (nobody knows how the run ended),
// while it is still in `from`: a compare-and-swap like UpdateStateClass, ErrStateConflict when
// the row moved on. reason becomes local_failed_reason, appended to a reason the run already
// recorded so that evidence is kept. With the outbox on, the terminal events are enqueued in the
// same transaction, as for any other failing transition.
func (s *Store) FailOrphan(runID string, from State, reason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("fail orphan %s: begin: %w", runID, err)
	}
	defer tx.Rollback()
	res, err := execStateUpdate(tx, runID, from, StateFailed, FailureUnknown)
	if err != nil {
		return fmt.Errorf("fail orphan %s: %w", runID, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("fail orphan %s: rows affected: %w", runID, err)
	} else if n == 0 {
		return ErrStateConflict
	}
	if _, err := tx.Exec(`UPDATE jobs SET local_failed_reason = CASE WHEN COALESCE(local_failed_reason, '') = '' THEN ? ELSE local_failed_reason || '; ' || ? END WHERE run_id = ?`,
		reason, reason, runID); err != nil {
		return fmt.Errorf("fail orphan %s: reason: %w", runID, err)
	}
	ob := s.outbox.Load()
	var t txOutbox
	if ob != nil && emitsEvent(from, StateFailed) {
		if err := s.enqueueForJob(tx, ob, runID, &t); err != nil {
			return fmt.Errorf("fail orphan %s: %w", runID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("fail orphan %s: commit: %w", runID, err)
	}
	s.committed(ob, &t)
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

// scanJob reads one jobColumns row. Every column but the NOT NULL ones is scanned as nullable: a
// row written by an older controller, or migrated, has NULL where this one writes "".
func scanJob(row scannable) (*Job, error) {
	var j Job
	var state, createdAt string
	var shadow, localAttempts, cloudFallback int
	var profileID, profileRevision, localFailedReason, sessionID, idempotencyKey sql.NullString
	var startedAt, deadline, finishedAt, resultPath, evidenceRefs sql.NullString
	var taskDescription, responseBody, localBackendUsed, retryOfRunID sql.NullString
	var inputTokens, outputTokens, reasoningTokens, apiCalls sql.NullInt64
	var completed, failed, cacheReadTokens, promptBytes, attempts sql.NullInt64
	var turnExitReason, auxByTask, injLessons, injRunbooks, promptSHA sql.NullString
	var costUSD sql.NullFloat64
	var submittedBy, failureClass, retriedBy, parentProfileRevision, model sql.NullString
	var resubmits sql.NullInt64

	if err := row.Scan(
		&j.RunID, &j.AgentKey, &profileID, &profileRevision, &j.Priority, &j.Seq, &state,
		&shadow, &localAttempts, &cloudFallback, &localFailedReason,
		&sessionID, &idempotencyKey, &createdAt, &startedAt, &deadline,
		&finishedAt, &resultPath, &evidenceRefs, &taskDescription, &responseBody,
		&localBackendUsed, &inputTokens, &outputTokens, &reasoningTokens, &apiCalls, &retryOfRunID,
		&completed, &failed, &turnExitReason, &costUSD, &cacheReadTokens, &auxByTask,
		&injLessons, &injRunbooks, &promptSHA, &promptBytes, &attempts, &submittedBy,
		&failureClass, &resubmits, &parentProfileRevision, &model, &retriedBy,
	); err != nil {
		return nil, err
	}
	j.ProfileID, j.ProfileRevision = profileID.String, profileRevision.String
	j.State = State(state)
	j.Shadow = shadow != 0
	j.LocalAttempts = localAttempts
	j.CloudFallbackUsed = cloudFallback != 0
	j.LocalFailedReason = localFailedReason.String
	j.SessionID = sessionID.String
	j.IdempotencyKey = idempotencyKey.String
	j.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	j.StartedAt = parseNullTime(startedAt)
	j.Deadline = parseNullTime(deadline)
	j.FinishedAt = parseNullTime(finishedAt)
	j.ResultPath, j.EvidenceRefs = resultPath.String, evidenceRefs.String
	j.TaskDescription = taskDescription.String
	j.ResponseBody = responseBody.String
	j.LocalBackendUsed = localBackendUsed.String
	j.InputTokens = int(inputTokens.Int64)
	j.OutputTokens = int(outputTokens.Int64)
	j.ReasoningTokens = int(reasoningTokens.Int64)
	j.APICalls = int(apiCalls.Int64)
	j.RetryOfRunID = retryOfRunID.String
	j.Usage = Usage{
		InputTokens: nullIntPtr(inputTokens), OutputTokens: nullIntPtr(outputTokens),
		ReasoningTokens: nullIntPtr(reasoningTokens), CacheReadTokens: nullIntPtr(cacheReadTokens),
		APICalls: nullIntPtr(apiCalls),
	}
	if costUSD.Valid {
		c := costUSD.Float64
		j.Usage.CostUSD = &c
	}
	j.Model = model.String
	if completed.Valid {
		b := completed.Int64 != 0
		j.Completed = &b
	}
	if failed.Valid {
		b := failed.Int64 != 0
		j.Failed = &b
	}
	j.TurnExitReason = turnExitReason.String
	j.CostUSD = costUSD.Float64
	j.CacheReadTokens = int(cacheReadTokens.Int64)
	j.AuxByTask = auxByTask.String
	j.InjectedLessons = injLessons.String
	j.InjectedRunbooks = injRunbooks.String
	j.PromptSHA256 = promptSHA.String
	j.PromptBytes = int(promptBytes.Int64)
	j.Attempts = int(attempts.Int64)
	j.SubmittedBy = submittedBy.String
	j.FailureClass = failureClass.String
	j.RetriedByRunID = retriedBy.String
	j.ParentProfileRevision = parentProfileRevision.String
	j.Resubmits = int(resubmits.Int64)
	if !resubmits.Valid && j.RetryOfRunID != "" {
		j.Resubmits = 1 // a retry written before the column: one deep, the only depth there is
	}
	return &j, nil
}

func nullIntPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func intPtrToNull(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func floatPtrToNull(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func boolPtrToNull(b *bool) any {
	if b == nil {
		return nil
	}
	return boolToInt(*b)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func timePtrToString(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339Nano)
}

func parseNullTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, ns.String)
	if err != nil {
		return nil
	}
	return &t
}

// SaveDrain records an operator's drain of backend, so it survives a restart: a restart during
// a model swap must not silently undrain the backend. It is idempotent and keeps the first since.
func (s *Store) SaveDrain(backend string, since time.Time) error {
	_, err := s.db.Exec(`INSERT INTO backend_drains (backend, since) VALUES (?, ?) ON CONFLICT(backend) DO NOTHING`,
		backend, since.UTC().Format(time.RFC3339Nano))
	return err
}

// DeleteDrain removes backend's drain, if any.
func (s *Store) DeleteDrain(backend string) error {
	_, err := s.db.Exec(`DELETE FROM backend_drains WHERE backend = ?`, backend)
	return err
}

// LoadDrains returns every recorded drain: backend -> since.
func (s *Store) LoadDrains() (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT backend, since FROM backend_drains`)
	if err != nil {
		return nil, fmt.Errorf("load drains: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var name, since string
		if err := rows.Scan(&name, &since); err != nil {
			return nil, fmt.Errorf("load drains: %w", err)
		}
		t, _ := time.Parse(time.RFC3339Nano, since)
		out[name] = t
	}
	return out, rows.Err()
}
