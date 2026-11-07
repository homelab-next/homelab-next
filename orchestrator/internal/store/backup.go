// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A migration changes the schema of a database that already holds data. ADR-0026's amendment of
// 2026-11-07 requires a backup before every run of one against a live database, checked
// restorable first and protected like the database itself, so that a failed migration is a
// restore and a return to the previous controller, never a repair in place. The store's side of
// that rule:
//
//   - Open refuses to migrate an existing database (ErrBackupRequired) unless the caller names a
//     backup in Options.MigrationBackup. A new, empty database needs none.
//   - BackupForMigration writes that backup with VACUUM INTO (a consistent snapshot taken inside
//     one read transaction), owner-only, and verifies it.
//   - VerifyBackup, which Open also runs inside the migration's own write transaction, so that
//     nothing can change the database between the check and the migration, requires the backup
//     to be a regular file owned by the database's owner, with no permission the database file
//     lacks, to open and pass PRAGMA integrity_check, and to hold exactly the database's schema
//     and rows.

// ErrBackupRequired: Open found schema changes to make on an existing database and no backup
// was named. Take one with BackupForMigration and pass its path as Options.MigrationBackup.
var ErrBackupRequired = errors.New("store: migrating an existing database needs a verified backup first")

// ErrBackupMismatch: the named backup is not a usable copy of the database as it is now.
var ErrBackupMismatch = errors.New("store: the backup does not verify against the database")

// BackupForMigration writes a backup of the database at dbPath to backupPath, which must not
// exist, and verifies it (VerifyBackup). The file is created owner-only (0600) before SQLite
// writes into it. On a failed verification the backup is removed. It never changes the
// database: it reads it in one transaction. Take it while no controller has the database open,
// or the database may change before Open migrates it, which Open then refuses
// (ErrBackupMismatch); holding LockInstance across both steps rules that out.
func BackupForMigration(dbPath, backupPath string) error {
	if err := checkBackupPaths(dbPath, backupPath); err != nil {
		return err
	}
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("store: backup: the database: %w", err)
	}
	f, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(backupPath)
		return fmt.Errorf("store: backup: %w", err)
	}
	fail := func(err error) error {
		os.Remove(backupPath)
		return err
	}
	db, err := openPlain(dbPath)
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	// VACUUM INTO writes into an existing file only when it is empty, which keeps the mode
	// set above.
	if _, err := db.Exec(`VACUUM INTO ?`, backupPath); err != nil {
		return fail(fmt.Errorf("store: backup: VACUUM INTO: %w", err))
	}
	if err := syncFile(backupPath); err != nil {
		return fail(fmt.Errorf("store: backup: %w", err))
	}
	if err := VerifyBackup(dbPath, backupPath); err != nil {
		return fail(err)
	}
	return nil
}

// VerifyBackup checks that backupPath is a restorable copy of the database at dbPath as it is
// now: see the comment at the top of this file. It changes neither file.
func VerifyBackup(dbPath, backupPath string) error {
	if err := checkBackupPaths(dbPath, backupPath); err != nil {
		return err
	}
	db, err := openPlain(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("store: verify backup: %w", err)
	}
	defer tx.Rollback()
	return verifyBackupAgainst(tx, dbPath, backupPath)
}

// verifyBackupAgainst checks backupPath against the live database as q (a transaction on it)
// sees it.
func verifyBackupAgainst(q queryer, dbPath, backupPath string) error {
	if err := checkBackupFile(dbPath, backupPath); err != nil {
		return err
	}
	bdb, err := sql.Open("sqlite", "file:"+backupPath+"?mode=ro&immutable=1")
	if err != nil {
		return fmt.Errorf("%w: open %s: %v", ErrBackupMismatch, backupPath, err)
	}
	defer bdb.Close()
	var verdict []string
	rows, err := bdb.Query(`PRAGMA integrity_check`)
	if err != nil {
		return fmt.Errorf("%w: %s: integrity_check: %v", ErrBackupMismatch, backupPath, err)
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			return fmt.Errorf("%w: %s: integrity_check: %v", ErrBackupMismatch, backupPath, err)
		}
		verdict = append(verdict, line)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("%w: %s: integrity_check: %v", ErrBackupMismatch, backupPath, err)
	}
	if len(verdict) != 1 || verdict[0] != "ok" {
		return fmt.Errorf("%w: %s fails integrity_check: %s", ErrBackupMismatch, backupPath, strings.Join(verdict, "; "))
	}
	want, err := fingerprint(q)
	if err != nil {
		return fmt.Errorf("store: verify backup: the database: %w", err)
	}
	got, err := fingerprint(bdb)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrBackupMismatch, backupPath, err)
	}
	if got != want {
		return fmt.Errorf("%w: %s does not hold the database's current schema and rows (taken before a later change?)", ErrBackupMismatch, backupPath)
	}
	return nil
}

// checkBackupPaths refuses a backup path that is the database itself or one of its side files,
// and a path SQLite's file name parsing would cut short.
func checkBackupPaths(dbPath, backupPath string) error {
	if backupPath == "" {
		return fmt.Errorf("store: backup: no backup path")
	}
	if strings.ContainsAny(dbPath, "?#") || strings.ContainsAny(backupPath, "?#%") {
		return fmt.Errorf("store: backup: a path holds '?', '#' or (the backup's) '%%', which SQLite's file name parsing treats as special")
	}
	a, err := filepath.Abs(dbPath)
	if err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	b, err := filepath.Abs(backupPath)
	if err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	for _, side := range []string{"", "-wal", "-shm", "-journal", ".lock"} {
		if b == a+side {
			return fmt.Errorf("store: backup: %s is the database or one of its own files", backupPath)
		}
	}
	return nil
}

// checkBackupFile requires the backup to be protected like the database: a regular file (no
// symbolic link) with the database file's owner and no permission bit the database file lacks.
func checkBackupFile(dbPath, backupPath string) error {
	bi, err := os.Lstat(backupPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupMismatch, err)
	}
	if !bi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrBackupMismatch, backupPath)
	}
	di, err := os.Stat(dbPath)
	if err != nil {
		return fmt.Errorf("store: verify backup: the database: %w", err)
	}
	if extra := bi.Mode().Perm() &^ di.Mode().Perm(); extra != 0 {
		return fmt.Errorf("%w: %s grants %v, which the database file does not: protect it like the database", ErrBackupMismatch, backupPath, extra)
	}
	bs, ok1 := bi.Sys().(*syscall.Stat_t)
	ds, ok2 := di.Sys().(*syscall.Stat_t)
	if ok1 && ok2 && bs.Uid != ds.Uid {
		return fmt.Errorf("%w: %s is owned by uid %d, the database by uid %d", ErrBackupMismatch, backupPath, bs.Uid, ds.Uid)
	}
	return nil
}

// fingerprint digests a database's schema and every row of every table, in a fixed order, so
// that two databases with the same digest hold the same data. Values are hashed with their
// storage class, so 1, 1.0, '1' and NULL all differ.
func fingerprint(q queryer) (string, error) {
	h := sha256.New()
	rows, err := q.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY type, name`)
	if err != nil {
		return "", err
	}
	var tables []string
	for rows.Next() {
		var typ, name, tbl, ddl string
		if err := rows.Scan(&typ, &name, &tbl, &ddl); err != nil {
			rows.Close()
			return "", err
		}
		for _, s := range []string{typ, name, tbl, ddl} {
			hashString(h, s)
		}
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := rows.Close(); err != nil {
		return "", err
	}
	for _, t := range tables {
		hashString(h, "rows:"+t)
		if err := hashRows(h, q, t); err != nil {
			return "", fmt.Errorf("table %s: %w", t, err)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashRows(h hash.Hash, q queryer, table string) error {
	// table names come from sqlite_master; quote them as identifiers all the same
	rows, err := q.Query(`SELECT * FROM "` + strings.ReplaceAll(table, `"`, `""`) + `" ORDER BY rowid`)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var n uint64
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		for _, v := range vals {
			hashValue(h, v)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	h.Write(buf[:])
	return nil
}

func hashString(h hash.Hash, s string) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(s)))
	h.Write(buf[:])
	h.Write([]byte(s))
}

func hashValue(h hash.Hash, v any) {
	var buf [8]byte
	switch x := v.(type) {
	case nil:
		h.Write([]byte{0})
	case int64:
		h.Write([]byte{1})
		binary.BigEndian.PutUint64(buf[:], uint64(x))
		h.Write(buf[:])
	case float64:
		h.Write([]byte{2})
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(x))
		h.Write(buf[:])
	case string:
		h.Write([]byte{3})
		hashString(h, x)
	case []byte:
		h.Write([]byte{4})
		hashString(h, string(x))
	default: // the driver's other types (bool, time) as their text
		h.Write([]byte{5})
		hashString(h, fmt.Sprintf("%T:%v", x, x))
	}
}

// openPlain opens a database without changing it: no journal mode or other setting is applied,
// only a wait for a lock held elsewhere.
func openPlain(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", dbPath, err)
	}
	return db, nil
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
