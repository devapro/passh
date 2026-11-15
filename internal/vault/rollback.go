package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// The rollback record (§4.10) is <state>/revisions.json: for each vault_id,
// the highest revision this machine has opened or saved, that revision's
// saved_at and when it was recorded. Nothing else: no paths, no names.
//
//	{
//	  "version": 1,
//	  "vaults": {
//	    "0f6c1d2e-…": {"revision": 42, "saved_at": "2026-11-15T12:00:00Z", "seen_at": "2026-11-15T12:00:05Z"}
//	  }
//	}

const (
	recordName    = "revisions.json"
	recordVersion = 1
)

type record struct {
	Version int                    `json:"version"`
	Vaults  map[string]recordEntry `json:"vaults"`
}

type recordEntry struct {
	Revision uint64    `json:"revision"`
	SavedAt  time.Time `json:"saved_at"`
	SeenAt   time.Time `json:"seen_at"`
}

func locksDir(stateDir string) string   { return filepath.Join(stateDir, "locks") }
func recordPath(stateDir string) string { return filepath.Join(stateDir, recordName) }

// Problems with the rollback record. Only a damaged record (not JSON, or no
// version) is replaced by a new one; a newer version or an unreadable file
// is left alone, so no other vault's entry is lost.
var (
	errRecordDamaged = errors.New("is damaged")
	errRecordNewer   = errors.New("was written by a newer passh")
)

// readRecord reads the rollback record; a missing file is an empty record.
// On error the empty record comes back too.
func readRecord(stateDir string) (record, error) {
	rec := record{Version: recordVersion, Vaults: map[string]recordEntry{}}
	data, err := os.ReadFile(recordPath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return rec, nil
	}
	if err != nil {
		return rec, err
	}
	var r record
	if err := json.Unmarshal(data, &r); err != nil || r.Version < 1 {
		return rec, fmt.Errorf("%s %w", recordPath(stateDir), errRecordDamaged)
	}
	if r.Version > recordVersion {
		return rec, fmt.Errorf("%s %w (version %d)", recordPath(stateDir), errRecordNewer, r.Version)
	}
	if r.Vaults != nil {
		rec.Vaults = r.Vaults
	}
	return rec, nil
}

// updateRecord records revision rev (saved at savedAt) for vaultID if it is
// higher than the recorded one, or in any case with force (the user
// accepted an older copy). The file is replaced atomically, under a lock so
// that two passh processes don't lose each other's updates; ctx ends a
// wait for that lock. A damaged record is replaced; a newer or unreadable
// one is left alone (error).
func updateRecord(ctx context.Context, stateDir, vaultID string, rev uint64, savedAt, now time.Time, force bool) error {
	if err := mkdirs(locksDir(stateDir)); err != nil {
		return err
	}
	lock, err := lockFile(ctx, filepath.Join(locksDir(stateDir), "revisions.lock"))
	if err != nil {
		return err
	}
	defer lock.unlock()
	rec, err := readRecord(stateDir)
	if err != nil && !errors.Is(err, errRecordDamaged) {
		return err
	}
	if cur, ok := rec.Vaults[vaultID]; ok && !force && rev <= cur.Revision {
		return nil
	}
	rec.Vaults[vaultID] = recordEntry{Revision: rev, SavedAt: savedAt.UTC(), SeenAt: now.UTC().Truncate(time.Second)}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(recordPath(stateDir), append(data, '\n'), hookRecordWritten); err != nil {
		return err
	}
	hook(hookRecorded, recordPath(stateDir))
	return nil
}

// RollbackStatus compares an opened vault with the rollback record (§4.10).
type RollbackStatus struct {
	Revision uint64    // the opened file's revision
	SavedAt  time.Time // and its saved_at
	// Seen reports whether this machine had a record for the vault_id when
	// the file was opened; SeenRevision and SeenSavedAt are that record.
	Seen         bool
	SeenRevision uint64
	SeenSavedAt  time.Time
}

// Older reports whether the file is older than a revision this machine has
// seen before.
func (s RollbackStatus) Older() bool { return s.Seen && s.Revision < s.SeenRevision }

// Message is the warning of §4.10. It is empty unless Older.
func (s RollbackStatus) Message() string {
	if !s.Older() {
		return ""
	}
	return fmt.Sprintf("this copy is older than one seen before on this machine (r%d of %s; seen r%d of %s). "+
		"If you didn't restore it on purpose, the file may have been replaced.",
		s.Revision, s.SavedAt.UTC().Format(time.DateOnly), s.SeenRevision, s.SeenSavedAt.UTC().Format(time.DateOnly))
}

// checkRollback compares the opened revision with the record and acts as
// §4.10 says. It updates the record when the revision is higher, asks
// (Prompt) or warns (Warn) when it is lower, and lowers the record when the
// user accepts. Problems with the record file itself are warnings: they
// never stop a vault from opening.
func (v *Vault) checkRollback(ctx context.Context, vaultID string, rev uint64, savedAt time.Time, real string) (RollbackStatus, error) {
	st := RollbackStatus{Revision: rev, SavedAt: savedAt}
	o := &v.opts
	rec, err := readRecord(o.StateDir)
	if err != nil {
		if errors.Is(err, errRecordDamaged) {
			v.warn(fmt.Sprintf("the rollback record %v; a new one is started, so older copies aren't detected this time", err))
		} else {
			// Leave a newer or unreadable record alone.
			v.warn(fmt.Sprintf("the rollback record can't be used, so older copies aren't detected: %v", err))
			return st, nil
		}
	}
	if e, ok := rec.Vaults[vaultID]; ok {
		st.Seen, st.SeenRevision, st.SeenSavedAt = true, e.Revision, e.SavedAt
	}
	if !st.Older() {
		if !st.Seen || rev > st.SeenRevision {
			v.record(ctx, vaultID, rev, savedAt, false)
		}
		return st, nil
	}
	// Files in the backups folder are old on purpose; report-only callers
	// (verify --full, merge's other file) show the comparison themselves.
	if !o.RollbackWarn || o.RollbackReportOnly || v.inBackups(real) {
		return st, nil
	}
	if o.Prompt == nil {
		v.warn(st.Message())
		return st, nil
	}
	ok, err := o.Prompt(st.Message())
	if err != nil {
		return st, err
	}
	if !ok {
		return st, ErrRollbackDeclined
	}
	v.record(ctx, vaultID, rev, savedAt, true)
	return st, nil
}

// record updates the rollback record; a failure is a warning. A cancelled
// ctx skips a wait for the record's lock: the record is advisory, and the
// next open records the revision.
func (v *Vault) record(ctx context.Context, vaultID string, rev uint64, savedAt time.Time, force bool) {
	if err := updateRecord(ctx, v.opts.StateDir, vaultID, rev, savedAt, v.opts.Now(), force); err != nil {
		v.warn(fmt.Sprintf("the rollback record wasn't updated: %v", err))
	}
}

// inBackups reports whether real (a resolved path) lies in the automatic
// backups folder.
func (v *Vault) inBackups(real string) bool {
	root, err := filepath.EvalSymlinks(backupsRoot(v.opts.StateDir))
	if err != nil {
		root = filepath.Clean(backupsRoot(v.opts.StateDir))
	}
	return isWithin(real, root)
}
