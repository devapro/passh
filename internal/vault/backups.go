package vault

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/vaultfile"
)

// Automatic backups (§4.7) live in <state>/backups/<vault_id>/, one complete
// vault file per save:
//
//	00000042-20261115T120031Z-r41.passh
//
// The first part is the backup's sequence number in its folder: one more
// than the highest number there, assigned under the backups lock, zero
// padded to backupSeqWidth digits (more digits once it outgrows them). It
// alone decides which backup is newer, for rotation and for listing, so
// neither a clock that went back nor a vault restored to a lower revision
// can make rotation remove the backups just made (§4.7: "keeps the newest
// backup.keep files", newest meaning most recently made). The UTC time the
// backup was made and the revision it holds follow, for people.
//
// Backups made by passh before the sequence number was added are named
// 20261115T120031Z-r42.passh, with -2, -3, … before the extension for a
// second backup of the same revision in the same second. They count as
// older than every numbered backup and among themselves are ordered by the
// time in their names, then revision, so rotation removes them first.

// BackupTimeFormat is the time in a backup's file name (UTC).
const BackupTimeFormat = "20060102T150405Z"

// backupSeqWidth is the minimum number of digits of a backup's sequence
// number, so that `ls` lists backups in the order they were made.
const backupSeqWidth = 8

// maxBackupSeq bounds the sequence numbers that count: a file named with
// a higher one (not made by passh) is ignored, so the next number always
// fits.
const maxBackupSeq = 1 << 62

var (
	backupName       = regexp.MustCompile(`^(\d{1,20})-(\d{8}T\d{6}Z)-r(\d{1,20})\.passh$`)
	legacyBackupName = regexp.MustCompile(`^(\d{8}T\d{6}Z)-r(\d{1,20})(?:-(\d{1,6}))?\.passh$`)
)

// backupTemp names the temporary files of backups being written:
// .backup.tmp-<random> in the vault id's folder.
const backupTemp = "backup"

// Backup is one automatic backup.
type Backup struct {
	VaultID  string    // the vault_id folder it is in
	Path     string    // the backup file
	Time     time.Time // when it was made, UTC, from its name
	Revision uint64    // the revision it holds, from its name
	// seq is the sequence number from the name; 0 for a backup named
	// before sequence numbers existed (older than every numbered one).
	seq uint64
	// dup is the -2, -3, … suffix of such an old name (1 without one).
	dup int
}

// String is the line `passh backups` prints:
// "2026-11-15 12:00:31  r42  <path>".
func (b Backup) String() string {
	return fmt.Sprintf("%s  r%d  %s", b.Time.UTC().Format(time.DateTime), b.Revision, b.Path)
}

func backupsRoot(stateDir string) string { return filepath.Join(stateDir, "backups") }

// backupDirName is the folder name for a vault_id. A vault_id is a UUID; one
// that isn't safe as a file name (it is authenticated data, but still) is
// replaced by a digest.
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func backupDirName(vaultID string) string {
	if safeID.MatchString(vaultID) {
		return vaultID
	}
	return "id-" + hashName(vaultID)
}

// BackupDir is the folder holding the automatic backups of vaultID.
func BackupDir(stateDir, vaultID string) string {
	return filepath.Join(backupsRoot(stateDir), backupDirName(vaultID))
}

// backupFileName is the name of the backup with sequence number seq, made
// at now, of revision rev.
func backupFileName(seq uint64, now time.Time, rev uint64) string {
	return fmt.Sprintf("%0*d-%s-r%d.passh", backupSeqWidth, seq, now.UTC().Format(BackupTimeFormat), rev)
}

// writeBackup stores content, the current vault file at revision rev, as a
// new backup of vaultID and then keeps only the newest keep backups. The
// backup is complete or absent: it is written to a temporary file, fsynced
// and renamed. Its sequence number is one more than the highest in the
// folder. Rotation never removes the backup just written or protect (the
// vault's real path). Errors in removing old backups don't fail the
// backup; they come back as rotateErr. ctx ends a wait for the backups
// lock.
func writeBackup(ctx context.Context, stateDir, vaultID string, rev uint64, content []byte, now time.Time, keep int, protect string) (path string, rotateErr, err error) {
	dir := BackupDir(stateDir, vaultID)
	if err := mkdirs(dir); err != nil {
		return "", nil, err
	}
	if err := mkdirs(locksDir(stateDir)); err != nil {
		return "", nil, err
	}
	// Copies of one vault in two places have different save locks but
	// share this folder.
	lock, err := lockFile(ctx, filepath.Join(locksDir(stateDir), "backups-"+hashName(vaultID)+".lock"))
	if err != nil {
		return "", nil, err
	}
	defer lock.unlock()
	if _, err := removeTemps(dir, backupTemp); err != nil {
		return "", nil, err
	}
	list, err := listDir(dir, filepath.Base(dir))
	if err != nil {
		return "", nil, err
	}
	seq := uint64(1)
	if len(list) > 0 {
		seq = list[0].seq + 1 // newest first; old names have seq 0
	}
	t, err := writeTemp(dir, backupTemp, content, "", hookBackupWritten, hookBackupSynced)
	if err != nil {
		return "", nil, err
	}
	// Under the lock nobody else adds a backup here; a file that appears
	// anyway (a copy put in by hand) only moves the number on.
	for range 1000 {
		path = filepath.Join(dir, backupFileName(seq, now, rev))
		err = renameNoReplace(t.path, path)
		if !errors.Is(err, fs.ErrExist) {
			break
		}
		seq++
	}
	if err != nil {
		t.discard()
		return "", nil, err
	}
	// Renamed and fsynced already: closing only releases the descriptor
	// and its lock (see tempFile.close).
	_ = t.close()
	hook(hookBackupRenamed, path)
	if err := syncDir(dir); err != nil {
		return "", nil, err
	}
	rotateErr = rotate(dir, keep, path, protect)
	hook(hookBackupDone, path)
	return path, rotateErr, nil
}

// rotate keeps the newest keep backups in dir: the keep highest sequence
// numbers, whatever the times and revisions in their names. It never
// removes the protected paths.
func rotate(dir string, keep int, protect ...string) error {
	list, err := listDir(dir, filepath.Base(dir))
	if err != nil || len(list) <= keep {
		return err
	}
	var firstErr error
	for _, b := range list[keep:] {
		if slices.Contains(protect, b.Path) {
			continue
		}
		if err := os.Remove(b.Path); err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// listDir lists the backups in one vault_id folder, newest first. Files
// that aren't named like a backup are ignored.
func listDir(dir, id string) ([]Backup, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Backup
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		if b, ok := parseBackupName(e.Name()); ok {
			b.VaultID, b.Path = id, filepath.Join(dir, e.Name())
			out = append(out, b)
		}
	}
	sortBackups(out)
	return out, nil
}

// parseBackupName reads the sequence number, time and revision from a
// backup's file name, in the current form or the one before sequence
// numbers.
func parseBackupName(name string) (Backup, bool) {
	var b Backup
	var seq, ts, rev, dup string
	if m := backupName.FindStringSubmatch(name); m != nil {
		seq, ts, rev = m[1], m[2], m[3]
	} else if m := legacyBackupName.FindStringSubmatch(name); m != nil {
		ts, rev, dup = m[1], m[2], m[3]
	} else {
		return b, false
	}
	t, err := time.Parse(BackupTimeFormat, ts)
	if err != nil {
		return b, false
	}
	b.Time = t.UTC()
	if b.Revision, err = strconv.ParseUint(rev, 10, 64); err != nil {
		return b, false
	}
	if seq != "" {
		if b.seq, err = strconv.ParseUint(seq, 10, 64); err != nil || b.seq == 0 || b.seq > maxBackupSeq {
			return b, false
		}
	}
	b.dup = 1
	if dup != "" {
		b.dup, _ = strconv.Atoi(dup) // at most 6 digits: always fits
	}
	return b, true
}

// sortBackups orders backups newest first: by vault, then by sequence
// number (the order they were made in), then, for old names without one,
// by the time in the name, the revision and the -2, -3, … suffix.
func sortBackups(list []Backup) {
	slices.SortFunc(list, func(a, b Backup) int {
		return cmp.Or(cmp.Compare(a.VaultID, b.VaultID), cmp.Compare(b.seq, a.seq),
			b.Time.Compare(a.Time), cmp.Compare(b.Revision, a.Revision),
			cmp.Compare(b.dup, a.dup), cmp.Compare(a.Path, b.Path))
	})
}

// ListBackups lists the automatic backups of vaultID, newest (most
// recently made) first; with an empty vaultID, those of every vault on this
// machine, grouped by vault.
func ListBackups(stateDir, vaultID string) ([]Backup, error) {
	if vaultID != "" {
		return listDir(BackupDir(stateDir, vaultID), vaultID)
	}
	ents, err := os.ReadDir(backupsRoot(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var all []Backup
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		list, err := listDir(filepath.Join(backupsRoot(stateDir), e.Name()), e.Name())
		if err != nil {
			return nil, err
		}
		all = append(all, list...)
	}
	sortBackups(all)
	return all, nil
}

// FindBackups lists the automatic backups of the vault file at path without
// decrypting it (for `passh backups`, which needs no passphrase). The
// vault_id is encrypted, so a vault's backups are recognized by their key
// block, which every save copies byte for byte. matched is false when no
// backup has the file's key block (the file is damaged, or was changed by
// passwd or rekey and not saved since); then every backup on this machine
// is listed.
func FindBackups(stateDir, path string) (list []Backup, matched bool, err error) {
	data, err := readVaultFile(path)
	if err != nil {
		return nil, false, err
	}
	var keyBlock []byte
	if f, err := vaultfile.Parse(data); err == nil {
		keyBlock = f.KeyBlock
	}
	return findBackups(stateDir, keyBlock, nil)
}

// findBackups lists the backups of the vault ids whose backups share
// keyBlock, or whose data blocks key (if not nil) opens; failing that, all
// backups.
func findBackups(stateDir string, keyBlock []byte, key *age.X25519Identity) ([]Backup, bool, error) {
	all, err := ListBackups(stateDir, "")
	if err != nil {
		return nil, false, err
	}
	ids := map[string]bool{}
	for _, b := range all {
		if ids[b.VaultID] {
			continue
		}
		data, err := readVaultFile(b.Path)
		if err != nil {
			continue
		}
		f, err := vaultfile.Parse(data)
		if err != nil {
			continue
		}
		if (keyBlock != nil && bytes.Equal(f.KeyBlock, keyBlock)) || (key != nil && opensHeader(f.DataBlock, key)) {
			ids[b.VaultID] = true
		}
	}
	if len(ids) == 0 {
		return all, false, nil
	}
	var out []Backup
	for _, b := range all {
		if ids[b.VaultID] {
			out = append(out, b)
		}
	}
	return out, true, nil
}

// opensHeader reports whether key unwraps the file key of an age file,
// without decrypting its payload.
func opensHeader(block []byte, key *age.X25519Identity) bool {
	hdr, err := age.ExtractHeader(bytes.NewReader(block))
	if err != nil {
		return false
	}
	_, err = age.DecryptHeader(hdr, key)
	return err == nil
}
