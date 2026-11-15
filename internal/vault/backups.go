package vault

import (
	"bytes"
	"cmp"
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
// vault file per save, named after the UTC time the backup was made and the
// revision it holds: 20261115T120031Z-r42.passh. Two backups of the same
// revision made in the same second get -2, -3, … before the extension.

// BackupTimeFormat is the time in a backup's file name (UTC).
const BackupTimeFormat = "20060102T150405Z"

var backupName = regexp.MustCompile(`^(\d{8}T\d{6}Z)-r(\d{1,20})(?:-(\d{1,6}))?\.passh$`)

// backupTemp names the temporary files of backups being written:
// .backup.tmp-<random> in the vault id's folder.
const backupTemp = "backup"

// Backup is one automatic backup.
type Backup struct {
	VaultID  string    // the vault_id folder it is in
	Path     string    // the backup file
	Time     time.Time // when it was made, UTC, from its name
	Revision uint64    // the revision it holds, from its name
	seq      int       // -2, -3, … for backups made in the same second
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

// writeBackup stores content, the current vault file at revision rev, as a
// new backup of vaultID and then keeps only the newest keep backups. The
// backup is complete or absent: it is written to a temporary file, fsynced
// and renamed. Rotation never removes the backup just written or protect
// (the vault's real path). Errors in removing old backups don't fail the
// backup; they come back as rotateErr.
func writeBackup(stateDir, vaultID string, rev uint64, content []byte, now time.Time, keep int, protect string) (path string, rotateErr, err error) {
	dir := BackupDir(stateDir, vaultID)
	if err := mkdirs(dir); err != nil {
		return "", nil, err
	}
	if err := mkdirs(locksDir(stateDir)); err != nil {
		return "", nil, err
	}
	// Copies of one vault in two places have different save locks but
	// share this folder.
	lock, err := lockFile(filepath.Join(locksDir(stateDir), "backups-"+hashName(vaultID)+".lock"))
	if err != nil {
		return "", nil, err
	}
	defer lock.unlock()
	if _, err := removeTemps(dir, backupTemp); err != nil {
		return "", nil, err
	}
	t, err := writeTemp(dir, backupTemp, content, "", hookBackupWritten, hookBackupSynced)
	if err != nil {
		return "", nil, err
	}
	stem := now.UTC().Format(BackupTimeFormat) + "-r" + strconv.FormatUint(rev, 10)
	path = filepath.Join(dir, stem+".passh")
	for n := 2; ; n++ {
		err = renameNoReplace(t.path, path)
		if err == nil || !errors.Is(err, fs.ErrExist) || n > 1000 {
			break
		}
		path = filepath.Join(dir, stem+"-"+strconv.Itoa(n)+".passh")
	}
	if err != nil {
		t.discard()
		return "", nil, err
	}
	t.close()
	hook(hookBackupRenamed, path)
	if err := syncDir(dir); err != nil {
		return "", nil, err
	}
	rotateErr = rotate(dir, keep, path, protect)
	hook(hookBackupDone, path)
	return path, rotateErr, nil
}

// rotate keeps the newest keep backups in dir (by revision, then time; a
// clock that went back doesn't matter). It never removes the protected
// paths.
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
		m := backupName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		t, err := time.Parse(BackupTimeFormat, m[1])
		if err != nil {
			continue
		}
		rev, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			continue
		}
		seq := 1
		if m[3] != "" {
			seq, _ = strconv.Atoi(m[3])
		}
		out = append(out, Backup{VaultID: id, Path: filepath.Join(dir, e.Name()), Time: t.UTC(), Revision: rev, seq: seq})
	}
	sortBackups(out)
	return out, nil
}

// sortBackups orders backups newest first: by vault, then by revision,
// then by time. The revision decides because a clock that went back would
// otherwise make the newest backup look like the oldest.
func sortBackups(list []Backup) {
	slices.SortFunc(list, func(a, b Backup) int {
		return cmp.Or(cmp.Compare(a.VaultID, b.VaultID), cmp.Compare(b.Revision, a.Revision),
			b.Time.Compare(a.Time), cmp.Compare(b.seq, a.seq), cmp.Compare(a.Path, b.Path))
	})
}

// ListBackups lists the automatic backups of vaultID, newest (highest
// revision) first; with an empty vaultID, those of every vault on this
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
