package vault

// testHook is called at every step of a save (§4.6) with the step's name
// and the file it concerns, so the fault-injection tests can kill the
// process there. It is unexported and nil in passh: only this package's
// _test.go files set it.
var testHook func(point, file string)

// hookLockBusy is reported, with the lock file, when a lock is found held
// by someone else and the wait begins; an uncontended save never passes it.
const hookLockBusy = "lock-busy"

// The save steps hook reports, in order. A save that makes a backup and
// updates the rollback record passes all of them (hookOldRemoved only where
// the vault is replaced by an exchanging rename).
const (
	hookLocked        = "locked"         // lock taken, leftover temporary files removed
	hookChecked       = "checked"        // step 2: the file is still the one that was opened
	hookTempCreated   = "temp-created"   // step 4: empty temporary file
	hookTempWritten   = "temp-written"   // written, before fsync
	hookTempSynced    = "temp-synced"    // after fsync, before the read-back check
	hookVerified      = "verified"       // step 5 passed
	hookRechecked     = "rechecked"      // step 6: the file read again, still the one opened
	hookBackupWritten = "backup-written" // backup's temporary file written, before fsync
	hookBackupSynced  = "backup-synced"  // after its fsync, before its rename
	hookBackupRenamed = "backup-renamed" // after its rename, before the folder fsync
	hookBackupDone    = "backup-done"    // backup in place, folder synced, old backups rotated
	hookBeforeRename  = "before-rename"  // step 7: just before the rename
	hookRenamed       = "renamed"        // the new file is the vault, before the folder fsync
	hookOldRemoved    = "old-removed"    // the exchanged-out old file checked and removed
	hookDirSynced     = "dir-synced"     // after the folder fsync
	hookRecordWritten = "record-written" // rollback record's temporary file written and synced
	hookRecorded      = "recorded"       // rollback record in place
)

func hook(point, file string) {
	if testHook != nil && point != "" {
		testHook(point, file)
	}
}
