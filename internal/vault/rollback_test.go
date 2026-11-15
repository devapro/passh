package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/devapro/passh/internal/keys"
)

// olderCopy returns an env whose vault is at revision 3 (recorded), and the
// bytes of revision 2 of the same vault.
func olderCopy(t *testing.T) (*env, []byte) {
	t.Helper()
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw") // r2
	old := e.read()
	mustAdd(t, v, "b", "pw") // r3
	if rec, _ := readRecord(e.state); rec.Vaults[v.Info().VaultID].Revision != 3 {
		t.Fatalf("record %+v", rec)
	}
	e.take()
	return e, old
}

func recorded(t *testing.T, e *env) uint64 {
	t.Helper()
	rec, err := readRecord(e.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rec.Vaults {
		return r.Revision
	}
	return 0
}

// Safety test 11, first bullet: with a terminal, the older copy prompts;
// declining exits without changes; accepting stops the warning.
func TestRollbackPrompt(t *testing.T) {
	e, old := olderCopy(t)
	e.write(old)
	recBefore, _ := os.ReadFile(recordPath(e.state))

	e.answer = false
	_, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), e.opts())
	if !errors.Is(err, ErrRollbackDeclined) {
		t.Fatalf("declined: %v", err)
	}
	warns, prompts := e.take()
	want := "this copy is older than one seen before on this machine (r2 of 2026-11-15; seen r3 of 2026-11-15). " +
		"If you didn't restore it on purpose, the file may have been replaced."
	if len(prompts) != 1 || prompts[0] != want || len(warns) != 0 {
		t.Fatalf("prompts %q, warnings %q", prompts, warns)
	}
	recAfter, _ := os.ReadFile(recordPath(e.state))
	if !bytes.Equal(recBefore, recAfter) || !bytes.Equal(e.read(), old) {
		t.Fatal("declining changed something")
	}

	e.answer = true
	v := e.open()
	if _, prompts := e.take(); len(prompts) != 1 {
		t.Fatalf("prompts %q", prompts)
	}
	st := v.Rollback()
	if !st.Older() || st.Revision != 2 || st.SeenRevision != 3 || st.Message() != want {
		t.Fatalf("status %+v", st)
	}
	if r := recorded(t, e); r != 2 {
		t.Fatalf("accepting recorded r%d, want r2", r)
	}
	// No warning the next time; saving moves on from r2.
	w := e.open()
	if warns, prompts := e.take(); len(prompts) != 0 || len(warns) != 0 || w.Rollback().Older() {
		t.Fatalf("second open: prompts %q warnings %q", prompts, warns)
	}
	mustAdd(t, w, "c", "pw")
	if r := recorded(t, e); r != 3 {
		t.Fatalf("after save: r%d", r)
	}
}

// Safety test 11, second bullet: without a terminal the warning goes to
// Warn, the command continues and the record doesn't change.
func TestRollbackWithoutTerminal(t *testing.T) {
	e, old := olderCopy(t)
	e.noPrompt = true
	e.write(old)
	for range 2 {
		v := e.open()
		warns, _ := e.take()
		if len(warns) != 1 || warns[0] != v.Rollback().Message() || !v.Rollback().Older() {
			t.Fatalf("warnings %q", warns)
		}
		if r := recorded(t, e); r != 3 {
			t.Fatalf("record r%d, want unchanged r3", r)
		}
	}
	// A save of the older copy gives r3 again: still not higher.
	v := e.open()
	mustAdd(t, v, "c", "pw")
	if r := recorded(t, e); r != 3 {
		t.Fatalf("record r%d", r)
	}
}

// Safety test 11, third bullet: files in the backups folder and report-only
// opens (verify --full, merge's other file) never prompt or warn, but
// report the comparison.
func TestRollbackNoPrompt(t *testing.T) {
	e, old := olderCopy(t)
	backups := listBackups(t, e.state)
	if len(backups) != 2 {
		t.Fatalf("backups %v", backups)
	}
	for _, b := range backups {
		v := e.openFile(b.Path)
		if !v.Rollback().Older() {
			t.Errorf("%s: not reported as older", b.Path)
		}
	}
	// Through a symlink, too.
	link := filepath.Join(t.TempDir(), "restore-me.passh")
	if err := os.Symlink(backups[0].Path, link); err != nil {
		t.Fatal(err)
	}
	e.openFile(link)
	if warns, prompts := e.take(); len(warns) != 0 || len(prompts) != 0 {
		t.Fatalf("backups: prompts %q warnings %q", prompts, warns)
	}

	e.write(old)
	o := e.opts()
	o.RollbackReportOnly = true
	v, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), o)
	if err != nil {
		t.Fatal(err)
	}
	if warns, prompts := e.take(); len(warns) != 0 || len(prompts) != 0 {
		t.Fatalf("report only: prompts %q warnings %q", prompts, warns)
	}
	if st := v.Rollback(); !st.Older() || st.Message() == "" {
		t.Fatalf("report only: status %+v", st)
	}
	if r := recorded(t, e); r != 3 {
		t.Fatalf("record r%d", r)
	}
}

// Safety test 11, fourth bullet: with rollback.warn off nothing warns.
func TestRollbackOff(t *testing.T) {
	e, old := olderCopy(t)
	e.write(old)
	for _, noPrompt := range []bool{false, true} {
		e.noPrompt = noPrompt
		o := e.opts()
		o.RollbackWarn = false
		v, err := Open(context.Background(), e.path, keys.FromIdentity(e.key), o)
		if err != nil {
			t.Fatal(err)
		}
		if warns, prompts := e.take(); len(warns) != 0 || len(prompts) != 0 {
			t.Fatalf("warn off: prompts %q warnings %q", prompts, warns)
		}
		if !v.Rollback().Older() || recorded(t, e) != 3 {
			t.Fatal("warn off: the comparison or the record changed")
		}
	}
}

// Reload checks again, and a declined reload keeps the current state.
func TestRollbackOnReload(t *testing.T) {
	e, old := olderCopy(t)
	v := e.open()
	e.write(old)
	e.answer = false
	if err := v.Reload(context.Background()); !errors.Is(err, ErrRollbackDeclined) {
		t.Fatalf("reload: %v", err)
	}
	if v.Info().Revision != 3 {
		t.Fatal("declined reload changed the state")
	}
}

// A newer copy raises the record; a first open records it.
func TestRecordRaised(t *testing.T) {
	e := newEnv(t)
	v := e.open()
	mustAdd(t, v, "a", "pw")
	newer := e.read()
	// A machine without a record opens a copy (report-only, as verify
	// --full does): the copy's revision is recorded.
	if err := os.Remove(recordPath(e.state)); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "copy.passh")
	if err := os.WriteFile(copyPath, newer, 0o600); err != nil {
		t.Fatal(err)
	}
	o := e.opts()
	o.RollbackReportOnly = true
	if _, err := Open(context.Background(), copyPath, keys.FromIdentity(e.key), o); err != nil {
		t.Fatal(err)
	}
	if r := recorded(t, e); r != 2 {
		t.Fatalf("record r%d after the first open", r)
	}
}

// A damaged record warns and is replaced; it never stops a vault opening.
func TestDamagedRecord(t *testing.T) {
	e := newEnv(t)
	if err := os.WriteFile(recordPath(e.state), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := e.open()
	warns, _ := e.take()
	if len(warns) != 1 || v.Rollback().Seen {
		t.Fatalf("warnings %q", warns)
	}
	if r := recorded(t, e); r != 1 {
		t.Fatalf("record r%d", r)
	}
}
