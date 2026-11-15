package tui

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/devapro/passh/internal/clipboard"
	"github.com/devapro/passh/internal/editor"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vault"
)

func TestRevealAndAutoHide(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/github")
	h.lacks("s3cr3t-P@ss", "JBSWY3DP")
	h.contains("password  ••••••••", "otp       ••••••••", "[c]opy [r]eveal")
	h.press("r")
	h.contains("s3cr3t-P@ss", "otpauth://totp/x?secret=JBSWY3DP", "shown for 10 s more")
	// The hide timer is scheduled for 10 s (S5).
	var hide *timer
	for i := range h.timers {
		if _, ok := h.timers[i].msg.(hideMsg); ok {
			hide = &h.timers[i]
		}
	}
	if hide == nil || hide.d != editor.RevealDuration {
		t.Fatalf("no 10 s hide timer: %+v", h.timers)
	}
	h.clock.Advance(9 * time.Second)
	h.send(tickMsg{})
	h.contains("s3cr3t-P@ss", "shown for 1 s more")
	h.clock.Advance(time.Second)
	h.send(tickMsg{})
	h.lacks("s3cr3t-P@ss")
	h.contains("password  ••••••••")

	// The timer message hides too; r toggles.
	h.press("r")
	h.contains("s3cr3t-P@ss")
	h.send(hide.msg) // a stale timer: ignored
	h.contains("s3cr3t-P@ss")
	h.send(h.timers[len(h.timers)-1].msg)
	h.lacks("s3cr3t-P@ss")
	h.press("r", "r")
	h.lacks("s3cr3t-P@ss")

	// Moving to another entry hides it.
	h.press("r", "down")
	h.press("up")
	h.lacks("s3cr3t-P@ss")
}

func TestCopy(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/github")
	h.press("c")
	if len(h.clip.copies) != 1 || h.clip.copies[0] != (copyRec{"s3cr3t-P@ss", 30 * time.Second}) {
		t.Fatalf("copies %+v", h.clip.copies)
	}
	h.contains("Password copied · clears in 30 s")
	h.lacks("s3cr3t-P@ss")
	h.clock.Advance(12 * time.Second)
	h.send(tickMsg{})
	h.contains("clears in 18 s")
	h.press("u")
	if h.clip.copies[1].value != "arsenii" {
		t.Fatalf("copies %+v", h.clip.copies)
	}
	h.contains("Username copied · clears in 30 s")
	h.clock.Advance(30 * time.Second)
	h.send(tickMsg{})
	h.contains("Clipboard cleared.")

	// Nothing to copy.
	h.selectPath("readme")
	h.press("u")
	h.contains("readme has no username.")
	if len(h.clip.copies) != 2 {
		t.Fatal("copied an empty value")
	}
}

// Without a clipboard, copying shows the hint of §6.3 and never the
// secret.
func TestCopyWithoutClipboard(t *testing.T) {
	noClip := &clipboard.NoClipboardError{Reason: "clipboard.osc52 is off and clipboard.command is empty"}
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) { d.clip, d.clipErr = nil, noClip })
	h.selectPath("work/github")
	h.press("c")
	h.contains("no clipboard", "copy with: passh show work/github --field password | pbcopy")
	h.lacks("s3cr3t-P@ss")

	// A failing copy shows the error, not the secret.
	h = newHarness(t, sampleEntries())
	h.clip.err = errors.New("clipboard command: exit status 1")
	h.selectPath("work/github")
	h.press("c")
	h.contains("Not copied: clipboard command: exit status 1")
	h.lacks("s3cr3t-P@ss")
}

func TestEditRoundTrip(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/github")
	h.press("e")
	if h.m.form == nil {
		t.Fatal("e didn't open the form")
	}
	h.contains("edit work/github", "ctrl+s save")
	h.press("tab", "ctrl+u") // username
	h.typeText("bob")
	h.press("ctrl+s")
	if h.m.form != nil {
		t.Fatalf("the form is still open:\n%s", h.plain())
	}
	h.contains("Saved work/github.", "username  bob")
	got, _ := h.diskEntry("work/github")
	if got.Username != "bob" || got.Password != "s3cr3t-P@ss" || len(got.Fields) != 2 {
		t.Fatalf("on disk: %+v", got)
	}
	// An unchanged form saves nothing.
	h.press("e", "ctrl+s")
	h.contains("No changes.")
	// Esc cancels.
	h.press("e", "esc")
	if h.m.form != nil {
		t.Fatal("esc didn't close an unchanged form")
	}
	h.contains("Cancelled.")
}

func TestAddRoundTrip(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/jira")
	h.press("a")
	if h.m.prompt == nil || h.m.prompt.in.String() != "work/" {
		t.Fatalf("the path prompt should start with the folder: %+v", h.m.prompt)
	}
	h.contains("New entry's path: work/")
	// An existing path and an invalid one are refused in the prompt.
	h.typeText("jira")
	h.press("enter")
	h.contains("work/jira already exists")
	h.press("ctrl+u")
	h.typeText("../x")
	h.press("enter")
	h.contains("invalid path")
	h.press("ctrl+u")
	h.typeText("work/gitlab")
	h.press("enter")
	if h.m.form == nil {
		t.Fatalf("no form:\n%s", h.plain())
	}
	h.contains("add work/gitlab")
	h.typeText("new-secret")
	h.press("tab")
	h.typeText("me")
	h.press("tab", "tab")
	h.typeText("work, new")
	h.press("ctrl+s")
	h.contains("Added work/gitlab.")
	got, ok := h.diskEntry("work/gitlab")
	if !ok || got.Password != "new-secret" || got.Username != "me" || !slices.Equal(got.Tags, []string{"work", "new"}) {
		t.Fatalf("on disk: %+v", got)
	}
	if e, _ := h.m.selectedEntry(); e.Path.String() != "work/gitlab" {
		t.Fatalf("selected %s", e.Path)
	}
	// Esc in the prompt cancels.
	h.press("a", "esc")
	if h.m.prompt != nil {
		t.Fatal("esc didn't close the prompt")
	}
}

func TestDeleteRoundTrip(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("bank/chase")
	h.press("d")
	h.contains("Delete bank/chase? [y/N]")
	h.press("n")
	h.contains("Not deleted.")
	if _, ok := h.diskEntry("bank/chase"); !ok {
		t.Fatal("deleted after no")
	}
	h.press("d", "y")
	h.contains("Deleted bank/chase.")
	if _, ok := h.diskEntry("bank/chase"); ok {
		t.Fatal("not deleted")
	}
	h.wantList("v bank", "*  revolut", "> homelab", "> work", "readme")
}

func TestTagsRoundTrip(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/github")
	h.press("t")
	if h.m.prompt == nil || h.m.prompt.in.String() != "work, dev, 2fa" {
		t.Fatalf("tags prompt %+v", h.m.prompt)
	}
	h.press("ctrl+u")
	h.typeText("work, a,b")
	h.press("enter")
	h.contains("Tags of work/github saved.")
	got, _ := h.diskEntry("work/github")
	if !slices.Equal(got.Tags, []string{"work", "a", "b"}) {
		t.Fatalf("tags %v", got.Tags)
	}
	// Invalid tags are refused in the prompt; unchanged tags save nothing.
	h.press("t", "ctrl+u")
	h.send(pasteMsg("a, \u0007bell"))
	h.press("enter")
	h.contains("invalid tag")
	h.press("ctrl+u")
	h.typeText("work, a, b")
	h.press("enter")
	h.contains("No changes.")
}

func TestMoveRoundTrip(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/jira")
	h.press("m", "ctrl+u")
	h.typeText("work/bank")
	h.press("enter")
	h.contains("Moved work/jira to work/bank.")
	if _, ok := h.diskEntry("work/bank"); !ok {
		t.Fatal("not moved")
	}
	h.press("m", "ctrl+u")
	h.typeText("work/github")
	h.press("enter")
	h.contains("already exists")
	h.press("esc")
}

// "Vault changed on disk": polling shows the banner, changes are blocked,
// R reloads, and a save refused meanwhile keeps the form's values.
func TestChangedOnDisk(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.send(pollMsg{})
	h.lacks("changed on disk")
	h.external(func(v *vault.Vault) {
		if _, err := v.Add(entry("other/machine", nil), false); err != nil {
			t.Fatal(err)
		}
	})
	h.send(pollMsg{})
	h.contains("Vault changed on disk — R to reload")
	for _, k := range []string{"e", "a", "t", "m", "d"} {
		h.selectPath("work/github")
		h.press(k)
		if h.m.form != nil || h.m.prompt != nil || h.m.confirm != nil {
			t.Fatalf("%s opened while the vault changed on disk", k)
		}
	}
	h.contains("Changes are blocked")
	h.press("R")
	h.lacks("changed on disk")
	h.contains("Reloaded: revision 2, 7 entries.", "other")

	// Now the change happens while the form is open.
	h.selectPath("work/github")
	h.press("e", "tab", "ctrl+u")
	h.typeText("edited-user")
	h.external(func(v *vault.Vault) { // changes another value of the same entry
		e, _ := v.Get(paths.MustParse("work/github"))
		e.URL = "https://changed.example"
		if _, err := v.Update(e); err != nil {
			t.Fatal(err)
		}
	})
	h.press("ctrl+s")
	if h.m.form != nil || h.m.kept == nil {
		t.Fatal("a refused save should close the form and keep the input")
	}
	h.contains("Not saved: the vault changed on disk", "your input is kept")
	got, _ := h.diskEntry("work/github")
	if got.Username != "arsenii" {
		t.Fatal("saved over a changed vault")
	}
	h.press("R")
	if h.m.form == nil {
		t.Fatalf("the form didn't come back after R:\n%s", h.plain())
	}
	h.contains("edit work/github (not saved yet)", "your input is back", "It changed on disk too")
	// Esc asks before dropping kept input.
	h.press("esc")
	h.contains("Discard the changes that weren't saved?")
	h.press("x") // keep editing
	h.press("ctrl+s")
	h.contains("Saved work/github.")
	got, _ = h.diskEntry("work/github")
	if got.Username != "edited-user" || got.URL != "https://changed.example" {
		t.Fatalf("the reload lost a change: %+v", got)
	}
}

// When the change on disk didn't touch the edited entry, the same form
// comes back (Form.Resume), with its "changed" state intact.
func TestChangedOnDiskResumesSameForm(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/github")
	h.press("e", "tab", "ctrl+u")
	h.typeText("edited-user")
	f := h.m.form
	h.external(func(v *vault.Vault) {
		if _, err := v.Add(entry("other/entry", nil), false); err != nil {
			t.Fatal(err)
		}
	})
	h.press("ctrl+s")
	if h.m.form != nil || h.m.kept == nil {
		t.Fatal("a refused save should hide the form and keep it")
	}
	h.press("R")
	if h.m.form != f || h.m.fctx.resumed {
		t.Fatal("the same form should come back")
	}
	h.contains("Reloaded: your input is back; ctrl+s saves it.", "edited-user")
	if !f.Changed() {
		t.Fatal("the form lost its changes")
	}
	h.press("ctrl+s")
	h.contains("Saved work/github.")
	got, _ := h.diskEntry("work/github")
	if got.Username != "edited-user" {
		t.Fatalf("on disk: %+v", got)
	}
	if _, ok := h.diskEntry("other/entry"); !ok {
		t.Fatal("the change on disk was lost")
	}
}

// A save refused for another reason reopens the form at once with the
// error, values intact.
func TestRefusedSaveResumesForm(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.press("a", "ctrl+u")
	h.typeText("work/new")
	h.press("enter")
	f := h.m.form
	h.typeText("pw")
	// Someone adds the same path meanwhile, and the TUI already knows the
	// file changed (reloaded), so the save fails with "already exists".
	h.external(func(v *vault.Vault) {
		if _, err := v.Add(entry("work/new", nil), false); err != nil {
			t.Fatal(err)
		}
	})
	h.send(pollMsg{})
	if !h.m.changedOnDisk {
		t.Fatal("not detected")
	}
	h.m.changedOnDisk = false
	if err := h.m.v.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.press("ctrl+s")
	if h.m.form != f || f.Done() {
		t.Fatalf("the form didn't come back:\n%s", h.plain())
	}
	h.contains("Not saved: work/new: already exists")
	h.press("esc")
	h.contains("Discard the changes?")
}

// A prompt's save refused by a change on disk keeps its text too.
func TestChangedOnDiskKeepsPrompt(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("work/github")
	h.press("t", "ctrl+u")
	h.typeText("kept-tag")
	h.external(func(v *vault.Vault) {
		if _, err := v.Add(entry("x/y", nil), false); err != nil {
			t.Fatal(err)
		}
	})
	h.press("enter")
	if h.m.prompt != nil || h.m.kept == nil {
		t.Fatal("the prompt should be kept for after the reload")
	}
	h.press("R")
	if h.m.prompt == nil || h.m.prompt.in.String() != "kept-tag" {
		t.Fatalf("prompt after reload: %+v", h.m.prompt)
	}
	h.press("enter")
	got, _ := h.diskEntry("work/github")
	if !slices.Equal(got.Tags, []string{"kept-tag"}) {
		t.Fatalf("tags %v", got.Tags)
	}

	// Delete and move are refused too, without saving.
	h.external(func(v *vault.Vault) {
		if err := v.Remove(paths.MustParse("x/y")); err != nil {
			t.Fatal(err)
		}
	})
	h.selectPath("readme")
	h.press("d", "y")
	h.contains("Not deleted: the vault changed on disk")
	if _, ok := h.diskEntry("readme"); !ok {
		t.Fatal("deleted over a changed vault")
	}
}

// An entry deleted on disk while its edit was refused comes back as an
// add.
func TestKeptEditOfDeletedEntry(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.selectPath("readme")
	h.press("e", "tab")
	h.typeText("u")
	h.external(func(v *vault.Vault) {
		if err := v.Remove(paths.MustParse("readme")); err != nil {
			t.Fatal(err)
		}
	})
	h.press("ctrl+s", "R")
	h.contains("readme was deleted on disk: saving adds it again.", "add readme")
	h.press("ctrl+s")
	got, ok := h.diskEntry("readme")
	if !ok || got.Username != "u" {
		t.Fatalf("readme: %+v %v", got, ok)
	}
}

func TestReloadAfterRekeyNeedsUnlock(t *testing.T) {
	h := newHarness(t, sampleEntries(), withPassphrase())
	h.typeText(testPass)
	h.press("enter")
	h.mustUnlocked()
	h.external(func(v *vault.Vault) {
		if _, err := v.Rekey([]byte("x")); err != nil {
			t.Fatal(err)
		}
	})
	h.send(pollMsg{})
	h.press("R")
	h.contains("Reload failed", "rekeyed elsewhere")
	if !h.m.changedOnDisk {
		t.Fatal("saving should stay blocked")
	}
}

type fakeDialog struct {
	stopped, done bool
	msgs          []tea.Msg
	copied        error
	req           PrintRequest
}

func (d *fakeDialog) Init() tea.Cmd { return nil }
func (d *fakeDialog) Update(msg tea.Msg) tea.Cmd {
	d.msgs = append(d.msgs, msg)
	if k, ok := msg.(tea.KeyPressMsg); ok {
		switch k.String() {
		case "esc":
			d.done = true
		case "c":
			d.copied = d.req.Copy("https://10.0.0.2:8443/p/token")
		}
	}
	return nil
}
func (d *fakeDialog) View(w, h int) string { return "PRINT DIALOG \x1b]52;c;x\x07" }
func (d *fakeDialog) Done() bool           { return d.done }
func (d *fakeDialog) Stop()                { d.stopped = true }

func TestPrintPage(t *testing.T) {
	var dlg *fakeDialog
	page := func(ctx context.Context, req PrintRequest) (PrintDialog, error) {
		dlg = &fakeDialog{req: req}
		if len(req.Data.Entries) != 6 {
			t.Errorf("print page got %d entries", len(req.Data.Entries))
		}
		return dlg, nil
	}
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) { d.print = page })
	h.press("P")
	h.contains("The print page is off", "print_web.enabled")
	h.cfg.PrintWeb.Enabled = true
	h.press("P", "enter")
	h.typeText("print")
	h.press("enter")
	h.contains("Not confirmed")
	if dlg != nil {
		t.Fatal("started without PRINT")
	}
	h.press("P", "enter")
	h.typeText("PRINT")
	h.press("enter")
	if dlg == nil || h.m.printDlg == nil {
		t.Fatal("the print page didn't start")
	}
	h.contains("PRINT DIALOG", `\x1b]52;c;x\x07`)
	h.checkInert("print dialog")
	h.press("c")
	if dlg.copied != nil || h.clip.copies[0].value != "https://10.0.0.2:8443/p/token" {
		t.Fatalf("copy URL: %v %+v", dlg.copied, h.clip.copies)
	}
	h.send(hideMsg{seq: 999}) // other messages reach the dialog... hideMsg is ours
	h.send(struct{ x int }{1})
	if len(dlg.msgs) != 2 {
		t.Fatalf("dialog got %d messages", len(dlg.msgs))
	}
	h.press("esc")
	if h.m.printDlg != nil || !dlg.stopped {
		t.Fatal("Esc didn't close the dialog")
	}
	h.contains("Print page stopped.")
	// A lock stops a running print page (§7.4).
	h.press("P", "enter")
	h.typeText("PRINT")
	h.press("enter")
	d2 := dlg
	h.clock.Advance(h.cfg.Session.IdleTTL)
	h.send(tickMsg{})
	if !d2.stopped || h.m.screen != screenLock {
		t.Fatal("the lock didn't stop the print page")
	}
}

func TestHelp(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.press("?")
	h.contains("Keys", "fuzzy search", "lock now", "quit (locks)")
	h.press("down", "up")
	h.press("x")
	if h.m.help {
		t.Fatal("a key didn't close the help")
	}
}

func TestRebase(t *testing.T) {
	orig := model.Entry{Password: "p", Username: "u", URL: "url", Tags: []string{"a"}, Notes: "n"}
	cur := orig.Clone()
	cur.URL = "url2"
	edited := orig.Clone()
	edited.Password, edited.Tags, edited.Notes = "p2", []string{"b"}, "n2"
	got := rebase(cur, orig, edited)
	if got.Password != "p2" || got.URL != "url2" || got.Username != "u" || !slices.Equal(got.Tags, []string{"b"}) || got.Notes != "n2" {
		t.Fatalf("rebase: %+v", got)
	}
}

func TestStatusExpires(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.contains("Unlocked")
	h.clock.Advance(statusTTL)
	h.send(tickMsg{})
	h.lacks("Unlocked:")
	h.contains("unlocked · locks in")
}
