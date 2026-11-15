package tui

import (
	"context"
	"slices"
	"testing"

	"passh/internal/paths"
	"passh/internal/print"
	"passh/internal/printweb"
)

// L locks from every screen that isn't a text field (§5.2).
func TestLockKeyFromEveryScreen(t *testing.T) {
	enable := func(h *harness, d *deps) { h.cfg.PrintWeb.Enabled = true }
	for _, tc := range []struct {
		name string
		open func(h *harness)
	}{
		{"list", func(h *harness) {}},
		{"tags view", func(h *harness) { h.press("tab", "space") }},
		{"detail", func(h *harness) { h.selectPath("work/github"); h.press("enter", "r") }},
		{"help", func(h *harness) { h.press("?") }},
		{"search results", func(h *harness) { h.press("/"); h.typeText("git"); h.press("enter") }},
		{"delete question", func(h *harness) { h.selectPath("work/github"); h.press("d") }},
		{"print setup", func(h *harness) { h.press("P") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, sampleEntries(), enable)
			tc.open(h)
			h.press("L")
			if h.m.screen != screenLock {
				t.Fatalf("L didn't lock:\n%s", h.plain())
			}
			h.lacks("github", "s3cr3t")
			if _, ok := h.diskEntry("work/github"); !ok {
				t.Fatal("the delete question answered yes")
			}
		})
	}
}

// L in the print dialog locks, and the lock stops the print page (§7.4).
func TestLockKeyInPrintDialog(t *testing.T) {
	h, page, _ := printHarness(t)
	h.press("L")
	if h.m.screen != screenLock || h.m.printDlg != nil || page.stopCount() == 0 {
		t.Fatalf("screen %v, dialog %v, stops %d", h.m.screen, h.m.printDlg != nil, page.stopCount())
	}
	// The outcome screen too.
	h, page, _ = printHarness(t)
	page.end(printweb.Result{Outcome: printweb.Expired})
	h.send(printTickMsg{h.dialog().id})
	h.press("L")
	if h.m.screen != screenLock {
		t.Fatal("L on the outcome screen didn't lock")
	}
}

// L during the rollback question locks and answers no.
func TestLockKeyDuringRollbackQuestion(t *testing.T) {
	h := reloadRollbackHarness(t)
	h.press("L")
	h.run(nil)
	if h.m.screen != screenLock {
		t.Fatal("not locked")
	}
}

// In a text field L is a letter.
func TestLockKeyIsALetterInTextFields(t *testing.T) {
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) { h.cfg.PrintWeb.Enabled = true })
	h.press("/", "L")
	if h.m.screen != screenMain || h.m.search.in.String() != "L" {
		t.Fatal("L in the search")
	}
	h.press("esc")
	h.selectPath("work/github")
	h.press("t", "ctrl+u", "L")
	if h.m.screen != screenMain || h.m.prompt.in.String() != "L" {
		t.Fatal("L in the tags prompt")
	}
	h.press("esc", "e", "tab", "ctrl+u", "L")
	if h.m.screen != screenMain || h.m.form == nil {
		t.Fatal("L in the form")
	}
	h.press("ctrl+s")
	if e, _ := h.diskEntry("work/github"); e.Username != "L" {
		t.Fatalf("username %q", e.Username)
	}
	h.press("P", "enter", "L")
	if h.m.screen != screenMain || h.m.prompt.in.String() != "L" {
		t.Fatal("L in the PRINT prompt")
	}
	h.press("esc", "?")
	h.contains("lock now (in a text field L is a letter)")
}

// P asks what to print: the folder under the cursor by default in the
// Folders view, the selected tags in the Tags view; and which fields.
func TestPrintSetup(t *testing.T) {
	var got PrintRequest
	page := func(ctx context.Context, req PrintRequest) (PrintDialog, error) {
		got = req
		return &fakeDialog{req: req}, nil
	}
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) { h.cfg.PrintWeb.Enabled = true; d.print = page })
	h.selectPath("work/github")
	h.press("P")
	h.contains("Print page: what to print", "( ) all entries (6 entries)", "(•) folder work/ (2 entries)",
		"[x] password", "[x] username", "[x] url", "[ ] custom fields", "space choose")
	// Fields: drop username, add custom fields.
	h.press("down", "down", "space", "down", "down", "space")
	h.contains("[ ] username", "[x] custom fields")
	h.press("enter")
	h.contains("Type PRINT")
	h.typeText("PRINT")
	h.press("enter")
	want := print.Options{Folder: paths.MustParse("work"), Fields: []string{print.FieldPassword, print.FieldURL, print.FieldCustom}}
	if got.Sheet.Folder != want.Folder || got.Sheet.Tags != nil || !slices.Equal(got.Sheet.Fields, want.Fields) {
		t.Fatalf("sheet options %+v, want %+v", got.Sheet, want)
	}
	h.press("esc")

	// All entries, chosen by hand.
	h.press("P", "up", "space", "enter")
	h.typeText("PRINT")
	h.press("enter")
	if !got.Sheet.Folder.IsZero() || got.Sheet.Tags != nil || !slices.Equal(got.Sheet.Fields, print.DefaultFields) {
		t.Fatalf("all: %+v", got.Sheet)
	}
	h.press("esc")

	// Tags view: the selected tags (AND).
	h.press("tab", "space") // 2fa
	h.press("P")
	h.contains("(•) tags 2fa (2 entries)")
	h.press("enter")
	h.typeText("PRINT")
	h.press("enter")
	if !slices.Equal(got.Sheet.Tags, []string{"2fa"}) || !got.Sheet.Folder.IsZero() {
		t.Fatalf("tags: %+v", got.Sheet)
	}
	h.press("esc")

	// No field, then Esc.
	h.press("P", "down", "space", "down", "space", "down", "space", "enter")
	h.contains("Choose at least one field.")
	h.press("esc")
	if h.m.printSetup != nil {
		t.Fatal("Esc didn't cancel")
	}
	h.contains("Print page cancelled.")
}

// The default print page builds the sheet from the choice.
func TestPrintSetupBuildsSheet(t *testing.T) {
	var opts printweb.Options
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) {
		h.cfg.PrintWeb.Enabled = true
		d.startPage = func(ctx context.Context, o printweb.Options) (pageInfo, pageServer, error) {
			opts = o
			return pageInfo{URLs: []string{url1}, Fingerprint: fp, Expires: h.clock.Now().Add(5 * 60e9)}, newFakePage(), nil
		}
	})
	h.selectPath("work/github")
	h.press("P", "end", "space", "enter")
	h.typeText("PRINT")
	h.press("enter")
	sheet, ok := opts.Doc.(*print.Sheet)
	if !ok || sheet.Len() != 2 || !slices.Equal(sheet.Fields(), []string{"password", "username", "url", "fields"}) {
		t.Fatalf("sheet: %v %d %v", ok, sheet.Len(), sheet.Fields())
	}
}

func TestPrintSetupNarrow(t *testing.T) {
	h := newHarness(t, sampleEntries(), func(h *harness, d *deps) { h.cfg.PrintWeb.Enabled = true })
	h.resize(40, 20)
	h.selectPath("homelab/pi/ssh")
	h.press("P")
	h.checkFits(40, 20, "print setup")
	h.contains("folder homelab/pi/", "custom fields", "Enter continue")
	h.resize(80, 24)
	h.checkFits(80, 24, "print setup")
}
