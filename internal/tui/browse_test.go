package tui

import (
	"strings"
	"testing"

	"passh/internal/model"
)

// listText returns the list's rows as plain text, for assertions.
func (h *harness) listText() []string {
	rows, idx := h.m.rowsAndCursor()
	out := make([]string, len(rows))
	for i, r := range rows {
		s := strings.Repeat("  ", r.depth) + r.label
		switch r.kind {
		case rowFolder:
			if r.open {
				s = strings.Repeat("  ", r.depth) + "v " + r.label
			} else {
				s = strings.Repeat("  ", r.depth) + "> " + r.label
			}
		case rowTag:
			if r.open {
				s = "[x] " + r.label
			} else {
				s = "[ ] " + r.label
			}
		}
		if i == idx {
			s = "*" + s
		}
		out[i] = s
	}
	return out
}

func (h *harness) wantList(want ...string) {
	h.t.Helper()
	got := h.listText()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		h.t.Fatalf("list:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFolderNavigation(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.wantList("*> bank", "> homelab", "> work", "readme")
	h.contains("▸ bank", "(2)", "▸ work", "(2)", "▸ homelab", "(1)", "bank/", "2 entries")

	h.press("enter") // open bank
	h.wantList("*v bank", "  chase", "  revolut", "> homelab", "> work", "readme")
	h.contains("▾ bank")
	h.press("down")
	h.wantList("v bank", "*  chase", "  revolut", "> homelab", "> work", "readme")
	// The detail pane shows the selected entry, password masked.
	h.contains("bank/chase", "username  chase-user", "password  ••••••••")
	h.lacks("pw-bank/chase")

	h.press("left") // to the parent folder
	h.wantList("*v bank", "  chase", "  revolut", "> homelab", "> work", "readme")
	h.press("left") // close it
	h.wantList("*> bank", "> homelab", "> work", "readme")

	h.press("down", "right", "right") // homelab, then pi (a nested folder)
	h.wantList("> bank", "v homelab", "*  > pi", "> work", "readme")
	h.press("enter", "down")
	h.wantList("> bank", "v homelab", "  v pi", "*    ssh", "> work", "readme")
	h.press("end")
	h.wantList("> bank", "v homelab", "  v pi", "    ssh", "> work", "*readme")
	h.press("home")
	h.wantList("*> bank", "v homelab", "  v pi", "    ssh", "> work", "readme")
	h.press("up") // stays at the top
	h.wantList("*> bank", "v homelab", "  v pi", "    ssh", "> work", "readme")
	h.press("pgdown")
	h.wantList("> bank", "v homelab", "  v pi", "    ssh", "> work", "*readme")

	// Enter on an entry opens the full detail; Esc goes back.
	h.press("enter")
	if !h.m.detail {
		t.Fatal("Enter on an entry didn't open its detail")
	}
	h.contains("readme", "Esc back")
	h.press("esc")
	if h.m.detail {
		t.Fatal("Esc didn't close the detail")
	}
	h.wantList("> bank", "v homelab", "  v pi", "    ssh", "> work", "*readme")
}

func TestEmptyVault(t *testing.T) {
	h := newHarness(t, nil)
	h.contains("No entries yet: a adds one.")
	h.press("c", "down", "enter", "r", "e", "d", "t", "m")
	h.contains("Select an entry first.")
	h.press("tab")
	h.contains("No tags yet")
}

func TestTagsViewAND(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.press("tab")
	if h.m.view != viewTags {
		t.Fatal("Tab didn't switch to the Tags view")
	}
	h.contains("[Tags]", "[ ] 2fa", "(2)", "[ ] work", "Space selects tags")
	// Tags sorted by name: 2fa dev finance homelab work.
	h.wantList("*[ ] 2fa", "[ ] dev", "[ ] finance", "[ ] homelab", "[ ] work",
		"Space selects tags; the entries that have all of them show here.")
	h.press("space") // 2fa
	h.wantList("*[x] 2fa", "[ ] dev", "[ ] finance", "[ ] homelab", "[ ] work",
		"── 2 entries with 2fa ──", "bank/revolut", "work/github")
	h.press("down", "down", "enter") // finance too: AND
	h.wantList("[x] 2fa", "[ ] dev", "*[x] finance", "[ ] homelab", "[ ] work",
		"── 1 entry with 2fa + finance ──", "bank/revolut")
	h.press("down", "down", "space") // work: no entry has all three
	h.wantList("[x] 2fa", "[ ] dev", "[x] finance", "[ ] homelab", "*[x] work",
		"── 0 entries with 2fa + finance + work ──")
	h.press("up", "up", "enter") // drop finance: 2fa + work
	h.wantList("[x] 2fa", "[ ] dev", "*[ ] finance", "[ ] homelab", "[x] work",
		"── 1 entry with 2fa + work ──", "work/github")
	h.press("down", "down", "down") // onto the entry, skipping the note
	h.wantList("[x] 2fa", "[ ] dev", "[ ] finance", "[ ] homelab", "[x] work",
		"── 1 entry with 2fa + work ──", "*work/github")
	h.contains("username  arsenii")
	h.press("c")
	if len(h.clip.copies) != 1 || h.clip.copies[0].value != "s3cr3t-P@ss" {
		t.Fatalf("copies %+v", h.clip.copies)
	}
	h.press("esc") // clears the selection
	h.wantList("[ ] 2fa", "[ ] dev", "[ ] finance", "[ ] homelab", "*[ ] work",
		"Space selects tags; the entries that have all of them show here.")
	h.press("tab")
	if h.m.view != viewFolders {
		t.Fatal("Tab didn't switch back")
	}
}

func TestSearch(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.press("/")
	if !h.m.search.typing {
		t.Fatal("/ didn't open the search")
	}
	h.typeText("gthb")
	h.wantList("*work/github")
	h.contains("/ gthb")
	// Keys type while searching; c is text here.
	h.typeText("c")
	h.wantList("No matches.")
	h.press("backspace")
	h.press("enter")
	if h.m.search.typing || !h.m.search.active {
		t.Fatal("Enter should keep the results and stop typing")
	}
	h.press("c") // now c copies
	if len(h.clip.copies) != 1 || h.clip.copies[0].value != "s3cr3t-P@ss" {
		t.Fatalf("copies %+v", h.clip.copies)
	}
	h.press("esc")
	if h.m.search.active {
		t.Fatal("Esc didn't close the search")
	}

	// Tags are searched too: "homelab" is a tag of homelab/pi/ssh, and
	// "finance" matches only through tags.
	h.press("/")
	h.typeText("finance")
	got := h.listText()
	if len(got) != 2 || !strings.HasSuffix(got[0], "bank/chase") || !strings.HasSuffix(got[1], "bank/revolut") {
		t.Fatalf("finance: %v", got)
	}
	h.contains("#finance")
	h.press("down", "enter") // Enter accepts; the list keeps the cursor
	h.press("enter")         // and opens the entry
	if !h.m.detail || h.m.detailID == "" {
		t.Fatal("Enter on a result didn't open it")
	}
	if e, _ := h.m.selectedEntry(); e.Path.String() != "bank/revolut" {
		t.Fatalf("opened %s", e.Path)
	}
	h.press("esc", "esc")
	// An empty query lists everything; Enter on no results closes.
	h.press("/")
	if len(h.listText()) != 6 {
		t.Fatalf("empty query: %v", h.listText())
	}
	h.typeText("zzzz")
	h.press("enter")
	if h.m.search.active {
		t.Fatal("Enter with no results should close the search")
	}
	// Tab while typing closes the search and switches the view.
	h.press("/")
	h.typeText("w")
	h.press("tab")
	if h.m.search.active || h.m.view != viewTags {
		t.Fatal("Tab while searching")
	}
}

func TestSearchPasteAndRefresh(t *testing.T) {
	h := newHarness(t, sampleEntries())
	h.press("/")
	h.send(pasteMsg("jira\n"))
	h.wantList("*work/jira")
	h.press("enter", "d", "y")
	h.wantList("No matches.")
	if _, ok := h.diskEntry("work/jira"); ok {
		t.Fatal("not deleted")
	}
}

func TestBuildTreeCounts(t *testing.T) {
	es := sampleEntries()
	for i := range es {
		es[i].ID = es[i].Path.String()
	}
	root := buildTree(model.NewData().List())
	if root.count != 0 {
		t.Fatal("empty tree")
	}
	root = buildTree(sortEntries(es))
	if root.count != 6 || len(root.folders) != 3 || len(root.entries) != 1 {
		t.Fatalf("root %d, %d folders, %d entries", root.count, len(root.folders), len(root.entries))
	}
	if hl := root.byName["homelab"]; hl.count != 1 || hl.byName["pi"].path != "homelab/pi" {
		t.Fatal("nested folder")
	}
}

func sortEntries(es []model.Entry) []model.Entry {
	d := model.NewData()
	d.Entries = es
	return d.List()
}
