package tui

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sahilm/fuzzy"

	"passh/internal/editor"
	"passh/internal/model"
	"passh/internal/paths"
)

type rowKind int

const (
	rowFolder rowKind = iota
	rowEntry
	rowTag
	rowNote // text only; the cursor skips it
)

// row is one line of the list.
type row struct {
	kind  rowKind
	depth int
	label string // raw; escaped when drawn
	count int
	key   string // "f:"+folder, "e:"+entry id, "t:"+tag; "" for notes
	open  bool   // folder expanded, tag selected
	note  string // search: the tag that matched
}

func (r row) selectable() bool { return r.kind != rowNote }

// folder is a node of the Folders view's tree.
type folder struct {
	name    string
	path    string
	count   int // entries at any depth
	folders []*folder
	byName  map[string]*folder
	entries []leaf
}

type leaf struct{ id, name string }

// buildTree builds the folder tree of entries (sorted by path).
func buildTree(entries []model.Entry) *folder {
	root := &folder{byName: map[string]*folder{}}
	for _, e := range entries {
		segs := e.Path.Segments()
		f := root
		f.count++
		for i, s := range segs[:len(segs)-1] {
			c, ok := f.byName[s]
			if !ok {
				c = &folder{name: s, path: strings.Join(segs[:i+1], "/"), byName: map[string]*folder{}}
				f.byName[s] = c
				f.folders = append(f.folders, c)
			}
			c.count++
			f = c
		}
		f.entries = append(f.entries, leaf{id: e.ID, name: segs[len(segs)-1]})
	}
	return root
}

// rows lists the folder's visible rows: subfolders first, then entries.
func (f *folder) rows(depth int, expanded map[string]bool, out []row) []row {
	for _, c := range f.folders {
		open := expanded[c.path]
		out = append(out, row{kind: rowFolder, depth: depth, label: c.name, count: c.count, key: "f:" + c.path, open: open})
		if open {
			out = c.rows(depth+1, expanded, out)
		}
	}
	for _, l := range f.entries {
		out = append(out, row{kind: rowEntry, depth: depth, label: l.name, key: "e:" + l.id})
	}
	return out
}

// searchState is the fuzzy search (§6.2) over paths and tags.
type searchState struct {
	active  bool
	typing  bool
	in      editor.LineInput
	results []searchResult
}

type searchResult struct {
	id, path, tag string
	score         int
}

func (s *searchState) wipe() {
	s.in.Wipe()
	*s = searchState{}
}

// run searches entries for the query: an entry matches by its path or by
// any of its tags, with its best score. An empty query lists everything.
func (s *searchState) run(entries []model.Entry) {
	q := s.in.String()
	s.results = s.results[:0]
	if strings.TrimSpace(q) == "" {
		for _, e := range entries {
			s.results = append(s.results, searchResult{id: e.ID, path: e.Path.String()})
		}
		return
	}
	best := map[int]searchResult{}
	ps := make([]string, len(entries))
	for i, e := range entries {
		ps[i] = e.Path.String()
	}
	for _, mt := range fuzzy.Find(q, ps) {
		best[mt.Index] = searchResult{id: entries[mt.Index].ID, path: ps[mt.Index], score: mt.Score}
	}
	tagged := map[string][]int{}
	var names []string
	for i, e := range entries {
		for _, t := range e.Tags {
			if _, ok := tagged[t]; !ok {
				names = append(names, t)
			}
			tagged[t] = append(tagged[t], i)
		}
	}
	for _, mt := range fuzzy.Find(q, names) {
		t := names[mt.Index]
		for _, i := range tagged[t] {
			if cur, ok := best[i]; !ok || mt.Score > cur.score {
				best[i] = searchResult{id: entries[i].ID, path: ps[i], tag: t, score: mt.Score}
			}
		}
	}
	for _, r := range best {
		s.results = append(s.results, r)
	}
	sort.Slice(s.results, func(i, j int) bool {
		a, b := s.results[i], s.results[j]
		if a.score != b.score {
			return a.score > b.score
		}
		return a.path < b.path
	})
}

// list is the list on screen: the search results while a search is
// active, else the Folders or Tags view.
func (m *app) list() viewKind {
	if m.search.active {
		return viewSearch
	}
	return m.view
}

func (m *app) rows() []row {
	switch m.list() {
	case viewSearch:
		if len(m.search.results) == 0 {
			return []row{{kind: rowNote, label: "No matches."}}
		}
		out := make([]row, 0, len(m.search.results))
		for _, r := range m.search.results {
			out = append(out, row{kind: rowEntry, label: r.path, key: "e:" + r.id, note: r.tag})
		}
		return out
	case viewTags:
		return m.tagRows()
	}
	if len(m.entries) == 0 {
		return []row{{kind: rowNote, label: "No entries yet: a adds one."}}
	}
	return m.tree.rows(0, m.expanded, nil)
}

// selectedTags returns the selected tags, sorted.
func (m *app) selectedTags() []string {
	var out []string
	for t, on := range m.tagSel {
		if on {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

func (m *app) tagRows() []row {
	if len(m.tags) == 0 {
		return []row{{kind: rowNote, label: "No tags yet: t edits an entry's tags."}}
	}
	out := make([]row, 0, len(m.tags)+8)
	for _, tc := range m.tags {
		out = append(out, row{kind: rowTag, label: tc.Tag, count: tc.Count, key: "t:" + tc.Tag, open: m.tagSel[tc.Tag]})
	}
	sel := m.selectedTags()
	if len(sel) == 0 {
		return append(out, row{kind: rowNote, label: "Space selects tags; the entries that have all of them show here."})
	}
	matches := m.taggedEntries(sel)
	out = append(out, row{kind: rowNote, label: entriesNote(len(matches), sel)})
	for _, e := range matches {
		out = append(out, row{kind: rowEntry, label: e.Path.String(), key: "e:" + e.ID})
	}
	return out
}

// taggedEntries returns the entries that have every tag in sel (AND).
func (m *app) taggedEntries(sel []string) []model.Entry {
	var out []model.Entry
	for _, e := range m.entries {
		ok := true
		for _, t := range sel {
			if !slices.Contains(e.Tags, t) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, e)
		}
	}
	return out
}

func entriesNote(n int, sel []string) string {
	what := "entries"
	if n == 1 {
		what = "entry"
	}
	return "── " + strconv.Itoa(n) + " " + what + " with " + strings.Join(sel, " + ") + " ──"
}

// rowsAndCursor returns the rows and the cursor's index (-1 when nothing
// is selectable), keeping the cursor on the same item across changes.
func (m *app) rowsAndCursor() ([]row, int) {
	rows := m.rows()
	c := &m.cur[m.list()]
	idx := -1
	if c.key != "" {
		for i, r := range rows {
			if r.key == c.key {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		idx = nearestSelectable(rows, min(max(c.idx, 0), len(rows)-1))
	}
	if idx >= 0 {
		c.key, c.idx = rows[idx].key, idx
	}
	return rows, idx
}

func nearestSelectable(rows []row, i int) int {
	if i < 0 {
		return -1
	}
	for j := i; j < len(rows); j++ {
		if rows[j].selectable() {
			return j
		}
	}
	for j := i - 1; j >= 0; j-- {
		if rows[j].selectable() {
			return j
		}
	}
	return -1
}

// move moves the cursor by delta selectable rows (stopping at the ends).
func (m *app) move(delta int) {
	rows, idx := m.rowsAndCursor()
	if idx < 0 {
		return
	}
	before := rows[idx].key
	step := 1
	if delta < 0 {
		step, delta = -1, -delta
	}
	for ; delta > 0; delta-- {
		j := idx + step
		for j >= 0 && j < len(rows) && !rows[j].selectable() {
			j += step
		}
		if j < 0 || j >= len(rows) {
			break
		}
		idx = j
	}
	m.setCursor(rows, idx)
	if rows[idx].key != before {
		m.reveal.id = "" // a reveal belongs to one entry (S5)
	}
}

func (m *app) moveTo(end bool) {
	rows, idx := m.rowsAndCursor()
	if idx < 0 {
		return
	}
	if end {
		m.setCursor(rows, nearestSelectable(rows, len(rows)-1))
	} else {
		m.setCursor(rows, nearestSelectable(rows, 0))
	}
	m.reveal.id = ""
}

func (m *app) setCursor(rows []row, idx int) {
	if idx < 0 || idx >= len(rows) {
		return
	}
	c := &m.cur[m.list()]
	c.key, c.idx = rows[idx].key, idx
}

// selectedRow returns the row under the cursor.
func (m *app) selectedRow() (row, bool) {
	rows, idx := m.rowsAndCursor()
	if idx < 0 {
		return row{}, false
	}
	return rows[idx], true
}

// selectedEntry is the entry the entry keys act on: the open detail's, or
// the one under the cursor.
func (m *app) selectedEntry() (model.Entry, bool) {
	if m.detail {
		return m.entryByID(m.detailID)
	}
	r, ok := m.selectedRow()
	if !ok || r.kind != rowEntry {
		return model.Entry{}, false
	}
	return m.entryByID(strings.TrimPrefix(r.key, "e:"))
}

// selectEntry puts the cursor on the entry, opening its folders.
func (m *app) selectEntry(id string) {
	e, ok := m.entryByID(id)
	if !ok {
		return
	}
	if m.list() == viewFolders {
		segs := e.Path.Segments()
		for i := 1; i < len(segs); i++ {
			m.expanded[strings.Join(segs[:i], "/")] = true
		}
	}
	c := &m.cur[m.list()]
	c.key = "e:" + id
	if m.detail {
		m.detailID = id
	}
}

// folderOfCursor returns the folder for a new entry: the folder under the
// cursor, or the folder of the entry under it.
func (m *app) folderOfCursor() string {
	r, ok := m.selectedRow()
	if !ok {
		return ""
	}
	switch r.kind {
	case rowFolder:
		return strings.TrimPrefix(r.key, "f:")
	case rowEntry:
		if e, ok := m.entryByID(strings.TrimPrefix(r.key, "e:")); ok {
			return e.Path.Folder()
		}
	}
	return ""
}

// activate is Enter (and → on folders): open a folder, select a tag, open
// an entry's detail.
func (m *app) activate(toggle bool) {
	r, ok := m.selectedRow()
	if !ok {
		return
	}
	switch r.kind {
	case rowFolder:
		p := strings.TrimPrefix(r.key, "f:")
		switch {
		case toggle:
			m.expanded[p] = !m.expanded[p]
		case m.expanded[p]:
			m.move(1) // → on an open folder steps into it
		default:
			m.expanded[p] = true
		}
	case rowTag:
		t := strings.TrimPrefix(r.key, "t:")
		m.tagSel[t] = !m.tagSel[t]
		if !m.tagSel[t] {
			delete(m.tagSel, t)
		}
	case rowEntry:
		m.openDetail(strings.TrimPrefix(r.key, "e:"))
	}
}

func (m *app) openDetail(id string) {
	if m.detailID != id {
		m.reveal.id = ""
	}
	m.detail, m.detailID, m.detailOff = true, id, 0
}

// back is ← on the list: close the folder, or go to the parent folder.
func (m *app) back() {
	r, ok := m.selectedRow()
	if !ok || m.list() != viewFolders {
		return
	}
	if r.kind == rowFolder && r.open {
		delete(m.expanded, strings.TrimPrefix(r.key, "f:"))
		return
	}
	var parent string
	switch r.kind {
	case rowFolder:
		p := strings.TrimPrefix(r.key, "f:")
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			parent = p[:i]
		}
	case rowEntry:
		if e, ok := m.entryByID(strings.TrimPrefix(r.key, "e:")); ok {
			parent = e.Path.Folder()
		}
	}
	if parent != "" {
		m.cur[viewFolders].key = "f:" + parent
	}
}

// pathTaken reports whether an entry has path p.
func (m *app) pathTaken(p paths.Path) bool {
	for _, e := range m.entries {
		if e.Path == p {
			return true
		}
	}
	return false
}
