package print

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/sanitize"
)

// Field names for --fields. The standard names are those of `show --field`;
// any other name selects the custom fields with exactly that key.
const (
	FieldPassword = model.FieldPassword
	FieldUsername = model.FieldUsername
	FieldURL      = model.FieldURL
	FieldTags     = model.FieldTags
	FieldNotes    = model.FieldNotes
	// FieldCustom selects every custom field of an entry, each under its
	// own key.
	FieldCustom = "fields"
)

// defaultFields are printed when no fields are chosen: the --fields value
// of the §7.2 synopsis. Never written; DefaultFieldList hands out copies.
var defaultFields = []string{FieldPassword, FieldUsername, FieldURL}

// DefaultFieldList returns the fields printed when none are chosen, the
// --fields value of the §7.2 synopsis: password, username, url. Each call
// returns a new slice (API-7).
func DefaultFieldList() []string { return slices.Clone(defaultFields) }

// DefaultFields is a copy of DefaultFieldList, kept for existing callers.
// This package never reads it, so changing it changes nothing here; new
// code calls DefaultFieldList.
var DefaultFields = DefaultFieldList()

var standardFields = []string{FieldPassword, FieldUsername, FieldURL, FieldTags, FieldNotes, FieldCustom}

var (
	// ErrNoEntries means no entry matches the folder and tags.
	ErrNoEntries = errors.New("no entries to print")
	// ErrField is wrapped by every problem with a field name.
	ErrField = errors.New("invalid field")
)

// ParseFields reads a --fields value such as "password,username,url".
// Names are separated by commas; blanks around them are ignored. Standard
// names (password, username, url, tags, notes, and fields for every custom
// field) are matched in any case; any other name must be a valid custom
// field key and is matched exactly. Repeated names count once. An empty
// value gives DefaultFieldList. Fields are printed in the order given.
func ParseFields(s string) ([]string, error) {
	var out []string
	for name := range strings.SplitSeq(s, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if std := strings.ToLower(name); slices.Contains(standardFields, std) {
			name = std
		} else if !model.ValidFieldKey(name) {
			return nil, fmt.Errorf("%w %q: use %s, or the key of a custom field",
				ErrField, name, strings.Join(standardFields, ", "))
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return DefaultFieldList(), nil
	}
	return out, nil
}

// Options chooses what a password sheet holds.
type Options struct {
	// Folder limits the sheet to the entries inside this folder, at any
	// depth (--folder). The zero Path means every entry.
	Folder paths.Path
	// Tags limits the sheet to the entries that have all these tags
	// (--tag). Tags are compared after trimming and NFC normalization.
	Tags []string
	// Fields are the fields to print, in order (--fields, see ParseFields).
	// Nil means DefaultFieldList. Empty values are left out.
	Fields []string
	// Date is the print date; the zero time means now.
	Date time.Time
}

// Sheet is the password sheet (§7.2): the chosen entries grouped by folder,
// with the chosen fields.
type Sheet struct {
	date   time.Time
	fields []string
	scope  string
	count  int
	groups []group
}

type group struct {
	folder  string // "" for the top level
	entries []model.Entry
}

// NewSheet selects the entries to print and groups them by folder. The
// folder and tag filters are applied here, with the semantics of
// model.Data.Filter, so that the sheet can say what was selected. It fails
// with ErrNoEntries when nothing matches, and with ErrField when a custom
// field name is in none of the selected entries (most likely a typo).
//
// Groups are ordered with the top level first, then folders by path; entries
// by name. A folder's subfolders are groups of their own.
func NewSheet(entries []model.Entry, opts Options) (*Sheet, error) {
	fields := opts.Fields
	if fields == nil {
		fields = defaultFields // read only; NewSheet copies what it keeps
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: no fields to print", ErrField)
	}
	for _, f := range fields {
		if !slices.Contains(standardFields, f) && !model.ValidFieldKey(f) {
			return nil, fmt.Errorf("%w %q", ErrField, f)
		}
	}
	date := opts.Date
	if date.IsZero() {
		date = time.Now()
	}

	scope := describeScope(opts.Folder, opts.Tags)
	selected := (&model.Data{Entries: entries}).Filter(opts.Folder, opts.Tags)
	if len(selected) == 0 {
		if scope == "" {
			return nil, fmt.Errorf("%w: the vault has no entries", ErrNoEntries)
		}
		return nil, fmt.Errorf("%w: none matches %s", ErrNoEntries, sanitize.Line(scope))
	}
	for _, f := range fields {
		if slices.Contains(standardFields, f) {
			continue
		}
		found := slices.ContainsFunc(selected, func(e model.Entry) bool {
			return slices.ContainsFunc(e.Fields, func(cf model.Field) bool { return cf.Key == f })
		})
		if !found {
			return nil, fmt.Errorf("%w %q: no selected entry has a field with this key", ErrField, f)
		}
	}

	byFolder := map[string][]model.Entry{}
	for _, e := range selected {
		f := e.Path.Folder()
		byFolder[f] = append(byFolder[f], e)
	}
	folders := make([]string, 0, len(byFolder))
	for f := range byFolder {
		folders = append(folders, f)
	}
	slices.SortFunc(folders, compareFolders)
	s := &Sheet{
		date:   date,
		fields: slices.Clone(fields),
		scope:  scope,
		count:  len(selected),
	}
	for _, f := range folders {
		es := byFolder[f]
		slices.SortStableFunc(es, func(a, b model.Entry) int { return strings.Compare(a.Path.Name(), b.Path.Name()) })
		s.groups = append(s.groups, group{folder: f, entries: es})
	}
	return s, nil
}

// compareFolders orders folders segment by segment, the top level ("")
// first.
func compareFolders(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return -1
	case b == "":
		return 1
	}
	pa, errA := paths.ParseFolder(a)
	pb, errB := paths.ParseFolder(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	return paths.Compare(pa, pb)
}

// describeScope describes the filters, "" for none.
func describeScope(folder paths.Path, tags []string) string {
	var parts []string
	if !folder.IsZero() {
		parts = append(parts, "folder "+folder.String())
	}
	switch len(tags) {
	case 0:
	case 1:
		parts = append(parts, "tag "+strings.TrimSpace(tags[0]))
	default:
		ts := make([]string, len(tags))
		for i, t := range tags {
			ts[i] = strings.TrimSpace(t)
		}
		parts = append(parts, "tags "+strings.Join(ts, ", "))
	}
	return strings.Join(parts, "; ")
}

// Len returns the number of entries on the sheet.
func (s *Sheet) Len() int { return s.count }

// Fields returns the fields printed, in order.
func (s *Sheet) Fields() []string { return slices.Clone(s.fields) }

// Title implements Document.
func (s *Sheet) Title() string { return "passh password sheet" }

// Date implements Document.
func (s *Sheet) Date() time.Time { return s.date }

// Legend implements Document: what the marks under values mean.
func (s *Sheet) Legend() []string {
	return []string{
		"Under 0 O 1 l I and spaces: D digit, U capital letter, L small letter, S space",
		Continuation + ` continues the line above; \uXXXX is a character that can't be printed`,
	}
}

// Blocks implements Document.
func (s *Sheet) Blocks() []Block { return s.blocks(targetWeb) }

func (s *Sheet) blocks(t target) []Block {
	entries := strconv.Itoa(s.count) + " entries"
	if s.count == 1 {
		entries = "1 entry"
	}
	head := Block{Rows: []Row{{Kind: RowTitle, Text: s.Title()}}}
	meta := "printed " + FormatDate(s.date) + " · " + entries
	if s.scope != "" {
		meta += " · " + s.scope
	}
	head.Rows = append(head.Rows, t.proseRows(RowMeta, sanitize.Line(meta))...)
	head.Rows = append(head.Rows, t.proseRows(RowMeta, sanitize.Line(
		"fields: "+strings.Join(s.fields, ", ")))...)
	blocks := []Block{head}

	for _, g := range s.groups {
		name := g.folder
		if name == "" {
			name = "(top level)"
		}
		fb := Block{KeepWithNext: true, Rows: []Row{{Kind: RowSpace}}}
		fb.Rows = append(fb.Rows, t.hardRows(RowFolder, sanitize.Line(name), 0)...)
		blocks = append(blocks, fb)
		for _, e := range g.entries {
			eb := Block{Rows: []Row{{Kind: RowSpace}}}
			eb.Rows = append(eb.Rows, t.hardRows(RowEntry, sanitize.Line(e.Path.Name()), 0)...)
			eb.Rows = append(eb.Rows, s.entryRows(t, e)...)
			blocks = append(blocks, eb)
		}
	}
	return blocks
}

// entryRows lays out the chosen fields of e. Empty values are left out.
func (s *Sheet) entryRows(t target, e model.Entry) []Row {
	var rows []Row
	line := func(label, v string) {
		if v != "" {
			rows = append(rows, t.valueRows(sanitize.Line(label), []string{sanitize.Line(v)}, true)...)
		}
	}
	for _, f := range s.fields {
		switch f {
		case FieldPassword:
			line(f, e.Password)
		case FieldUsername:
			line(f, e.Username)
		case FieldURL:
			line(f, e.URL)
		case FieldTags:
			if len(e.Tags) > 0 {
				rows = append(rows, t.valueRows(f, []string{sanitize.Line(strings.Join(e.Tags, ", "))}, false)...)
			}
		case FieldNotes:
			if lines := noteLines(e.Notes); len(lines) > 0 {
				rows = append(rows, t.valueRows(f, lines, false)...)
			}
		case FieldCustom:
			for _, cf := range e.Fields {
				line(cf.Key, cf.Value)
			}
		default:
			for _, cf := range e.Fields {
				if cf.Key == f {
					line(cf.Key, cf.Value)
				}
			}
		}
	}
	return rows
}

// noteLines splits notes into sanitized lines, tabs expanded, without
// trailing blank lines.
func noteLines(notes string) []string {
	text := strings.TrimRight(sanitize.Text(notes), "\n \t")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = expandTabs(l)
	}
	return lines
}
