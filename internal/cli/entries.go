package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sahilm/fuzzy"
	"github.com/spf13/cobra"

	"github.com/devapro/passh/internal/entrytext"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/sanitize"
	"github.com/devapro/passh/internal/vault"
)

func (a *app) cmdLs() *cobra.Command {
	var tags []string
	c := &cobra.Command{
		Use:   "ls [folder]",
		Short: a.T("Print the tree of entries, optionally filtered by tag"),
		Args:  rangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var folder paths.Path
			if len(args) == 1 {
				p, err := paths.ParseFolder(args[0])
				if err != nil {
					return err
				}
				folder = p
			}
			for i, t := range tags {
				n, err := model.NormalizeTag(t)
				if err != nil {
					return err
				}
				tags[i] = n
			}
			v, err := a.unlock(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			d := v.Snapshot()
			list := d.Filter(folder, tags)
			if !folder.IsZero() && len(list) == 0 {
				if e, ok := d.Get(folder); ok && hasAllTags(e, tags) {
					// `ls work/github` names an entry: print just it.
					return writeAll(a.stdout, line(e.Path.String())+"\n")
				}
				if len(d.ListFolder(folder)) == 0 {
					return i18n.Errorf("%s: no such folder", folder)
				}
			}
			header := displayPath(v.Info().Path)
			if !folder.IsZero() {
				header = line(folder.String()) + "/"
			}
			if len(tags) > 0 {
				header += "  (tag " + line(strings.Join(tags, ", ")) + ")"
			}
			var rel []string
			for _, e := range list {
				p := e.Path.String()
				if !folder.IsZero() {
					p = strings.TrimPrefix(p, folder.String()+"/")
				}
				rel = append(rel, p)
			}
			out := header + "\n" + renderTree(rel)
			if len(list) == 0 {
				out += "(no entries)\n"
			}
			return writeAll(a.stdout, out)
		},
	}
	c.Flags().StringSliceVar(&tags, "tag", nil, a.T("only entries with this tag (repeat for several: all must match)"))
	return c
}

func hasAllTags(e model.Entry, tags []string) bool {
	for _, t := range tags {
		if !slices.Contains(e.Tags, t) {
			return false
		}
	}
	return true
}

// treeDir is one folder of the tree.
type treeDir struct {
	folders map[string]*treeDir
	entries []string
}

// renderTree draws slash-separated paths as a tree, folders with a
// trailing "/". A name can be both an entry and a folder ("work" and
// "work/x"); it then appears twice. Every name is escaped (S4).
func renderTree(list []string) string {
	root := &treeDir{folders: map[string]*treeDir{}}
	for _, p := range list {
		segs := strings.Split(p, "/")
		d := root
		for _, s := range segs[:len(segs)-1] {
			sub, ok := d.folders[s]
			if !ok {
				sub = &treeDir{folders: map[string]*treeDir{}}
				d.folders[s] = sub
			}
			d = sub
		}
		d.entries = append(d.entries, segs[len(segs)-1])
	}
	var b strings.Builder
	root.render(&b, "")
	return b.String()
}

type treeItem struct {
	name   string
	folder *treeDir
}

func (d *treeDir) render(b *strings.Builder, indent string) {
	items := make([]treeItem, 0, len(d.folders)+len(d.entries))
	for name, sub := range d.folders {
		items = append(items, treeItem{name: name, folder: sub})
	}
	for _, name := range d.entries {
		items = append(items, treeItem{name: name})
	}
	slices.SortFunc(items, func(x, y treeItem) int {
		if c := strings.Compare(x.name, y.name); c != 0 {
			return c
		}
		switch {
		case x.folder != nil && y.folder == nil:
			return -1
		case x.folder == nil && y.folder != nil:
			return 1
		}
		return 0
	})
	for i, it := range items {
		branch, next := "├── ", "│   "
		if i == len(items)-1 {
			branch, next = "└── ", "    "
		}
		b.WriteString(indent + branch + sanitize.Line(it.name))
		if it.folder != nil {
			b.WriteString("/\n")
			it.folder.render(b, indent+next)
			continue
		}
		b.WriteString("\n")
	}
}

func (a *app) cmdFind() *cobra.Command {
	return &cobra.Command{
		Use:   "find <query>",
		Short: a.T("Fuzzy search on paths and tags"),
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.unlock(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			hits := findEntries(v.Entries(), args[0])
			if len(hits) == 0 {
				return i18n.Errorf("no entry matches %q", args[0])
			}
			var b strings.Builder
			for _, h := range hits {
				b.WriteString(line(h.path))
				if h.tag != "" {
					b.WriteString("  (tag " + line(h.tag) + ")")
				}
				b.WriteString("\n")
			}
			return writeAll(a.stdout, b.String())
		},
	}
}

// findHit is one result of findEntries: an entry's path and, if it matched
// through a tag rather than its path, that tag.
type findHit struct {
	path  string
	tag   string
	score int
}

// findEntries matches query fuzzily (sahilm/fuzzy, case-insensitive)
// against every entry's path and tags, best match first.
func findEntries(entries []model.Entry, query string) []findHit {
	best := map[int]findHit{}
	consider := func(i int, h findHit) {
		if cur, ok := best[i]; !ok || h.score > cur.score {
			best[i] = h
		}
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Path.String()
	}
	for _, m := range fuzzy.Find(query, names) {
		consider(m.Index, findHit{path: names[m.Index], score: m.Score})
	}
	var tags []string
	for _, e := range entries {
		for _, t := range e.Tags {
			if !slices.Contains(tags, t) {
				tags = append(tags, t)
			}
		}
	}
	for _, m := range fuzzy.Find(query, tags) {
		for i, e := range entries {
			if slices.Contains(e.Tags, m.Str) {
				// A path match of the same quality wins over a tag match.
				consider(i, findHit{path: names[i], tag: m.Str, score: m.Score - 1})
			}
		}
	}
	out := make([]findHit, 0, len(best))
	for _, h := range best {
		out = append(out, h)
	}
	slices.SortFunc(out, func(x, y findHit) int {
		if x.score != y.score {
			return y.score - x.score
		}
		return paths.Compare(paths.MustParse(x.path), paths.MustParse(y.path))
	})
	return out
}

func (a *app) cmdShow() *cobra.Command {
	var (
		field string
		raw   bool
	)
	c := &cobra.Command{
		Use:   "show <path>",
		Short: a.T("Print an entry (text form) or one field"),
		Long: a.T("Print an entry in its text form: the password on line 1, then username, url,\n" +
			"tags and other fields, then the notes after ---.\n\n" +
			"Control characters and escape sequences in the entry are shown escaped, so an\n" +
			"entry can't drive your terminal. --raw prints the exact bytes instead.\n" +
			"--field prints one value (password, username, url, tags, notes or a custom\n" +
			"field). When stdout is not a terminal (a pipe or a file), --field prints the\n" +
			"exact value without a final newline, e.g.\n" +
			"  passh show work/github --field password | pbcopy"),
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := paths.Parse(args[0])
			if err != nil {
				return err
			}
			v, err := a.unlock(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			e, ok := v.Get(p)
			if !ok {
				return notFound(v, p)
			}
			if cmd.Flags().Changed("field") {
				return a.showField(e, field, raw)
			}
			text := entrytext.Format(e)
			if !raw {
				text = sanitize.Text(text)
			}
			return writeAll(a.stdout, text)
		},
	}
	c.Flags().StringVar(&field, "field", "", a.T("print only this field: password, username, url, tags, notes or a custom field"))
	c.Flags().BoolVar(&raw, "raw", false, a.T("print exact bytes, without escaping control characters"))
	return c
}

// showField prints one field (§6.1). Escaping policy (S4):
//
//   - stdout is a terminal: the value is escaped and ends with a newline;
//   - stdout is not a terminal (`| pbcopy`, `> file`, `$(…)`): the exact
//     value without a newline, so a piped password is the password;
//   - --raw: the exact value without a newline, wherever stdout goes.
func (a *app) showField(e model.Entry, name string, raw bool) error {
	val, ok := e.Field(name)
	if !ok {
		return i18n.Errorf("%s has no field %q", e.Path, name)
	}
	if raw || !a.stdoutIsTerminal() {
		return writeAll(a.stdout, val)
	}
	return writeAll(a.stdout, sanitize.Text(val)+"\n")
}

// notFound is the error for a path without an entry; it points to `ls` if
// the path is a folder.
func notFound(v *vault.Vault, p paths.Path) error {
	if d := v.Snapshot(); d != nil && len(d.ListFolder(p)) > 0 {
		return i18n.Errorf("%s is a folder, not an entry: list it with `passh ls %s`", p, p)
	}
	return fmt.Errorf("%s: %w", p, model.ErrNotFound)
}

func (a *app) cmdTags() *cobra.Command {
	return &cobra.Command{
		Use:   "tags",
		Short: a.T("List tags with their entry counts"),
		Args:  noArgs(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := a.unlock(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			counts := v.Snapshot().TagCounts()
			if len(counts) == 0 {
				a.notef("no tags")
				return nil
			}
			width := 0
			names := make([]string, len(counts))
			for i, c := range counts {
				names[i] = line(c.Tag)
				width = max(width, len([]rune(names[i])))
			}
			var b strings.Builder
			for i, c := range counts {
				fmt.Fprintf(&b, "%-*s  %d\n", width, names[i], c.Count)
			}
			return writeAll(a.stdout, b.String())
		},
	}
}
