// Package importpass reads a pass store (password-store.org) for
// `passh import pass` (spec §4.9).
//
// The store is only read. It is walked through os.Root, so no symlink can
// lead outside it: a symlink that would is skipped and reported, never
// followed. Dot-files and dot-folders (.git, .gpg-id, …) are ignored, and
// so is every file whose name doesn't end in ".gpg". An entry's path is
// the file's path in the store without ".gpg", checked by paths.Parse.
//
// Each file is decrypted by `gpg --decrypt` (through internal/exec), with
// the ciphertext on stdin, the plaintext read from stdout into memory, and
// success judged from --status-fd only (S8). The plaintext is parsed by
// entrytext.ParseImport. A dry run decrypts nothing and doesn't start gpg.
//
// Run returns a Result the CLI turns into one save and a summary. Names in
// it (Item.File, Skip.File, Skip.Detail) come from the store and may hold
// any bytes, control characters included: escape them for the terminal
// (S4).
package importpass

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"passh/internal/config"
	"passh/internal/entrytext"
	"passh/internal/model"
	"passh/internal/paths"
)

// EnvStoreDir names the pass store, as for pass.
const EnvStoreDir = "PASSWORD_STORE_DIR"

// StoreDir returns the pass store folder as an absolute path: dir if it is
// not empty (a leading ~/ is expanded), else $PASSWORD_STORE_DIR, else
// ~/.password-store.
func StoreDir(dir string) (string, error) {
	if dir == "" {
		dir = os.Getenv(EnvStoreDir)
	}
	if dir == "" {
		home, err := config.HomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".password-store"), nil
	}
	return config.ExpandPath(dir)
}

// Options describe one import.
type Options struct {
	// Dir is the store folder; see StoreDir for the default.
	Dir string
	// Overwrite imports entries whose path is already in the vault
	// (--overwrite). Without it they are skipped as Conflict.
	Overwrite bool
	// DryRun lists what would be imported and the conflicts without
	// decrypting anything; gpg isn't started.
	DryRun bool
	// Exists reports whether the vault already has an entry at a path.
	// nil means the vault is empty.
	Exists func(paths.Path) bool
	// Progress, if set, is called before each file is decrypted, with its
	// number (from 1), the number of files to decrypt and its store path.
	Progress func(n, total int, file string)
	// GPG configures gpg.
	GPG GPG
}

// Reason tells why a file was skipped.
type Reason int

// Reasons for skipping a file.
const (
	InvalidPath    Reason = iota + 1 // the path fails the validator (§4.4)
	Conflict                         // the path is in the vault and Overwrite is off
	DuplicatePath                    // another file gives the same path (after NFC normalization)
	SymlinkOutside                   // a symlink that leads outside the store (or is absolute): not followed
	BrokenSymlink                    // a symlink to nothing
	SymlinkFolder                    // a symlink to a folder in the store: not followed
	NotRegular                       // not a regular file (a FIFO, device, …)
	Unreadable                       // the file or folder can't be read
	TooLarge                         // the file or its plaintext is too large for a pass entry
	DecryptFailed                    // gpg didn't decrypt it
	NotAnEntry                       // the plaintext isn't a text entry (e.g. binary data)
)

var reasonNames = map[Reason]string{
	InvalidPath:    "invalid path",
	Conflict:       "already in the vault",
	DuplicatePath:  "duplicate path",
	SymlinkOutside: "symlink leads outside the store",
	BrokenSymlink:  "broken symlink",
	SymlinkFolder:  "symlink to a folder",
	NotRegular:     "not a regular file",
	Unreadable:     "unreadable",
	TooLarge:       "too large",
	DecryptFailed:  "decryption failed",
	NotAnEntry:     "not a text entry",
}

func (r Reason) String() string {
	if s, ok := reasonNames[r]; ok {
		return s
	}
	return fmt.Sprintf("Reason(%d)", int(r))
}

// Item is a file that is imported (or, in a dry run, would be).
type Item struct {
	File    string     // path in the store, slash-separated, e.g. "work/github.gpg"
	Path    paths.Path // the entry path, e.g. "work/github"
	Replace bool       // the vault has this path and Overwrite is on
	// Entry is the decrypted content with Path set; ID and times are
	// unset (model.Data.Add sets them). Zero in a dry run.
	Entry model.Entry
}

// Skip is a file (or folder) that is not imported.
type Skip struct {
	File   string // path in the store, slash-separated
	Reason Reason
	Detail string // more about the reason, e.g. the rule a path breaks
}

// Result is the outcome of Run.
type Result struct {
	Dir     string // the store folder
	DryRun  bool
	Items   []Item // sorted by path
	Skipped []Skip // sorted by file
}

// Entries returns the entries to add, in path order: for each item,
// model.Data.Add(entry, now, opts.Overwrite), then one save. Nil in a dry
// run.
func (r *Result) Entries() []model.Entry {
	if r.DryRun {
		return nil
	}
	out := make([]model.Entry, 0, len(r.Items))
	for _, it := range r.Items {
		out = append(out, it.Entry)
	}
	return out
}

// SkippedBy counts the skipped files per reason.
func (r *Result) SkippedBy() map[Reason]int {
	m := map[Reason]int{}
	for _, s := range r.Skipped {
		m[s.Reason]++
	}
	return m
}

// Run reads the store. It fails without a result if the store can't be
// opened, if gpg is needed but missing, if the user cancels the passphrase
// prompt (ErrCanceled), or if ctx is canceled; everything else that goes
// wrong with one file skips that file.
func Run(ctx context.Context, opts Options) (*Result, error) {
	dir, err := StoreDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("pass store: %w", err)
	}
	defer root.Close()

	res := &Result{Dir: dir, DryRun: opts.DryRun}
	files, err := walk(root, res)
	if err != nil {
		return nil, fmt.Errorf("pass store %s: %w", dir, err)
	}
	plan(res, files, opts)

	if !opts.DryRun && len(res.Items) > 0 {
		if err := decryptAll(ctx, root, res, opts); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(res.Items, func(a, b Item) int { return paths.Compare(a.Path, b.Path) })
	slices.SortStableFunc(res.Skipped, func(a, b Skip) int { return strings.Compare(a.File, b.File) })
	return res, nil
}

// walk lists the store's *.gpg files (and symlinks to files in the store),
// in lexical order, and records what it skips in res.
func walk(root *os.Root, res *Result) ([]string, error) {
	var files []string
	skip := func(file string, r Reason, detail string) {
		res.Skipped = append(res.Skipped, Skip{File: file, Reason: r, Detail: detail})
	}
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == "." {
				return err
			}
			skip(p, Unreadable, errDetail(err))
			return nil
		}
		if p == "." {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") { // .git, .gpg-id, .extensions, …
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		isGPG := strings.HasSuffix(d.Name(), ".gpg")
		switch t := d.Type(); {
		case d.IsDir():
		case t&fs.ModeSymlink != 0:
			r, detail, ok := checkSymlink(root, p)
			switch {
			case ok && isGPG:
				files = append(files, p)
			case ok:
			case r == SymlinkOutside || r == SymlinkFolder || isGPG:
				skip(p, r, detail)
			}
		case t.IsRegular():
			if isGPG {
				files = append(files, p)
			}
		default:
			if isGPG {
				skip(p, NotRegular, "")
			}
		}
		return nil
	})
	return files, err
}

// checkSymlink resolves a symlink through the root, which refuses to leave
// the store. ok means it leads to a regular file in the store.
func checkSymlink(root *os.Root, p string) (r Reason, detail string, ok bool) {
	fi, err := root.Stat(p)
	switch {
	case err == nil && fi.Mode().IsRegular():
		return 0, "", true
	case err == nil && fi.IsDir():
		return SymlinkFolder, "not followed", false
	case err == nil:
		return NotRegular, "", false
	case errors.Is(err, fs.ErrNotExist):
		return BrokenSymlink, "", false
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.ELOOP):
		return Unreadable, errDetail(err), false
	}
	return SymlinkOutside, "not followed", false
}

// errDetail is an error's message without the "op path:" prefix of a
// *fs.PathError, whose path is already in Skip.File.
func errDetail(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// plan turns files into items, skipping invalid paths, duplicates and
// conflicts.
func plan(res *Result, files []string, opts Options) {
	seen := map[paths.Path]string{}
	for _, f := range files {
		p, err := paths.Parse(strings.TrimSuffix(f, ".gpg"))
		if err != nil {
			var pe *paths.Error
			detail := err.Error()
			if errors.As(err, &pe) {
				detail = pe.Rule.Error()
			}
			res.Skipped = append(res.Skipped, Skip{File: f, Reason: InvalidPath, Detail: detail})
			continue
		}
		if prev, dup := seen[p]; dup {
			res.Skipped = append(res.Skipped, Skip{File: f, Reason: DuplicatePath, Detail: "same path as " + prev})
			continue
		}
		seen[p] = f
		exists := opts.Exists != nil && opts.Exists(p)
		if exists && !opts.Overwrite {
			res.Skipped = append(res.Skipped, Skip{File: f, Reason: Conflict, Detail: "use --overwrite to replace it"})
			continue
		}
		res.Items = append(res.Items, Item{File: f, Path: p, Replace: exists})
	}
}

// decryptAll decrypts and parses every item, moving failures to
// res.Skipped.
func decryptAll(ctx context.Context, root *os.Root, res *Result, opts Options) error {
	gpg, err := newGPGRunner(opts.GPG)
	if err != nil {
		return err
	}
	items := res.Items
	res.Items = make([]Item, 0, len(items))
	for i, it := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		if opts.Progress != nil {
			opts.Progress(i+1, len(items), it.File)
		}
		skip := func(r Reason, detail string) {
			res.Skipped = append(res.Skipped, Skip{File: it.File, Reason: r, Detail: detail})
		}
		ct, r, detail := readFile(root, it.File)
		if r != 0 {
			skip(r, detail)
			continue
		}
		pt, failure, err := gpg.decrypt(ctx, ct)
		if err != nil {
			return err
		}
		if failure != "" {
			skip(DecryptFailed, failure)
			continue
		}
		e, err := entrytext.ParseImport(string(pt))
		clear(pt)
		if err != nil {
			skip(NotAnEntry, err.Error())
			continue
		}
		e.Path = it.Path
		it.Entry = e
		res.Items = append(res.Items, it)
	}
	return nil
}

// readFile reads a .gpg file through the root. O_NONBLOCK keeps a FIFO
// swapped in after the walk from blocking the open; the type is checked on
// the open file.
func readFile(root *os.Root, name string) ([]byte, Reason, string) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		// Also a file replaced by a symlink leading outside since the walk:
		// the root refuses it ("path escapes from parent").
		return nil, Unreadable, errDetail(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, Unreadable, errDetail(err)
	}
	if !fi.Mode().IsRegular() {
		return nil, NotRegular, ""
	}
	if fi.Size() > maxCiphertext {
		return nil, TooLarge, fmt.Sprintf("larger than %d MiB", maxCiphertext>>20)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCiphertext+1))
	if err != nil {
		return nil, Unreadable, errDetail(err)
	}
	if len(b) > maxCiphertext {
		return nil, TooLarge, fmt.Sprintf("larger than %d MiB", maxCiphertext>>20)
	}
	return b, 0, ""
}
