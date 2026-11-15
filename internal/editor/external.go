package editor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	xterm "golang.org/x/term"

	"passh/internal/entrytext"
	"passh/internal/exec"
	"passh/internal/model"
	"passh/internal/sanitize"
	"passh/internal/tty"
)

// External editor (`passh edit --editor`, §5.6, S1, S8).
//
// The entry's text form (§4.3) goes into a file in a new folder on tmpfs:
// $XDG_RUNTIME_DIR if it is on tmpfs and belongs to the user, else
// /dev/shm if it is on tmpfs; nowhere else, so plaintext never reaches a
// persistent disk. The folder has mode 0700, the file 0600. Afterwards,
// also on errors and interrupts, every file in the folder is overwritten
// with zeros and the folder is removed (best effort: a kill -9 leaves it,
// and Leftovers finds it).

var (
	// ErrNoTmpfs means there is no tmpfs for the temporary file (e.g. on
	// macOS); the CLI falls back to the built-in form.
	ErrNoTmpfs = errors.New("no tmpfs for the temporary file")
	// ErrNoChange means the user saved the entry unchanged.
	ErrNoChange = errors.New("no change")
	// ErrInterrupted means a signal or a cancelled context ended the
	// editor; nothing was changed.
	ErrInterrupted = errors.New("editing interrupted")
)

// shmDir is the fallback tmpfs folder; tests point it elsewhere.
var shmDir = "/dev/shm"

const (
	tempPrefix  = "passh-edit-"
	tempName    = "entry.txt"
	maxFileSize = 16 << 20
)

// TempBase returns the folder that will hold the temporary folder:
// $XDG_RUNTIME_DIR if it is an absolute path to a folder of the user's on
// tmpfs, else /dev/shm if it is on tmpfs. Otherwise it returns an error
// wrapping ErrNoTmpfs. The CLI can call it first to fall back to the form
// before it says anything about the editor.
func TempBase() (string, error) {
	var tried []string
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		if filepath.IsAbs(d) && isDir(d, true) && onTmpfs(d) {
			return d, nil
		}
		tried = append(tried, "$XDG_RUNTIME_DIR ("+d+")")
	}
	if isDir(shmDir, false) && onTmpfs(shmDir) {
		return shmDir, nil
	}
	tried = append(tried, shmDir)
	return "", fmt.Errorf("%w (checked %s): the entry would be written to disk in plain text; use the built-in form (passh edit without --editor)",
		ErrNoTmpfs, strings.Join(tried, " and "))
}

// isDir reports whether p is a directory (not a symlink to one), owned by
// the current user if mine.
func isDir(p string, mine bool) bool {
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() {
		return false
	}
	if !mine {
		return true
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// Leftovers lists temporary folders an `edit --editor` left behind, e.g.
// when passh was killed while the editor ran; for `passh doctor`. Only the
// current user's folders are listed.
func Leftovers() []string {
	var bases []string
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && filepath.IsAbs(d) {
		bases = append(bases, d)
	}
	bases = append(bases, shmDir)
	var out []string
	for _, b := range bases {
		matches, _ := filepath.Glob(filepath.Join(b, tempPrefix+"*"))
		for _, m := range matches {
			if isDir(m, true) {
				out = append(out, m)
			}
		}
	}
	return out
}

// Kind is an editor passh knows how to make leak-safe.
type Kind int

const (
	// KindOther is any editor passh has no flags for.
	KindOther Kind = iota
	// KindVim is vim (also vim.basic, vim.tiny and the like).
	KindVim
	// KindNeovim is nvim.
	KindNeovim
	// KindNano is GNU nano.
	KindNano
)

func (k Kind) String() string {
	switch k {
	case KindVim:
		return "vim"
	case KindNeovim:
		return "neovim"
	case KindNano:
		return "nano"
	}
	return "other"
}

// vimSet turns off every file vim and neovim would write besides the file.
const vimSet = "set nobackup nowritebackup noundofile noswapfile"

// leakSafeFlags are the flags of §5.6 for each known editor.
var leakSafeFlags = map[Kind][]string{
	KindVim:    {"-n", "-u", "NONE", "-i", "NONE", "-c", vimSet},
	KindNeovim: {"-n", "--clean", "-i", "NONE", "-c", vimSet},
	KindNano:   {"--ignorercfiles", "--nohelp"},
}

// Editor is the external editor to run.
type Editor struct {
	// Name is the program as given, e.g. "vim".
	Name string
	// Path is where it was found in $PATH.
	Path string
	// Args are the words that followed the program in $EDITOR, then the
	// leak-safe flags for Kind. Edit adds "--" (for known editors) and the
	// file.
	Args []string
	Kind Kind
	// Warning is set for an editor passh has no flags for; the caller shows
	// it before starting the editor.
	Warning string
}

// fallbackEditor is used when neither $EDITOR nor $VISUAL is set.
const fallbackEditor = "vi"

// FindEditor returns the editor from $EDITOR (§5.6), else $VISUAL, else
// vi. The value is split into words without a shell (exec.SplitWords).
func FindEditor() (*Editor, error) {
	for _, v := range []string{"EDITOR", "VISUAL"} {
		if s := os.Getenv(v); strings.TrimSpace(s) != "" {
			ed, err := NewEditor(s)
			if err != nil {
				return nil, fmt.Errorf("$%s: %w", v, err)
			}
			return ed, nil
		}
	}
	return NewEditor(fallbackEditor)
}

// NewEditor returns the editor for a command line such as "vim" or
// "emacsclient -t". The kind comes from the program's name, or from the
// name of the file it is a symlink to (/usr/bin/vi → vim.basic is vim;
// busybox's vi is not).
func NewEditor(cmdline string) (*Editor, error) {
	words, err := exec.SplitWords(cmdline)
	if err != nil {
		return nil, err
	}
	if len(words) == 0 || words[0] == "" {
		return nil, errors.New("the editor command is empty")
	}
	path, err := exec.LookPath(words[0])
	if err != nil {
		return nil, err
	}
	kind := detectKind(words[0], path)
	ed := &Editor{
		Name: words[0],
		Path: path,
		Args: append(words[1:len(words):len(words)], leakSafeFlags[kind]...),
		Kind: kind,
	}
	if kind == KindOther {
		ed.Warning = fmt.Sprintf("passh can't control backup, swap or history files of %s: they may keep a copy of the entry on disk. "+
			"Graphical editors must also wait until the file is closed (e.g. code --wait).", sanitize.Line(filepath.Base(words[0])))
	}
	return ed, nil
}

func detectKind(word, path string) Kind {
	var names []string
	if real, err := filepath.EvalSymlinks(path); err == nil {
		names = append(names, filepath.Base(real))
	}
	names = append(names, filepath.Base(path), filepath.Base(word))
	for _, n := range names {
		if k := kindOf(n); k != KindOther {
			return k
		}
	}
	return KindOther
}

func kindOf(name string) Kind {
	switch {
	case name == "nvim" || strings.HasPrefix(name, "nvim."):
		return KindNeovim
	case name == "vim" || strings.HasPrefix(name, "vim."):
		return KindVim
	case name == "nano":
		return KindNano
	}
	return KindOther
}

// Argv returns the arguments after the program for editing file: Args,
// then "--" for the editors known to take it, then file (an absolute path,
// so it can't be taken for an option either way).
func (ed *Editor) Argv(file string) []string {
	args := append([]string(nil), ed.Args...)
	if ed.Kind != KindOther {
		args = append(args, "--")
	}
	return append(args, file)
}

// ParseError is an edited text that isn't a valid entry. Its message
// starts with "line N: " when the line is known (Line > 0).
type ParseError struct {
	Line int
	Err  error
}

func (e *ParseError) Error() string { return e.Err.Error() }
func (e *ParseError) Unwrap() error { return e.Err }

var lineRE = regexp.MustCompile(`^line (\d+): `)

// parseText parses the edited text form.
func parseText(text string) (model.Entry, error) {
	if !utf8.ValidString(text) {
		i := 0
		for i < len(text) {
			r, size := utf8.DecodeRuneInString(text[i:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			i += size
		}
		n := 1 + strings.Count(text[:i], "\n")
		return model.Entry{}, &ParseError{Line: n, Err: fmt.Errorf("line %d: the text is not valid UTF-8", n)}
	}
	e, err := entrytext.Parse(text)
	if err != nil {
		pe := &ParseError{Err: err}
		if m := lineRE.FindStringSubmatch(err.Error()); m != nil {
			pe.Line, _ = strconv.Atoi(m[1])
		}
		return model.Entry{}, pe
	}
	return e, nil
}

// Edit opens e's text form in the editor on the terminal term (the
// *os.File of /dev/tty, used as the editor's stdin, stdout and stderr) and
// returns e with the edited content: password, username, url, tags, custom
// fields and notes. The id, path, times and unknown keys stay; a custom
// field that is still there unchanged keeps its unknown keys too.
//
// Errors: ErrNoChange when the content is the same; a *ParseError when the
// text isn't a valid entry, unless retry (if not nil) is called with it and
// returns true, then the editor opens again on the text as the user left
// it; ErrNoTmpfs; ErrInterrupted; or the editor's failure (a non-zero exit
// status, as from vim's :cq, counts as one). The temporary file is gone
// whenever Edit returns, also while retry asks.
func (ed *Editor) Edit(ctx context.Context, term *os.File, e model.Entry, retry func(*ParseError) bool) (model.Entry, error) {
	orig := entrytext.Format(e)
	text := orig
	for {
		out, err := ed.EditText(ctx, term, text)
		if err != nil {
			return model.Entry{}, err
		}
		if out == orig {
			return model.Entry{}, ErrNoChange
		}
		parsed, err := parseText(out)
		if err != nil {
			var pe *ParseError
			if errors.As(err, &pe) && retry != nil && retry(pe) {
				text = out
				continue
			}
			return model.Entry{}, err
		}
		r := withContent(e, parsed)
		if r.Equal(e) {
			return model.Entry{}, ErrNoChange
		}
		return r, nil
	}
}

// withContent returns e with the content of p. Custom fields equal to one
// of e's (same key and value) are taken from e, unknown keys included.
func withContent(e, p model.Entry) model.Entry {
	r := e.Clone()
	r.Password, r.Username, r.URL, r.Notes = p.Password, p.Username, p.URL, p.Notes
	r.Tags = p.Tags
	old := r.Fields // deep copies of e's fields
	used := make([]bool, len(old))
	r.Fields = nil
	for _, f := range p.Fields {
		for i, o := range old {
			if !used[i] && o.Key == f.Key && o.Value == f.Value {
				used[i] = true
				f = o
				break
			}
		}
		r.Fields = append(r.Fields, f)
	}
	return r
}

// editSignals end the editor: passh kills it, removes the file and
// returns ErrInterrupted instead of dying with the file in place.
var editSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// EditText runs the editor on text in a temporary file on tmpfs and
// returns the file's content afterwards. The temporary folder is wiped
// and removed before it returns, whatever happens.
func (ed *Editor) EditText(ctx context.Context, term *os.File, text string) (out string, err error) {
	if !tty.IsTerminal(term) {
		return "", fmt.Errorf("the editor needs a terminal: %w", tty.ErrNoTerminal)
	}
	base, err := TempBase()
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(base, tempPrefix+"*")
	if err != nil {
		return "", fmt.Errorf("creating the temporary folder: %w", err)
	}
	defer func() {
		if werr := wipeDir(dir); werr != nil && err == nil {
			out, err = "", werr
		}
	}()
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating the temporary folder: %w", err)
	}
	if !onTmpfs(dir) {
		return "", fmt.Errorf("%w: %s is not on tmpfs", ErrNoTmpfs, dir)
	}
	file := filepath.Join(dir, tempName)
	if err := writeNew(file, text); err != nil {
		return "", err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, editSignals...)
	defer signal.Stop(sigs)
	caught := make(chan os.Signal, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case s := <-sigs:
			caught <- s
			cancel()
		case <-stop:
		}
	}()

	fd := int(term.Fd())
	state, serr := xterm.GetState(fd) // the editor may be killed in raw mode
	runErr := exec.Run(runCtx, exec.Command{
		Name:   ed.Path,
		Args:   ed.Argv(file),
		Stdin:  term,
		Stdout: term,
		Stderr: term,
	})
	if serr == nil {
		_ = xterm.Restore(fd, state)
	}

	select {
	case s := <-caught:
		return "", fmt.Errorf("%w by %v; nothing was changed", ErrInterrupted, s)
	default:
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("%w: %w; nothing was changed", ErrInterrupted, context.Cause(ctx))
	}
	if runErr != nil {
		return "", fmt.Errorf("the editor failed (%w); nothing was changed", runErr)
	}
	b, err := readSmall(file)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// writeNew creates file with mode 0600 (whatever the umask) and writes
// text.
func writeNew(file, text string) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("creating the temporary file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("creating the temporary file: %w", err)
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return fmt.Errorf("writing the temporary file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing the temporary file: %w", err)
	}
	return nil
}

// readSmall reads the edited file, refusing one over maxFileSize.
func readSmall(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("reading the edited file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the edited file: %w", err)
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("the edited file is larger than %d MiB", maxFileSize>>20)
	}
	return b, nil
}

// wipeDir overwrites every regular file under dir with zeros (the edited
// file, and any backup or swap file an editor left), then removes dir.
// Overwriting is best effort; a failure to remove is reported.
func wipeDir(dir string) error {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			zeroFile(p)
		}
		return nil
	})
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing the temporary folder %s: %w; remove it yourself, it holds the entry in plain text", dir, err)
	}
	return nil
}

func zeroFile(p string) {
	f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	zeros := make([]byte, 32<<10)
	for left := fi.Size(); left > 0; {
		n := int64(len(zeros))
		if left < n {
			n = left
		}
		w, err := f.Write(zeros[:n])
		if err != nil {
			return
		}
		left -= int64(w)
	}
	_ = f.Sync()
}
