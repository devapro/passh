package tui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"filippo.io/age"
	"github.com/charmbracelet/x/ansi"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/vault"
	"github.com/devapro/passh/internal/vaultfile"
)

// The whole test binary runs with HOME, the XDG folders and the rest
// pointed at a temporary tree (IMPLEMENTATION.md, test isolation).
var isolatedVars = []string{
	"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
	"TMPDIR", "PASSWORD_STORE_DIR", "GNUPGHOME",
}

func TestMain(m *testing.M) {
	// agent.Start re-executes this test binary as the agent, as passh's
	// hidden subcommand does.
	if len(os.Args) > 1 && os.Args[1] == agent.ChildCommand {
		os.Exit(agent.ChildMain(os.Args[2:]))
	}
	root, err := os.MkdirTemp("", "passh-tui-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, v := range isolatedVars {
		dir := filepath.Join(root, strings.ToLower(v))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv(v, dir)
	}
	os.Setenv("PASSH_CONFIG", filepath.Join(root, "passh-config.toml"))
	os.Setenv("TERM", "xterm-256color")
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}

const testPass = "orbit velvet cactus lumen harbor quill"

// lowKeyBlock builds a key block like keys.WrapKey, with a tiny scrypt
// work factor so that passphrase tests stay fast. passh itself always
// writes 2^18.
func lowKeyBlock(t testing.TB, id *age.X25519Identity, pass string) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(4)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(id.String() + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// writeVault writes a vault (revision 1) holding entries.
func writeVault(t testing.TB, path string, key *age.X25519Identity, entries ...model.Entry) {
	t.Helper()
	data := model.NewData()
	data.Revision = 1
	data.SavedAt = t0
	for _, e := range entries {
		if _, err := data.Add(e, t0, false); err != nil {
			t.Fatal(err)
		}
	}
	plain, err := data.Encode()
	if err != nil {
		t.Fatal(err)
	}
	db, err := keys.EncryptData(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	file, err := vaultfile.Encode(lowKeyBlock(t, key, testPass), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
}

func entry(path string, mod func(e *model.Entry)) model.Entry {
	e := model.Entry{Path: paths.MustParse(path), Password: "pw-" + path}
	if mod != nil {
		mod(&e)
	}
	return e
}

func sampleEntries() []model.Entry {
	return []model.Entry{
		entry("bank/chase", func(e *model.Entry) { e.Tags = []string{"finance"}; e.Username = "chase-user" }),
		entry("bank/revolut", func(e *model.Entry) { e.Tags = []string{"finance", "2fa"} }),
		entry("work/github", func(e *model.Entry) {
			e.Password = "s3cr3t-P@ss"
			e.Username = "arsenii"
			e.URL = "https://github.com"
			e.Tags = []string{"work", "dev", "2fa"}
			e.Fields = []model.Field{{Key: "recovery-email", Value: "me@example.com"}, {Key: "otp", Value: "otpauth://totp/x?secret=JBSWY3DP"}}
			e.Notes = "Recovery codes in notes.\nline two"
		}),
		entry("work/jira", func(e *model.Entry) { e.Tags = []string{"work"} }),
		entry("homelab/pi/ssh", func(e *model.Entry) { e.Tags = []string{"homelab"} }),
		entry("readme", nil),
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type copyRec struct {
	value string
	d     time.Duration
}

// fakeClip is a clipboard without a timer: a copy stays pending until
// ClearPending, or until the test fires the timed clear (fire). The TUI
// reads the deadline against its own clock.
type fakeClip struct {
	mu       sync.Mutex
	now      func() time.Time // nil: time.Now
	copies   []copyRec
	clears   int
	pending  bool
	deadline time.Time
	err      error // CopyFor's
	clearErr error // the clears'
	copied   bool  // a copy was made: ClearResult reports on it
	cleared  bool  // the last copy's clear happened
	lastErr  error // its error
	// gate, if set, holds CopyFor until the test closes it; entered gets
	// a value when a copy waits there. Set before the copy starts.
	gate, entered chan struct{}
}

func (c *fakeClip) CopyFor(_ context.Context, v string, d time.Duration) error {
	if c.gate != nil {
		c.entered <- struct{}{}
		<-c.gate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	c.copies = append(c.copies, copyRec{v, d})
	c.pending, c.deadline = true, now().Add(d)
	c.copied, c.cleared, c.lastErr = true, false, nil
	return nil
}

// fire runs the timed clear, as the real clipboard's timer would.
func (c *fakeClip) fire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

// clearLocked clears a pending value. c.mu is held.
func (c *fakeClip) clearLocked() error {
	if !c.pending {
		return nil
	}
	c.clears++
	c.pending, c.cleared, c.lastErr = false, true, c.clearErr
	return c.clearErr
}

// ClearResult implements ClearReporter.
func (c *fakeClip) ClearResult() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.copied {
		return true, nil
	}
	return c.cleared, c.lastErr
}

func (c *fakeClip) Pending() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline, c.pending
}

func (c *fakeClip) state() (copies []copyRec, clears int, pending bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]copyRec(nil), c.copies...), c.clears, c.pending
}

func (c *fakeClip) ClearPending(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clearLocked()
}

type fakeAgent struct {
	mu      sync.Mutex
	key     *age.X25519Identity
	running bool
	stops   int
	keyReqs int
	stopErr error
}

func (a *fakeAgent) KeyFor(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keyReqs++
	if !a.running {
		return nil, agent.ErrNoAgent
	}
	if len(keyBlock) == 0 {
		return nil, errors.New("fake agent: asked without a key block")
	}
	return a.key, nil
}

func (a *fakeAgent) Running(context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

func (a *fakeAgent) Stop(context.Context) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stops++
	if a.stopErr != nil {
		return false, a.stopErr
	}
	was := a.running
	a.running = false
	return was, nil
}

type timer struct {
	d   time.Duration
	msg tea.Msg
}

// harness drives the model like Bubble Tea does: it sends messages to
// Update and runs the commands it returns, except timers, which it records
// (tests send tickMsg and friends themselves, with a fake clock). When the
// program quits, it locks like Run does after the program (shutdown).
type harness struct {
	t      *testing.T
	m      *app
	cfg    *config.Config
	clock  *fakeClock
	clip   *fakeClip
	agent  *fakeAgent
	path   string
	state  string
	key    *age.X25519Identity
	timers []timer
	quit   bool
	// wrap, if set, wraps every vault the TUI opens (gates, failures).
	wrap func(*vault.Vault) Vault

	results chan tea.Msg // finished commands' messages
	pending int          // commands still running
}

type hopt func(h *harness, d *deps)

// withPassphrase: no key source, no agent: the lock screen asks.
func withPassphrase() hopt { return func(h *harness, d *deps) { d.keySource = nil } }

// withAgent: the key comes from a (fake) running agent.
func withAgent() hopt {
	return func(h *harness, d *deps) {
		d.keySource = nil
		h.agent.running = true
		d.agent = h.agent
	}
}

func newHarness(t *testing.T, entries []model.Entry, opts ...hopt) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{
		t:     t,
		cfg:   config.Default(),
		clock: &fakeClock{t: t0},
		path:  filepath.Join(dir, "vault.passh"),
		state: filepath.Join(dir, "state"),
	}
	h.clip = &fakeClip{now: h.clock.Now}
	var err error
	if h.key, err = keys.NewVaultKey(); err != nil {
		t.Fatal(err)
	}
	h.agent = &fakeAgent{key: h.key}
	writeVault(t, h.path, h.key, entries...)
	h.cfg.Vault = h.path
	h.start(opts...)
	return h
}

// start makes a new model over the harness's vault, as a new `passh`
// would, and runs its Init.
func (h *harness) start(opts ...hopt) {
	h.t.Helper()
	h.timers, h.quit = nil, false
	d := deps{
		cfg:       h.cfg,
		vaultPath: h.path,
		keySource: keys.FromIdentity(h.key),
		clip:      h.clip,
		ctx:       h.t.Context(),
		now:       h.clock.Now,
		after: func(dur time.Duration, msg tea.Msg) tea.Cmd {
			h.timers = append(h.timers, timer{dur, msg})
			return nil
		},
	}
	for _, o := range opts {
		o(h, &d)
	}
	d.open = h.opener()
	h.m = newModel(d)
	h.send(tea.WindowSizeMsg{Width: 100, Height: 30})
	h.run(h.m.Init())
}

func (h *harness) vaultOptions() vault.Options {
	return vault.Options{StateDir: h.state, BackupKeep: 2, RollbackWarn: h.cfg.Rollback.Warn, Now: h.clock.Now}
}

func (h *harness) opener() opener {
	return func(ctx context.Context, ks keys.KeySource, prompt func(string) (bool, error), warn func(string)) (Vault, error) {
		o := h.vaultOptions()
		o.Prompt, o.Warn = prompt, warn
		v, err := vault.Open(ctx, h.path, ks, o)
		if err != nil {
			return nil, err
		}
		if h.wrap != nil {
			return h.wrap(v), nil
		}
		return v, nil
	}
}

func (h *harness) send(msg tea.Msg) {
	h.t.Helper()
	_, cmd := h.m.Update(msg)
	h.run(cmd)
}

// run runs cmd concurrently, as Bubble Tea does, and feeds its messages
// back until every command has finished, or only the wait for the answer
// to a rollback question is left.
func (h *harness) run(cmd tea.Cmd) {
	h.t.Helper()
	h.spawn(cmd)
	deadline := time.After(10 * time.Second)
	for h.pending > 0 {
		if h.pending == 1 && h.asked() {
			return // the result waits for the user's answer
		}
		select {
		case msg := <-h.results:
			h.pending--
			h.deliver(msg)
		case <-time.After(2 * time.Millisecond):
		case <-deadline:
			h.t.Fatal("a command didn't finish")
		}
	}
}

// asked reports whether the model shows the rollback question.
func (h *harness) asked() bool {
	return h.m.lk.ask != "" || (h.m.confirm != nil && h.m.confirm.kind == confirmRollback)
}

func (h *harness) spawn(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	if h.results == nil {
		h.results = make(chan tea.Msg, 64)
	}
	h.pending++
	go func() { h.results <- cmd() }()
}

func (h *harness) deliver(msg tea.Msg) {
	switch msg := msg.(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			h.spawn(c)
		}
	case tea.QuitMsg:
		h.quit = true
		h.m.shutdown() // what Run does once the program has ended
	default:
		_, cmd := h.m.Update(msg)
		h.spawn(cmd)
	}
}

// key builds the key press Bubble Tea reports for a name such as "tab",
// "shift+tab", "ctrl+s", "R" or "a".
func key(t *testing.T, name string) tea.KeyPressMsg {
	t.Helper()
	parts := strings.Split(name, "+")
	if name == "+" {
		parts = []string{"+"}
	}
	var k tea.KeyPressMsg
	for _, m := range parts[:len(parts)-1] {
		switch m {
		case "ctrl":
			k.Mod |= tea.ModCtrl
		case "alt":
			k.Mod |= tea.ModAlt
		case "shift":
			k.Mod |= tea.ModShift
		}
	}
	codes := map[string]rune{
		"tab": tea.KeyTab, "enter": tea.KeyEnter, "esc": tea.KeyEscape, "backspace": tea.KeyBackspace,
		"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
		"home": tea.KeyHome, "end": tea.KeyEnd, "delete": tea.KeyDelete,
		"pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown, "space": tea.KeySpace,
	}
	last := parts[len(parts)-1]
	if c, ok := codes[last]; ok {
		k.Code = c
	} else {
		k.Code = []rune(last)[0]
		if k.Mod == 0 {
			k.Text = last
		}
	}
	if k.String() != name {
		t.Fatalf("key %q reports itself as %q", name, k.String())
	}
	return k
}

func (h *harness) press(names ...string) {
	h.t.Helper()
	for _, n := range names {
		h.send(key(h.t, n))
	}
}

func (h *harness) typeText(s string) {
	h.t.Helper()
	for _, r := range s {
		h.send(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
}

func (h *harness) view() string { return h.m.View().Content }

// plain is the view without styling.
func (h *harness) plain() string { return ansi.Strip(h.view()) }

// shows reports whether the view shows text, wherever the layout wrapped
// it: the plain view is compared as it is, and also flowed, with the box
// borders gone and each line break read as a space (a break between words)
// or as nothing (a long word, such as a temporary path, broken in the
// middle). Runs of spaces count as one.
func shows(view, text string) bool {
	if strings.Contains(view, text) {
		return true
	}
	text = collapse(text)
	var lines []string
	for l := range strings.SplitSeq(strings.ReplaceAll(view, "│", " "), "\n") {
		lines = append(lines, strings.TrimSpace(l))
	}
	return strings.Contains(collapse(strings.Join(lines, " ")), text) ||
		strings.Contains(collapse(strings.Join(lines, "")), text)
}

// collapse turns every run of whitespace into one space.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

func (h *harness) contains(want ...string) {
	h.t.Helper()
	p := h.plain()
	for _, w := range want {
		if !shows(p, w) {
			h.t.Fatalf("the view lacks %q:\n%s", w, p)
		}
	}
}

func (h *harness) lacks(bad ...string) {
	h.t.Helper()
	p := h.plain()
	for _, b := range bad {
		if shows(p, b) {
			h.t.Fatalf("the view shows %q:\n%s", b, p)
		}
	}
}

// selectPath moves the cursor to the entry at path in the Folders view.
func (h *harness) selectPath(path string) {
	h.t.Helper()
	e, ok := h.diskEntry(path)
	if !ok {
		h.t.Fatalf("no entry %s on disk", path)
	}
	h.m.selectEntry(e.ID)
	if got, ok := h.m.selectedEntry(); !ok || got.Path.String() != path {
		h.t.Fatalf("selected %v %v, want %s", got.Path, ok, path)
	}
}

// diskVault opens the vault file as another passh process would.
func (h *harness) diskVault() *vault.Vault {
	h.t.Helper()
	v, err := vault.Open(context.Background(), h.path, keys.FromIdentity(h.key), h.vaultOptions())
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

func (h *harness) diskEntry(path string) (model.Entry, bool) {
	h.t.Helper()
	v := h.diskVault()
	defer v.Close()
	return v.Get(paths.MustParse(path))
}

// external changes the vault file behind the TUI's back.
func (h *harness) external(fn func(v *vault.Vault)) {
	h.t.Helper()
	v := h.diskVault()
	defer v.Close()
	fn(v)
}

func (h *harness) mustUnlocked() {
	h.t.Helper()
	if h.m.screen != screenMain {
		h.t.Fatalf("not unlocked:\n%s", h.plain())
	}
}

func pasteMsg(s string) tea.PasteMsg { return tea.PasteMsg{Content: s} }

func TestShowsWrappedText(t *testing.T) {
	for _, view := range []string{
		" /tmp/x/vault.passh: data is\n damaged; restore a backup",                   // break between words
		"│ /tmp/x/vault.passh: data is   │\n│ damaged; restore a backup    │",        // inside the box
		" /tmp/passh-tui-\n test-123/vault.passh: data is damaged; restore a backup", // a long word broken
	} {
		for _, want := range []string{"data is damaged; restore a backup", "vault.passh: data is damaged"} {
			if !shows(view, want) {
				t.Errorf("%q not found in %q", want, view)
			}
		}
	}
	if !shows(" /tmp/passh-tui-\n test-123/vault.passh", "/tmp/passh-tui-test-123/vault.passh") {
		t.Error("a path broken in the middle")
	}
	if shows("data is\n damaged", "data is not damaged") || shows("abc", "abd") {
		t.Error("false match")
	}
}
