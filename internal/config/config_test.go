package config

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devapro/passh/internal/i18n"
)

// isolate points every location passh could touch at a fresh temporary
// tree and returns the fake $HOME.
func isolate(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for env, sub := range map[string]string{
		"HOME":               "home",
		"XDG_CONFIG_HOME":    "home/.config",
		"XDG_DATA_HOME":      "home/.local/share",
		"XDG_STATE_HOME":     "home/.local/state",
		"XDG_RUNTIME_DIR":    "run",
		"TMPDIR":             "tmp",
		"PASSWORD_STORE_DIR": "home/.password-store",
		"GNUPGHOME":          "home/.gnupg",
	} {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv(env, dir)
	}
	t.Setenv("PASSH_CONFIG", "")
	return filepath.Join(root, "home")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateParsesToDefaults(t *testing.T) {
	home := isolate(t)
	text, err := Template("~/.local/share/passh/vault.passh")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.Vault = filepath.Join(home, ".local/share/passh/vault.passh")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("template parses to\n%+v\nwant\n%+v", got, want)
	}
}

func TestDefaults(t *testing.T) {
	isolate(t)
	d := Default()
	if d.Session.IdleTTL != 5*time.Minute || !d.Session.StopAgent ||
		d.Agent.IdleTTL != 15*time.Minute || d.Agent.MaxTTL != 2*time.Hour ||
		d.Backup.Keep != 10 || !d.Rollback.Warn ||
		d.Clipboard.ClearAfter != 30*time.Second || !d.Clipboard.OSC52 || len(d.Clipboard.Command) != 0 ||
		d.PrintWeb.Enabled || d.PrintWeb.Port != 8443 ||
		!reflect.DeepEqual(d.PrintWeb.Interfaces, []string{"wg0", "eth0"}) ||
		len(d.PrintWeb.AllowFrom) != 0 || len(d.PrintWeb.Hostnames) != 0 ||
		d.PrintWeb.TTL != 5*time.Minute || d.Vault != "" {
		t.Errorf("Default() = %+v", d)
	}
	// Only vault is required.
	cfg, err := Parse([]byte(`vault = "/srv/v.passh"`))
	if err != nil {
		t.Fatal(err)
	}
	d.Vault = "/srv/v.passh"
	if !reflect.DeepEqual(cfg, d) {
		t.Errorf("minimal config = %+v, want defaults", cfg)
	}
}

// TestTemplateMatchesSpec keeps the template in step with the §3.3 example.
func TestTemplateMatchesSpec(t *testing.T) {
	isolate(t)
	spec, err := os.ReadFile("../../spec.md")
	if err != nil {
		t.Skipf("spec.md not available: %v", err)
	}
	s := string(spec)
	i := strings.Index(s, "### 3.3 Config file")
	if i < 0 {
		t.Skip("§3.3 not found in spec.md")
	}
	s = s[i:]
	start := strings.Index(s, "```toml\n")
	if start < 0 {
		t.Fatal("no toml block in §3.3")
	}
	s = s[start+len("```toml\n"):]
	block := s[:strings.Index(s, "```")]
	text, err := Template("~/.local/share/passh/vault.passh")
	if err != nil {
		t.Fatal(err)
	}
	if text != block {
		t.Errorf("template differs from spec §3.3:\n--- template\n%s\n--- spec\n%s", text, block)
	}
}

func TestParseAllValues(t *testing.T) {
	isolate(t)
	cfg, err := Parse([]byte(`
vault = "/data/my vault.passh"
[session]
idle_ttl = "90s"
stop_agent = false
[agent]
idle_ttl = "1h30m"
max_ttl = "8h"
[backup]
keep = 0
[rollback]
warn = false
[clipboard]
clear_after = "45s"
osc52 = false
command = ["xclip", "-selection", "clipboard"]
[print_web]
enabled = true
port = 9443
interfaces = ["wlan0"]
allow_from = ["192.168.1.7/24", "fd00::/8"]
hostnames = ["pi.local"]
ttl = "15m"
`))
	if err != nil {
		t.Fatal(err)
	}
	want := &Config{
		Vault:     "/data/my vault.passh",
		Session:   Session{IdleTTL: 90 * time.Second},
		Agent:     Agent{IdleTTL: 90 * time.Minute, MaxTTL: 8 * time.Hour},
		Backup:    Backup{Keep: 0},
		Rollback:  Rollback{Warn: false},
		Clipboard: Clipboard{ClearAfter: 45 * time.Second, Command: []string{"xclip", "-selection", "clipboard"}},
		PrintWeb: PrintWeb{
			Enabled:    true,
			Port:       9443,
			Interfaces: []string{"wlan0"},
			AllowFrom:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00::/8")},
			Hostnames:  []string{"pi.local"},
			TTL:        15 * time.Minute,
		},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("Parse =\n%+v\nwant\n%+v", cfg, want)
	}
}

func TestVaultPath(t *testing.T) {
	home := isolate(t)
	for in, want := range map[string]string{
		`"~/v.passh"`:               filepath.Join(home, "v.passh"),
		`"~/a/../b//v.passh"`:       filepath.Join(home, "b/v.passh"),
		`"/abs/v.passh"`:            "/abs/v.passh",
		`'C:\no'`:                   "",
		`"relative/v.passh"`:        "",
		`""`:                        "",
		`"~"`:                       "",
		`"~other/v.passh"`:          "",
		`"./v.passh"`:               "",
		`"\u00e9t\u00e9/v.passh"`:   "",
		`"/\u00e9t\u00e9/v.passh"`:  "/\u00e9t\u00e9/v.passh",
		`"/with \"quote\"/v.passh"`: `/with "quote"/v.passh`,
	} {
		cfg, err := Parse([]byte("vault = " + in))
		if want == "" {
			if err == nil {
				t.Errorf("vault = %s accepted as %q", in, cfg.Vault)
			} else if !strings.Contains(err.Error(), "vault") {
				t.Errorf("vault = %s: error %q doesn't name vault", in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("vault = %s: %v", in, err)
			continue
		}
		if cfg.Vault != want {
			t.Errorf("vault = %s gives %q, want %q", in, cfg.Vault, want)
		}
	}
}

func TestUnknownKeys(t *testing.T) {
	isolate(t)
	_, err := Parse([]byte(`
vault = "/v"
colour = "blue"
[session]
idel_ttl = "5m"
[sesion]
idle_ttl = "1m"
stop_agent = true
[print_web]
ttl = "5m"
tls = true
`))
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *Error", err)
	}
	want := []string{
		`unknown key "colour"`,
		`unknown key "session.idel_ttl"`,
		`unknown key "sesion"`,
		`unknown key "print_web.tls"`,
	}
	if got := problemTexts(ce); !reflect.DeepEqual(got, want) {
		t.Errorf("problems = %q, want %q", got, want)
	}
}

func TestValidation(t *testing.T) {
	isolate(t)
	tests := []struct {
		body string
		want string // substring of the error
	}{
		{"", "vault is required"},
		{`vault = 3`, "vault"},
		{"[session]\nidle_ttl = \"5\"", "session.idle_ttl"},
		{"[session]\nidle_ttl = \"0s\"", "session.idle_ttl"},
		{"[session]\nidle_ttl = \"-1m\"", "session.idle_ttl"},
		{"[session]\nidle_ttl = 300", "idle_ttl"},
		{"[session]\nstop_agent = \"yes\"", "stop_agent"},
		{"[agent]\nidle_ttl = \"soon\"", "agent.idle_ttl"},
		{"[agent]\nmax_ttl = \"0\"", "agent.max_ttl"},
		{"[backup]\nkeep = -1", "backup.keep"},
		{"[backup]\nkeep = 10000000", "backup.keep"},
		{"[backup]\nkeep = \"10\"", "keep"},
		{"[backup]\nkeep = 1.5", "keep"},
		{"[clipboard]\nclear_after = \"\"", "clipboard.clear_after"},
		{"[clipboard]\ncommand = [\"\"]", "clipboard.command"},
		{"[clipboard]\ncommand = \"pbcopy\"", "command"},
		{"[print_web]\nport = 0", "print_web.port"},
		{"[print_web]\nport = 65536", "print_web.port"},
		{"[print_web]\nttl = \"59s\"", "print_web.ttl"},
		{"[print_web]\nttl = \"16m\"", "print_web.ttl"},
		{"[print_web]\nttl = \"1h\"", "print_web.ttl"},
		{"[print_web]\nallow_from = [\"10.0.0.0/33\"]", "print_web.allow_from"},
		{"[print_web]\nallow_from = [\"10.0.0.1\"]", "print_web.allow_from"},
		{"[print_web]\nallow_from = [\"lan\"]", "print_web.allow_from"},
		{"[print_web]\ninterfaces = [\"\"]", "print_web.interfaces"},
		{"[print_web]\nhostnames = [\"pi local\"]", "print_web.hostnames"},
		{"session = 5", "session"},
		{"[session\n", "line"},
		{`language = "de"`, `language: "de" is not one of "en", "ru" or "sr"`},
		{`language = "RU"`, "language"},
		{`language = ""`, "language"},
		{`language = 1`, "language"},
	}
	for _, tc := range tests {
		body := tc.body
		if !strings.Contains(body, "vault") && tc.want != "vault is required" {
			body = "vault = \"/v\"\n" + body
		}
		_, err := Parse([]byte(body))
		if err == nil {
			t.Errorf("%q: no error", body)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %q doesn't mention %q", body, err, tc.want)
		}
	}
	// The TTL bounds themselves are valid.
	for _, ttl := range []string{"1m", "15m", "60s", "14m59s"} {
		if _, err := Parse([]byte("vault = \"/v\"\n[print_web]\nttl = \"" + ttl + "\"")); err != nil {
			t.Errorf("print_web.ttl = %s: %v", ttl, err)
		}
	}
	for _, port := range []string{"1", "65535"} {
		if _, err := Parse([]byte("vault = \"/v\"\n[print_web]\nport = " + port)); err != nil {
			t.Errorf("print_web.port = %s: %v", port, err)
		}
	}
}

// TestLanguage: language is en, ru or sr, exactly; absent means en (§3.3).
func TestLanguage(t *testing.T) {
	isolate(t)
	for in, want := range map[string]i18n.Lang{"": i18n.En, `language = "en"`: i18n.En, `language = "ru"`: i18n.Ru, `language = "sr"`: i18n.Sr} {
		cfg, err := Parse([]byte("vault = \"/v\"\n" + in))
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if cfg.Language != want {
			t.Errorf("%q: Language = %v, want %v", in, cfg.Language, want)
		}
	}
	if Default().Language != i18n.En {
		t.Errorf("Default().Language = %v, want en", Default().Language)
	}
	// Without a vault key (allowed with --vault), the language still counts.
	path := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, path, "language = \"sr\"\n")
	cfg, err := Resolve(path, "/v.passh")
	if err != nil || cfg.Language != i18n.Sr {
		t.Errorf("Resolve with --vault and a config naming only the language: %+v, %v", cfg, err)
	}
}

func TestAllProblemsReported(t *testing.T) {
	isolate(t)
	_, err := Parse([]byte("vault = \"rel\"\ntypo = 1\n[backup]\nkeep = -2\n[print_web]\nport = 0\n"))
	var ce *Error
	if !errors.As(err, &ce) || len(ce.Problems) != 4 {
		t.Fatalf("err = %v, want 4 problems", err)
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "config:\n  ") {
		t.Errorf("message = %q", msg)
	}
}

func TestLocate(t *testing.T) {
	home := isolate(t)
	cfgHome := os.Getenv("XDG_CONFIG_HOME")

	loc, err := Locate("")
	if err != nil || loc != (Location{filepath.Join(cfgHome, "passh/config.toml"), SourceDefault}) {
		t.Errorf("default: %v, %v", loc, err)
	}

	t.Setenv("XDG_CONFIG_HOME", "relative/ignored")
	loc, _ = Locate("")
	if loc.Path != filepath.Join(home, ".config/passh/config.toml") {
		t.Errorf("relative XDG_CONFIG_HOME not ignored: %v", loc)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	loc, _ = Locate("")
	if loc.Path != filepath.Join(home, ".config/passh/config.toml") {
		t.Errorf("empty XDG_CONFIG_HOME: %v", loc)
	}

	t.Setenv("PASSH_CONFIG", "~/work/passh.toml")
	loc, _ = Locate("")
	if loc != (Location{filepath.Join(home, "work/passh.toml"), SourceEnv}) {
		t.Errorf("env: %v", loc)
	}

	loc, _ = Locate("/etc/other.toml")
	if loc != (Location{"/etc/other.toml", SourceFlag}) {
		t.Errorf("flag beats env: %v", loc)
	}

	wd, _ := os.Getwd()
	loc, _ = Locate("rel.toml")
	if loc.Path != filepath.Join(wd, "rel.toml") {
		t.Errorf("relative flag not made absolute: %v", loc)
	}
	if s := loc.String(); !strings.Contains(s, "--config") {
		t.Errorf("Location.String() = %q", s)
	}

	t.Setenv("HOME", "")
	t.Setenv("PASSH_CONFIG", "")
	if _, err := Locate(""); err == nil {
		t.Error("Locate without HOME or XDG_CONFIG_HOME succeeded")
	}
	if _, err := Locate("~/x.toml"); err == nil {
		t.Error("~ expanded without HOME")
	}
}

func TestResolve(t *testing.T) {
	home := isolate(t)
	def, _ := DefaultConfigPath()

	// No config file, no --vault: ErrNoConfig with a hint.
	_, err := Resolve("", "")
	if !errors.Is(err, ErrNoConfig) {
		t.Fatalf("err = %v, want ErrNoConfig", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "passh init") || !strings.Contains(msg, def) || !strings.Contains(msg, "--vault") {
		t.Errorf("message %q lacks the hint", msg)
	}

	// No config file, --vault: defaults plus the vault.
	cfg, err := Resolve("", "~/usb/vault.passh")
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.Vault = filepath.Join(home, "usb/vault.passh")
	want.VaultFromFlag = true
	want.Location = Location{def, SourceDefault}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("Resolve with --vault =\n%+v\nwant\n%+v", cfg, want)
	}

	// A relative --vault is made absolute.
	wd, _ := os.Getwd()
	cfg, _ = Resolve("", "v.passh")
	if cfg.Vault != filepath.Join(wd, "v.passh") {
		t.Errorf("relative --vault = %q", cfg.Vault)
	}

	// A file named with --config must exist, even with --vault.
	_, err = Resolve(filepath.Join(home, "missing.toml"), "/v")
	if !errors.Is(err, ErrNoConfig) || !strings.Contains(err.Error(), "--config") {
		t.Errorf("missing --config file: %v", err)
	}

	// $PASSH_CONFIG naming a missing file is tolerated with --vault.
	t.Setenv("PASSH_CONFIG", filepath.Join(home, "env-missing.toml"))
	if _, err := Resolve("", "/v"); err != nil {
		t.Errorf("missing $PASSH_CONFIG file with --vault: %v", err)
	}
	_, err = Resolve("", "")
	if !errors.Is(err, ErrNoConfig) || !strings.Contains(err.Error(), "$PASSH_CONFIG") {
		t.Errorf("missing $PASSH_CONFIG file: %v", err)
	}
	t.Setenv("PASSH_CONFIG", "")

	// An existing file is read; --vault overrides its vault.
	writeFile(t, def, "vault = \"~/main.passh\"\n[backup]\nkeep = 3\n")
	cfg, err = Resolve("", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault != filepath.Join(home, "main.passh") || cfg.Backup.Keep != 3 || !cfg.Loaded || cfg.VaultFromFlag {
		t.Errorf("Resolve = %+v", cfg)
	}
	cfg, err = Resolve("", "/other.passh")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault != "/other.passh" || cfg.Backup.Keep != 3 || !cfg.VaultFromFlag {
		t.Errorf("Resolve with --vault = %+v", cfg)
	}

	// A file without vault is fine only with --vault.
	writeFile(t, def, "[backup]\nkeep = 4\n")
	if _, err := Resolve("", ""); err == nil || !strings.Contains(err.Error(), "vault is required") {
		t.Errorf("file without vault: %v", err)
	}
	if cfg, err := Resolve("", "/v"); err != nil || cfg.Backup.Keep != 4 {
		t.Errorf("file without vault, --vault: %+v, %v", cfg, err)
	}

	// An invalid file is an error even with --vault, and names the file.
	writeFile(t, def, "vault = \"/v\"\nbogus = 1\n")
	_, err = Resolve("", "/v")
	var ce *Error
	if !errors.As(err, &ce) || ce.Path != def || !strings.Contains(err.Error(), def) {
		t.Errorf("invalid file: %v", err)
	}

	// Load reads a given path.
	other := filepath.Join(home, "other.toml")
	writeFile(t, other, "vault = \"/o\"\n")
	cfg, err = Load(other)
	if err != nil || cfg.Vault != "/o" || cfg.Location != (Location{other, SourceFile}) {
		t.Errorf("Load = %+v, %v", cfg, err)
	}
	if _, err := Load(filepath.Join(home, "nope.toml")); !errors.Is(err, ErrNoConfig) {
		t.Errorf("Load(missing) = %v", err)
	}
	if _, err := Load(home); err == nil || errors.Is(err, ErrNoConfig) {
		t.Errorf("Load(directory) = %v", err)
	}
}

func TestWriteInitial(t *testing.T) {
	home := isolate(t)
	path, _ := DefaultConfigPath()
	vault := filepath.Join(home, ".local/share/passh/vault.passh")
	if err := WriteInitial(path, vault); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %o, want 600", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(path))
	if di.Mode().Perm() != 0o700 {
		t.Errorf("config folder mode = %o, want 700", di.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "vault    = \"~/.local/share/passh/vault.passh\"\nlanguage = \"en\"") {
		t.Errorf("vault under HOME not written as ~/: %q", strings.SplitN(string(data), "\n", 2)[0])
	}
	if !strings.Contains(string(data), "# TUI locks after this much inactivity") {
		t.Error("template comments missing")
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault != vault {
		t.Errorf("vault = %q, want %q", cfg.Vault, vault)
	}

	// Never rewritten.
	if err := WriteInitial(path, "/elsewhere"); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second WriteInitial = %v, want fs.ErrExist", err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(data) {
		t.Error("existing config was changed")
	}

	// A dangling symlink at the path is not followed.
	link := filepath.Join(home, "link.toml")
	target := filepath.Join(home, "target.toml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteInitial(link, "/v"); !errors.Is(err, fs.ErrExist) {
		t.Errorf("WriteInitial over a symlink = %v, want fs.ErrExist", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Error("symlink target was created")
	}

	// Paths outside HOME and with special characters round-trip.
	for _, v := range []string{"/srv/vault.passh", `/odd "dir"\x/v.passh`, "/tab\there/v", "~/x/v.passh"} {
		p := filepath.Join(t.TempDir(), "c.toml")
		if err := WriteInitial(p, v); err != nil {
			t.Errorf("WriteInitial(%q): %v", v, err)
			continue
		}
		cfg, err := Load(p)
		if err != nil {
			t.Errorf("Load after WriteInitial(%q): %v", v, err)
			continue
		}
		want, _ := ExpandHome(v)
		if cfg.Vault != want {
			t.Errorf("vault %q came back as %q", v, cfg.Vault)
		}
	}

	for _, v := range []string{"relative.passh", "", "/bad\xff"} {
		if err := WriteInitial(filepath.Join(t.TempDir(), "c.toml"), v); err == nil {
			t.Errorf("WriteInitial(vault %q) succeeded", v)
		}
	}
}

func TestDirs(t *testing.T) {
	home := isolate(t)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	if p, _ := DefaultVaultPath(); p != filepath.Join(home, ".local/share/passh/vault.passh") {
		t.Errorf("DefaultVaultPath = %q", p)
	}
	if p, _ := StateDir(); p != filepath.Join(home, ".local/state/passh") {
		t.Errorf("StateDir = %q", p)
	}
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	t.Setenv("XDG_STATE_HOME", "/xdg/state")
	if p, _ := DefaultVaultPath(); p != "/xdg/data/passh/vault.passh" {
		t.Errorf("DefaultVaultPath = %q", p)
	}
	if p, _ := StateDir(); p != "/xdg/state/passh" {
		t.Errorf("StateDir = %q", p)
	}

	t.Setenv("HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	if _, err := StateDir(); err == nil {
		t.Error("StateDir without HOME succeeded")
	}
	t.Setenv("HOME", "relative")
	if _, err := HomeDir(); err == nil {
		t.Error("relative HOME accepted")
	}
}

func TestExpandAndContractHome(t *testing.T) {
	home := isolate(t)
	for in, want := range map[string]string{
		"~":       home,
		"~/a/b":   filepath.Join(home, "a/b"),
		"/abs":    "/abs",
		"rel":     "rel",
		"~user/x": "~user/x",
		"x/~/y":   "x/~/y",
	} {
		if got, err := ExpandHome(in); err != nil || got != want {
			t.Errorf("ExpandHome(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for in, want := range map[string]string{
		filepath.Join(home, "a/b"): "~/a/b",
		home:                       home,
		home + "x/y":               home + "x/y",
		"/elsewhere":               "/elsewhere",
	} {
		if got := ContractHome(in); got != want {
			t.Errorf("ContractHome(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ExpandPath(""); err == nil {
		t.Error("ExpandPath(\"\") succeeded")
	}
	if Source(99).String() != "file" || SourceEnv.String() != "$PASSH_CONFIG" || SourceDefault.String() != "default location" {
		t.Error("Source.String")
	}
}

func TestResolveWithoutHome(t *testing.T) {
	isolate(t)
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, err := Resolve("", ""); err == nil {
		t.Error("Resolve without HOME and --vault succeeded")
	}
	cfg, err := Resolve("", "/media/usb/vault.passh")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault != "/media/usb/vault.passh" || cfg.Loaded || !cfg.VaultFromFlag || cfg.Backup.Keep != 10 {
		t.Errorf("Resolve = %+v", cfg)
	}
	if _, err := Resolve("", "~/v.passh"); err == nil {
		t.Error("--vault ~/… expanded without HOME")
	}
}

// SEC-8 (CORE-011): a config file larger than 1 MiB is refused without
// being parsed; one of exactly 1 MiB is read.
func TestLoadTooLarge(t *testing.T) {
	isolate(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	head := "vault = \"/v\"\n"
	writeFile(t, path, head+strings.Repeat("#", maxFileSize-len(head)))
	if _, err := Load(path); err != nil {
		t.Fatalf("1 MiB: %v", err)
	}
	writeFile(t, path, head+strings.Repeat("#", maxFileSize-len(head)+1))
	_, err := Load(path)
	var ce *Error
	if !errors.As(err, &ce) || err.Error() != "config "+path+": the file is larger than 1 MiB" {
		t.Fatalf("1 MiB + 1: %v", err)
	}
	if _, err := Resolve(path, ""); !errors.As(err, &ce) {
		t.Fatalf("Resolve: %v", err)
	}
}
