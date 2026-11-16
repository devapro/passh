// Package config locates, parses and validates the passh config file (§3.3)
// and knows passh's folders (§3.2).
//
// The file is TOML and strict: unknown keys are errors, so typos don't go
// unnoticed. Every key except vault has a default. With --vault, passh works
// without a config file (Resolve).
package config

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/devapro/passh/internal/i18n"
)

// Config holds the settings of §3.3, with defaults filled in and values
// validated. Durations are parsed; Vault is an absolute, cleaned path.
type Config struct {
	Vault string
	// Language is the language passh writes in for people (§3.3); En when
	// the key is absent.
	Language  i18n.Lang
	Session   Session
	Agent     Agent
	Backup    Backup
	Rollback  Rollback
	Clipboard Clipboard
	PrintWeb  PrintWeb

	// Location is where the config file was looked for.
	Location Location
	// Loaded is true when that file was read; false when Resolve fell back
	// to defaults because of --vault.
	Loaded bool
	// VaultFromFlag is true when Vault came from --vault.
	VaultFromFlag bool
}

// Session is the [session] table.
type Session struct {
	IdleTTL   time.Duration // TUI locks after this much inactivity
	StopAgent bool          // a TUI lock also stops the agent
}

// Agent is the [agent] table.
type Agent struct {
	IdleTTL time.Duration // the agent exits after this long without a request
	MaxTTL  time.Duration // and after this long in any case
}

// Backup is the [backup] table.
type Backup struct {
	Keep int // automatic backups kept; 0 = off
}

// Rollback is the [rollback] table.
type Rollback struct {
	Warn bool
}

// Clipboard is the [clipboard] table.
type Clipboard struct {
	ClearAfter time.Duration
	OSC52      bool
	Command    []string // empty: no local clipboard tool
}

// PrintWeb is the [print_web] table.
type PrintWeb struct {
	Enabled    bool
	Port       int
	Interfaces []string
	AllowFrom  []netip.Prefix // masked; empty: subnets of the bound addresses
	Hostnames  []string
	TTL        time.Duration // 1–15 min
}

// Limits for print_web.ttl (§7.4).
const (
	MinPrintWebTTL = time.Minute
	MaxPrintWebTTL = 15 * time.Minute
)

// maxKeep bounds backup.keep, to catch nonsense values.
const maxKeep = 1_000_000

// maxFileSize bounds what is read of a config file (SEC-8): the path can
// come from $PASSH_CONFIG or --config, and a real one is a few hundred
// bytes.
const maxFileSize = 1 << 20

// Default returns the default settings. Vault is empty: it has no default
// in a config file (DefaultVaultPath is what `passh init` proposes).
func Default() *Config {
	return &Config{
		Session:   Session{IdleTTL: 5 * time.Minute, StopAgent: true},
		Agent:     Agent{IdleTTL: 15 * time.Minute, MaxTTL: 2 * time.Hour},
		Backup:    Backup{Keep: 10},
		Rollback:  Rollback{Warn: true},
		Clipboard: Clipboard{ClearAfter: 30 * time.Second, OSC52: true, Command: []string{}},
		PrintWeb: PrintWeb{
			Port:       8443,
			Interfaces: []string{"wg0", "eth0"},
			AllowFrom:  []netip.Prefix{},
			Hostnames:  []string{},
			TTL:        5 * time.Minute,
		},
	}
}

// ErrNoConfig is matched (errors.Is) by the error for a missing config file.
var ErrNoConfig = i18n.NewError("no config file")

// NotFoundError reports a missing config file and how to create one.
type NotFoundError struct {
	Location
}

func (e *NotFoundError) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language.
func (e *NotFoundError) Localize(p i18n.Printer) string {
	if e.Source == SourceFlag || e.Source == SourceEnv {
		return p.T("no config file at %s (from %s): run `passh init` to create one, "+
			"or create it with the line vault = \"/path/to/vault.passh\", or pass --vault <file>", e.Path, e.Source.String())
	}
	return p.T("no config file at %s: run `passh init` to create one, "+
		"or create it with the line vault = \"/path/to/vault.passh\", or pass --vault <file>", e.Path)
}

// Is makes errors.Is(err, ErrNoConfig) true.
func (e *NotFoundError) Is(target error) bool { return target == ErrNoConfig }

// Error reports every problem found in a config file.
type Error struct {
	Path string // the file, or "" for Parse
	// Problems has one line each, e.g. `unknown key "session.idel_ttl"`,
	// to show in the user's language (Localize; String is English).
	Problems []i18n.Message
}

func (e *Error) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language, one
// problem per line.
func (e *Error) Localize(p i18n.Printer) string {
	if len(e.Problems) == 1 {
		if e.Path == "" {
			return p.T("config: %v", e.Problems[0])
		}
		return p.T("config %s: %v", e.Path, e.Problems[0])
	}
	lines := make([]string, len(e.Problems))
	for i, m := range e.Problems {
		lines[i] = m.Localize(p)
	}
	prefix := p.T("config:")
	if e.Path != "" {
		prefix = p.T("config %s:", e.Path)
	}
	return prefix + "\n  " + strings.Join(lines, "\n  ")
}

// Resolve finds and loads the config for one command. configFlag and
// vaultFlag are the values of --config and --vault, "" when not given.
//
// With vaultFlag, a missing config file is not an error and defaults are
// used, unless the file was named with --config: a file asked for
// explicitly must exist. A config file that exists is always read and must
// be valid; vaultFlag then overrides its vault.
func Resolve(configFlag, vaultFlag string) (*Config, error) {
	loc, err := Locate(configFlag)
	if err != nil {
		if configFlag != "" || vaultFlag == "" {
			return nil, err
		}
		// No usable default location (e.g. $HOME unset), but --vault is
		// enough to work without a config file.
		return withVault(Default(), vaultFlag)
	}
	cfg, err := load(loc.Path, vaultFlag == "")
	switch {
	case err == nil:
		cfg.Loaded = true
	case errors.Is(err, ErrNoConfig) && vaultFlag != "" && loc.Source != SourceFlag:
		cfg = Default()
	default:
		var nf *NotFoundError
		if errors.As(err, &nf) {
			nf.Location = loc
		}
		return nil, err
	}
	cfg.Location = loc
	if vaultFlag == "" {
		return cfg, nil
	}
	return withVault(cfg, vaultFlag)
}

// withVault applies the --vault override.
func withVault(cfg *Config, vaultFlag string) (*Config, error) {
	v, err := ExpandPath(vaultFlag)
	if err != nil {
		return nil, i18n.Errorf("%s: %w", "--vault", err)
	}
	cfg.Vault = v
	cfg.VaultFromFlag = true
	return cfg, nil
}

// Load reads and validates the config file at path. A missing file gives a
// *NotFoundError (errors.Is(err, ErrNoConfig)); problems in the file give
// an *Error.
func Load(path string) (*Config, error) {
	cfg, err := load(path, true)
	if err != nil {
		return nil, err
	}
	cfg.Loaded = true
	cfg.Location = Location{Path: path, Source: SourceFile}
	return cfg, nil
}

func load(path string, requireVault bool) (*Config, error) {
	data, err := readFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &NotFoundError{Location{Path: path, Source: SourceFile}}
		}
		return nil, err
	}
	cfg, err := parse(data, requireVault)
	if err != nil {
		var ce *Error
		if errors.As(err, &ce) {
			ce.Path = path
		}
		return nil, err
	}
	return cfg, nil
}

// readFile reads a config file of at most maxFileSize bytes. A missing
// file gives an error matching fs.ErrNotExist; a larger one an *Error.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, i18n.Errorf("config: %w", err)
	}
	defer f.Close() // read-only
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, i18n.Errorf("config: %w", err)
	}
	if len(data) > maxFileSize {
		return nil, &Error{Path: path, Problems: []i18n.Message{i18n.Msg("the file is larger than 1 MiB")}}
	}
	return data, nil
}

// Parse decodes and validates config file contents. vault is required.
func Parse(data []byte) (*Config, error) {
	return parse(data, true)
}

// raw mirrors the file. Pointers tell "absent" (default) from "set".
type raw struct {
	Vault    *string `toml:"vault"`
	Language *string `toml:"language"`
	Session  *struct {
		IdleTTL   *string `toml:"idle_ttl"`
		StopAgent *bool   `toml:"stop_agent"`
	} `toml:"session"`
	Agent *struct {
		IdleTTL *string `toml:"idle_ttl"`
		MaxTTL  *string `toml:"max_ttl"`
	} `toml:"agent"`
	Backup *struct {
		Keep *int64 `toml:"keep"`
	} `toml:"backup"`
	Rollback *struct {
		Warn *bool `toml:"warn"`
	} `toml:"rollback"`
	Clipboard *struct {
		ClearAfter *string   `toml:"clear_after"`
		OSC52      *bool     `toml:"osc52"`
		Command    *[]string `toml:"command"`
	} `toml:"clipboard"`
	PrintWeb *struct {
		Enabled    *bool     `toml:"enabled"`
		Port       *int64    `toml:"port"`
		Interfaces *[]string `toml:"interfaces"`
		AllowFrom  *[]string `toml:"allow_from"`
		Hostnames  *[]string `toml:"hostnames"`
		TTL        *string   `toml:"ttl"`
	} `toml:"print_web"`
}

func parse(data []byte, requireVault bool) (*Config, error) {
	var r raw
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&r)
	if err != nil {
		// The TOML library's message, in English (§3.3).
		return nil, &Error{Problems: []i18n.Message{i18n.Raw(strings.TrimPrefix(err.Error(), "toml: "))}}
	}
	v := &validator{}
	if und := md.Undecoded(); len(und) > 0 {
		var reported []string
		for _, k := range und {
			ks := k.String()
			if isUnder(ks, reported) {
				continue // a key inside an unknown table: the table is reported
			}
			reported = append(reported, ks)
			v.problemf("unknown key %q", ks)
		}
	}

	cfg := Default()
	switch {
	case r.Vault != nil:
		cfg.Vault = v.vault(*r.Vault)
	case requireVault:
		v.problemf("vault is required, e.g. vault = %q", "~/.local/share/passh/vault.passh")
	}
	if r.Language != nil {
		l, err := i18n.Parse(*r.Language)
		if err != nil {
			v.problemf("%s: %v", "language", err) // i18n.Parse's message stays English
		}
		cfg.Language = l
	}
	if s := r.Session; s != nil {
		v.duration("session.idle_ttl", s.IdleTTL, &cfg.Session.IdleTTL)
		setIf(&cfg.Session.StopAgent, s.StopAgent)
	}
	if a := r.Agent; a != nil {
		v.duration("agent.idle_ttl", a.IdleTTL, &cfg.Agent.IdleTTL)
		v.duration("agent.max_ttl", a.MaxTTL, &cfg.Agent.MaxTTL)
	}
	if b := r.Backup; b != nil && b.Keep != nil {
		switch {
		case *b.Keep < 0:
			v.problemf("backup.keep: %d must be 0 or more", *b.Keep)
		case *b.Keep > maxKeep:
			v.problemf("backup.keep: %d is more than %d", *b.Keep, maxKeep)
		default:
			cfg.Backup.Keep = int(*b.Keep)
		}
	}
	if rb := r.Rollback; rb != nil {
		setIf(&cfg.Rollback.Warn, rb.Warn)
	}
	if c := r.Clipboard; c != nil {
		v.duration("clipboard.clear_after", c.ClearAfter, &cfg.Clipboard.ClearAfter)
		setIf(&cfg.Clipboard.OSC52, c.OSC52)
		if c.Command != nil {
			cmd := *c.Command
			if len(cmd) > 0 && strings.TrimSpace(cmd[0]) == "" {
				v.problemf("clipboard.command: the program name (first element) is empty")
			}
			cfg.Clipboard.Command = cmd
		}
	}
	if p := r.PrintWeb; p != nil {
		setIf(&cfg.PrintWeb.Enabled, p.Enabled)
		if p.Port != nil {
			if *p.Port < 1 || *p.Port > 65535 {
				v.problemf("print_web.port: %d is not between 1 and 65535", *p.Port)
			} else {
				cfg.PrintWeb.Port = int(*p.Port)
			}
		}
		if p.Interfaces != nil {
			cfg.PrintWeb.Interfaces = v.names("print_web.interfaces", *p.Interfaces)
		}
		if p.Hostnames != nil {
			cfg.PrintWeb.Hostnames = v.names("print_web.hostnames", *p.Hostnames)
		}
		if p.AllowFrom != nil {
			cfg.PrintWeb.AllowFrom = v.prefixes("print_web.allow_from", *p.AllowFrom)
		}
		if v.duration("print_web.ttl", p.TTL, &cfg.PrintWeb.TTL) &&
			(cfg.PrintWeb.TTL < MinPrintWebTTL || cfg.PrintWeb.TTL > MaxPrintWebTTL) {
			v.problemf("print_web.ttl: %q is not between 1m and 15m", *p.TTL)
		}
	}
	if len(v.problems) > 0 {
		return nil, &Error{Problems: v.problems}
	}
	return cfg, nil
}

func isUnder(key string, parents []string) bool {
	for _, p := range parents {
		if strings.HasPrefix(key, p+".") {
			return true
		}
	}
	return false
}

func setIf[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

type validator struct {
	problems []i18n.Message
}

// problemf records a problem.
//
// i18n:wrapper
func (v *validator) problemf(format string, args ...any) {
	v.problems = append(v.problems, i18n.Msg(format, args...))
}

// duration parses *s into dst if s is set. It reports whether a valid
// value was set.
func (v *validator) duration(key string, s *string, dst *time.Duration) bool {
	if s == nil {
		return false
	}
	d, err := time.ParseDuration(*s)
	switch {
	case err != nil:
		v.problemf("%s: %q is not a duration such as \"30s\", \"5m\" or \"2h\"", key, *s)
		return false
	case d <= 0:
		v.problemf("%s: %q must be more than zero", key, *s)
		return false
	}
	*dst = d
	return true
}

func (v *validator) vault(s string) string {
	if s == "" {
		v.problemf("vault is empty")
		return ""
	}
	if !strings.HasPrefix(s, "~/") && !filepath.IsAbs(s) {
		v.problemf("vault: %q must be an absolute path or start with ~/", s)
		return ""
	}
	p, err := ExpandHome(s)
	if err != nil {
		v.problemf("%s: %v", "vault", err)
		return ""
	}
	return filepath.Clean(p)
}

func (v *validator) names(key string, list []string) []string {
	for _, n := range list {
		if n == "" || strings.ContainsFunc(n, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			v.problemf("%s: %q is not a valid name", key, n)
		}
	}
	return list
}

func (v *validator) prefixes(key string, list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			v.problemf("%s: %q is not a CIDR such as \"192.168.1.0/24\" or \"fd00::/8\"", key, s)
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}
