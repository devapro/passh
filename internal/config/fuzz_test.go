package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParse checks that Parse never panics, that it fails only with an
// *Error listing at least one problem, and that what it accepts keeps the
// rules of §3.3 and §7.4: an absolute, clean vault path, positive
// durations, print_web.ttl within 1–15 min, a port in range, backup.keep
// within bounds, a clipboard command with a program name and masked
// allow_from prefixes. The seed corpus runs as a normal test (TEST-12).
func FuzzParse(f *testing.F) {
	f.Setenv("HOME", f.TempDir()) // for "~/" paths; nothing is written there
	tmpl, err := Template("~/.local/share/passh/vault.passh")
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		tmpl,
		`vault = "/srv/v.passh"`,
		"vault = \"/data/my vault.passh\"\n[session]\nidle_ttl = \"90s\"\nstop_agent = false\n[agent]\nidle_ttl = \"1h30m\"\nmax_ttl = \"8h\"\n" +
			"[backup]\nkeep = 0\n[clipboard]\nclear_after = \"45s\"\ncommand = [\"xclip\", \"-selection\", \"clipboard\"]\n" +
			"[print_web]\nenabled = true\nport = 9443\ninterfaces = [\"wlan0\"]\nallow_from = [\"192.168.1.7/24\", \"fd00::/8\"]\nhostnames = [\"pi.local\"]\nttl = \"15m\"\n",
		"vault = \"~/a/../b//v.passh\"",
		"vault = \"rel\"\ntypo = 1\n[backup]\nkeep = -2\n[print_web]\nport = 0\n",
		"vault = \"/v\"\n[sesion]\nidle_ttl = \"1m\"\n[print_web]\ntls = true\n",
		"vault = \"/v\"\n[print_web]\nttl = \"14m59s\"\nallow_from = [\"10.0.0.0/33\"]",
		"vault = \"/v\"\n[clipboard]\ncommand = [\" \"]",
		"[session\n", "", "vault = 3", "\x00", "vault = '''\n/v'''",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(data)
		if err != nil {
			var ce *Error
			if cfg != nil || !errors.As(err, &ce) || len(ce.Problems) == 0 {
				t.Fatalf("Parse(%q) = %v, %v; want nil and an *Error with problems", data, cfg != nil, err)
			}
			for _, p := range ce.Problems {
				if p.String() == "" {
					t.Fatalf("Parse(%q): an empty problem in %q", data, ce.Problems)
				}
			}
			return
		}
		if !filepath.IsAbs(cfg.Vault) || filepath.Clean(cfg.Vault) != cfg.Vault {
			t.Errorf("Parse(%q): vault %q is not absolute and clean", data, cfg.Vault)
		}
		for name, d := range map[string]int64{
			"session.idle_ttl": int64(cfg.Session.IdleTTL), "agent.idle_ttl": int64(cfg.Agent.IdleTTL),
			"agent.max_ttl": int64(cfg.Agent.MaxTTL), "clipboard.clear_after": int64(cfg.Clipboard.ClearAfter),
		} {
			if d <= 0 {
				t.Errorf("Parse(%q): %s = %d", data, name, d)
			}
		}
		if ttl := cfg.PrintWeb.TTL; ttl < MinPrintWebTTL || ttl > MaxPrintWebTTL {
			t.Errorf("Parse(%q): print_web.ttl = %v", data, ttl)
		}
		if p := cfg.PrintWeb.Port; p < 1 || p > 65535 {
			t.Errorf("Parse(%q): print_web.port = %d", data, p)
		}
		if k := cfg.Backup.Keep; k < 0 || k > maxKeep {
			t.Errorf("Parse(%q): backup.keep = %d", data, k)
		}
		if c := cfg.Clipboard.Command; len(c) > 0 && strings.TrimSpace(c[0]) == "" {
			t.Errorf("Parse(%q): clipboard.command %q has no program", data, c)
		}
		for _, p := range cfg.PrintWeb.AllowFrom {
			if p != p.Masked() {
				t.Errorf("Parse(%q): allow_from %v is not masked", data, p)
			}
		}
	})
}
