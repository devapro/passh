package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// vaultPlaceholder marks where Template puts the vault path.
const vaultPlaceholder = "@VAULT@"

// template is the config file `passh init` writes: the §3.3 example with
// every default spelled out and commented.
const template = `vault = @VAULT@

[session]
idle_ttl   = "5m"       # TUI locks after this much inactivity
stop_agent = true       # a TUI lock also stops the agent (§5.3)

[agent]                 # started only by ` + "`passh unlock`" + ` (§5.3)
idle_ttl = "15m"        # exits after this long without a request
max_ttl  = "2h"         # and after this long in any case

[backup]
keep = 10               # previous versions kept in ~/.local/state/passh/backups/ (0 = off)

[rollback]
warn = true             # warn when a vault is older than one seen before (§4.10)

[clipboard]
clear_after = "30s"
osc52       = true      # copy through the terminal (works over SSH)
command     = []        # optional local tool instead, e.g. ["pbcopy"] or ["wl-copy"]

[print_web]             # §7.4; off unless enabled
enabled    = false
port       = 8443
interfaces = ["wg0", "eth0"]
allow_from = []         # extra CIDR limit; default = subnets of the bound addresses
hostnames  = []         # optional names for the certificate, e.g. ["pi.local"]
ttl        = "5m"       # 1–15 min
`

// Template returns the initial config file text for vault, which must be an
// absolute path or start with "~/". A path under $HOME is written as "~/…".
func Template(vault string) (string, error) {
	if !strings.HasPrefix(vault, "~/") && !filepath.IsAbs(vault) {
		return "", fmt.Errorf("vault %q must be an absolute path or start with ~/", vault)
	}
	if !utf8.ValidString(vault) {
		return "", fmt.Errorf("vault path %q is not valid UTF-8, which TOML can't hold", vault)
	}
	if filepath.IsAbs(vault) {
		vault = ContractHome(filepath.Clean(vault))
	}
	return strings.Replace(template, vaultPlaceholder, tomlString(vault), 1), nil
}

// WriteInitial creates the config file at path for `passh init`: the
// Template text with vault, mode 0600, in a parent folder created with mode
// 0700 if missing. It never overwrites: if path exists (even as a dangling
// symlink), it returns an error matching fs.ErrExist and changes nothing.
func WriteInitial(path, vault string) error {
	text, err := Template(vault)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating the config folder: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating the config file: %w", err)
	}
	_, werr := f.WriteString(text)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(path) // ours (O_EXCL created it) and incomplete; the error above is the one to report
		return fmt.Errorf("writing the config file %s: %w", path, err)
	}
	return nil
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
