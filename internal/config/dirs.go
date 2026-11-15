package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Source tells where the config file's location came from.
type Source int

const (
	// SourceFile: a path passed directly to Load.
	SourceFile Source = iota
	// SourceFlag: --config <file>.
	SourceFlag
	// SourceEnv: $PASSH_CONFIG.
	SourceEnv
	// SourceDefault: $XDG_CONFIG_HOME/passh/config.toml
	// (default ~/.config/passh/config.toml).
	SourceDefault
)

func (s Source) String() string {
	switch s {
	case SourceFlag:
		return "--config"
	case SourceEnv:
		return "$PASSH_CONFIG"
	case SourceDefault:
		return "default location"
	default:
		return "file"
	}
}

// Location is a config file path and where it came from.
type Location struct {
	Path   string
	Source Source
}

func (l Location) String() string {
	return l.Path + " (" + l.Source.String() + ")"
}

// EnvConfig is the environment variable that names the config file.
const EnvConfig = "PASSH_CONFIG"

// Locate returns the config file location, first match wins (§3.3):
// configFlag (the --config value), then $PASSH_CONFIG, then
// $XDG_CONFIG_HOME/passh/config.toml (default ~/.config/passh/config.toml).
// The file doesn't have to exist. A leading ~/ is expanded and a relative
// path is made absolute.
func Locate(configFlag string) (Location, error) {
	if configFlag != "" {
		p, err := ExpandPath(configFlag)
		if err != nil {
			return Location{}, fmt.Errorf("--config: %w", err)
		}
		return Location{Path: p, Source: SourceFlag}, nil
	}
	if env := os.Getenv(EnvConfig); env != "" {
		p, err := ExpandPath(env)
		if err != nil {
			return Location{}, fmt.Errorf("$%s: %w", EnvConfig, err)
		}
		return Location{Path: p, Source: SourceEnv}, nil
	}
	p, err := DefaultConfigPath()
	if err != nil {
		return Location{}, err
	}
	return Location{Path: p, Source: SourceDefault}, nil
}

// HomeDir returns $HOME.
func HomeDir() (string, error) {
	home := os.Getenv("HOME")
	if home == "" {
		return "", errors.New("$HOME is not set")
	}
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("$HOME (%q) is not an absolute path", home)
	}
	return filepath.Clean(home), nil
}

// ExpandHome replaces a leading "~/" (or a lone "~") with $HOME. Other
// paths, including "~user/…", are returned unchanged.
func ExpandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, p[1:]), nil
}

// ContractHome is the reverse of ExpandHome: a path under $HOME is written
// as "~/…". Other paths are returned unchanged.
func ContractHome(p string) string {
	home, err := HomeDir()
	if err != nil || home == "/" {
		return p
	}
	if rest, ok := strings.CutPrefix(filepath.Clean(p), home+"/"); ok && rest != "" {
		return "~/" + rest
	}
	return p
}

// ExpandPath turns a path given on the command line or in the environment
// into an absolute, cleaned path: "~/" is expanded and a relative path is
// resolved against the current directory.
func ExpandPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	p, err := ExpandHome(p)
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

// xdgDir returns $env if it is set to an absolute path (the XDG spec says
// to ignore relative ones), otherwise $HOME/fallback.
func xdgDir(env, fallback string) (string, error) {
	if d := os.Getenv(env); d != "" && filepath.IsAbs(d) {
		return filepath.Clean(d), nil
	}
	home, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, fallback), nil
}

// DefaultConfigPath is $XDG_CONFIG_HOME/passh/config.toml
// (default ~/.config/passh/config.toml).
func DefaultConfigPath() (string, error) {
	d, err := xdgDir("XDG_CONFIG_HOME", ".config")
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "passh", "config.toml"), nil
}

// DefaultVaultPath is $XDG_DATA_HOME/passh/vault.passh
// (default ~/.local/share/passh/vault.passh), the vault `passh init`
// creates when none is given.
func DefaultVaultPath() (string, error) {
	d, err := xdgDir("XDG_DATA_HOME", ".local/share")
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "passh", "vault.passh"), nil
}

// StateDir is $XDG_STATE_HOME/passh (default ~/.local/state/passh): automatic
// backups, lock files, rollback records, the agent's socket folder and the
// print page certificate (§3.2). It is not created here; EnsureStateDir
// creates it.
func StateDir() (string, error) {
	d, err := xdgDir("XDG_STATE_HOME", ".local/state")
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "passh"), nil
}
