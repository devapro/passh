package importpass

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"passh/internal/exec"
)

// testUID is the user id of the throwaway key in the test GnuPG home.
const testUID = "passh test <passh-test@example.invalid>"

// testBase is a short folder under /tmp holding everything the tests
// write: $HOME, the XDG folders, $TMPDIR and $GNUPGHOME. Short, because
// without /run/user gpg-agent puts its sockets in $GNUPGHOME, and socket
// paths are limited to about 100 bytes.
var testBase string

// haveGPG tells whether gpg is installed and the test key was made.
var haveGPG bool

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	base, err := os.MkdirTemp("/tmp", "phimp")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	testBase = base
	defer os.RemoveAll(base)

	// Never touch the real user's files (IMPLEMENTATION.md).
	env := map[string]string{
		"HOME":               filepath.Join(base, "home"),
		"XDG_CONFIG_HOME":    filepath.Join(base, "home", ".config"),
		"XDG_DATA_HOME":      filepath.Join(base, "home", ".local", "share"),
		"XDG_STATE_HOME":     filepath.Join(base, "home", ".local", "state"),
		"XDG_RUNTIME_DIR":    filepath.Join(base, "run"),
		"TMPDIR":             filepath.Join(base, "tmp"),
		"PASSH_CONFIG":       filepath.Join(base, "home", ".config", "passh", "config.toml"),
		"PASSWORD_STORE_DIR": filepath.Join(base, "home", ".password-store"),
		"GNUPGHOME":          filepath.Join(base, "g"),
	}
	for k, v := range env {
		if k != "PASSH_CONFIG" {
			if err := os.MkdirAll(v, 0o700); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
		os.Setenv(k, v)
	}
	os.Unsetenv("GPG_TTY")
	os.Unsetenv("GPG_AGENT_INFO")

	if _, err := exec.LookPath("gpg"); err == nil {
		defer stopAgent()
		if err := gpgRun(nil, "--batch", "--passphrase", "", "--quick-gen-key", testUID, "future-default", "default", "never"); err != nil {
			fmt.Fprintln(os.Stderr, "making the test key:", err)
			return 1
		}
		haveGPG = true
	}
	return m.Run()
}

// stopAgent stops the gpg-agent of the test GnuPG home and removes its
// socket folder (which gpg puts under /run/user/<uid>/gnupg when that
// exists).
func stopAgent() {
	ctx := context.Background()
	_ = exec.Run(ctx, exec.Command{Name: "gpgconf", Args: []string{"--kill", "all"}})
	_ = exec.Run(ctx, exec.Command{Name: "gpgconf", Args: []string{"--remove-socketdir"}})
}

func gpgRun(stdin []byte, args ...string) error {
	var stderr bytes.Buffer
	err := exec.Run(context.Background(), exec.Command{
		Name: "gpg", Args: args, Stdin: bytes.NewReader(stdin), Stderr: &stderr,
	})
	if err != nil {
		return fmt.Errorf("%w: %s", err, stderr.Bytes())
	}
	return nil
}

func needGPG(t *testing.T) {
	t.Helper()
	if !haveGPG {
		t.Skip("gpg is not installed")
	}
}

// encrypt returns plaintext encrypted to the test key, as `pass insert`
// would store it.
func encrypt(t *testing.T, plaintext string) []byte {
	t.Helper()
	var stderr bytes.Buffer
	out, err := exec.Output(t.Context(), exec.Command{
		Name: "gpg",
		Args: []string{
			"--batch", "--yes", "--trust-model", "always", "--compress-algo", "none",
			"--encrypt", "--recipient", testUID,
		},
		Stdin:  bytes.NewReader([]byte(plaintext)),
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("gpg --encrypt: %v: %s", err, stderr.Bytes())
	}
	return out
}
