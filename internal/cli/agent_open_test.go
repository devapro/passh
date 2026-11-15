package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/agent"
	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/keys"
	"github.com/devapro/passh/internal/model"
	"github.com/devapro/passh/internal/paths"
	"github.com/devapro/passh/internal/tty"
	"github.com/devapro/passh/internal/vaultfile"
)

// agent.Start re-executes this test binary as the agent, as passh runs its
// hidden subcommand (§5.3). init runs before the test flags are parsed.
func init() {
	if len(os.Args) > 1 && os.Args[1] == agent.ChildCommand {
		os.Exit(agent.ChildMain(os.Args[2:]))
	}
}

// isolateEnv points every location passh may touch at a temporary folder
// (IMPLEMENTATION.md).
func isolateEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, v := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
		"TMPDIR", "PASSWORD_STORE_DIR", "GNUPGHOME"} {
		d := filepath.Join(root, strings.ToLower(v))
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv(v, d)
	}
	t.Setenv("PASSH_CONFIG", filepath.Join(root, "config.toml"))
	// A race-enabled agent would otherwise sleep 1 s before exiting.
	t.Setenv("GORACE", strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"))
	return root
}

// testKeyBlock is a key block like keys.WrapKey's, with a cheap scrypt.
func testKeyBlock(t *testing.T, id *age.X25519Identity) []byte {
	t.Helper()
	r, err := age.NewScryptRecipient("cli test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(4)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(w, id.String())
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Through the agent and without a terminal, a data block the agent's key
// doesn't open (a damaged age header in block 2, or a block encrypted to
// another key) is "data is damaged; restore a backup" (§4.5, §13.2.10), not
// "the agent's key doesn't open …" followed by "vault is locked".
func TestAgentDataDamageIsNamed(t *testing.T) {
	root := isolateEnv(t)
	ctx := context.Background()
	key, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	kb := testKeyBlock(t, key)
	data := model.NewData()
	data.Revision, data.SavedAt = 1, time.Now()
	if _, err := data.Add(model.Entry{Path: paths.MustParse("work/github"), Password: "pw"}, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	plain, err := data.Encode()
	if err != nil {
		t.Fatal(err)
	}
	db, err := keys.EncryptData(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	file, err := vaultfile.Encode(kb, db)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "vault.passh")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := agent.Start(ctx, path, key, agent.Options{KeyBlock: kb, IdleTTL: time.Minute, MaxTTL: time.Minute}); err != nil {
		t.Fatalf("starting the agent: %v", err)
	}
	t.Cleanup(func() {
		if c, err := agent.NewClient(path); err == nil {
			_, _ = c.Stop(context.Background())
		}
	})

	stderr, err := os.Create(filepath.Join(root, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	a := &app{stdout: devNull(t), stderr: stderr, termTried: true, termErr: tty.ErrNoTerminal}
	cfg := config.Default()
	cfg.Vault = path
	v, err := a.openVault(ctx, cfg, path, openOpts{})
	if err != nil {
		t.Fatalf("open through the agent: %v", err)
	}
	v.Close()

	flipped := bytes.Clone(db)
	i := bytes.Index(flipped, []byte("\n-> X25519 "))
	body := i + 1 + bytes.IndexByte(flipped[i+1:], '\n') + 1
	if flipped[body] == 'A' {
		flipped[body] = 'B'
	} else {
		flipped[body] = 'A'
	}
	fresh, _ := age.GenerateX25519Identity()
	foreign, err := keys.EncryptData(fresh, plain)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string][]byte{"damaged header": flipped, "another key": foreign} {
		bad, err := vaultfile.Encode(kb, block)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = a.openVault(ctx, cfg, path, openOpts{})
		if err == nil || errors.Is(err, errLocked) || !errors.Is(err, keys.ErrDataDamaged) || errors.Is(err, keys.ErrKeyMismatch) ||
			!strings.Contains(err.Error(), "data is damaged; restore a backup") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if out, _ := os.ReadFile(stderr.Name()); bytes.Contains(out, []byte("doesn't open")) || bytes.Contains(out, []byte("passphrase")) {
		t.Errorf("stderr:\n%s", out)
	}
}
