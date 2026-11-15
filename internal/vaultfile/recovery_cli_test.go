package vaultfile

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"

	"passh/internal/keys"
)

// The manual recovery of spec §8 and acceptance criterion 9: without passh,
// the stock age CLI turns a vault into its JSON, with the paper key and with
// the passphrase. The block extraction runs exactly the commands of §8.
//
// Tests start processes with os/exec directly: pty.Start needs an *exec.Cmd,
// and internal/exec (S8) is for passh's own code.

const extractCommands = `tr -d '\r' < vault.passh | awk '/BEGIN AGE ENCRYPTED FILE/{n++} n==1{print} n==1 && /END AGE ENCRYPTED FILE/{exit}' > key.age
tr -d '\r' < vault.passh | awk '/BEGIN AGE ENCRYPTED FILE/{n++} n==2{print} n==2 && /END AGE ENCRYPTED FILE/{exit}' > data.age
`

func ageCLI(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../.tools/bin/age")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("stock age CLI not found: %v", err)
	}
	return p
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = subprocessEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(name), strings.Join(args, " "), err, out)
	}
}

// extract writes vault to a fresh folder, runs the §8 extraction there and
// checks that it yields the two armored blocks.
func extract(t *testing.T, vault []byte, fx *fixture) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vault.passh"), vault, 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "/bin/sh", "-c", extractCommands)
	for name, block := range map[string][]byte{"key.age": fx.keyBlock, "data.age": fx.dataBlock} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != armored(block) {
			t.Fatalf("%s isn't the armored block:\n%s", name, got)
		}
	}
	return dir
}

func checkJSON(t *testing.T, dir string, fx *fixture) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fx.plain) {
		t.Fatalf("vault.json differs:\n%s", got)
	}
}

func TestManualRecoveryPaperKey(t *testing.T) {
	age := ageCLI(t)
	fx := newFixture(t)
	for name, vault := range map[string][]byte{
		"canonical": fx.file,
		"CRLF copy": bytes.ReplaceAll(fx.file, []byte("\n"), []byte("\r\n")),
		// §8's awk starts at the first BEGIN line and stops at each END
		// line, so text around the vault doesn't reach the blocks.
		"text before, CRLF":    append([]byte("Subject: vault\r\n\r\n"), bytes.ReplaceAll(fx.file, []byte("\n"), []byte("\r\n"))...),
		"text after the vault": append(bytes.Clone(fx.file), "\n-- \nsent from my phone\n-----BEGIN AGE ENCRYPTED FILE-----\nnot base64\n"...),
	} {
		t.Run(name, func(t *testing.T) {
			dir := extract(t, vault, fx)
			// The paper key, typed as one line without spaces (§8).
			paper := strings.Join(strings.Fields(keys.FormatRecoveryKey(fx.id)), "")
			if err := os.WriteFile(filepath.Join(dir, "key.txt"), []byte(paper+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			run(t, dir, age, "-d", "-i", "key.txt", "-o", "vault.json", "data.age")
			checkJSON(t, dir, fx)
		})
	}
}

// TestManualRecoveryPassphrase drives `age -d key.age` through a terminal,
// where age reads the passphrase, at the real work factor 2^18: the key
// block comes from keys.WrapKey unchanged.
func TestManualRecoveryPassphrase(t *testing.T) {
	if testing.Short() {
		t.Skip("scrypt at 2^18 is slow")
	}
	age := ageCLI(t)
	id, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := keys.WrapKey(id, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if hdr := string(kb[:bytes.Index(kb, []byte("\n---"))]); !strings.Contains(hdr, " 18\n") {
		t.Fatalf("key block isn't at work factor 18:\n%s", hdr)
	}
	fx := fixtureFor(t, id, kb)
	dir := extract(t, fx.file, fx)

	// Step 3 of §8: age asks for the passphrase on the terminal.
	out, err := decryptWithPassphrase(t, dir, age, testPass)
	if err != nil {
		t.Fatalf("age -d key.age: %v\nterminal output:\n%s", err, out)
	}
	key, err := os.ReadFile(filepath.Join(dir, "key.txt"))
	if err != nil {
		t.Fatalf("%v\nterminal output:\n%s", err, out)
	}
	if string(key) != id.String()+"\n" {
		t.Fatal("key.txt isn't the vault key")
	}
	// Step 4 of §8.
	run(t, dir, age, "-d", "-i", "key.txt", "-o", "vault.json", "data.age")
	checkJSON(t, dir, fx)
}

// TestManualRecoveryWrongPassphrase: the same terminal path refuses a wrong
// passphrase and writes no key file (low work factor).
func TestManualRecoveryWrongPassphrase(t *testing.T) {
	age := ageCLI(t)
	fx := newFixture(t)
	dir := extract(t, fx.file, fx)
	out, err := decryptWithPassphrase(t, dir, age, "not the passphrase")
	if err == nil || !strings.Contains(out, "incorrect passphrase") {
		t.Fatalf("wrong passphrase accepted: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.txt")); !os.IsNotExist(err) {
		t.Fatalf("key.txt written: %v", err)
	}
}

// decryptWithPassphrase runs `age -d -o key.txt key.age` with a pseudo
// terminal as its controlling terminal, waits for the passphrase prompt and
// types the passphrase. It returns what age wrote to the terminal and age's
// exit error.
func decryptWithPassphrase(t *testing.T, dir, age, pass string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, age, "-d", "-o", "key.txt", "key.age")
	cmd.Dir = dir
	cmd.Env = subprocessEnv()
	tty, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()

	var mu sync.Mutex
	var screen bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, err := tty.Read(buf)
			mu.Lock()
			screen.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	shown := func() string {
		mu.Lock()
		defer mu.Unlock()
		return screen.String()
	}

	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(strings.ToLower(shown()), "passphrase") {
		if time.Now().After(deadline) {
			t.Fatalf("no passphrase prompt; terminal shows %q", shown())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := io.WriteString(tty, pass+"\r"); err != nil {
		t.Fatal(err)
	}
	werr := cmd.Wait()
	tty.Close()
	<-done
	return shown(), werr
}
