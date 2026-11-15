package tui

import (
	"context"
	"os"
	"testing"
	"time"

	"passh/internal/agent"
	"passh/internal/keys"
	"passh/internal/model"
	"passh/internal/vaultfile"
)

// keyBlockOf returns the key block of the vault file at path.
func keyBlockOf(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return f.KeyBlock
}

// A real agent unlocked for one key block: after the vault's key block
// changes (a passwd done elsewhere), the TUI must not take the agent's key,
// although that key still opens the data; it asks for the passphrase,
// which checks the new key block.
func TestAgentRefusedForChangedKeyBlock(t *testing.T) {
	h := newHarness(t, sampleEntries(), withPassphrase())
	ctx := context.Background()
	if _, err := agent.Start(ctx, h.path, h.key, agent.Options{
		KeyBlock: keyBlockOf(t, h.path), IdleTTL: time.Minute, MaxTTL: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	c, err := agent.NewClient(h.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.Stop(context.Background()) })
	realAgent := func(h *harness, d *deps) {
		d.keySource, d.agent = nil, NewAgent(c)
		h.cfg.Session.StopAgent = false // keep the agent between the two runs
	}

	// The key block the agent was unlocked for: the TUI takes its key.
	h.start(realAgent)
	h.mustUnlocked()
	h.press("q")

	// passwd elsewhere: same vault key, new passphrase, new key block.
	data, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	const newPass = "a different passphrase entirely"
	changed, err := vaultfile.Encode(lowKeyBlock(t, h.key, newPass), f.DataBlock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path, changed, 0o600); err != nil {
		t.Fatal(err)
	}

	h.start(realAgent)
	if h.m.screen != screenLock {
		t.Fatalf("the TUI took the agent's key for another key block:\n%s", h.plain())
	}
	h.contains("Passphrase", "unlocked for another key block")
	h.lacks("An agent is running")
	// Enter on an empty passphrase doesn't fall back to the agent either.
	h.press("enter")
	if h.m.screen != screenLock {
		t.Fatal("Enter used the agent")
	}
	h.typeText(newPass)
	h.press("enter")
	h.mustUnlocked()
	if st, err := c.Status(ctx); err != nil || st.PID == 0 {
		t.Fatalf("the agent should still run: %v", err)
	}
}

// A data block replaced by one encrypted to another key, under the same key
// block: with the key from a checking source (the agent), that is damage,
// not a stale key. Reload and reopen say "data is damaged" and list the
// backups; the lock screen doesn't ask for a passphrase that can't help.
func TestDamagedDataWithAgentKey(t *testing.T) {
	h := newHarness(t, sampleEntries(), withPassphrase())
	ctx := context.Background()
	if _, err := agent.Start(ctx, h.path, h.key, agent.Options{
		KeyBlock: keyBlockOf(t, h.path), IdleTTL: time.Minute, MaxTTL: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	c, err := agent.NewClient(h.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.Stop(context.Background()) })
	realAgent := func(h *harness, d *deps) {
		d.keySource, d.agent = nil, NewAgent(c)
		h.cfg.Session.StopAgent = false
	}
	h.start(realAgent)
	h.mustUnlocked()

	// Replace the data block, keep the key block.
	data, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	other, err := keys.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := model.NewData().Encode()
	if err != nil {
		t.Fatal(err)
	}
	db, err := keys.EncryptData(other, plain)
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := vaultfile.Encode(f.KeyBlock, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path, replaced, 0o600); err != nil {
		t.Fatal(err)
	}

	// Reload.
	h.send(pollMsg{})
	h.contains("Vault changed on disk")
	h.press("R")
	h.contains("Reload failed", "data is damaged", "isn't encrypted to this vault's key", "no automatic backups")
	h.mustUnlocked()

	// Reopen.
	h.press("q")
	h.start(realAgent)
	if h.m.screen != screenLock {
		t.Fatal("opened a damaged vault")
	}
	h.contains("data is damaged; restore a backup", "isn't encrypted to this vault's key", "no automatic backups", "Enter try again")
	h.lacks("Passphrase", "enter the passphrase", "doesn't open this vault")
	// Enter tries again (still damaged); q quits.
	h.press("enter")
	h.contains("data is damaged; restore a backup")
	h.press("q")
	if !h.quit {
		t.Fatal("q didn't quit")
	}
}
