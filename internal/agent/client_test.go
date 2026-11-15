package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/devapro/passh/internal/keys"
)

// fakeAgent listens on e's socket and answers every request with answer
// (nothing at all if answer is "", and never if hang is set).
func fakeAgent(t *testing.T, e *env, answer string, hang bool) {
	t.Helper()
	real, _ := realPath(e.vault)
	sock, err := ensureSocketPath(real)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = readMessage(c, maxMessage)
			if hang {
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			} else {
				_, _ = io.WriteString(c, answer)
			}
			c.Close()
		}
	}()
}

func TestClientRejectsBadAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		want         string // in the error; "" for ErrNoAgent
	}{
		{"other version", `{"v":2,"ok":true,"key":"x"}` + "\n", "protocol version 2"},
		{"version error", `{"v":1,"ok":false,"code":"version","error":"the agent speaks protocol version 1, not 0"}` + "\n", "protocol version 1, not 0"},
		{"invalid key", `{"v":1,"ok":true,"key":"AGE-SECRET-KEY-1INVALID"}` + "\n", "no valid vault key"},
		{"lower-case key", `{"v":1,"ok":true,"key":"age-secret-key-1qqqq"}` + "\n", "no valid vault key"},
		{"key not a string", `{"v":1,"ok":true,"key":42}` + "\n", "holds no vault key"},
		{"no key", `{"v":1,"ok":true}` + "\n", "holds no vault key"},
		{"malformed", "{nope\n", "malformed answer"},
		{"wrong types", `{"v":1,"ok":"yes"}` + "\n", "malformed answer"},
		{"no answer", "", "closed the connection without answering"},
		{"no newline", `{"v":1,"ok":true}`, "reading the answer"},
		{"too long", strings.Repeat("x", maxMessage+1), "reading the answer"},
		{"expired", `{"v":1,"ok":false,"code":"expired","error":"the agent has expired"}` + "\n", ""},
		{"refused", `{"v":1,"ok":false,"code":"bad_request","error":"unknown request"}` + "\n", "refused the request: unknown request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := isolate(t)
			fakeAgent(t, e, tc.answer, false)
			_, err := e.client(t).KeyFor(context.Background(), e.keyBlock)
			if tc.want == "" {
				if !errors.Is(err, ErrNoAgent) {
					t.Errorf("err = %v, want ErrNoAgent", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, ErrNoAgent) {
				t.Errorf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

func TestClientTimeout(t *testing.T) {
	e := isolate(t)
	fakeAgent(t, e, "", true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.client(t).Status(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want a deadline error", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %s", d)
	}

	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := e.client(t).Status(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestClientNoAgent(t *testing.T) {
	e := isolate(t)
	c := e.client(t)
	ctx := context.Background()
	if _, err := c.KeyFor(ctx, e.keyBlock); !errors.Is(err, ErrNoAgent) {
		t.Errorf("KeyFor: %v", err)
	}
	if _, err := c.Status(ctx); !errors.Is(err, ErrNoAgent) {
		t.Errorf("Status: %v", err)
	}
	if _, err := c.Stop(ctx); !errors.Is(err, ErrNoAgent) {
		t.Errorf("Stop: %v", err)
	}
	// An agent folder without a socket.
	real, _ := realPath(e.vault)
	if _, err := ensureSocketPath(real); err != nil {
		t.Fatal(err)
	}
	if _, err := c.KeyFor(ctx, e.keyBlock); !errors.Is(err, ErrNoAgent) {
		t.Errorf("KeyFor with an empty folder: %v", err)
	}
}

// TestClientRefusesBadFolder: a client doesn't talk to a socket in a folder
// that fails the checks, and says so instead of reporting "no agent".
func TestClientRefusesBadFolder(t *testing.T) {
	e := isolate(t)
	serve(t, e, time.Minute, time.Minute)
	dir := filepath.Dir(e.socket(t))
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	_, err := KeySource{Vault: e.vault}.VaultKey(context.Background(), nil)
	if err == nil || errors.Is(err, ErrNoAgent) || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("err = %v, want a refusal", err)
	}
}

func TestKeySource(t *testing.T) {
	e := isolate(t)
	var ks keys.KeySource = KeySource{Vault: e.vault}
	ctx := context.Background()
	if _, err := ks.VaultKey(ctx, nil); !errors.Is(err, ErrNoAgent) {
		t.Errorf("without an agent: %v, want ErrNoAgent", err)
	}
	serve(t, e, time.Minute, time.Minute)
	id, err := ks.VaultKey(ctx, e.keyBlock)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != e.key.String() {
		t.Error("another key")
	}
	// Another key block (passwd elsewhere, damage): no key, and the
	// caller falls back as without an agent.
	for _, kb := range [][]byte{nil, []byte("another key block"), append(e.keyBlock[:len(e.keyBlock):len(e.keyBlock)], 'x')} {
		if _, err := ks.VaultKey(ctx, kb); !errors.Is(err, ErrKeyBlockChanged) || !errors.Is(err, ErrNoAgent) {
			t.Errorf("key block %q: %v", kb, err)
		}
	}
	// The same vault through a symlink finds the same agent.
	link := filepath.Join(e.root, "link.passh")
	if err := os.Symlink(e.vault, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (KeySource{Vault: link}).VaultKey(ctx, e.keyBlock); err != nil {
		t.Errorf("through a symlink: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := ks.VaultKey(cancelled, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	if _, err := (KeySource{Vault: filepath.Join(e.root, "missing")}).VaultKey(ctx, nil); err == nil || errors.Is(err, ErrNoAgent) {
		t.Errorf("missing vault: %v", err)
	}
	if _, err := (KeySource{}).VaultKey(ctx, nil); err == nil {
		t.Error("empty vault path accepted")
	}
}

func TestSocketPath(t *testing.T) {
	e := isolate(t)
	sock := e.socket(t)
	if !regexp.MustCompile(`^agent-[0-9a-f]{16}\.sock$`).MatchString(filepath.Base(sock)) {
		t.Errorf("socket name %q", filepath.Base(sock))
	}
	if want := filepath.Join(e.root, "s", "passh", "agent"); filepath.Dir(sock) != want {
		t.Errorf("socket folder %s, want %s", filepath.Dir(sock), want)
	}
	// Relative paths, symlinks and ".." name the same vault.
	t.Chdir(e.root)
	link := filepath.Join(e.root, "h", "v")
	if err := os.Symlink(e.vault, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"vault.passh", link, filepath.Join(e.root, "h", "..", "vault.passh")} {
		if got, err := SocketPath(p); err != nil || got != sock {
			t.Errorf("SocketPath(%s) = %s, %v; want %s", p, got, err, sock)
		}
	}
	other := filepath.Join(e.root, "other.passh")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := SocketPath(other); got == sock {
		t.Error("two vaults share a socket")
	}
	if _, err := SocketPath(filepath.Join(e.root, "missing")); err == nil {
		t.Error("missing vault accepted")
	}
	// Nothing was created.
	if exists(filepath.Join(e.root, "s", "passh")) {
		t.Error("SocketPath created the state folder")
	}
}

func TestAlreadyRunningError(t *testing.T) {
	err := error(&AlreadyRunningError{Status: Status{IdleLeft: 14*time.Minute + 59*time.Second + 600*time.Millisecond, MaxLeft: 2 * time.Hour}})
	if !errors.Is(err, ErrAlreadyRunning) || errors.Is(err, ErrNoAgent) {
		t.Error("errors.Is")
	}
	want := "an agent is already running for this vault: it exits in 15m0s if unused, in 2h0m0s at the latest"
	if err.Error() != want {
		t.Errorf("message %q, want %q", err.Error(), want)
	}
	if roundDuration(-time.Second) != 0 {
		t.Error("negative duration")
	}
}

func TestReadMessage(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		err      error
	}{
		{"hello\n", "hello", nil},
		{"hello\nrest", "hello", nil},
		{"\n", "", nil},
		{"", "", io.EOF},
		{"partial", "", errNoLine},
		{"12345678", "", errTooLarge},
		{"1234567\n", "1234567", nil},
	} {
		// One byte at a time, to exercise the reassembly.
		got, err := readMessage(iotest.OneByteReader(strings.NewReader(tc.in)), 8)
		if !errors.Is(err, tc.err) || string(got) != tc.want {
			t.Errorf("readMessage(%q) = %q, %v; want %q, %v", tc.in, got, err, tc.want, tc.err)
		}
		if err == nil && cap(got) != 8 {
			t.Errorf("readMessage(%q): cap %d, want the whole buffer", tc.in, cap(got))
		}
	}
	boom := errors.New("boom")
	if _, err := readMessage(iotest.ErrReader(boom), 8); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
}

func TestEncodeKeyResponse(t *testing.T) {
	e := isolate(t)
	buf := encodeKeyResponse(e.keyText())
	if !bytes.HasSuffix(buf, []byte("\n")) {
		t.Error("no newline")
	}
	msg, err := readMessage(bytes.NewReader(buf), maxMessage)
	if err != nil {
		t.Fatal(err)
	}
	r := new(response)
	if err := json.Unmarshal(msg, r); err != nil {
		t.Fatal(err)
	}
	raw, ok := unquote(r.Key)
	if !r.OK || r.V != ProtocolVersion || !ok {
		t.Fatalf("response %+v", r)
	}
	id, err := parseKey(raw)
	if err != nil || id.String() != e.key.String() {
		t.Errorf("key round trip: %v", err)
	}
}

func TestValidKeyText(t *testing.T) {
	e := isolate(t)
	good := e.key.String()
	for s, want := range map[string]bool{
		good:                         true,
		strings.ToLower(good):        false,
		"AGE-SECRET-KEY-1":           false,
		"AGE-SECRET-KEY-1ABC\"":      false,
		"AGE-SECRET-KEY-1ABC\\":      false,
		good + "\n":                  false,
		"AGE-SECRET-KEY-1" + "Q":     true, // the shape only; parseKey checks the rest
		strings.Repeat("A", 200):     false,
		"AGE-PLUGIN-FOO-1QQQQQQQQQQ": false,
	} {
		if got := validKeyText([]byte(s)); got != want {
			t.Errorf("validKeyText(%.40q) = %v", s, got)
		}
	}
	if _, err := parseKey([]byte("AGE-SECRET-KEY-1QQQ")); err == nil {
		t.Error("parseKey accepted a bad checksum")
	}
}
