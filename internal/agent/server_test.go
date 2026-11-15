package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// testServer is an agent served inside the test process.
type testServer struct {
	*server
	sigs   chan os.Signal
	done   chan struct{}
	reason exitReason
}

// serve starts an in-process agent for e with a fast socket watch, and
// stops it at the end of the test.
func serve(t *testing.T, e *env, idle, maxTTL time.Duration) *testServer {
	t.Helper()
	return serveClock(t, e, idle, maxTTL, nil)
}

// serveClock is serve with the agent's clock set to clk (nil: the real
// one). The socket watch, every 10 ms, notices a TTL the fake clock was
// advanced past.
func serveClock(t *testing.T, e *env, idle, maxTTL time.Duration, clk *fakeClock) *testServer {
	t.Helper()
	oldWatch := watchInterval
	watchInterval = 10 * time.Millisecond
	real, err := realPath(e.vault)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(real, e.keyText(), keyBlockSum(e.keyBlock), idle, maxTTL)
	watchInterval = oldWatch
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if clk != nil {
		clk.install(s)
	}
	ts := &testServer{server: s, sigs: make(chan os.Signal, 1), done: make(chan struct{})}
	// Ends when the agent exits: a TTL, a stop, or the SIGTERM the cleanup
	// sends; the cleanup waits for it.
	go func() {
		ts.reason = s.run(ts.sigs)
		close(ts.done)
	}()
	t.Cleanup(func() {
		select {
		case ts.sigs <- syscall.SIGTERM:
		default:
		}
		<-ts.done
	})
	return ts
}

// wait waits for the agent to exit and returns why it did.
func (ts *testServer) wait(t *testing.T, timeout time.Duration) exitReason {
	t.Helper()
	select {
	case <-ts.done:
	case <-time.After(timeout):
		t.Fatalf("agent still running after %s", timeout)
	}
	if exists(ts.socket) {
		t.Errorf("socket %s left behind", ts.socket)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.key != nil {
		t.Error("key not wiped")
	}
	return ts.reason
}

// withPeerUID makes every peer look like uid (or fail with err) until the
// end of the test. Call it before serve, so it is restored after the agent
// stops.
func withPeerUID(t *testing.T, uid int, err error) {
	t.Helper()
	old := peerUID
	peerUID = func(*net.UnixConn) (int, error) { return uid, err }
	t.Cleanup(func() { peerUID = old })
}

func TestFolderAndSocketModes(t *testing.T) {
	e := isolate(t)
	// The modes don't depend on the umask.
	old := unix.Umask(0)
	defer unix.Umask(old)
	ts := serve(t, e, time.Minute, time.Minute)

	fi, err := os.Lstat(filepath.Dir(ts.socket))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("agent folder mode = %v, want drwx------", fi.Mode())
	}
	if want := filepath.Join(e.root, "s", "passh", "agent"); filepath.Dir(ts.socket) != want {
		t.Errorf("agent folder = %s, want %s", filepath.Dir(ts.socket), want)
	}
	fi, err = os.Lstat(ts.socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want Srw-------", fi.Mode())
	}
	if got := e.socket(t); got != ts.socket {
		t.Errorf("SocketPath = %s, agent listens on %s", got, ts.socket)
	}
}

// TestPathLengthFallback: with a state folder too long for a socket path,
// the socket goes to passh-<uid> in $TMPDIR.
func TestPathLengthFallback(t *testing.T) {
	e := isolate(t)
	long := filepath.Join(e.root, strings.Repeat("l", 60))
	if err := os.Mkdir(long, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", long)
	ts := serve(t, e, time.Minute, time.Minute)
	want := filepath.Join(e.root, "t", "passh-"+strconv.Itoa(os.Getuid()))
	if filepath.Dir(ts.socket) != want {
		t.Errorf("agent folder = %s, want %s", filepath.Dir(ts.socket), want)
	}
	if len(ts.socket) > 103 {
		t.Errorf("socket path is %d bytes", len(ts.socket))
	}
	fi, err := os.Lstat(want)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("fallback folder: %v, %v", fi, err)
	}
	if _, err := e.client(t).KeyFor(context.Background(), e.keyBlock); err != nil {
		t.Errorf("Key: %v", err)
	}
}

func TestForeignPeerRefused(t *testing.T) {
	e := isolate(t)
	withPeerUID(t, os.Getuid()+1, nil)
	ts := serve(t, e, time.Minute, time.Minute)
	ts.mu.Lock()
	lastUse := ts.lastUse
	ts.mu.Unlock()

	for _, op := range []string{opKey, opStatus, opStop} {
		got := rawRequest(t, ts.socket, `{"v":1,"op":"`+op+`"}`+"\n")
		if got != "" {
			t.Errorf("%s from another uid answered: %q", op, got)
		}
	}
	ts.mu.Lock()
	if !ts.lastUse.Equal(lastUse) {
		t.Error("a refused request counted as use")
	}
	ts.mu.Unlock()
	select {
	case <-ts.done:
		t.Fatal("a stop request from another uid stopped the agent")
	default:
	}

	// The client in turn refuses an agent of another uid.
	_, err := e.client(t).KeyFor(context.Background(), e.keyBlock)
	if err == nil || errors.Is(err, ErrNoAgent) || !strings.Contains(err.Error(), "uid") {
		t.Errorf("client accepted an agent of another uid: %v", err)
	}
}

func TestPeerCredentialErrorRefused(t *testing.T) {
	e := isolate(t)
	withPeerUID(t, -1, errors.New("no credentials"))
	ts := serve(t, e, time.Minute, time.Minute)
	if got := rawRequest(t, ts.socket, `{"v":1,"op":"key"}`+"\n"); got != "" {
		t.Errorf("answered without peer credentials: %q", got)
	}
}

// TestRealPeerCredentials checks the real SO_PEERCRED/LOCAL_PEERCRED call.
func TestRealPeerCredentials(t *testing.T) {
	e := isolate(t)
	ts := serve(t, e, time.Minute, time.Minute)
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: ts.socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := socketPeerUID(c)
	if err != nil || uid != os.Getuid() {
		t.Errorf("socketPeerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
}

func TestKeyAndStatus(t *testing.T) {
	e := isolate(t)
	ts := serve(t, e, time.Minute, time.Hour)
	c := e.client(t)
	id, err := c.KeyFor(context.Background(), e.keyBlock)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != e.key.String() {
		t.Error("the agent returned another key")
	}
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	real, _ := realPath(e.vault)
	if st.PID != os.Getpid() || st.Vault != real || st.Socket != ts.socket {
		t.Errorf("status = %+v", st)
	}
	if st.IdleLeft <= 50*time.Second || st.IdleLeft > time.Minute || st.MaxLeft <= 59*time.Minute || st.MaxLeft > time.Hour {
		t.Errorf("time left: idle %s, max %s", st.IdleLeft, st.MaxLeft)
	}
	if st.Left() != st.IdleLeft {
		t.Errorf("Left = %s", st.Left())
	}
	if c.Socket() != ts.socket {
		t.Errorf("Socket = %s", c.Socket())
	}
}

// TestIdleTTL: key requests restart the idle TTL, status requests don't,
// and the agent exits once it runs out. The agent's clock is a fake one.
func TestIdleTTL(t *testing.T) {
	e := isolate(t)
	const idle = 10 * time.Minute
	clk := newFakeClock()
	ts := serveClock(t, e, idle, 24*time.Hour, clk)
	c := e.client(t)
	ctx := context.Background()

	// Key requests keep it alive well past the idle TTL.
	for i := range 10 {
		clk.advance(idle / 2)
		if _, err := c.KeyFor(ctx, e.keyBlock); err != nil {
			t.Fatalf("KeyFor after %s: %v", time.Duration(i+1)*idle/2, err)
		}
	}
	// Status requests don't.
	st1, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Minute)
	st2, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st1.IdleLeft != idle || st2.IdleLeft != idle-time.Minute {
		t.Errorf("idle time left %s, then %s; want %s, then %s", st1.IdleLeft, st2.IdleLeft, idle, idle-time.Minute)
	}
	clk.advance(idle - time.Minute)
	if r := ts.wait(t, 5*time.Second); r != exitIdle {
		t.Errorf("exit reason = %q, want %q", r, exitIdle)
	}
	if _, err := c.KeyFor(ctx, e.keyBlock); !errors.Is(err, ErrNoAgent) {
		t.Errorf("KeyFor after exit: %v, want ErrNoAgent", err)
	}
}

// TestMaxTTL: use doesn't extend the max TTL; the agent answers until it
// runs out, not after. The agent's clock is a fake one.
func TestMaxTTL(t *testing.T) {
	e := isolate(t)
	const maxTTL = time.Hour
	clk := newFakeClock()
	ts := serveClock(t, e, 24*time.Hour, maxTTL, clk)
	c := e.client(t)
	ctx := context.Background()
	for range 59 {
		clk.advance(time.Minute)
		if _, err := c.KeyFor(ctx, e.keyBlock); err != nil {
			t.Fatalf("KeyFor before the max TTL: %v", err)
		}
	}
	clk.advance(time.Minute)
	if _, err := c.KeyFor(ctx, e.keyBlock); !errors.Is(err, ErrNoAgent) {
		t.Errorf("KeyFor at the max TTL: %v, want ErrNoAgent", err)
	}
	if r := ts.wait(t, 5*time.Second); r != exitMax {
		t.Errorf("exit reason = %q, want %q", r, exitMax)
	}
}

// TestExpiredKeyRequest: a key request that arrives after a TTL ran out,
// before the agent noticed, isn't answered with the key.
func TestExpiredKeyRequest(t *testing.T) {
	e := isolate(t)
	real, _ := realPath(e.vault)
	s, err := newServer(real, e.keyText(), keyBlockSum(e.keyBlock), 20*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clk := newFakeClock()
	clk.install(s)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		s.acceptLoop()
	}()
	defer s.shutdown(acceptDone)
	clk.advance(40 * time.Millisecond) // no wait loop runs: nothing notices
	c := e.client(t)
	if _, err := c.KeyFor(context.Background(), e.keyBlock); !errors.Is(err, ErrNoAgent) {
		t.Errorf("KeyFor after the idle TTL: %v, want ErrNoAgent", err)
	}
	st, err := c.Status(context.Background())
	if err != nil || st.IdleLeft != time.Millisecond {
		t.Errorf("Status = %+v, %v; want 1 ms idle time left", st, err)
	}
}

func TestStop(t *testing.T) {
	e := isolate(t)
	ts := serve(t, e, time.Minute, time.Minute)
	c := e.client(t)
	st, err := c.Stop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.PID != os.Getpid() || st.Socket != ts.socket {
		t.Errorf("status = %+v", st)
	}
	// Stop returns once the socket is gone.
	if exists(ts.socket) {
		t.Error("socket still there after Stop")
	}
	if r := ts.wait(t, 5*time.Second); r != exitStop {
		t.Errorf("exit reason = %q, want %q", r, exitStop)
	}
	if _, err := c.Stop(context.Background()); !errors.Is(err, ErrNoAgent) {
		t.Errorf("second Stop: %v, want ErrNoAgent", err)
	}
}

func TestSignalStops(t *testing.T) {
	e := isolate(t)
	ts := serve(t, e, time.Minute, time.Minute)
	ts.sigs <- syscall.SIGTERM
	if r := ts.wait(t, 5*time.Second); r != exitSignal {
		t.Errorf("exit reason = %q, want %q", r, exitSignal)
	}
}

func TestSocketRemoved(t *testing.T) {
	e := isolate(t)
	ts := serve(t, e, time.Minute, time.Minute)
	if err := os.Remove(ts.socket); err != nil {
		t.Fatal(err)
	}
	if r := ts.wait(t, 5*time.Second); r != exitSocket {
		t.Errorf("exit reason = %q, want %q", r, exitSocket)
	}
}

// TestSocketReplaced: an agent whose socket path now holds another socket
// exits and leaves the other socket alone.
func TestSocketReplaced(t *testing.T) {
	e := isolate(t)
	ts := serve(t, e, time.Minute, time.Minute)
	other := filepath.Join(filepath.Dir(ts.socket), "other.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: other, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.SetUnlinkOnClose(false)
	if err := os.Rename(other, ts.socket); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ts.done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent still running after its socket was replaced")
	}
	if ts.reason != exitSocket {
		t.Errorf("exit reason = %q, want %q", ts.reason, exitSocket)
	}
	if !exists(ts.socket) {
		t.Error("the agent removed a socket that wasn't its own")
	}
}

func TestStaleSocketRemoved(t *testing.T) {
	e := isolate(t)
	real, _ := realPath(e.vault)
	sock, err := ensureSocketPath(real)
	if err != nil {
		t.Fatal(err)
	}
	makeStaleSocket(t, sock)
	if _, err := e.client(t).Status(context.Background()); !errors.Is(err, ErrNoAgent) {
		t.Errorf("Status with a stale socket: %v, want ErrNoAgent", err)
	}
	ts := serve(t, e, time.Minute, time.Minute)
	if _, err := e.client(t).KeyFor(context.Background(), e.keyBlock); err != nil {
		t.Errorf("Key: %v", err)
	}
	if ts.socket != sock {
		t.Errorf("socket = %s, want %s", ts.socket, sock)
	}
}

func makeStaleSocket(t *testing.T, path string) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if !exists(path) {
		t.Fatal("stale socket not left behind")
	}
}

func TestSecondServerRefused(t *testing.T) {
	e := isolate(t)
	serve(t, e, time.Minute, time.Minute)
	real, _ := realPath(e.vault)
	if _, err := newServer(real, e.keyText(), keyBlockSum(e.keyBlock), time.Minute, time.Minute); !errors.Is(err, errRunning) {
		t.Errorf("second agent: %v, want errRunning", err)
	}
	// The first one still works.
	if _, err := e.client(t).KeyFor(context.Background(), e.keyBlock); err != nil {
		t.Errorf("Key: %v", err)
	}
}

func TestNonSocketNotReplaced(t *testing.T) {
	e := isolate(t)
	real, _ := realPath(e.vault)
	sock, err := ensureSocketPath(real)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = newServer(real, e.keyText(), keyBlockSum(e.keyBlock), time.Minute, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("err = %v, want a refusal", err)
	}
	if b, _ := os.ReadFile(sock); string(b) != "mine" {
		t.Error("the file was replaced")
	}
}

func TestNewServerRefuses(t *testing.T) {
	e := isolate(t)
	real, _ := realPath(e.vault)
	sum := keyBlockSum(e.keyBlock)
	for name, f := range map[string]func() error{
		"zero idle": func() error { _, err := newServer(real, e.keyText(), sum, 0, time.Minute); return err },
		"zero max":  func() error { _, err := newServer(real, e.keyText(), sum, time.Minute, -1); return err },
		"bad key": func() error {
			_, err := newServer(real, []byte("AGE-SECRET-KEY-1x"), sum, time.Minute, time.Minute)
			return err
		},
		"no key block": func() error { _, err := newServer(real, e.keyText(), "", time.Minute, time.Minute); return err },
	} {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A refused agent folder.
	dir := filepath.Join(e.root, "s", "passh", "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newServer(real, e.keyText(), sum, time.Minute, time.Minute); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("err = %v, want a refusal of the folder", err)
	}
}

func TestProtocolErrors(t *testing.T) {
	e := isolate(t)
	ts := serve(t, e, time.Minute, time.Minute)
	ts.mu.Lock()
	lastUse := ts.lastUse
	ts.mu.Unlock()
	sum := keyBlockSum(e.keyBlock)
	for _, tc := range []struct{ req, want string }{
		{`{"v":2,"op":"key"}` + "\n", `"code":"version"`},
		{`{"op":"key"}` + "\n", `"code":"version"`},
		{"garbage\n", `"code":"bad_request"`},
		{`{"v":1,"op":"nope"}` + "\n", `"code":"bad_request"`},
		{`{"v":1,"op":"` + strings.Repeat("n", maxMessage-40) + `"}` + "\n", `"code":"bad_request"`},
		{strings.Repeat("x", maxMessage+10), `request too large`},
		// INV-12: a key request names the key block (CLI-013).
		{`{"v":1,"op":"key"}` + "\n", `"code":"bad_request","error":"a key request must name the vault's key block`},
		{`{"v":1,"op":"key","key_block":""}` + "\n", `"code":"bad_request"`},
		{`{"v":1,"op":"key","key_block":"` + strings.ToUpper(sum) + `"}` + "\n", `"code":"bad_request","error":"key_block is not a hex SHA-256"`},
		{`{"v":1,"op":"key","key_block":"` + keyBlockSum([]byte("other")) + `"}` + "\n", `"code":"key_block_changed"`},
		{`{"v":1,"op":"key","key_block":"` + sum + `"}`, ``}, // no newline before EOF: no answer
		{"", ``}, // a bare connection
	} {
		got := rawRequest(t, ts.socket, tc.req)
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("request %.30q: answer %q, want %q", tc.req, got, tc.want)
		}
		if len(got) > maxMessage {
			t.Errorf("request %.30q: an answer of %d bytes, more than a client reads", tc.req, len(got))
		}
		if strings.Contains(got, "AGE-SECRET-KEY") {
			t.Errorf("request %.30q got the key", tc.req)
		}
	}
	ts.mu.Lock()
	if !ts.lastUse.Equal(lastUse) {
		t.Error("a bad request counted as use")
	}
	ts.mu.Unlock()
	// Still serving.
	if _, err := e.client(t).KeyFor(context.Background(), e.keyBlock); err != nil {
		t.Errorf("Key: %v", err)
	}
}

// rawRequest dials the agent, sends req, half-closes, and returns whatever
// the agent answers before closing.
func rawRequest(t *testing.T, socket, req string) string {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return rawRequestOn(t, c, req)
}

// rawRequestOn is rawRequest on a connection made by the caller.
func rawRequestOn(t *testing.T, c *net.UnixConn, req string) string {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// The agent may refuse (close) the connection before this write: it
	// drops a foreign peer right after accept, without reading. Whether the
	// write runs before or after that depends on scheduling, so a write to
	// an already closed connection is not an error here; what the agent
	// answered, if anything, is still read and returned for the caller to
	// check.
	if _, err := io.WriteString(c, req); err != nil && !closedByAgent(err) {
		t.Fatal(err)
	}
	_ = c.CloseWrite()
	b, err := io.ReadAll(c)
	if err != nil && !closedByAgent(err) {
		t.Fatal(err)
	}
	return string(b)
}

// closedByAgent reports whether err means the agent closed the connection.
func closedByAgent(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

// TestRawRequestAfterRefusal pins down the ordering that made
// TestForeignPeerRefused flaky under load: the agent refuses and closes a
// foreign peer's connection before the request is written (EPIPE).
func TestRawRequestAfterRefusal(t *testing.T) {
	e := isolate(t)
	withPeerUID(t, os.Getuid()+1, nil)
	ts := serve(t, e, time.Minute, time.Minute)
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: ts.socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Wait until the agent has refused and closed this connection.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || (!errors.Is(err, io.EOF) && !closedByAgent(err)) {
		t.Fatalf("read = %d, %v; want the connection closed by the agent", n, err)
	}
	for _, op := range []string{opKey, opStatus, opStop} {
		if got := rawRequestOn(t, c, `{"v":1,"op":"`+op+`"}`+"\n"); got != "" {
			t.Errorf("%s answered: %q", op, got)
		}
	}
	select {
	case <-ts.done:
		t.Error("the agent stopped")
	default:
	}
}
