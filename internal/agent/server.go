package agent

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/keys"
)

// Timing of the agent. Variables so tests can shorten them.
var (
	// watchInterval is how often the agent checks that its socket file is
	// still its own.
	watchInterval = time.Second
	// connTimeout bounds one connection, on both sides.
	connTimeout = 5 * time.Second
)

// exitReason tells why the agent exited.
type exitReason string

const (
	exitIdle   exitReason = "idle TTL reached"
	exitMax    exitReason = "max TTL reached"
	exitStop   exitReason = "stop requested"
	exitSignal exitReason = "signal"
	exitSocket exitReason = "socket removed or replaced"
	exitAccept exitReason = "accept failed"
)

// errRunning: another agent answers on the socket.
var errRunning = errors.New("another agent is running on the socket")

// server is a running agent: a listening socket and the key it serves.
type server struct {
	vault   string // the vault's real path
	socket  string
	ln      *net.UnixListener
	dev     uint64 // the socket file's device and inode, to notice its
	ino     uint64 // removal or replacement
	uid     int
	pid     int
	idleTTL time.Duration
	maxTTL  time.Duration
	watch   time.Duration
	start   time.Time
	// now is the clock (CONC-8): time.Now, or a fake one in tests. The
	// socket watch still runs on real time.
	now func() time.Time

	// keyBlock is the hex SHA-256 of the key block the key was unwrapped
	// from; a key request must name it (INV-12).
	keyBlock string

	mu      sync.Mutex
	lastUse time.Time
	key     []byte // vault key text; wiped on exit

	stopOnce sync.Once
	stopped  chan struct{} // closed by a stop request
	conns    sync.WaitGroup
}

// newServer creates the agent folder and the socket for the vault at the
// real path real, and returns a server that owns key (it wipes it on exit)
// and serves it only for the key block whose hex SHA-256 is keyBlock. A
// stale socket (nobody listening) is removed first; a live one gives
// errRunning.
func newServer(real string, key []byte, keyBlock string, idleTTL, maxTTL time.Duration) (*server, error) {
	if idleTTL <= 0 || maxTTL <= 0 {
		return nil, errors.New("agent: TTLs must be positive")
	}
	if !validKeyText(key) {
		return nil, errors.New("agent: not a vault key")
	}
	if !validSum(keyBlock) {
		return nil, errors.New("agent: no key block digest")
	}
	socket, err := ensureSocketPath(real)
	if err != nil {
		return nil, err
	}
	ln, err := listen(socket)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(socket)
	if err == nil && fi.Mode().Type() != fs.ModeSocket {
		err = fmt.Errorf("%s is not a socket", socket)
	}
	if err == nil {
		// Only the owner may connect. The folder is 0700 anyway, and nobody
		// is accepted before this.
		err = os.Chmod(socket, 0o600)
	}
	if err != nil {
		ln.Close()
		if fi != nil && fi.Mode().Type() == fs.ModeSocket {
			_ = os.Remove(socket) // just created by listen, in our 0700 folder
		}
		return nil, fmt.Errorf("agent: setting up the socket: %w", err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	now := time.Now()
	return &server{
		now:      time.Now,
		keyBlock: keyBlock,
		vault:    real,
		socket:   socket,
		ln:       ln,
		dev:      uint64(st.Dev),
		ino:      st.Ino,
		uid:      os.Getuid(),
		pid:      os.Getpid(),
		idleTTL:  idleTTL,
		maxTTL:   maxTTL,
		watch:    watchInterval,
		start:    now,
		lastUse:  now,
		key:      key,
		stopped:  make(chan struct{}),
	}, nil
}

// listen binds the socket. If the path exists and is a socket nobody
// listens on (a crashed agent's), it is removed and binding is retried.
func listen(socket string) (*net.UnixListener, error) {
	for range 3 {
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
		if err == nil {
			// The socket is removed by the agent only while it is its own
			// (see shutdown), not by Close.
			ln.SetUnlinkOnClose(false)
			return ln, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, fmt.Errorf("agent: creating the socket: %w", err)
		}
		fi, err := os.Lstat(socket)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("agent: %w", err)
		}
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("agent: %s exists and is not a socket; refusing to replace it", socket)
		}
		c, err := net.DialTimeout("unix", socket, connTimeout)
		if err == nil {
			c.Close()
			return nil, errRunning
		}
		if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("agent: checking the existing socket: %w", err)
		}
		if err := os.Remove(socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("agent: removing the stale socket: %w", err)
		}
	}
	return nil, fmt.Errorf("agent: %s keeps reappearing", socket)
}

// run serves requests until an exit condition (see the package comment),
// then shuts down: the socket is removed and the key wiped. sigs delivers
// the signals that stop the agent; it may be nil.
func (s *server) run(sigs <-chan os.Signal) exitReason {
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		s.acceptLoop()
	}()
	reason := s.wait(sigs, acceptDone)
	s.shutdown(acceptDone)
	return reason
}

func (s *server) wait(sigs <-chan os.Signal, acceptDone <-chan struct{}) exitReason {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		now := s.now()
		if r := s.expired(now); r != "" {
			return r
		}
		timer.Reset(min(s.watch, s.untilExpiry(now)))
		select {
		case <-timer.C:
			if !s.ownsSocket() {
				return exitSocket
			}
		case <-s.stopped:
			return exitStop
		case <-sigs:
			return exitSignal
		case <-acceptDone:
			return exitAccept
		}
	}
}

func (s *server) acceptLoop() {
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// EMFILE and the like: back off instead of spinning.
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
				errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EINTR) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		s.conns.Add(1)
		go s.handle(c)
	}
}

// handle answers one connection. Peers of another uid get no answer.
func (s *server) handle(c *net.UnixConn) {
	defer s.conns.Done()
	defer c.Close()
	if err := checkPeer(c, s.uid); err != nil {
		return
	}
	if err := c.SetDeadline(time.Now().Add(connTimeout)); err != nil {
		return
	}
	msg, err := readMessage(c, maxMessage)
	if err != nil {
		if errors.Is(err, errTooLarge) {
			_, _ = c.Write(encodeResponse(errorResponse(codeBadRequest, i18n.Mark("request too large"))))
		}
		return
	}
	req, refused := parseRequest(msg)
	if refused != nil {
		_, _ = c.Write(encodeResponse(*refused))
		return
	}
	switch req.Op {
	case opKey:
		if subtle.ConstantTimeCompare([]byte(req.KeyBlock), []byte(s.keyBlock)) != 1 {
			_, _ = c.Write(encodeResponse(errorResponse(codeKeyBlock, "the vault's key block isn't the one this agent was unlocked with")))
			return
		}
		buf := s.keyResponse()
		if buf == nil {
			_, _ = c.Write(encodeResponse(errorResponse(codeExpired, "the agent has expired")))
			return
		}
		_, _ = c.Write(buf)
		keys.Zero(buf)
	case opStatus:
		_, _ = c.Write(encodeResponse(statusResponse(s.status(s.now()))))
	case opStop:
		st := s.status(s.now())
		s.stop()
		_, _ = c.Write(encodeResponse(statusResponse(st)))
	}
}

// keyResponse records a use and returns the key response, or nil if the
// agent has expired or is stopping.
func (s *server) keyResponse() []byte {
	select {
	case <-s.stopped:
		return nil
	default:
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil || s.expiredLocked(now) != "" {
		return nil
	}
	s.lastUse = now
	return encodeKeyResponse(s.key)
}

func (s *server) stop() {
	s.stopOnce.Do(func() { close(s.stopped) })
}

func (s *server) expired(now time.Time) exitReason {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiredLocked(now)
}

func (s *server) expiredLocked(now time.Time) exitReason {
	switch {
	case elapsed(s.start, now) >= s.maxTTL:
		return exitMax
	case elapsed(s.lastUse, now) >= s.idleTTL:
		return exitIdle
	}
	return ""
}

func (s *server) status(now time.Time) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		PID:      s.pid,
		Vault:    s.vault,
		Socket:   s.socket,
		IdleLeft: max(s.idleTTL-elapsed(s.lastUse, now), 0),
		MaxLeft:  max(s.maxTTL-elapsed(s.start, now), 0),
	}
}

// untilExpiry is the time until the first TTL runs out, at least 1 ms.
func (s *server) untilExpiry(now time.Time) time.Duration {
	st := s.status(now)
	return max(st.Left(), time.Millisecond)
}

// ownsSocket reports whether the socket path still refers to the socket
// this agent created.
func (s *server) ownsSocket() bool {
	fi, err := os.Lstat(s.socket)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && uint64(st.Dev) == s.dev && st.Ino == s.ino
}

// shutdown stops accepting, removes the socket if it is still this agent's,
// waits for the connections being answered, and wipes the key.
func (s *server) shutdown(acceptDone <-chan struct{}) {
	s.stop()
	// The socket goes first, so a client whose connection is dropped by
	// the Close below finds it gone and reports "no agent".
	if s.ownsSocket() {
		_ = os.Remove(s.socket)
	}
	s.ln.Close()
	<-acceptDone
	s.conns.Wait()
	s.mu.Lock()
	keys.Zero(s.key)
	s.key = nil
	s.mu.Unlock()
}
