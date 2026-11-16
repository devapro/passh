// Package agent is passh's agent (spec §5.3, ADR-8): a background copy of
// passh that keeps one vault's key in memory for a limited time, so later
// commands, including ones run over SSH without a terminal, don't ask for
// the passphrase.
//
//   - Start (used only by `passh unlock`) re-executes the passh binary with
//     the hidden subcommand ChildCommand, whose cobra command calls
//     ChildMain. The vault key reaches the child only through its stdin
//     pipe (S2), never through arguments or the environment.
//   - Client asks a running agent for the key, its status, or to stop.
//     KeySource is a keys.KeySource backed by the agent. Neither ever starts
//     an agent: without one they return ErrNoAgent, and the caller falls
//     back to a passphrase prompt (§5.1).
//
// There is one agent per vault, on the socket agent-<hash>.sock in the agent
// folder (config.AgentDir), where <hash> is the first 16 hex digits of the
// SHA-256 of the vault's real path. The folder has mode 0700 and the socket
// 0600, and the agent answers only peers with its own uid (SO_PEERCRED on
// Linux, LOCAL_PEERCRED on macOS).
//
// The agent exits at the first of: IdleTTL without a key request, MaxTTL
// since it started, a stop request, SIGTERM or SIGINT, or its socket file
// being removed or replaced. It ignores SIGHUP and runs in its own session,
// so it outlives the SSH session that started it (§6.4). On exit it removes
// its socket (if the path still refers to it) and wipes its copy of the key.
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"time"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
)

// ChildCommand is the hidden passh subcommand that runs the agent process.
// Start runs `passh __agent --vault=<real path> --idle-ttl=<d> --max-ttl=<d>`;
// the subcommand passes the arguments after its name to ChildMain unparsed.
const ChildCommand = "__agent"

// ProtocolVersion is the version of the request/response protocol between
// clients and the agent. A client and an agent of different versions refuse
// each other with a clear error.
const ProtocolVersion = 1

var (
	// ErrNoAgent: no agent is running for the vault (no socket, a stale
	// socket, or an agent that has just expired). Callers fall back to a
	// passphrase prompt (§5.1).
	ErrNoAgent = i18n.NewError("no agent is running for this vault")

	// ErrKeyBlockChanged: the agent holds the key for another key block
	// than the vault file has now: a passwd or rekey elsewhere, or a
	// damaged or replaced key block. The agent's key isn't used, so such a
	// key block is never carried into a save unchecked; the caller asks
	// for the passphrase instead, which checks it (§5.1).
	// errors.Is(err, ErrNoAgent) is true for it too.
	ErrKeyBlockChanged error = keyBlockChanged{}

	// ErrAlreadyRunning: Start found an agent already running for the vault.
	// The error Start returns is an *AlreadyRunningError, which carries the
	// agent's status and satisfies errors.Is(err, ErrAlreadyRunning).
	ErrAlreadyRunning = i18n.NewError("an agent is already running for this vault")
)

type keyBlockChanged struct{}

func (e keyBlockChanged) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language.
func (keyBlockChanged) Localize(p i18n.Printer) string {
	return p.T("the vault's key block isn't the one `passh unlock` opened (passwd elsewhere, or damaged): the agent's key isn't used")
}

// Is makes errors.Is(err, ErrNoAgent) true, so callers fall back to the
// passphrase.
func (keyBlockChanged) Is(target error) bool { return target == ErrNoAgent }

// AlreadyRunningError is returned by Start when an agent is already running
// for the vault.
type AlreadyRunningError struct {
	Status Status
}

func (e *AlreadyRunningError) Error() string { return e.Localize(i18n.Printer{}) }

// Localize implements i18n.Localizer: the message in p's language.
func (e *AlreadyRunningError) Localize(p i18n.Printer) string {
	return p.T("%v: it exits in %s if unused, in %s at the latest",
		ErrAlreadyRunning, roundDuration(e.Status.IdleLeft), roundDuration(e.Status.MaxLeft))
}

// Is makes errors.Is(err, ErrAlreadyRunning) true.
func (e *AlreadyRunningError) Is(target error) bool { return target == ErrAlreadyRunning }

// Status describes a running agent.
type Status struct {
	PID    int    // the agent's process id
	Vault  string // the vault's real path
	Socket string // the agent's socket
	// IdleLeft is the time until the agent exits if no key is requested
	// meanwhile; each key request restarts it.
	IdleLeft time.Duration
	// MaxLeft is the time until the agent exits in any case.
	MaxLeft time.Duration
}

// Left is the time until the agent exits if it isn't used: the smaller of
// IdleLeft and MaxLeft.
func (s Status) Left() time.Duration { return min(s.IdleLeft, s.MaxLeft) }

// peerUID returns the uid of the process at the other end of a Unix socket
// connection. It is a variable so tests can simulate a peer of another user
// (a real one needs root).
var peerUID = socketPeerUID

// SocketPath returns the path of the agent socket for vault, without
// creating anything. The vault must exist: its real path (symlinks
// resolved) names the socket.
func SocketPath(vault string) (string, error) {
	real, err := realPath(vault)
	if err != nil {
		return "", err
	}
	return socketPathFor(real)
}

// socketPathFor is SocketPath for the vault's real path.
func socketPathFor(real string) (string, error) {
	name := socketName(real)
	dir, err := config.AgentDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// ensureSocketPath is SocketPath for the real path real, after creating and
// checking the agent folder (config.EnsureAgentDir).
func ensureSocketPath(real string) (string, error) {
	name := socketName(real)
	dir, err := config.EnsureAgentDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// socketName is agent-<first 16 hex digits of SHA-256(real path)>.sock.
func socketName(real string) string {
	sum := sha256.Sum256([]byte(real))
	return "agent-" + hex.EncodeToString(sum[:8]) + ".sock"
}

// realPath returns the vault's absolute path with symlinks resolved, so
// every way of naming the same vault finds the same agent.
func realPath(vault string) (string, error) {
	if vault == "" {
		return "", errors.New("agent: no vault path")
	}
	abs, err := filepath.Abs(vault)
	if err != nil {
		return "", i18n.Errorf("agent: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", i18n.Errorf("agent: resolving the vault path: %w", err)
	}
	return real, nil
}

// checkPeer refuses a peer whose uid isn't uid.
func checkPeer(c *net.UnixConn, uid int) error {
	got, err := peerUID(c)
	if err != nil {
		return i18n.Errorf("reading peer credentials: %w", err)
	}
	if got != uid {
		return i18n.Errorf("peer is uid %d, not uid %d", got, uid)
	}
	return nil
}

// elapsed is the time from since to now. It is the larger of the monotonic
// and the wall-clock difference: the monotonic clock stops while the machine
// sleeps, and a TTL must count that time too.
func elapsed(since, now time.Time) time.Duration {
	return max(now.Sub(since), now.Round(0).Sub(since.Round(0)))
}

// roundDuration rounds d to whole seconds for messages, never below zero.
func roundDuration(d time.Duration) time.Duration {
	return max(d.Round(time.Second), 0)
}
