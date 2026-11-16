package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/devapro/passh/internal/config"
	"github.com/devapro/passh/internal/i18n"
	"github.com/devapro/passh/internal/keys"
)

// Client talks to the agent of one vault. Every call opens its own
// connection. A Client never starts an agent.
type Client struct {
	vault  string // real path
	socket string
}

// NewClient returns a client for the agent of vault. It doesn't connect and
// doesn't create anything; the vault must exist (its real path names the
// socket).
func NewClient(vault string) (*Client, error) {
	real, err := realPath(vault)
	if err != nil {
		return nil, err
	}
	socket, err := socketPathFor(real)
	if err != nil {
		return nil, err
	}
	return &Client{vault: real, socket: socket}, nil
}

// Socket returns the path of the agent's socket.
func (c *Client) Socket() string { return c.socket }

// KeyFor asks the agent for the vault key of a vault whose key block is
// keyBlock, and checks that the answer is a valid age X25519 identity. The
// agent answers only for the key block `passh unlock` opened (INV-12):
// otherwise it is ErrKeyBlockChanged (which is also ErrNoAgent), so a key
// block changed or damaged since then isn't carried into every save. It is
// ErrNoAgent when no agent is running. Whether the key opens the vault shows
// only when the caller decrypts the data block. A key request restarts the
// agent's idle TTL.
func (c *Client) KeyFor(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	resp, err := c.doReq(ctx, opKey, keyBlockSum(keyBlock))
	if err != nil {
		return nil, err
	}
	defer keys.Zero(resp.Key)
	raw, ok := unquote(resp.Key)
	if !ok {
		return nil, i18n.NewError("agent: the agent's answer holds no vault key")
	}
	id, err := parseKey(raw)
	if err != nil {
		return nil, i18n.Errorf("agent: the agent's answer holds no valid vault key: %w", err)
	}
	return id, nil
}

// Status asks the agent for its status. It is ErrNoAgent when no agent is
// running. A status request doesn't count as use: it doesn't restart the
// idle TTL.
func (c *Client) Status(ctx context.Context) (Status, error) {
	resp, err := c.do(ctx, opStatus)
	if err != nil {
		return Status{}, err
	}
	st := resp.status()
	st.Socket = c.socket
	return st, nil
}

// Stop asks the agent to exit and waits until it has removed its socket
// (bounded by ctx, or by a few seconds if ctx has no deadline). It returns
// the agent's status from just before it stopped, or ErrNoAgent when no
// agent is running.
func (c *Client) Stop(ctx context.Context) (Status, error) {
	resp, err := c.do(ctx, opStop)
	if err != nil {
		return Status{}, err
	}
	st := resp.status()
	st.Socket = c.socket
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Lstat(c.socket); errors.Is(err, fs.ErrNotExist) {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, i18n.Errorf("agent: waiting for the agent (pid %d) to exit: %w", st.PID, ctx.Err())
		case <-tick.C:
		}
	}
}

// do sends one request and returns the agent's successful response.
func (c *Client) do(ctx context.Context, op string) (*response, error) {
	return c.doReq(ctx, op, "")
}

// doReq is do with a key block digest for a key request.
func (c *Client) doReq(ctx context.Context, op, keyBlock string) (*response, error) {
	if err := config.CheckAgentDir(filepath.Dir(c.socket)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoAgent
		}
		return nil, i18n.Errorf("agent: %w", err)
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrNoAgent
		}
		return nil, i18n.Errorf("agent: connecting to %s: %w", c.socket, err)
	}
	conn := nc.(*net.UnixConn)
	defer conn.Close()
	// The agent must be ours too: a socket served by someone else would
	// mean the folder checks were circumvented.
	if err := checkPeer(conn, os.Getuid()); err != nil {
		return nil, i18n.Errorf("agent: refusing the agent socket %s: %w", c.socket, err)
	}
	stopWatch := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopWatch()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req := `{"v":` + strconv.Itoa(ProtocolVersion) + `,"op":"` + op + `"`
	if keyBlock != "" {
		req += `,"key_block":"` + keyBlock + `"` // hex: needs no escaping
	}
	req += "}\n"
	if _, err := io.WriteString(conn, req); err != nil {
		if c.gone(err) {
			return nil, ErrNoAgent
		}
		return nil, i18n.Errorf("agent: sending the request: %w", c.ioError(ctx, err))
	}
	msg, err := readMessage(conn, maxMessage)
	if err != nil {
		if c.gone(err) {
			return nil, ErrNoAgent
		}
		if errors.Is(err, io.EOF) {
			return nil, i18n.NewError("agent: the agent closed the connection without answering")
		}
		return nil, i18n.Errorf("agent: reading the answer: %w", c.ioError(ctx, err))
	}
	defer clear(msg[:cap(msg)])
	return parseResponse(msg)
}

// parseResponse decodes one answer line (without its newline). The version
// is checked before the rest, whose shape may differ. A refusal becomes its
// error: ErrNoAgent for "expired", ErrKeyBlockChanged for
// "key_block_changed". The caller wipes resp.Key (a buffer of its own).
func parseResponse(msg []byte) (*response, error) {
	var v struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(msg, &v); err != nil {
		return nil, errMalformedAnswer
	}
	if v.V != ProtocolVersion {
		return nil, i18n.Errorf("agent: the running agent speaks protocol version %d, this passh %d; kill it and run `passh unlock` again", v.V, ProtocolVersion)
	}
	resp := new(response)
	if err := json.Unmarshal(msg, resp); err != nil {
		keys.Zero(resp.Key)
		return nil, errMalformedAnswer
	}
	if !resp.OK {
		keys.Zero(resp.Key)
		switch resp.Code {
		case codeExpired:
			return nil, ErrNoAgent
		case codeKeyBlock:
			return nil, ErrKeyBlockChanged
		case codeVersion:
			return nil, i18n.Errorf("agent: %v", answer(resp.Error))
		default:
			return nil, i18n.Errorf("agent: the agent refused the request: %v", answer(resp.Error))
		}
	}
	return resp, nil
}

// gone reports whether err is a dropped connection from an agent that has
// exited meanwhile (it removes its socket before it drops connections).
func (c *Client) gone(err error) bool {
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
		return false
	}
	_, statErr := os.Lstat(c.socket)
	return errors.Is(statErr, fs.ErrNotExist)
}

// ioError is the cause of a failed read or write. The only deadlines on
// the connection come from ctx, so a deadline error is reported as ctx's.
func (c *Client) ioError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}

// errMalformedAnswer: the agent's answer isn't the protocol's JSON.
var errMalformedAnswer = i18n.NewError("agent: malformed answer")

// answer is the error text of a refusal read from the agent's socket, as
// an error, so that i18n.Printer.Error translates it when the whole text is
// a catalog key (the agent marks its answers with i18n.Mark).
func answer(text string) error { return errors.New(text) }

// withDefaultTimeout bounds ctx by connTimeout unless it has a deadline.
func withDefaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, connTimeout)
}

// unquote strips the quotes of a raw JSON string that needs no unescaping
// (a vault key has no characters JSON escapes). The result shares raw's
// memory.
func unquote(raw json.RawMessage) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	return raw[1 : len(raw)-1], true
}

// KeySource is a keys.KeySource that gets the vault key from the agent of
// Vault. It never starts an agent: with none running, VaultKey returns an
// error satisfying errors.Is(err, ErrNoAgent), and the caller asks for the
// passphrase instead (§5.1). The agent answers only for the key block
// `passh unlock` opened; for another one (a passwd elsewhere, a damaged or
// replaced key block) VaultKey returns ErrKeyBlockChanged, which is also
// ErrNoAgent, so the passphrase checks the new key block before any save
// copies it. Whether the key decrypts the data block is the caller's
// check.
type KeySource struct {
	Vault string // the vault's path
}

var _ keys.KeyBlockChecker = KeySource{}

// ChecksKeyBlock implements keys.KeyBlockChecker: the agent serves the key
// only for the key block `passh unlock` unwrapped with the passphrase.
func (KeySource) ChecksKeyBlock() bool { return true }

// VaultKey implements keys.KeySource.
func (s KeySource) VaultKey(ctx context.Context, keyBlock []byte) (*age.X25519Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := NewClient(s.Vault)
	if err != nil {
		return nil, err
	}
	return c.KeyFor(ctx, keyBlock)
}
