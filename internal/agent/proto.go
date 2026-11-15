package agent

// The protocol: one request and one response per connection, each a JSON
// object on one line ending in "\n", at most maxMessage bytes.
//
//	request:  {"v":1,"op":"status"|"stop"}
//	          {"v":1,"op":"key","key_block":"<hex SHA-256 of the vault's key block>"}
//	response: {"v":1,"ok":true,"key":"AGE-SECRET-KEY-1…"}                   (key)
//	          {"v":1,"ok":true,"pid":…,"vault":…,"idle_left_ms":…,"max_left_ms":…} (status, stop)
//	          {"v":1,"ok":false,"code":"expired"|"bad_request"|"version"|"key_block_changed","error":"…"}
//
// A key request must name the vault's key block (INV-12): without
// "key_block", or with one that isn't a lower-case hex SHA-256, it is a
// "bad_request"; with another key block than the one `passh unlock` opened,
// "key_block_changed". (Before 2026-11-15 the key block was optional; no
// released client relied on that, so the version stays 1.)
//
// The agent answers peers of another uid with nothing: it closes the
// connection. A request of another version gets a "version" error.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"filippo.io/age"
)

const (
	opKey    = "key"
	opStatus = "status"
	opStop   = "stop"

	codeExpired    = "expired"     // the agent is past a TTL or stopping
	codeBadRequest = "bad_request" // malformed or unknown request
	codeVersion    = "version"     // unsupported protocol version
	codeKeyBlock   = "key_block_changed"

	// maxMessage caps a request or a response line, newline included.
	maxMessage = 4096

	// keyPrefix starts every vault key (an age X25519 identity).
	keyPrefix = "AGE-SECRET-KEY-1"
)

type request struct {
	V        int    `json:"v"`
	Op       string `json:"op"`
	KeyBlock string `json:"key_block,omitempty"` // hex SHA-256, for "key"
}

// maxOpEcho bounds how much of an unknown operation's name an error
// response repeats, so the response stays far below maxMessage.
const maxOpEcho = 32

// parseRequest decodes one request line (without its newline) and checks
// it. For a request the agent doesn't serve, it returns the error response
// to send instead.
func parseRequest(msg []byte) (request, *response) {
	var req request
	refuse := func(code, format string, args ...any) (request, *response) {
		r := errorResponse(code, format, args...)
		return request{}, &r
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return refuse(codeBadRequest, "malformed request")
	}
	if req.V != ProtocolVersion {
		return refuse(codeVersion, "the agent speaks protocol version %d, not %d", ProtocolVersion, req.V)
	}
	switch req.Op {
	case opKey:
		if req.KeyBlock == "" {
			return refuse(codeBadRequest, "a key request must name the vault's key block (key_block)")
		}
		if !validSum(req.KeyBlock) {
			return refuse(codeBadRequest, "key_block is not a hex SHA-256")
		}
	case opStatus, opStop:
	default:
		return refuse(codeBadRequest, "unknown request %.*q", maxOpEcho, req.Op)
	}
	return req, nil
}

// keyBlockSum is the hex SHA-256 of a key block, as requests carry it.
func keyBlockSum(keyBlock []byte) string {
	sum := sha256.Sum256(keyBlock)
	return hex.EncodeToString(sum[:])
}

// validSum reports whether s is a hex SHA-256 as keyBlockSum writes it.
func validSum(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type response struct {
	V     int    `json:"v"`
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
	// Key is the raw JSON string, so the client gets a buffer of its own
	// that it can wipe (a Go string can't be).
	Key        json.RawMessage `json:"key,omitempty"`
	PID        int             `json:"pid,omitempty"`
	Vault      string          `json:"vault,omitempty"`
	IdleLeftMS int64           `json:"idle_left_ms,omitempty"`
	MaxLeftMS  int64           `json:"max_left_ms,omitempty"`
}

var (
	errTooLarge = errors.New("message too large")
	errNoLine   = errors.New("connection closed in the middle of a message")
)

// readMessage reads one line of at most limit bytes (newline included) into
// a buffer of its own and returns the line without the newline. The caller
// may wipe the whole buffer with clear(msg[:cap(msg)]). A connection closed
// before any byte gives io.EOF.
func readMessage(r io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, limit)
	n := 0
	for {
		m, err := r.Read(buf[n:])
		if i := bytes.IndexByte(buf[n:n+m], '\n'); i >= 0 {
			return buf[: n+i : limit], nil
		}
		n += m
		if err != nil {
			clear(buf[:n])
			if errors.Is(err, io.EOF) {
				if n == 0 {
					return nil, io.EOF
				}
				return nil, errNoLine
			}
			return nil, err
		}
		if n == limit {
			clear(buf)
			return nil, errTooLarge
		}
	}
}

// encodeKeyResponse builds the key response by hand into one buffer the
// caller wipes after writing it. encoding/json would leave copies of the key
// in its pooled buffers. key must pass validKeyText, so it needs no
// escaping.
func encodeKeyResponse(key []byte) []byte {
	head := `{"v":` + strconv.Itoa(ProtocolVersion) + `,"ok":true,"key":"`
	const tail = "\"}\n"
	buf := make([]byte, 0, len(head)+len(key)+len(tail))
	buf = append(buf, head...)
	buf = append(buf, key...)
	return append(buf, tail...)
}

// encodeResponse encodes a response without a key.
func encodeResponse(r response) []byte {
	r.V = ProtocolVersion
	b, err := json.Marshal(r)
	if err != nil { // can't happen: the type has only plain fields
		b = []byte(`{"v":` + strconv.Itoa(ProtocolVersion) + `,"ok":false,"code":"` + codeBadRequest + `"}`)
	}
	return append(b, '\n')
}

func errorResponse(code, format string, args ...any) response {
	return response{Code: code, Error: fmt.Sprintf(format, args...)}
}

func statusResponse(st Status) response {
	return response{
		OK:         true,
		PID:        st.PID,
		Vault:      st.Vault,
		IdleLeftMS: max(st.IdleLeft.Milliseconds(), 1),
		MaxLeftMS:  max(st.MaxLeft.Milliseconds(), 1),
	}
}

func (r response) status() Status {
	return Status{
		PID:      r.PID,
		Vault:    r.Vault,
		IdleLeft: time.Duration(r.IdleLeftMS) * time.Millisecond,
		MaxLeft:  time.Duration(r.MaxLeftMS) * time.Millisecond,
	}
}

// validKeyText reports whether b looks like a vault key: the age identity
// prefix followed by upper-case bech32 characters. It doesn't check the
// checksum; parseKey does.
func validKeyText(b []byte) bool {
	if len(b) <= len(keyPrefix) || len(b) > 128 || !bytes.HasPrefix(b, []byte(keyPrefix)) {
		return false
	}
	for _, c := range b[len(keyPrefix):] {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// parseKey checks b with validKeyText and parses it as an age X25519
// identity.
func parseKey(b []byte) (*age.X25519Identity, error) {
	if !validKeyText(b) {
		return nil, errors.New("not a vault key")
	}
	id, err := age.ParseX25519Identity(string(b))
	if err != nil {
		return nil, errors.New("not a valid vault key")
	}
	return id, nil
}
