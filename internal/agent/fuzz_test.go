package agent

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParseRequest (TEST-12, CLI-020) feeds arbitrary bytes to the agent's
// request decoding, as a peer's connection would: readMessage, then
// parseRequest. It never panics; a request it accepts is one the agent
// serves (version, operation, and for a key request a well-formed key-block
// digest, INV-12); and every refusal is a JSON line a client reads, within
// maxMessage. The seed corpus runs in every `go test`.
func FuzzParseRequest(f *testing.F) {
	sum := keyBlockSum([]byte("key block"))
	for _, seed := range []string{
		`{"v":1,"op":"key","key_block":"` + sum + `"}` + "\n",
		`{"v":1,"op":"status"}` + "\n",
		`{"v":1,"op":"stop"}` + "\n",
		`{"v":1,"op":"key"}` + "\n",
		`{"v":1,"op":"key","key_block":"` + strings.ToUpper(sum) + `"}` + "\n",
		`{"v":1,"op":"key","key_block":42}` + "\n",
		`{"v":2,"op":"status"}` + "\n",
		`{"op":"status"}` + "\n",
		`{"v":1,"op":"` + strings.Repeat("x", 3000) + `"}` + "\n",
		`{"v":1,"op":"\u0000\ud800"}` + "\n",
		`[]` + "\n",
		"garbage\n",
		"\n",
		"",
		strings.Repeat("x", maxMessage+1),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := readMessage(bytes.NewReader(data), maxMessage)
		if err != nil {
			return
		}
		if len(msg) >= maxMessage {
			t.Fatalf("readMessage returned %d bytes, more than maxMessage allows", len(msg))
		}
		req, refused := parseRequest(msg)
		if refused == nil {
			if req.V != ProtocolVersion {
				t.Errorf("accepted version %d", req.V)
			}
			switch req.Op {
			case opKey:
				if !validSum(req.KeyBlock) {
					t.Errorf("accepted a key request with key_block %q", req.KeyBlock)
				}
			case opStatus, opStop:
			default:
				t.Errorf("accepted operation %q", req.Op)
			}
			return
		}
		if refused.OK || refused.Code == "" || refused.Key != nil {
			t.Errorf("refusal %+v", refused)
		}
		line := encodeResponse(*refused)
		if len(line) > maxMessage {
			t.Errorf("a refusal of %d bytes: a client can't read it", len(line))
		}
		back, err := readMessage(bytes.NewReader(line), maxMessage)
		if err != nil {
			t.Fatalf("the refusal doesn't read back: %v", err)
		}
		var r response
		if err := json.Unmarshal(back, &r); err != nil || r.V != ProtocolVersion || r.OK || r.Code != refused.Code {
			t.Errorf("the refusal decodes to %+v, %v", r, err)
		}
	})
}

// FuzzParseResponse feeds arbitrary bytes to the client's side: an answer
// read with readMessage and decoded as Client.KeyFor does. It never panics
// and never yields a key that isn't a valid vault key.
func FuzzParseResponse(f *testing.F) {
	for _, seed := range []string{
		`{"v":1,"ok":true,"key":"AGE-SECRET-KEY-1QQQQ"}` + "\n",
		`{"v":1,"ok":true,"pid":42,"vault":"/v","idle_left_ms":1,"max_left_ms":2}` + "\n",
		`{"v":1,"ok":false,"code":"key_block_changed","error":"x"}` + "\n",
		`{"v":1,"ok":true,"key":42}` + "\n",
		`{"v":1,"ok":true,"key":"\"\\"}` + "\n",
		`{"v":2}` + "\n",
		"{\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := readMessage(bytes.NewReader(data), maxMessage)
		if err != nil {
			return
		}
		resp, err := parseResponse(msg)
		if err != nil || !resp.OK || resp.Key == nil {
			return
		}
		raw, ok := unquote(resp.Key)
		if !ok {
			return
		}
		if id, err := parseKey(raw); err == nil && !validKeyText([]byte(id.String())) {
			t.Errorf("parseKey accepted %q", raw)
		}
	})
}
